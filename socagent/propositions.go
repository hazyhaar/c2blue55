package socagent

import (
	"errors"
	"math"
	"path/filepath"
	"strconv"
	"strings"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55"
)

const (
	FactLOLBASExec         = "LOLBAS_EXEC"
	FactHighEntropyPayload = "HIGH_ENTROPY_PAYLOAD"
	FactDoctrineMutation   = "DOCTRINE_MUTATION"

	RemediateQuarantinePID    = "Quarantine PID"
	RemediateRevertFSMutation = "Review blocked write; verify mutation before any revert"
	RemediateRevokeMCPToken   = "Revoke MCP Token"
)

var (
	ErrInvalidProposition = errors.New("socagent: proposition not attested")
	ErrUnknownFactType    = errors.New("socagent: unknown fact type")
	ErrConfidence         = errors.New("socagent: confidence must be finite in [0,1]")
)

type Proposition struct {
	Type     string `json:"type"`
	Entity   string `json:"entity"`
	Evidence string `json:"evidence"`
	// Zero means uncalibrated, not a statistical assertion of impossibility.
	Confidence float64 `json:"confidence"`
}

func Translate(events []c2blue55.Event) []Proposition {
	out := make([]Proposition, 0, len(events))
	return TranslateInto(out, events)
}

func TranslateInto(dst []Proposition, events []c2blue55.Event) []Proposition {
	for i := range events {
		if p, ok := translateEvent(&events[i]); ok {
			dst = append(dst, p)
		}
	}
	return dst
}

func Validate(p Proposition) error {
	switch p.Type {
	case FactLOLBASExec, FactHighEntropyPayload, FactDoctrineMutation:
	default:
		return ErrUnknownFactType
	}
	if p.Entity == "" || p.Evidence == "" {
		return ErrInvalidProposition
	}
	if math.IsNaN(p.Confidence) || math.IsInf(p.Confidence, 0) || p.Confidence < 0 || p.Confidence > 1 {
		return ErrConfidence
	}
	return nil
}

func ValidateAll(facts []Proposition) error {
	if len(facts) == 0 {
		return ErrNoFacts
	}
	for i := range facts {
		if err := Validate(facts[i]); err != nil {
			return err
		}
	}
	return nil
}

func RemediationFor(facts []Proposition, events []c2blue55.Event) []string {
	var needPID, needFS, needMCP bool
	for i := range facts {
		switch facts[i].Type {
		case FactLOLBASExec:
			needPID = true
		case FactDoctrineMutation:
			needFS = true
		}
	}
	for i := range events {
		switch events[i].Subsystem {
		case c2blue55.SubProc:
			needPID = true
		case c2blue55.SubFile, c2blue55.SubHarness:
			needFS = needFS || isDoctrineEvent(&events[i], payloadString(events[i].Payload[:]))
		case c2blue55.SubMCP:
			needMCP = true
		}
	}
	out := make([]string, 0, 3)
	if needPID {
		out = append(out, RemediateQuarantinePID)
	}
	if needFS {
		out = append(out, RemediateRevertFSMutation)
	}
	if needMCP {
		out = append(out, RemediateRevokeMCPToken)
	}
	return out
}

func translateEvent(ev *c2blue55.Event) (Proposition, bool) {
	payload := payloadString(ev.Payload[:])
	switch {
	case isLOLBASEvent(ev, payload):
		name := commandName(payload)
		evidence := "LOLBAS indicator observed; execution not attested"
		if name != "" {
			evidence = name + " indicator observed; execution not attested"
		}
		return Proposition{
			Type:       FactLOLBASExec,
			Entity:     strconv.FormatUint(uint64(ev.Pid), 10),
			Evidence:   evidence,
			Confidence: 0,
		}, true
	case isEntropyEvent(ev):
		bits := float64(ev.Src) / 256
		var b strings.Builder
		b.Grow(64)
		b.WriteString("Payload with local entropy ")
		b.WriteString(strconv.FormatFloat(bits, 'f', 2, 64))
		b.WriteString(" b/o; cryptographic origin unproven")
		return Proposition{
			Type:       FactHighEntropyPayload,
			Entity:     strconv.FormatUint(uint64(ev.Pid), 10),
			Evidence:   b.String(),
			Confidence: 0,
		}, true
	case isDoctrineEvent(ev, payload):
		entity := payload
		if entity == "" {
			entity = strconv.FormatUint(uint64(ev.Pid), 10)
		}
		return Proposition{
			Type:       FactDoctrineMutation,
			Entity:     entity,
			Evidence:   "Protected-path write reported blocked; mutation not attested",
			Confidence: 0,
		}, true
	default:
		return Proposition{}, false
	}
}

func isLOLBASEvent(ev *c2blue55.Event, payload string) bool {
	if ev.Flags&c2blue55.FlagLOLBAS != 0 {
		return ev.Subsystem == c2blue55.SubProc || ev.Subsystem == c2blue55.SubMCP || ev.Action == c2blue55.ActExec
	}
	if ev.Subsystem == c2blue55.SubProc && ev.Action == c2blue55.ActExec && commandName(payload) != "" {
		return true
	}
	if ev.Subsystem == c2blue55.SubMCP && commandName(payload) != "" {
		return true
	}
	return false
}

func isEntropyEvent(ev *c2blue55.Event) bool {
	return ev.Subsystem == c2blue55.SubEntropy && ev.Src <= 8*256
}

func isDoctrineEvent(ev *c2blue55.Event, payload string) bool {
	return (ev.Subsystem == c2blue55.SubFile || ev.Subsystem == c2blue55.SubHarness) &&
		ev.Action == c2blue55.ActWrite && ev.Flags&c2blue55.FlagBlocked != 0 && protectedPath(payload)
}

func payloadString(p []byte) string {
	n := 0
	for n < len(p) && p[n] != 0 {
		n++
	}
	return string(p[:n])
}

func commandName(payload string) string {
	known := [...]string{
		"netcat", "python", "base64", "socat", "ncat", "wget", "curl",
		"perl", "ruby", "bash", "dash", "php", "lua", "zsh", "ash", "nc", "sh",
	}
	lower := strings.ToLower(payload)
	for _, name := range known {
		if tokenPresent(lower, name) {
			return name
		}
	}
	return ""
}

func tokenPresent(s, name string) bool {
	i := 0
	for {
		j := strings.Index(s[i:], name)
		if j < 0 {
			return false
		}
		j += i
		beforeOK := j == 0 || isTokenSep(s[j-1])
		after := j + len(name)
		afterOK := after == len(s) || isTokenSep(s[after])
		if beforeOK && afterOK {
			return true
		}
		i = j + 1
	}
}

func isTokenSep(c byte) bool {
	return c == '/' || c == ' ' || c == '\t' || c == '|' || c == ';' || c == ':' || c == '=' || c == '"' || c == '\''
}

func protectedPath(payload string) bool {
	if !filepath.IsAbs(payload) {
		return false
	}
	clean := filepath.Clean(payload)
	base := filepath.Base(clean)
	return base == "AGENTS.md" || base == "CLAUDE.md" || strings.Contains(clean, "/.claude/")
}
