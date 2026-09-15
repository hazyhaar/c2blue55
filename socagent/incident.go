package socagent

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strconv"
	"sync/atomic"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55"
	"uuid"
)

const (
	ScoreThreshold = 100
	VerdictThreat  = "CORRELATED_THREAT"
)

var (
	ErrNotConfirmed = errors.New("socagent: refused: not a confirmed correlated threat")
	ErrNoFacts      = errors.New("socagent: refused: no attested propositions")

	idSeq atomic.Uint32
)

type IncidentReport struct {
	ID        string        `json:"id"`
	Timestamp time.Time     `json:"timestamp"`
	Score     uint32        `json:"score"`
	Facts     []Proposition `json:"facts"`
	Verdict   string        `json:"verdict"`
}

type Dossier struct {
	Incident    IncidentReport `json:"incident"`
	Remediation []string       `json:"remediation"`
}

func Confirmed(flags, score uint32) bool {
	if score >= ScoreThreshold {
		return true
	}
	return flags&c2blue55.FlagCorrelatedThreat != 0
}

func ComposeV7(unixMs uint64, seq uint16, randB uint64) string {
	var u uuid.UUID
	u[0] = byte(unixMs >> 40)
	u[1] = byte(unixMs >> 32)
	u[2] = byte(unixMs >> 24)
	u[3] = byte(unixMs >> 16)
	u[4] = byte(unixMs >> 8)
	u[5] = byte(unixMs)
	u[6] = 0x70 | byte((seq>>8)&0x0F)
	u[7] = byte(seq)
	u[8] = 0x80 | byte((randB>>56)&0x3F)
	u[9] = byte(randB >> 48)
	u[10] = byte(randB >> 40)
	u[11] = byte(randB >> 32)
	u[12] = byte(randB >> 24)
	u[13] = byte(randB >> 16)
	u[14] = byte(randB >> 8)
	u[15] = byte(randB)
	return u.String()
}

func Build(events []c2blue55.Event, score, flags uint32) (*IncidentReport, error) {
	return BuildAt(events, score, flags, time.Now().UTC(), uint16(idSeq.Add(1)))
}

func BuildAt(events []c2blue55.Event, score, flags uint32, at time.Time, seq uint16) (*IncidentReport, error) {
	if !Confirmed(flags, score) {
		return nil, ErrNotConfirmed
	}
	facts := Translate(events)
	if err := ValidateAll(facts); err != nil {
		return nil, err
	}
	at = at.UTC()
	unixMs := uint64(at.UnixMilli())
	id := ComposeV7(unixMs, seq, hashFacts(facts))
	return &IncidentReport{
		ID:        id,
		Timestamp: at,
		Score:     score,
		Facts:     facts,
		Verdict:   VerdictThreat,
	}, nil
}

func Admit(events []c2blue55.Event, score, flags uint32) (*Dossier, error) {
	return AdmitAt(events, score, flags, time.Now().UTC(), uint16(idSeq.Add(1)))
}

func AdmitAt(events []c2blue55.Event, score, flags uint32, at time.Time, seq uint16) (*Dossier, error) {
	rep, err := BuildAt(events, score, flags, at, seq)
	if err != nil {
		return nil, err
	}
	return &Dossier{
		Incident:    *rep,
		Remediation: RemediationFor(rep.Facts, events),
	}, nil
}

func (d Dossier) MarshalJSON() ([]byte, error) {
	return AppendJSON(make([]byte, 0, 512), &d), nil
}

func AppendJSON(dst []byte, d *Dossier) []byte {
	dst = append(dst, `{"incident":{"id":`...)
	dst = appendJSONString(dst, d.Incident.ID)
	dst = append(dst, `,"timestamp":"`...)
	dst = d.Incident.Timestamp.UTC().AppendFormat(dst, time.RFC3339Nano)
	dst = append(dst, '"')
	dst = append(dst, `,"score":`...)
	dst = strconv.AppendUint(dst, uint64(d.Incident.Score), 10)
	dst = append(dst, `,"facts":[`...)
	for i := range d.Incident.Facts {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendFactJSON(dst, &d.Incident.Facts[i])
	}
	dst = append(dst, `],"verdict":`...)
	dst = appendJSONString(dst, d.Incident.Verdict)
	dst = append(dst, `},"remediation":[`...)
	for i := range d.Remediation {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = appendJSONString(dst, d.Remediation[i])
	}
	dst = append(dst, `]}`...)
	return dst
}

func hashFacts(facts []Proposition) uint64 {
	h := sha256.New()
	for i := range facts {
		h.Write([]byte(facts[i].Type))
		h.Write([]byte{0})
		h.Write([]byte(facts[i].Entity))
		h.Write([]byte{0})
		h.Write([]byte(facts[i].Evidence))
		h.Write([]byte{0})
	}
	sum := h.Sum(nil)
	return binary.BigEndian.Uint64(sum[:8])
}

func appendFactJSON(dst []byte, p *Proposition) []byte {
	dst = append(dst, `{"type":`...)
	dst = appendJSONString(dst, p.Type)
	dst = append(dst, `,"entity":`...)
	dst = appendJSONString(dst, p.Entity)
	dst = append(dst, `,"evidence":`...)
	dst = appendJSONString(dst, p.Evidence)
	dst = append(dst, `,"confidence":`...)
	if p.Confidence == 1 {
		dst = append(dst, '1')
	} else {
		dst = strconv.AppendFloat(dst, p.Confidence, 'g', -1, 64)
	}
	return append(dst, '}')
}

func appendJSONString(dst []byte, s string) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\\':
			dst = append(dst, '\\', c)
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if c < 0x20 {
				const hexdigits = "0123456789abcdef"
				dst = append(dst, '\\', 'u', '0', '0', hexdigits[c>>4], hexdigits[c&0xF])
			} else {
				dst = append(dst, c)
			}
		}
	}
	return append(dst, '"')
}
