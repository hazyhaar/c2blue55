// Package c2blue55 evaluates caller-provided observations and payloads.
// It does not connect host probes or apply system/network interdictions.
package c2blue55

import (
	"errors"
	"sync"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

// Constantes de sous-systèmes de capture
const (
	SubProc    uint16 = 1 // Processus (fork, exec, LOLBAS)
	SubFile    uint16 = 2 // Système de fichiers (fanotify, altération doctrine)
	SubNet     uint16 = 3 // Réseau (sockets, balises beaconing, exfiltration)
	SubMCP     uint16 = 4 // Proxy JSON-RPC 2.0 des outils MCP d'agents
	SubHarness uint16 = 5 // Intégrité doctrinale (AGENTS.md, guards)
	SubEntropy uint16 = 6 // Entropie de Shannon et classification de payload
	SubGPU     uint16 = 7 // Tenseurs et mémoire VRAM GPU
)

// Actions captées
const (
	ActExec     uint16 = 1
	ActOpen     uint16 = 2
	ActConnect  uint16 = 3
	ActToolCall uint16 = 4
	ActRead     uint16 = 5
	ActWrite    uint16 = 6
	ActMmapExec uint16 = 7
)

// Drapeaux de verdicts et classification de menaces (Flags)
const (
	FlagNone             uint32 = 0x0000
	FlagVerdictOK        uint32 = 0x0001
	FlagBlocked          uint32 = 0x0002
	FlagAnomaly          uint32 = 0x0004
	FlagLOLBAS           uint32 = 0x0008
	FlagBeaconing        uint32 = 0x0010
	FlagDrift            uint32 = 0x0020
	FlagHexPayload       uint32 = 0x0040
	FlagBase64Payload    uint32 = 0x0080
	FlagCryptoPayload    uint32 = 0x0100
	FlagCorrelatedThreat uint32 = 0x0200
	FlagSuspiciousMCP    uint32 = 0x0400
	FlagBurstCollapsed   uint32 = 0x0800
)

// Classes de charge utile (PayloadClass)
const (
	PayloadClassUnknown          uint16 = 0
	PayloadClassProse            uint16 = 1
	PayloadClassHex              uint16 = 2
	PayloadClassBase64           uint16 = 3
	PayloadClassCryptoCompressed uint16 = 4
	PayloadClassJWT              uint16 = 5
)

// Modes d'application et politiques de sécurité
const (
	ModePassive     byte = 0 // Audit seul (observation passive)
	ModeActive      byte = 1 // Veto actif (application effective des blocages)
	PolicyFailOpen  byte = 0 // Laisser passer en cas de saturation ou erreur
	PolicyFailClose byte = 1 // Bloquer en cas de saturation ou erreur
)

// Event est la structure d'événement universelle de 128 octets.
type Event = engine.Probe_event_t

// EntropyProfile contient la métrologie complète d'un échantillon analysé.
type EntropyProfile struct {
	EntropyQ8     uint32
	CharMask      uint32
	DistinctCount uint16
	PayloadClass  uint16
	Len           uint64
}

// Config définit la configuration statique du superviseur.
type Config struct {
	EnableProc     bool
	EnableFile     bool
	EnableNet      bool
	EnableMCP      bool
	EnableEntropy  bool
	EnableGPU      bool
	EnforceMode    byte
	FailSafePolicy byte
	MCPSocketPath  string
	HarnessDir     string
}

// Channel encapsule une file circulaire SPSC lock-free à 1024 slots.
type Channel struct {
	raw engine.Probe_channel_t
}

// NewChannel initialise une nouvelle file circulaire.
func NewChannel() *Channel {
	ch := &Channel{}
	engine.C2bt_channel_init(&ch.raw)
	return ch
}

// Write insère un événement de façon lock-free. Retourne 0 en succès, -2 sur saturation (avec drop atomique).
func (c *Channel) Write(ev *Event) int {
	return engine.C2bt_channel_write(&c.raw, ev)
}

// Read extrait un événement de façon lock-free. Retourne 1 si un événement a été lu, 0 si la file est vide.
func (c *Channel) Read(ev *Event) int {
	return engine.C2bt_channel_read(&c.raw, ev)
}

// ReadBatch lit jusqu'à maxEvents sans blocage.
func (c *Channel) ReadBatch(out []Event, maxEvents int) int {
	return engine.C2bt_channel_read_batch(&c.raw, out, maxEvents)
}

// Drops retourne le compteur atomique de rejets sur saturation.
func (c *Channel) Drops() uint64 {
	return engine.C2bt_channel_get_drops(&c.raw)
}

// Context evaluates caller-injected observations; it captures no host activity
// and applies no OS or network interdiction. Lifecycle calls must not run
// concurrently with injection or polling; injection is SPSC.
type Context struct {
	raw engine.C2bt_ctx_t
}

// NewContext initialise le contexte de sécurité in-place.
func NewContext(cfg Config) *Context {
	ctx := &Context{}
	rawCfg := engine.C2bt_config_t{
		Enforce_mode:     cfg.EnforceMode,
		Fail_safe_policy: cfg.FailSafePolicy,
	}
	if cfg.EnableProc {
		rawCfg.Enable_proc = 1
	}
	if cfg.EnableFile {
		rawCfg.Enable_file = 1
	}
	if cfg.EnableNet {
		rawCfg.Enable_net = 1
	}
	if cfg.EnableMCP {
		rawCfg.Enable_mcp = 1
	}
	if cfg.EnableEntropy {
		rawCfg.Enable_entropy = 1
	}
	if cfg.EnableGPU {
		rawCfg.Enable_gpu = 1
	}
	if cfg.MCPSocketPath != "" {
		rawCfg.Mcp_socket_path = []byte(cfg.MCPSocketPath)
	}
	if cfg.HarnessDir != "" {
		rawCfg.Harness_dir = []byte(cfg.HarnessDir)
	}

	engine.C2bt_init_inplace(&ctx.raw, &rawCfg)
	return ctx
}

var ErrUnsupportedConfig = errors.New("c2blue55: probes and interception are not connected; use Config{} for injected observation only")

// Start enables injected observation only. All Enable*, active enforcement,
// fail-close and probe path settings are rejected, never silently ignored.
func (c *Context) Start() error {
	if c == nil || engine.C2bt_start(&c.raw) != 0 {
		return ErrUnsupportedConfig
	}
	return nil
}

// Stop suspends polling; queued observations are retained for the next Start.
func (c *Context) Stop() error {
	if c == nil {
		return ErrUnsupportedConfig
	}
	engine.C2bt_stop(&c.raw)
	return nil
}

// InjectObservation queues a caller observation, not an independently attested
// capture. One producer is allowed. Returns -1 when stopped/invalid, -2 on full.
func (c *Context) InjectObservation(ev *Event) int {
	if c == nil || c.raw.Running == 0 || ev == nil || ev.Subsystem < SubProc || ev.Subsystem > SubGPU {
		return -1
	}
	return engine.C2bt_channel_write(&c.raw.Chan_proc, ev)
}

// PollBatch evaluates injected observations. Flags are detection/veto advice,
// including FlagBlocked; they do not attest an applied system interdiction.
func (c *Context) PollBatch(outBatch []Event, maxEvents int) int {
	if c == nil {
		return 0
	}
	return engine.C2bt_poll_batch(&c.raw, outBatch, maxEvents)
}

// CalcEntropyQ8 calcule l'entropie de Shannon en virgule fixe Q8.8 (0..2048).
func CalcEntropyQ8(data []byte) uint32 {
	return engine.C2bt_calc_entropy_8_8(data, uint64(len(data)))
}

// CalcEntropyBits calcule l'entropie de Shannon réelle en bits par octet (0.0..8.0).
func CalcEntropyBits(data []byte) float64 {
	q8 := CalcEntropyQ8(data)
	return float64(q8) / 256.0
}

// ProfilePayload extrait le profil d'entropie et la classe de charge utile en une passe.
func ProfilePayload(data []byte) EntropyProfile {
	var rawProf engine.C2bt_entropy_profile_t
	engine.C2bt_profile_payload(data, uint64(len(data)), &rawProf)
	return EntropyProfile{
		EntropyQ8:     rawProf.Entropy_q8,
		CharMask:      rawProf.Char_mask,
		DistinctCount: rawProf.Distinct_count,
		PayloadClass:  rawProf.Payload_class,
		Len:           rawProf.Len_,
	}
}

// EvalRulesBatch évalue les règles de filtrage LOLBAS, MCP et doctrine par lot.
func EvalRulesBatch(inEvents []Event, outEvents []Event, count int) int {
	return engine.C2bt_eval_rules_batch(inEvents, outEvents, count)
}

var (
	grammarMu              sync.RWMutex
	grammarTable           engine.C2bt_grammar_table_t
	vetoGrammarJSON        = []byte(`{"jsonrpc":"2.0","error":{"code":-32600,"message":"C2BLUE_VETO: Tool grammar divergence D_JS violation"}}`)
	vetoUnknownGrammarJSON = []byte(`{"jsonrpc":"2.0","error":{"code":-32601,"message":"C2BLUE_VETO: unknown or invalid tool grammar"}}`)
	ErrInvalidToolGrammar  = errors.New("c2blue55: invalid grammar: require a non-NUL name of 1..31 bytes and a nonempty sample")
	ErrGrammarTableFull    = errors.New("c2blue55: grammar catalog full (32 tools)")
)

func RegisterToolGrammar(tool string, sample []byte, mask uint32, thresholdQ8 uint16) error {
	grammarMu.Lock()
	rc := engine.C2bt_grammar_register_tool(&grammarTable, tool, sample, mask, thresholdQ8)
	grammarMu.Unlock()
	if rc == -2 {
		return ErrGrammarTableFull
	}
	if rc != 0 {
		return ErrInvalidToolGrammar
	}
	return nil
}

func EvalGrammar(tool string, payload []byte) (djsQ8 uint32, flags uint32, vetoJSON []byte) {
	grammarMu.RLock()
	rc := engine.C2bt_grammar_eval(&grammarTable, tool, payload, &djsQ8, &flags)
	grammarMu.RUnlock()
	if rc < 0 {
		return djsQ8, FlagBlocked | FlagAnomaly | FlagSuspiciousMCP, vetoUnknownGrammarJSON
	}
	if rc == 1 {
		return djsQ8, flags, vetoGrammarJSON
	}
	return djsQ8, flags, nil
}

// EvalToolCall is the explicit tool-call entry point. EvalGrammar remains
// available to existing consumers with the same fail-closed behavior.
func EvalToolCall(tool string, payload []byte) (uint32, uint32, []byte) {
	return EvalGrammar(tool, payload)
}
