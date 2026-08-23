// Package c2blue55 — Socle unifié de défense système, surveillance d'agents IA et métrologie d'entropie ARCHTIME.
// Zéro allocation sur le chemin chaud (0 B/op), sans CGO, conforme Go 1.27.
package c2blue55

import (
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
	ActExec       uint16 = 1
	ActFork       uint16 = 2
	ActFileOpen   uint16 = 3
	ActFileWrite  uint16 = 4
	ActFileDelete uint16 = 5
	ActNetConnect uint16 = 6
	ActToolCall   uint16 = 7
	ActToolResult uint16 = 8
)

// Drapeaux de verdicts et classification de menaces (Flags)
const (
	FlagVerdictOK        uint32 = 0x0001
	FlagAnomaly          uint32 = 0x0002
	FlagBlocked          uint32 = 0x0004
	FlagLOLBAS           uint32 = 0x0008
	FlagCryptoPayload    uint32 = 0x0010
	FlagBase64Payload    uint32 = 0x0020
	FlagHexPayload       uint32 = 0x0040
	FlagSuspiciousMCP    uint32 = 0x0080
	FlagFSMutation       uint32 = 0x0100
	FlagNetActivity      uint32 = 0x0200
	FlagCorrelatedThreat uint32 = 0x0400
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

// Context est le superviseur in-place intégrant canaux, règles et corrélateur.
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

// Start démarre la surveillance.
func (c *Context) Start() error {
	engine.C2bt_start(&c.raw)
	return nil
}

// Stop arrête la surveillance et libère les descripteurs sous-jacents.
func (c *Context) Stop() error {
	engine.C2bt_stop(&c.raw)
	return nil
}

// PollBatch relève et évalue équitablement les événements des 4 canaux en round-robin.
func (c *Context) PollBatch(outBatch []Event, maxEvents int) int {
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
