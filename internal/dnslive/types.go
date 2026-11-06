// Package dnslive expose un serveur DNS UDP de laboratoire et son tableau de
// bord. Chaque source enregistrée possède son propre pipeline de détection ;
// l'étiquette de run ne sert qu'à choisir le répondeur de laboratoire.
package dnslive

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/dnslab"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

const (
	evidenceEmitter      = "c2blue-dns-live"
	evidenceCaptureMode  = "udp-reconstructed"
	unregisteredKind     = "unregistered"
	queryDirection       = "query"
	responseDirection    = "response"
	liveEventMemoryLimit = 4096
)

var (
	ErrLiveConfig   = errors.New("dnslive: configuration invalide")
	ErrLiveStarted  = errors.New("dnslive: service déjà démarré")
	ErrLiveNotStart = errors.New("dnslive: service non démarré")
)

// Config décrit les deux écoutes locales, le répertoire des preuves et le
// secret partagé. EventWriter reçoit, lorsqu'il est fourni, une copie de chaque
// ligne JSONL après son écriture dans la preuve du run.
type Config struct {
	UDPListen      string
	HTTPListen     string
	EvidenceDir    string
	DashboardToken string
	Language       string
	EventWriter    io.Writer
}

type liveEvent struct {
	Sequence     uint64 `json:"sequence"`
	RunID        string `json:"run_id"`
	Kind         string `json:"kind"`
	TimestampNS  int64  `json:"timestamp_ns"`
	Direction    string `json:"direction"`
	SrcIP        string `json:"src_ip"`
	SrcPort      uint16 `json:"src_port"`
	DstIP        string `json:"dst_ip"`
	DstPort      uint16 `json:"dst_port"`
	TxID         uint16 `json:"txid"`
	QName        string `json:"qname"`
	QType        uint16 `json:"qtype"`
	Decision     uint8  `json:"decision"`
	Class        string `json:"class"`
	ReasonCode   string `json:"reason_code"`
	PacketSHA256 string `json:"packet_sha256"`
	PacketBase64 string `json:"packet_base64"`
	ParseError   string `json:"parse_error"`
	SubdomainLen int    `json:"subdomain_len"`
	LabelCount   int    `json:"label_count"`
	MaxLabelLen  int    `json:"max_label_len"`
	AnswerCount  int    `json:"answer_count"`
	RDataBytes   int    `json:"rdata_bytes"`
}

type storedLiveEvent struct {
	liveEvent
	Emitter     string `json:"emitter"`
	CaptureMode string `json:"capture_mode"`
}

type liveRun struct {
	RunID      string `json:"run_id"`
	Kind       string `json:"kind"`
	SourceIP   string `json:"source_ip"`
	SourcePort uint16 `json:"source_port"`
	Finished   bool   `json:"finished"`
}

type liveSource struct {
	key         netip.AddrPort
	runID       string
	kind        string
	registered  bool
	finished    bool
	pipeline    *c2blue55.Pipeline
	zone        *dnslab.Zone
	evidence    *evidenceSession
	soaNegative engine.SOANegativeTracker
	aaaaIID     engine.AAAAIIDTracker
}

type liveRunHistory struct {
	public  liveRun
	source  *liveSource
	ordinal uint64
}

// Service détient tout l'état mutable du serveur. Aucun état de détection ou de
// journalisation n'est partagé entre instances.
type Service struct {
	cfg Config

	mu              sync.Mutex
	started         bool
	closing         bool
	udpConn         *net.UDPConn
	httpListener    net.Listener
	httpServer      *http.Server
	sequence        uint64
	runOrdinal      uint64
	events          []liveEvent
	eventsEvicted   uint64
	sources         map[netip.AddrPort]*liveSource
	runs            map[string]*liveRunHistory
	journalErr      error
	asynchronousErr error
	closeErr        error
	closeOnce       sync.Once
	workerWG        sync.WaitGroup
}
