package c2blue55

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"

	"github.com/hazyhaar/c2blue55/internal/engine"
)

// RecordedEpisodeLine représente une entrée synchronisée du fichier <run_id>.episodes.jsonl.
type RecordedEpisodeLine struct {
	FrameIndex    int     `json:"frame_index"`
	TimestampNs   int64   `json:"timestamp_ns"`
	TxID          uint16  `json:"txid"`
	IsResponse    bool    `json:"is_response"`
	QType         uint16  `json:"qtype"`
	Subdomain     string  `json:"subdomain"`
	ParentApex    string  `json:"parent_apex"`
	ReasonCode    string  `json:"reason_code"`
	Decision      uint8   `json:"decision"`
	DownlinkRatio float32 `json:"downlink_ratio"`
	PacketSHA256  string  `json:"packet_sha256"`
}

// RecordSession enregistre de manière atomique et synchronisée chaque message DNS valide
// à la fois dans <run_id>.pcap et dans <run_id>.episodes.jsonl.
type RecordSession struct {
	mu        sync.Mutex
	pcapPath  string
	jsonlPath string
	pcapFile  *os.File
	jsonlFile *os.File
	pipe      *Pipeline
	episodes  engine.DNSEpisodeStore
	rollup    engine.DNSClientRollup
	stream18  engine.StreamingDNS18State
	frameIdx  int
}

// NewDefaultPipeline instancie un Pipeline par défaut sans fichier de log externe.
func NewDefaultPipeline() *Pipeline {
	p, _ := NewPipeline(PipelineConfig{}, nil)
	return p
}

// NewRecordSession ouvre la session d'enregistrement et écrit l'en-tête global PCAP nanoseconde.
func NewRecordSession(dir, runID string, pipe *Pipeline) (*RecordSession, error) {
	if dir == "" || runID == "" || pipe == nil {
		return nil, errors.New("c2blue55: paramètres NewRecordSession invalides")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	pcapPath := filepath.Join(dir, runID+".pcap")
	jsonlPath := filepath.Join(dir, runID+".episodes.jsonl")

	pf, err := os.Create(pcapPath)
	if err != nil {
		return nil, err
	}
	jf, err := os.Create(jsonlPath)
	if err != nil {
		_ = pf.Close()
		return nil, err
	}

	var ghdr [24]byte
	binary.LittleEndian.PutUint32(ghdr[0:4], pcapMagicNsLE)
	binary.LittleEndian.PutUint16(ghdr[4:6], 2)
	binary.LittleEndian.PutUint16(ghdr[6:8], 4)
	binary.LittleEndian.PutUint32(ghdr[16:20], 65535)
	binary.LittleEndian.PutUint32(ghdr[20:24], pcapLinkRawIP)
	if _, err := pf.Write(ghdr[:]); err != nil {
		_ = pf.Close()
		_ = jf.Close()
		return nil, err
	}

	return &RecordSession{
		pcapPath:  pcapPath,
		jsonlPath: jsonlPath,
		pcapFile:  pf,
		jsonlFile: jf,
		pipe:      pipe,
	}, nil
}

// PCAPPath retourne le chemin du fichier PCAP écrit par la session.
func (rs *RecordSession) PCAPPath() string { return rs.pcapPath }

// JSONLPath retourne le chemin du fichier JSONL d'épisodes écrit par la session.
func (rs *RecordSession) JSONLPath() string { return rs.jsonlPath }

// RecordDNSMessage valide le message DNS, normalise clientIP sur QR=1 (F-Adv-1),
// écrit la trame IPv4/UDP dans le PCAP et journalise l'épisode évalué dans le JSONL.
func (rs *RecordSession) RecordDNSMessage(raw []byte, tsNs int64, srcIP, dstIP [16]byte) (EvaluationResult, error) {
	var msg DNSMessage
	if err := ParseDNSMessage(raw, &msg); err != nil {
		return EvaluationResult{}, err
	}

	rs.mu.Lock()
	defer rs.mu.Unlock()

	// Normalisation directionnelle : sur QR=1, le client est dstIP (F-Adv-1).
	clientIP := srcIP
	if msg.IsResponse && dstIP != ([16]byte{}) {
		clientIP = dstIP
	}

	verdict, _, pipeReason, err := rs.pipe.EvaluateDNSMessageWithReason(raw, tsNs, clientIP, dstIP)
	if err != nil {
		return verdict, err
	}

	sub := msg.Subdomain[:msg.SubdomainLen]
	parent := msg.ParentDomain[:msg.ParentDomainLen]
	var rdata []byte
	if msg.AnswerCount > 0 {
		rdata = msg.Answers[0].RData[:msg.Answers[0].RDataLen]
	}

	obs := engine.DNSExchangeObs{
		TimestampNs: tsNs,
		SrcIP:       clientIP,
		TxID:        msg.ID,
		IsResponse:  msg.IsResponse,
		RCode:       msg.RCode,
		QType:       msg.QType,
		ParentApex:  parent,
		Subdomain:   sub,
		AnswerRData: rdata,
		AnswerCount: msg.AnswerCount,
		HasNonLDH:   msg.HasNonLDH,
	}
	snap, _ := rs.episodes.ObserveExchange(obs, nil)
	_, reason, consumed := rs.stream18.ObserveAndClassify18(
		raw, tsNs, clientIP, sub, parent, msg.QType, snap, engine.EpisodeP3Features{},
	)
	if !consumed {
		p4 := rs.rollup.ObserveParentApex(clientIP, fnv64Msg(parent), labelEntropyNorm(sub), tsNs)
		if p4.DistinctHighEntParents >= 3 && p4.CompositeP4Score > 0.20 {
			reason = engine.ReasonP4MultiParentSharding
		}
	}
	if reason == engine.ReasonNone && pipeReason != engine.ReasonNone {
		reason = pipeReason
	}

	// Construction du paquet Raw IPv4 (20 octets) + UDP (8 octets) + DNS raw.
	pktLen := 28 + len(raw)
	frame := make([]byte, 16+pktLen)
	binary.LittleEndian.PutUint32(frame[0:4], uint32(tsNs/1_000_000_000))
	binary.LittleEndian.PutUint32(frame[4:8], uint32(tsNs%1_000_000_000))
	binary.LittleEndian.PutUint32(frame[8:12], uint32(pktLen))
	binary.LittleEndian.PutUint32(frame[12:16], uint32(pktLen))

	ipHdr := frame[16:36]
	ipHdr[0] = 0x45
	binary.BigEndian.PutUint16(ipHdr[2:4], uint16(pktLen))
	ipHdr[8] = 64
	ipHdr[9] = ipProtoUDP
	copy(ipHdr[12:16], srcIP[12:16])
	copy(ipHdr[16:20], dstIP[12:16])

	udpHdr := frame[36:44]
	ephemPort := uint16(49152) + (msg.ID & 0x3fff)
	if msg.IsResponse {
		binary.BigEndian.PutUint16(udpHdr[0:2], dnsPort)
		binary.BigEndian.PutUint16(udpHdr[2:4], ephemPort)
	} else {
		binary.BigEndian.PutUint16(udpHdr[0:2], ephemPort)
		binary.BigEndian.PutUint16(udpHdr[2:4], dnsPort)
	}
	binary.BigEndian.PutUint16(udpHdr[4:6], uint16(8+len(raw)))
	copy(frame[44:], raw)

	if _, err := rs.pcapFile.Write(frame); err != nil {
		return verdict, err
	}

	sum := sha256.Sum256(raw)
	line := RecordedEpisodeLine{
		FrameIndex:    rs.frameIdx,
		TimestampNs:   tsNs,
		TxID:          msg.ID,
		IsResponse:    msg.IsResponse,
		QType:         msg.QType,
		Subdomain:     string(sub),
		ParentApex:    string(parent),
		ReasonCode:    reason,
		Decision:      uint8(verdict.Decision),
		DownlinkRatio: snap.DownlinkRatio,
		PacketSHA256:  hex.EncodeToString(sum[:]),
	}
	enc, err := json.Marshal(line)
	if err != nil {
		return verdict, err
	}
	enc = append(enc, '\n')
	if _, err := rs.jsonlFile.Write(enc); err != nil {
		return verdict, err
	}
	rs.frameIdx++
	return verdict, nil
}

// Close synchronise et ferme les fichiers PCAP et JSONL.
func (rs *RecordSession) Close() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	var err1, err2 error
	if rs.pcapFile != nil {
		err1 = rs.pcapFile.Close()
		rs.pcapFile = nil
	}
	if rs.jsonlFile != nil {
		err2 = rs.jsonlFile.Close()
		rs.jsonlFile = nil
	}
	return errors.Join(err1, err2)
}
