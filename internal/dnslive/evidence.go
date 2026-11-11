package dnslive

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/hazyhaar/pkg/ecritureatomique"
)

type evidenceRetention struct {
	Policy           string `json:"policy"`
	MaxPacketBytes   int    `json:"max_packet_bytes"`
	TruncatedPackets uint64 `json:"truncated_packets"`
	DroppedPackets   uint64 `json:"dropped_packets"`
}

type evidenceFiles struct {
	JSONL string `json:"jsonl"`
	PCAP  string `json:"pcap"`
}

type evidenceManifest struct {
	RunID       string            `json:"run_id"`
	Emitter     string            `json:"emitter"`
	CaptureMode string            `json:"capture_mode"`
	Retention   evidenceRetention `json:"retention"`
	Files       evidenceFiles     `json:"files"`
}

type evidenceSession struct {
	directory      string
	runID          string
	jsonlName      string
	pcapName       string
	manifestName   string
	jsonlFile      *os.File
	pcapFile       *os.File
	jsonlWriter    *bufio.Writer
	pcapWriter     *bufio.Writer
	appended       uint64
	closed         bool
	finishErr      error
	writeManifest  bool
	lastActivityNS int64
}

func openEvidenceSession(directory, runID, stem string) (*evidenceSession, error) {
	session := &evidenceSession{
		directory:      directory,
		runID:          runID,
		jsonlName:      stem + ".jsonl",
		pcapName:       stem + ".pcap",
		manifestName:   stem + ".manifest.json",
		writeManifest:  runID != "",
		lastActivityNS: time.Now().UnixNano(),
	}
	jsonlPath := filepath.Join(directory, session.jsonlName)
	jsonlFile, err := os.OpenFile(jsonlPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("dnslive: créer le JSONL: %w", err)
	}
	session.jsonlFile = jsonlFile
	session.jsonlWriter = bufio.NewWriterSize(jsonlFile, 256*1024)
	pcapPath := filepath.Join(directory, session.pcapName)
	pcapFile, err := os.OpenFile(pcapPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("dnslive: créer le PCAP reconstitué: %w", err), session.closeFiles())
	}
	session.pcapFile = pcapFile
	session.pcapWriter = bufio.NewWriterSize(pcapFile, 256*1024)
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(header[4:6], 2)
	binary.LittleEndian.PutUint16(header[6:8], 4)
	binary.LittleEndian.PutUint32(header[16:20], 262144)
	binary.LittleEndian.PutUint32(header[20:24], 1)
	if err := writeEntirely(session.pcapWriter, header); err != nil {
		return nil, errors.Join(fmt.Errorf("dnslive: écrire l'en-tête PCAP: %w", err), session.closeFiles())
	}
	if err := session.pcapWriter.Flush(); err != nil {
		return nil, errors.Join(fmt.Errorf("dnslive: vider l'en-tête PCAP: %w", err), session.closeFiles())
	}
	if err := pcapFile.Sync(); err != nil {
		return nil, errors.Join(fmt.Errorf("dnslive: synchroniser l'en-tête PCAP: %w", err), session.closeFiles())
	}
	return session, nil
}

func writeEntirely(destination io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := destination.Write(payload)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}

func (session *evidenceSession) append(event liveEvent, wirePacket []byte) ([]byte, error) {
	if session.closed {
		return nil, errors.New("dnslive: preuve déjà fermée")
	}
	line, err := json.Marshal(storedLiveEvent{
		liveEvent:   event,
		Emitter:     evidenceEmitter,
		CaptureMode: evidenceCaptureMode,
	})
	if err != nil {
		return nil, fmt.Errorf("dnslive: encoder l'événement JSONL: %w", err)
	}
	line = append(line, '\n')
	frame, err := reconstructUDPPacket(event, wirePacket)
	if err != nil {
		return nil, err
	}
	record := make([]byte, 16+len(frame))
	binary.LittleEndian.PutUint32(record[0:4], uint32(event.TimestampNS/1_000_000_000))
	binary.LittleEndian.PutUint32(record[4:8], uint32(event.TimestampNS%1_000_000_000/1_000))
	binary.LittleEndian.PutUint32(record[8:12], uint32(len(frame)))
	binary.LittleEndian.PutUint32(record[12:16], uint32(len(frame)))
	copy(record[16:], frame)
	jsonlErr := writeEntirely(session.jsonlWriter, line)
	pcapErr := writeEntirely(session.pcapWriter, record)
	if jsonlErr == nil && pcapErr == nil {
		session.appended++
		if session.appended%256 == 0 {
			jsonlErr = errors.Join(session.jsonlWriter.Flush(), session.jsonlFile.Sync())
			pcapErr = errors.Join(session.pcapWriter.Flush(), session.pcapFile.Sync())
		}
	}
	if jsonlErr != nil || pcapErr != nil {
		return nil, errors.Join(
			wrapEvidenceError("journaliser le JSONL", jsonlErr),
			wrapEvidenceError("journaliser le PCAP reconstitué", pcapErr),
		)
	}
	return line, nil
}

func wrapEvidenceError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("dnslive: %s: %w", operation, err)
}

// flush vide les tampons de la session vers le disque. Un échec interdit
// l'émission de la réponse UDP correspondante : échec de journal = pas de
// réponse, appliqué à chaque datagramme et non seulement à la clôture.
func (session *evidenceSession) flush() error {
	if session.closed || session.jsonlWriter == nil || session.jsonlFile == nil ||
		session.pcapWriter == nil || session.pcapFile == nil {
		return errors.New("dnslive: vider une preuve déjà fermée")
	}
	err := errors.Join(
		session.jsonlWriter.Flush(),
		session.jsonlFile.Sync(),
		session.pcapWriter.Flush(),
		session.pcapFile.Sync(),
	)
	return wrapEvidenceError("vider la preuve avant réponse", err)
}

func (session *evidenceSession) closeFiles() error {
	var joined error
	if session.jsonlWriter != nil {
		joined = errors.Join(joined, session.jsonlWriter.Flush())
		session.jsonlWriter = nil
	}
	if session.jsonlFile != nil {
		joined = errors.Join(joined, session.jsonlFile.Close())
		session.jsonlFile = nil
	}
	if session.pcapWriter != nil {
		joined = errors.Join(joined, session.pcapWriter.Flush())
		session.pcapWriter = nil
	}
	if session.pcapFile != nil {
		joined = errors.Join(joined, session.pcapFile.Close())
		session.pcapFile = nil
	}
	return joined
}

func (session *evidenceSession) finish(ctx context.Context) error {
	if session.closed {
		return session.finishErr
	}
	session.closed = true
	var syncErr error
	if session.jsonlWriter != nil {
		syncErr = errors.Join(syncErr, session.jsonlWriter.Flush())
	}
	if session.jsonlFile != nil {
		syncErr = errors.Join(syncErr, session.jsonlFile.Sync())
	}
	if session.pcapWriter != nil {
		syncErr = errors.Join(syncErr, session.pcapWriter.Flush())
	}
	if session.pcapFile != nil {
		syncErr = errors.Join(syncErr, session.pcapFile.Sync())
	}
	closeErr := session.closeFiles()
	var manifestErr error
	if session.writeManifest {
		manifest := evidenceManifest{
			RunID:       session.runID,
			Emitter:     evidenceEmitter,
			CaptureMode: evidenceCaptureMode,
			Retention: evidenceRetention{
				Policy:           "retain-all",
				MaxPacketBytes:   0,
				TruncatedPackets: 0,
				DroppedPackets:   0,
			},
			Files: evidenceFiles{JSONL: session.jsonlName, PCAP: session.pcapName},
		}
		payload, err := json.Marshal(manifest)
		if err == nil {
			payload = append(payload, '\n')
			err = ecritureatomique.Ecrire(ctx, filepath.Join(session.directory, session.manifestName), payload)
		}
		manifestErr = wrapEvidenceError("publier le manifeste", err)
	}
	session.finishErr = errors.Join(
		wrapEvidenceError("synchroniser les preuves", syncErr),
		wrapEvidenceError("fermer les preuves", closeErr),
		manifestErr,
	)
	return session.finishErr
}

func (session *evidenceSession) manifest() (evidenceManifest, error) {
	if !session.closed || session.finishErr != nil || !session.writeManifest {
		return evidenceManifest{}, errors.New("dnslive: manifeste non finalisé")
	}
	return evidenceManifest{
		RunID:       session.runID,
		Emitter:     evidenceEmitter,
		CaptureMode: evidenceCaptureMode,
		Retention: evidenceRetention{
			Policy:           "retain-all",
			MaxPacketBytes:   0,
			TruncatedPackets: 0,
			DroppedPackets:   0,
		},
		Files: evidenceFiles{JSONL: session.jsonlName, PCAP: session.pcapName},
	}, nil
}

func reconstructUDPPacket(event liveEvent, wirePacket []byte) ([]byte, error) {
	source, err := netip.ParseAddr(event.SrcIP)
	if err != nil {
		return nil, fmt.Errorf("dnslive: adresse source de preuve invalide: %w", err)
	}
	destination, err := netip.ParseAddr(event.DstIP)
	if err != nil {
		return nil, fmt.Errorf("dnslive: adresse destination de preuve invalide: %w", err)
	}
	source = source.Unmap()
	destination = destination.Unmap()
	if source.Is4() != destination.Is4() {
		return nil, errors.New("dnslive: familles IP incohérentes dans la preuve")
	}
	if source.Is4() && len(wirePacket) > math.MaxUint16-28 {
		return nil, errors.New("dnslive: charge UDP trop grande pour IPv4")
	}
	if source.Is6() && len(wirePacket) > math.MaxUint16-8 {
		return nil, errors.New("dnslive: charge UDP trop grande pour IPv6")
	}
	ipHeaderLength := 40
	etherType := uint16(0x86dd)
	if source.Is4() {
		ipHeaderLength = 20
		etherType = 0x0800
	}
	frame := make([]byte, 14+ipHeaderLength+8+len(wirePacket))
	frame[0], frame[1], frame[2], frame[3], frame[4], frame[5] = 0x02, 0, 0, 0, 0, 2
	frame[6], frame[7], frame[8], frame[9], frame[10], frame[11] = 0x02, 0, 0, 0, 0, 1
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	ipHeader := frame[14 : 14+ipHeaderLength]
	udpHeader := frame[14+ipHeaderLength : 14+ipHeaderLength+8]
	udpLength := 8 + len(wirePacket)
	if source.Is4() {
		ipHeader[0] = 0x45
		binary.BigEndian.PutUint16(ipHeader[2:4], uint16(ipHeaderLength+udpLength))
		binary.BigEndian.PutUint16(ipHeader[4:6], uint16(event.Sequence))
		ipHeader[8] = 64
		ipHeader[9] = 17
		source4 := source.As4()
		destination4 := destination.As4()
		copy(ipHeader[12:16], source4[:])
		copy(ipHeader[16:20], destination4[:])
		binary.BigEndian.PutUint16(ipHeader[10:12], internetChecksum(ipHeader))
	} else {
		ipHeader[0] = 0x60
		binary.BigEndian.PutUint16(ipHeader[4:6], uint16(udpLength))
		ipHeader[6] = 17
		ipHeader[7] = 64
		source16 := source.As16()
		destination16 := destination.As16()
		copy(ipHeader[8:24], source16[:])
		copy(ipHeader[24:40], destination16[:])
	}
	binary.BigEndian.PutUint16(udpHeader[0:2], event.SrcPort)
	binary.BigEndian.PutUint16(udpHeader[2:4], event.DstPort)
	binary.BigEndian.PutUint16(udpHeader[4:6], uint16(udpLength))
	copy(frame[14+ipHeaderLength+8:], wirePacket)
	checksumInput := make([]byte, 0, ipHeaderLength+udpLength)
	if source.Is4() {
		checksumInput = append(checksumInput, ipHeader[12:20]...)
		checksumInput = append(checksumInput, 0, 17, byte(udpLength>>8), byte(udpLength))
	} else {
		checksumInput = append(checksumInput, ipHeader[8:40]...)
		checksumInput = append(checksumInput, 0, 0, 0, 0)
		binary.BigEndian.PutUint32(checksumInput[len(checksumInput)-4:], uint32(udpLength))
		checksumInput = append(checksumInput, 0, 0, 0, 17)
	}
	checksumInput = append(checksumInput, frame[14+ipHeaderLength:]...)
	udpChecksum := internetChecksum(checksumInput)
	if udpChecksum == 0 {
		udpChecksum = math.MaxUint16
	}
	binary.BigEndian.PutUint16(udpHeader[6:8], udpChecksum)
	return frame, nil
}

func internetChecksum(payload []byte) uint16 {
	var sum uint32
	for len(payload) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(payload[:2]))
		payload = payload[2:]
	}
	if len(payload) == 1 {
		sum += uint32(payload[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func sourceEvidenceStem(runID string, source netip.AddrPort) string {
	if runID != "" {
		return runID
	}
	digest := sha256.Sum256([]byte(source.String()))
	return "unregistered-" + hex.EncodeToString(digest[:8])
}
