package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

const (
	pcapGlobalLen = 24
	pcapRecordLen = 16
	sll2HeaderLen = 20
	dnsHeaderLen  = 12
	realPCAPName  = "local-dns-20261027T113715Z.pcap"
	zoneApex      = "lab.pound2pound.fr"
	answerTXTText = "canary-lab-pound2pound"
	readBound     = 200 * time.Millisecond
)

type wireQuestion struct {
	payload  []byte
	qsection []byte
	qname    string
	qtype    uint16
	flags    uint16
	id       uint16
}

func labZone() dnslab.Zone {
	return dnslab.Zone{
		Apex:      []byte(zoneApex),
		AnswerA:   [4]byte{10, 55, 0, 1},
		AnswerTXT: []byte(answerTXTText),
		TTL:       0,
	}
}

func inLabZone(qname string) bool {
	return qname == zoneApex || strings.HasSuffix(qname, "."+zoneApex)
}

func responseFlags(queryFlags uint16, authoritative bool, rcode uint16) uint16 {
	rd := (queryFlags >> 8) & 1
	opcode := (queryFlags >> 11) & 0xF
	flags := uint16(0x8000) | (opcode << 11) | (rd << 8) | rcode
	if authoritative {
		flags |= 0x0400
	}
	return flags
}

func answerARecord() []byte {
	return []byte{
		0xC0, 0x0C,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x04,
		0x0A, 0x37, 0x00, 0x01,
	}
}

func answerTXTRecord() []byte {
	text := []byte(answerTXTText)
	rec := make([]byte, 13+len(text))
	rec[0], rec[1] = 0xC0, 0x0C
	rec[2], rec[3] = 0x00, 0x10
	rec[4], rec[5] = 0x00, 0x01
	rdlen := 1 + len(text)
	rec[10] = byte(rdlen >> 8)
	rec[11] = byte(rdlen)
	rec[12] = byte(len(text))
	copy(rec[13:], text)
	return rec
}

func expectResponse(q wireQuestion, verdict dnslab.Verdict) []byte {
	var rcode uint16
	authoritative := false
	var answer []byte
	switch verdict {
	case dnslab.VerdictAnswerA:
		authoritative = true
		answer = answerARecord()
	case dnslab.VerdictAnswerTXT:
		authoritative = true
		answer = answerTXTRecord()
	case dnslab.VerdictNoData:
		authoritative = true
	case dnslab.VerdictRefused:
		rcode = 5
	}
	ancount := uint16(0)
	if len(answer) > 0 {
		ancount = 1
	}
	out := make([]byte, dnsHeaderLen+len(q.qsection)+len(answer))
	binary.BigEndian.PutUint16(out[0:2], q.id)
	binary.BigEndian.PutUint16(out[2:4], responseFlags(q.flags, authoritative, rcode))
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], ancount)
	copy(out[dnsHeaderLen:], q.qsection)
	copy(out[dnsHeaderLen+len(q.qsection):], answer)
	return out
}

func questionSectionEnd(payload []byte) (int, bool) {
	if len(payload) < dnsHeaderLen {
		return 0, false
	}
	cursor := dnsHeaderLen
	for {
		if cursor >= len(payload) {
			return 0, false
		}
		labelLen := int(payload[cursor])
		if labelLen == 0 {
			cursor++
			break
		}
		if labelLen&0xC0 == 0xC0 || labelLen > 63 || cursor+1+labelLen > len(payload) {
			return 0, false
		}
		cursor += 1 + labelLen
	}
	if cursor+4 > len(payload) {
		return 0, false
	}
	return cursor + 4, true
}

func redhostLabDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("répertoire du paquet illisible: %v", err)
	}
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("aucun .git au-dessus du répertoire du paquet")
		}
		dir = parent
	}
	candidates := []string{
		filepath.Join(dir, "wittgenstein"),
		filepath.Join(dir, "..", "wittgenstein"),
		filepath.Join(dir, "..", "..", "..", "wittgenstein"),
	}
	for _, cand := range candidates {
		lab := filepath.Join(cand, "redhost_lab")
		st, statErr := os.Stat(lab)
		if statErr == nil && st.IsDir() {
			return lab
		}
	}
	t.Fatalf("wittgenstein/redhost_lab introuvable depuis la racine %s", dir)
	return ""
}

func udp53Payload(packet []byte) ([]byte, bool) {
	if len(packet) < sll2HeaderLen+20 {
		return nil, false
	}
	network := packet[sll2HeaderLen:]
	if network[0]>>4 != 4 {
		return nil, false
	}
	headerLen := int(network[0]&0x0f) * 4
	if headerLen < 20 || len(network) < headerLen+8 || network[9] != 17 {
		return nil, false
	}
	if binary.BigEndian.Uint16(network[6:8])&0x1fff != 0 {
		return nil, false
	}
	totalLen := int(binary.BigEndian.Uint16(network[2:4]))
	if totalLen < headerLen+8 || totalLen > len(network) {
		return nil, false
	}
	transport := network[headerLen:totalLen]
	dport := binary.BigEndian.Uint16(transport[2:4])
	udpLen := int(binary.BigEndian.Uint16(transport[4:6]))
	if dport != 53 || udpLen < dnsHeaderLen || udpLen > len(transport) {
		return nil, false
	}
	return transport[8:udpLen], true
}

func indexQuestions(t *testing.T, capture []byte) map[uint32][]byte {
	t.Helper()
	if len(capture) < pcapGlobalLen {
		t.Fatalf("capture plus courte que l'en-tête global: %d", len(capture))
	}
	magic := binary.LittleEndian.Uint32(capture[:4])
	if magic != 0xa1b2c3d4 && magic != 0xa1b23c4d {
		t.Fatalf("magic pcap réel inattendu: %#x", magic)
	}
	indexed := make(map[uint32][]byte)
	cursor := pcapGlobalLen
	var record uint32
	for cursor+pcapRecordLen <= len(capture) {
		incl := int(binary.LittleEndian.Uint32(capture[cursor+8 : cursor+12]))
		packetOff := cursor + pcapRecordLen
		if packetOff+incl > len(capture) {
			t.Fatalf("capture réelle incomplète à l'enregistrement %d", record+1)
		}
		record++
		if payload, ok := udp53Payload(capture[packetOff : packetOff+incl]); ok {
			indexed[record] = append([]byte(nil), payload...)
		}
		cursor = packetOff + incl
	}
	return indexed
}

func loadRealQuestions(t *testing.T) []wireQuestion {
	t.Helper()
	pcapPath := filepath.Join(redhostLabDir(t), realPCAPName)
	capture, err := os.ReadFile(pcapPath)
	if err != nil {
		t.Fatalf("lecture de la capture réelle: %v", err)
	}
	indexed := indexQuestions(t, capture)
	var questions []wireQuestion
	_, err = c2blue55.ReadPCAPDNSQuestions(pcapPath, func(meta c2blue55.PCAPQuestionMeta, ev *c2blue55.DNSEvent) error {
		payload, ok := indexed[meta.Record]
		if !ok {
			t.Fatalf("enregistrement %d absent du mini-lecteur", meta.Record)
		}
		end, ok := questionSectionEnd(payload)
		if !ok {
			t.Fatalf("section question illisible, enregistrement %d", meta.Record)
		}
		questions = append(questions, wireQuestion{
			payload:  payload,
			qsection: append([]byte(nil), payload[dnsHeaderLen:end]...),
			qname:    strings.Clone(ev.FQDN()),
			qtype:    ev.QType,
			flags:    ev.Flags,
			id:       ev.ID,
		})
		return nil
	})
	if err != nil {
		t.Fatalf("ReadPCAPDNSQuestions: %v", err)
	}
	if len(questions) != 69 {
		t.Fatalf("questions réelles: %d, attendu 69", len(questions))
	}
	return questions
}

func mustFind(t *testing.T, questions []wireQuestion, qname string, qtype uint16, inZone bool) wireQuestion {
	t.Helper()
	for _, q := range questions {
		if q.qname == qname && q.qtype == qtype && inLabZone(q.qname) == inZone {
			return q
		}
	}
	t.Fatalf("question absente: %s qtype %d inZone=%v", qname, qtype, inZone)
	return wireQuestion{}
}

func waitServe(t *testing.T, errCh <-chan error) error {
	t.Helper()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case err := <-errCh:
		return err
	case <-timer.C:
		t.Fatal("serveDNS n'a pas rendu dans le délai borné")
	}
	return nil
}

func readOne(t *testing.T, client *net.UDPConn) ([]byte, error) {
	t.Helper()
	if err := client.SetReadDeadline(time.Now().Add(readBound)); err != nil {
		t.Fatalf("échéance de lecture: %v", err)
	}
	scratch := make([]byte, 512)
	n, err := client.Read(scratch)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), scratch[:n]...), nil
}

func journalLines(t *testing.T, dir string) []dnslab.JournalLine {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "dnslab-*.jsonl"))
	if err != nil {
		t.Fatalf("parcours du journal: %v", err)
	}
	var lines []dnslab.JournalLine
	for _, path := range matches {
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("lecture %s: %v", path, err)
		}
		for row := range bytes.SplitSeq(payload, []byte{'\n'}) {
			if len(row) == 0 {
				continue
			}
			var line dnslab.JournalLine
			if err := json.Unmarshal(row, &line); err != nil {
				t.Fatalf("%s: JSON illisible: %v", path, err)
			}
			lines = append(lines, line)
		}
	}
	return lines
}

type runningDNS struct {
	conn    net.PacketConn
	client  *net.UDPConn
	cancel  context.CancelFunc
	errCh   <-chan error
	journal *dnslab.JournalWriter
	sport   uint16
}

func startServe(t *testing.T, zone *dnslab.Zone, limiter *dnslab.RateLimiter, journal *dnslab.JournalWriter) runningDNS {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("écoute: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = conn.Close()
	})
	serverAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("adresse d'écoute %T, attendu *net.UDPAddr", conn.LocalAddr())
	}
	client, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, serverAddr)
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	clientAddr, ok := client.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("adresse client %T", client.LocalAddr())
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- serveDNS(ctx, conn, zone, limiter, journal, func(dnslab.JournalLine) {})
	}()
	return runningDNS{
		conn:    conn,
		client:  client,
		cancel:  cancel,
		errCh:   errCh,
		journal: journal,
		sport:   uint16(clientAddr.Port),
	}
}

func stopServe(t *testing.T, run runningDNS) {
	t.Helper()
	run.cancel()
	err := waitServe(t, run.errCh)
	if err != nil {
		t.Fatalf("annulation: serveDNS a rendu %v, attendu nil", err)
	}
	if run.journal != nil {
		if err := run.journal.Close(); err != nil {
			t.Fatalf("Close journal: %v", err)
		}
	}
}

func TestServeDNS_JournalBeforeAnswerAndRRL(t *testing.T) {
	questions := loadRealQuestions(t)
	inA := mustFind(t, questions, zoneApex, 1, true)
	inTXT := mustFind(t, questions, zoneApex, 16, true)
	outA := mustFind(t, questions, "hazyhaar.fr", 1, false)
	exchanges := []struct {
		q       wireQuestion
		verdict dnslab.Verdict
	}{
		{inA, dnslab.VerdictAnswerA},
		{inTXT, dnslab.VerdictAnswerTXT},
		{outA, dnslab.VerdictRefused},
	}

	zone := labZone()
	dir := t.TempDir()
	instant := time.Date(2026, 10, 27, 11, 37, 17, 0, time.UTC)
	journal, jErr := dnslab.OpenJournal(dir, func() time.Time { return instant })
	if jErr != nil {
		journal = nil
	}
	limiter, limErr := dnslab.NewRateLimiter(50, 100, 1024)
	if limErr != nil {
		limiter = nil
	}
	run := startServe(t, &zone, limiter, journal)
	for i, ex := range exchanges {
		if _, err := run.client.Write(ex.q.payload); err != nil {
			t.Fatalf("envoi %d: %v", i, err)
		}
		got, err := readOne(t, run.client)
		want := expectResponse(ex.q, ex.verdict)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("question %s qtype %d: aucune réponse conforme (%v, %d octets reçus, %d attendus)", ex.q.qname, ex.q.qtype, err, len(got), len(want))
		}
	}
	stopServe(t, run)
	lines := journalLines(t, dir)
	if len(lines) != 3 {
		t.Fatalf("journal: %d lignes, attendu 3 dans l'ordre des questions", len(lines))
	}
	for i, ex := range exchanges {
		line := lines[i]
		want := expectResponse(ex.q, ex.verdict)
		if line.Source != "127.0.0.1" || line.SourcePort != run.sport || line.QName != ex.q.qname || line.QType != ex.q.qtype || line.Verdict == "" || line.Verdict != ex.verdict.String() || line.ResponseLen != uint16(len(want)) || line.RateLimited {
			t.Fatalf("ligne %d: src=%s sport=%d qname=%s qtype=%d verdict=%q resp_len=%d rrl=%v, attendu 127.0.0.1:%d %s qtype %d verdict %q resp_len %d", i, line.Source, line.SourcePort, line.QName, line.QType, line.Verdict, line.ResponseLen, line.RateLimited, run.sport, ex.q.qname, ex.q.qtype, ex.verdict.String(), len(want))
		}
	}

	rrlDir := t.TempDir()
	rrlJournal, rrlErr := dnslab.OpenJournal(rrlDir, func() time.Time { return instant })
	if rrlErr != nil || rrlJournal == nil {
		t.Fatalf("journal de rafale: %v", rrlErr)
	}
	rrlLimiter, rrlLimErr := dnslab.NewRateLimiter(1, 2, 1024)
	if rrlLimErr != nil || rrlLimiter == nil {
		t.Fatalf("limiteur de rafale: %v", rrlLimErr)
	}
	rrl := startServe(t, &zone, rrlLimiter, rrlJournal)
	for i := range 5 {
		if _, err := rrl.client.Write(inA.payload); err != nil {
			t.Fatalf("rafale envoi %d: %v", i, err)
		}
	}
	received := 0
	if err := rrl.client.SetReadDeadline(time.Now().Add(readBound)); err != nil {
		t.Fatalf("échéance de rafale: %v", err)
	}
	scratch := make([]byte, 512)
	for {
		n, err := rrl.client.Read(scratch)
		if err != nil {
			break
		}
		if n > 0 {
			received++
		}
	}
	if received > 2 {
		t.Fatalf("rafale: %d réponses, attendu au plus 2", received)
	}
	stopServe(t, rrl)
	rrlLines := journalLines(t, rrlDir)
	limited := 0
	for _, line := range rrlLines {
		if line.RateLimited {
			limited++
		}
	}
	if len(rrlLines) != 5 || limited != 3 || received != 2 {
		t.Fatalf("rafale: %d réponses, %d lignes dont %d rrl=true, attendu 2 réponses et 5 lignes dont 3 limitées", received, len(rrlLines), limited)
	}
}

func TestServeDNS_JournalErrorStopsLoop(t *testing.T) {
	questions := loadRealQuestions(t)
	apex := mustFind(t, questions, zoneApex, 1, true)
	dir := t.TempDir()
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Errorf("rétablissement du répertoire: %v", err)
		}
	})
	instant := time.Date(2026, 10, 27, 10, 59, 59, 0, time.UTC)
	journal, err := dnslab.OpenJournal(dir, func() time.Time { return instant })
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	if journal != nil {
		line := dnslab.JournalLine{TS: 1, Source: "127.0.0.1", QName: "lab.pound2pound.fr", QType: 1, QClass: 1, Verdict: "ignored"}
		if err := journal.Append(&line); err != nil {
			t.Fatalf("Append initial: %v", err)
		}
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	instant = time.Date(2026, 10, 27, 11, 0, 0, 0, time.UTC)
	zone := labZone()
	limiter, limErr := dnslab.NewRateLimiter(50, 100, 1024)
	if limErr != nil {
		limiter = nil
	}
	run := startServe(t, &zone, limiter, journal)
	if _, err := run.client.Write(apex.payload); err != nil {
		t.Fatalf("envoi: %v", err)
	}
	got, readErr := readOne(t, run.client)
	srvErr := waitServe(t, run.errCh)
	if readErr == nil {
		t.Fatalf("une réponse de %d octets a été émise pour la question dont le journal échoue", len(got))
	}
	if !errors.Is(srvErr, fs.ErrPermission) {
		t.Fatalf("serveDNS err=%v, attendu l'erreur du journal enveloppant fs.ErrPermission", srvErr)
	}
}
