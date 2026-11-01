package dnslab_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
)

type wireQuestion struct {
	record     uint32
	payload    []byte
	qsection   []byte
	qname      string
	qtype      uint16
	qclass     uint16
	flags      uint16
	id         uint16
	additional uint16
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

func expectedVerdict(q wireQuestion) dnslab.Verdict {
	if !inLabZone(q.qname) {
		return dnslab.VerdictRefused
	}
	switch q.qtype {
	case 1:
		return dnslab.VerdictAnswerA
	case 16:
		return dnslab.VerdictAnswerTXT
	default:
		return dnslab.VerdictNoData
	}
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
	rec := []byte{
		0xC0, 0x0C,
		0x00, 0x01,
		0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x04,
		0x0A, 0x37, 0x00, 0x01,
	}
	return rec
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

func expectResponse(id, queryFlags uint16, qsection []byte, verdict dnslab.Verdict) []byte {
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
	case dnslab.VerdictNotImp:
		rcode = 4
	case dnslab.VerdictFormErr:
		rcode = 1
	}
	ancount := uint16(0)
	if len(answer) > 0 {
		ancount = 1
	}
	out := make([]byte, dnsHeaderLen+len(qsection)+len(answer))
	binary.BigEndian.PutUint16(out[0:2], id)
	binary.BigEndian.PutUint16(out[2:4], responseFlags(queryFlags, authoritative, rcode))
	binary.BigEndian.PutUint16(out[4:6], 1)
	binary.BigEndian.PutUint16(out[6:8], ancount)
	copy(out[dnsHeaderLen:], qsection)
	copy(out[dnsHeaderLen+len(qsection):], answer)
	return out
}

func expectFromPayload(payload []byte, verdict dnslab.Verdict) []byte {
	end, ok := questionSectionEnd(payload)
	if !ok {
		return nil
	}
	return expectResponse(
		binary.BigEndian.Uint16(payload[0:2]),
		binary.BigEndian.Uint16(payload[2:4]),
		payload[dnsHeaderLen:end],
		verdict,
	)
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

func wireNameLower(name []byte) string {
	var bld strings.Builder
	for i := 0; i < len(name); {
		labelLen := int(name[i])
		if labelLen == 0 || i+1+labelLen > len(name) {
			break
		}
		if bld.Len() > 0 {
			bld.WriteByte('.')
		}
		for _, char := range name[i+1 : i+1+labelLen] {
			if char >= 'A' && char <= 'Z' {
				char += 32
			}
			bld.WriteByte(char)
		}
		i += 1 + labelLen
	}
	return bld.String()
}

func clonePayload(payload []byte) []byte {
	return append([]byte(nil), payload...)
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
	linkType := binary.LittleEndian.Uint32(capture[20:24])
	if linkType != 276 {
		t.Fatalf("type de lien %d, attendu 276", linkType)
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
		packet := capture[packetOff : packetOff+incl]
		if payload, ok := udp53Payload(packet); ok {
			indexed[record] = append([]byte(nil), payload...)
		}
		cursor = packetOff + incl
	}
	if cursor != len(capture) {
		t.Fatalf("capture réelle: %d octets après le dernier enregistrement complet", len(capture)-cursor)
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
		if ev == nil {
			t.Fatalf("visiteur appelé avec un événement nul")
		}
		payload, ok := indexed[meta.Record]
		if !ok {
			t.Fatalf("enregistrement %d absent du mini-lecteur", meta.Record)
		}
		end, ok := questionSectionEnd(payload)
		if !ok {
			t.Fatalf("section question illisible, enregistrement %d", meta.Record)
		}
		lower := wireNameLower(payload[dnsHeaderLen : end-4])
		if lower != ev.FQDN() {
			t.Fatalf("enregistrement %d: nom fil %q, FQDN %q", meta.Record, lower, ev.FQDN())
		}
		if binary.BigEndian.Uint16(payload[end-4:end-2]) != ev.QType {
			t.Fatalf("enregistrement %d: type fil %d, événement %d", meta.Record, binary.BigEndian.Uint16(payload[end-4:end-2]), ev.QType)
		}
		questions = append(questions, wireQuestion{
			record:     meta.Record,
			payload:    payload,
			qsection:   append([]byte(nil), payload[dnsHeaderLen:end]...),
			qname:      strings.Clone(ev.FQDN()),
			qtype:      ev.QType,
			qclass:     ev.QClass,
			flags:      ev.Flags,
			id:         ev.ID,
			additional: binary.BigEndian.Uint16(payload[10:12]),
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

func mustFind(t *testing.T, questions []wireQuestion, qname string, qtype uint16) wireQuestion {
	t.Helper()
	for _, q := range questions {
		if q.qname == qname && q.qtype == qtype {
			return q
		}
	}
	t.Fatalf("question absente de la capture: %s qtype %d", qname, qtype)
	return wireQuestion{}
}

func labelCountOf(qname string) int {
	if qname == "" {
		return 0
	}
	return strings.Count(qname, ".") + 1
}

func maxLabelLenOf(qname string) int {
	maxLen := 0
	for label := range strings.SplitSeq(qname, ".") {
		if len(label) > maxLen {
			maxLen = len(label)
		}
	}
	return maxLen
}

func firstDiff(got, want []byte) int {
	n := min(len(got), len(want))
	for i := range n {
		if got[i] != want[i] {
			return i
		}
	}
	return n
}

func TestBuildResponse_RealQuestionsVerdicts(t *testing.T) {
	questions := loadRealQuestions(t)
	var wantA, wantTXT, wantNoData, wantRefused, withAdditional int
	for _, q := range questions {
		switch expectedVerdict(q) {
		case dnslab.VerdictAnswerA:
			wantA++
		case dnslab.VerdictAnswerTXT:
			wantTXT++
		case dnslab.VerdictNoData:
			wantNoData++
		case dnslab.VerdictRefused:
			wantRefused++
		}
		if q.additional > 0 {
			withAdditional++
		}
	}
	if wantA != 20 || wantTXT != 6 || wantNoData != 7 || wantRefused != 36 {
		t.Fatalf("oracle terrain incohérent: A=%d TXT=%d NODATA=%d REFUSED=%d", wantA, wantTXT, wantNoData, wantRefused)
	}
	if withAdditional == 0 {
		t.Fatal("aucune question réelle ne porte de section additionnelle: le rejet d'OPT ne serait pas éprouvé")
	}

	zone := labZone()
	var hits [8]int
	shown := 0
	for _, q := range questions {
		wantVerdict := expectedVerdict(q)
		want := expectResponse(q.id, q.flags, q.qsection, wantVerdict)
		if len(want) >= 512 {
			t.Fatalf("attente >= 512 pour %s: l'oracle est faux", q.qname)
		}
		response := make([]byte, 512)
		for i := range response {
			response[i] = 0xA5
		}
		n, decision, err := dnslab.BuildResponse(q.payload, &zone, response)
		if n >= 0 && n <= len(response) {
			hits[decision.Verdict]++
		}
		gotName := ""
		if decision.QNameLen > 0 {
			gotName = string(decision.QName[:decision.QNameLen])
		}
		matched := err == nil && n == len(want) && n < 512 && decision.Verdict == wantVerdict && decision.RCode == want[3] && decision.QType == q.qtype && decision.QClass == q.qclass && gotName == q.qname && decision.InZone == inLabZone(q.qname) && int(decision.LabelCount) == labelCountOf(q.qname) && int(decision.MaxLabelLen) == maxLabelLenOf(q.qname) && bytes.Equal(response[:n], want) && bytes.Equal(response[n:], bytes.Repeat([]byte{0xA5}, len(response)-n))
		if !matched {
			if shown < 4 {
				gotN := 0
				if n > 0 && n <= len(response) {
					gotN = n
				}
				t.Errorf("enregistrement %d %s qtype %d: n=%d verdict=%d rcode=%d qname=%q inZone=%v, attendu n=%d verdict=%d qname=%q", q.record, q.qname, q.qtype, gotN, decision.Verdict, decision.RCode, gotName, decision.InZone, len(want), wantVerdict, q.qname)
				if n > 0 && n <= len(response) {
					t.Errorf("enregistrement %d: premier écart à l'octet %d", q.record, firstDiff(response[:n], want))
				}
				shown++
			}
			continue
		}
		if !bytes.Equal(response[dnsHeaderLen:dnsHeaderLen+len(q.qsection)], q.qsection) {
			t.Errorf("enregistrement %d: section question non recopiée", q.record)
		}
		if binary.BigEndian.Uint16(response[10:12]) != 0 {
			t.Errorf("enregistrement %d: ARCOUNT=%d, attendu 0", q.record, binary.BigEndian.Uint16(response[10:12]))
		}
	}
	if hits[dnslab.VerdictAnswerA] != 20 || hits[dnslab.VerdictAnswerTXT] != 6 || hits[dnslab.VerdictNoData] != 7 || hits[dnslab.VerdictRefused] != 36 {
		t.Fatalf("écart fonctionnel: comptes par verdict A=%d TXT=%d NODATA=%d REFUSED=%d, attendu 20, 6, 7, 36", hits[dnslab.VerdictAnswerA], hits[dnslab.VerdictAnswerTXT], hits[dnslab.VerdictNoData], hits[dnslab.VerdictRefused])
	}
}

func TestBuildResponse_ZeroAlloc(t *testing.T) {
	questions := loadRealQuestions(t)
	var sample wireQuestion
	found := false
	for _, q := range questions {
		if q.qtype == 1 && inLabZone(q.qname) {
			sample = q
			found = true
			break
		}
	}
	if !found {
		t.Fatal("aucune question A en zone dans la capture réelle")
	}
	zone := labZone()
	want := expectResponse(sample.id, sample.flags, sample.qsection, dnslab.VerdictAnswerA)
	response := make([]byte, 512)
	n, decision, err := dnslab.BuildResponse(sample.payload, &zone, response)
	if err != nil || n <= 0 || n > len(response) || decision.Verdict != dnslab.VerdictAnswerA || !bytes.Equal(response[:n], want) {
		t.Fatalf("écart fonctionnel: n=%d verdict=%d err=%v, attendu une réponse A de %d octets", n, decision.Verdict, err, len(want))
	}
	allocs := testing.AllocsPerRun(1000, func() {
		_, _, _ = dnslab.BuildResponse(sample.payload, &zone, response)
	})
	if allocs != 0 {
		t.Fatalf("BuildResponse alloue %v fois par appel, attendu 0", allocs)
	}
}

func assertFormErr(t *testing.T, question []byte, zone *dnslab.Zone) {
	t.Helper()
	response := make([]byte, 512)
	n, decision, err := dnslab.BuildResponse(question, zone, response)
	if err != nil {
		t.Fatalf("erreur %v, attendu FORMERR sans erreur de lecture", err)
	}
	if n <= 0 || n >= 512 {
		t.Fatalf("n=%d, attendu une réponse FORMERR de longueur positive et inférieure à 512", n)
	}
	if decision.Verdict != dnslab.VerdictFormErr || decision.RCode != 1 {
		t.Fatalf("verdict=%d rcode=%d, attendu FORMERR et rcode 1", decision.Verdict, decision.RCode)
	}
	if binary.BigEndian.Uint16(response[0:2]) != binary.BigEndian.Uint16(question[0:2]) {
		t.Fatalf("ID=%d, attendu %d", binary.BigEndian.Uint16(response[0:2]), binary.BigEndian.Uint16(question[0:2]))
	}
	flags := binary.BigEndian.Uint16(response[2:4])
	if flags&0x8000 == 0 || flags&0x000F != 1 || flags&0x0400 != 0 {
		t.Fatalf("flags=%04x, attendu QR=1 AA=0 rcode=1", flags)
	}
}

func assertWire(t *testing.T, question []byte, zone *dnslab.Zone, verdict dnslab.Verdict) dnslab.Decision {
	t.Helper()
	want := expectFromPayload(question, verdict)
	if want == nil || len(want) >= 512 {
		t.Fatalf("oracle de réponse inutilisable (%d octets)", len(want))
	}
	response := make([]byte, 512)
	n, decision, err := dnslab.BuildResponse(question, zone, response)
	if err != nil || n != len(want) || !bytes.Equal(response[:min(max(n, 0), len(response))], want) || decision.Verdict != verdict {
		got := 0
		if n > 0 && n <= len(response) {
			got = n
		}
		t.Fatalf("écart fonctionnel: n=%d verdict=%d err=%v, attendu n=%d verdict=%d (premier écart %d)", got, decision.Verdict, err, len(want), verdict, firstDiff(response[:got], want))
	}
	return decision
}

func withQType(payload []byte, qtype uint16) []byte {
	end, ok := questionSectionEnd(payload)
	if !ok {
		return nil
	}
	mutated := clonePayload(payload)
	binary.BigEndian.PutUint16(mutated[end-4:end-2], qtype)
	return mutated
}

func withQClass(payload []byte, qclass uint16) []byte {
	end, ok := questionSectionEnd(payload)
	if !ok {
		return nil
	}
	mutated := clonePayload(payload)
	binary.BigEndian.PutUint16(mutated[end-2:end], qclass)
	return mutated
}

func withOpcode(payload []byte, opcode uint16) []byte {
	mutated := clonePayload(payload)
	flags := binary.BigEndian.Uint16(mutated[2:4])
	flags = (flags &^ 0x7800) | (opcode << 11)
	binary.BigEndian.PutUint16(mutated[2:4], flags)
	return mutated
}

func withNameWire(header []byte, nameWire []byte, qtype, qclass uint16) []byte {
	packet := make([]byte, dnsHeaderLen+len(nameWire)+4)
	copy(packet, header[:dnsHeaderLen])
	binary.BigEndian.PutUint16(packet[10:12], 0)
	copy(packet[dnsHeaderLen:], nameWire)
	off := dnsHeaderLen + len(nameWire)
	binary.BigEndian.PutUint16(packet[off:off+2], qtype)
	binary.BigEndian.PutUint16(packet[off+2:off+4], qclass)
	return packet
}

func nameWire300() []byte {
	wire := make([]byte, 0, 300)
	for range 4 {
		wire = append(wire, 63)
		wire = append(wire, bytes.Repeat([]byte{'a'}, 63)...)
	}
	wire = append(wire, 42)
	wire = append(wire, bytes.Repeat([]byte{'b'}, 42)...)
	wire = append(wire, 0)
	return wire
}

func nameWireLabel64() []byte {
	wire := make([]byte, 0, 66)
	wire = append(wire, 64)
	wire = append(wire, bytes.Repeat([]byte{'c'}, 64)...)
	wire = append(wire, 0)
	return wire
}

func uppercaseLabels(payload []byte) []byte {
	mutated := clonePayload(payload)
	cursor := dnsHeaderLen
	for cursor < len(mutated) {
		labelLen := int(mutated[cursor])
		if labelLen == 0 || labelLen > 63 || cursor+1+labelLen > len(mutated) {
			break
		}
		for i := 1; i <= labelLen; i++ {
			if mutated[cursor+i] >= 'a' && mutated[cursor+i] <= 'z' {
				mutated[cursor+i] -= 32
			}
		}
		cursor += 1 + labelLen
	}
	return mutated
}

func withFirstLabel(payload []byte, label string) []byte {
	first := int(payload[dnsHeaderLen])
	rest := payload[dnsHeaderLen+1+first:]
	packet := make([]byte, 0, dnsHeaderLen+1+len(label)+len(rest))
	packet = append(packet, payload[:dnsHeaderLen]...)
	packet = append(packet, byte(len(label)))
	packet = append(packet, label...)
	packet = append(packet, rest...)
	return packet
}

func TestBuildResponse_HostileForms(t *testing.T) {
	questions := loadRealQuestions(t)
	apex := mustFind(t, questions, zoneApex, 1)
	hazy := mustFind(t, questions, "hazyhaar.fr", 1)
	zone := labZone()

	t.Run("pointeur_compression", func(t *testing.T) {
		mutated := clonePayload(apex.payload)
		mutated[dnsHeaderLen] = 0xC0
		mutated[dnsHeaderLen+1] = 0x0C
		assertFormErr(t, mutated, &zone)
	})
	t.Run("qdcount_2", func(t *testing.T) {
		mutated := clonePayload(apex.payload)
		binary.BigEndian.PutUint16(mutated[4:6], 2)
		assertFormErr(t, mutated, &zone)
	})
	t.Run("nom_300", func(t *testing.T) {
		wire := nameWire300()
		if len(wire) != 300 {
			t.Fatalf("nom de contrôle: %d octets, attendu 300", len(wire))
		}
		assertFormErr(t, withNameWire(apex.payload, wire, apex.qtype, apex.qclass), &zone)
	})
	t.Run("label_64", func(t *testing.T) {
		assertFormErr(t, withNameWire(apex.payload, nameWireLabel64(), apex.qtype, apex.qclass), &zone)
	})
	t.Run("qr_positionne", func(t *testing.T) {
		mutated := clonePayload(apex.payload)
		mutated[2] |= 0x80
		response := make([]byte, 512)
		n, decision, err := dnslab.BuildResponse(mutated, &zone, response)
		if !errors.Is(err, dnslab.ErrNotAQuery) || n != 0 || decision.Verdict != dnslab.VerdictIgnored {
			t.Fatalf("QR=1: n=%d verdict=%d err=%v, attendu n=0 VerdictIgnored et ErrNotAQuery", n, decision.Verdict, err)
		}
	})
	t.Run("onze_octets", func(t *testing.T) {
		short := clonePayload(apex.payload[:11])
		response := make([]byte, 512)
		n, decision, err := dnslab.BuildResponse(short, &zone, response)
		if !errors.Is(err, dnslab.ErrQueryTooShort) || n != 0 || decision.Verdict != dnslab.VerdictIgnored {
			t.Fatalf("11 octets: n=%d verdict=%d err=%v, attendu n=0 VerdictIgnored et ErrQueryTooShort", n, decision.Verdict, err)
		}
	})
	t.Run("opcode_2", func(t *testing.T) {
		assertWire(t, withOpcode(apex.payload, 2), &zone, dnslab.VerdictNotImp)
	})
	t.Run("qtype_255", func(t *testing.T) {
		assertWire(t, withQType(apex.payload, 255), &zone, dnslab.VerdictNotImp)
	})
	t.Run("qtype_252", func(t *testing.T) {
		assertWire(t, withQType(apex.payload, 252), &zone, dnslab.VerdictRefused)
	})
	t.Run("qtype_251", func(t *testing.T) {
		assertWire(t, withQType(apex.payload, 251), &zone, dnslab.VerdictRefused)
	})
	t.Run("qclass_3", func(t *testing.T) {
		assertWire(t, withQClass(apex.payload, 3), &zone, dnslab.VerdictRefused)
	})
	t.Run("hazyhaar_majuscule", func(t *testing.T) {
		mutated := uppercaseLabels(hazy.payload)
		decision := assertWire(t, mutated, &zone, dnslab.VerdictRefused)
		gotName := ""
		if decision.QNameLen > 0 {
			gotName = string(decision.QName[:decision.QNameLen])
		}
		if gotName != "hazyhaar.fr" {
			t.Fatalf("QName=%q, attendu hazyhaar.fr", gotName)
		}
		end, ok := questionSectionEnd(mutated)
		if !ok {
			t.Fatal("variante majuscule illisible")
		}
		response := expectFromPayload(mutated, dnslab.VerdictRefused)
		if !bytes.Equal(response[dnsHeaderLen:end], mutated[dnsHeaderLen:end]) {
			t.Fatal("l'attente ne conserve pas la casse de la question")
		}
		if bytes.Contains(mutated[dnsHeaderLen:end], []byte("hazyhaar")) {
			t.Fatal("la variante n'est pas en majuscules")
		}
	})
	t.Run("apex_exact", func(t *testing.T) {
		decision := assertWire(t, apex.payload, &zone, dnslab.VerdictAnswerA)
		if !decision.InZone {
			t.Fatal("l'apex exact n'est pas reconnu en zone")
		}
		want := expectFromPayload(apex.payload, dnslab.VerdictAnswerA)
		answer := want[len(want)-16:]
		if !bytes.Equal(answer, answerARecord()) {
			t.Fatalf("enregistrement A %x, attendu %x", answer, answerARecord())
		}
	})
	t.Run("suffixe_sans_point", func(t *testing.T) {
		mutated := withFirstLabel(apex.payload, "xlab")
		decision := assertWire(t, mutated, &zone, dnslab.VerdictRefused)
		gotName := ""
		if decision.QNameLen > 0 {
			gotName = string(decision.QName[:decision.QNameLen])
		}
		if gotName != "xlab.pound2pound.fr" || decision.InZone {
			t.Fatalf("QName=%q inZone=%v, attendu xlab.pound2pound.fr hors zone", gotName, decision.InZone)
		}
	})
	t.Run("tampon_511", func(t *testing.T) {
		scratch := bytes.Repeat([]byte{0xA5}, 511)
		before := clonePayload(scratch)
		n, _, err := dnslab.BuildResponse(apex.payload, &zone, scratch)
		if !errors.Is(err, dnslab.ErrResponseBufferTooSmall) || n != 0 {
			t.Fatalf("tampon 511: n=%d err=%v, attendu n=0 et ErrResponseBufferTooSmall", n, err)
		}
		if !bytes.Equal(scratch, before) {
			t.Fatal("tampon 511: écriture malgré le refus")
		}
	})
}

func TestNewZone_Refusals(t *testing.T) {
	answerA := [4]byte{10, 55, 0, 1}
	cases := []struct {
		name string
		apex string
		text string
	}{
		{"apex_vide", "", "canary"},
		{"txt_256", zoneApex, strings.Repeat("t", 256)},
		{"label_64", strings.Repeat("a", 64), "canary"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := dnslab.NewZone(tc.apex, answerA, tc.text, 0)
			if !errors.Is(err, dnslab.ErrZoneContract) {
				t.Fatalf("erreur=%v, attendu ErrZoneContract", err)
			}
		})
	}
	t.Run("apex_en_minuscules", func(t *testing.T) {
		zone, err := dnslab.NewZone("Lab.Pound2Pound.FR", answerA, answerTXTText, 0)
		if err != nil {
			t.Fatalf("zone valide refusée: %v", err)
		}
		if string(zone.Apex) != zoneApex {
			t.Fatalf("Apex=%q, attendu %s", zone.Apex, zoneApex)
		}
		if zone.AnswerA != answerA || string(zone.AnswerTXT) != answerTXTText || zone.TTL != 0 {
			t.Fatalf("zone=%+v, réponses ou TTL non conservés", zone)
		}
	})
	t.Run("txt_255_accepte", func(t *testing.T) {
		text := strings.Repeat("u", 255)
		zone, err := dnslab.NewZone(zoneApex, answerA, text, 30)
		if err != nil {
			t.Fatalf("TXT de 255 octets refusé: %v", err)
		}
		if string(zone.AnswerTXT) != text {
			t.Fatalf("AnswerTXT longueur %d, attendu 255", len(zone.AnswerTXT))
		}
	})
}
