package c2blue55_test

import (
	"encoding/binary"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hazyhaar/c2blue55"
)

const (
	pcapGlobalLen       = 24
	pcapRecordLen       = 16
	sll2HeaderLen       = 20
	dnsHeaderLen        = 12
	udpHeaderLen        = 8
	firstQuestionRecord = 1
	firstQuestionPort   = 38498
	firstQuestionStamp  = 1793101037220066
	realPCAPName        = "local-dns-20261027T113715Z.pcap"
	realManifestName    = "local-dns-20261027T113715Z.manifest.json"
)

type terrainCouple struct {
	occurrences int
	fqdn        string
	qtype       uint16
	sub         string
	parent      string
	sld         string
	tld         string
	labelCount  uint8
	maxLabelLen uint8
	hasEncoding bool
}

type coupleKey struct {
	fqdn  string
	qtype uint16
}

type pcapSpan struct {
	index     uint32
	headerOff int
	packetOff int
	inclLen   uint32
	origLen   uint32
	timestamp uint64
}

type recordSink struct {
	records []uint32
}

var terrainCouples = []terrainCouple{
	{1, "hazyhaar.fr", 2, "", "hazyhaar.fr", "hazyhaar", "fr", 2, 8, false},
	{1, "pound2pound.fr", 1, "", "pound2pound.fr", "pound2pound", "fr", 2, 11, false},
	{1, "pound2pound.fr", 2, "", "pound2pound.fr", "pound2pound", "fr", 2, 11, false},
	{2, "fcteucqacmalnaiwlgubgjv7lw6ykjmerb9xu9ecaybvc0z7fghqa.t.lab.pound2pound.fr", 16, "fcteucqacmalnaiwlgubgjv7lw6ykjmerb9xu9ecaybvc0z7fghqa.t.lab", "pound2pound.fr", "pound2pound", "fr", 5, 53, false},
	{2, "hazyhaar.fr", 15, "", "hazyhaar.fr", "hazyhaar", "fr", 2, 8, false},
	{2, "hazyhaar.fr", 1, "", "hazyhaar.fr", "hazyhaar", "fr", 2, 8, false},
	{2, "lab.pound2pound.fr", 15, "lab", "pound2pound.fr", "pound2pound", "fr", 3, 11, false},
	{2, "lab.pound2pound.fr", 1, "lab", "pound2pound.fr", "pound2pound", "fr", 3, 11, false},
	{2, "lab.pound2pound.fr", 2, "lab", "pound2pound.fr", "pound2pound", "fr", 3, 11, false},
	{2, "pound2pound.fr", 15, "", "pound2pound.fr", "pound2pound", "fr", 2, 11, false},
	{2, "probe-3-jo6im5xkqi27s2zhsml3viptjqbwg34b2xetr6y.lab.pound2pound.fr", 1, "probe-3-jo6im5xkqi27s2zhsml3viptjqbwg34b2xetr6y.lab", "pound2pound.fr", "pound2pound", "fr", 4, 47, false},
	{2, "probe-4-gu2dtyncdhrca4awargiwfpfkktvplj47bmiuli.lab.pound2pound.fr", 1, "probe-4-gu2dtyncdhrca4awargiwfpfkktvplj47bmiuli.lab", "pound2pound.fr", "pound2pound", "fr", 4, 47, false},
	{2, "www.hazyhaar.fr", 15, "www", "hazyhaar.fr", "hazyhaar", "fr", 3, 8, false},
	{2, "www.hazyhaar.fr", 1, "www", "hazyhaar.fr", "hazyhaar", "fr", 3, 8, false},
	{2, "www.hazyhaar.fr", 2, "www", "hazyhaar.fr", "hazyhaar", "fr", 3, 8, false},
	{3, "hazyhaar.fr", 28, "", "hazyhaar.fr", "hazyhaar", "fr", 2, 8, false},
	{3, "lab.pound2pound.fr", 28, "lab", "pound2pound.fr", "pound2pound", "fr", 3, 11, false},
	{3, "pound2pound.fr", 28, "", "pound2pound.fr", "pound2pound", "fr", 2, 11, false},
	{3, "probe-1-omi23y5l2lltcrbvqya6jeom22g3wxca4kdxzny.lab.pound2pound.fr", 1, "probe-1-omi23y5l2lltcrbvqya6jeom22g3wxca4kdxzny.lab", "pound2pound.fr", "pound2pound", "fr", 4, 47, false},
	{3, "probe-5-gnh3cd23tsgzjz44ba24mbs2fsliwchyj5klp6q.lab.pound2pound.fr", 1, "probe-5-gnh3cd23tsgzjz44ba24mbs2fsliwchyj5klp6q.lab", "pound2pound.fr", "pound2pound", "fr", 4, 47, false},
	{3, "www.hazyhaar.fr", 28, "www", "hazyhaar.fr", "hazyhaar", "fr", 3, 8, false},
	{4, "hazyhaar.fr", 16, "", "hazyhaar.fr", "hazyhaar", "fr", 2, 8, false},
	{4, "lab.pound2pound.fr", 16, "lab", "pound2pound.fr", "pound2pound", "fr", 3, 11, false},
	{4, "pound2pound.fr", 16, "", "pound2pound.fr", "pound2pound", "fr", 2, 11, false},
	{4, "probe-2-3ertutpjrmp7ujxf5o6xu7zegy2dnwwd3kc7zia.lab.pound2pound.fr", 1, "probe-2-3ertutpjrmp7ujxf5o6xu7zegy2dnwwd3kc7zia.lab", "pound2pound.fr", "pound2pound", "fr", 4, 47, false},
	{4, "probe-6-4dxnddw7p74v4h4twfqfgtiw7ct2cpejpx7dddq.lab.pound2pound.fr", 1, "probe-6-4dxnddw7p74v4h4twfqfgtiw7ct2cpejpx7dddq.lab", "pound2pound.fr", "pound2pound", "fr", 4, 47, false},
	{4, "www.hazyhaar.fr", 16, "www", "hazyhaar.fr", "hazyhaar", "fr", 3, 8, false},
}

func (s *recordSink) visit(meta c2blue55.PCAPQuestionMeta, _ *c2blue55.DNSEvent) error {
	s.records = append(s.records, meta.Record)
	return nil
}

func (s *recordSink) saw(record uint32) bool {
	return slices.Contains(s.records, record)
}

func expectedRealStats() c2blue55.PCAPIngestStats {
	return c2blue55.PCAPIngestStats{
		Records:      156,
		LinkType:     276,
		UDPQuestions: 69,
		UDPResponses: 51,
		TCPSegments:  36,
		Accepted:     69,
	}
}

func packIPv4(a, b, c, d byte) [16]byte {
	var addr [16]byte
	addr[0], addr[1], addr[2], addr[3] = a, b, c, d
	return addr
}

func rejectedSum(stats c2blue55.PCAPIngestStats) uint32 {
	return stats.RejectedTooShort + stats.RejectedInvalidLabel + stats.RejectedLoopPointer + stats.RejectedNameTooLong + stats.RejectedContract
}

func validateTerrain(t *testing.T) {
	t.Helper()
	if len(terrainCouples) != 27 {
		t.Fatalf("table terrain: %d couples, attendu 27", len(terrainCouples))
	}
	var sum int
	seen := make(map[coupleKey]struct{}, len(terrainCouples))
	shapes := make(map[string]terrainCouple, len(terrainCouples))
	for _, couple := range terrainCouples {
		sum += couple.occurrences
		key := coupleKey{couple.fqdn, couple.qtype}
		if _, ok := seen[key]; ok {
			t.Fatalf("couple dupliqué: %s qtype %d", couple.fqdn, couple.qtype)
		}
		seen[key] = struct{}{}
		if prev, ok := shapes[couple.fqdn]; ok {
			if prev.sub != couple.sub || prev.parent != couple.parent || prev.sld != couple.sld || prev.tld != couple.tld || prev.labelCount != couple.labelCount || prev.maxLabelLen != couple.maxLabelLen || prev.hasEncoding != couple.hasEncoding {
				t.Fatalf("forme incohérente pour %s", couple.fqdn)
			}
		}
		shapes[couple.fqdn] = couple
		parts := strings.Split(couple.fqdn, ".")
		if len(parts) != int(couple.labelCount) {
			t.Fatalf("LabelCount incohérent pour %s", couple.fqdn)
		}
		maxLen := 0
		for _, part := range parts {
			if len(part) > maxLen {
				maxLen = len(part)
			}
		}
		if maxLen != int(couple.maxLabelLen) {
			t.Fatalf("MaxLabelLen incohérent pour %s: %d != %d", couple.fqdn, maxLen, couple.maxLabelLen)
		}
		if couple.parent != couple.sld+"."+couple.tld {
			t.Fatalf("parent incohérent pour %s", couple.fqdn)
		}
		if couple.sub == "" {
			if couple.fqdn != couple.parent {
				t.Fatalf("apex incohérent pour %s", couple.fqdn)
			}
		} else if !strings.HasPrefix(couple.fqdn, couple.sub+".") {
			t.Fatalf("sous-domaine incohérent pour %s", couple.fqdn)
		}
	}
	if sum != 69 {
		t.Fatalf("somme des occurrences %d, attendu 69", sum)
	}
}

func terrainCounts() map[coupleKey]int {
	out := make(map[coupleKey]int, len(terrainCouples))
	for _, couple := range terrainCouples {
		out[coupleKey{couple.fqdn, couple.qtype}] = couple.occurrences
	}
	return out
}

func terrainShape(fqdn string) (terrainCouple, bool) {
	for _, couple := range terrainCouples {
		if couple.fqdn == fqdn {
			return couple, true
		}
	}
	return terrainCouple{}, false
}

func subCardinalityForParent(parent string) (uint32, bool) {
	switch parent {
	case "hazyhaar.fr":
		return 2, true
	case "pound2pound.fr":
		return 9, true
	default:
		return 0, false
	}
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

func realLabPaths(t *testing.T) (pcapPath, manifestPath string) {
	t.Helper()
	lab := redhostLabDir(t)
	pcapPath = filepath.Join(lab, realPCAPName)
	manifestPath = filepath.Join(lab, realManifestName)
	if _, err := os.Stat(pcapPath); err != nil {
		t.Fatalf("capture réelle introuvable: %v", err)
	}
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("manifeste réel introuvable: %v", err)
	}
	return pcapPath, manifestPath
}

func readRealCapture(t *testing.T) (pcapPath string, capture []byte) {
	t.Helper()
	pcapPath, _ = realLabPaths(t)
	var err error
	capture, err = os.ReadFile(pcapPath)
	if err != nil {
		t.Fatalf("lecture de la capture réelle: %v", err)
	}
	return pcapPath, capture
}

func writeTempBytes(t *testing.T, name string, payload []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatalf("écriture de %s: %v", name, err)
	}
	return path
}

func walkPCAP(t *testing.T, capture []byte) (linkType uint32, spans []pcapSpan) {
	t.Helper()
	if len(capture) < pcapGlobalLen {
		t.Fatalf("capture plus courte que l'en-tête global: %d", len(capture))
	}
	magic := binary.LittleEndian.Uint32(capture[0:4])
	if magic != 0xa1b2c3d4 && magic != 0xa1b23c4d {
		t.Fatalf("magic pcap réel inattendu: %#x", magic)
	}
	linkType = binary.LittleEndian.Uint32(capture[20:24])
	cursor := pcapGlobalLen
	for cursor+pcapRecordLen <= len(capture) {
		tsSec := binary.LittleEndian.Uint32(capture[cursor : cursor+4])
		tsFrac := binary.LittleEndian.Uint32(capture[cursor+4 : cursor+8])
		incl := binary.LittleEndian.Uint32(capture[cursor+8 : cursor+12])
		orig := binary.LittleEndian.Uint32(capture[cursor+12 : cursor+16])
		packetOff := cursor + pcapRecordLen
		if int(incl) > len(capture)-packetOff {
			t.Fatalf("capture réelle incomplète à l'enregistrement %d", len(spans)+1)
		}
		usec := uint64(tsFrac)
		if magic == 0xa1b23c4d {
			usec /= 1000
		}
		spans = append(spans, pcapSpan{
			index:     uint32(len(spans) + 1),
			headerOff: cursor,
			packetOff: packetOff,
			inclLen:   incl,
			origLen:   orig,
			timestamp: uint64(tsSec)*1_000_000 + usec,
		})
		cursor = packetOff + int(incl)
	}
	if cursor != len(capture) {
		t.Fatalf("capture réelle: %d octets après le dernier enregistrement complet", len(capture)-cursor)
	}
	return linkType, spans
}

func udpQuestionDNSOffset(packet []byte) (dnsOff int, sport uint16, question bool) {
	if len(packet) < sll2HeaderLen+20 {
		return 0, 0, false
	}
	network := packet[sll2HeaderLen:]
	if network[0]>>4 != 4 {
		return 0, 0, false
	}
	ihl := int(network[0]&0x0f) * 4
	if ihl < 20 || len(network) < ihl+udpHeaderLen {
		return 0, 0, false
	}
	if network[9] != 17 {
		return 0, 0, false
	}
	fragField := binary.BigEndian.Uint16(network[6:8])
	if fragField&0x1fff != 0 {
		return 0, 0, false
	}
	sport = binary.BigEndian.Uint16(network[ihl : ihl+2])
	dport := binary.BigEndian.Uint16(network[ihl+2 : ihl+4])
	if dport != 53 {
		return 0, sport, false
	}
	return sll2HeaderLen + ihl + udpHeaderLen, sport, true
}

func locateFirstUDPQuestion(t *testing.T, capture []byte) (pcapSpan, int) {
	t.Helper()
	linkType, spans := walkPCAP(t, capture)
	if linkType != 276 {
		t.Fatalf("type de lien réel %d, attendu 276 pour localiser UDP/53", linkType)
	}
	for _, span := range spans {
		packet := capture[span.packetOff : span.packetOff+int(span.inclLen)]
		dnsOff, sport, question := udpQuestionDNSOffset(packet)
		if !question {
			continue
		}
		if span.index != firstQuestionRecord || sport != firstQuestionPort {
			t.Fatalf("première question UDP/53: enregistrement %d port %d, attendu %d et %d", span.index, sport, firstQuestionRecord, firstQuestionPort)
		}
		qnameAt := span.packetOff + dnsOff + dnsHeaderLen
		if qnameAt+2 > len(capture) || capture[qnameAt] == 0 || capture[qnameAt] > 63 {
			t.Fatalf("QNAME de la première question illisible à l'offset %d", qnameAt)
		}
		return span, dnsOff
	}
	t.Fatal("aucune question UDP/53 dans la capture réelle")
	return pcapSpan{}, 0
}

func withOrigLenBumped(t *testing.T, capture []byte) ([]byte, uint32) {
	t.Helper()
	span, _ := locateFirstUDPQuestion(t, capture)
	if span.origLen != span.inclLen {
		t.Fatalf("premier UDP/53 déjà tronqué: orig=%d incl=%d", span.origLen, span.inclLen)
	}
	mutated := append([]byte(nil), capture...)
	binary.LittleEndian.PutUint32(mutated[span.headerOff+12:span.headerOff+16], span.inclLen+1)
	return mutated, span.index
}

func withLoopPointer(t *testing.T, capture []byte) ([]byte, uint32) {
	t.Helper()
	span, dnsOff := locateFirstUDPQuestion(t, capture)
	qnameAt := span.packetOff + dnsOff + dnsHeaderLen
	mutated := append([]byte(nil), capture...)
	mutated[qnameAt] = 0xC0
	mutated[qnameAt+1] = 0x0C
	return mutated, span.index
}

func prefixCapture(t *testing.T, capture []byte, n int) []byte {
	t.Helper()
	_, spans := walkPCAP(t, capture)
	if len(spans) < n {
		t.Fatalf("capture réelle: %d enregistrements, préfixe %d impossible", len(spans), n)
	}
	end := spans[n-1].packetOff + int(spans[n-1].inclLen)
	return append([]byte(nil), capture[:end]...)
}

func cutMidLastHeader(t *testing.T, capture []byte) []byte {
	t.Helper()
	_, spans := walkPCAP(t, capture)
	last := spans[len(spans)-1]
	cut := last.headerOff + pcapRecordLen/2
	return append([]byte(nil), capture[:cut]...)
}

func lastRecordIndex(t *testing.T, capture []byte) uint32 {
	t.Helper()
	_, spans := walkPCAP(t, capture)
	return spans[len(spans)-1].index
}

func assertCoupleShape(t *testing.T, ev *c2blue55.DNSEvent) {
	t.Helper()
	if ev == nil {
		t.Fatalf("visiteur appelé avec un événement nul")
	}
	fqdn := ev.FQDN()
	var matched terrainCouple
	found := false
	for _, couple := range terrainCouples {
		if couple.fqdn == fqdn && couple.qtype == ev.QType {
			matched = couple
			found = true
			break
		}
	}
	if !found {
		t.Errorf("couple hors vérité terrain: %s qtype %d", fqdn, ev.QType)
		return
	}
	if ev.Sub() != matched.sub {
		t.Errorf("%s Sub=%q, attendu %q", fqdn, ev.Sub(), matched.sub)
	}
	if ev.Parent() != matched.parent {
		t.Errorf("%s Parent=%q, attendu %q", fqdn, ev.Parent(), matched.parent)
	}
	if ev.RegistrableSLD() != matched.sld {
		t.Errorf("%s RegistrableSLD=%q, attendu %q", fqdn, ev.RegistrableSLD(), matched.sld)
	}
	if ev.PublicSuffix() != matched.tld {
		t.Errorf("%s PublicSuffix=%q, attendu %q", fqdn, ev.PublicSuffix(), matched.tld)
	}
	if ev.LabelCount != matched.labelCount {
		t.Errorf("%s LabelCount=%d, attendu %d", fqdn, ev.LabelCount, matched.labelCount)
	}
	if ev.MaxLabelLen != matched.maxLabelLen {
		t.Errorf("%s MaxLabelLen=%d, attendu %d", fqdn, ev.MaxLabelLen, matched.maxLabelLen)
	}
	if ev.HasEncoding != matched.hasEncoding {
		t.Errorf("%s HasEncoding=%v, attendu %v", fqdn, ev.HasEncoding, matched.hasEncoding)
	}
}

func TestPCAPIngest_RealCaptureCounts(t *testing.T) {
	validateTerrain(t)
	pcapPath, _ := readRealCapture(t)
	wantCounts := terrainCounts()
	seen := make(map[coupleKey]int, len(wantCounts))
	var callN int
	var firstMeta c2blue55.PCAPQuestionMeta
	var firstFQDN string
	var firstQType uint16
	var firstClient [16]byte
	var firstStamp uint64

	stats, err := c2blue55.ReadPCAPDNSQuestions(pcapPath, func(meta c2blue55.PCAPQuestionMeta, ev *c2blue55.DNSEvent) error {
		callN++
		if ev == nil {
			t.Fatalf("visiteur appelé avec un événement nul")
		}
		if ev.Timestamp != meta.Timestamp || ev.ClientIP != meta.SourceIP {
			t.Errorf("enregistrement %d: Timestamp ou ClientIP non recopiés depuis la provenance", meta.Record)
		}
		assertCoupleShape(t, ev)
		if callN == 1 {
			firstMeta = meta
			firstFQDN = strings.Clone(ev.FQDN())
			firstQType = ev.QType
			firstClient = ev.ClientIP
			firstStamp = ev.Timestamp
		}
		seen[coupleKey{strings.Clone(ev.FQDN()), ev.QType}]++
		return nil
	})
	if err != nil {
		t.Fatalf("ReadPCAPDNSQuestions: %v", err)
	}
	if stats != expectedRealStats() {
		t.Fatalf("écart fonctionnel: PCAPIngestStats=%+v, attendu %+v", stats, expectedRealStats())
	}
	if stats.UDPQuestions != stats.Accepted+rejectedSum(stats) {
		t.Fatalf("invariant UDPQuestions rompu: %+v", stats)
	}
	if callN == 0 {
		t.Fatal("visiteur jamais appelé, attendu 69 questions")
	}
	wantSrc := packIPv4(127, 0, 0, 1)
	wantDst := packIPv4(127, 0, 0, 53)
	if firstMeta.Record != 1 || firstMeta.Timestamp != firstQuestionStamp || firstMeta.SourceIP != wantSrc || firstMeta.DestIP != wantDst || firstMeta.IPv6 || firstMeta.SourcePort != firstQuestionPort {
		t.Fatalf("premier appel: %+v, attendu record 1, ts %d, 127.0.0.1 -> 127.0.0.53, port %d, IPv6 faux", firstMeta, firstQuestionStamp, firstQuestionPort)
	}
	if firstStamp != firstMeta.Timestamp || firstClient != firstMeta.SourceIP {
		t.Fatalf("premier événement: Timestamp=%d ClientIP=%v, provenance Timestamp=%d SourceIP=%v", firstStamp, firstClient, firstMeta.Timestamp, firstMeta.SourceIP)
	}
	if firstFQDN != "hazyhaar.fr" || firstQType != 1 {
		t.Fatalf("première question %s/%d, attendu hazyhaar.fr/1", firstFQDN, firstQType)
	}
	if !maps.Equal(seen, wantCounts) {
		t.Fatalf("couples (FQDN, QType)=%v, attendu %v", seen, wantCounts)
	}
}

func TestPCAPIngest_TruncatedFileRefused(t *testing.T) {
	_, capture := readRealCapture(t)
	incomplete := lastRecordIndex(t, capture)
	cases := []struct {
		name    string
		payload []byte
		noVisit bool
	}{
		{name: "dernier octet amputé", payload: append([]byte(nil), capture[:len(capture)-1]...)},
		{name: "en-tête du dernier enregistrement coupé", payload: cutMidLastHeader(t, capture)},
		{name: "en-tête global incomplet", payload: append([]byte(nil), capture[:23]...), noVisit: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempBytes(t, "capture.pcap", tc.payload)
			var sink recordSink
			_, err := c2blue55.ReadPCAPDNSQuestions(path, sink.visit)
			if !errors.Is(err, c2blue55.ErrPCAPTruncated) {
				t.Fatalf("erreur=%v, attendu ErrPCAPTruncated", err)
			}
			if tc.noVisit {
				if len(sink.records) != 0 {
					t.Fatalf("visiteur appelé %d fois sur un en-tête global incomplet", len(sink.records))
				}
				return
			}
			if sink.saw(incomplete) {
				t.Fatalf("le visiteur a reçu une question de l'enregistrement incomplet %d", incomplete)
			}
		})
	}
}

func TestPCAPIngest_SnaplenTruncatedPacketCounted(t *testing.T) {
	_, capture := readRealCapture(t)
	mutated, skipped := withOrigLenBumped(t, capture)
	path := writeTempBytes(t, "snaplen.pcap", mutated)
	var sink recordSink
	stats, err := c2blue55.ReadPCAPDNSQuestions(path, sink.visit)
	if err != nil {
		t.Fatalf("ReadPCAPDNSQuestions: %v", err)
	}
	if stats.TruncatedPackets != 1 || stats.UDPQuestions != 68 || stats.Accepted != 68 || stats.Records != 156 {
		t.Fatalf("écart fonctionnel: %+v, attendu TruncatedPackets=1 UDPQuestions=68 Accepted=68 Records=156", stats)
	}
	if stats.UDPQuestions != stats.Accepted+rejectedSum(stats) {
		t.Fatalf("invariant UDPQuestions rompu: %+v", stats)
	}
	if sink.saw(skipped) {
		t.Fatalf("le visiteur a reçu le paquet tronqué par snaplen (enregistrement %d)", skipped)
	}
}

func TestPCAPIngest_LoopPointerQuestionCounted(t *testing.T) {
	_, capture := readRealCapture(t)
	mutated, skipped := withLoopPointer(t, capture)
	path := writeTempBytes(t, "loop.pcap", mutated)
	var sink recordSink
	stats, err := c2blue55.ReadPCAPDNSQuestions(path, sink.visit)
	if err != nil {
		t.Fatalf("lecture interrompue par le pointeur circulaire: %v", err)
	}
	if stats.RejectedLoopPointer != 1 || stats.Accepted != 68 || stats.UDPQuestions != 69 || stats.Records != 156 {
		t.Fatalf("écart fonctionnel: %+v, attendu RejectedLoopPointer=1 Accepted=68 UDPQuestions=69 Records=156", stats)
	}
	if stats.UDPQuestions != stats.Accepted+rejectedSum(stats) {
		t.Fatalf("invariant UDPQuestions rompu: %+v", stats)
	}
	if sink.saw(skipped) {
		t.Fatalf("le visiteur a été appelé pour la question à pointeur circulaire (enregistrement %d)", skipped)
	}
}

func TestPCAPIngest_BadMagicAndLinkTypeRefused(t *testing.T) {
	_, capture := readRealCapture(t)
	t.Run("magic altéré", func(t *testing.T) {
		mutated := append([]byte(nil), capture...)
		mutated[0] ^= 0xff
		path := writeTempBytes(t, "bad-magic.pcap", mutated)
		var sink recordSink
		stats, err := c2blue55.ReadPCAPDNSQuestions(path, sink.visit)
		if !errors.Is(err, c2blue55.ErrPCAPBadMagic) {
			t.Fatalf("erreur=%v, attendu ErrPCAPBadMagic", err)
		}
		if stats.Records != 0 || len(sink.records) != 0 {
			t.Fatalf("Records=%d visites=%d, attendu 0 et 0", stats.Records, len(sink.records))
		}
	})
	t.Run("type de lien 999", func(t *testing.T) {
		mutated := append([]byte(nil), capture...)
		binary.LittleEndian.PutUint32(mutated[20:24], 999)
		path := writeTempBytes(t, "bad-link.pcap", mutated)
		var sink recordSink
		stats, err := c2blue55.ReadPCAPDNSQuestions(path, sink.visit)
		if !errors.Is(err, c2blue55.ErrPCAPLinkType) {
			t.Fatalf("erreur=%v, attendu ErrPCAPLinkType", err)
		}
		if stats.Records != 0 || len(sink.records) != 0 {
			t.Fatalf("Records=%d visites=%d, attendu 0 et 0", stats.Records, len(sink.records))
		}
	})
}

func TestPCAPIngest_VisitErrorPropagated(t *testing.T) {
	pcapPath, _ := readRealCapture(t)
	sentinel := errors.New("visiteur: interruption demandée")
	var calls int
	stats, err := c2blue55.ReadPCAPDNSQuestions(pcapPath, func(c2blue55.PCAPQuestionMeta, *c2blue55.DNSEvent) error {
		calls++
		if calls == 5 {
			return sentinel
		}
		return nil
	})
	if !errors.Is(err, sentinel) || stats.Accepted != 5 {
		t.Fatalf("propagation du visiteur: err=%v appels=%d Accepted=%d, attendu la sentinelle et Accepted=5", err, calls, stats.Accepted)
	}
}

func TestPCAPIngest_AllocationsIndependentOfRecordCount(t *testing.T) {
	pcapPath, capture := readRealCapture(t)
	stats, err := c2blue55.ReadPCAPDNSQuestions(pcapPath, func(c2blue55.PCAPQuestionMeta, *c2blue55.DNSEvent) error {
		return nil
	})
	if err != nil {
		t.Fatalf("ReadPCAPDNSQuestions: %v", err)
	}
	if stats != expectedRealStats() {
		t.Fatalf("écart fonctionnel: PCAPIngestStats=%+v, attendu %+v", stats, expectedRealStats())
	}
	prefix := prefixCapture(t, capture, 10)
	prefixPath := writeTempBytes(t, "prefix-10.pcap", prefix)
	prefixStats, err := c2blue55.ReadPCAPDNSQuestions(prefixPath, func(c2blue55.PCAPQuestionMeta, *c2blue55.DNSEvent) error {
		return nil
	})
	if err != nil {
		t.Fatalf("préfixe de 10 enregistrements: %v", err)
	}
	if prefixStats.Records != 10 {
		t.Fatalf("préfixe de 10 enregistrements: Records=%d, attendu 10", prefixStats.Records)
	}
	silent := func(c2blue55.PCAPQuestionMeta, *c2blue55.DNSEvent) error { return nil }
	fullAllocs := testing.AllocsPerRun(20, func() {
		_, _ = c2blue55.ReadPCAPDNSQuestions(pcapPath, silent)
	})
	prefixAllocs := testing.AllocsPerRun(20, func() {
		_, _ = c2blue55.ReadPCAPDNSQuestions(prefixPath, silent)
	})
	if fullAllocs != prefixAllocs {
		t.Fatalf("allocations par lecture: capture complète %v, préfixe de 10 enregistrements %v", fullAllocs, prefixAllocs)
	}
}
