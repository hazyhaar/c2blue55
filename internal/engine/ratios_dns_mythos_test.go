package engine

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type paquetDNSBrutPCAP struct {
	horodatageNs  int64
	ipClient      [16]byte
	txID          uint16
	estReponse    bool
	rcode         uint8
	qtype         uint16
	qname         []byte
	sousDomaine   []byte
	apexParent    []byte
	premierRData  []byte
	nbReponses    uint8
	totalRDLength int
	trameDNS      []byte
}

// lireCapturePCAPRawIPv4 extrait intégralement sans troncature chaque datagramme UDP DNS
// d'une capture PCAP Raw IPv4 (linkType == 101) et vérifie que tous les octets ont été lus.
func lireCapturePCAPRawIPv4(t testing.TB, nomFichier string) []paquetDNSBrutPCAP {
	t.Helper()
	chemin := filepath.Join("..", "..", "testdata", "rat-20261101", nomFichier)
	brut, err := os.ReadFile(chemin)
	if err != nil {
		t.Fatalf("lecture capture %s: %v", nomFichier, err)
	}
	if len(brut) < 24 {
		t.Fatalf("capture %s trop courte: %d octets", nomFichier, len(brut))
	}
	var ordre binary.ByteOrder = binary.LittleEndian
	facteurSousSec := int64(1000)
	switch binary.LittleEndian.Uint32(brut[0:4]) {
	case 0xa1b2c3d4:
	case 0xa1b23c4d:
		facteurSousSec = 1
	case 0xd4c3b2a1:
		ordre = binary.BigEndian
	case 0x4d3cb2a1:
		ordre = binary.BigEndian
		facteurSousSec = 1
	default:
		t.Fatalf("magique PCAP invalide dans %s: 0x%08x", nomFichier, binary.LittleEndian.Uint32(brut[0:4]))
	}
	if typeLiaison := ordre.Uint32(brut[20:24]); typeLiaison != 101 {
		t.Fatalf("linkType PCAP inattendu dans %s: %d (attendu 101 Raw IPv4)", nomFichier, typeLiaison)
	}

	var sortie []paquetDNSBrutPCAP
	pos := 24
	for pos < len(brut) {
		if len(brut)-pos < 16 {
			t.Fatalf("en-tête d'enregistrement PCAP tronqué dans %s à %d/%d", nomFichier, pos, len(brut))
		}
		sec := int64(ordre.Uint32(brut[pos : pos+4]))
		sousSec := int64(ordre.Uint32(brut[pos+4 : pos+8]))
		inclLen := int(ordre.Uint32(brut[pos+8 : pos+12]))
		origLen := int(ordre.Uint32(brut[pos+12 : pos+16]))
		pos += 16
		if inclLen != origLen || inclLen < 28 || inclLen > len(brut)-pos {
			t.Fatalf("enregistrement PCAP tronqué ou invalide dans %s: incl=%d orig=%d restant=%d", nomFichier, inclLen, origLen, len(brut)-pos)
		}
		pktIP := brut[pos : pos+inclLen]
		pos += inclLen
		ihl := int(pktIP[0]&0x0F) * 4
		if (pktIP[0]>>4) != 4 || pktIP[9] != 17 || ihl < 20 || len(pktIP)-ihl < 8 {
			t.Fatalf("paquet non-IPv4/UDP inattendu dans %s", nomFichier)
		}
		portSrc := binary.BigEndian.Uint16(pktIP[ihl : ihl+2])
		portDst := binary.BigEndian.Uint16(pktIP[ihl+2 : ihl+4])
		udpLen := int(binary.BigEndian.Uint16(pktIP[ihl+4 : ihl+6]))
		if udpLen < 20 || udpLen != len(pktIP)-ihl || (portSrc != 53 && portDst != 53) {
			t.Fatalf("datagramme UDP DNS invalide dans %s: sport=%d dport=%d ulen=%d", nomFichier, portSrc, portDst, udpLen)
		}
		trame := bytes.Clone(pktIP[ihl+8 : ihl+udpLen])
		drapeaux := binary.BigEndian.Uint16(trame[2:4])
		estResp := (drapeaux & 0x8000) != 0
		var client [16]byte
		if estResp {
			copy(client[:4], pktIP[16:20])
		} else {
			copy(client[:4], pktIP[12:16])
		}
		qname, finQName := extraireQNameFilaireTest(t, trame)
		if len(trame)-finQName < 4 {
			t.Fatalf("question DNS tronquée dans %s", nomFichier)
		}
		qtype := binary.BigEndian.Uint16(trame[finQName : finQName+2])
		sub, _, _, parent, _, _, _, okSplit := splitDNSNameBytes(qname)
		if !okSplit {
			t.Fatalf("splitDNSNameBytes invalide sur %q dans %s", string(qname), nomFichier)
		}
		resume := summarizeWirePacket(trame)
		var premierRD []byte
		totalRD := 0
		for idx := 0; idx < resume.answerCount; idx++ {
			if idx == 0 {
				premierRD = resume.answers[0].rdata
			}
			totalRD += int(resume.answers[idx].rdLength)
		}
		sortie = append(sortie, paquetDNSBrutPCAP{
			horodatageNs:  sec*1_000_000_000 + sousSec*facteurSousSec,
			ipClient:      client,
			txID:          binary.BigEndian.Uint16(trame[0:2]),
			estReponse:    estResp,
			rcode:         uint8(drapeaux & 0x000F),
			qtype:         qtype,
			qname:         qname,
			sousDomaine:   bytes.Clone(sub),
			apexParent:    bytes.Clone(parent),
			premierRData:  premierRD,
			nbReponses:    uint8(min(resume.answerCount, 255)),
			totalRDLength: totalRD,
			trameDNS:      trame,
		})
	}
	if pos != len(brut) {
		t.Fatalf("lecture PCAP incomplète pour %s: %d/%d octets lus", nomFichier, pos, len(brut))
	}
	return sortie
}

func extraireQNameFilaireTest(t testing.TB, trame []byte) ([]byte, int) {
	t.Helper()
	var nom []byte
	off := 12
	for off < len(trame) {
		longueur := int(trame[off])
		off++
		if longueur == 0 {
			return nom, off
		}
		if (longueur&0xC0) != 0 || longueur > len(trame)-off {
			t.Fatalf("label QNAME invalide à l'offset %d (len=%d)", off-1, longueur)
		}
		if len(nom) > 0 {
			nom = append(nom, '.')
		}
		nom = append(nom, trame[off:off+longueur]...)
		off += longueur
	}
	t.Fatalf("QNAME non terminé dans une trame de %d octets", len(trame))
	return nil, 0
}

type enregistrementRFCFilaire struct {
	proprietaire string
	rrType       uint16
	rrClass      uint16
	ttl          uint32
	rdata        []byte
}

func encoderNomDNSFilaireRFC(nom string) []byte {
	if nom == "" {
		return []byte{0}
	}
	var out []byte
	for label := range strings.SplitSeq(nom, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out
}

func construireTrameReponseRFC(
	txID uint16,
	opcode uint8,
	rcode uint8,
	qname string,
	qtype uint16,
	answers []enregistrementRFCFilaire,
	authorities []enregistrementRFCFilaire,
	additionals []enregistrementRFCFilaire,
) []byte {
	var pkt []byte
	enTete := make([]byte, 12)
	binary.BigEndian.PutUint16(enTete[0:2], txID)
	drapeaux := uint16(0x8180) | (uint16(opcode&0x0F) << 11) | uint16(rcode&0x0F)
	binary.BigEndian.PutUint16(enTete[2:4], drapeaux)
	binary.BigEndian.PutUint16(enTete[4:6], 1)
	binary.BigEndian.PutUint16(enTete[6:8], uint16(len(answers)))
	binary.BigEndian.PutUint16(enTete[8:10], uint16(len(authorities)))
	binary.BigEndian.PutUint16(enTete[10:12], uint16(len(additionals)))
	pkt = append(pkt, enTete...)

	pkt = append(pkt, encoderNomDNSFilaireRFC(qname)...)
	var qTail [4]byte
	binary.BigEndian.PutUint16(qTail[0:2], qtype)
	binary.BigEndian.PutUint16(qTail[2:4], 1)
	pkt = append(pkt, qTail[:]...)

	ecrireSection := func(section []enregistrementRFCFilaire) {
		for _, rr := range section {
			pkt = append(pkt, encoderNomDNSFilaireRFC(rr.proprietaire)...)
			var meta [10]byte
			classe := rr.rrClass
			if classe == 0 {
				classe = 1
			}
			binary.BigEndian.PutUint16(meta[0:2], rr.rrType)
			binary.BigEndian.PutUint16(meta[2:4], classe)
			binary.BigEndian.PutUint32(meta[4:8], rr.ttl)
			binary.BigEndian.PutUint16(meta[8:10], uint16(len(rr.rdata)))
			pkt = append(pkt, meta[:]...)
			pkt = append(pkt, rr.rdata...)
		}
	}
	ecrireSection(answers)
	ecrireSection(authorities)
	ecrireSection(additionals)
	return pkt
}

func rdataTXTFilaire(texte string) []byte {
	out := make([]byte, 1+len(texte))
	out[0] = byte(len(texte))
	copy(out[1:], texte)
	return out
}

func rdataSOAFilaire(mname, rname string, serial uint32) []byte {
	var rd []byte
	rd = append(rd, encoderNomDNSFilaireRFC(mname)...)
	rd = append(rd, encoderNomDNSFilaireRFC(rname)...)
	var nombres [20]byte
	binary.BigEndian.PutUint32(nombres[0:4], serial)
	binary.BigEndian.PutUint32(nombres[4:8], 3600)
	binary.BigEndian.PutUint32(nombres[8:12], 900)
	binary.BigEndian.PutUint32(nombres[12:16], 604800)
	binary.BigEndian.PutUint32(nombres[16:20], 300)
	rd = append(rd, nombres[:]...)
	return rd
}

func rdataRRSIGFilaire(typeCouvert uint16, signataire string) []byte {
	var rd []byte
	var fixe [18]byte
	binary.BigEndian.PutUint16(fixe[0:2], typeCouvert)
	fixe[2] = 13 // ECDSAP256SHA256
	fixe[3] = 2
	binary.BigEndian.PutUint32(fixe[4:8], 300)
	binary.BigEndian.PutUint32(fixe[8:12], 1900000000)
	binary.BigEndian.PutUint32(fixe[12:16], 1890000000)
	binary.BigEndian.PutUint16(fixe[16:18], 12345)
	rd = append(rd, fixe[:]...)
	rd = append(rd, encoderNomDNSFilaireRFC(signataire)...)
	rd = append(rd, bytes.Repeat([]byte{0x5a}, 64)...)
	return rd
}

func rdataNSEC3Filaire() []byte {
	var rd []byte
	rd = append(rd, 1, 0, 0, 10, 0, 20)
	rd = append(rd, bytes.Repeat([]byte{0x33}, 20)...)
	rd = append(rd, 0, 1, 0x40)
	return rd
}

func rdataTSIGFilaire(txID uint16) []byte {
	var rd []byte
	rd = append(rd, encoderNomDNSFilaireRFC("hmac-sha256")...)
	var meta [10]byte
	// Time Signed (6 octets) + Fudge (2 octets = 300) + MAC Size (2 octets = 32)
	meta[5] = 1
	binary.BigEndian.PutUint16(meta[6:8], 300)
	binary.BigEndian.PutUint16(meta[8:10], 32)
	rd = append(rd, meta[:]...)
	rd = append(rd, bytes.Repeat([]byte{0x77}, 32)...)
	var fin [6]byte
	binary.BigEndian.PutUint16(fin[0:2], txID)
	pkt := append(rd, fin[:]...)
	return pkt
}

func rdataCAATailleExacte(indice int, tailleTotale int) []byte {
	// RFC 8659 : [flags:1][tagLen:1][tag:"issue"][valeur ASCII]
	enTete := []byte{0, 5, 'i', 's', 's', 'u', 'e'}
	if tailleTotale <= len(enTete) {
		return bytes.Repeat([]byte{'a' + byte(indice%26)}, tailleTotale)
	}
	prefixe := fmt.Sprintf("ca-%04d-", indice)
	out := make([]byte, 0, tailleTotale)
	out = append(out, enTete...)
	for len(out) < tailleTotale {
		manquant := tailleTotale - len(out)
		if manquant >= len(prefixe) {
			out = append(out, prefixe...)
		} else {
			out = append(out, prefixe[:manquant]...)
		}
	}
	return out
}

func rdataMXTailleExacte256(indice int) []byte {
	// Preference (2 octets) + nom filaire DNS valide de 254 octets = 256 octets exacts.
	// 4 labels : (1+62) + (1+62) + (1+62) + (1+63) + 1(nul) = 63*3 + 64 + 1 = 254 octets.
	l0 := fmt.Sprintf("m%05d%s", indice, strings.Repeat("a", 56)) // 62
	l1 := fmt.Sprintf("n%05d%s", indice, strings.Repeat("b", 56)) // 62
	l2 := fmt.Sprintf("p%05d%s", indice, strings.Repeat("c", 56)) // 62
	l3 := fmt.Sprintf("q%05d%s", indice, strings.Repeat("d", 57)) // 63
	nom := l0 + "." + l1 + "." + l2 + "." + l3
	filaire := encoderNomDNSFilaireRFC(nom)
	rd := make([]byte, 2+len(filaire))
	binary.BigEndian.PutUint16(rd[0:2], 10)
	copy(rd[2:], filaire)
	return rd
}

func TestRAT01_ExportedReasonConstants(t *testing.T) {
	if ReasonP14NegativeAnswerPayload != "REASON_P14_NXDOMAIN_ANSWER_PAYLOAD" {
		t.Fatalf("ReasonP14NegativeAnswerPayload = %q, attendu %q",
			ReasonP14NegativeAnswerPayload, "REASON_P14_NXDOMAIN_ANSWER_PAYLOAD")
	}
	if ReasonP15RDataRenewal != "REASON_P15_RDATA_RENEWAL" {
		t.Fatalf("ReasonP15RDataRenewal = %q, attendu %q",
			ReasonP15RDataRenewal, "REASON_P15_RDATA_RENEWAL")
	}
}

func TestRAT01_P14_NegativeAnswerPayloadAndShortCircuitFixes(t *testing.T) {
	// 1. Positif a) + Jumeau négatif f) sur captures réelles :
	//    40 réponses NXDOMAIN Soar (TXT 65 o en Answer) face aux 200 réponses bénignes réelles.
	captureSoar := lireCapturePCAPRawIPv4(t, "soar-signed-nxdomain-cache-auth.pcap")
	captureBenigne := lireCapturePCAPRawIPv4(t, "benign-rrtypes-clear.pcap")

	var etatSoar StreamingDNS18State
	nbReqSoar := 0
	nbRespSoar := 0
	tp := 0
	fn := 0
	for _, pkt := range captureSoar {
		cls, reason, consumed := etatSoar.ObserveAndClassify18(
			pkt.trameDNS, pkt.horodatageNs, pkt.ipClient, pkt.sousDomaine, pkt.apexParent,
			pkt.qtype, DNSEpisodeSnapshot{}, EpisodeP3Features{},
		)
		if !pkt.estReponse {
			nbReqSoar++
			continue
		}
		nbRespSoar++
		if cls == "P14" && reason == ReasonP14NegativeAnswerPayload && consumed {
			tp++
		} else {
			fn++
			t.Errorf("Soar réponse #%d: obtenu (%q, %q, %v), attendu (\"P14\", %q, true)",
				nbRespSoar, cls, reason, consumed, ReasonP14NegativeAnswerPayload)
		}
	}
	if nbReqSoar != 40 || nbRespSoar != 40 {
		t.Fatalf("capture Soar: req=%d resp=%d, attendu 40 et 40", nbReqSoar, nbRespSoar)
	}

	var etatBenin StreamingDNS18State
	nbRespBenignes := 0
	fp := 0
	tn := 0
	for _, pkt := range captureBenigne {
		cls, reason, _ := etatBenin.ObserveAndClassify18(
			pkt.trameDNS, pkt.horodatageNs, pkt.ipClient, pkt.sousDomaine, pkt.apexParent,
			pkt.qtype, DNSEpisodeSnapshot{}, EpisodeP3Features{},
		)
		if !pkt.estReponse {
			continue
		}
		nbRespBenignes++
		if cls == "P14" || reason == ReasonP14NegativeAnswerPayload {
			fp++
			t.Errorf("capture bénigne réponse #%d: faux positif P14 (%q, %q) sur %s (qtype=%d)",
				nbRespBenignes, cls, reason, string(pkt.qname), pkt.qtype)
		} else {
			tn++
		}
	}
	if nbRespBenignes != 200 {
		t.Fatalf("capture bénigne: resp=%d, attendu 200", nbRespBenignes)
	}
	totalEvalue := tp + fp + tn + fn
	majoritaire := max(tp+fn, tn+fp)
	majorityClassRate := float64(majoritaire) / float64(totalEvalue)
	t.Logf("P14 captures réelles: TP=%d FP=%d TN=%d FN=%d total=%d majority_class_rate=%.6f",
		tp, fp, tn, fn, totalEvalue, majorityClassRate)
	if tp != 40 || fp != 0 || tn != 200 || fn != 0 {
		t.Fatalf("comptes P14 invalides: TP=%d FP=%d TN=%d FN=%d (majority_class_rate=%.6f)",
			tp, fp, tn, fn, majorityClassRate)
	}

	// 2. Positifs b), c), d), e) sur fixtures RFC :
	charge64 := strings.Repeat("x", 64) // 1 + 64 = 65 octets RDATA TXT
	client := [16]byte{10, 55, 0, 2}

	trameTronqueeSansRR := make([]byte, 0, 48)
	enTeteTronque := make([]byte, 12)
	binary.BigEndian.PutUint16(enTeteTronque[0:2], 0x2101)
	binary.BigEndian.PutUint16(enTeteTronque[2:4], 0x8183) // QR=1, OPCODE=0, RCODE=3
	binary.BigEndian.PutUint16(enTeteTronque[4:6], 1)      // QDCOUNT=1
	binary.BigEndian.PutUint16(enTeteTronque[6:8], 1)      // ANCOUNT=1 mais 0 RR derrière
	trameTronqueeSansRR = append(trameTronqueeSansRR, enTeteTronque...)
	trameTronqueeSansRR = append(trameTronqueeSansRR, encoderNomDNSFilaireRFC("nx.soar.example")...)
	trameTronqueeSansRR = append(trameTronqueeSansRR, 0, 16, 0, 1)

	trameTronqueeDemiRR := append(bytes.Clone(trameTronqueeSansRR), 0xc0, 0x0c, 0x00, 0x10, 0x00)

	casPositifsP14 := []struct {
		nom   string
		sous  string
		apex  string
		qtype uint16
		trame []byte
	}{
		{
			nom:   "b-txt-en-authority",
			sous:  "nx1",
			apex:  "soar.example",
			qtype: 16,
			trame: construireTrameReponseRFC(0x2001, 0, 3, "nx1.soar.example", 16,
				nil,
				[]enregistrementRFCFilaire{{proprietaire: "soar.example", rrType: 16, ttl: 60, rdata: rdataTXTFilaire(charge64)}},
				nil,
			),
		},
		{
			nom:   "c-null-en-additional",
			sous:  "nx2",
			apex:  "soar.example",
			qtype: 10,
			trame: construireTrameReponseRFC(0x2002, 0, 3, "nx2.soar.example", 10,
				nil,
				[]enregistrementRFCFilaire{{proprietaire: "soar.example", rrType: 6, ttl: 60, rdata: rdataSOAFilaire("ns1.soar.example", "hm.soar.example", 1)}},
				[]enregistrementRFCFilaire{{proprietaire: "nx2.soar.example", rrType: 10, ttl: 60, rdata: bytes.Repeat([]byte{0xab}, 48)}},
			),
		},
		{
			nom:   "d1-court-circuit-underscore-qtype16-qr1",
			sous:  "_sip._tls",
			apex:  "soar.example",
			qtype: 16,
			trame: construireTrameReponseRFC(0x2003, 0, 3, "_sip._tls.soar.example", 16,
				[]enregistrementRFCFilaire{{proprietaire: "_sip._tls.soar.example", rrType: 16, ttl: 30, rdata: rdataTXTFilaire(charge64)}},
				nil,
				nil,
			),
		},
		{
			nom:   "d2-court-circuit-srv-qtype33-qr1",
			sous:  "_sip._tls",
			apex:  "soar.example",
			qtype: 33,
			trame: construireTrameReponseRFC(0x2004, 0, 3, "_sip._tls.soar.example", 33,
				[]enregistrementRFCFilaire{{proprietaire: "_sip._tls.soar.example", rrType: 16, ttl: 30, rdata: rdataTXTFilaire(charge64)}},
				nil,
				nil,
			),
		},
		{
			nom:   "e1-nxdomain-ancount1-zero-rr-decodable",
			sous:  "nx",
			apex:  "soar.example",
			qtype: 16,
			trame: trameTronqueeSansRR,
		},
		{
			nom:   "e2-nxdomain-ancount1-rr-coupe",
			sous:  "nx",
			apex:  "soar.example",
			qtype: 16,
			trame: trameTronqueeDemiRR,
		},
		{
			nom:   "e3-nxdomain-edns-extended-rcode-non-nul",
			sous:  "nx3",
			apex:  "soar.example",
			qtype: 16,
			trame: construireTrameReponseRFC(0x2005, 0, 3, "nx3.soar.example", 16,
				nil,
				[]enregistrementRFCFilaire{{proprietaire: "soar.example", rrType: 6, ttl: 300, rdata: rdataSOAFilaire("ns1.soar.example", "hm.soar.example", 2)}},
				[]enregistrementRFCFilaire{{proprietaire: "", rrType: 41, rrClass: 1232, ttl: 0x01000000, rdata: nil}},
			),
		},
	}

	for idx, tc := range casPositifsP14 {
		var st StreamingDNS18State
		cls, reason, consumed := st.ObserveAndClassify18(
			tc.trame, int64(idx+1)*1_000_000, client, []byte(tc.sous), []byte(tc.apex),
			tc.qtype, DNSEpisodeSnapshot{}, EpisodeP3Features{},
		)
		if cls != "P14" || reason != ReasonP14NegativeAnswerPayload || !consumed {
			t.Errorf("cas positif P14 %s: obtenu (%q, %q, %v), attendu (\"P14\", %q, true)",
				tc.nom, cls, reason, consumed, ReasonP14NegativeAnswerPayload)
		}
	}

	// 3. Jumeaux négatifs a), b), c), d), e) sur fixtures RFC :
	casNegatifsP14 := []struct {
		nom            string
		sous           string
		apex           string
		qtype          uint16
		exigerBeninPur bool
		trame          []byte
	}{
		{
			nom:            "a-nxdomain-cname-seul-et-soa",
			sous:           "www",
			apex:           "example.org",
			qtype:          1,
			exigerBeninPur: true,
			trame: construireTrameReponseRFC(0x3001, 0, 3, "www.example.org", 1,
				[]enregistrementRFCFilaire{{proprietaire: "www.example.org", rrType: 5, ttl: 300, rdata: encoderNomDNSFilaireRFC("cible.example.org")}},
				[]enregistrementRFCFilaire{{proprietaire: "example.org", rrType: 6, ttl: 300, rdata: rdataSOAFilaire("ns1.example.org", "hm.example.org", 20261101)}},
				nil,
			),
		},
		{
			nom:            "b-nxdomain-dnssec-cname-rrsig-soa-nsec3-opt-tsig",
			sous:           "www",
			apex:           "example.org",
			qtype:          1,
			exigerBeninPur: true,
			trame: construireTrameReponseRFC(0x3002, 0, 3, "www.example.org", 1,
				[]enregistrementRFCFilaire{
					{proprietaire: "www.example.org", rrType: 5, ttl: 300, rdata: encoderNomDNSFilaireRFC("absent.example.org")},
					{proprietaire: "www.example.org", rrType: 46, ttl: 300, rdata: rdataRRSIGFilaire(5, "example.org")},
				},
				[]enregistrementRFCFilaire{
					{proprietaire: "example.org", rrType: 6, ttl: 300, rdata: rdataSOAFilaire("ns1.example.org", "hm.example.org", 20261101)},
					{proprietaire: "example.org", rrType: 46, ttl: 300, rdata: rdataRRSIGFilaire(6, "example.org")},
					{proprietaire: "h0p1q2.example.org", rrType: 50, ttl: 300, rdata: rdataNSEC3Filaire()},
					{proprietaire: "h0p1q2.example.org", rrType: 46, ttl: 300, rdata: rdataRRSIGFilaire(50, "example.org")},
				},
				[]enregistrementRFCFilaire{
					// OPT avec bit DO=1 (0x00008000) : OPT.TTL >> 24 == 0, 100 % légitime DNSSEC.
					{proprietaire: "", rrType: 41, rrClass: 1232, ttl: 0x00008000, rdata: nil},
					{proprietaire: "tsig-cle.example.org", rrType: 250, rrClass: 255, ttl: 0, rdata: rdataTSIGFilaire(0x3002)},
				},
			),
		},
		{
			nom:            "c-nxdomain-dname-cname-rrsig",
			sous:           "sub.alias",
			apex:           "example.org",
			qtype:          1,
			exigerBeninPur: true,
			trame: construireTrameReponseRFC(0x3003, 0, 3, "sub.alias.example.org", 1,
				[]enregistrementRFCFilaire{
					{proprietaire: "alias.example.org", rrType: 39, ttl: 300, rdata: encoderNomDNSFilaireRFC("cible.example.net")},
					{proprietaire: "sub.alias.example.org", rrType: 5, ttl: 300, rdata: encoderNomDNSFilaireRFC("sub.cible.example.net")},
					{proprietaire: "alias.example.org", rrType: 46, ttl: 300, rdata: rdataRRSIGFilaire(39, "example.org")},
				},
				[]enregistrementRFCFilaire{{proprietaire: "example.net", rrType: 6, ttl: 300, rdata: rdataSOAFilaire("ns1.example.net", "hm.example.net", 1)}},
				nil,
			),
		},
		{
			nom:            "d-dns-update-opcode5-rcode3-avec-answer",
			sous:           "host1",
			apex:           "example.org",
			qtype:          6,
			exigerBeninPur: false,
			trame: construireTrameReponseRFC(0x3004, 5, 3, "host1.example.org", 6,
				[]enregistrementRFCFilaire{{proprietaire: "host1.example.org", rrType: 16, ttl: 0, rdata: rdataTXTFilaire("update-refused")}},
				nil,
				nil,
			),
		},
		{
			nom:            "e1-dmarc-txt-benin-rcode0",
			sous:           "_dmarc",
			apex:           "example.org",
			qtype:          16,
			exigerBeninPur: true,
			trame: construireTrameReponseRFC(0x3005, 0, 0, "_dmarc.example.org", 16,
				[]enregistrementRFCFilaire{{proprietaire: "_dmarc.example.org", rrType: 16, ttl: 300, rdata: rdataTXTFilaire("v=DMARC1; p=reject;")}},
				nil,
				nil,
			),
		},
		{
			nom:            "e2-dkim-selecteur-mixte-txt-benin-rcode0-non-pollue-niveau3",
			sous:           "Selector23456789abcdefgh._domainkey",
			apex:           "example.org",
			qtype:          16,
			exigerBeninPur: true,
			trame: construireTrameReponseRFC(0x3006, 0, 0, "Selector23456789abcdefgh._domainkey.example.org", 16,
				[]enregistrementRFCFilaire{{proprietaire: "Selector23456789abcdefgh._domainkey.example.org", rrType: 16, ttl: 300, rdata: rdataTXTFilaire("v=DKIM1; k=rsa; p=MIIB;")}},
				nil,
				nil,
			),
		},
	}

	for idx, tc := range casNegatifsP14 {
		var st StreamingDNS18State
		cls, reason, consumed := st.ObserveAndClassify18(
			tc.trame, int64(idx+1)*1_000_000, client, []byte(tc.sous), []byte(tc.apex),
			tc.qtype, DNSEpisodeSnapshot{}, EpisodeP3Features{},
		)
		if cls == "P14" || reason == ReasonP14NegativeAnswerPayload {
			t.Errorf("jumeau négatif P14 %s: déclenchement interdit (%q, %q, %v)", tc.nom, cls, reason, consumed)
		}
		if tc.exigerBeninPur && (cls != "BENIGN" || reason != ReasonNone || !consumed) {
			t.Errorf("jumeau négatif %s: obtenu (%q, %q, %v), attendu (\"BENIGN\", %q, true)",
				tc.nom, cls, reason, consumed, ReasonNone)
		}
	}
}

func construireRoundRobinCompressible(
	txID uint16,
	premierLabel string,
	rrType uint16,
	ttl uint32,
	rotation int,
) []byte {
	// QNAME = <premierLabel>.c.lab.pound2pound.fr ; le suffixe c.lab.pound2pound.fr débute
	// à l'offset 12 + 1 + len(premierLabel), qui varie à chaque réponse selon premierLabel.
	qname := premierLabel + ".c.lab.pound2pound.fr"
	offsetSuffixe := uint16(12 + 1 + len(premierLabel))

	var pkt []byte
	enTete := make([]byte, 12)
	binary.BigEndian.PutUint16(enTete[0:2], txID)
	binary.BigEndian.PutUint16(enTete[2:4], 0x8180)
	binary.BigEndian.PutUint16(enTete[4:6], 1)
	binary.BigEndian.PutUint16(enTete[6:8], 3)
	pkt = append(pkt, enTete...)
	pkt = append(pkt, encoderNomDNSFilaireRFC(qname)...)
	var qTail [4]byte
	binary.BigEndian.PutUint16(qTail[0:2], rrType)
	binary.BigEndian.PutUint16(qTail[2:4], 1)
	pkt = append(pkt, qTail[:]...)

	nomsServeurs := [3]string{
		"relais-primaire-alpha",
		"relais-secondaire-bravo",
		"relais-tertiaire-charlie",
	}
	for k := range 3 {
		idxSrv := (rotation + k) % 3
		// Propriétaire = pointeur vers le QNAME (0xC00C)
		pkt = append(pkt, 0xC0, 0x0C)
		var rdata []byte
		if rrType == 15 {
			var pref [2]byte
			binary.BigEndian.PutUint16(pref[:], uint16(10*(idxSrv+1)))
			rdata = append(rdata, pref[:]...)
		} else {
			var srvHdr [6]byte
			binary.BigEndian.PutUint16(srvHdr[0:2], 10)
			binary.BigEndian.PutUint16(srvHdr[2:4], 20)
			binary.BigEndian.PutUint16(srvHdr[4:6], uint16(443+idxSrv))
			rdata = append(rdata, srvHdr[:]...)
		}
		hote := nomsServeurs[idxSrv]
		rdata = append(rdata, byte(len(hote)))
		rdata = append(rdata, hote...)
		// Pointeur de compression RFC 1035 vers c.lab.pound2pound.fr (offset variable !)
		rdata = append(rdata, 0xC0|byte(offsetSuffixe>>8), byte(offsetSuffixe))

		var meta [10]byte
		binary.BigEndian.PutUint16(meta[0:2], rrType)
		binary.BigEndian.PutUint16(meta[2:4], 1)
		binary.BigEndian.PutUint32(meta[4:8], ttl)
		binary.BigEndian.PutUint16(meta[8:10], uint16(len(rdata)))
		pkt = append(pkt, meta[:]...)
		pkt = append(pkt, rdata...)
	}
	return pkt
}

func decouvrirCinqClesMemeAlveoleP15(t *testing.T, client [16]byte, qtype uint16) [5]string {
	t.Helper()
	const nbCandidats = 1025 // > 256 * 4 = 1024 créneaux : collision >= 5 garantie par Dirichlet
	candidats := make([]string, nbCandidats)
	trames := make([][]byte, nbCandidats)
	rdataFixe := rdataCAATailleExacte(1, 256)
	for i := range nbCandidats {
		candidats[i] = fmt.Sprintf("alveole-%04d.example", i)
		trames[i] = construireTrameReponseRFC(uint16(0x5000+i), 0, 0, "h."+candidats[i], qtype,
			[]enregistrementRFCFilaire{{proprietaire: "h." + candidats[i], rrType: qtype, ttl: 60, rdata: rdataFixe}},
			nil, nil,
		)
	}

	var sondeInitiale RenouvellementRDataTracker
	for i := range nbCandidats {
		sondeInitiale.ObserveResponse(int64(i+1)*1_000_000, client, []byte(candidats[i]), qtype, trames[i])
	}
	indiceBase := -1
	for i := range nbCandidats {
		_, obs := sondeInitiale.ObserveResponse(2_000_000_000+int64(i)*1_000, client, []byte(candidats[i]), qtype, trames[i])
		if obs.Reponses == 1 {
			indiceBase = i
			break
		}
	}
	if indiceBase < 0 {
		t.Fatalf("aucune éviction observée après %d clés distinctes dans une table 256x4", nbCandidats)
	}

	evinceBase := func(indices []int) bool {
		var trLoc RenouvellementRDataTracker
		_, obs0 := trLoc.ObserveResponse(1_000_000, client, []byte(candidats[indiceBase]), qtype, trames[indiceBase])
		if obs0.Reponses != 1 {
			t.Fatalf("initialisation sonde invalide: Reponses=%d", obs0.Reponses)
		}
		for pas, idx := range indices {
			trLoc.ObserveResponse(int64(pas+2)*1_000_000, client, []byte(candidats[idx]), qtype, trames[idx])
		}
		_, obsFin := trLoc.ObserveResponse(9_000_000_000, client, []byte(candidats[indiceBase]), qtype, trames[indiceBase])
		return obsFin.Reponses == 1
	}

	var pool []int
	for idx := indiceBase + 1; idx < nbCandidats; idx++ {
		pool = append(pool, idx)
	}
	var retenues []int
	for len(retenues) < 4 {
		bas, haut := 1, len(pool)
		if !evinceBase(append(append([]int(nil), retenues...), pool...)) {
			t.Fatalf("invariant de collision rompu à l'étape %d", len(retenues))
		}
		for bas < haut {
			milieu := (bas + haut) / 2
			essai := make([]int, 0, len(retenues)+milieu)
			essai = append(essai, retenues...)
			essai = append(essai, pool[:milieu]...)
			if evinceBase(essai) {
				haut = milieu
			} else {
				bas = milieu + 1
			}
		}
		collisionIdx := pool[bas-1]
		retenues = append(retenues, collisionIdx)
		pool = pool[:bas-1]
	}

	return [5]string{
		candidats[indiceBase],
		candidats[retenues[3]],
		candidats[retenues[2]],
		candidats[retenues[1]],
		candidats[retenues[0]],
	}
}

func TestRAT01_P15_RDataRenewalTrackerAndStreaming(t *testing.T) {
	// 1. Positif a) sur capture réelle vaydns-mx-clear.pcap (352 réponses MX) :
	captureVayMX := lireCapturePCAPRawIPv4(t, "vaydns-mx-clear.pcap")
	var episodes DNSEpisodeStore
	var etatMX StreamingDNS18State
	nbRespMX := 0
	nbDetectesP15OuP1 := 0
	nbDetectesP15 := 0

	for _, pkt := range captureVayMX {
		snap, _ := episodes.ObserveExchange(DNSExchangeObs{
			TimestampNs: pkt.horodatageNs,
			SrcIP:       pkt.ipClient,
			TxID:        pkt.txID,
			IsResponse:  pkt.estReponse,
			RCode:       pkt.rcode,
			QType:       pkt.qtype,
			ParentApex:  pkt.apexParent,
			Subdomain:   pkt.sousDomaine,
			AnswerRData: pkt.premierRData,
			AnswerCount: pkt.nbReponses,
		}, nil)
		cls, reason, consumed := etatMX.ObserveAndClassify18(
			pkt.trameDNS, pkt.horodatageNs, pkt.ipClient, pkt.sousDomaine, pkt.apexParent,
			pkt.qtype, snap, EpisodeP3Features{},
		)
		if !pkt.estReponse {
			continue
		}
		nbRespMX++
		if cls == "P15" {
			if reason != ReasonP15RDataRenewal || !consumed {
				t.Errorf("VayDNS MX réponse #%d: P15 mal formé (%q, %q, %v)", nbRespMX, cls, reason, consumed)
			}
			nbDetectesP15++
			nbDetectesP15OuP1++
		} else if cls == "P1" {
			if reason != ReasonP1DownlinkExfil || !consumed {
				t.Errorf("VayDNS MX réponse #%d: P1 mal formé (%q, %q, %v)", nbRespMX, cls, reason, consumed)
			}
			nbDetectesP15OuP1++
		}
	}
	if nbRespMX != 352 {
		t.Fatalf("capture VayDNS MX: %d réponses QR=1 lues, attendu 352", nbRespMX)
	}
	if nbDetectesP15OuP1 < 320 || nbDetectesP15 == 0 {
		t.Fatalf("VayDNS MX: détectés P15|P1=%d/352 (dont P15=%d), attendu >= 320 et P15 > 0",
			nbDetectesP15OuP1, nbDetectesP15)
	}

	// Déclenchement direct de RenouvellementRDataTracker.ObserveResponse dès la 8e réponse à grand RDATA :
	var trackerGrandRData RenouvellementRDataTracker
	rangGrandRData := 0
	for _, pkt := range captureVayMX {
		if !pkt.estReponse || pkt.totalRDLength < 128 {
			continue
		}
		rangGrandRData++
		feu, obs := trackerGrandRData.ObserveResponse(pkt.horodatageNs, pkt.ipClient, pkt.apexParent, pkt.qtype, pkt.trameDNS)
		// Vérification statique explicite des types de tous les champs de RenouvellementRDataObs :
		var (
			reponses        uint16 = obs.Reponses
			distinctes      uint8  = obs.Distinctes
			moyenneRDLength uint16 = obs.MoyenneRDLength
			permille        int64  = obs.Permille
			valide          bool   = obs.Valide
		)
		if rangGrandRData < 8 {
			if feu || valide {
				t.Fatalf("VayDNS MX grand RDATA #%d: déclenchement prématuré feu=%v obs=%+v", rangGrandRData, feu, obs)
			}
		} else if rangGrandRData == 8 {
			if !feu || !valide || reponses != 8 || distinctes < 6 || permille < 750 || moyenneRDLength < 128 {
				t.Fatalf("VayDNS MX 8e grand RDATA: feu=%v obs=%+v (attendu feu=true Valide=true Reponses=8 Permille>=750 MoyenneRDLength>=128)",
					feu, obs)
			}
			break
		}
	}
	if rangGrandRData < 8 {
		t.Fatalf("capture VayDNS MX: seulement %d réponses à grand RDATA trouvées", rangGrandRData)
	}

	// 2. Positif b) : 16 réponses CAA (qtype=257) et 16 réponses MX (qtype=15) avec RDATA distincts de 256 octets :
	client := [16]byte{10, 55, 0, 2}
	apex := []byte("tunnel-rdata.example")
	for _, qtypeTest := range []uint16{257, 15} {
		var tr RenouvellementRDataTracker
		var st StreamingDNS18State
		for i := 1; i <= 16; i++ {
			var rd []byte
			if qtypeTest == 257 {
				rd = rdataCAATailleExacte(i, 256)
			} else {
				rd = rdataMXTailleExacte256(i)
			}
			if len(rd) != 256 {
				t.Fatalf("fixture RDATA qtype=%d longueur=%d, attendu 256", qtypeTest, len(rd))
			}
			qname := fmt.Sprintf("n%02d.tunnel-rdata.example", i)
			sub := []byte(fmt.Sprintf("n%02d", i))
			trame := construireTrameReponseRFC(uint16(0x6000+i), 0, 0, qname, qtypeTest,
				[]enregistrementRFCFilaire{{proprietaire: qname, rrType: qtypeTest, ttl: 60, rdata: rd}},
				nil, nil,
			)
			ts := int64(i) * 1_000_000_000
			feu, obs := tr.ObserveResponse(ts, client, apex, qtypeTest, trame)
			cls, reason, consumed := st.ObserveAndClassify18(
				trame, ts, client, sub, apex, qtypeTest, DNSEpisodeSnapshot{}, EpisodeP3Features{},
			)
			if i <= 7 {
				if feu || obs.Valide {
					t.Fatalf("qtype=%d réponse #%d: feu=%v obs=%+v, attendu Valide=false avant la 8e", qtypeTest, i, feu, obs)
				}
			} else {
				if !feu || !obs.Valide || obs.Permille != 1000 || obs.MoyenneRDLength != 256 {
					t.Fatalf("qtype=%d réponse #%d: feu=%v obs=%+v, attendu feu=true Valide=true Permille=1000 MoyenneRDLength=256",
						qtypeTest, i, feu, obs)
				}
				if cls != "P15" || reason != ReasonP15RDataRenewal || !consumed {
					t.Fatalf("ObserveAndClassify18 qtype=%d réponse #%d: (%q, %q, %v), attendu (\"P15\", %q, true)",
						qtypeTest, i, cls, reason, consumed, ReasonP15RDataRenewal)
				}
			}
		}
	}

	// 3. Jumeau négatif a) : Rotation round-robin [A,B,C],[B,C,A],[C,A,B] sur MX et SRV avec TTL décroissant
	//    (300, 299, 298...) et pointeurs de compression RFC 1035 décalés par QNAME de longueurs variables :
	apexLab := []byte("pound2pound.fr")
	for _, rrTypeRR := range []uint16{15, 33} {
		var trRR RenouvellementRDataTracker
		for i := range 16 {
			premierLbl := "h" + strings.Repeat("a", i)
			trameRR := construireRoundRobinCompressible(uint16(0x7000+i), premierLbl, rrTypeRR, uint32(300-i), i)
			feu, obs := trRR.ObserveResponse(int64(i+1)*1_000_000_000, client, apexLab, rrTypeRR, trameRR)
			if feu || obs.Distinctes != 1 {
				t.Fatalf("round-robin rrType=%d réponse #%d: feu=%v obs=%+v, attendu feu=false et Distinctes=1",
					rrTypeRR, i+1, feu, obs)
			}
		}
	}

	// 4. Jumeau négatif b1) : Churn de cibles distinctes courtes (RDLength < 64) sur 16 réponses -> feu == false :
	var trCourt RenouvellementRDataTracker
	for i := range 16 {
		rdCourt := rdataCAATailleExacte(i, 32)
		trameCourte := construireTrameReponseRFC(uint16(0x7100+i), 0, 0, "svc.consul.example", 257,
			[]enregistrementRFCFilaire{{proprietaire: "svc.consul.example", rrType: 257, ttl: 5, rdata: rdCourt}},
			nil, nil,
		)
		feu, _ := trCourt.ObserveResponse(int64(i+1)*500_000_000, client, []byte("consul.example"), 257, trameCourte)
		if feu {
			t.Fatalf("churn court RDLength=32 réponse #%d: feu=true interdit", i+1)
		}
	}

	// 5. Jumeau négatif b2) : Churn modéré Consul/Kubernetes : 8 cibles distinctes de RDLength == 200
	//    répétées sur 16 réponses (8/16 = 500 permille < 750 permille) -> feu == false :
	var trModere RenouvellementRDataTracker
	var derniereObsModere RenouvellementRDataObs
	for i := range 16 {
		idCible := i / 2 // C0, C0, C1, C1, ..., C7, C7 -> jamais >= 750 permille, et exactement 8/16 = 500 à i=15
		rd200 := rdataCAATailleExacte(100+idCible, 200)
		trame200 := construireTrameReponseRFC(uint16(0x7200+i), 0, 0, "k8s.cluster.example", 257,
			[]enregistrementRFCFilaire{{proprietaire: "k8s.cluster.example", rrType: 257, ttl: 5, rdata: rd200}},
			nil, nil,
		)
		var feu bool
		feu, derniereObsModere = trModere.ObserveResponse(int64(i+1)*500_000_000, client, []byte("cluster.example"), 257, trame200)
		if feu {
			t.Fatalf("churn modéré 8/16 RDLength=200 réponse #%d: feu=true interdit (obs=%+v)", i+1, derniereObsModere)
		}
	}
	if !derniereObsModere.Valide || derniereObsModere.Distinctes != 8 || derniereObsModere.Permille != 500 || derniereObsModere.MoyenneRDLength != 200 {
		t.Fatalf("churn modéré 16e réponse: obs=%+v, attendu Valide=true Distinctes=8 Permille=500 MoyenneRDLength=200",
			derniereObsModere)
	}

	// 6. Jumeau négatif c1) : Expiration de fenêtre à 10 min (> 600_000_000_000 ns) :
	var trExpire RenouvellementRDataTracker
	for i := range 7 {
		rd := rdataCAATailleExacte(200+i, 256)
		trame := construireTrameReponseRFC(uint16(0x7300+i), 0, 0, "exp.example", 257,
			[]enregistrementRFCFilaire{{proprietaire: "exp.example", rrType: 257, ttl: 60, rdata: rd}},
			nil, nil,
		)
		if feu, _ := trExpire.ObserveResponse(int64(i)*1_000_000_000, client, []byte("exp.example"), 257, trame); feu {
			t.Fatalf("expiration pré-chauffage #%d: feu prématuré", i+1)
		}
	}
	trameApres10Min := construireTrameReponseRFC(0x7399, 0, 0, "exp.example", 257,
		[]enregistrementRFCFilaire{{proprietaire: "exp.example", rrType: 257, ttl: 60, rdata: rdataCAATailleExacte(299, 256)}},
		nil, nil,
	)
	feuExp, obsExp := trExpire.ObserveResponse(6*1_000_000_000+600_000_000_001, client, []byte("exp.example"), 257, trameApres10Min)
	if feuExp || obsExp.Valide || obsExp.Reponses != 1 || obsExp.Distinctes != 1 {
		t.Fatalf("après expiration > 10 min: feu=%v obs=%+v, attendu réinitialisation (Valide=false Reponses=1 Distinctes=1)",
			feuExp, obsExp)
	}

	// 7. Jumeau négatif c2) : Éviction LRU propre sur collision de 5 clés dans le même ensemble (& 255) :
	clesCollision := decouvrirCinqClesMemeAlveoleP15(t, client, 257)
	var trLRU RenouvellementRDataTracker
	envoyerCle := func(cle string, sel int, ts int64) (bool, RenouvellementRDataObs) {
		rd := rdataCAATailleExacte(sel, 256)
		trame := construireTrameReponseRFC(uint16(0x7400+sel), 0, 0, "h."+cle, 257,
			[]enregistrementRFCFilaire{{proprietaire: "h." + cle, rrType: 257, ttl: 60, rdata: rd}},
			nil, nil,
		)
		return trLRU.ObserveResponse(ts, client, []byte(cle), 257, trame)
	}
	// clesCollision[0] est créée en premier (t=1..6), clesCollision[1] à t=10..16 (7 rép),
	// clesCollision[2] à t=20..26 (7 rép), clesCollision[3] à t=30..36 (7 rép), puis clesCollision[0]
	// reçoit sa 7e réponse à t=50 -> la victime LRU authentique est clesCollision[1] (dernier accès t=16).
	for r := range 6 {
		envoyerCle(clesCollision[0], 1000+r, int64(1+r)*1_000_000)
	}
	for r := range 7 {
		envoyerCle(clesCollision[1], 2000+r, int64(10+r)*1_000_000)
		envoyerCle(clesCollision[2], 3000+r, int64(20+r)*1_000_000)
		envoyerCle(clesCollision[3], 4000+r, int64(30+r)*1_000_000)
	}
	if feu, obs := envoyerCle(clesCollision[0], 1006, 50*1_000_000); feu || obs.Reponses != 7 {
		t.Fatalf("7e réponse sur clesCollision[0]: feu=%v obs=%+v, attendu Reponses=7 sans feu", feu, obs)
	}
	// Insertion de la 5e clé en collision : doit évincer clesCollision[1] avec remise à zéro propre.
	if feu, obs := envoyerCle(clesCollision[4], 5000, 60*1_000_000); feu || obs.Valide || obs.Reponses != 1 || obs.Distinctes != 1 {
		t.Fatalf("insertion 5e clé en collision: feu=%v obs=%+v, attendu voie propre Reponses=1 Distinctes=1", feu, obs)
	}
	// clesCollision[0] (rafraîchie à t=50ms) a survécu : sa 8e réponse déclenche immédiatement !
	if feu, obs := envoyerCle(clesCollision[0], 1007, 70*1_000_000); !feu || !obs.Valide || obs.Reponses != 8 {
		t.Fatalf("8e réponse sur clesCollision[0] non-LRU: feu=%v obs=%+v, attendu feu=true Reponses=8", feu, obs)
	}
	// clesCollision[1] (évincée par LRU) repart proprement à 1 sans résidu :
	if feu, obs := envoyerCle(clesCollision[1], 2099, 80*1_000_000); feu || obs.Valide || obs.Reponses != 1 || obs.Distinctes != 1 {
		t.Fatalf("réinsertion de la victime LRU clesCollision[1]: feu=%v obs=%+v, attendu Reponses=1 Distinctes=1", feu, obs)
	}

	// 8. Jumeau négatif d) : 0 feu P15 sur les 200 réponses réelles de benign-rrtypes-clear.pcap :
	captureBenigne := lireCapturePCAPRawIPv4(t, "benign-rrtypes-clear.pcap")
	var trBenin RenouvellementRDataTracker
	var stBenin StreamingDNS18State
	nbBeninVerifies := 0
	for _, pkt := range captureBenigne {
		if !pkt.estReponse {
			continue
		}
		nbBeninVerifies++
		if feu, obs := trBenin.ObserveResponse(pkt.horodatageNs, pkt.ipClient, pkt.apexParent, pkt.qtype, pkt.trameDNS); feu {
			t.Errorf("benign-rrtypes réponse #%d (%s qtype=%d): faux positif ObserveResponse obs=%+v",
				nbBeninVerifies, string(pkt.qname), pkt.qtype, obs)
		}
		cls, reason, _ := stBenin.ObserveAndClassify18(
			pkt.trameDNS, pkt.horodatageNs, pkt.ipClient, pkt.sousDomaine, pkt.apexParent,
			pkt.qtype, DNSEpisodeSnapshot{}, EpisodeP3Features{},
		)
		if cls == "P15" || reason == ReasonP15RDataRenewal {
			t.Errorf("benign-rrtypes réponse #%d (%s qtype=%d): faux positif P15 ObserveAndClassify18 (%q, %q)",
				nbBeninVerifies, string(pkt.qname), pkt.qtype, cls, reason)
		}
	}
	if nbBeninVerifies != 200 {
		t.Fatalf("benign-rrtypes: %d réponses vérifiées, attendu 200", nbBeninVerifies)
	}
}

func TestRAT01_StripLeadingRFCUnderscoreLabelsAndSRVView(t *testing.T) {
	// 1. Vérification unitaire champ par champ de StripLeadingRFCUnderscoreLabels :
	casUnitaires := []struct {
		entree        string
		resteAttendu  string
		retireAttendu uint8
	}{
		{entree: "_https._tcp.svc00.c.lab", resteAttendu: "svc00.c.lab", retireAttendu: 2},
		{entree: "_sip._tls", resteAttendu: "", retireAttendu: 2},
		{entree: "_xmpp-server._tcp.chat.c.lab", resteAttendu: "chat.c.lab", retireAttendu: 2},
		{entree: "_evilbase32payload999.c.lab", resteAttendu: "_evilbase32payload999.c.lab", retireAttendu: 0},
		{entree: "svc00.c.lab", resteAttendu: "svc00.c.lab", retireAttendu: 0},
		{entree: "", resteAttendu: "", retireAttendu: 0},
	}
	for _, tc := range casUnitaires {
		reste, retires := StripLeadingRFCUnderscoreLabels([]byte(tc.entree))
		if string(reste) != tc.resteAttendu || len(reste) != len(tc.resteAttendu) || retires != tc.retireAttendu {
			t.Errorf("StripLeadingRFCUnderscoreLabels(%q) = (%q [len=%d], %d), attendu (%q [len=%d], %d)",
				tc.entree, string(reste), len(reste), retires, tc.resteAttendu, len(tc.resteAttendu), tc.retireAttendu)
		}
	}

	// 2. Chargement de la disquette scellée réelle floppy_dns_c2.c2book :
	cheminDisquette := filepath.Join("..", "..", "testdata", "wittgenstein", "floppies", "floppy_dns_c2.c2book")
	disquetteDNS, err := LoadFloppyMmap(cheminDisquette, WittgensteinFloppyKey(FloppyFamilyDNSC2))
	if err != nil {
		t.Fatalf("LoadFloppyMmap(%s): %v", cheminDisquette, err)
	}
	t.Cleanup(func() {
		if errClose := disquetteDNS.Close(); errClose != nil {
			t.Errorf("fermeture disquette DNS: %v", errClose)
		}
	})

	evaluerLotRequetesSRV := func(noms [][]byte, qtype uint16) (nbBloques int) {
		cardParParent := make(map[string]uint32)
		vusParentSous := make(map[string]bool)
		for _, fqdn := range noms {
			sub, sld, tld, parent, lc, maxLen, hasEnc, ok := splitDNSNameBytes(fqdn)
			if !ok {
				t.Fatalf("splitDNSNameBytes a échoué sur %q", string(fqdn))
			}
			cleParent := strings.ToLower(string(parent))
			if len(sub) > 0 {
				cle := cleParent + "\x00" + strings.ToLower(string(sub))
				if !vusParentSous[cle] {
					vusParentSous[cle] = true
					cardParParent[cleParent]++
				}
			}
			verdict := EvaluateDNSView(DNSQueryView{
				FQDN:            fqdn,
				Subdomain:       sub,
				SLD:             sld,
				TLD:             tld,
				QType:           qtype,
				LabelCount:      lc,
				MaxLabelLen:     maxLen,
				HasEncodingChar: hasEnc,
				SubCardinality:  max(cardParParent[cleParent], 1),
			}, disquetteDNS, nil)
			if verdict.Action == VerdictBlock {
				nbBloques++
			}
		}
		return nbBloques
	}

	// a) 50 requêtes SRV bénignes _https._tcp.svcXX.c.lab.pound2pound.fr de benign-rrtypes-clear.pcap :
	captureBenigne := lireCapturePCAPRawIPv4(t, "benign-rrtypes-clear.pcap")
	var srvBenins [][]byte
	for _, pkt := range captureBenigne {
		if !pkt.estReponse && pkt.qtype == 33 {
			srvBenins = append(srvBenins, pkt.qname)
		}
	}
	if len(srvBenins) != 50 {
		t.Fatalf("benign-rrtypes-clear.pcap: %d requêtes SRV extraites, attendu 50", len(srvBenins))
	}
	fpSRV := evaluerLotRequetesSRV(srvBenins, 33)
	if fpSRV > 5 {
		t.Fatalf("SRV bénins _https._tcp: FP=%d/50 blocages VerdictBlock, exigé <= 5", fpSRV)
	}

	// b) 366 requêtes SRV hostiles de vaydns-srv-clear.pcap + variante d'évasion préfixée par _sip._tls.<qname> :
	captureVaySRV := lireCapturePCAPRawIPv4(t, "vaydns-srv-clear.pcap")
	var srvHostiles [][]byte
	var srvHostilesPrefixes [][]byte
	for _, pkt := range captureVaySRV {
		if !pkt.estReponse && pkt.qtype == 33 {
			srvHostiles = append(srvHostiles, pkt.qname)
			srvHostilesPrefixes = append(srvHostilesPrefixes, []byte("_sip._tls."+string(pkt.qname)))
		}
	}
	if len(srvHostiles) != 366 {
		t.Fatalf("vaydns-srv-clear.pcap: %d requêtes SRV extraites, attendu 366", len(srvHostiles))
	}
	tpSRVBrut := evaluerLotRequetesSRV(srvHostiles, 33)
	tpSRVPrefixe := evaluerLotRequetesSRV(srvHostilesPrefixes, 33)

	tnSRV := len(srvBenins) - fpSRV
	fnSRVBrut := len(srvHostiles) - tpSRVBrut
	totalSRV := len(srvBenins) + len(srvHostiles)
	majSRV := float64(max(len(srvBenins), len(srvHostiles))) / float64(totalSRV)
	t.Logf("EvaluateDNSView SRV captures réelles: TP_brut=%d/366 TP_sip_tls=%d/366 FP=%d/50 TN=%d FN=%d majority_class_rate=%.6f",
		tpSRVBrut, tpSRVPrefixe, fpSRV, tnSRV, fnSRVBrut, majSRV)

	if tpSRVBrut < 340 {
		t.Fatalf("SRV hostiles VayDNS bruts: TP=%d/366 blocages VerdictBlock, exigé >= 340", tpSRVBrut)
	}
	if tpSRVPrefixe < 340 {
		t.Fatalf("évasion SRV VayDNS préfixée _sip._tls: TP=%d/366 blocages VerdictBlock, exigé >= 340", tpSRVPrefixe)
	}
}

func rdataSRVFilaire(port uint16, target string) []byte {
	var srvHdr [6]byte
	binary.BigEndian.PutUint16(srvHdr[0:2], 0)
	binary.BigEndian.PutUint16(srvHdr[2:4], 100)
	binary.BigEndian.PutUint16(srvHdr[4:6], port)
	var rd []byte
	rd = append(rd, srvHdr[:]...)
	rd = append(rd, encoderNomDNSFilaireRFC(target)...)
	return rd
}

func TestRAT01_SRVResponseShortCircuitAndNegativeFixes(t *testing.T) {
	client := [16]byte{10, 55, 0, 2}
	snap := DNSEpisodeSnapshot{
		DownlinkRatio:    4.5,
		MeanRDataEntropy: 4.8,
	}

	// 1. Cas bénin : échanges requête + réponse SRV Active Directory (qtype=33, port 389,
	//    cible courte dc01.corp-ad.internal) sous ratios descendants/entropie élevés.
	srvBenins := []struct {
		nom   string
		sous  string
		apex  string
		qname string
	}{
		{
			nom:   "ad-dc-msdcs",
			sous:  "_ldap._tcp.dc._msdcs",
			apex:  "corp-ad.internal",
			qname: "_ldap._tcp.dc._msdcs.corp-ad.internal",
		},
		{
			nom:   "ad-default-site",
			sous:  "_ldap._tcp.Default-First-Site-Name._sites",
			apex:  "corp-ad.internal",
			qname: "_ldap._tcp.Default-First-Site-Name._sites.corp-ad.internal",
		},
		{
			nom:   "ad-gc-msdcs",
			sous:  "_ldap._tcp.gc._msdcs",
			apex:  "corp-ad.internal",
			qname: "_ldap._tcp.gc._msdcs.corp-ad.internal",
		},
		{
			nom:   "ad-gc-tcp",
			sous:  "_gc._tcp",
			apex:  "corp-ad.internal",
			qname: "_gc._tcp.corp-ad.internal",
		},
	}

	var stBenin StreamingDNS18State
	for idx, tc := range srvBenins {
		if !IsRFCUnderscoreSubdomain(tc.sous) {
			t.Errorf("cas bénin %s: IsRFCUnderscoreSubdomain(%q) = false, attendu true", tc.nom, tc.sous)
		}
		reqWire := buildWireQuerySimple(uint16(0x8800+idx), tc.qname, 33)
		respWire := construireTrameReponseRFC(
			uint16(0x8800+idx), 0, 0, tc.qname, 33,
			[]enregistrementRFCFilaire{{
				proprietaire: tc.qname,
				rrType:       33,
				ttl:          600,
				rdata:        rdataSRVFilaire(389, "dc01.corp-ad.internal"),
			}},
			nil, nil,
		)
		ts := int64(idx+1) * 10_000_000
		cls, reason, consumed := stBenin.ObserveAndClassify18(
			reqWire, ts, client, []byte(tc.sous), []byte(tc.apex), 33, snap, EpisodeP3Features{},
		)
		if cls != "BENIGN" || reason != ReasonNone || !consumed {
			t.Errorf("cas bénin SRV req %s: obtenu (%q, %q, %v), attendu (\"BENIGN\", %q, true)",
				tc.nom, cls, reason, consumed, ReasonNone)
		}
		cls, reason, consumed = stBenin.ObserveAndClassify18(
			respWire, ts+1_000_000, client, []byte(tc.sous), []byte(tc.apex), 33, snap, EpisodeP3Features{},
		)
		if cls != "BENIGN" || reason != ReasonNone || !consumed {
			t.Errorf("cas bénin SRV resp %s: obtenu (%q, %q, %v), attendu (\"BENIGN\", %q, true)",
				tc.nom, cls, reason, consumed, ReasonNone)
		}
	}

	// 2. Jumeau négatif 1 (P7) : réponse SRV sur _ldap._tcp.dc._msdcs.corp-ad.internal
	//    avec port non-standard 4444 et cible encodée >= 20 octets -> P7.
	var st StreamingDNS18State
	qname := "_ldap._tcp.dc._msdcs.corp-ad.internal"
	sous := []byte("_ldap._tcp.dc._msdcs")
	apex := []byte("corp-ad.internal")
	trame := construireTrameReponseRFC(
		0x8901, 0, 0, qname, 33,
		[]enregistrementRFCFilaire{{
			proprietaire: qname,
			rrType:       33,
			ttl:          60,
			rdata:        rdataSRVFilaire(4444, "c2stage0123456789abcdef.corp-ad.internal"),
		}},
		nil, nil,
	)
	cls, reason, consumed := st.ObserveAndClassify18(
		trame, 100_000_000, client, sous, apex, 33, snap, EpisodeP3Features{},
	)
	if cls != "P7" || reason != ReasonP7SRVC2Endpoint || !consumed {
		t.Fatalf("jumeau négatif 1 (P7 SRV port 4444): obtenu (%q, %q, %v), attendu (\"P7\", %q, true)",
			cls, reason, consumed, ReasonP7SRVC2Endpoint)
	}

	// 3. Jumeau négatif 2 (P15) : >= 12 réponses SRV à port standard 389 mais RDATA distinctes
	//    (>= 48 octets et >= seuil P15) sous _ldap._tcp.dc._msdcs.corp-ad.internal -> P15.
	var stP15 StreamingDNS18State
	for i := 1; i <= 12; i++ {
		target := fmt.Sprintf(
			"n%02d-srv-node-aa.n%02d-srv-node-bb.n%02d-srv-node-cc.n%02d-srv-node-dd.n%02d-srv-node-ee.n%02d-srv-node-ff.n%02d-srv-node-gg.n%02d-srv-node-hh.corp-ad.internal",
			i, i, i, i, i, i, i, i,
		)
		rd := rdataSRVFilaire(389, target)
		if len(rd) < 48 {
			t.Fatalf("fixture RDATA SRV #%d trop courte: %d octets", i, len(rd))
		}
		respWire := construireTrameReponseRFC(
			uint16(0x8950+i), 0, 0, qname, 33,
			[]enregistrementRFCFilaire{{
				proprietaire: qname,
				rrType:       33,
				ttl:          60,
				rdata:        rd,
			}},
			nil, nil,
		)
		ts := int64(i) * 1_000_000_000
		cls, reason, consumed = stP15.ObserveAndClassify18(
			respWire, ts, client, sous, apex, 33, snap, EpisodeP3Features{},
		)
		if i < 8 {
			if cls != "BENIGN" || reason != ReasonNone || !consumed {
				t.Fatalf("jumeau négatif 2 pré-seuil #%d: obtenu (%q, %q, %v), attendu (\"BENIGN\", %q, true)",
					i, cls, reason, consumed, ReasonNone)
			}
		} else {
			if cls != "P15" || reason != ReasonP15RDataRenewal || !consumed {
				t.Fatalf("jumeau négatif 2 P15 réponse #%d: obtenu (%q, %q, %v), attendu (\"P15\", %q, true)",
					i, cls, reason, consumed, ReasonP15RDataRenewal)
			}
		}
	}
}

func TestRAT01_ZeroAllocHotPaths(t *testing.T) {
	captureSoar := lireCapturePCAPRawIPv4(t, "soar-signed-nxdomain-cache-auth.pcap")
	var pktSoar paquetDNSBrutPCAP
	for _, pkt := range captureSoar {
		if pkt.estReponse {
			pktSoar = pkt
			break
		}
	}
	var stP14 StreamingDNS18State
	allocsP14 := testing.AllocsPerRun(500, func() {
		stP14.ObserveAndClassify18(
			pktSoar.trameDNS, pktSoar.horodatageNs, pktSoar.ipClient,
			pktSoar.sousDomaine, pktSoar.apexParent, pktSoar.qtype,
			DNSEpisodeSnapshot{}, EpisodeP3Features{},
		)
	})
	if allocsP14 != 0 {
		t.Errorf("ObserveAndClassify18 (chemin P14): %.2f allocs/op, attendu 0", allocsP14)
	}

	captureVayMX := lireCapturePCAPRawIPv4(t, "vaydns-mx-clear.pcap")
	var pktMX paquetDNSBrutPCAP
	for _, pkt := range captureVayMX {
		if pkt.estReponse && pkt.totalRDLength >= 200 {
			pktMX = pkt
			break
		}
	}
	var stP15 StreamingDNS18State
	allocsStreamP15 := testing.AllocsPerRun(500, func() {
		stP15.ObserveAndClassify18(
			pktMX.trameDNS, pktMX.horodatageNs, pktMX.ipClient,
			pktMX.sousDomaine, pktMX.apexParent, pktMX.qtype,
			DNSEpisodeSnapshot{}, EpisodeP3Features{},
		)
	})
	if allocsStreamP15 != 0 {
		t.Errorf("ObserveAndClassify18 (chemin P15): %.2f allocs/op, attendu 0", allocsStreamP15)
	}

	var trackerP15 RenouvellementRDataTracker
	allocsTracker := testing.AllocsPerRun(500, func() {
		trackerP15.ObserveResponse(
			pktMX.horodatageNs, pktMX.ipClient, pktMX.apexParent, pktMX.qtype, pktMX.trameDNS,
		)
	})
	if allocsTracker != 0 {
		t.Errorf("RenouvellementRDataTracker.ObserveResponse: %.2f allocs/op, attendu 0", allocsTracker)
	}

	cheminDisquette := filepath.Join("..", "..", "testdata", "wittgenstein", "floppies", "floppy_dns_c2.c2book")
	disquetteDNS, err := LoadFloppyMmap(cheminDisquette, WittgensteinFloppyKey(FloppyFamilyDNSC2))
	if err != nil {
		t.Fatalf("LoadFloppyMmap: %v", err)
	}
	t.Cleanup(func() {
		if errClose := disquetteDNS.Close(); errClose != nil {
			t.Errorf("fermeture disquette DNS: %v", errClose)
		}
	})

	fqdnSRV := []byte("_https._tcp.svc00.c.lab.pound2pound.fr")
	subSRV, sldSRV, tldSRV, _, lcSRV, maxLenSRV, hasEncSRV, okSRV := splitDNSNameBytes(fqdnSRV)
	if !okSRV {
		t.Fatal("splitDNSNameBytes invalide sur fqdnSRV")
	}
	vueSRV := DNSQueryView{
		FQDN:            fqdnSRV,
		Subdomain:       subSRV,
		SLD:             sldSRV,
		TLD:             tldSRV,
		QType:           33,
		LabelCount:      lcSRV,
		MaxLabelLen:     maxLenSRV,
		HasEncodingChar: hasEncSRV,
		SubCardinality:  12,
	}
	allocsEvalSRV := testing.AllocsPerRun(500, func() {
		EvaluateDNSView(vueSRV, disquetteDNS, nil)
	})
	if allocsEvalSRV != 0 {
		t.Errorf("EvaluateDNSView (_https._tcp SRV): %.2f allocs/op, attendu 0", allocsEvalSRV)
	}
}
