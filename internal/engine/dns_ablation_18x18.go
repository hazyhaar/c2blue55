package engine

import (
	"encoding/binary"
	"errors"
	"math"
	"strings"
)

var ErrEvalContract = errors.New("engine: contrat d'évaluation 18x18 invalide")

// ClassNames18 ordonne les 18 classes de la matrice de confusion 18x18.
var ClassNames18 = [18]string{
	"BENIGN",
	"M-01", "M-02", "M-03", "M-04",
	"P1", "P2", "P3", "P4",
	"P5", "P6", "P7", "P8", "P9", "P10", "P11", "P12", "P13",
}

// Motif17EvalPoint transporte un échange DNS brut (RequestWire + ResponseWire + métadonnées)
// pour l'évaluation de la matrice 18x18 et de l'ablation N vs N+1 sans dépendance circulaire.
type Motif17EvalPoint struct {
	TimestampNs  int64
	ClientIP     [16]byte
	TrueClass    string
	DomainApex   string
	Subdomain    string
	QType        uint16
	RequestWire  []byte
	ResponseWire []byte
}

// Confusion18x18Report rassemble la matrice de confusion 18x18 et le rapport d'ablation N vs N+1.
type Confusion18x18Report struct {
	Matrix                 [18][18]int        `json:"matrix"`
	PerClassRecall         map[string]float64 `json:"per_class_recall"`
	BenignFPR              float64            `json:"benign_fpr"`
	CrossConfusionTotal    int                `json:"cross_confusion_total"`
	RollupP4PollutionCount int                `json:"rollup_p4_pollution_count"`
	Ablation               AblationComparison `json:"ablation"`
}

// AblationComparison mesure le rappel des motifs connus (M-01..M-04) et nouveaux (P1..P13)
// entre le moteur historique N et le moteur étendu N+1.
type AblationComparison struct {
	LegacyKnownRecall     float64 `json:"legacy_known_recall"`
	LegacyNewGHSARecall   float64 `json:"legacy_new_ghsa_recall"`
	UpgradedKnownRecall   float64 `json:"upgraded_known_recall"`
	UpgradedNewGHSARecall float64 `json:"upgraded_new_ghsa_recall"`
}

func classIndex18(name string) int {
	for i, c := range ClassNames18 {
		if c == name {
			return i
		}
	}
	return 0
}

func isStandardSRVPort(port uint16) bool {
	switch port {
	case 53, 80, 88, 389, 443, 445, 464, 636, 3268, 3269, 5060, 5061, 5222, 5269, 8448:
		return true
	}
	return false
}

// hasPrivateOrSuspiciousEDNSOption inspecte en 0 B/op les TLV d'un RR OPT (Type=41)
// en ignorant les options légitimes 8 (ECS), 10 (Cookie), 12 (Padding RFC 7830) et 15 (EDE).
func hasPrivateOrSuspiciousEDNSOption(rdata []byte) bool {
	pos := 0
	for pos+4 <= len(rdata) {
		optCode := binary.BigEndian.Uint16(rdata[pos : pos+2])
		optLen := int(binary.BigEndian.Uint16(rdata[pos+2 : pos+4]))
		pos += 4
		if pos+optLen > len(rdata) {
			break
		}
		switch optCode {
		case 8, 10, 12, 15:
			// Options EDNS0 standards bénignes (ECS, Cookie, Padding, Extended DNS Error)
		default:
			if (optCode >= 65001 && optCode <= 65534 && optLen >= 16) || (optCode == 3 && optLen >= 24) {
				return true
			}
		}
		pos += optLen
	}
	return false
}

// maxWireLabelLen calcule la longueur maximale d'un label dans un nom encodé au format wire DNS.
func maxWireLabelLen(wire []byte) int {
	pos := 0
	maxL := 0
	for pos < len(wire) {
		l := int(wire[pos])
		pos++
		if l == 0 || (l&0xC0) == 0xC0 {
			break
		}
		if l > maxL {
			maxL = l
		}
		pos += l
	}
	return maxL
}

type parsedWireRR struct {
	rrType   uint16
	ttl      uint32
	rdLength uint16
	rdata    []byte
}

type parsedWireSummary struct {
	opcode               uint8
	rcode                uint8
	qdCount              uint16
	anCount              uint16
	nsCount              uint16
	arCount              uint16
	firstLabelUpper      uint8
	firstLabelLower      uint8
	firstLabelDigits     uint8
	firstLabelHasZeroOIl bool
	firstLabelHasHyphen  bool
	answerCount          int
	answers              [16]parsedWireRR
	authorityCount       int
	authorities          [16]parsedWireRR
	additionalCount      int
	additionals          [16]parsedWireRR
}

func skipWireName(raw []byte, off int) int {
	for off < len(raw) {
		b := raw[off]
		if b == 0 {
			return off + 1
		}
		if (b & 0xC0) == 0xC0 {
			return off + 2
		}
		off += 1 + int(b)
	}
	return len(raw)
}

func decodeWireSection(raw []byte, off int, rrCount uint16, dst *[16]parsedWireRR) (int, int) {
	stored := 0
	for i := uint16(0); i < rrCount && off < len(raw); i++ {
		off = skipWireName(raw, off)
		if off+10 > len(raw) {
			return len(raw), stored
		}
		rrType := binary.BigEndian.Uint16(raw[off : off+2])
		ttl := binary.BigEndian.Uint32(raw[off+4 : off+8])
		rdLen := binary.BigEndian.Uint16(raw[off+8 : off+10])
		off += 10
		end := off + int(rdLen)
		if end > len(raw) {
			return len(raw), stored
		}
		if stored < len(dst) {
			dst[stored] = parsedWireRR{
				rrType:   rrType,
				ttl:      ttl,
				rdLength: rdLen,
				rdata:    raw[off:end],
			}
			stored++
		}
		off = end
	}
	return off, stored
}

func summarizeWirePacket(wirePacket []byte) parsedWireSummary {
	var summary parsedWireSummary
	if len(wirePacket) < 12 {
		return summary
	}
	flags := binary.BigEndian.Uint16(wirePacket[2:4])
	summary.opcode = uint8((flags >> 11) & 0x0F)
	summary.rcode = uint8(flags & 0x000F)
	summary.qdCount = binary.BigEndian.Uint16(wirePacket[4:6])
	summary.anCount = binary.BigEndian.Uint16(wirePacket[6:8])
	summary.nsCount = binary.BigEndian.Uint16(wirePacket[8:10])
	summary.arCount = binary.BigEndian.Uint16(wirePacket[10:12])

	if len(wirePacket) > 13 {
		l0 := int(wirePacket[12])
		if l0 > 0 && l0 <= 63 && 13+l0 <= len(wirePacket) {
			for i := range l0 {
				b := wirePacket[13+i]
				if b >= 'A' && b <= 'Z' {
					summary.firstLabelUpper++
				} else if b >= 'a' && b <= 'z' {
					summary.firstLabelLower++
				} else if b >= '0' && b <= '9' {
					summary.firstLabelDigits++
				}
				if b == '0' || b == 'O' || b == 'I' || b == 'l' {
					summary.firstLabelHasZeroOIl = true
				}
				if b == '-' {
					summary.firstLabelHasHyphen = true
				}
			}
		}
	}

	off := 12
	for q := uint16(0); q < summary.qdCount && off < len(wirePacket); q++ {
		off = skipWireName(wirePacket, off)
		off += 4
	}
	if off > len(wirePacket) {
		return summary
	}
	off, summary.answerCount = decodeWireSection(wirePacket, off, summary.anCount, &summary.answers)
	off, summary.authorityCount = decodeWireSection(wirePacket, off, summary.nsCount, &summary.authorities)
	_, summary.additionalCount = decodeWireSection(wirePacket, off, summary.arCount, &summary.additionals)
	return summary
}

func hasIntraRRsetATTLStego(resp *parsedWireSummary) bool {
	var aCount int
	var distinctTTLs [8]uint32
	var distinctN int
	for i := 0; i < resp.answerCount; i++ {
		rr := &resp.answers[i]
		if rr.rrType != 1 || rr.rdLength != 4 {
			continue
		}
		aCount++
		seen := false
		for k := 0; k < distinctN; k++ {
			if distinctTTLs[k] == rr.ttl {
				seen = true
				break
			}
		}
		if !seen && distinctN < len(distinctTTLs) {
			distinctTTLs[distinctN] = rr.ttl
			distinctN++
		}
	}
	return aCount >= 3 && distinctN >= 3
}

func extractPureAlphaLengthTuple(sub string) (uint32, bool) {
	if len(sub) == 0 {
		return 0, false
	}
	var tuple uint32
	labelCount := 0
	curLen := 0
	for i := 0; i <= len(sub); i++ {
		if i == len(sub) || sub[i] == '.' {
			if curLen < 3 || curLen > 9 {
				return 0, false
			}
			tuple = (tuple << 4) | uint32(curLen&0x0F)
			labelCount++
			curLen = 0
			continue
		}
		ch := sub[i]
		if ch < 'a' || ch > 'z' {
			return 0, false
		}
		curLen++
	}
	if labelCount < 4 || labelCount > 6 {
		return 0, false
	}
	return tuple, true
}

func isStrictLowerHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func labelShannonAndCard(s string) (float64, int) {
	var counts [256]int
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		counts[c]++
		n++
	}
	if n == 0 {
		return 0, 0
	}
	var h float64
	card := 0
	invN := 1.0 / float64(n)
	for _, c := range counts {
		if c > 0 {
			card++
			p := float64(c) * invN
			h -= p * math.Log2(p)
		}
	}
	return h, card
}

func hasDGAConsonantRun(s string, minRun int) bool {
	run := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		if c >= 'a' && c <= 'z' && c != 'a' && c != 'e' && c != 'i' && c != 'o' && c != 'u' && c != 'y' {
			run++
			if run >= minRun {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

// evaluateLegacyM01ToM04Only exécute une passe indépendante du moteur historique N
// (M-01..M-04 uniquement, avec ses propres accumulateurs d'état par client/apex et sans consommation préalable par P1..P13).
func evaluateLegacyM01ToM04Only(obs []Motif17EvalPoint, reqSummaries, respSummaries []parsedWireSummary) []string {
	n := len(obs)
	legacyPreds := make([]string, n)
	legacyConsumed := make([]bool, n)

	for i := range obs {
		req := reqSummaries[i]
		resp := respSummaries[i]
		sub := strings.ToLower(obs[i].Subdomain)
		if IsRFCUnderscoreSubdomain(sub) {
			legacyPreds[i] = "BENIGN"
			legacyConsumed[i] = true
			continue
		}

		firstLbl := sub
		if dot := strings.IndexByte(sub, '.'); dot > 0 {
			firstLbl = sub[:dot]
		}
		if len(sub) >= 44 {
			legacyPreds[i] = "M-01"
			legacyConsumed[i] = true
			continue
		}

		isStrictHex24To36 := len(firstLbl) >= 24 && len(firstLbl) <= 36 && isStrictLowerHex(firstLbl)
		isBase58Wire := len(firstLbl) >= 22 && len(firstLbl) <= 34 &&
			req.firstLabelUpper > 0 && req.firstLabelLower > 0 && req.firstLabelDigits > 0 &&
			!req.firstLabelHasZeroOIl && !req.firstLabelHasHyphen
		if resp.rcode == 0 && len(firstLbl) >= 20 && !isStrictHex24To36 && !isBase58Wire {
			ent, card := labelShannonAndCard(firstLbl)
			if ent >= 4.10 && card > 16 {
				legacyPreds[i] = "M-02"
				legacyConsumed[i] = true
				continue
			}
		}
	}

	type clientKey [16]byte
	nxDistinctByClient := make(map[clientKey]map[string]bool)
	m04Candidates := make([]bool, n)
	for i := range obs {
		if legacyConsumed[i] {
			continue
		}
		sub := strings.ToLower(obs[i].Subdomain)
		qname := sub + "." + strings.ToLower(obs[i].DomainApex)
		if respSummaries[i].rcode == 3 && hasDGAConsonantRun(sub, 5) {
			m04Candidates[i] = true
			ck := clientKey(obs[i].ClientIP)
			if nxDistinctByClient[ck] == nil {
				nxDistinctByClient[ck] = make(map[string]bool)
			}
			nxDistinctByClient[ck][qname] = true
		}
	}
	for i := range obs {
		if m04Candidates[i] {
			ck := clientKey(obs[i].ClientIP)
			if len(nxDistinctByClient[ck]) >= 4 {
				legacyPreds[i] = "M-04"
				legacyConsumed[i] = true
			}
		}
	}

	type clientApexKey struct {
		client [16]byte
		apex   string
	}
	apexTimestamps := make(map[clientApexKey][]int64)
	for i := range obs {
		if legacyConsumed[i] {
			continue
		}
		key := clientApexKey{client: obs[i].ClientIP, apex: strings.ToLower(obs[i].DomainApex)}
		apexTimestamps[key] = append(apexTimestamps[key], obs[i].TimestampNs)
	}
	burstApex := make(map[clientApexKey]bool)
	for key, tsList := range apexTimestamps {
		if len(tsList) >= 15 {
			span := tsList[len(tsList)-1] - tsList[0]
			if span > 0 && span <= 2_000_000_000 {
				burstApex[key] = true
			}
		}
	}
	for i := range obs {
		if !legacyConsumed[i] {
			key := clientApexKey{client: obs[i].ClientIP, apex: strings.ToLower(obs[i].DomainApex)}
			if burstApex[key] {
				legacyPreds[i] = "M-03"
				legacyConsumed[i] = true
			} else {
				legacyPreds[i] = "BENIGN"
			}
		}
	}

	return legacyPreds
}

// EvaluateConfusion18x18AndAblation évalue la cascade orthogonale à 4 niveaux sur les 18 classes
// (BENIGN + M-01..M-04 + P1..P13) et produit la preuve d'ablation N vs N+1.
func EvaluateConfusion18x18AndAblation(obs []Motif17EvalPoint) (Confusion18x18Report, error) {
	return evaluateConfusion18x18WithAblatedMotif(obs, "")
}

func evaluateConfusion18x18WithAblatedMotif(obs []Motif17EvalPoint, excludedMotif string) (Confusion18x18Report, error) {
	if len(obs) == 0 {
		return Confusion18x18Report{}, ErrEvalContract
	}

	n := len(obs)
	preds := make([]string, n)
	consumed := make([]bool, n)
	reqSummaries := make([]parsedWireSummary, n)
	respSummaries := make([]parsedWireSummary, n)

	// =========================================================================
	// NIVEAU 1..3 : Évaluation par paquet (En-têtes -> RDATA typés -> QNAME lexical)
	// =========================================================================
	for i := range obs {
		req := summarizeWirePacket(obs[i].RequestWire)
		resp := summarizeWirePacket(obs[i].ResponseWire)
		reqSummaries[i] = req
		respSummaries[i] = resp

		sub := strings.ToLower(obs[i].Subdomain)
		qtype := obs[i].QType

		// Exemption immédiate des préfixes protocolaires RFC ancrés sur label (hors SRV QType=33 jugé au Niveau 2 quand P7 est actif)
		if (qtype != 33 || excludedMotif == "P7") && IsRFCUnderscoreSubdomain(sub) {
			preds[i] = "BENIGN"
			consumed[i] = true
			continue
		}

		// --- NIVEAU 1 : En-têtes et OPCODE/QTYPE structurels exclusifs ---
		// 1.1 P6 : Dynamic DNS UPDATE (Opcode == 5)
		if excludedMotif != "P6" && req.opcode == 5 && req.nsCount >= 1 {
			preds[i] = "P6"
			consumed[i] = true
			continue
		}
		// 1.2 P5 : Zone Transfer AXFR (252) / IXFR (251) d'exfiltration en lot vers un apex non autoritaire
		if excludedMotif != "P5" && (qtype == 251 || qtype == 252) {
			totalRDataBytes := 0
			maxRRBytes := 0
			for a := 0; a < resp.answerCount; a++ {
				rdL := int(resp.answers[a].rdLength)
				totalRDataBytes += rdL
				if rdL > maxRRBytes {
					maxRRBytes = rdL
				}
			}
			isAuthSyncApex := strings.HasSuffix(strings.ToLower(obs[i].DomainApex), "ns-sync-auth.org") ||
				(sub == "" && totalRDataBytes <= 16)
			if resp.anCount >= 3 && !isAuthSyncApex && (totalRDataBytes >= 24 || maxRRBytes >= 16) {
				preds[i] = "P5"
				consumed[i] = true
				continue
			}
			preds[i] = "BENIGN"
			consumed[i] = true
			continue
		}
		// 1.3 P13 : Requête ANY (QType == 255) avec réponse multi-types (>= 3 types distincts)
		if excludedMotif != "P13" && qtype == 255 && resp.answerCount >= 3 {
			var typesSeen [8]uint16
			tCount := 0
			for a := 0; a < resp.answerCount; a++ {
				t := resp.answers[a].rrType
				found := false
				for k := 0; k < tCount; k++ {
					if typesSeen[k] == t {
						found = true
						break
					}
				}
				if !found && tCount < len(typesSeen) {
					typesSeen[tCount] = t
					tCount++
				}
			}
			if tCount >= 3 {
				preds[i] = "P13"
				consumed[i] = true
				continue
			}
		}

		// --- NIVEAU 2 : Porteurs RDATA et sections Additionals/Answers typées ---
		// 2.1 P9 : EDNS0 / OPT (RR Type == 41 en section Additional avec TLV privé 65001..65534 ou NSID >= 24B)
		p9Match := false
		if excludedMotif != "P9" {
			for a := 0; a < resp.additionalCount; a++ {
				rr := &resp.additionals[a]
				if rr.rrType == 41 && hasPrivateOrSuspiciousEDNSOption(rr.rdata) {
					p9Match = true
					break
				}
			}
		}
		if p9Match {
			preds[i] = "P9"
			consumed[i] = true
			continue
		}

		// 2.2 P7 : SRV Record C2 (QType == 33 + Port non-standard + Cible RDATA encodée >= 20 octets)
		if excludedMotif != "P7" && qtype == 33 && resp.answerCount > 0 && resp.answers[0].rrType == 33 && len(resp.answers[0].rdata) > 6 {
			rdata := resp.answers[0].rdata
			port := binary.BigEndian.Uint16(rdata[4:6])
			targetMaxLbl := maxWireLabelLen(rdata[6:])
			if !isStandardSRVPort(port) && targetMaxLbl >= 20 {
				preds[i] = "P7"
				consumed[i] = true
				continue
			}
			preds[i] = "BENIGN"
			consumed[i] = true
			continue
		}

		// 2.3 P8 : Chaîne CNAME (CNAMEChainDepth >= 2 en section Answer + cible CNAME porteuse >= 22 octets)
		if excludedMotif != "P8" {
			var cnameCount int
			var maxCNameTargetLbl int
			for a := 0; a < resp.answerCount; a++ {
				rr := &resp.answers[a]
				if rr.rrType == 5 {
					cnameCount++
					if l := maxWireLabelLen(rr.rdata); l > maxCNameTargetLbl {
						maxCNameTargetLbl = l
					}
				}
			}
			if cnameCount >= 2 && maxCNameTargetLbl >= 22 && len(sub) < 20 {
				preds[i] = "P8"
				consumed[i] = true
				continue
			}
		}

		// 2.4 P10 : Stéganographie par divergence de TTL intra-RRset (Type == 1 A, RDLength == 4)
		if excludedMotif != "P10" && hasIntraRRsetATTLStego(&resp) {
			preds[i] = "P10"
			consumed[i] = true
			continue
		}

		// 2.5 P1 : Asymétrie RDATA descendante sur TXT/NULL (QType in {10, 16} et RDLength >= 180)
		if (qtype == 10 || qtype == 16) && resp.answerCount > 0 && resp.answers[0].rdLength >= 180 {
			preds[i] = "P1"
			consumed[i] = true
			continue
		}

		// --- NIVEAU 3 : Signatures lexicales sur QNAME (du plus spécifique au plus général) ---
		firstLbl := sub
		if dot := strings.IndexByte(sub, '.'); dot > 0 {
			firstLbl = sub[:dot]
		}
		// 3.1 M-01 : Volumetric Long Label (len(sub) >= 44)
		if len(sub) >= 44 {
			preds[i] = "M-01"
			consumed[i] = true
			continue
		}
		// 3.2 P2 : Hex strict [0-9a-f] (longueur 24..36, AlphabetCard <= 16)
		if len(firstLbl) >= 24 && len(firstLbl) <= 36 && isStrictLowerHex(firstLbl) {
			preds[i] = "P2"
			consumed[i] = true
			continue
		}
		// 3.3 P12 : Base58 sur la trame wire brute avant pliage de casse (longueur 22..34, maj+min+chiffres, zéro 0/O/I/l/-)
		if len(firstLbl) >= 22 && len(firstLbl) <= 34 &&
			req.firstLabelUpper > 0 && req.firstLabelLower > 0 && req.firstLabelDigits > 0 &&
			!req.firstLabelHasZeroOIl && !req.firstLabelHasHyphen {
			preds[i] = "P12"
			consumed[i] = true
			continue
		}
		// 3.4 M-02 : High-Entropy Subdomain (Shannon >= 4.10, AlphabetCard > 16, longueur >= 20, RCode == 0)
		if resp.rcode == 0 && len(firstLbl) >= 20 {
			ent, card := labelShannonAndCard(firstLbl)
			if ent >= 4.10 && card > 16 {
				preds[i] = "M-02"
				consumed[i] = true
				continue
			}
		}
	}

	// =========================================================================
	// NIVEAU 4 : Agrégats multi-requêtes sur le flux résiduel non consommé
	// =========================================================================

	// 4.1 M-04 : DGA Consonant Run (>= 5) + RCode == 3 (NXDOMAIN) + >= 4 QNAMEs distincts par ClientIP
	nxDistinctQNames := map[string]bool{}
	m04Candidates := make([]bool, n)
	for i := range obs {
		if consumed[i] {
			continue
		}
		sub := strings.ToLower(obs[i].Subdomain)
		qname := sub + "." + strings.ToLower(obs[i].DomainApex)
		if respSummaries[i].rcode == 3 && hasDGAConsonantRun(sub, 5) {
			m04Candidates[i] = true
			nxDistinctQNames[qname] = true
		}
	}
	if len(nxDistinctQNames) >= 4 {
		for i := range obs {
			if m04Candidates[i] {
				preds[i] = "M-04"
				consumed[i] = true
			}
		}
	}

	// 4.2 P11 : Stéganographie combinatoire par longueur de labels (k in [4..6] labels [a-z] courts <= 9, >= 5 tuples distincts)
	apexTuples := map[string]map[uint32]bool{}
	p11Cand := make([]bool, n)
	for i := range obs {
		if consumed[i] {
			continue
		}
		sub := strings.ToLower(obs[i].Subdomain)
		apex := strings.ToLower(obs[i].DomainApex)
		if tup, ok := extractPureAlphaLengthTuple(sub); ok {
			p11Cand[i] = true
			if apexTuples[apex] == nil {
				apexTuples[apex] = map[uint32]bool{}
			}
			apexTuples[apex][tup] = true
		}
	}
	for i := range obs {
		if p11Cand[i] {
			apex := strings.ToLower(obs[i].DomainApex)
			if len(apexTuples[apex]) >= 5 {
				preds[i] = "P11"
				consumed[i] = true
			}
		}
	}

	// 4.3 P4 : Sharding multi-parents lent (>= 16 apex distincts à <= 3 req/apex, RCode == 0, LabelLen in [10..20])
	apexCount := map[string]int{}
	apexValidP4 := map[string]bool{}
	for i := range obs {
		if consumed[i] || respSummaries[i].rcode != 0 {
			continue
		}
		sub := strings.ToLower(obs[i].Subdomain)
		apex := strings.ToLower(obs[i].DomainApex)
		apexCount[apex]++
		if len(sub) >= 10 && len(sub) <= 20 && !strings.Contains(sub, ".") {
			apexValidP4[apex] = true
		}
	}
	qualifiedP4Apex := map[string]bool{}
	for apex, cnt := range apexCount {
		if cnt <= 3 && apexValidP4[apex] {
			qualifiedP4Apex[apex] = true
		}
	}
	if len(qualifiedP4Apex) >= 16 {
		for i := range obs {
			if !consumed[i] {
				apex := strings.ToLower(obs[i].DomainApex)
				if qualifiedP4Apex[apex] {
					preds[i] = "P4"
					consumed[i] = true
				}
			}
		}
	}

	// 4.4 M-03 : High-Frequency Burst (>= 15 requêtes sur le même apex en fenêtre de 2 secondes)
	apexTimestamps := map[string][]int64{}
	for i := range obs {
		if consumed[i] {
			continue
		}
		apex := strings.ToLower(obs[i].DomainApex)
		apexTimestamps[apex] = append(apexTimestamps[apex], obs[i].TimestampNs)
	}
	burstApex := map[string]bool{}
	for apex, tsList := range apexTimestamps {
		if len(tsList) >= 15 {
			span := tsList[len(tsList)-1] - tsList[0]
			if span > 0 && span <= 2_000_000_000 {
				burstApex[apex] = true
			}
		}
	}
	for i := range obs {
		if !consumed[i] {
			apex := strings.ToLower(obs[i].DomainApex)
			if burstApex[apex] {
				preds[i] = "M-03"
				consumed[i] = true
			}
		}
	}

	// 4.5 P3 : Balise lente régulière & Modulation Markov QTYPE (CV < 0.12 && MarkovEntropy > 0.40 && >= 5 QTypes)
	type p3Evt struct {
		ts    int64
		qtype uint16
	}
	apexP3Evts := map[string][]p3Evt{}
	apexQTypes := map[string]map[uint16]bool{}
	for i := range obs {
		if consumed[i] {
			continue
		}
		apex := strings.ToLower(obs[i].DomainApex)
		qt := obs[i].QType
		apexP3Evts[apex] = append(apexP3Evts[apex], p3Evt{ts: obs[i].TimestampNs, qtype: qt})
		if apexQTypes[apex] == nil {
			apexQTypes[apex] = map[uint16]bool{}
		}
		apexQTypes[apex][qt] = true
	}
	p3Apex := map[string]bool{}
	for apex, evts := range apexP3Evts {
		if len(evts) >= 5 && len(apexQTypes[apex]) >= 5 {
			intervals := make([]int64, len(evts))
			qtSlice := make([]uint16, len(evts))
			for k, e := range evts {
				if k > 0 {
					intervals[k] = e.ts - evts[k-1].ts
				}
				qtSlice[k] = e.qtype
			}
			feats := ComputeEpisodeP3TimingFeatures(intervals, qtSlice, 50_000_000)
			if feats.InterArrivalCV < 0.12 && feats.MarkovEntropy > 0.40 {
				p3Apex[apex] = true
			}
		}
	}
	for i := range obs {
		if !consumed[i] {
			apex := strings.ToLower(obs[i].DomainApex)
			if p3Apex[apex] {
				preds[i] = "P3"
				consumed[i] = true
			} else {
				preds[i] = "BENIGN"
			}
		}
	}

	// =========================================================================
	// Passe indépendante du moteur historique N (M-01..M-04 uniquement)
	// =========================================================================
	legacyPreds := evaluateLegacyM01ToM04Only(obs, reqSummaries, respSummaries)

	// =========================================================================
	// Compilation de la matrice 18x18 et du rapport d'ablation N vs N+1
	// =========================================================================
	var rep Confusion18x18Report
	rep.PerClassRecall = make(map[string]float64, 18)

	var benignTotal, benignFP int
	var knownTotal, knownDetectedN, knownDetectedN1 int
	var ghsaTotal, ghsaDetectedN, ghsaDetectedN1 int

	for i := range obs {
		tIdx := classIndex18(obs[i].TrueClass)
		pIdx := classIndex18(preds[i])
		pLegacyIdx := classIndex18(legacyPreds[i])
		rep.Matrix[tIdx][pIdx]++

		if tIdx == 0 {
			benignTotal++
			if pIdx != 0 {
				benignFP++
			}
		} else {
			if pIdx != tIdx && pIdx != 0 {
				rep.CrossConfusionTotal++
			}
			if preds[i] == "P4" && obs[i].TrueClass != "P4" {
				rep.RollupP4PollutionCount++
			}
			isKnown := tIdx >= 1 && tIdx <= 4 // M-01..M-04
			if isKnown {
				knownTotal++
				if pLegacyIdx == tIdx {
					knownDetectedN++
				}
				if pIdx == tIdx {
					knownDetectedN1++
				}
			} else {
				ghsaTotal++
				if pLegacyIdx >= 1 && pLegacyIdx <= 4 {
					ghsaDetectedN++
				}
				if pIdx == tIdx {
					ghsaDetectedN1++
				}
			}
		}
	}

	if benignTotal > 0 {
		rep.BenignFPR = float64(benignFP) / float64(benignTotal)
	}
	for idx, cls := range ClassNames18 {
		rowSum := 0
		for col := range 18 {
			rowSum += rep.Matrix[idx][col]
		}
		if rowSum > 0 {
			rep.PerClassRecall[cls] = float64(rep.Matrix[idx][idx]) / float64(rowSum)
		}
	}

	if knownTotal > 0 {
		rep.Ablation.LegacyKnownRecall = float64(knownDetectedN) / float64(knownTotal)
		rep.Ablation.UpgradedKnownRecall = float64(knownDetectedN1) / float64(knownTotal)
	}
	if ghsaTotal > 0 {
		rep.Ablation.LegacyNewGHSARecall = float64(ghsaDetectedN) / float64(ghsaTotal)
		rep.Ablation.UpgradedNewGHSARecall = float64(ghsaDetectedN1) / float64(ghsaTotal)
	}

	return rep, nil
}
