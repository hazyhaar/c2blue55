package engine

import (
	"encoding/binary"
	"errors"
	"math"
	"slices"
	"unsafe"
)

const (
	ReasonNone                     = "REASON_NONE"
	ReasonM01LongLabel             = "REASON_M01_LONG_LABEL"
	ReasonM02HighEntropy           = "REASON_M02_HIGH_ENTROPY"
	ReasonM03Burst                 = "REASON_M03_HIGH_FREQ_BURST"
	ReasonM04DGAConsonantNX        = "REASON_M04_DGA_CONSONANT_NX"
	ReasonP1DownlinkExfil          = "REASON_P1_DOWNLINK_EXFIL"
	ReasonP2DenseEncoding          = "REASON_P2_DENSE_ENCODING"
	ReasonP3BeaconMarkov           = "REASON_P3_BEACON_MARKOV"
	ReasonP4MultiParentSharding    = "REASON_P4_MULTIPARENT_SHARDING"
	ReasonP5AXFRBulk               = "REASON_P5_AXFR_BULK"
	ReasonP6DynamicUpdate          = "REASON_P6_DYNAMIC_UPDATE"
	ReasonP7SRVC2Endpoint          = "REASON_P7_SRV_C2"
	ReasonP8CNameChain             = "REASON_P8_CNAME_CHAIN"
	ReasonP9EDNS0PrivateOption     = "REASON_P9_EDNS0_PRIVATE"
	ReasonP10TTLStegoIntraA        = "REASON_P10_TTL_STEGO"
	ReasonP11LengthTupleStego      = "REASON_P11_LENGTH_TUPLE"
	ReasonP12Base58Case            = "REASON_P12_BASE58_CASE"
	ReasonP13ANYWildcard           = "REASON_P13_ANY_WILDCARD"
	ReasonP14NegativeAnswerPayload = "REASON_P14_NXDOMAIN_ANSWER_PAYLOAD"
	ReasonP15RDataRenewal          = "REASON_P15_RDATA_RENEWAL"
)

type StreamEvalPoint struct {
	PacketIndex int
	TimestampNs int64
	TrueFamily  string
	Subdomain   string
	Snap        DNSEpisodeSnapshot
	P3          EpisodeP3Features
	P4          ClientP4Features
}

type FamilyTTDReport struct {
	Family               string `json:"family"`
	Detected             bool   `json:"detected"`
	PacketsToDetect      int    `json:"packets_to_detect"`
	NanosecondsToDetect  int64  `json:"nanoseconds_to_detect"`
	FirstReasonCode      string `json:"first_reason_code"`
	TotalFamilyPackets   int    `json:"total_family_packets"`
	BenignFalsePositives int    `json:"benign_false_positives"`
}

type apexStreamSlot struct {
	apexHash  uint64
	tupleSet  [8]uint32
	tupleCnt  uint8
	burstRing [16]int64
	burstHead uint8
	burstCnt  uint8
	p3TS      [8]int64
	p3QT      [8]uint16
	p3Cnt     uint8
}

// StreamingDNS18State maintient en 0 B/op les compteurs circulaires de Niveau 4
// (M-04 NXDOMAIN distincts, P11 tuples de longueurs, M-03 rafale 2s, P3 Markov QTYPE, P4 sharding)
// pour la classification temps réel des 18 classes DNS.
type StreamingDNS18State struct {
	m04QNameHashes [16]uint64
	m04Count       uint8
	p4ApexHashes   [32]uint64
	p4Count        uint8
	apexSlots      [64]apexStreamSlot
	rdataRenewal   RenouvellementRDataTracker
}

func fnv64BytesStream(b []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

func fnv64PairStream(a, b []byte) uint64 {
	h := fnv64BytesStream(a)
	h ^= uint64('.')
	h *= 1099511628211
	for _, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

const maxRFCUnderscoreCompanionLabel = 32

func equalFoldLiteralASCII(label []byte, attendu string) bool {
	if len(label) != len(attendu) {
		return false
	}
	for indice := range len(attendu) {
		caractere := label[indice]
		if caractere >= 'A' && caractere <= 'Z' {
			caractere += 32
		}
		if caractere != attendu[indice] {
			return false
		}
	}
	return true
}

func isAllowedRFCUnderscoreLabel(label []byte) bool {
	switch len(label) {
	case 3:
		return equalFoldLiteralASCII(label, "_gc")
	case 4:
		return equalFoldLiteralASCII(label, "_spf") ||
			equalFoldLiteralASCII(label, "_tcp") ||
			equalFoldLiteralASCII(label, "_udp") ||
			equalFoldLiteralASCII(label, "_tls") ||
			equalFoldLiteralASCII(label, "_sip") ||
			equalFoldLiteralASCII(label, "_dns") ||
			equalFoldLiteralASCII(label, "_ntp") ||
			equalFoldLiteralASCII(label, "_ssh")
	case 5:
		return equalFoldLiteralASCII(label, "_dane") ||
			equalFoldLiteralASCII(label, "_quic") ||
			equalFoldLiteralASCII(label, "_http") ||
			equalFoldLiteralASCII(label, "_ldap") ||
			equalFoldLiteralASCII(label, "_xmpp") ||
			equalFoldLiteralASCII(label, "_sips") ||
			equalFoldLiteralASCII(label, "_imap") ||
			equalFoldLiteralASCII(label, "_pop3") ||
			equalFoldLiteralASCII(label, "_turn") ||
			equalFoldLiteralASCII(label, "_stun") ||
			equalFoldLiteralASCII(label, "_sctp")
	case 6:
		return equalFoldLiteralASCII(label, "_dmarc") ||
			equalFoldLiteralASCII(label, "_https") ||
			equalFoldLiteralASCII(label, "_imaps") ||
			equalFoldLiteralASCII(label, "_pop3s") ||
			equalFoldLiteralASCII(label, "_ldaps") ||
			equalFoldLiteralASCII(label, "_turns") ||
			equalFoldLiteralASCII(label, "_stuns") ||
			equalFoldLiteralASCII(label, "_msdcs") ||
			equalFoldLiteralASCII(label, "_sites")
	case 7:
		return equalFoldLiteralASCII(label, "_caldav") ||
			equalFoldLiteralASCII(label, "_matrix")
	case 8:
		return equalFoldLiteralASCII(label, "_mta-sts") ||
			equalFoldLiteralASCII(label, "_caldavs") ||
			equalFoldLiteralASCII(label, "_carddav") ||
			equalFoldLiteralASCII(label, "_kpasswd")
	case 9:
		return equalFoldLiteralASCII(label, "_kerberos") ||
			equalFoldLiteralASCII(label, "_carddavs")
	case 10:
		return equalFoldLiteralASCII(label, "_domainkey")
	case 11:
		return equalFoldLiteralASCII(label, "_submission")
	case 12:
		return equalFoldLiteralASCII(label, "_xmpp-server") ||
			equalFoldLiteralASCII(label, "_xmpp-client")
	case 13:
		return equalFoldLiteralASCII(label, "_autodiscover")
	case 15:
		return equalFoldLiteralASCII(label, "_acme-challenge")
	default:
		return false
	}
}

func isRFCUnderscoreBytes(sub []byte) bool {
	if len(sub) == 0 {
		return false
	}
	debut := 0
	aLabelUnderscore := false
	for indice := 0; indice <= len(sub); indice++ {
		if indice < len(sub) && sub[indice] != '.' {
			continue
		}
		label := sub[debut:indice]
		if len(label) == 0 || len(label) > maxRFCUnderscoreCompanionLabel {
			return false
		}
		if label[0] == '_' {
			if !isAllowedRFCUnderscoreLabel(label) {
				return false
			}
			aLabelUnderscore = true
		}
		debut = indice + 1
	}
	return aLabelUnderscore
}

func bytesHasSuffixFoldASCII(s []byte, suffix string) bool {
	if len(s) < len(suffix) {
		return false
	}
	off := len(s) - len(suffix)
	for i := range len(suffix) {
		ch := s[off+i]
		if ch >= 'A' && ch <= 'Z' {
			ch += 32
		}
		if ch != suffix[i] {
			return false
		}
	}
	return true
}

func firstLabelSlice(sub []byte) []byte {
	for i, b := range sub {
		if b == '.' {
			return sub[:i]
		}
	}
	return sub
}

func isStrictLowerHexBytes(s []byte) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func labelShannonAndCardBytes(s []byte) (float64, int) {
	if len(s) == 0 {
		return 0, 0
	}
	var counts [256]uint16
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		counts[c]++
	}
	invN := 1.0 / float64(len(s))
	var ent float64
	card := 0
	for _, cnt := range counts {
		if cnt > 0 {
			card++
			p := float64(cnt) * invN
			ent -= p * math.Log2(p)
		}
	}
	return ent, card
}

func hasDGAConsonantRunBytes(s []byte, minRun int) bool {
	run := 0
	for _, c := range s {
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

func extractPureAlphaLengthTupleBytes(sub []byte) (uint32, bool) {
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
		if ch >= 'A' && ch <= 'Z' {
			ch += 32
		}
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

func bytesContainsByte(s []byte, target byte) bool {
	return slices.Contains(s, target)
}

func (st *StreamingDNS18State) slotForApex(apexHash uint64) *apexStreamSlot {
	idx := int(apexHash & 63)
	for step := range 64 {
		probe := (idx + step) & 63
		slot := &st.apexSlots[probe]
		if slot.apexHash == apexHash {
			return slot
		}
		if slot.apexHash == 0 {
			slot.apexHash = apexHash
			return slot
		}
	}
	slot := &st.apexSlots[idx]
	*slot = apexStreamSlot{apexHash: apexHash}
	return slot
}

func hasNegativeAnswerPayloadP14(summary *parsedWireSummary) bool {
	if summary.anCount > uint16(summary.answerCount) ||
		summary.nsCount > uint16(summary.authorityCount) ||
		summary.arCount > uint16(summary.additionalCount) {
		return true
	}
	for indice := 0; indice < summary.answerCount; indice++ {
		switch summary.answers[indice].rrType {
		case 5, 39, 46:
		default:
			return true
		}
	}
	for indice := 0; indice < summary.authorityCount; indice++ {
		switch summary.authorities[indice].rrType {
		case 6, 46, 47, 50:
		default:
			return true
		}
	}
	for indice := 0; indice < summary.additionalCount; indice++ {
		enregistrement := &summary.additionals[indice]
		switch enregistrement.rrType {
		case 41:
			if (enregistrement.ttl >> 24) != 0 {
				return true
			}
		case 24, 46, 47, 50, 250:
		default:
			return true
		}
	}
	return false
}

// ObserveAndClassify18 évalue en 0 B/op un paquet DNS wire selon la cascade à 4 niveaux
// (BENIGN + M-01..M-04 + P1..P15).
func (st *StreamingDNS18State) ObserveAndClassify18(wirePacket []byte, tsNs int64, clientIP [16]byte, subdomain, parentApex []byte, qtype uint16, snap DNSEpisodeSnapshot, p3 EpisodeP3Features) (string, string, bool) {
	isResp := len(wirePacket) >= 4 && (binary.BigEndian.Uint16(wirePacket[2:4])&0x8000) != 0
	estUnderscoreRFC := isRFCUnderscoreBytes(subdomain)
	if !isResp && qtype != 33 && estUnderscoreRFC {
		return "BENIGN", ReasonNone, true
	}

	summary := summarizeWirePacket(wirePacket)

	// --- NIVEAU 1 : En-têtes et OPCODE/QTYPE structurels exclusifs ---
	if summary.opcode == 5 && summary.nsCount >= 1 {
		return "P6", ReasonP6DynamicUpdate, true
	}
	if qtype == 251 || qtype == 252 {
		if isResp {
			totalRDataBytes := 0
			maxRRBytes := 0
			for a := 0; a < summary.answerCount; a++ {
				rdL := int(summary.answers[a].rdLength)
				totalRDataBytes += rdL
				if rdL > maxRRBytes {
					maxRRBytes = rdL
				}
			}
			isAuthSyncApex := bytesHasSuffixFoldASCII(parentApex, "ns-sync-auth.org") ||
				(len(subdomain) == 0 && totalRDataBytes <= 16)
			if summary.anCount >= 3 && !isAuthSyncApex && (totalRDataBytes >= 24 || maxRRBytes >= 16) {
				return "P5", ReasonP5AXFRBulk, true
			}
		}
		return "BENIGN", ReasonNone, true
	}
	if qtype == 255 {
		if isResp && summary.answerCount >= 3 {
			var typesSeen [8]uint16
			tCount := 0
			for a := 0; a < summary.answerCount; a++ {
				rrT := summary.answers[a].rrType
				found := false
				for k := 0; k < tCount; k++ {
					if typesSeen[k] == rrT {
						found = true
						break
					}
				}
				if !found && tCount < len(typesSeen) {
					typesSeen[tCount] = rrT
					tCount++
				}
			}
			if tCount >= 3 {
				return "P13", ReasonP13ANYWildcard, true
			}
		}
		return "BENIGN", ReasonNone, true
	}

	// --- NIVEAU 2 : Porteurs RDATA et sections Additionals/Answers/Authorities typées ---
	if isResp {
		if summary.opcode == 0 && summary.rcode == 3 && hasNegativeAnswerPayloadP14(&summary) {
			return "P14", ReasonP14NegativeAnswerPayload, true
		}
		for a := 0; a < summary.additionalCount; a++ {
			rr := &summary.additionals[a]
			if rr.rrType == 41 && hasPrivateOrSuspiciousEDNSOption(rr.rdata) {
				return "P9", ReasonP9EDNS0PrivateOption, true
			}
		}
	}
	if qtype == 33 {
		if isResp && summary.answerCount > 0 && summary.answers[0].rrType == 33 && len(summary.answers[0].rdata) > 6 {
			rdata := summary.answers[0].rdata
			port := binary.BigEndian.Uint16(rdata[4:6])
			targetMaxLbl := maxWireLabelLen(rdata[6:])
			if !isStandardSRVPort(port) && targetMaxLbl >= 20 {
				return "P7", ReasonP7SRVC2Endpoint, true
			}
		}
		if !isResp {
			return "BENIGN", ReasonNone, true
		}
	}
	if isResp {
		cnameCount := 0
		maxCNameTargetLbl := 0
		for a := 0; a < summary.answerCount; a++ {
			rr := &summary.answers[a]
			if rr.rrType == 5 {
				cnameCount++
				if l := maxWireLabelLen(rr.rdata); l > maxCNameTargetLbl {
					maxCNameTargetLbl = l
				}
			}
		}
		if cnameCount >= 2 && maxCNameTargetLbl >= 22 && len(subdomain) < 20 {
			return "P8", ReasonP8CNameChain, true
		}
		if hasIntraRRsetATTLStego(&summary) {
			return "P10", ReasonP10TTLStegoIntraA, true
		}
		declenchementP15, _ := st.rdataRenewal.ObserveResponse(tsNs, clientIP, parentApex, qtype, wirePacket)
		if (qtype == 10 || (qtype == 16 && !estUnderscoreRFC)) && summary.answerCount > 0 && summary.answers[0].rdLength >= 180 {
			return "P1", ReasonP1DownlinkExfil, true
		}
		if declenchementP15 {
			return "P15", ReasonP15RDataRenewal, true
		}
		if qtype == 33 || estUnderscoreRFC {
			return "BENIGN", ReasonNone, true
		}
	}
	if snap.DownlinkRatio > 2.0 && snap.MeanRDataEntropy > 4.0 {
		return "P1", ReasonP1DownlinkExfil, true
	}

	// --- NIVEAU 3 : Signatures lexicales sur QNAME (du plus spécifique au plus général) ---
	firstLbl := firstLabelSlice(subdomain)
	if len(subdomain) >= 44 {
		return "M-01", ReasonM01LongLabel, true
	}
	if len(firstLbl) >= 24 && len(firstLbl) <= 36 && isStrictLowerHexBytes(firstLbl) {
		return "P2", ReasonP2DenseEncoding, true
	}
	if len(firstLbl) >= 22 && len(firstLbl) <= 34 &&
		summary.firstLabelUpper > 0 && summary.firstLabelLower > 0 && summary.firstLabelDigits > 0 &&
		!summary.firstLabelHasZeroOIl && !summary.firstLabelHasHyphen {
		return "P12", ReasonP12Base58Case, true
	}
	if (!isResp || summary.rcode == 0) && len(firstLbl) >= 20 {
		ent, card := labelShannonAndCardBytes(firstLbl)
		if ent >= 4.10 && card > 16 {
			return "M-02", ReasonM02HighEntropy, true
		}
	}

	// --- NIVEAU 4 : Agrégats multi-requêtes en 0 B/op ---
	apexHash := fnv64BytesStream(parentApex)
	slot := st.slotForApex(apexHash)

	// 4.1 M-04 : DGA Consonant Run (>= 5) + RCode == 3 (NXDOMAIN) sur >= 4 QNAMEs distincts
	if hasDGAConsonantRunBytes(subdomain, 5) {
		if isResp && summary.rcode == 3 {
			qnHash := fnv64PairStream(subdomain, parentApex)
			seen := false
			for i := uint8(0); i < st.m04Count; i++ {
				if st.m04QNameHashes[i] == qnHash {
					seen = true
					break
				}
			}
			if !seen && int(st.m04Count) < len(st.m04QNameHashes) {
				st.m04QNameHashes[st.m04Count] = qnHash
				st.m04Count++
			}
			if st.m04Count >= 4 {
				return "M-04", ReasonM04DGAConsonantNX, true
			}
		}
		return "BENIGN", ReasonNone, true
	}

	// 4.2 P11 : Stéganographie combinatoire par longueur de labels (k in [4..6] labels [a-z] courts <= 9, >= 5 tuples)
	if tup, ok := extractPureAlphaLengthTupleBytes(subdomain); ok {
		seen := false
		for i := uint8(0); i < slot.tupleCnt; i++ {
			if slot.tupleSet[i] == tup {
				seen = true
				break
			}
		}
		if !seen && int(slot.tupleCnt) < len(slot.tupleSet) {
			slot.tupleSet[slot.tupleCnt] = tup
			slot.tupleCnt++
		}
		if slot.tupleCnt >= 5 {
			return "P11", ReasonP11LengthTupleStego, true
		}
		return "BENIGN", ReasonNone, true
	}

	// 4.3 P4 : Sharding multi-parents lent (sous-domaine [10..32] sans '.', '-', '_' sur >= 4 apex distincts)
	if len(subdomain) >= 10 && len(subdomain) <= 32 &&
		!bytesContainsByte(subdomain, '.') && !bytesContainsByte(subdomain, '-') && !bytesContainsByte(subdomain, '_') {
		if !isResp || summary.rcode == 0 {
			seen := false
			for i := uint8(0); i < st.p4Count; i++ {
				if st.p4ApexHashes[i] == apexHash {
					seen = true
					break
				}
			}
			if !seen && int(st.p4Count) < len(st.p4ApexHashes) {
				st.p4ApexHashes[st.p4Count] = apexHash
				st.p4Count++
			}
			if st.p4Count >= 4 {
				return "P4", ReasonP4MultiParentSharding, true
			}
		}
		return "BENIGN", ReasonNone, false
	}

	// 4.4 M-03 & 4.5 P3 : Évalués sur les requêtes (QR=0) vers le même apex
	if !isResp {
		slot.burstRing[slot.burstHead&15] = tsNs
		slot.burstHead++
		if slot.burstCnt < 16 {
			slot.burstCnt++
		}
		if slot.burstCnt >= 15 {
			oldestIdx := (slot.burstHead - 15) & 15
			span := tsNs - slot.burstRing[oldestIdx]
			if span > 0 && span <= 2_000_000_000 {
				return "M-03", ReasonM03Burst, true
			}
		}

		// P3 : fusion Happy Eyeballs A+AAAA (< 50 ms) puis CV Welford + Markov QTYPE
		isHEPair := false
		if slot.p3Cnt > 0 {
			lastIdx := slot.p3Cnt - 1
			dt := tsNs - slot.p3TS[lastIdx]
			prevQT := slot.p3QT[lastIdx]
			if dt >= 0 && dt <= 50_000_000 && ((qtype == 28 && prevQT == 1) || (qtype == 1 && prevQT == 28)) {
				isHEPair = true
			}
		}
		if !isHEPair {
			if int(slot.p3Cnt) < len(slot.p3TS) {
				slot.p3TS[slot.p3Cnt] = tsNs
				slot.p3QT[slot.p3Cnt] = qtype
				slot.p3Cnt++
			} else {
				for k := range len(slot.p3TS) - 1 {
					slot.p3TS[k] = slot.p3TS[k+1]
					slot.p3QT[k] = slot.p3QT[k+1]
				}
				slot.p3TS[len(slot.p3TS)-1] = tsNs
				slot.p3QT[len(slot.p3QT)-1] = qtype
			}
		}
		if slot.p3Cnt >= 5 {
			var qtSeen [8]uint16
			qtDistinct := 0
			var intervals [8]int64
			for k := uint8(0); k < slot.p3Cnt; k++ {
				if k+1 < slot.p3Cnt {
					intervals[k] = slot.p3TS[k+1] - slot.p3TS[k]
				}
				qt := slot.p3QT[k]
				found := false
				for m := 0; m < qtDistinct; m++ {
					if qtSeen[m] == qt {
						found = true
						break
					}
				}
				if !found && qtDistinct < len(qtSeen) {
					qtSeen[qtDistinct] = qt
					qtDistinct++
				}
			}
			if qtDistinct >= 5 {
				feats := ComputeEpisodeP3TimingFeatures(intervals[:slot.p3Cnt], slot.p3QT[:slot.p3Cnt], 50_000_000)
				if feats.InterArrivalCV < 0.12 && feats.MarkovEntropy > 0.40 {
					return "P3", ReasonP3BeaconMarkov, true
				}
			}
		}
	}

	if p3.CompositeP3Score > 0.25 {
		return "P3", ReasonP3BeaconMarkov, true
	}

	return "BENIGN", ReasonNone, true
}

// IsRFCUnderscoreSubdomain détecte les sous-domaines RFC à préfixe underscore
// ancrés sur frontière de label (sans label vide ni label compagnon > 32 octets).
func IsRFCUnderscoreSubdomain(sub string) bool {
	if len(sub) == 0 {
		return false
	}
	return isRFCUnderscoreBytes(unsafe.Slice(unsafe.StringData(sub), len(sub)))
}

// ClassifyForensicReason retourne le premier motif forensique satisfait, ou ReasonNone.
func ClassifyForensicReason(snap DNSEpisodeSnapshot, p3 EpisodeP3Features, p4 ClientP4Features) string {
	if snap.DownlinkRatio > 2.0 && snap.MeanRDataEntropy > 4.0 {
		return ReasonP1DownlinkExfil
	}
	if snap.Base32HexScore > 0.35 {
		return ReasonP2DenseEncoding
	}
	if p3.CompositeP3Score > 0.25 {
		return ReasonP3BeaconMarkov
	}
	if p4.DistinctHighEntParents >= 3 && p4.CompositeP4Score > 0.20 {
		return ReasonP4MultiParentSharding
	}
	return ReasonNone
}

// ComputeStreamTTD calcule, par famille d'attaque, le délai de détection en paquets
// et en nanosecondes, ainsi que le nombre de faux positifs sur le trafic bénin.
func ComputeStreamTTD(obs []StreamEvalPoint) (map[string]FamilyTTDReport, error) {
	if len(obs) == 0 {
		return nil, errors.New("engine: flux d'observations vide")
	}

	reports := make(map[string]FamilyTTDReport)
	firstTs := make(map[string]int64)
	benignFP := 0

	for _, pt := range obs {
		reason := ClassifyForensicReason(pt.Snap, pt.P3, pt.P4)
		if IsRFCUnderscoreSubdomain(pt.Subdomain) {
			reason = ReasonNone
		}

		if pt.TrueFamily == "BENIGN" {
			if reason != ReasonNone {
				benignFP++
			}
			continue
		}

		fam := pt.TrueFamily
		if fam != "P1" && fam != "P2" && fam != "P3" && fam != "P4" {
			continue
		}

		rep := reports[fam]
		rep.Family = fam
		rep.TotalFamilyPackets++
		if rep.TotalFamilyPackets == 1 {
			firstTs[fam] = pt.TimestampNs
		}

		if !rep.Detected && reason != ReasonNone {
			rep.Detected = true
			rep.PacketsToDetect = rep.TotalFamilyPackets
			rep.NanosecondsToDetect = pt.TimestampNs - firstTs[fam]
			rep.FirstReasonCode = reason
		}

		reports[fam] = rep
	}

	for fam, rep := range reports {
		rep.BenignFalsePositives = benignFP
		reports[fam] = rep
	}

	return reports, nil
}
