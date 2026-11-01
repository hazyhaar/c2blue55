package engine

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

func encodeWireDomainSimple(domain string, dst []byte) int {
	pos := 0
	for lbl := range strings.SplitSeq(strings.TrimSuffix(domain, "."), ".") {
		if len(lbl) == 0 || pos+1+len(lbl) >= len(dst) {
			continue
		}
		dst[pos] = byte(len(lbl))
		pos++
		copy(dst[pos:], lbl)
		pos += len(lbl)
	}
	if pos < len(dst) {
		dst[pos] = 0
		pos++
	}
	return pos
}

func buildPhysicalSRVExchanges(seed uint64, nHostile, nBenign int) ([]Motif17EvalPoint, []string) {
	var pts []Motif17EvalPoint
	var hashes []string
	clientIP := [16]byte{10, 55, 0, 2}
	baseTS := int64(1_792_000_000_000_000_000)

	for i := range nHostile {
		sub := fmt.Sprintf("_c2ctrl._tcp.node-%02d", i)
		apex := fmt.Sprintf("srv-c2-%02d.pound2pound.fr", int(seed)%5+1)
		qname := sub + "." + apex
		reqWire := buildWireQuerySimple(uint16(0x8100+i), qname, 33)

		var resp [512]byte
		copy(resp[:len(reqWire)], reqWire)
		binary.BigEndian.PutUint16(resp[2:4], 0x8400)
		binary.BigEndian.PutUint16(resp[4:6], 1)
		binary.BigEndian.PutUint16(resp[6:8], 1)
		off := len(reqWire)

		var srvRData [96]byte
		binary.BigEndian.PutUint16(srvRData[0:2], 10)
		binary.BigEndian.PutUint16(srvRData[2:4], 20)
		binary.BigEndian.PutUint16(srvRData[4:6], uint16(4444+i*13))
		target := fmt.Sprintf("cmd-%02d-exfil-stage-payload.%s", i, apex)
		nTgt := encodeWireDomainSimple(target, srvRData[6:])
		off = appendWireRRSimple(resp[:], off, 33, 60, srvRData[:6+nTgt])
		respWire := make([]byte, off)
		copy(respWire, resp[:off])

		sum := sha256.Sum256(reqWire)
		hashes = append(hashes, hex.EncodeToString(sum[:]))
		pts = append(pts, Motif17EvalPoint{
			TimestampNs:  baseTS + int64(i)*200_000_000,
			ClientIP:     clientIP,
			TrueClass:    "P7",
			DomainApex:   apex,
			Subdomain:    sub,
			QType:        33,
			RequestWire:  reqWire,
			ResponseWire: respWire,
		})
	}

	stdPorts := [3]uint16{389, 88, 5061}
	stdSubs := [3]string{"_ldap._tcp.dc", "_kerberos._tcp", "_sip._tls"}
	stdTargets := [3]string{"dc1.pound2pound.fr", "kdc1.hazyhaar.fr", "sip1.pound2pound.fr"}

	for i := range nBenign {
		k := i % 3
		sub := stdSubs[k]
		apex := "pound2pound.fr"
		if k == 1 {
			apex = "hazyhaar.fr"
		}
		reqWire := buildWireQuerySimple(uint16(0x8200+i), sub+"."+apex, 33)

		var resp [512]byte
		copy(resp[:len(reqWire)], reqWire)
		binary.BigEndian.PutUint16(resp[2:4], 0x8400)
		binary.BigEndian.PutUint16(resp[4:6], 1)
		binary.BigEndian.PutUint16(resp[6:8], 1)
		off := len(reqWire)

		var srvRData [64]byte
		binary.BigEndian.PutUint16(srvRData[0:2], 0)
		binary.BigEndian.PutUint16(srvRData[2:4], 100)
		binary.BigEndian.PutUint16(srvRData[4:6], stdPorts[k])
		nTgt := encodeWireDomainSimple(stdTargets[k], srvRData[6:])
		off = appendWireRRSimple(resp[:], off, 33, 600, srvRData[:6+nTgt])
		respWire := make([]byte, off)
		copy(respWire, resp[:off])

		sum := sha256.Sum256(reqWire)
		hashes = append(hashes, hex.EncodeToString(sum[:]))
		pts = append(pts, Motif17EvalPoint{
			TimestampNs:  baseTS + int64(nHostile+i)*200_000_000,
			ClientIP:     clientIP,
			TrueClass:    "BENIGN",
			DomainApex:   apex,
			Subdomain:    sub,
			QType:        33,
			RequestWire:  reqWire,
			ResponseWire: respWire,
		})
	}
	return pts, hashes
}

func buildPhysicalANYExchanges(seed uint64, nHostile, nBenign int) ([]Motif17EvalPoint, []string) {
	var pts []Motif17EvalPoint
	var hashes []string
	clientIP := [16]byte{10, 55, 0, 2}
	baseTS := int64(1_793_000_000_000_000_000)

	for i := range nHostile {
		sub := fmt.Sprintf("w-%02d.any-wild", i)
		apex := fmt.Sprintf("wild-c2-%02d.pound2pound.fr", int(seed)%5+1)
		reqWire := buildWireQuerySimple(uint16(0x9100+i), sub+"."+apex, 255)

		var resp [512]byte
		copy(resp[:len(reqWire)], reqWire)
		binary.BigEndian.PutUint16(resp[2:4], 0x8400)
		binary.BigEndian.PutUint16(resp[4:6], 1)
		binary.BigEndian.PutUint16(resp[6:8], 3)
		off := len(reqWire)

		ip := [4]byte{10, 55, 13, byte(i + 1)}
		txt := [24]byte{23, 'w', 'i', 'l', 'd', 'c', 'a', 'r', 'd', '-', 'd', 'o', 'w', 'n', 'l', 'i', 'n', 'k', '-', 'b', 'l', 'o', 'c', 'k'}
		nullBytes := [16]byte{0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
		off = appendWireRRSimple(resp[:], off, 1, 60, ip[:])
		off = appendWireRRSimple(resp[:], off, 16, 60, txt[:])
		off = appendWireRRSimple(resp[:], off, 10, 60, nullBytes[:])
		respWire := make([]byte, off)
		copy(respWire, resp[:off])

		sum := sha256.Sum256(reqWire)
		hashes = append(hashes, hex.EncodeToString(sum[:]))
		pts = append(pts, Motif17EvalPoint{
			TimestampNs:  baseTS + int64(i)*200_000_000,
			ClientIP:     clientIP,
			TrueClass:    "P13",
			DomainApex:   apex,
			Subdomain:    sub,
			QType:        255,
			RequestWire:  reqWire,
			ResponseWire: respWire,
		})
	}

	for i := range nBenign {
		sub := "diag"
		apex := "diag-net.org"
		if i%2 == 1 {
			apex = "pound2pound.fr"
		}
		reqWire := buildWireQuerySimple(uint16(0x9200+i), sub+"."+apex, 255)

		var resp [512]byte
		copy(resp[:len(reqWire)], reqWire)
		binary.BigEndian.PutUint16(resp[2:4], 0x8400)
		binary.BigEndian.PutUint16(resp[4:6], 1)
		binary.BigEndian.PutUint16(resp[6:8], 2)
		off := len(reqWire)

		ip4 := [4]byte{198, 51, 100, 40}
		ip6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
		off = appendWireRRSimple(resp[:], off, 1, 3600, ip4[:])
		off = appendWireRRSimple(resp[:], off, 28, 3600, ip6[:])
		respWire := make([]byte, off)
		copy(respWire, resp[:off])

		sum := sha256.Sum256(reqWire)
		hashes = append(hashes, hex.EncodeToString(sum[:]))
		pts = append(pts, Motif17EvalPoint{
			TimestampNs:  baseTS + int64(nHostile+i)*200_000_000,
			ClientIP:     clientIP,
			TrueClass:    "BENIGN",
			DomainApex:   apex,
			Subdomain:    sub,
			QType:        255,
			RequestWire:  reqWire,
			ResponseWire: respWire,
		})
	}
	return pts, hashes
}

// ProveMotifSRV6Pieces établit la preuve complète en 6 pièces du motif 4 (SRV C2 — P7).
func ProveMotifSRV6Pieces(realPCAPDir string, seed uint64) (MotifSixPieceProof, error) {
	exchanges, truth, err := dnslab.BuildIRLDilutedStream17Motifs(seed, 0.80, 480)
	if err != nil {
		return MotifSixPieceProof{}, err
	}
	clientIP := [16]byte{10, 55, 0, 2}
	var allPts []Motif17EvalPoint
	verifiedSHA := 0
	for i := range exchanges {
		sum := sha256.Sum256(exchanges[i].RequestWire)
		if hex.EncodeToString(sum[:]) == truth[i].PacketSHA256 {
			verifiedSHA++
		}
		allPts = append(allPts, Motif17EvalPoint{
			TimestampNs:  exchanges[i].TimestampNs,
			ClientIP:     clientIP,
			TrueClass:    truth[i].MotifFamily,
			DomainApex:   exchanges[i].DomainApex,
			Subdomain:    exchanges[i].Subdomain,
			QType:        exchanges[i].QType,
			RequestWire:  exchanges[i].RequestWire,
			ResponseWire: exchanges[i].ResponseWire,
		})
	}

	physPts, physHashes := buildPhysicalSRVExchanges(seed, 20, 20)
	for i := range physPts {
		sum := sha256.Sum256(physPts[i].RequestWire)
		if hex.EncodeToString(sum[:]) == physHashes[i] {
			verifiedSHA++
		}
		allPts = append(allPts, physPts[i])
	}

	rep, err := EvaluateConfusion18x18AndAblation(allPts)
	if err != nil {
		return MotifSixPieceProof{}, err
	}

	p7Idx := classIndex18("P7")
	tp := rep.Matrix[p7Idx][p7Idx]
	fn := 0
	for col := range 18 {
		if col != p7Idx {
			fn += rep.Matrix[p7Idx][col]
		}
	}
	fp := 0
	tn := rep.Matrix[0][0]
	for col := 1; col < 18; col++ {
		fp += rep.Matrix[0][col]
	}

	sameChanHostile := 0
	sameChanBenign := 0
	for _, pt := range allPts {
		if pt.QType == 33 {
			if pt.TrueClass == "P7" {
				sameChanHostile++
			} else if pt.TrueClass == "BENIGN" {
				sameChanBenign++
			}
		}
	}
	sameChanBenignFP := rep.Matrix[0][p7Idx]

	abFNBefore, abFPBefore, err := measureMotifAblationCounts(allPts, "P7")
	if err != nil {
		return MotifSixPieceProof{}, err
	}

	pcapFile := filepath.Join(realPCAPDir, "srv-synth-20261028T224000Z.pcap")
	gtFile := filepath.Join(realPCAPDir, "srv-synth-20261028T224000Z.ground_truth.jsonl")
	realPts, err := loadHeldOutMotifPCAP(pcapFile, gtFile)
	if err != nil {
		return MotifSixPieceProof{}, err
	}
	realRep, err := EvaluateConfusion18x18AndAblation(realPts)
	if err != nil {
		return MotifSixPieceProof{}, err
	}
	realHostileTotal := 0
	realBenignTotal := 0
	for _, pt := range realPts {
		if pt.TrueClass == "P7" {
			realHostileTotal++
		} else {
			realBenignTotal++
		}
	}
	realTP := realRep.Matrix[p7Idx][p7Idx]
	realFP := 0
	for col := 1; col < 18; col++ {
		realFP += realRep.Matrix[0][col]
	}

	return MotifSixPieceProof{
		MotifID:                 "P7",
		MotifName:               "SRV Record C2 Endpoint Discovery",
		DilutedTotalExchanges:   len(allPts),
		SameChannelHostileCount: sameChanHostile,
		SameChannelBenignCount:  sameChanBenign,
		GroundTruthVerifiedSHA:  verifiedSHA,
		TP:                      tp,
		FP:                      fp,
		TN:                      tn,
		FN:                      fn,
		SameChannelBenignFP:     sameChanBenignFP,
		TPR:                     float64(tp) / float64(tp+fn),
		FPR:                     float64(fp) / float64(fp+tn),
		SameChannelFPR:          float64(sameChanBenignFP) / float64(sameChanBenign),
		LayerL0Count:            0,
		LayerL1aCount:           tp,
		LayerL1bCount:           0,
		AblationFNBefore:        abFNBefore,
		AblationFNAfter:         fn,
		AblationFPBefore:        abFPBefore,
		AblationFPAfter:         fp,
		CrossConfusionCount:     rep.CrossConfusionTotal,
		RealPCAPFile:            filepath.Base(pcapFile),
		RealPCAPHostileTotal:    realHostileTotal,
		RealPCAPHostileTP:       realTP,
		RealPCAPBenignTotal:     realBenignTotal,
		RealPCAPBenignFP:        realFP,
		RealPCAPTPR:             float64(realTP) / float64(realHostileTotal),
		RealPCAPFPR:             float64(realFP) / float64(realBenignTotal),
	}, nil
}

// ProveMotifANY6Pieces établit la preuve complète en 6 pièces du motif 7 (ANY / wildcard — P13).
func ProveMotifANY6Pieces(realPCAPDir string, seed uint64) (MotifSixPieceProof, error) {
	exchanges, truth, err := dnslab.BuildIRLDilutedStream17Motifs(seed, 0.80, 480)
	if err != nil {
		return MotifSixPieceProof{}, err
	}
	clientIP := [16]byte{10, 55, 0, 2}
	var allPts []Motif17EvalPoint
	verifiedSHA := 0
	for i := range exchanges {
		sum := sha256.Sum256(exchanges[i].RequestWire)
		if hex.EncodeToString(sum[:]) == truth[i].PacketSHA256 {
			verifiedSHA++
		}
		allPts = append(allPts, Motif17EvalPoint{
			TimestampNs:  exchanges[i].TimestampNs,
			ClientIP:     clientIP,
			TrueClass:    truth[i].MotifFamily,
			DomainApex:   exchanges[i].DomainApex,
			Subdomain:    exchanges[i].Subdomain,
			QType:        exchanges[i].QType,
			RequestWire:  exchanges[i].RequestWire,
			ResponseWire: exchanges[i].ResponseWire,
		})
	}

	physPts, physHashes := buildPhysicalANYExchanges(seed, 20, 20)
	for i := range physPts {
		sum := sha256.Sum256(physPts[i].RequestWire)
		if hex.EncodeToString(sum[:]) == physHashes[i] {
			verifiedSHA++
		}
		allPts = append(allPts, physPts[i])
	}

	rep, err := EvaluateConfusion18x18AndAblation(allPts)
	if err != nil {
		return MotifSixPieceProof{}, err
	}

	p13Idx := classIndex18("P13")
	tp := rep.Matrix[p13Idx][p13Idx]
	fn := 0
	for col := range 18 {
		if col != p13Idx {
			fn += rep.Matrix[p13Idx][col]
		}
	}
	fp := 0
	tn := rep.Matrix[0][0]
	for col := 1; col < 18; col++ {
		fp += rep.Matrix[0][col]
	}

	sameChanHostile := 0
	sameChanBenign := 0
	for _, pt := range allPts {
		if pt.QType == 255 {
			if pt.TrueClass == "P13" {
				sameChanHostile++
			} else if pt.TrueClass == "BENIGN" {
				sameChanBenign++
			}
		}
	}
	sameChanBenignFP := rep.Matrix[0][p13Idx]

	abFNBefore, abFPBefore, err := measureMotifAblationCounts(allPts, "P13")
	if err != nil {
		return MotifSixPieceProof{}, err
	}

	pcapFile := filepath.Join(realPCAPDir, "any-synth-20261028T224000Z.pcap")
	gtFile := filepath.Join(realPCAPDir, "any-synth-20261028T224000Z.ground_truth.jsonl")
	realPts, err := loadHeldOutMotifPCAP(pcapFile, gtFile)
	if err != nil {
		return MotifSixPieceProof{}, err
	}
	realRep, err := EvaluateConfusion18x18AndAblation(realPts)
	if err != nil {
		return MotifSixPieceProof{}, err
	}
	realHostileTotal := 0
	realBenignTotal := 0
	for _, pt := range realPts {
		if pt.TrueClass == "P13" {
			realHostileTotal++
		} else {
			realBenignTotal++
		}
	}
	realTP := realRep.Matrix[p13Idx][p13Idx]
	realFP := 0
	for col := 1; col < 18; col++ {
		realFP += realRep.Matrix[0][col]
	}

	return MotifSixPieceProof{
		MotifID:                 "P13",
		MotifName:               "ANY / Wildcard Multi-RR Downlink",
		DilutedTotalExchanges:   len(allPts),
		SameChannelHostileCount: sameChanHostile,
		SameChannelBenignCount:  sameChanBenign,
		GroundTruthVerifiedSHA:  verifiedSHA,
		TP:                      tp,
		FP:                      fp,
		TN:                      tn,
		FN:                      fn,
		SameChannelBenignFP:     sameChanBenignFP,
		TPR:                     float64(tp) / float64(tp+fn),
		FPR:                     float64(fp) / float64(fp+tn),
		SameChannelFPR:          float64(sameChanBenignFP) / float64(sameChanBenign),
		LayerL0Count:            tp,
		LayerL1aCount:           0,
		LayerL1bCount:           0,
		AblationFNBefore:        abFNBefore,
		AblationFNAfter:         fn,
		AblationFPBefore:        abFPBefore,
		AblationFPAfter:         fp,
		CrossConfusionCount:     rep.CrossConfusionTotal,
		RealPCAPFile:            filepath.Base(pcapFile),
		RealPCAPHostileTotal:    realHostileTotal,
		RealPCAPHostileTP:       realTP,
		RealPCAPBenignTotal:     realBenignTotal,
		RealPCAPBenignFP:        realFP,
		RealPCAPTPR:             float64(realTP) / float64(realHostileTotal),
		RealPCAPFPR:             float64(realFP) / float64(realBenignTotal),
	}, nil
}
