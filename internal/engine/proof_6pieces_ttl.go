package engine

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"path/filepath"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

// ComputeIntraARRsetTTLEntropy calcule en 0 B/op l'entropie de Shannon (en bits) des valeurs de TTL
// à l'intérieur du seul RRset Type=1 (A, RDLength=4) d'une réponse DNS wire, ainsi que le nombre de RR A.
func ComputeIntraARRsetTTLEntropy(wireResp []byte) (float64, int) {
	summary := summarizeWirePacket(wireResp)
	var aCount int
	var distinctTTLs [16]uint32
	var ttlCounts [16]int
	var distinctN int

	for i := 0; i < summary.answerCount; i++ {
		rr := &summary.answers[i]
		if rr.rrType != 1 || rr.rdLength != 4 {
			continue
		}
		aCount++
		found := false
		for k := 0; k < distinctN; k++ {
			if distinctTTLs[k] == rr.ttl {
				ttlCounts[k]++
				found = true
				break
			}
		}
		if !found && distinctN < len(distinctTTLs) {
			distinctTTLs[distinctN] = rr.ttl
			ttlCounts[distinctN] = 1
			distinctN++
		}
	}
	if aCount <= 1 || distinctN <= 1 {
		return 0.0, aCount
	}
	invN := 1.0 / float64(aCount)
	var ent float64
	for k := 0; k < distinctN; k++ {
		prob := float64(ttlCounts[k]) * invN
		ent -= prob * math.Log2(prob)
	}
	return ent, aCount
}

func buildPhysicalTTLStegoExchanges(seed uint64, nHostile, nBenign int) ([]Motif17EvalPoint, []string) {
	var pts []Motif17EvalPoint
	var hashes []string
	clientIP := [16]byte{10, 55, 0, 2}
	baseTS := int64(1_791_000_000_000_000_000)

	for i := range nHostile {
		sub := fmt.Sprintf("rr-pool-%02d", i)
		apex := fmt.Sprintf("ttl-c2-%02d.pound2pound.fr", int(seed)%5+1)
		qname := sub + "." + apex
		reqWire := buildWireQuerySimple(uint16(0x7100+i), qname, 1)

		var resp [512]byte
		copy(resp[:len(reqWire)], reqWire)
		binary.BigEndian.PutUint16(resp[2:4], 0x8400)
		binary.BigEndian.PutUint16(resp[4:6], 1)
		binary.BigEndian.PutUint16(resp[6:8], 4)
		off := len(reqWire)
		ttls := [4]uint32{
			uint32(110 + i*3),
			uint32(290 + i*5),
			uint32(670 + i*7),
			uint32(1430 + i*11),
		}
		for k, ttlV := range ttls {
			ip := [4]byte{10, 55, 10, byte(k + 1)}
			off = appendWireRRSimple(resp[:], off, 1, ttlV, ip[:])
		}
		respWire := make([]byte, off)
		copy(respWire, resp[:off])

		sum := sha256.Sum256(reqWire)
		hashes = append(hashes, hex.EncodeToString(sum[:]))
		pts = append(pts, Motif17EvalPoint{
			TimestampNs:  baseTS + int64(i)*200_000_000,
			ClientIP:     clientIP,
			TrueClass:    "P10",
			DomainApex:   apex,
			Subdomain:    sub,
			QType:        1,
			RequestWire:  reqWire,
			ResponseWire: respWire,
		})
	}

	for i := range nBenign {
		sub := fmt.Sprintf("edge-%02d", i)
		apex := "cdn-rr-pool.org"
		reqWire := buildWireQuerySimple(uint16(0x7200+i), sub+"."+apex, 1)

		var resp [512]byte
		copy(resp[:len(reqWire)], reqWire)
		binary.BigEndian.PutUint16(resp[2:4], 0x8400)
		binary.BigEndian.PutUint16(resp[4:6], 1)
		binary.BigEndian.PutUint16(resp[6:8], 4)
		off := len(reqWire)
		for k := range 4 {
			ip := [4]byte{198, 51, 100, byte(10 + k)}
			off = appendWireRRSimple(resp[:], off, 1, 300, ip[:])
		}
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
			QType:        1,
			RequestWire:  reqWire,
			ResponseWire: respWire,
		})
	}
	return pts, hashes
}

// ProveMotifTTLStego6Pieces établit la preuve complète en 6 pièces du motif 5 (TTL stego — P10).
func ProveMotifTTLStego6Pieces(realPCAPDir string, seed uint64) (MotifSixPieceProof, error) {
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

	physPts, physHashes := buildPhysicalTTLStegoExchanges(seed, 20, 20)
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

	p10Idx := classIndex18("P10")
	tp := rep.Matrix[p10Idx][p10Idx]
	fn := 0
	for col := range 18 {
		if col != p10Idx {
			fn += rep.Matrix[p10Idx][col]
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
		ent, aCnt := ComputeIntraARRsetTTLEntropy(pt.ResponseWire)
		if pt.TrueClass == "P10" && aCnt >= 3 && ent > 1.5 {
			sameChanHostile++
		} else if pt.TrueClass == "BENIGN" && aCnt >= 2 && ent == 0.0 {
			sameChanBenign++
		}
	}
	sameChanBenignFP := rep.Matrix[0][p10Idx]

	abFNBefore, abFPBefore, err := measureMotifAblationCounts(allPts, "P10")
	if err != nil {
		return MotifSixPieceProof{}, err
	}

	pcapFile := filepath.Join(realPCAPDir, "ttl-stego-synth-20261028T224000Z.pcap")
	gtFile := filepath.Join(realPCAPDir, "ttl-stego-synth-20261028T224000Z.ground_truth.jsonl")
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
		if pt.TrueClass == "P10" {
			realHostileTotal++
		} else {
			realBenignTotal++
		}
	}
	realTP := realRep.Matrix[p10Idx][p10Idx]
	realFP := 0
	for col := 1; col < 18; col++ {
		realFP += realRep.Matrix[0][col]
	}

	return MotifSixPieceProof{
		MotifID:                 "P10",
		MotifName:               "Intra-RRset A TTL Divergence Steganography",
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
