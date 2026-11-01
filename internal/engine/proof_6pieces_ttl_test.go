package engine

import (
	"encoding/binary"
	"testing"
)

func TestProveMotifTTLStego6Pieces(t *testing.T) {
	pcapDir := motifsV5RealPCAPDir(t)
	proof, err := ProveMotifTTLStego6Pieces(pcapDir, 0x25B01)
	if err != nil {
		t.Fatalf("ProveMotifTTLStego6Pieces : %v", err)
	}

	if proof.MotifID != "P10" {
		t.Errorf("MotifID = %q, attendu P10", proof.MotifID)
	}
	if proof.SameChannelHostileCount < 8 || proof.SameChannelBenignCount < 8 {
		t.Errorf("SameChannel counts insuffisants : hostile=%d benign=%d",
			proof.SameChannelHostileCount, proof.SameChannelBenignCount)
	}
	if proof.GroundTruthVerifiedSHA != proof.DilutedTotalExchanges {
		t.Errorf("GroundTruthVerifiedSHA=%d != DilutedTotalExchanges=%d",
			proof.GroundTruthVerifiedSHA, proof.DilutedTotalExchanges)
	}
	if proof.TPR < 0.95 {
		t.Errorf("TTL-stego TPR = %.4f, attendu >= 0.95", proof.TPR)
	}
	if proof.FPR > 0.01 || proof.SameChannelFPR != 0.0 || proof.SameChannelBenignFP != 0 {
		t.Errorf("TTL-stego FPR=%.4f SameChannelFPR=%.4f SameChannelBenignFP=%d, attendu 0 faux positif sur multi-A bénin et CNAME+A",
			proof.FPR, proof.SameChannelFPR, proof.SameChannelBenignFP)
	}
	if proof.AblationFNBefore != proof.SameChannelHostileCount || proof.AblationFNAfter != 0 {
		t.Errorf("Ablation FN(N)=%d -> FN(N+1)=%d, attendu %d -> 0",
			proof.AblationFNBefore, proof.AblationFNAfter, proof.SameChannelHostileCount)
	}
	if proof.AblationFPBefore != proof.AblationFPAfter {
		t.Errorf("Ablation FP modifiée : %d -> %d", proof.AblationFPBefore, proof.AblationFPAfter)
	}
	if proof.CrossConfusionCount != 0 {
		t.Errorf("CrossConfusionCount = %d, attendu 0", proof.CrossConfusionCount)
	}
	if proof.RealPCAPHostileTotal != 25 || proof.RealPCAPHostileTP != 25 || proof.RealPCAPTPR < 0.95 {
		t.Errorf("RealPCAP TTL-stego hostile : TP=%d/%d (TPR=%.4f), attendu 25/25",
			proof.RealPCAPHostileTP, proof.RealPCAPHostileTotal, proof.RealPCAPTPR)
	}
	if proof.RealPCAPBenignTotal != 25 || proof.RealPCAPBenignFP != 0 || proof.RealPCAPFPR != 0.0 {
		t.Errorf("RealPCAP TTL-stego bénin : FP=%d/%d (FPR=%.4f), attendu 0/25",
			proof.RealPCAPBenignFP, proof.RealPCAPBenignTotal, proof.RealPCAPFPR)
	}

	// Vérification directe du descripteur ComputeIntraARRsetTTLEntropy et 0 B/op
	qWire := buildWireQuerySimple(0x7001, "edge.cdn.example.com", 1)
	var bResp, hResp [256]byte
	copy(bResp[:len(qWire)], qWire)
	binary.BigEndian.PutUint16(bResp[2:4], 0x8400)
	binary.BigEndian.PutUint16(bResp[4:6], 1)
	binary.BigEndian.PutUint16(bResp[6:8], 4)
	offB := len(qWire)
	for k := range 4 {
		ip := [4]byte{198, 51, 100, byte(k + 1)}
		offB = appendWireRRSimple(bResp[:], offB, 1, 300, ip[:])
	}
	entB, cntB := ComputeIntraARRsetTTLEntropy(bResp[:offB])
	if cntB != 4 || entB != 0.0 {
		t.Errorf("multi-A bénin uniforme : ent=%.4f cnt=%d, attendu 0.0 et 4", entB, cntB)
	}

	copy(hResp[:len(qWire)], qWire)
	binary.BigEndian.PutUint16(hResp[2:4], 0x8400)
	binary.BigEndian.PutUint16(hResp[4:6], 1)
	binary.BigEndian.PutUint16(hResp[6:8], 4)
	offH := len(qWire)
	ttls := [4]uint32{137, 419, 823, 1951}
	for k, ttlV := range ttls {
		ip := [4]byte{10, 55, 10, byte(k + 1)}
		offH = appendWireRRSimple(hResp[:], offH, 1, ttlV, ip[:])
	}
	entH, cntH := ComputeIntraARRsetTTLEntropy(hResp[:offH])
	if cntH != 4 || entH < 1.9 {
		t.Errorf("multi-A TTL-stego : ent=%.4f cnt=%d, attendu >= 1.9 bits et 4", entH, cntH)
	}

	allocs := testing.AllocsPerRun(100, func() {
		_, _ = ComputeIntraARRsetTTLEntropy(hResp[:offH])
	})
	if allocs != 0 {
		t.Errorf("ComputeIntraARRsetTTLEntropy AllocsPerRun = %.2f, attendu 0", allocs)
	}
}
