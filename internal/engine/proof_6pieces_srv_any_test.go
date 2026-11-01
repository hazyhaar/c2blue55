package engine

import "testing"

func TestProveMotifsSRVAndANY6Pieces(t *testing.T) {
	pcapDir := motifsV5RealPCAPDir(t)

	// 1. Motif 4 : SRV (P7)
	srvProof, err := ProveMotifSRV6Pieces(pcapDir, 0x25C01)
	if err != nil {
		t.Fatalf("ProveMotifSRV6Pieces : %v", err)
	}
	if srvProof.MotifID != "P7" {
		t.Errorf("SRV MotifID = %q, attendu P7", srvProof.MotifID)
	}
	if srvProof.SameChannelHostileCount < 8 || srvProof.SameChannelBenignCount < 8 {
		t.Errorf("SRV SameChannel counts insuffisants : hostile=%d benign=%d",
			srvProof.SameChannelHostileCount, srvProof.SameChannelBenignCount)
	}
	if srvProof.GroundTruthVerifiedSHA != srvProof.DilutedTotalExchanges {
		t.Errorf("SRV GroundTruthVerifiedSHA=%d != DilutedTotalExchanges=%d",
			srvProof.GroundTruthVerifiedSHA, srvProof.DilutedTotalExchanges)
	}
	if srvProof.TPR < 0.95 || srvProof.FPR > 0.01 || srvProof.SameChannelFPR != 0.0 || srvProof.SameChannelBenignFP != 0 {
		t.Errorf("SRV TPR=%.4f FPR=%.4f SameChannelFPR=%.4f SameChannelBenignFP=%d",
			srvProof.TPR, srvProof.FPR, srvProof.SameChannelFPR, srvProof.SameChannelBenignFP)
	}
	if srvProof.AblationFNBefore != srvProof.SameChannelHostileCount || srvProof.AblationFNAfter != 0 || srvProof.AblationFPBefore != srvProof.AblationFPAfter {
		t.Errorf("SRV Ablation invalide : FN %d->%d, FP %d->%d",
			srvProof.AblationFNBefore, srvProof.AblationFNAfter, srvProof.AblationFPBefore, srvProof.AblationFPAfter)
	}
	if srvProof.CrossConfusionCount != 0 {
		t.Errorf("SRV CrossConfusionCount = %d, attendu 0", srvProof.CrossConfusionCount)
	}
	if srvProof.RealPCAPHostileTotal != 25 || srvProof.RealPCAPHostileTP != 25 || srvProof.RealPCAPTPR < 0.95 {
		t.Errorf("RealPCAP SRV hostile : TP=%d/%d (TPR=%.4f), attendu 25/25",
			srvProof.RealPCAPHostileTP, srvProof.RealPCAPHostileTotal, srvProof.RealPCAPTPR)
	}
	if srvProof.RealPCAPBenignTotal != 25 || srvProof.RealPCAPBenignFP != 0 || srvProof.RealPCAPFPR != 0.0 {
		t.Errorf("RealPCAP SRV bénin : FP=%d/%d (FPR=%.4f), attendu 0/25",
			srvProof.RealPCAPBenignFP, srvProof.RealPCAPBenignTotal, srvProof.RealPCAPFPR)
	}

	// 2. Motif 7 : ANY / wildcard (P13)
	anyProof, err := ProveMotifANY6Pieces(pcapDir, 0x25C02)
	if err != nil {
		t.Fatalf("ProveMotifANY6Pieces : %v", err)
	}
	if anyProof.MotifID != "P13" {
		t.Errorf("ANY MotifID = %q, attendu P13", anyProof.MotifID)
	}
	if anyProof.SameChannelHostileCount < 8 || anyProof.SameChannelBenignCount < 8 {
		t.Errorf("ANY SameChannel counts insuffisants : hostile=%d benign=%d",
			anyProof.SameChannelHostileCount, anyProof.SameChannelBenignCount)
	}
	if anyProof.GroundTruthVerifiedSHA != anyProof.DilutedTotalExchanges {
		t.Errorf("ANY GroundTruthVerifiedSHA=%d != DilutedTotalExchanges=%d",
			anyProof.GroundTruthVerifiedSHA, anyProof.DilutedTotalExchanges)
	}
	if anyProof.TPR < 0.95 || anyProof.FPR > 0.01 || anyProof.SameChannelFPR != 0.0 || anyProof.SameChannelBenignFP != 0 {
		t.Errorf("ANY TPR=%.4f FPR=%.4f SameChannelFPR=%.4f SameChannelBenignFP=%d",
			anyProof.TPR, anyProof.FPR, anyProof.SameChannelFPR, anyProof.SameChannelBenignFP)
	}
	if anyProof.AblationFNBefore != anyProof.SameChannelHostileCount || anyProof.AblationFNAfter != 0 || anyProof.AblationFPBefore != anyProof.AblationFPAfter {
		t.Errorf("ANY Ablation invalide : FN %d->%d, FP %d->%d",
			anyProof.AblationFNBefore, anyProof.AblationFNAfter, anyProof.AblationFPBefore, anyProof.AblationFPAfter)
	}
	if anyProof.CrossConfusionCount != 0 {
		t.Errorf("ANY CrossConfusionCount = %d, attendu 0", anyProof.CrossConfusionCount)
	}
	if anyProof.RealPCAPHostileTotal != 25 || anyProof.RealPCAPHostileTP != 25 || anyProof.RealPCAPTPR < 0.95 {
		t.Errorf("RealPCAP ANY hostile : TP=%d/%d (TPR=%.4f), attendu 25/25",
			anyProof.RealPCAPHostileTP, anyProof.RealPCAPHostileTotal, anyProof.RealPCAPTPR)
	}
	if anyProof.RealPCAPBenignTotal != 25 || anyProof.RealPCAPBenignFP != 0 || anyProof.RealPCAPFPR != 0.0 {
		t.Errorf("RealPCAP ANY bénin : FP=%d/%d (FPR=%.4f), attendu 0/25",
			anyProof.RealPCAPBenignFP, anyProof.RealPCAPBenignTotal, anyProof.RealPCAPFPR)
	}
}
