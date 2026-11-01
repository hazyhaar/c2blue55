package engine

import (
	"path/filepath"
	"runtime"
	"testing"
)

func motifsV5RealPCAPDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller indisponible")
	}
	// file = .../c2blue55/internal/engine/proof_6pieces_axfr_test.go
	// remonter à /devhoros/c2blue55/wittgenstein/redhost_lab/motifs_v5
	repoRoot := filepath.Dir(filepath.Dir(filepath.Dir(file)))
	parentDir := filepath.Dir(repoRoot)
	candidate := filepath.Join(parentDir, "wittgenstein", "redhost_lab", "motifs_v5")
	if filepath.Base(parentDir) == "coding" || filepath.Base(parentDir) == "testing" {
		// worktree: /devhoros/c2blue55/desks/<desk>/tree
		enveloppeRoot := filepath.Dir(filepath.Dir(parentDir))
		candidate = filepath.Join(enveloppeRoot, "wittgenstein", "redhost_lab", "motifs_v5")
	}
	return candidate
}

func TestProveMotifAXFR6Pieces(t *testing.T) {
	pcapDir := motifsV5RealPCAPDir(t)
	proof, err := ProveMotifAXFR6Pieces(pcapDir, 0x25A01)
	if err != nil {
		t.Fatalf("ProveMotifAXFR6Pieces : %v", err)
	}

	if proof.MotifID != "P5" {
		t.Errorf("MotifID = %q, attendu P5", proof.MotifID)
	}
	// Pièces 1 & 2 : Émetteur + baseline bénigne même canal (AXFR légitime) + vérité terrain SHA-256
	if proof.SameChannelHostileCount < 8 || proof.SameChannelBenignCount < 8 {
		t.Errorf("SameChannel counts insuffisants : hostile=%d benign=%d (attendu >= 8 chacun)",
			proof.SameChannelHostileCount, proof.SameChannelBenignCount)
	}
	if proof.GroundTruthVerifiedSHA != proof.DilutedTotalExchanges || proof.DilutedTotalExchanges < 240 {
		t.Errorf("GroundTruthVerifiedSHA=%d / DilutedTotalExchanges=%d", proof.GroundTruthVerifiedSHA, proof.DilutedTotalExchanges)
	}

	// Pièces 3 & 4 : Détection, seuils de falsification (TPR >= 0.95, FPR <= 0.01) et ablation N vs N+1
	if proof.TPR < 0.95 {
		t.Errorf("AXFR TPR = %.4f, attendu >= 0.95 (TP=%d FN=%d)", proof.TPR, proof.TP, proof.FN)
	}
	if proof.FPR > 0.01 || proof.SameChannelFPR != 0.0 || proof.SameChannelBenignFP != 0 {
		t.Errorf("AXFR FPR global=%.4f SameChannelFPR=%.4f SameChannelBenignFP=%d, attendu 0 faux positif sur AXFR bénin",
			proof.FPR, proof.SameChannelFPR, proof.SameChannelBenignFP)
	}
	if proof.AblationFNBefore != proof.SameChannelHostileCount || proof.AblationFNAfter != 0 {
		t.Errorf("Ablation FN(N)=%d -> FN(N+1)=%d, attendu %d -> 0",
			proof.AblationFNBefore, proof.AblationFNAfter, proof.SameChannelHostileCount)
	}
	if proof.AblationFPBefore != proof.AblationFPAfter {
		t.Errorf("Ablation FP modifiée : FP(N)=%d vs FP(N+1)=%d (doit rester strictement inchangée)",
			proof.AblationFPBefore, proof.AblationFPAfter)
	}

	// Pièce 5 : Orthogonalité dans la matrice 18x18 (0 confusion avec P1 ou M-01)
	if proof.CrossConfusionCount != 0 {
		t.Errorf("CrossConfusionCount = %d, attendu 0", proof.CrossConfusionCount)
	}

	// Pièce 6 : capture PCAP SYNTHÉTIQUE (axfr-synth-20261028T224000Z.pcap, gen_motif_pcap.py ; réétiquetée le 2026-10-29)
	if proof.RealPCAPHostileTotal != 25 || proof.RealPCAPHostileTP != 25 || proof.RealPCAPTPR < 0.95 {
		t.Errorf("RealPCAP AXFR hostile : TP=%d/%d (TPR=%.4f), attendu 25/25",
			proof.RealPCAPHostileTP, proof.RealPCAPHostileTotal, proof.RealPCAPTPR)
	}
	if proof.RealPCAPBenignTotal != 25 || proof.RealPCAPBenignFP != 0 || proof.RealPCAPFPR != 0.0 {
		t.Errorf("RealPCAP AXFR bénin même canal : FP=%d/%d (FPR=%.4f), attendu 0/25",
			proof.RealPCAPBenignFP, proof.RealPCAPBenignTotal, proof.RealPCAPFPR)
	}
}
