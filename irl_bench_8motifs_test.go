package c2blue55

import (
	"errors"
	"os"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

func TestRunIRL8MotifsFullSuite(t *testing.T) {
	outDir := t.TempDir()

	// 1. Refus sur graines identiques (SH-S21-01).
	if _, err := RunIRL8MotifsFullSuite(outDir, 0x9999, 0x9999); !errors.Is(err, dnslab.ErrSameRunLeak) {
		t.Fatalf("attendu ErrSameRunLeak sur graines identiques, obtenu %v", err)
	}

	// 2. Exécution de bout en bout sur les 8 familles simultanées (M-01..M-04 + P1..P4) diluées à 85% de bruit IRL.
	rep, err := RunIRL8MotifsFullSuite(outDir, 0x5501A, 0x5502B)
	if err != nil {
		t.Fatalf("RunIRL8MotifsFullSuite: %v", err)
	}

	if len(rep.Catalog) != 8 {
		t.Fatalf("Catalog len=%d (attendu 8)", len(rep.Catalog))
	}
	if rep.LiveSalveCount != 4 {
		t.Fatalf("LiveSalveCount=%d (attendu 4 salves <= 160 paquets)", rep.LiveSalveCount)
	}
	if !rep.ConfusionAndAblation.AblationPass {
		t.Fatalf("AblationPass == false: %+v", rep.ConfusionAndAblation)
	}
	if rep.ConfusionAndAblation.BenignFPR != 0 {
		t.Fatalf("BenignFPR=%.4f (attendu 0)", rep.ConfusionAndAblation.BenignFPR)
	}
	if rep.ConfusionAndAblation.CrossConfusionM02P2 != 0 {
		t.Fatalf("CrossConfusionM02P2=%d (attendu 0)", rep.ConfusionAndAblation.CrossConfusionM02P2)
	}
	if rep.ConfusionAndAblation.RollupP4PollutionCount != 0 {
		t.Fatalf("RollupP4PollutionCount=%d (attendu 0)", rep.ConfusionAndAblation.RollupP4PollutionCount)
	}

	for _, m := range []string{"M-01", "M-02", "M-03", "M-04"} {
		if rep.ConfusionAndAblation.RecallBaselineN[m] < 0.95 || rep.ConfusionAndAblation.RecallExtendedN1[m] < 0.95 {
			t.Fatalf("motif connu %s: RecallN=%.2f RecallN1=%.2f (<0.95)", m, rep.ConfusionAndAblation.RecallBaselineN[m], rep.ConfusionAndAblation.RecallExtendedN1[m])
		}
	}
	for _, p := range []string{"P1", "P2", "P3", "P4"} {
		if rep.ConfusionAndAblation.RecallBaselineN[p] != 0.0 {
			t.Fatalf("motif nouveau %s: RecallN=%.2f (attendu 0.0 sur baseline N)", p, rep.ConfusionAndAblation.RecallBaselineN[p])
		}
		if rep.ConfusionAndAblation.RecallExtendedN1[p] < 0.95 {
			t.Fatalf("motif nouveau %s: RecallN1=%.2f (<0.95 sur N+1)", p, rep.ConfusionAndAblation.RecallExtendedN1[p])
		}
	}

	for _, man := range []IRLRunArtifactManifest{rep.ManifestA, rep.ManifestB} {
		if len(man.PCAPSHA256) != 64 || len(man.EpisodesSHA256) != 64 || len(man.GroundTruthSHA256) != 64 || man.TotalFrames != 640 {
			t.Fatalf("manifeste 8 motifs invalide: %+v", man)
		}
	}
	if st, err := os.Stat(rep.ManifestJSONPath); err != nil || st.Size() == 0 {
		t.Fatalf("manifest.json absent ou vide: %v", err)
	}
}
