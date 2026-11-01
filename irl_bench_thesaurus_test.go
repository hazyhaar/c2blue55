package c2blue55

import (
	"errors"
	"os"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

func TestRunIRLDilutedBench(t *testing.T) {
	outDir := t.TempDir()

	// 1. Refus sur graines identiques (SH-S19-01).
	if _, err := RunIRLDilutedBench(outDir, 0x1111, 0x1111); !errors.Is(err, dnslab.ErrSameRunLeak) {
		t.Fatalf("attendu ErrSameRunLeak sur graines identiques, obtenu %v", err)
	}

	// 2. Exécution complète de bout en bout (Run-A et Run-B dilués à 85% de bruit IRL).
	summary, err := RunIRLDilutedBench(outDir, 0xA101, 0xB202)
	if err != nil {
		t.Fatalf("RunIRLDilutedBench: %v", err)
	}

	if !summary.OOSProof.AllPass {
		t.Fatalf("OOSProof.AllPass == false: %+v", summary.OOSProof)
	}
	if summary.BenignFalsePositives != 0 {
		t.Fatalf("BenignFalsePositives=%d (attendu 0)", summary.BenignFalsePositives)
	}

	for _, fam := range []string{"P1", "P2", "P3", "P4"} {
		rep, ok := summary.TTDByFamily[fam]
		if !ok || !rep.Detected {
			t.Fatalf("famille %s non détectée dans TTDByFamily: %+v", fam, rep)
		}
		if rep.PacketsToDetect <= 0 || rep.PacketsToDetect > 6 {
			t.Fatalf("famille %s: PacketsToDetect=%d hors [1,6]", fam, rep.PacketsToDetect)
		}
		if rep.BenignFalsePositives != 0 {
			t.Fatalf("famille %s: BenignFalsePositives=%d != 0", fam, rep.BenignFalsePositives)
		}
	}

	// 3. Vérification de l'intégrité des manifestes SHA-256 croisés (PCAP + JSONL + GroundTruth).
	for _, m := range []IRLRunArtifactManifest{summary.ManifestA, summary.ManifestB} {
		if len(m.PCAPSHA256) != 64 || len(m.EpisodesSHA256) != 64 || len(m.GroundTruthSHA256) != 64 || m.TotalFrames < 80 {
			t.Fatalf("manifeste d'artefacts incomplet: %+v", m)
		}
		stats, err := ReadPCAPDNSMessages(m.PCAPPath, nil)
		if err != nil {
			t.Fatalf("ReadPCAPDNSMessages(%s): %v", m.PCAPPath, err)
		}
		if stats.TotalPackets != m.TotalFrames || stats.MalformedCount != 0 {
			t.Fatalf("incohérence PCAP(%s): stats=%+v vs TotalFrames=%d", m.RunID, stats, m.TotalFrames)
		}
	}

	if st, err := os.Stat(summary.ManifestJSONPath); err != nil || st.Size() == 0 {
		t.Fatalf("manifest.json absent ou vide: %v", err)
	}
	if len(summary.BlueTeam.SigmaRulesYAML) == 0 || len(summary.BlueTeam.SuricataRules) == 0 {
		t.Fatalf("bundle BlueTeam vide")
	}
}
