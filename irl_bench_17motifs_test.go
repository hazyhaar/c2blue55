package c2blue55

import (
	"os"
	"strings"
	"testing"
)

func TestRunIRL17MotifsFullSuite(t *testing.T) {
	outDir := t.TempDir()
	rep, err := RunIRL17MotifsFullSuite(outDir, 0x5517A1, 0x5517B2)
	if err != nil {
		t.Fatalf("RunIRL17MotifsFullSuite : %v", err)
	}

	if len(rep.Catalog) != 17 {
		t.Errorf("len(Catalog) = %d, attendu 17", len(rep.Catalog))
	}
	if rep.LiveSalveCount != 6 {
		t.Errorf("LiveSalveCount = %d, attendu 6 (480 échanges découpés en salves <= 160 paquets F-21)", rep.LiveSalveCount)
	}

	for _, runCheck := range []struct {
		name string
		conf *Full17MotifsBenchmarkReport
	}{
		{"RunA+RunB", &rep},
	} {
		_ = runCheck
		for _, c := range []struct {
			label string
			r     int
			fpr   float64
			cross int
			poll  int
			abN   float64
			abN1  float64
		}{
			{
				"RunA",
				len(rep.Confusion18x18RunA.PerClassRecall),
				rep.Confusion18x18RunA.BenignFPR,
				rep.Confusion18x18RunA.CrossConfusionTotal,
				rep.Confusion18x18RunA.RollupP4PollutionCount,
				rep.Confusion18x18RunA.Ablation.LegacyNewGHSARecall,
				rep.Confusion18x18RunA.Ablation.UpgradedNewGHSARecall,
			},
			{
				"RunB",
				len(rep.Confusion18x18RunB.PerClassRecall),
				rep.Confusion18x18RunB.BenignFPR,
				rep.Confusion18x18RunB.CrossConfusionTotal,
				rep.Confusion18x18RunB.RollupP4PollutionCount,
				rep.Confusion18x18RunB.Ablation.LegacyNewGHSARecall,
				rep.Confusion18x18RunB.Ablation.UpgradedNewGHSARecall,
			},
		} {
			if c.r != 18 {
				t.Errorf("[%s] PerClassRecall count = %d, attendu 18", c.label, c.r)
			}
			if c.fpr != 0 {
				t.Errorf("[%s] BenignFPR = %.4f, attendu 0.0", c.label, c.fpr)
			}
			if c.cross != 0 {
				t.Errorf("[%s] CrossConfusionTotal = %d, attendu 0", c.label, c.cross)
			}
			if c.poll != 0 {
				t.Errorf("[%s] RollupP4PollutionCount = %d, attendu 0", c.label, c.poll)
			}
			if c.abN != 0.0 || c.abN1 < 0.95 {
				t.Errorf("[%s] Ablation NewGHSA N=%.4f N+1=%.4f, attendu 0.0 et >= 0.95", c.label, c.abN, c.abN1)
			}
		}
	}

	if rep.ManifestA.PCAPSHA256 == "" || rep.ManifestB.PCAPSHA256 == "" || rep.ManifestA.PCAPSHA256 == rep.ManifestB.PCAPSHA256 {
		t.Errorf("manifestes PCAP SHA-256 invalides ou identiques entre Run-A et Run-B")
	}

	// Vérifier la complétude de docs/inter_channel_c2_roadmap.md (6 familles C2 inter-canaux)
	docBytes, err := os.ReadFile("docs/inter_channel_c2_roadmap.md")
	if err != nil {
		t.Fatalf("lecture docs/inter_channel_c2_roadmap.md : %v", err)
	}
	doc := string(docBytes)
	for _, requiredSection := range []string{
		"ICMP",
		"HTTP/HTTPS",
		"NTP",
		"SMB",
		"ALPC",
		"MQTT",
		"QUIC",
	} {
		if !strings.Contains(doc, requiredSection) {
			t.Errorf("docs/inter_channel_c2_roadmap.md : section ou mot-clé %q manquant", requiredSection)
		}
	}
}
