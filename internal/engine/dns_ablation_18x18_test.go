package engine

import (
	"testing"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

func TestConfusion18x18AndAblation(t *testing.T) {
	exchanges, truth, err := dnslab.BuildIRLDilutedStream17Motifs(0x5518A, 0.80, 480)
	if err != nil {
		t.Fatalf("BuildIRLDilutedStream17Motifs : %v", err)
	}

	pts := make([]Motif17EvalPoint, len(exchanges))
	clientIP := [16]byte{10, 55, 0, 2}
	for i := range exchanges {
		pts[i] = Motif17EvalPoint{
			TimestampNs:  exchanges[i].TimestampNs,
			ClientIP:     clientIP,
			TrueClass:    truth[i].MotifFamily,
			DomainApex:   exchanges[i].DomainApex,
			Subdomain:    exchanges[i].Subdomain,
			QType:        exchanges[i].QType,
			RequestWire:  exchanges[i].RequestWire,
			ResponseWire: exchanges[i].ResponseWire,
		}
	}

	rep, err := EvaluateConfusion18x18AndAblation(pts)
	if err != nil {
		t.Fatalf("EvaluateConfusion18x18AndAblation : %v", err)
	}

	if rep.BenignFPR != 0 {
		t.Errorf("BenignFPR = %.4f, attendu 0.0 (aucun faux positif sur AXFR bénin, CDN CNAME, EDNS0 ECS/Padding, SRV AD, DNS-0x20, K8s)", rep.BenignFPR)
	}
	if rep.CrossConfusionTotal != 0 {
		t.Errorf("CrossConfusionTotal = %d, attendu 0 (matrice 18x18 strictement diagonale)", rep.CrossConfusionTotal)
	}
	if rep.RollupP4PollutionCount != 0 {
		t.Errorf("RollupP4PollutionCount = %d, attendu 0", rep.RollupP4PollutionCount)
	}

	for _, cls := range ClassNames18[1:] {
		rec := rep.PerClassRecall[cls]
		if rec < 0.95 {
			t.Errorf("Recall[%s] = %.4f, attendu >= 0.95", cls, rec)
		}
	}

	// Preuve d'ablation N vs N+1 :
	// - En état N (heuristiques amont seules M-01..M-04) : KnownRecall >= 0.95 et NewGHSARecall == 0.0
	// - En état N+1 (17 familles) : KnownRecall >= 0.95 et NewGHSARecall >= 0.95
	if rep.Ablation.LegacyKnownRecall < 0.95 {
		t.Errorf("Ablation LegacyKnownRecall = %.4f, attendu >= 0.95", rep.Ablation.LegacyKnownRecall)
	}
	if rep.Ablation.LegacyNewGHSARecall != 0.0 {
		t.Errorf("Ablation LegacyNewGHSARecall = %.4f, attendu 0.0", rep.Ablation.LegacyNewGHSARecall)
	}
	if rep.Ablation.UpgradedKnownRecall < 0.95 {
		t.Errorf("Ablation UpgradedKnownRecall = %.4f, attendu >= 0.95", rep.Ablation.UpgradedKnownRecall)
	}
	if rep.Ablation.UpgradedNewGHSARecall < 0.95 {
		t.Errorf("Ablation UpgradedNewGHSARecall = %.4f, attendu >= 0.95", rep.Ablation.UpgradedNewGHSARecall)
	}
}
