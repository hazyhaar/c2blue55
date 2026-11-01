package engine

import (
	"strings"
	"testing"
)

func TestExportBlueTeamArtifacts(t *testing.T) {
	// 1. Refus si la preuve OOS est incomplète (SH-S17b-01).
	badProof := OOSPatternProof{AllPass: false}
	if _, err := ExportBlueTeamArtifacts(badProof, DefaultPhysicalBounds()); err == nil {
		t.Fatalf("ExportBlueTeamArtifacts devait refuser une preuve avec AllPass=false")
	}

	// 2. Preuve OOS complète et génération des artefacts Sigma + Suricata.
	validProof := OOSPatternProof{
		AllPass: true,
		Families: map[string]FamilyOOSMetrics{
			"P1": {Family: "P1", Recall: 1.0, FalsePositives: 0, AUC: 1.0, LODO_AUC: 1.0},
			"P2": {Family: "P2", Recall: 1.0, FalsePositives: 0, AUC: 1.0, LODO_AUC: 1.0},
			"P3": {Family: "P3", Recall: 1.0, FalsePositives: 0, AUC: 0.98, LODO_AUC: 0.96},
			"P4": {Family: "P4", Recall: 1.0, FalsePositives: 0, AUC: 0.99, LODO_AUC: 0.97},
		},
	}
	bounds := PhysicalInvariantBounds{
		MinRDataBytes:      200,
		MinDownlinkEntropy: 4.5,
		MinSubdomainLen:    24,
		MaxBeaconCV:        0.15,
		MinHighEntParents:  4,
	}
	bundle, err := ExportBlueTeamArtifacts(validProof, bounds)
	if err != nil {
		t.Fatalf("ExportBlueTeamArtifacts: %v", err)
	}
	if len(bundle.CoveredMotifs) != 4 {
		t.Fatalf("CoveredMotifs=%v (attendu 4 familles P1..P4)", bundle.CoveredMotifs)
	}

	// Vérification de la présence des seuils physiques et des exemptions RFC (_domainkey, _acme-challenge).
	for _, token := range []string{"200", "24", "_domainkey", "_acme-challenge", "P1", "P2", "P3", "P4"} {
		if !strings.Contains(bundle.SigmaRulesYAML, token) {
			t.Fatalf("SigmaRulesYAML ne contient pas le jeton attendu %q", token)
		}
		if !strings.Contains(bundle.SuricataRules, token) {
			t.Fatalf("SuricataRules ne contient pas le jeton attendu %q", token)
		}
	}

	// Interdiction absolue de tout IOC statique de laboratoire (.test, pound2pound, runa, runb).
	combined := strings.ToLower(bundle.SigmaRulesYAML + "\n" + bundle.SuricataRules)
	for _, forbidden := range []string{".test", "pound2pound", "runa-", "runb-", "beacon-a", "beacon-b"} {
		if strings.Contains(combined, forbidden) {
			t.Fatalf("fuite d'IOC statique de laboratoire %q dans les règles BlueTeam exportées", forbidden)
		}
	}
}
