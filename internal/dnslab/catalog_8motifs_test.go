package dnslab

import "testing"

func TestPatternCatalog8Motifs(t *testing.T) {
	if _, ok := LookupPatternSpec("INEXISTANT"); ok {
		t.Fatalf("LookupPatternSpec(INEXISTANT) devait renvoyer false")
	}

	cat := PatternCatalog()
	if len(cat) != 8 {
		t.Fatalf("PatternCatalog: attendu 8 motifs (4 connus + 4 nouveaux), obtenu %d", len(cat))
	}

	seenCode := make(map[string]bool)
	seenReason := make(map[string]bool)
	knownCount := 0
	newCount := 0

	for _, sp := range cat {
		if sp.Code == "" || sp.Name == "" || sp.PhysicalInvariant == "" || sp.ExpectedReasonCode == "" || sp.OrthogonalityGuard == "" {
			t.Fatalf("PatternSpec incomplète: %+v", sp)
		}
		if seenCode[sp.Code] {
			t.Fatalf("Code dupliqué: %s", sp.Code)
		}
		if seenReason[sp.ExpectedReasonCode] {
			t.Fatalf("ExpectedReasonCode dupliqué: %s", sp.ExpectedReasonCode)
		}
		seenCode[sp.Code] = true
		seenReason[sp.ExpectedReasonCode] = true

		switch sp.Category {
		case CategoryKnownBaseline:
			knownCount++
		case CategoryNewGHSA:
			newCount++
		default:
			t.Fatalf("catégorie inconnue %q pour %s", sp.Category, sp.Code)
		}

		looked, ok := LookupPatternSpec(sp.Code)
		if !ok || looked.ExpectedReasonCode != sp.ExpectedReasonCode {
			t.Fatalf("LookupPatternSpec(%s) incohérent: %+v", sp.Code, looked)
		}
	}

	if knownCount != 4 || newCount != 4 {
		t.Fatalf("répartition incorrecte: known=%d new=%d (attendu 4 et 4)", knownCount, newCount)
	}
	for _, want := range []string{"M-01", "M-02", "M-03", "M-04", "P1", "P2", "P3", "P4"} {
		if !seenCode[want] {
			t.Fatalf("motif %s manquant au catalogue", want)
		}
	}
}
