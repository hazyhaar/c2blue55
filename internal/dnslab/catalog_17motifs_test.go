package dnslab

import "testing"

func TestPatternCatalog17Motifs(t *testing.T) {
	cat := PatternCatalog17()
	if len(cat) != 17 {
		t.Fatalf("PatternCatalog17 len = %d, attendu 17 (4 KNOWN_BASELINE M-01..M-04 + 13 NEW_GHSA P1..P13)", len(cat))
	}

	expectedIDs := []string{
		"M-01", "M-02", "M-03", "M-04",
		"P1", "P2", "P3", "P4",
		"P5", "P6", "P7", "P8", "P9", "P10", "P11", "P12", "P13",
	}
	var knownCount, ghsaCount int
	for i, wantID := range expectedIDs {
		spec, ok := LookupPatternSpec17(wantID)
		if !ok {
			t.Fatalf("LookupPatternSpec17(%q) introuvable", wantID)
		}
		if cat[i].ID != wantID {
			t.Errorf("cat[%d].ID = %q, attendu %q", i, cat[i].ID, wantID)
		}
		if spec.Name == "" || spec.PhysicalInvariant == "" || spec.ReasonCode == "" || spec.OrthogonalGuard == "" {
			t.Errorf("motif %q incomplet : %+v", wantID, spec)
		}
		switch spec.Category {
		case CategoryKnownBaseline:
			knownCount++
		case CategoryNewGHSA:
			ghsaCount++
		default:
			t.Errorf("motif %q catégorie invalide %q", wantID, spec.Category)
		}
	}
	if knownCount != 4 || ghsaCount != 13 {
		t.Errorf("knownCount=%d (attendu 4), ghsaCount=%d (attendu 13)", knownCount, ghsaCount)
	}
	if _, ok := LookupPatternSpec17("INCONNU-99"); ok {
		t.Error("LookupPatternSpec17(INCONNU-99) = true, attendu false")
	}
}
