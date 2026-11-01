package dnslab

import "testing"

func TestPatternCatalog23Motifs(t *testing.T) {
	cat := PatternCatalog23()
	if len(cat) != 23 {
		t.Fatalf("len(PatternCatalog23()) = %d, attendu 23 (4 connus M-01..M-04 + 19 nouveaux/exotiques P1..P19)", len(cat))
	}

	expectedIDs := []string{
		"M-01", "M-02", "M-03", "M-04",
		"P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9", "P10", "P11", "P12", "P13",
		"P14", "P15", "P16", "P17", "P18", "P19",
	}
	for _, id := range expectedIDs {
		spec, ok := LookupPatternSpec23(id)
		if !ok {
			t.Errorf("LookupPatternSpec23(%q) introuvable", id)
			continue
		}
		if spec.ID != id || spec.PhysicalInvariant == "" || spec.ReasonCode == "" || spec.OrthogonalGuard == "" {
			t.Errorf("motif %s incomplet : %+v", id, spec)
		}
	}

	for _, exoticID := range []string{"P17", "P18", "P19"} {
		spec, ok := LookupPatternSpec23(exoticID)
		if !ok || spec.Category != CategoryExotic {
			t.Errorf("motif %s Category = %q, attendu %q", exoticID, spec.Category, CategoryExotic)
		}
	}
}
