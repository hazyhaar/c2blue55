package dnslab

import (
	"errors"
	"testing"
)

func TestGenerateP3P4(t *testing.T) {
	corpus, err := GenerateP3P4DisjointPairs(303, 404)
	if err != nil {
		t.Fatalf("GenerateP3P4DisjointPairs(303, 404) : %v", err)
	}

	runs := []struct {
		name string
		exs  []GeneratedExchange
	}{
		{"RunA", corpus.RunA},
		{"RunB", corpus.RunB},
	}
	for _, r := range runs {
		counts := map[string]int{}
		p4Apexes := map[string]bool{}
		for _, ex := range r.exs {
			counts[ex.Family]++
			if ex.Family == "P4" {
				p4Apexes[ex.DomainApex] = true
			}
		}
		for _, fam := range []string{"P3", "P4", "BENIGN"} {
			if counts[fam] < 30 {
				t.Errorf("%s : %d échanges %s, attendu >= 30", r.name, counts[fam], fam)
			}
		}
		if len(p4Apexes) < 10 {
			t.Errorf("%s : %d DomainApex distincts en P4, attendu >= 10", r.name, len(p4Apexes))
		}
	}

	apexA := map[string]bool{}
	for _, ex := range corpus.RunA {
		apexA[ex.DomainApex] = true
	}
	for _, ex := range corpus.RunB {
		if apexA[ex.DomainApex] {
			t.Errorf("SH-S11b-01 : DomainApex %q partagé entre RunA et RunB", ex.DomainApex)
		}
	}

	if _, err := GenerateP3P4DisjointPairs(77, 77); !errors.Is(err, ErrSameRunLeak) {
		t.Errorf("SH-S11b-01 : GenerateP3P4DisjointPairs(77, 77) = %v, attendu ErrSameRunLeak", err)
	}
}
