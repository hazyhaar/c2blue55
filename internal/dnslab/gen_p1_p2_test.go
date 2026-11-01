package dnslab

import (
	"errors"
	"testing"
)

func TestGenerateP1P2(t *testing.T) {
	corpus, err := GenerateP1P2DisjointPairs(101, 202)
	if err != nil {
		t.Fatalf("GenerateP1P2DisjointPairs(101, 202) : erreur inattendue : %v", err)
	}

	runs := []struct {
		name string
		run  []GeneratedExchange
	}{
		{"RunA", corpus.RunA},
		{"RunB", corpus.RunB},
	}
	for _, r := range runs {
		counts := map[string]int{}
		for _, ex := range r.run {
			counts[ex.Family]++
		}
		for _, fam := range []string{"P1", "P2", "BENIGN"} {
			if counts[fam] < 30 {
				t.Errorf("%s : %d échanges %s, attendu >= 30", r.name, counts[fam], fam)
			}
		}
	}

	apex := map[string]bool{}
	sub := map[string]bool{}
	for _, ex := range corpus.RunA {
		apex[ex.DomainApex] = true
		sub[ex.Subdomain] = true
	}
	for _, ex := range corpus.RunB {
		if apex[ex.DomainApex] {
			t.Errorf("DomainApex %q partagé entre RunA et RunB", ex.DomainApex)
		}
		if sub[ex.Subdomain] {
			t.Errorf("Subdomain %q partagé entre RunA et RunB", ex.Subdomain)
		}
	}
}

func TestGenerateP1P2SameSeedRejected(t *testing.T) {
	_, err := GenerateP1P2DisjointPairs(42, 42)
	if !errors.Is(err, ErrSameRunLeak) {
		t.Errorf("SH-S11a-01 : GenerateP1P2DisjointPairs(42, 42) = %v, attendu ErrSameRunLeak", err)
	}
}

func TestValidateLiveRateGuard(t *testing.T) {
	valid := []struct {
		ip      string
		maxQPS  int
		maxPkts int
	}{
		{"10.55.0.2", 5, 200},
		{"127.0.0.1", 5, 100},
	}
	for _, c := range valid {
		if err := ValidateLiveRateGuard(c.ip, c.maxQPS, c.maxPkts); err != nil {
			t.Errorf("ValidateLiveRateGuard(%q, %d, %d) = %v, attendu nil", c.ip, c.maxQPS, c.maxPkts, err)
		}
	}

	invalid := []struct {
		ip      string
		maxQPS  int
		maxPkts int
	}{
		{"8.8.8.8", 5, 200},
		{"10.55.0.2", 6, 200},
		{"10.55.0.2", 5, 201},
	}
	for _, c := range invalid {
		if err := ValidateLiveRateGuard(c.ip, c.maxQPS, c.maxPkts); err == nil {
			t.Errorf("ValidateLiveRateGuard(%q, %d, %d) = nil, attendu une erreur (F-21)", c.ip, c.maxQPS, c.maxPkts)
		}
	}
}
