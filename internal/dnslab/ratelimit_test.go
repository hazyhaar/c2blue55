package dnslab_test

import (
	"errors"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

func tallyAllow(limiter *dnslab.RateLimiter, source [16]byte, nowUnixMicro int64, calls int) int {
	nTrue := 0
	for range calls {
		if limiter.Allow(source, nowUnixMicro) {
			nTrue++
		}
	}
	return nTrue
}

func TestRateLimiter_BurstThenRate(t *testing.T) {
	limiter, err := dnslab.NewRateLimiter(50, 100, 1024)
	sourceA := [16]byte{127, 0, 0, 1}
	got := tallyAllow(limiter, sourceA, 0, 1000)
	if got != 100 {
		t.Fatalf("t=0: %d vrais sur 1000, attendu exactement 100 (NewRateLimiter err=%v)", got, err)
	}

	second := [16]byte{10, 55, 0, 2}
	gotSecond := tallyAllow(limiter, second, 0, 1000)
	if gotSecond != 100 {
		found := false
		for n := byte(1); n < 64 && !found; n++ {
			var candidate [16]byte
			candidate[0] = n
			candidate[15] = 0x5A
			if candidate == sourceA || candidate == second {
				continue
			}
			gotSecond = tallyAllow(limiter, candidate, 0, 1000)
			if gotSecond == 100 {
				second = candidate
				found = true
			}
		}
		if !found {
			t.Fatalf("source distincte à t=0: %d vrais, attendu 100", gotSecond)
		}
	}

	gotPartial := tallyAllow(limiter, sourceA, 100_000, 100)
	if gotPartial > 5 {
		t.Fatalf("t=+100 ms: %d vrais sur 100, attendu au plus 5", gotPartial)
	}

	gotRefill := tallyAllow(limiter, second, 2_000_000, 150)
	if gotRefill != 100 {
		t.Fatalf("t=+2 s: %d vrais, attendu 100", gotRefill)
	}

	var probe [16]byte
	probe[1] = 7
	allocs := testing.AllocsPerRun(1000, func() {
		limiter.Allow(probe, 3_000_000)
	})
	if allocs != 0 {
		t.Fatalf("Allow alloue %v fois par appel, attendu 0", allocs)
	}
}

func TestNewRateLimiter_Refusals(t *testing.T) {
	cases := []struct {
		name                      string
		perSecond, burst, buckets uint32
	}{
		{"perSecond_nul", 0, 100, 1024},
		{"burst_nul", 50, 0, 1024},
		{"seaux_non_puissance_de_deux", 50, 100, 1000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			limiter, err := dnslab.NewRateLimiter(tc.perSecond, tc.burst, tc.buckets)
			if !errors.Is(err, dnslab.ErrRateLimiterContract) || limiter != nil {
				t.Fatalf("limiteur=%v err=%v, attendu nil et ErrRateLimiterContract", limiter, err)
			}
		})
	}
	t.Run("contrat_valide", func(t *testing.T) {
		limiter, err := dnslab.NewRateLimiter(50, 100, 1024)
		if err != nil || limiter == nil {
			t.Fatalf("contrat valide refusé: err=%v", err)
		}
	})
}
