package engine

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func makeRunCorpus(runID, tag string) *EpisodeRunCorpus {
	proto := map[string][8]float32{
		"P1":     {6.0, 7.5},
		"P2":     {0, 0, 0.85, 36.0},
		"P3":     {0, 0, 0, 0, 0.05, 0.88},
		"P4":     {0, 0, 0, 0, 0, 0, 12.0, 0.90},
		"BENIGN": {0.5, 1.0, 0.0, 4.0, 0.65, 0.0, 1.0, 0.0},
	}
	c := &EpisodeRunCorpus{RunID: runID}
	for _, fam := range []string{"P1", "P2", "P3", "P4", "BENIGN"} {
		for j := range 12 {
			s := EpisodeVectorSample{
				Family:     fam,
				DomainApex: fmt.Sprintf("%s-%s-%d.test", tag, strings.ToLower(fam), j%4),
			}
			for k := range s.Features {
				s.Features[k] = proto[fam][k] + oosJitter(j, k)
			}
			c.Samples = append(c.Samples, s)
		}
	}
	return c
}

func oosJitter(i, k int) float32 {
	return float32((i*7+k*3)%5-2) * 0.01
}

func TestProvePatternOutOfSample(t *testing.T) {
	runA := makeRunCorpus("run-a", "runa")
	runB := makeRunCorpus("run-b", "runb")

	proof, err := ProvePatternOutOfSample(runA, runB)
	if err != nil {
		t.Fatalf("ProvePatternOutOfSample: err = %v, want nil", err)
	}
	if !proof.AllPass {
		t.Errorf("AllPass = false, want true")
	}
	for _, fam := range []string{"P1", "P2", "P3", "P4"} {
		m, ok := proof.Families[fam]
		if !ok {
			t.Errorf("%s: famille absente de la preuve", fam)
			continue
		}
		if m.FalsePositives != 0 {
			t.Errorf("%s: FalsePositives = %d, want 0", fam, m.FalsePositives)
		}
		if m.AUC < 0.90 {
			t.Errorf("%s: AUC = %.3f, want >= 0.90", fam, m.AUC)
		}
		if m.LODO_AUC < 0.90 {
			t.Errorf("%s: LODO_AUC = %.3f, want >= 0.90", fam, m.LODO_AUC)
		}
		if m.MaxSphereRad <= 0 {
			t.Errorf("%s: MaxSphereRad = %v, want > 0", fam, m.MaxSphereRad)
		}
	}

	t.Run("SH-S13-01/same-run", func(t *testing.T) {
		_, err := ProvePatternOutOfSample(runA, runA)
		if !errors.Is(err, ErrSameRunLeak) {
			t.Fatalf("runA/runA: err = %v, want ErrSameRunLeak", err)
		}
	})

	t.Run("SH-S13-01/shared-apex", func(t *testing.T) {
		leaky := makeRunCorpus("run-b", "runb")
		leaky.Samples[0].DomainApex = runA.Samples[0].DomainApex
		_, err := ProvePatternOutOfSample(runA, leaky)
		if !errors.Is(err, ErrSameRunLeak) {
			t.Fatalf("DomainApex partagé: err = %v, want ErrSameRunLeak", err)
		}
	})
}
