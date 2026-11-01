package engine

import "testing"

func TestEpisodeP3Timing(t *testing.T) {
	const dualWindow int64 = 50_000_000

	const pairs = 40
	hsQ := make([]uint16, 0, 2*pairs)
	hsI := make([]int64, 0, 2*pairs-1)
	for k := range pairs {
		hsQ = append(hsQ, 1, 28)
		hsI = append(hsI, 2_000_000)
		if k < pairs-1 {
			hsI = append(hsI, 3_000_000_000+int64((k*7919)%97)*40_000_000)
		}
	}
	hs := ComputeEpisodeP3TimingFeatures(hsI, hsQ, dualWindow)
	if hs.DualStackPairs != pairs {
		t.Errorf("SH-S10b-01 : DualStackPairs = %d, attendu %d", hs.DualStackPairs, pairs)
	}
	if hs.CompositeP3Score >= 0 {
		t.Errorf("SH-S10b-01 : CompositeP3Score = %v, attendu < 0 (fausse alerte)", hs.CompositeP3Score)
	}

	const beacons = 200
	cycle := []uint16{1, 28, 16, 10, 5}
	c2Q := make([]uint16, beacons)
	c2I := make([]int64, beacons-1)
	for i := range c2Q {
		c2Q[i] = cycle[i%len(cycle)]
	}
	for i := range c2I {
		c2I[i] = 1_000_000_000 + int64((i*7919)%101-50)*1_000_000
	}
	c2 := ComputeEpisodeP3TimingFeatures(c2I, c2Q, dualWindow)
	if c2.MarkovEntropy <= 0.45 {
		t.Errorf("balise C2 : MarkovEntropy = %v, attendu > 0.45", c2.MarkovEntropy)
	}
	if c2.CompositeP3Score <= 0.35 {
		t.Errorf("balise C2 : CompositeP3Score = %v, attendu > 0.35", c2.CompositeP3Score)
	}

	allocs := testing.AllocsPerRun(100, func() {
		_ = ComputeEpisodeP3TimingFeatures(c2I, c2Q, dualWindow)
	})
	if allocs != 0 {
		t.Errorf("AllocsPerRun = %v, attendu 0", allocs)
	}
}
