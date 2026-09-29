package goclassifier

import (
	"math"
	"testing"
)

func TestFHT512Orthogonality(t *testing.T) {
	var a, b [RabitqDim]float32
	for i := range a {
		a[i] = float32((i%17)-8) * 0.25
		b[i] = float32((i*7%23)-11) * 0.125
	}

	transformedA, transformedB := a, b
	FHT512(&transformedA)
	FHT512(&transformedB)

	var dotOriginal, dotTransformed, normOriginal, normTransformed float32
	for i := 0; i < RabitqDim; i++ {
		dotOriginal += a[i] * b[i]
		dotTransformed += transformedA[i] * transformedB[i]
		normOriginal += a[i] * a[i]
		normTransformed += transformedA[i] * transformedA[i]
	}

	if diff := math.Abs(float64(dotTransformed - dotOriginal)); diff > 1e-2 {
		t.Fatalf("inner product not preserved: original=%f transformed=%f diff=%e", dotOriginal, dotTransformed, diff)
	}
	if diff := math.Abs(float64(normTransformed - normOriginal)); diff > 1e-2 {
		t.Fatalf("norm not preserved: original=%f transformed=%f diff=%e", normOriginal, normTransformed, diff)
	}
}

func TestProjectRabitqDistancePreservation(t *testing.T) {
	const dim = 37

	a := make([]float32, dim)
	b := make([]float32, dim)
	for i := range a {
		a[i] = float32(i%13-6) * 0.25
		b[i] = float32(i%7-3) * 0.5
	}

	var pa, pb [RabitqDim]float32
	ProjectRabitq(&pa, a)
	ProjectRabitq(&pb, b)

	var sqOriginal, sqProjected float32
	for i := 0; i < dim; i++ {
		d := a[i] - b[i]
		sqOriginal += d * d
	}
	for i := 0; i < RabitqDim; i++ {
		d := pa[i] - pb[i]
		sqProjected += d * d
	}

	if diff := math.Abs(float64(sqProjected - sqOriginal)); diff > 1e-2 {
		t.Fatalf("distance not preserved: original=%f projected=%f diff=%e", sqOriginal, sqProjected, diff)
	}
}

func TestQuantizeRabitqKnownVector(t *testing.T) {
	var v [RabitqDim]float32
	for i := 0; i < 256; i++ {
		v[i] = 1
	}
	for i := 256; i < RabitqDim; i++ {
		v[i] = -1
	}

	code := QuantizeRabitq(&v)

	for w := 0; w < 4; w++ {
		if code.Bits[w] != ^uint64(0) {
			t.Fatalf("word %d = %#x, want all bits set", w, code.Bits[w])
		}
	}
	for w := 4; w < RabitqWords; w++ {
		if code.Bits[w] != 0 {
			t.Fatalf("word %d = %#x, want zero", w, code.Bits[w])
		}
	}

	if diff := math.Abs(float64(code.L1 - 512)); diff > 1e-3 {
		t.Fatalf("L1 = %f, want 512", code.L1)
	}
	wantL2 := float32(math.Sqrt(512))
	if diff := math.Abs(float64(code.L2 - wantL2)); diff > 1e-3 {
		t.Fatalf("L2 = %f, want %f", code.L2, wantL2)
	}
}

func TestHamming512Parity(t *testing.T) {
	var a, b [RabitqWords]uint64
	for w := 0; w < RabitqWords; w++ {
		a[w] = uint64(w+1) * 0x9E3779B97F4A7C15
		b[w] = uint64(w+2) * 0xC2B2AE3D27D4EB4F
	}

	want := 0
	for w := 0; w < RabitqWords; w++ {
		x := a[w] ^ b[w]
		for x != 0 {
			want += int(x & 1)
			x >>= 1
		}
	}

	if got := hamming512(&a, &b); got != want {
		t.Fatalf("hamming parity mismatch: popcount=%d scalar=%d", got, want)
	}
}

func TestAsymmetricDistanceSelfIsZero(t *testing.T) {
	var v [RabitqDim]float32
	for i := range v {
		v[i] = float32((i%31)-15) * 0.1
	}

	code := QuantizeRabitq(&v)
	if d := AsymmetricDistance(&v, code); math.Abs(float64(d)) > 1e-3 {
		t.Fatalf("self asymmetric distance = %f, want 0", d)
	}
}

func TestRabitqProbeVerdicts(t *testing.T) {
	probe, err := NewRabitqProbe(2)
	if err != nil {
		t.Fatalf("NewRabitqProbe: %v", err)
	}

	e0 := make([]float32, RabitqDim)
	e0[0] = 1
	e1 := make([]float32, RabitqDim)
	e1[1] = 1
	e2 := make([]float32, RabitqDim)
	e2[2] = 1

	if err := probe.AddPrototype(0, e0); err != nil {
		t.Fatalf("AddPrototype(0): %v", err)
	}
	if err := probe.AddPrototype(1, e1); err != nil {
		t.Fatalf("AddPrototype(1): %v", err)
	}

	confirm, err := probe.Probe(e0, 0, 1)
	if err != nil {
		t.Fatalf("Probe(e0): %v", err)
	}
	if confirm.Verdict != ProbeConfirm {
		t.Fatalf("e0 verdict = %s (d1=%f d2=%f), want confirm", confirm.Verdict, confirm.D1, confirm.D2)
	}

	contradiction, err := probe.Probe(e1, 0, 1)
	if err != nil {
		t.Fatalf("Probe(e1): %v", err)
	}
	if contradiction.Verdict != ProbeContradiction {
		t.Fatalf("e1 verdict = %s (d1=%f d2=%f), want contradiction", contradiction.Verdict, contradiction.D1, contradiction.D2)
	}

	anomaly, err := probe.Probe(e2, 0, 1)
	if err != nil {
		t.Fatalf("Probe(e2): %v", err)
	}
	if anomaly.Verdict != ProbeAnomaly {
		t.Fatalf("e2 verdict = %s (d1=%f d2=%f), want anomaly", anomaly.Verdict, anomaly.D1, anomaly.D2)
	}
}

func TestRabitqProbeZeroAllocations(t *testing.T) {
	probe, err := NewRabitqProbe(2)
	if err != nil {
		t.Fatalf("NewRabitqProbe: %v", err)
	}

	first := make([]float32, RabitqDim)
	first[0] = 1
	second := make([]float32, RabitqDim)
	second[1] = 1

	if err := probe.AddPrototype(0, first); err != nil {
		t.Fatalf("AddPrototype(0): %v", err)
	}
	if err := probe.AddPrototype(1, second); err != nil {
		t.Fatalf("AddPrototype(1): %v", err)
	}

	allocs := testing.AllocsPerRun(1000, func() {
		_, _ = probe.Probe(first, 0, 1)
	})
	if allocs != 0.0 {
		t.Fatalf("Probe allocated %.2f objects/op, want 0.0", allocs)
	}
}

func BenchmarkRabitqProbe512D(b *testing.B) {
	probe, _ := NewRabitqProbe(2)
	first := make([]float32, RabitqDim)
	second := make([]float32, RabitqDim)
	for i := 0; i < RabitqDim; i++ {
		first[i] = float32((i%13)-6) * 0.25
		second[i] = float32((i%7)-3) * 0.5
	}
	_ = probe.AddPrototype(0, first)
	_ = probe.AddPrototype(1, second)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = probe.Probe(first, 0, 1)
	}
}
