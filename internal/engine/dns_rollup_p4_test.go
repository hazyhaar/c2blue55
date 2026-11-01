package engine

import "testing"

func TestDNSClientRollupP4(t *testing.T) {
	const stepNs = int64(500_000_000)

	r := NewDNSClientRollup()
	srcIP := [16]byte{10, 0, 0, 1}
	var ts int64
	var f ClientP4Features
	for apex := uint64(1); apex <= 12; apex++ {
		for range 2 {
			f = r.ObserveParentApex(srcIP, apex, 0.82, ts)
			ts += stepNs
		}
	}
	if f.DistinctHighEntParents < 10 {
		t.Errorf("DistinctHighEntParents = %d, attendu >= 10", f.DistinctHighEntParents)
	}
	if f.CrossParentSeqCorr <= 0.50 {
		t.Errorf("CrossParentSeqCorr = %.3f, attendu > 0.50", f.CrossParentSeqCorr)
	}
	if f.CompositeP4Score <= 0.40 {
		t.Errorf("CompositeP4Score = %.3f, attendu > 0.40", f.CompositeP4Score)
	}

	rb := NewDNSClientRollup()
	srcIP2 := [16]byte{10, 0, 0, 2}
	ts = 0
	for apex := uint64(1); apex <= 12; apex++ {
		for range 2 {
			f = rb.ObserveParentApex(srcIP2, apex, 0.18, ts)
			ts += stepNs
		}
	}
	if f.DistinctHighEntParents != 0 {
		t.Errorf("jumeau bénin : DistinctHighEntParents = %d, attendu 0", f.DistinctHighEntParents)
	}
	if f.CompositeP4Score >= 0 {
		t.Errorf("jumeau bénin : CompositeP4Score = %.3f, attendu < 0", f.CompositeP4Score)
	}

	ra := NewDNSClientRollup()
	ts = 0
	for apex := uint64(1); apex <= 12; apex++ {
		ra.ObserveParentApex(srcIP, apex, 0.82, ts)
		ts += stepNs
	}
	allocs := testing.AllocsPerRun(100, func() {
		f = ra.ObserveParentApex(srcIP, 1, 0.82, ts)
		ts += stepNs
	})
	if allocs != 0 {
		t.Errorf("allocs/op = %v, attendu 0", allocs)
	}
}
