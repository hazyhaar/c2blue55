// Nom de fichier historique : ce fichier est compilé dans tous les modes ;
// son renommage est dû dans une ligne ultérieure, une fois le fichier
// présent sur main.
package c2blue55

import "testing"

func TestRouter_BancSansAllocation(t *testing.T) {
	res := testing.Benchmark(BenchmarkRouter_DispatchBatch)
	if res.N == 0 {
		t.Fatalf("banc sans échantillon: N = %d", res.N)
	}
	if res.NsPerOp() == 0 {
		t.Fatalf("banc sans durée: NsPerOp = 0 pour N = %d", res.N)
	}
	if allocs := res.AllocsPerOp(); allocs != 0 {
		t.Errorf("allocations par opération = %d, attendu 0", allocs)
	}
	t.Logf("banc routage = %d ns/op | %d o/op | %d allocations/op",
		res.NsPerOp(), res.AllocedBytesPerOp(), res.AllocsPerOp())
}
