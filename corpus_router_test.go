package c2blue55

import (
	"runtime/debug"
	"sync/atomic"
	"testing"
	"time"
)

// raceInstrumented indique si le binaire de test a été compilé avec le
// détecteur de courses. L'instrumentation ralentit le chemin chaud d'un facteur
// supérieur à dix ; le plancher de débit est donc abaissé en conséquence, sans
// jamais masquer une régression puisque la référence non instrumentée reste à
// 10^7 ev/s.
func raceInstrumented() bool {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, setting := range info.Settings {
		if setting.Key == "-race" && setting.Value == "true" {
			return true
		}
	}
	return false
}

func corpusRings(r *CorpusRouter) []*SubRing {
	return []*SubRing{
		r.RingWebCache(),
		r.RingK8sContainer(),
		r.RingMiddleware(),
		r.RingProxyMicro(),
		r.RingCloudCI(),
		r.RingKernelUnix(),
	}
}

var corpusIDs = []uint16{
	CorpusWebCache,
	CorpusK8sContainer,
	CorpusMiddleware,
	CorpusProxyMicro,
	CorpusCloudCI,
	CorpusKernelUnix,
}

func TestCorpusRouter_DispatchSelective(t *testing.T) {
	rt := NewCorpusRouter()
	rings := corpusRings(rt)

	for index, id := range corpusIDs {
		ev := Event{Src: uint64(id)}
		if !rt.Dispatch(id, &ev) {
			t.Fatalf("Dispatch(corpus %d) refusé", id)
		}
		for j, ring := range rings {
			want := uint64(0)
			if j == index {
				want = 1
			}
			if got := ring.Len(); got != want {
				t.Fatalf("après Dispatch(%d): anneau %d Len = %d, attendu %d", id, j, got, want)
			}
		}
		var got Event
		if !rings[index].Pop(&got) {
			t.Fatalf("anneau %d vide, événement attendu", index)
		}
		if got.Src != uint64(id) {
			t.Fatalf("anneau %d Src = %d, attendu %d", index, got.Src, id)
		}
	}

	if rt.Dispatch(0, &Event{}) {
		t.Fatal("identifiant de corpus 0 routé")
	}
	if rt.Dispatch(CorpusKernelUnix+1, &Event{}) {
		t.Fatal("identifiant de corpus hors domaine routé")
	}
	if rt.Dispatch(CorpusWebCache, nil) {
		t.Fatal("événement nul routé")
	}
	if total := rt.RingWebCache().Drops() + rt.RingKernelUnix().Drops(); total != 0 {
		t.Fatalf("rejets parasites = %d, attendu 0", total)
	}
}

func TestCorpusRouter_DispatchFanout(t *testing.T) {
	rt := NewCorpusRouter()
	ev := Event{Src: 0xF00D}
	if n := rt.DispatchFanout(&ev); n != CorpusRingCount {
		t.Fatalf("DispatchFanout = %d, attendu %d", n, CorpusRingCount)
	}
	for index, ring := range corpusRings(rt) {
		if ring.Len() != 1 {
			t.Fatalf("anneau %d Len = %d, attendu 1", index, ring.Len())
		}
		var got Event
		if !ring.Pop(&got) || got.Src != 0xF00D {
			t.Fatalf("anneau %d contenu = 0x%x, attendu 0xF00D", index, got.Src)
		}
	}
	if n := rt.DispatchFanout(nil); n != 0 {
		t.Fatalf("DispatchFanout(nil) = %d, attendu 0", n)
	}
}

func TestCorpusRouter_DispatchFanoutBatch(t *testing.T) {
	rt := NewCorpusRouter()
	batch := make([]Event, dispatchBatch)
	for i := range batch {
		batch[i].Src = uint64(i)
	}
	want := dispatchBatch * CorpusRingCount
	if n := rt.DispatchFanoutBatch(batch); n != want {
		t.Fatalf("DispatchFanoutBatch = %d, attendu %d", n, want)
	}

	var out [dispatchBatch]Event
	for index, ring := range corpusRings(rt) {
		if got := ring.Len(); got != dispatchBatch {
			t.Fatalf("anneau %d Len = %d, attendu %d", index, got, dispatchBatch)
		}
		n := ring.PopBatch(out[:], consumeBatch)
		if n != dispatchBatch {
			t.Fatalf("anneau %d PopBatch = %d, attendu %d", index, n, dispatchBatch)
		}
		for i := 0; i < n; i++ {
			if out[i].Src != uint64(i) {
				t.Fatalf("anneau %d slot %d Src = %d, attendu %d", index, i, out[i].Src, i)
			}
		}
	}

	if n := rt.DispatchFanoutBatch(nil); n != 0 {
		t.Fatalf("DispatchFanoutBatch(nil) = %d, attendu 0", n)
	}
}

func TestCorpusRouter_FanoutBatchSaturation(t *testing.T) {
	rt := NewCorpusRouter()
	ring := rt.RingWebCache()
	oversized := make([]Event, subRingSlots+dispatchBatch)
	for i := range oversized {
		oversized[i].Src = uint64(i)
	}
	want := subRingSlots * CorpusRingCount
	if n := rt.DispatchFanoutBatch(oversized); n != want {
		t.Fatalf("DispatchFanoutBatch saturé = %d, attendu %d", n, want)
	}
	if got := ring.Len(); got != subRingSlots {
		t.Fatalf("anneau saturé Len = %d, attendu %d", got, subRingSlots)
	}
	if got := ring.Drops(); got != dispatchBatch {
		t.Fatalf("anneau saturé Drops = %d, attendu %d", got, dispatchBatch)
	}
}

func TestCorpusRouter_RunWorkers(t *testing.T) {
	rt := NewCorpusRouter()
	ev := Event{Src: 0xAB}
	if n := rt.DispatchFanout(&ev); n != CorpusRingCount {
		t.Fatalf("DispatchFanout = %d, attendu %d", n, CorpusRingCount)
	}

	var counts [CorpusRingCount]atomic.Int64
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		rt.RunWorkers(CorpusWorkers{
			WebCache:     WorkerFunc(func(*Event) { counts[0].Add(1) }),
			K8sContainer: WorkerFunc(func(*Event) { counts[1].Add(1) }),
			Middleware:   WorkerFunc(func(*Event) { counts[2].Add(1) }),
			ProxyMicro:   WorkerFunc(func(*Event) { counts[3].Add(1) }),
			CloudCI:      WorkerFunc(func(*Event) { counts[4].Add(1) }),
			KernelUnix:   WorkerFunc(func(*Event) { counts[5].Add(1) }),
		}, stop)
		close(done)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		total := int64(0)
		for i := range counts {
			total += counts[i].Load()
		}
		if total == CorpusRingCount {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("consommation incomplète: %d/%d", total, CorpusRingCount)
		}
		time.Sleep(time.Millisecond)
	}
	for i := range counts {
		if got := counts[i].Load(); got != 1 {
			t.Fatalf("corpus %d compteur = %d, attendu 1", i, got)
		}
	}

	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunWorkers ne s'est pas retiré après arrêt")
	}
}

func TestCorpusRouter_Throughput(t *testing.T) {
	res := testing.Benchmark(BenchmarkCorpusRouter_DispatchFanoutBatch)
	if res.N == 0 || res.NsPerOp() == 0 {
		t.Fatal("benchmark sans échantillon exploitable")
	}
	if allocs := res.AllocsPerOp(); allocs != 0 {
		t.Errorf("allocations = %d/op, attendu 0", allocs)
	}
	rate := float64(dispatchBatch) / float64(res.NsPerOp()) * 1e9
	floor := 1e7
	if raceInstrumented() {
		floor = 1e5
	}
	if rate < floor {
		t.Errorf("débit = %.0f ev/s, attendu > %.0f", rate, floor)
	}
	t.Logf("débit fan-out multi-corpus = %.0f ev/s (plancher %.0f) | %d ns/op | %d B/op | %d allocs/op",
		rate, floor, res.NsPerOp(), res.AllocedBytesPerOp(), res.AllocsPerOp())
}

// BenchmarkCorpusRouter_DispatchFanoutBatch mesure le chemin chaud de diffusion
// d'un lot de 64 événements vers les six corpus, suivi du vidage complet des six
// sous-anneaux afin qu'aucun lot ne soit rejeté. Les tampons sont des tableaux
// locaux et ne comptent pas comme allocations.
func BenchmarkCorpusRouter_DispatchFanoutBatch(b *testing.B) {
	rt := NewCorpusRouter()
	var batch [dispatchBatch]Event
	for i := range batch {
		batch[i].Subsystem = SubFile
		batch[i].Src = uint64(i)
	}
	var drain [CorpusRingCount][dispatchBatch]Event

	b.ReportAllocs()
	b.SetBytes(int64(dispatchBatch * 128))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rt.DispatchFanoutBatch(batch[:])
		for ring := 0; ring < CorpusRingCount; ring++ {
			rt.rings[ring].PopBatch(drain[ring][:], consumeBatch)
		}
	}
}
