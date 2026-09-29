package c2blue55

import (
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func TestRouter_Sizing(t *testing.T) {
	if got := unsafe.Sizeof(Event{}); got != 128 {
		t.Fatalf("Sizeof(Event) = %d, attendu 128", got)
	}
	want := uintptr(subRingSlots*128 + 3*cacheLine)
	if got := unsafe.Sizeof(SubRing{}); got != want {
		t.Fatalf("Sizeof(SubRing) = %d, attendu %d", got, want)
	}
}

func TestSubRing_SPSC_WrapAndSaturation(t *testing.T) {
	var ring SubRing
	for i := 0; i < subRingSlots; i++ {
		ev := Event{Src: uint64(i)}
		if !ring.Push(&ev) {
			t.Fatalf("Push(%d) refusé sur anneau non plein", i)
		}
	}
	if ring.Len() != subRingSlots {
		t.Fatalf("Len = %d, attendu %d", ring.Len(), subRingSlots)
	}
	full := Event{Src: 0xDEAD}
	if ring.Push(&full) {
		t.Fatal("Push accepté sur anneau plein")
	}
	if ring.Drops() != 1 {
		t.Fatalf("Drops = %d, attendu 1", ring.Drops())
	}

	var got Event
	for i := 0; i < subRingSlots; i++ {
		if !ring.Pop(&got) {
			t.Fatalf("Pop(%d) refusé", i)
		}
		if got.Src != uint64(i) {
			t.Fatalf("Pop(%d).Src = %d, attendu %d", i, got.Src, i)
		}
	}
	if ring.Pop(&got) {
		t.Fatal("Pop accepté sur anneau vide")
	}

	for i := 0; i < 10; i++ {
		ev := Event{Src: uint64(i)}
		if !ring.Push(&ev) {
			t.Fatalf("Push(%d) refusé après vidage", i)
		}
	}
}

func TestSubRing_PopBatch(t *testing.T) {
	var ring SubRing
	for i := 0; i < 100; i++ {
		ev := Event{Src: uint64(i)}
		ring.Push(&ev)
	}
	out := make([]Event, 64)
	if n := ring.PopBatch(out, 64); n != 64 || out[0].Src != 0 || out[63].Src != 63 {
		t.Fatalf("PopBatch #1 = %d (out[0]=%d out[63]=%d)", n, out[0].Src, out[63].Src)
	}
	if n := ring.PopBatch(out, 64); n != 36 || out[0].Src != 64 || out[35].Src != 99 {
		t.Fatalf("PopBatch #2 = %d (out[0]=%d out[35]=%d)", n, out[0].Src, out[35].Src)
	}
	if n := ring.PopBatch(out, 64); n != 0 {
		t.Fatalf("PopBatch #3 = %d, attendu 0", n)
	}
}

func TestRouter_DispatchBySubsystem(t *testing.T) {
	rt := NewRouter()
	cases := []struct {
		sub  uint16
		ring *SubRing
	}{
		{SubProc, rt.RingProc()},
		{SubFile, rt.RingFile()},
		{SubNet, rt.RingNet()},
		{SubMem, rt.RingMem()},
	}
	for _, c := range cases {
		ev := Event{Subsystem: c.sub}
		if !rt.Dispatch(&ev) {
			t.Fatalf("Dispatch(0x%04x) refusé", c.sub)
		}
		if c.ring.Len() != 1 {
			t.Fatalf("sous-anneau 0x%04x Len = %d, attendu 1", c.sub, c.ring.Len())
		}
	}
	unknown := Event{Subsystem: 0xBEEF}
	if rt.Dispatch(&unknown) {
		t.Fatal("un sous-système inconnu a été routé")
	}
}

func TestDispatchLoop_RoutesAndStops(t *testing.T) {
	rt := NewRouter()
	input := NewChannel()
	const total = 40
	for i := 0; i < total; i++ {
		ev := Event{Subsystem: uint16(i%4) + SubProc, Src: uint64(i)}
		if rc := input.Write(&ev); rc != 0 {
			t.Fatalf("Write(%d) = %d", i, rc)
		}
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		rt.DispatchLoop(input, stop)
		close(done)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		got := rt.RingProc().Len() + rt.RingFile().Len() + rt.RingNet().Len() + rt.RingMem().Len()
		if got == total {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("routage incomplet: %d/%d", got, total)
		}
		time.Sleep(time.Millisecond)
	}

	select {
	case <-done:
		t.Fatal("DispatchLoop s'est retiré sans signal d'arrêt")
	default:
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("DispatchLoop ne s'est pas retiré après arrêt")
	}
}

func TestRouter_RunWorkers(t *testing.T) {
	rt := NewRouter()
	var proc, file, net, mem atomic.Int64
	const total = 8
	for i := 0; i < total; i++ {
		ev := Event{Subsystem: uint16(i%4) + SubProc}
		if !rt.Dispatch(&ev) {
			t.Fatalf("Dispatch(%d) refusé", i)
		}
	}

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		rt.RunWorkers(Workers{
			Proc: WorkerFunc(func(*Event) { proc.Add(1) }),
			File: WorkerFunc(func(*Event) { file.Add(1) }),
			Net:  WorkerFunc(func(*Event) { net.Add(1) }),
			Mem:  WorkerFunc(func(*Event) { mem.Add(1) }),
		}, stop)
		close(done)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		if proc.Load()+file.Load()+net.Load()+mem.Load() == total {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("consommation incomplète: %d/%d", proc.Load()+file.Load()+net.Load()+mem.Load(), total)
		}
		time.Sleep(time.Millisecond)
	}
	if proc.Load() != 2 || file.Load() != 2 || net.Load() != 2 || mem.Load() != 2 {
		t.Fatalf("répartition = proc:%d file:%d net:%d mem:%d, attendu 2/2/2/2",
			proc.Load(), file.Load(), net.Load(), mem.Load())
	}
	close(stop)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RunWorkers ne s'est pas retiré après arrêt")
	}
}

func TestRouter_ZeroAllocHotPath(t *testing.T) {
	rt := NewRouter()
	ev := Event{Subsystem: SubProc}
	var out Event
	allocs := testing.AllocsPerRun(4096, func() {
		rt.Dispatch(&ev)
		rt.RingProc().Pop(&out)
	})
	if allocs != 0 {
		t.Errorf("AllocsPerRun = %.2f, attendu 0 (0 B/op)", allocs)
	}
}

// BenchmarkRouter_DispatchBatch mesure le chemin chaud de routage par lot de 64
// suivi du vidage des quatre sous-anneaux, afin qu'aucun lot ne soit rejeté par
// saturation. Les tampons sont locaux et ne sont pas comptés comme allocations.
func BenchmarkRouter_DispatchBatch(b *testing.B) {
	rt := NewRouter()
	var batch [dispatchBatch]Event
	for i := range batch {
		batch[i].Subsystem = uint16(i&3) + SubProc
	}
	var drain [routerRingCount][dispatchBatch]Event

	b.ReportAllocs()
	b.SetBytes(int64(dispatchBatch * 128))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rt.DispatchBatch(batch[:])
		rt.RingProc().PopBatch(drain[0][:], consumeBatch)
		rt.RingFile().PopBatch(drain[1][:], consumeBatch)
		rt.RingNet().PopBatch(drain[2][:], consumeBatch)
		rt.RingMem().PopBatch(drain[3][:], consumeBatch)
	}
}

func TestRouter_ThroughputExceedsMillion(t *testing.T) {
	res := testing.Benchmark(BenchmarkRouter_DispatchBatch)
	if res.N == 0 || res.NsPerOp() == 0 {
		t.Fatal("benchmark sans échantillon exploitable")
	}
	if allocs := res.AllocsPerOp(); allocs != 0 {
		t.Errorf("allocations = %d/op, attendu 0", allocs)
	}
	rate := float64(dispatchBatch) / float64(res.NsPerOp()) * 1e9
	if rate < 1_000_000 {
		t.Errorf("débit = %.0f ev/s, attendu > 1000000", rate)
	}
	t.Logf("débit routage = %.0f ev/s | %d ns/op | %d B/op | %d allocs/op",
		rate, res.NsPerOp(), res.AllocedBytesPerOp(), res.AllocsPerOp())
}
