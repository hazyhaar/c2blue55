package engine

import (
	"encoding/binary"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

// synthEntry fabrique une entrée déterministe à partir d'une graine.
func synthEntry(rng *rand.Rand, threatID uint32, subsystem, severity uint16) CodebookEntry {
	var e CodebookEntry
	for k := 0; k < codebookWords; k++ {
		e.Bitcode[k] = rng.Uint64()
	}
	e.ThreatID = threatID
	e.Subsystem = subsystem
	e.Severity = severity
	return e
}

// synthCorpus fabrique un corpus reproductible de n entrées distinctes.
func synthCorpus(seed uint64, n int) []CodebookEntry {
	rng := rand.New(rand.NewPCG(seed, 0xC0DEB00C))
	entries := make([]CodebookEntry, n)
	for i := range entries {
		entries[i] = synthEntry(rng, uint32(i)+1, uint16(i%7)+1, SeverityLow)
	}
	return entries
}

func TestCodebookStructSizes(t *testing.T) {
	if got := unsafe.Sizeof(CodebookEntry{}); got != codebookEntrySize {
		t.Fatalf("taille CodebookEntry = %d, attendue %d", got, codebookEntrySize)
	}
	if got := unsafe.Sizeof(CodebookHeader{}); got != codebookHeaderSize {
		t.Fatalf("taille CodebookHeader = %d, attendue %d", got, codebookHeaderSize)
	}
}

func TestCodebookRoundTripBitExact(t *testing.T) {
	entries := synthCorpus(0xA11CE, 37)
	path := filepath.Join(t.TempDir(), "roundtrip.c2book")

	if err := SaveCodebook(path, entries); err != nil {
		t.Fatalf("SaveCodebook: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lecture brute: %v", err)
	}
	wantSize := codebookHeaderSize + len(entries)*codebookEntrySize
	if len(raw) != wantSize {
		t.Fatalf("taille fichier = %d, attendue %d", len(raw), wantSize)
	}
	if string(raw[0:8]) != "C2BOOK1\x00" {
		t.Fatalf("magie = %q", raw[0:8])
	}
	if v := binary.LittleEndian.Uint16(raw[8:10]); v != codebookVersion {
		t.Fatalf("version = %d", v)
	}
	if d := binary.LittleEndian.Uint16(raw[10:12]); d != codebookVectorDim {
		t.Fatalf("dimension = %d", d)
	}
	if c := binary.LittleEndian.Uint32(raw[12:16]); c != uint32(len(entries)) {
		t.Fatalf("nombre d'entrées = %d", c)
	}
	for i := 16; i < codebookHeaderSize; i++ {
		if raw[i] != 0 {
			t.Fatalf("réserve non nulle à l'offset %d", i)
		}
	}

	cb, err := LoadCodebook(path)
	if err != nil {
		t.Fatalf("LoadCodebook: %v", err)
	}
	if cb.Len() != len(entries) {
		t.Fatalf("Len = %d, attendu %d", cb.Len(), len(entries))
	}
	for i := range entries {
		if cb.entries[i] != entries[i] {
			t.Fatalf("entrée %d divergente après aller-retour:\n got %+v\nwant %+v", i, cb.entries[i], entries[i])
		}
	}
}

func TestCodebookEmptyRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.c2book")
	if err := SaveCodebook(path, nil); err != nil {
		t.Fatalf("SaveCodebook: %v", err)
	}
	cb, err := LoadCodebook(path)
	if err != nil {
		t.Fatalf("LoadCodebook: %v", err)
	}
	if cb.Len() != 0 {
		t.Fatalf("Len = %d, attendu 0", cb.Len())
	}
	var query [codebookWords]uint64
	if _, _, found := cb.SearchNearest(&query, 512); found {
		t.Fatal("un codebook vide ne doit rien trouver")
	}
}

func TestLoadCodebookRejectsBadHeader(t *testing.T) {
	dir := t.TempDir()

	bad := make([]byte, codebookHeaderSize)
	copy(bad, "NOTABOOK")
	if err := os.WriteFile(filepath.Join(dir, "magic.c2book"), bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCodebook(filepath.Join(dir, "magic.c2book")); err != ErrCodebookMagic {
		t.Fatalf("magie invalide: erreur = %v", err)
	}

	trunc := make([]byte, 5)
	if err := os.WriteFile(filepath.Join(dir, "trunc.c2book"), trunc, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCodebook(filepath.Join(dir, "trunc.c2book")); err != ErrCodebookCorrupt {
		t.Fatalf("tronqué: erreur = %v", err)
	}
}

func TestCodebookSearchNearestExact(t *testing.T) {
	entries := synthCorpus(0xBEEF, 64)
	cb := NewCodebook(entries)

	for _, idx := range []int{0, 1, 17, 63} {
		query := entries[idx].Bitcode
		match, dist, found := cb.SearchNearest(&query, 0)
		if !found {
			t.Fatalf("entrée %d: aucune correspondance exacte", idx)
		}
		if dist != 0 {
			t.Fatalf("entrée %d: distance = %d, attendue 0", idx, dist)
		}
		if match != entries[idx] {
			t.Fatalf("entrée %d: mauvais voisin %+v", idx, match)
		}
	}
}

func TestCodebookSearchNearestWithHammingNoise(t *testing.T) {
	entries := synthCorpus(0x5EED, 128)
	cb := NewCodebook(entries)

	// La cible subit exactement 9 bits de bruit ; aucune autre entrée ne doit
	// tomber à cette distance.
	query := entries[42].Bitcode
	for _, bit := range []uint{0, 63, 64, 129, 200, 300, 400, 500, 511} {
		query[bit/64] ^= 1 << (bit % 64)
	}

	match, dist, found := cb.SearchNearest(&query, 9)
	if !found {
		t.Fatal("aucun voisin dans le seuil de 9")
	}
	if dist != 9 {
		t.Fatalf("distance = %d, attendue 9", dist)
	}
	if match != entries[42] {
		t.Fatalf("voisin = %+v, attendu entrée 42", match)
	}

	if _, _, found := cb.SearchNearest(&query, 8); found {
		t.Fatal("le seuil 8 ne doit pas retenir une distance de 9")
	}
}

func TestCodebookSearchAll(t *testing.T) {
	entries := synthCorpus(0xF00D, 256)
	cb := NewCodebook(entries)

	// Chaque entrée reçoit un bruit distinct de un à trois bits ; la requête
	// reprend le bitcode de la première entrée. Le seuil de 3 doit retenir les
	// vingt premières entrées (bruit croissant) et borner le résultat.
	query := entries[0].Bitcode
	out := make([]CodebookMatch, 256)
	got := cb.SearchAll(&query, 0, out)
	if got != 1 || out[0].Entry != entries[0] || out[0].Distance != 0 {
		t.Fatalf("seuil 0: count=%d premier=%+v", got, out[0])
	}

	query2 := entries[5].Bitcode
	query2[0] ^= 0b1011
	got = cb.SearchAll(&query2, 3, out[:8])
	if got < 1 {
		t.Fatal("seuil 3: aucune correspondance pour un bruit de 3 bits")
	}
	for i := 0; i < got && i < len(out[:8]); i++ {
		if out[i].Distance > 3 {
			t.Fatalf("match %d hors seuil: distance %d", i, out[i].Distance)
		}
	}
	// Le tampon borné à huit éléments ne doit pas être dépassé.
	if got > 8 {
		if len(out) < 8 {
			t.Fatal("tampon tronqué")
		}
	}

	// Un tampon nil reste sans allocation et compte les correspondances.
	if n := cb.SearchAll(&query, 0, nil); n != 1 {
		t.Fatalf("tampon nil: count = %d, attendu 1", n)
	}
}

func TestCodebookSearchNilGuards(t *testing.T) {
	var cb *Codebook
	var query [codebookWords]uint64
	if _, _, found := cb.SearchNearest(&query, 512); found {
		t.Fatal("codebook nil: found doit être faux")
	}
	if n := cb.SearchAll(&query, 512, nil); n != 0 {
		t.Fatalf("codebook nil: count = %d", n)
	}
	live := NewCodebook(synthCorpus(1, 4))
	if _, _, found := live.SearchNearest(nil, 512); found {
		t.Fatal("requête nil: found doit être faux")
	}
}

func TestCodebookZeroAllocation(t *testing.T) {
	cb := NewCodebook(synthCorpus(0x0A110C, 512))
	var query [codebookWords]uint64
	for k := range query {
		query[k] = 0x9E3779B97F4A7C15
	}
	out := make([]CodebookMatch, 64)

	if n := testing.AllocsPerRun(200, func() {
		_, _, _ = cb.SearchNearest(&query, 512)
	}); n != 0 {
		t.Fatalf("SearchNearest alloue %v objets par appel", n)
	}
	if n := testing.AllocsPerRun(200, func() {
		_ = cb.SearchAll(&query, 512, out)
	}); n != 0 {
		t.Fatalf("SearchAll alloue %v objets par appel", n)
	}
}

func TestCodebookLatencyPerEntry(t *testing.T) {
	if testing.Short() {
		t.Skip("mesure de latence ignorée en mode court")
	}
	if raceDetectorEnabled {
		t.Skip("mesure de latence ignorée sous détecteur de courses")
	}
	const n = 4096
	cb := NewCodebook(synthCorpus(0x1A7E, n))
	var query [codebookWords]uint64
	for k := range query {
		query[k] = uint64(k)*0x9E3779B97F4A7C15 + 1
	}
	out := make([]CodebookMatch, n)

	const rounds = 64
	cb.SearchAll(&query, 512, out)
	start := time.Now()
	for r := 0; r < rounds; r++ {
		cb.SearchAll(&query, 512, out)
	}
	elapsed := time.Since(start)
	perEntry := float64(elapsed.Nanoseconds()) / float64(rounds*n)
	if perEntry >= 50.0 {
		t.Fatalf("latence par entrée = %.2f ns, cible < 50 ns (banc nominal < 10 ns sur matériel dédié)", perEntry)
	}
	t.Logf("latence par entrée = %.3f ns (%d entrées, %d tours)", perEntry, n, rounds)
}

func BenchmarkCodebookSearchAll(b *testing.B) {
	const n = 4096
	cb := NewCodebook(synthCorpus(0xBE0C, n))
	var query [codebookWords]uint64
	for k := range query {
		query[k] = uint64(k)*0x9E3779B97F4A7C15 + 1
	}
	out := make([]CodebookMatch, n)

	b.ReportAllocs()
	b.ReportMetric(0, "ns/entrée")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = cb.SearchAll(&query, 512, out)
	}
	per := float64(b.Elapsed().Nanoseconds()) / float64(b.N*n)
	b.ReportMetric(per, "ns/entrée")
}

func BenchmarkCodebookSearchNearest(b *testing.B) {
	const n = 4096
	cb := NewCodebook(synthCorpus(0xBE0D, n))
	query := cb.entries[n/2].Bitcode

	b.ReportAllocs()
	b.ResetTimer()
	var match CodebookEntry
	for i := 0; i < b.N; i++ {
		match, _, _ = cb.SearchNearest(&query, 512)
	}
	_ = match
}

func runWorkerSearch(ac *AtomicCodebook, workerID int, stop *atomic.Bool, wg *sync.WaitGroup) {
	defer wg.Done()
	var q [codebookWords]uint64
	for k := range q {
		q[k] = uint64(workerID*1000 + k)
	}
	out := make([]CodebookMatch, 250)
	qRef := &q
	for {
		if stop.Load() {
			break
		}
		ac.SearchNearest(qRef, 256)
		ac.SearchAll(qRef, 256, out)
		ac.Len()
	}
}

func TestAtomicCodebook_ConcurrentHotReload(t *testing.T) {
	cb1 := NewCodebook(synthCorpus(0x1001, 100))
	cb2 := NewCodebook(synthCorpus(0x2002, 200))

	ac := NewAtomicCodebook(cb1)
	if ac.Len() != 100 {
		t.Fatalf("ac.Len() initial = %d, attendu 100", ac.Len())
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	const readers = 4
	stopRef := &stop
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go runWorkerSearch(ac, r, stopRef, &wg)
	}

	for i := 0; i < 20; i++ {
		time.Sleep(2 * time.Millisecond)
		if i%2 == 0 {
			ac.Swap(cb2)
		} else {
			ac.Swap(cb1)
		}
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "reload_test.c2book")
	if err := SaveCodebook(path, cb2.entries); err != nil {
		t.Fatalf("SaveCodebook: %v", err)
	}
	if err := ac.ReloadFile(path); err != nil {
		t.Fatalf("ReloadFile: %v", err)
	}
	if ac.Len() != 200 {
		t.Fatalf("ac.Len() apres ReloadFile = %d, attendu 200", ac.Len())
	}

	stop.Store(true)
	wg.Wait()
}

