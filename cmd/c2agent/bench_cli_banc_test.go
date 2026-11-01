package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	c2 "github.com/hazyhaar/c2blue55"
)

func benchCLIRead(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func benchCLIWrite(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func benchCLICaptures(t *testing.T) []string {
	t.Helper()
	paths := make([]string, 0, 14)
	for _, directory := range []string{"n04-20261029", "a04-20261029", "i03-20261029"} {
		matches, err := filepath.Glob(filepath.Join("..", "..", "testdata", directory, "*.pcap"))
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, matches...)
	}
	if len(paths) != 14 {
		t.Fatalf("inventaire: %d captures au lieu de 14", len(paths))
	}
	return paths
}

func benchCLIRun(t *testing.T, mode string, args []string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	var stdout, stderr bytes.Buffer
	code := RunBenchCLI(ctx, mode, args, &stdout, &stderr)
	if ctx.Err() != nil {
		t.Fatalf("commande non terminée dans le délai: %v", ctx.Err())
	}
	return code, stdout.String(), stderr.String()
}

func benchCLIDirectories(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "replay-") {
			paths = append(paths, filepath.Join(root, entry.Name()))
		}
	}
	return paths
}

func benchCLIMode(t *testing.T, path string, expected os.FileMode) {
	t.Helper()
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if stat.Mode().Perm() != expected {
		t.Fatalf("%s: permissions %o, attendu %o", path, stat.Mode().Perm(), expected)
	}
}

func benchCLIStrings(value any) []string {
	switch typed := value.(type) {
	case string:
		return []string{typed}
	case []any:
		var values []string
		for _, child := range typed {
			values = append(values, benchCLIStrings(child)...)
		}
		return values
	case map[string]any:
		var values []string
		for _, child := range typed {
			values = append(values, benchCLIStrings(child)...)
		}
		return values
	default:
		return nil
	}
}

func benchCLIManifest(t *testing.T, directory string, complete bool) map[string]any {
	t.Helper()
	benchCLIMode(t, directory, 0o700)
	for _, piece := range []string{"capture.pcap", "observations.jsonl", "capture.stderr", "manifest.json"} {
		benchCLIMode(t, filepath.Join(directory, piece), 0o600)
	}
	content := benchCLIRead(t, filepath.Join(directory, "manifest.json"))
	var manifest map[string]any
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.UseNumber()
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		t.Fatalf("manifest avec contenu final: %v", err)
	}
	if manifest["emitter"] != "generator" || manifest["mode"] != "replay" || manifest["complete"] != complete {
		t.Fatalf("identité/complétude: %s", content)
	}
	errorsValue, exists := manifest["errors"]
	if !exists {
		t.Fatalf("champ errors absent: %s", content)
	}
	errorsText := strings.Join(benchCLIStrings(errorsValue), " ")
	if (strings.TrimSpace(errorsText) == "") != complete {
		t.Fatalf("erreurs incompatibles avec complete=%v: %s", complete, content)
	}
	values := benchCLIStrings(manifest)
	contains := func(expected string) bool {
		return slices.Contains(values, expected)
	}
	for _, piece := range []string{"capture.pcap", "observations.jsonl", "capture.stderr"} {
		digest := sha256.Sum256(benchCLIRead(t, filepath.Join(directory, piece)))
		if !contains(hex.EncodeToString(digest[:])) {
			t.Fatalf("empreinte de %s absente du manifeste", piece)
		}
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	if !contains(hostname) {
		t.Fatal("hôte d'exécution absent du manifeste")
	}
	generatorFound, times := false, 0
	for _, value := range values {
		if strings.Contains(value, "bench_cli.go") || strings.Contains(value, "RunBenchCLI") {
			generatorFound = true
		}
		if _, err := time.Parse(time.RFC3339Nano, value); err == nil {
			times++
		}
	}
	if !generatorFound || times < 2 {
		t.Fatalf("provenance du générateur ou heures absentes: %s", content)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(benchCLIRead(t, executable))
	if !contains(hex.EncodeToString(digest[:])) {
		t.Fatal("empreinte de l'exécutable effectif absente")
	}
	return manifest
}

func benchCLIObservations(t *testing.T, path string) []c2.BenchObservation {
	t.Helper()
	content := benchCLIRead(t, path)
	if len(content) != 0 && content[len(content)-1] != '\n' {
		t.Fatal("dernière observation sans fin de ligne")
	}
	lines := bytes.Split(content, []byte{'\n'})
	observations := make([]c2.BenchObservation, 0, len(lines)-1)
	for index, line := range lines[:len(lines)-1] {
		var observation c2.BenchObservation
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&observation); err != nil {
			t.Fatalf("ligne %d: %v", index+1, err)
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			t.Fatalf("ligne %d, contenu surnuméraire: %v", index+1, err)
		}
		observations = append(observations, observation)
	}
	return observations
}

func benchCLIExpected(t *testing.T, content []byte) []c2.BenchObservation {
	t.Helper()
	observer, err := c2.NewBenchObserver([]uint16{53, 5335})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := observer.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	expected := make([]c2.BenchObservation, 0)
	stats, err := c2.ReadBenchPCAP(bytes.NewReader(content), func(packet c2.BenchPacket) error {
		observation, err := observer.ObservePacket(packet)
		if err != nil {
			return err
		}
		expected = append(expected, observation)
		return nil
	})
	if err != nil || stats.Packets != uint64(len(expected)) || stats.Bytes != uint64(len(content)) {
		t.Fatalf("moteur partagé: stats=%+v observations=%d err=%v", stats, len(expected), err)
	}
	return expected
}

func TestBancACLI_ReplayAllRealCapturesAndNeverOverwrite(t *testing.T) {
	// Le répertoire vide ne contient aucun tcpdump de remplacement. Le rejeu
	// doit fonctionner sans outil de capture et sans accès au réseau.
	t.Setenv("PATH", t.TempDir())
	for _, source := range benchCLICaptures(t) {
		t.Run(filepath.Base(source), func(t *testing.T) {
			content := benchCLIRead(t, source)
			expected := benchCLIExpected(t, content)
			root := t.TempDir()
			args := []string{"--pcap", source, "--out-root", root, "--max-bytes", strconv.Itoa(len(content) + 1), "--dns-ports", "53,5335"}
			code, stdout, stderr := benchCLIRun(t, "replay", args)
			if code != 0 {
				t.Fatalf("replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			directories := benchCLIDirectories(t, root)
			if len(directories) != 1 {
				t.Fatalf("répertoires: %q", directories)
			}
			first := directories[0]
			benchCLIManifest(t, first, true)
			if !bytes.Equal(benchCLIRead(t, filepath.Join(first, "capture.pcap")), content) {
				t.Fatal("capture non intégrale ou modifiée")
			}
			got := benchCLIObservations(t, filepath.Join(first, "observations.jsonl"))
			if !reflect.DeepEqual(got, expected) {
				t.Fatalf("observations différentes du moteur partagé: %d contre %d lignes", len(got), len(expected))
			}
			before := make(map[string][]byte, 4)
			for _, piece := range []string{"capture.pcap", "observations.jsonl", "capture.stderr", "manifest.json"} {
				before[piece] = benchCLIRead(t, filepath.Join(first, piece))
			}
			code, stdout, stderr = benchCLIRun(t, "replay", args)
			if code != 0 {
				t.Fatalf("second replay code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			directories = benchCLIDirectories(t, root)
			if len(directories) != 2 {
				t.Fatalf("nom réutilisé: %q", directories)
			}
			for piece, original := range before {
				if !bytes.Equal(original, benchCLIRead(t, filepath.Join(first, piece))) {
					t.Fatalf("pièce préexistante écrasée: %s", piece)
				}
			}
			for _, directory := range directories {
				benchCLIManifest(t, directory, true)
				if !bytes.Equal(before["observations.jsonl"], benchCLIRead(t, filepath.Join(directory, "observations.jsonl"))) {
					t.Fatal("même capture, observations sérialisées différentes")
				}
			}
			if !bytes.Equal(content, benchCLIRead(t, source)) {
				t.Fatal("source altérée")
			}
		})
	}
}

func TestBancACLI_StrictLimitAndFailureManifest(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	source := filepath.Join("..", "..", "testdata", "i03-20261029", "i03-runA.pcap")
	content := benchCLIRead(t, source)
	for _, limit := range []int{24, len(content) - 1, len(content), len(content) + 1} {
		t.Run(fmt.Sprintf("max-%d", limit), func(t *testing.T) {
			root := t.TempDir()
			code, stdout, stderr := benchCLIRun(t, "replay", []string{"--pcap", source, "--out-root", root, "--max-bytes", strconv.Itoa(limit), "--dns-ports", "53,5335"})
			complete := limit > len(content)
			if (code == 0) != complete {
				t.Fatalf("limite atteinte: code=%d complete attendu=%v stdout=%s stderr=%s", code, complete, stdout, stderr)
			}
			directories := benchCLIDirectories(t, root)
			if len(directories) != 1 {
				t.Fatalf("dossier d'échec non conservé: %q", directories)
			}
			benchCLIManifest(t, directories[0], complete)
			copied := benchCLIRead(t, filepath.Join(directories[0], "capture.pcap"))
			if len(copied) > limit || len(copied) > len(content) || !bytes.Equal(copied, content[:len(copied)]) {
				t.Fatal("copie au-delà de la limite ou octets fabriqués")
			}
		})
	}
	// fixture-truncated.pcap: emitter: generator;
	// generator: cmd/c2agent/bench_cli_banc_test.go:TestBancACLI_StrictLimitAndFailureManifest.
	fixturePath := filepath.Join(t.TempDir(), "fixture-truncated.pcap")
	benchCLIWrite(t, fixturePath, content[:len(content)-1])
	root := t.TempDir()
	code, _, _ := benchCLIRun(t, "replay", []string{"--pcap", fixturePath, "--out-root", root, "--max-bytes", strconv.Itoa(len(content) + 1)})
	if code == 0 {
		t.Fatal("troncature finale acceptée")
	}
	directories := benchCLIDirectories(t, root)
	if len(directories) != 1 {
		t.Fatal("troncature sans dossier de preuve")
	}
	benchCLIManifest(t, directories[0], false)
	if !bytes.Equal(benchCLIRead(t, filepath.Join(directories[0], "capture.pcap")), content[:len(content)-1]) {
		t.Fatal("préfixe réellement lu non conservé")
	}
}

func TestBancACLI_InvalidArgumentsRefused(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	source := filepath.Join("..", "..", "testdata", "i03-20261029", "i03-ping.pcap")
	for _, mode := range []string{"replay", "observe"} {
		for _, name := range []string{"missing-source", "extra", "port-zero", "port-high", "port-negative", "port-text", "port-empty", "bytes-low", "bytes-high", "missing-root", "duration-absent", "duration-low", "duration-high"} {
			if mode == "replay" && strings.HasPrefix(name, "duration-") {
				continue
			}
			t.Run(mode+"/"+name, func(t *testing.T) {
				root := t.TempDir()
				args := []string{"--out-root", root}
				if name == "missing-root" {
					args = []string{"--out-root", filepath.Join(root, "absent")}
				}
				if name != "missing-source" {
					if mode == "replay" {
						args = append(args, "--pcap", source)
					} else {
						args = append(args, "--interface", "fixture-interface-must-not-open")
					}
				}
				if mode == "observe" && !strings.HasPrefix(name, "duration-") {
					args = append(args, "--duration", "1s")
				}
				switch name {
				case "extra":
					args = append(args, "unexpected")
				case "port-zero":
					args = append(args, "--dns-ports", "0")
				case "port-high":
					args = append(args, "--dns-ports", "65536")
				case "port-negative":
					args = append(args, "--dns-ports", "-1")
				case "port-text":
					args = append(args, "--dns-ports", "dns")
				case "port-empty":
					args = append(args, "--dns-ports", "53,,5335")
				case "bytes-low":
					args = append(args, "--max-bytes", "23")
				case "bytes-high":
					args = append(args, "--max-bytes", "1073741825")
				case "duration-low":
					args = append(args, "--duration", "999ms")
				case "duration-high":
					args = append(args, "--duration", "3601s")
				}
				code, stdout, stderr := benchCLIRun(t, mode, args)
				if code == 0 || strings.TrimSpace(stderr) == "" {
					t.Fatalf("argument invalide: code=%d stdout=%s stderr=%s", code, stdout, stderr)
				}
				// Un échec de lancement de tcpdump ne prouve pas un refus
				// d'arguments : aucun dossier ne doit avoir été réservé.
				entries, err := os.ReadDir(root)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 0 {
					t.Fatalf("validation tardive: %v", entries)
				}
			})
		}
	}
}

func TestBancACLI_ConcurrentUniqueDirectories(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	root := t.TempDir()
	source := filepath.Join("..", "..", "testdata", "i03-20261029", "i03-ping.pcap")
	args := []string{"--pcap", source, "--out-root", root, "--max-bytes", "1073741824"}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	type outcome struct {
		code   int
		output string
	}
	results := make(chan outcome, 2)
	for range 2 {
		go func() {
			var stdout, stderr bytes.Buffer
			code := RunBenchCLI(ctx, "replay", args, &stdout, &stderr)
			results <- outcome{code, stdout.String() + stderr.String()}
		}()
	}
	for range 2 {
		replayReply := <-results
		if replayReply.code != 0 {
			t.Errorf("rejeu concurrent: %d %s", replayReply.code, replayReply.output)
		}
	}
	directories := benchCLIDirectories(t, root)
	if len(directories) != 2 {
		t.Fatalf("réservation concurrente: %q", directories)
	}
	for _, directory := range directories {
		benchCLIManifest(t, directory, true)
	}
}

func TestBancACLI_MainDispatchesReplay(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	binaryPath := filepath.Join(t.TempDir(), "c2agent")
	build := exec.CommandContext(ctx, "go", "build", "-o", binaryPath, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("construction CLI: %v\n%s", err, output)
	}
	source, err := filepath.Abs(filepath.Join("..", "..", "testdata", "i03-20261029", "i03-ping.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	command := exec.CommandContext(ctx, binaryPath, "replay", "--pcap", source, "--out-root", root, "--max-bytes", "1073741824", "--dns-ports", "53,5335")
	// Le binaire est réellement construit et exécuté; aucun serveur, captureur
	// ou paquet réseau de remplacement n'est fourni.
	command.Dir = t.TempDir()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("aiguillage replay: %v\n%s", err, output)
	}
	directories := benchCLIDirectories(t, root)
	if len(directories) != 1 {
		t.Fatalf("aiguillage sans pièce: %q", directories)
	}
	if !bytes.Equal(benchCLIRead(t, filepath.Join(directories[0], "capture.pcap")), benchCLIRead(t, source)) {
		t.Fatal("aiguillage: capture différente")
	}
	if got, expected := benchCLIObservations(t, filepath.Join(directories[0], "observations.jsonl")), benchCLIExpected(t, benchCLIRead(t, source)); !reflect.DeepEqual(got, expected) {
		t.Fatal("aiguillage: observations différentes")
	}
}
