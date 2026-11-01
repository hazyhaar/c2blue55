package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	c2 "github.com/hazyhaar/c2blue55"
)

// Les signatures de production sont proposées avant ce fichier dans
// desks/testing/criteres-sante-observateur-20261030.md. Aucune implémentation
// de ces signatures, aucun état mutable de paquet et aucun serveur de
// remplacement ne vivent dans ce test.

func healthCloseBounded(t *testing.T, health *benchHealthController) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- health.Close(ctx) }()
	select {
	case err := <-finished:
		if err != nil {
			t.Errorf("clôture HTTP: %v", err)
		}
	case <-ctx.Done():
		t.Errorf("clôture HTTP non terminée: %v", ctx.Err())
		return
	}
	select {
	case <-health.Done():
	case <-ctx.Done():
		t.Errorf("goroutine HTTP non terminée: %v", ctx.Err())
	}
}

func healthStart(t *testing.T, address string) *benchHealthController {
	t.Helper()
	health, err := newBenchHealth(t.Context(), address)
	if err != nil {
		t.Fatalf("liaison de santé %s: %v", address, err)
	}
	if health == nil {
		t.Fatal("contrôleur absent sans erreur")
	}
	t.Cleanup(func() { healthCloseBounded(t, health) })
	host, port, err := net.SplitHostPort(health.Addr())
	if err != nil || !net.ParseIP(host).IsLoopback() || port == "0" || port == "" {
		t.Fatalf("adresse effectivement liée invalide: %q, %v", health.Addr(), err)
	}
	return health
}

func healthHTTP(t *testing.T, health *benchHealthController, method, path string, status int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, method, "http://"+health.Addr()+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("HTTP %s %s: %v", method, path, err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil || len(body) > 4096 {
		t.Fatalf("corps HTTP hors borne ou illisible: octets=%d erreur=%v", len(body), err)
	}
	if response.StatusCode != status {
		t.Fatalf("HTTP %s %s: statut=%d attendu=%d", method, path, response.StatusCode, status)
	}
	if status == http.StatusMethodNotAllowed && response.Header.Get("Allow") != "GET" {
		t.Errorf("Allow=%q, attendu GET", response.Header.Get("Allow"))
	}
	if method == http.MethodGet && path == "/healthz" {
		if !strings.HasPrefix(response.Header.Get("Content-Type"), "application/json") {
			t.Errorf("Content-Type=%q", response.Header.Get("Content-Type"))
		}
		var metadata struct {
			Emitter   string `json:"emitter"`
			Generator string `json:"generator"`
			Ready     *bool  `json:"ready"`
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		if err := decoder.Decode(&metadata); err != nil {
			t.Fatal(err)
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			t.Fatalf("contenu JSON surnuméraire: %v", err)
		}
		if metadata.Emitter != "generator" || metadata.Generator != "cmd/c2agent/bench_health.go:newBenchHealth" ||
			metadata.Ready == nil || *metadata.Ready != (status == http.StatusOK) {
			t.Fatalf("métadonnées de santé incompatibles: %+v", metadata)
		}
	}
}

func healthPortRefused(t *testing.T, address string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err == nil {
		if closeErr := connection.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatalf("port encore ouvert après extinction: %s", address)
	}
	if ctx.Err() != nil {
		t.Fatalf("absence de refus immédiat du port %s: %v", address, err)
	}
	var operation *net.OpError
	if !errors.As(err, &operation) || !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("erreur autre qu'un refus de connexion: %v", err)
	}
}

func TestBenchHealth_LoopbackHTTPAndClose(t *testing.T) {
	for _, address := range []string{"127.0.0.1:0", "127.0.0.2:0", "[::1]:0"} {
		t.Run(address, func(t *testing.T) {
			health := healthStart(t, address)
			healthHTTP(t, health, "GET", "/healthz", 503)
			healthHTTP(t, health, "GET", "/badpath", 404)
			healthHTTP(t, health, "POST", "/healthz", 405)
			healthCloseBounded(t, health)
			healthPortRefused(t, health.Addr())
		})
	}
	for _, address := range []string{":0", "0.0.0.0:0", "[::]:0", "192.0.2.1:0", "[2001:db8::1]:0"} {
		t.Run("reject/"+address, func(t *testing.T) {
			health, err := newBenchHealth(t.Context(), address)
			if health != nil {
				healthCloseBounded(t, health)
				t.Error("contrôleur rendu pour une adresse refusée")
			}
			if err == nil {
				t.Fatalf("liaison non locale acceptée: %s", address)
			}
		})
	}
}

// fixture-format-header: emitter: generator;
// generator: cmd/c2agent/bench_health_test.go:healthFixtureHeader.
// Ces octets éprouvent le format, jamais une capture réseau physique.
func healthFixtureHeader(order binary.ByteOrder, nano bool) []byte {
	fixture := make([]byte, 24)
	magic := uint32(0xa1b2c3d4)
	if nano {
		magic = 0xa1b23c4d
	}
	order.PutUint32(fixture, magic)
	order.PutUint16(fixture[4:], 2)
	order.PutUint16(fixture[6:], 4)
	order.PutUint32(fixture[16:], 262144)
	order.PutUint32(fixture[20:], 1)
	return fixture
}

type healthReadLedger struct {
	source     io.Reader
	readBytes  int
	maxRequest int
}

func (ledger *healthReadLedger) Read(destination []byte) (int, error) {
	ledger.maxRequest = max(ledger.maxRequest, len(destination))
	n, err := ledger.source.Read(destination)
	ledger.readBytes += n
	return n, err
}

func TestBenchHealth_HeaderOnlyFormatsAndInvalidNeverReady(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, nano := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nano-%v", order, nano), func(t *testing.T) {
				fixture := healthFixtureHeader(order, nano)
				stats, err := c2.ReadBenchPCAP(bytes.NewReader(fixture), func(c2.BenchPacket) error { return nil })
				if err != nil || stats.Bytes != 24 || stats.Packets != 0 {
					t.Fatalf("en-tête seul refusé par le lecteur partagé: %+v %v", stats, err)
				}
				health := healthStart(t, "127.0.0.1:0")
				healthHTTP(t, health, "GET", "/healthz", 503)
				ledger := &healthReadLedger{source: bytes.NewReader(fixture)}
				reader, err := benchReadyCaptureReader(ledger, health)
				if err != nil || reader == nil || ledger.readBytes != 24 || ledger.maxRequest > 24 {
					t.Fatalf("préparation: octets=%d demandeMax=%d erreur=%v", ledger.readBytes, ledger.maxRequest, err)
				}
				healthHTTP(t, health, "GET", "/healthz", 200)
				got, err := io.ReadAll(io.LimitReader(reader, 25))
				if err != nil || !bytes.Equal(got, fixture) {
					t.Fatalf("en-tête non conservé: octets=%d erreur=%v", len(got), err)
				}
				healthHTTP(t, health, "GET", "/healthz", 503)
			})
		}
	}
	for _, name := range []string{"magic", "version", "snaplen-zero", "snaplen-high", "link", "empty", "truncated"} {
		t.Run("fixture-invalid/"+name, func(t *testing.T) {
			fixture := healthFixtureHeader(binary.LittleEndian, false)
			switch name {
			case "magic":
				fixture[0] ^= 0xff
			case "version":
				fixture[4] = 3
			case "snaplen-zero":
				binary.LittleEndian.PutUint32(fixture[16:], 0)
			case "snaplen-high":
				binary.LittleEndian.PutUint32(fixture[16:], 1<<20+1)
			case "link":
				binary.LittleEndian.PutUint32(fixture[20:], 0xffffffff)
			case "empty":
				fixture = fixture[:0]
			case "truncated":
				fixture = fixture[:23]
			}
			if _, err := c2.ReadBenchPCAP(bytes.NewReader(fixture), func(c2.BenchPacket) error { return nil }); err == nil {
				t.Fatal("jumeau négatif non refusé par le lecteur partagé")
			}
			health := healthStart(t, "127.0.0.1:0")
			reader, err := benchReadyCaptureReader(bytes.NewReader(fixture), health)
			if err == nil || reader != nil {
				t.Fatalf("en-tête invalide accepté: lecteurPrésent=%v erreur=%v", reader != nil, err)
			}
			healthHTTP(t, health, "GET", "/healthz", 503)
		})
	}
}

func TestBenchHealth_PipeHeaderReadyBeforeAnyPacketAndRevocation(t *testing.T) {
	health := healthStart(t, "127.0.0.1:0")
	other := healthStart(t, "127.0.0.1:0")
	source, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, piece := range []*os.File{source, writer} {
			if err := piece.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				t.Error(err)
			}
		}
	})
	if err := source.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	type captureCheck struct {
		reader io.Reader
		err    error
	}
	finished := make(chan captureCheck, 1)
	joined := false
	t.Cleanup(func() {
		if joined {
			return
		}
		if err := source.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			t.Error(err)
		}
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Error("goroutine de préparation non terminée après fermeture de sa source")
		}
	})
	go func() {
		reader, err := benchReadyCaptureReader(source, health)
		finished <- captureCheck{reader, err}
	}()
	// fixture-format-header, même générateur explicite que ci-dessus. Le tube
	// est un vrai tube OS ; son contenu reste une fixture de format.
	fixture := healthFixtureHeader(binary.LittleEndian, false)
	if n, err := writer.Write(fixture[:23]); err != nil || n != 23 {
		t.Fatalf("écriture du préfixe: n=%d erreur=%v", n, err)
	}
	healthHTTP(t, health, "GET", "/healthz", 503)
	select {
	case checkReply := <-finished:
		joined = true
		t.Fatalf("préparation terminée avant le dernier octet: %v", checkReply.err)
	default:
	}
	if n, err := writer.Write(fixture[23:]); err != nil || n != 1 {
		t.Fatalf("écriture du dernier octet: n=%d erreur=%v", n, err)
	}
	select {
	case checkReply := <-finished:
		joined = true
		if checkReply.err != nil || checkReply.reader == nil {
			t.Fatalf("préparation: %v", checkReply.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("préparation bloquée après 24 octets sans paquet ni EOF")
	}
	healthHTTP(t, health, "GET", "/healthz", 200)
	healthHTTP(t, other, "GET", "/healthz", 503)
	health.NotReady()
	healthHTTP(t, health, "GET", "/healthz", 503)
	if _, err := benchReadyCaptureReader(bytes.NewReader(fixture), health); err == nil {
		t.Fatal("instance révoquée réarmée par une validation tardive")
	}
	healthHTTP(t, health, "GET", "/healthz", 503)
}

// Ce lecteur instrumente le contrat io.Reader (n > 0 avec erreur) ; il ne
// remplace ni un captureur ni un serveur et ne produit aucune trame.
type healthReaderWithError struct {
	source   io.Reader
	failure  error
	position int
	failAt   int
}

func (source *healthReaderWithError) Read(destination []byte) (int, error) {
	n, err := source.source.Read(destination)
	source.position += n
	if source.position >= source.failAt {
		return n, source.failure
	}
	return n, err
}

func TestBenchHealth_SourceErrorsAtHeaderAndAfterReady(t *testing.T) {
	for _, failAt := range []int{24, 25} {
		t.Run(strconv.Itoa(failAt), func(t *testing.T) {
			health := healthStart(t, "127.0.0.1:0")
			fixture := healthFixtureHeader(binary.LittleEndian, false)
			fixture = append(fixture, 0)
			failure := errors.New("fixture-source-read-error")
			source := &healthReaderWithError{source: bytes.NewReader(fixture), failure: failure, failAt: failAt}
			reader, err := benchReadyCaptureReader(source, health)
			if failAt == 24 {
				if !errors.Is(err, failure) || reader != nil {
					t.Fatalf("erreur accompagnant le 24e octet effacée: %v", err)
				}
			} else {
				if err != nil || reader == nil {
					t.Fatalf("préparation: %v", err)
				}
				healthHTTP(t, health, "GET", "/healthz", 200)
				got, err := io.ReadAll(io.LimitReader(reader, int64(len(fixture)+1)))
				if !errors.Is(err, failure) || !bytes.Equal(got, fixture) {
					t.Fatalf("erreur/corps source non conservés: octets=%d erreur=%v", len(got), err)
				}
			}
			healthHTTP(t, health, "GET", "/healthz", 503)
		})
	}
}

func healthKnownCaptures(t *testing.T) []struct{ path, digest string } {
	t.Helper()
	known := []struct{ path, digest string }{
		{"a04-20261029/a04-benin-aaaa.pcap", "d972cc6687d010963ed40f17ec712e9476ee39a24c37ad46cff2b78abb89db93"},
		{"a04-20261029/a04-benin-fw-aaaa.client-leg-redbo.pcap", "8c45fcb0d6be80564550dc7fd5589647e1f62f9d8d3eadf397fd7a3c68e18c9e"},
		{"a04-20261029/a04-benin-fw-aaaa.pcap", "b98b3765ebd19f5ad1b4c00d43dac46cc76c39ea94aab70d385c2bbed2728936"},
		{"a04-20261029/a04-runA-aaaa.pcap", "edaa69e8a52e8ff4fab8195878c43f4a558ec63d7c4b16d1b8bf43916f44a14d"},
		{"a04-20261029/a04-runB-aaaa.pcap", "65c8292512227a9b737fbb4b3af8a0be326d106a5e02c9723d1971bf02b2e1c5"},
		{"a04-20261029/redhost-dnslab-20261029T17Z.pcap", "6418f2d0dbeaf44711bee0484515d47ee0109770ef28b66fd3295332d1b1b2ee"},
		{"i03-20261029/i03-ping.pcap", "0deffb943ca49ff22014af9d7c9b7d9dd2710c7851c7fa051ec3b82ef7898b4e"},
		{"i03-20261029/i03-runA.pcap", "f799b9fb4d487db91971ccc28f2861e8e93c0fef53c1234262a54e60bb113b98"},
		{"i03-20261029/i03-runB.pcap", "0c66050c423caff6ce67c28d9ac2d4edb1c30b698052cc908aef771f14de7612"},
		{"i03-20261029/redhost-icmp-20261029T160107Z.pcap", "4ad300bb7593c127bc5c034f74a863f7f03954f5ee84c2a4516f6ffca3430b44"},
		{"i03-20261029/redhost-ptunnel-20261029T164739Z.pcap", "ca9f79ef797cef21189b8ece552b3472e5270fe03a1fcb38e12058a3abd0acbd"},
		{"n04-20261029/n04-benin-soa-v2.pcap", "57bb8f2f207b4f7c1e657eece8ddb3f152969aefcd5dc7a7c1497c0361eb92f8"},
		{"n04-20261029/n04-runA-stego-v2.pcap", "15a15d533f201420af06284c21e32430b0600ffda8a4b99284e302c44ffecf20"},
		{"n04-20261029/n04-runB-stego-v2.pcap", "632a7aed2c845450627e65781542c55a0c070dd0fa412b37c6140a63e741b49f"},
	}
	root := filepath.Join("..", "..", "testdata")
	var actual, expected []string
	for _, directory := range []string{"a04-20261029", "i03-20261029", "n04-20261029"} {
		paths, err := filepath.Glob(filepath.Join(root, directory, "*.pcap"))
		if err != nil {
			t.Fatal(err)
		}
		actual = append(actual, paths...)
	}
	for index := range known {
		known[index].path = filepath.Join(root, filepath.FromSlash(known[index].path))
		expected = append(expected, known[index].path)
	}
	slices.Sort(actual)
	slices.Sort(expected)
	if len(actual) != 14 || !slices.Equal(actual, expected) {
		t.Fatalf("inventaire bloquant: chemins=%q attendus=%q", actual, expected)
	}
	return known
}

func healthReadExisting(t *testing.T, path, digest string) []byte {
	t.Helper()
	source, err := os.Open(path)
	if err != nil {
		t.Fatalf("source existante obligatoire: %v", err)
	}
	defer func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	}()
	stat, err := source.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() < 24 || stat.Size() > 1<<20 {
		t.Fatalf("source existante hors inventaire: %s, %v", path, err)
	}
	content, err := io.ReadAll(io.LimitReader(source, stat.Size()+1))
	if err != nil || int64(len(content)) != stat.Size() {
		t.Fatalf("lecture intégrale: octets=%d erreur=%v", len(content), err)
	}
	got := sha256.Sum256(content)
	if hex.EncodeToString(got[:]) != digest {
		t.Fatalf("source modifiée: %s sha256=%x", path, got)
	}
	return content
}

func TestBenchHealth_All14ExistingCapturesBitIdentical(t *testing.T) {
	for _, capture := range healthKnownCaptures(t) {
		t.Run(filepath.Base(capture.path), func(t *testing.T) {
			expected := healthReadExisting(t, capture.path, capture.digest)
			health := healthStart(t, "127.0.0.1:0")
			source, err := os.Open(capture.path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			}()
			ledger := &healthReadLedger{source: source}
			reader, err := benchReadyCaptureReader(ledger, health)
			if err != nil || reader == nil || ledger.readBytes != 24 || ledger.maxRequest > 24 {
				t.Fatalf("prélecture hors borne: octets=%d demandeMax=%d erreur=%v", ledger.readBytes, ledger.maxRequest, err)
			}
			healthHTTP(t, health, "GET", "/healthz", 200)
			got, err := io.ReadAll(io.LimitReader(reader, int64(len(expected)+1)))
			if err != nil || !bytes.Equal(got, expected) {
				t.Fatalf("capture non intégrale ou différente: source=%d rendu=%d erreur=%v", len(expected), len(got), err)
			}
			healthHTTP(t, health, "GET", "/healthz", 503)
			t.Logf("source=%s octets=%d sha256=%x", capture.path, len(got), sha256.Sum256(got))
		})
	}
}

func TestBenchHealth_ExactCaptureLimitStillFails(t *testing.T) {
	capture := healthKnownCaptures(t)[7]
	expected := healthReadExisting(t, capture.path, capture.digest)
	for _, prepared := range []bool{false, true} {
		for _, extra := range []int{0, 1} {
			t.Run(fmt.Sprintf("prepared-%v/extra-%d", prepared, extra), func(t *testing.T) {
				source, err := os.Open(capture.path)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if err := source.Close(); err != nil {
						t.Error(err)
					}
				}()
				var reader io.Reader = source
				if prepared {
					health := healthStart(t, "127.0.0.1:0")
					reader, err = benchReadyCaptureReader(source, health)
					if err != nil {
						t.Fatal(err)
					}
				}
				var copied bytes.Buffer
				var manifest benchCampaignManifest
				err = benchReadCapture(reader, int64(len(expected)+extra), &copied, &manifest, func(c2.BenchPacket) error { return nil })
				if extra == 0 {
					if err == nil || !strings.Contains(err.Error(), "limite de taille atteinte") {
						t.Fatalf("limite exacte non refusée: %v", err)
					}
				} else if err != nil {
					t.Fatalf("capture sous la borne refusée: %v", err)
				}
				if manifest.CopiedBytes != int64(len(expected)) || manifest.PCAPStats.Bytes != uint64(len(expected)) ||
					manifest.PCAPStats.Packets == 0 || !bytes.Equal(copied.Bytes(), expected) {
					t.Fatalf("capture/statistiques changées: copiés=%d PCAP=%+v", manifest.CopiedBytes, manifest.PCAPStats)
				}
			})
		}
	}
}

func TestBenchHealth_CancelEndsServerAndRefusesPort(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	health, err := newBenchHealth(ctx, "127.0.0.1:0")
	if err != nil || health == nil {
		t.Fatalf("serveur: %v", err)
	}
	t.Cleanup(func() { healthCloseBounded(t, health) })
	healthHTTP(t, health, "GET", "/healthz", 503)
	fixture := healthFixtureHeader(binary.LittleEndian, false)
	if _, err := benchReadyCaptureReader(bytes.NewReader(fixture), health); err != nil {
		t.Fatal(err)
	}
	healthHTTP(t, health, "GET", "/healthz", 200)
	cancel()
	select {
	case <-health.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("goroutine HTTP survivante après annulation")
	}
	healthPortRefused(t, health.Addr())
}

func TestBenchHealth_RealCaptureCommandMinimalFixedLocale(t *testing.T) {
	t.Setenv("C2BLUE_HEALTH_MUST_NOT_LEAK", "fixture-environment-marker")
	filter := "ip proto 253 and src host 127.0.0.2 and dst host 127.0.0.3"
	command := benchCaptureCommand("lo", filter)
	if command == nil {
		t.Fatal("commande tcpdump absente")
	}
	if filepath.Base(command.Path) != "tcpdump" || command.Err != nil {
		t.Fatalf("véritable exécutable tcpdump non résolu: chemin=%s erreur=%v", command.Path, command.Err)
	}
	expected := []string{"tcpdump", "-n", "-s", "0", "-U", "-i", "lo", "-w", "-", filter}
	if !reflect.DeepEqual(command.Args, expected) {
		t.Fatalf("arguments=%q attendus=%q", command.Args, expected)
	}
	if command.SysProcAttr == nil || !command.SysProcAttr.Setpgid || command.WaitDelay <= 0 || command.WaitDelay > 2*time.Second {
		t.Fatal("groupe propre ou borne de récolte absents")
	}
	environment := make(map[string]string, len(command.Env))
	for _, entry := range command.Env {
		key, value, exists := strings.Cut(entry, "=")
		if !exists || key == "" {
			t.Fatal("entrée d'environnement invalide")
		}
		if _, duplicate := environment[key]; duplicate {
			t.Fatalf("variable dupliquée: %s", key)
		}
		environment[key] = value
	}
	if len(environment) != 3 || environment["LANG"] != "C" || environment["LC_ALL"] != "C" || environment["PATH"] == "" {
		t.Fatalf("environnement non minimal ou langue non fixée: clés=%d LANG=%q LC_ALL=%q PATHprésent=%v", len(environment), environment["LANG"], environment["LC_ALL"], environment["PATH"] != "")
	}
}
