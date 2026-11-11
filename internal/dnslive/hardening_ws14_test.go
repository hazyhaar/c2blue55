package dnslive_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55/internal/dnslive"
)

// Durcissement ws-1.4 après audit Sol : l'API n'accepte que Bearer, une
// source non enregistrée ne peut pas affaiblir un run enregistré, la
// clôture avant démarrage est irréversible, la lecture d'un corps lent est
// bornée, l'en-tête d'éviction est porté par le tableau, et le drapeau
// -lang sélectionne la langue du tableau.

func TestAPIRoutesRejectBasicCredentials(t *testing.T) {
	harness := startLiveHarness(t, nil)
	for _, path := range []string{"/api/v1/runs", "/api/v1/events?after=0"} {
		status, _, _ := harness.request(t, http.MethodGet, path, nil, fixtureBasicAuth, fixtureDashboardToken)
		if status != http.StatusUnauthorized {
			t.Fatalf("GET %s avec des identifiants Basic = %d, want 401 : l'API n'accepte que Bearer", path, status)
		}
	}
	client := dialLiveUDP(t, harness)
	status, _, _ := harness.request(t, http.MethodPost, "/api/v1/registrations",
		fixtureRegistrationBody(t, "run-basic-refuse", "P1", client.LocalAddr().(*net.UDPAddr)),
		fixtureBasicAuth, fixtureDashboardToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("POST /api/v1/registrations avec des identifiants Basic = %d, want 401", status)
	}
}

func TestUnregisteredFloodKeepsRegisteredRunAnswering(t *testing.T) {
	harness := startLiveHarness(t, nil)
	registered := dialLiveUDP(t, harness)
	registerLiveRun(t, harness, "run-legit-flood", "P1", registered.LocalAddr().(*net.UDPAddr))
	if response := exchangeLiveUDP(t, registered, fixtureQuery(t, 0x3100, "www.example.com", 1)); len(response) == 0 {
		t.Fatal("échange de contrôle avant l'inondation sans réponse du laboratoire")
	}

	const floodSources = 160
	for range floodSources {
		source := dialLiveUDP(t, harness)
		go func() {
			query := fixtureQuery(t, 0x3200, "unregistered.example.com", 1)
			_, _ = source.Write(query)
			// Le contrat gelé répond aux sources non enregistrées sans
			// inventer de run : la lecture de cette réponse n'est pas
			// assertée ici, seule la santé du run enregistré l'est.
			_ = source.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			buffer := make([]byte, 512)
			_, _ = source.Read(buffer)
		}()
	}
	if response := exchangeLiveUDP(t, registered, fixtureQuery(t, 0x3101, "www.example.com", 1)); len(response) == 0 {
		t.Fatal("le run enregistré ne répond plus après l'inondation de sources non enregistrées")
	}
	status, _, _ := harness.request(t, http.MethodGet, "/api/v1/runs", nil, fixtureBearerAuth, fixtureDashboardToken)
	fixtureExpectStatus(t, status, http.StatusOK)
}

func TestCloseBeforeStartPreventsLaterStart(t *testing.T) {
	cfg := dnslive.Config{
		UDPListen:      "127.0.0.1:0",
		HTTPListen:     "127.0.0.1:0",
		EvidenceDir:    t.TempDir(),
		DashboardToken: fixtureDashboardToken,
	}
	serviceLive, err := dnslive.New(cfg)
	if err != nil {
		t.Fatalf("dnslive.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = serviceLive.Close(ctx)
	if err := serviceLive.Start(); err == nil {
		t.Fatal("un service clos avant son démarrage doit refuser tout démarrage ultérieur : la clôture est irréversible")
	}
}

func TestRegistrationSlowBodyTimesOut(t *testing.T) {
	harness := startLiveHarness(t, nil)
	parsed, err := url.Parse(harness.httpBase)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	head := "POST /api/v1/registrations HTTP/1.1\r\n" +
		"Host: " + parsed.Host + "\r\n" +
		"Authorization: Bearer " + fixtureDashboardToken + "\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 65536\r\n\r\n"
	if _, err := conn.Write([]byte(head + strings.Repeat("{", 512))); err != nil {
		t.Fatalf("écrire la requête partielle: %v", err)
	}
	started := time.Now()
	if err := conn.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, readErr := io.ReadAll(io.LimitReader(conn, 1<<20))
	elapsed := time.Since(started)
	var timeout net.Error
	if readErr == nil {
		t.Fatalf("la connexion est restée ouverte %s avec un corps jamais terminé", elapsed)
	}
	if errors.As(readErr, &timeout) && timeout.Timeout() {
		t.Fatalf("le serveur n'a pas clos le corps lent en %s : chaque lecture partielle retient une goroutine et une connexion", elapsed)
	}
	if elapsed > 12*time.Second {
		t.Fatalf("le corps lent a été clos après %s, want une échéance bien plus courte", elapsed)
	}
}

func TestEventsEvictedHeaderIsSurfacedByDashboard(t *testing.T) {
	harness := startLiveHarness(t, nil)
	status, headers, _ := harness.request(t, http.MethodGet, "/api/v1/events?after=0", nil, fixtureBearerAuth, fixtureDashboardToken)
	fixtureExpectStatus(t, status, http.StatusOK)
	if got := headers.Get("X-Events-Evicted"); got == "" {
		t.Fatal("l'API n'expose pas X-Events-Evicted : l'opérateur ne peut pas voir qu'une fenêtre a été évacuée")
	}
	status, _, page := harness.request(t, http.MethodGet, "/", nil, fixtureBasicAuth, fixtureDashboardToken)
	fixtureExpectStatus(t, status, http.StatusOK)
	if !bytes.Contains(page, []byte("X-Events-Evicted")) {
		t.Fatal("le tableau de bord ignore X-Events-Evicted : l'éviction de la fenêtre mémoire reste invisible à l'opérateur")
	}
}

func TestCommandLanguageFlagSelectsEnglishDashboard(t *testing.T) {
	buildContext, cancelBuild := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelBuild()
	binaryPath := filepath.Join(t.TempDir(), "c2blue-dns-live")
	build := exec.CommandContext(buildContext, "go", "build", "-o", binaryPath, "../../cmd/c2blue-dns-live")
	build.Env = append(os.Environ(), "GOEXPERIMENT=simd")
	output, err := build.CombinedOutput()
	if buildContext.Err() != nil {
		t.Fatalf("go build c2blue-dns-live exceeded 60 s: %v\n%s", buildContext.Err(), output)
	}
	if err != nil {
		t.Fatalf("go build c2blue-dns-live: %v\n%s", err, output)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate command HTTP address: %v", err)
	}
	httpAddress := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release command HTTP address: %v", err)
	}
	var commandOutput bytes.Buffer
	command := exec.CommandContext(t.Context(), binaryPath,
		"-udp-listen", "127.0.0.1:0",
		"-http-listen", httpAddress,
		"-evidence-dir", t.TempDir(),
		"-lang", "en",
	)
	command.Env = append(os.Environ(),
		"GOEXPERIMENT=simd",
		"C2BLUE_DASHBOARD_TOKEN="+fixtureDashboardToken,
	)
	command.Stdout = io.Discard
	command.Stderr = &commandOutput
	if err := command.Start(); err != nil {
		t.Fatalf("start c2blue-dns-live: %v", err)
	}
	t.Cleanup(func() {
		if err := command.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("stop c2blue-dns-live: %v", err)
		}
		if err := command.Wait(); err != nil {
			t.Logf("c2blue-dns-live terminated after test cleanup: %v", err)
		}
		t.Logf("c2blue-dns-live output:\n%s", commandOutput.String())
	})

	client := &http.Client{Timeout: 250 * time.Millisecond}
	t.Cleanup(client.CloseIdleConnections)
	deadline := time.Now().Add(20 * time.Second)
	var page string
	for {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+httpAddress+"/", nil)
		if err != nil {
			t.Fatalf("NewRequest command dashboard: %v", err)
		}
		request.SetBasicAuth("observer", fixtureDashboardToken)
		response, requestErr := client.Do(request)
		if requestErr == nil {
			payload, readErr := io.ReadAll(io.LimitReader(response.Body, (1<<20)+1))
			if readErr != nil {
				t.Fatalf("read command dashboard: %v", readErr)
			}
			if err := response.Body.Close(); err != nil {
				t.Fatalf("close command dashboard response: %v", err)
			}
			if response.StatusCode != http.StatusOK {
				t.Fatalf("command GET / = %d: %s", response.StatusCode, payload)
			}
			page = string(payload)
			break
		}
		if err := t.Context().Err(); err != nil {
			t.Fatalf("command dashboard request context: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatalf("command dashboard did not answer within 20 s: %v", requestErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	assertEnglishDNSLiveDashboard(t, page)
}
