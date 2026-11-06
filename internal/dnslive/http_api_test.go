package dnslive_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/dnslive"
)

func TestRegistrationLifecycleStrictJSONAndGuards(t *testing.T) {
	harness := startLiveHarness(t, nil)
	clientA := dialLiveUDP(t, harness)
	clientB := dialLiveUDP(t, harness)
	addrA := clientA.LocalAddr().(*net.UDPAddr)
	addrB := clientB.LocalAddr().(*net.UDPAddr)
	validA := fixtureRegistrationBody(t, "run-a", "BENIGN_EDNS0_STD", addrA)

	status, _, _ := harness.request(t, http.MethodPost, "/api/v1/registrations", validA, fixtureBearerAuth, "mauvais-secret")
	fixtureExpectStatus(t, status, http.StatusUnauthorized)
	status, _, _ = harness.request(t, http.MethodGet, "/api/v1/registrations", nil, fixtureBearerAuth, fixtureDashboardToken)
	fixtureExpectStatus(t, status, http.StatusMethodNotAllowed)

	var object map[string]any
	if err := json.Unmarshal(validA, &object); err != nil {
		t.Fatalf("fixture JSON: %v", err)
	}
	object["champ_inconnu"] = true
	unknownField, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("fixture champ inconnu: %v", err)
	}
	invalidBodies := []struct {
		name string
		body []byte
	}{
		{"champ_inconnu", unknownField},
		{"deux_valeurs_json", append(bytes.Clone(validA), '\n', '{', '}')},
		{"champ_dupliqué", []byte(`{"run_id":"run-a","run_id":"run-b","kind":"P1","source_ip":"127.0.0.1","source_port":12345}`)},
		{"json_tronque", bytes.Clone(validA[:len(validA)-1])},
		{"run_id_traversée", fixtureRegistrationBody(t, "../escape", "BENIGN_EDNS0_STD", addrA)},
		{"run_id_slash", fixtureRegistrationBody(t, "a/b", "BENIGN_EDNS0_STD", addrA)},
		{"kind_vide", fixtureRegistrationBody(t, "run-vide", "", addrA)},
		{"ip_invalide", []byte(`{"run_id":"run-ip","kind":"P1","source_ip":"pas-une-ip","source_port":12345}`)},
		{"port_zero", []byte(`{"run_id":"run-port","kind":"P1","source_ip":"127.0.0.1","source_port":0}`)},
	}
	for _, testCase := range invalidBodies {
		t.Run(testCase.name, func(t *testing.T) {
			status, _, _ := harness.request(t, http.MethodPost, "/api/v1/registrations", testCase.body, fixtureBearerAuth, fixtureDashboardToken)
			fixtureExpectStatus(t, status, http.StatusBadRequest)
		})
	}

	oversized := []byte(`{"run_id":"` + strings.Repeat("a", 1<<20) + `","kind":"P1","source_ip":"127.0.0.1","source_port":12345}`)
	status, _, _ = harness.request(t, http.MethodPost, "/api/v1/registrations", oversized, fixtureBearerAuth, fixtureDashboardToken)
	fixtureExpectStatus(t, status, http.StatusBadRequest, http.StatusRequestEntityTooLarge)

	registerLiveRun(t, harness, "run-a", "BENIGN_EDNS0_STD", addrA)
	status, _, _ = harness.request(t, http.MethodPost, "/api/v1/registrations", fixtureRegistrationBody(t, "run-conflit", "P1", addrA), fixtureBearerAuth, fixtureDashboardToken)
	fixtureExpectStatus(t, status, http.StatusConflict)
	registerLiveRun(t, harness, "run-b", "M-04", addrB)

	status, _, _ = harness.request(t, http.MethodGet, "/api/v1/runs", nil, fixtureBearerAuth, "mauvais-secret")
	fixtureExpectStatus(t, status, http.StatusUnauthorized)
	runs := fetchLiveRuns(t, harness)
	if len(runs) != 2 {
		t.Fatalf("runs = %d, attendu 2 après le conflit: %+v", len(runs), runs)
	}
	byID := make(map[string]liveRun, len(runs))
	for _, run := range runs {
		byID[run.RunID] = run
	}
	wantA := liveRun{RunID: "run-a", Kind: "BENIGN_EDNS0_STD", SourceIP: addrA.IP.String(), SourcePort: uint16(addrA.Port)}
	wantB := liveRun{RunID: "run-b", Kind: "M-04", SourceIP: addrB.IP.String(), SourcePort: uint16(addrB.Port)}
	if byID["run-a"] != wantA || byID["run-b"] != wantB {
		t.Fatalf("registre = %+v, attendu run-a=%+v run-b=%+v", byID, wantA, wantB)
	}

	status, _, _ = harness.request(t, http.MethodPost, "/api/v1/registrations/run-a/finish", nil, fixtureBearerAuth, "mauvais-secret")
	fixtureExpectStatus(t, status, http.StatusUnauthorized)
	status, _, _ = harness.request(t, http.MethodPut, "/api/v1/registrations/run-a/finish", nil, fixtureBearerAuth, fixtureDashboardToken)
	fixtureExpectStatus(t, status, http.StatusMethodNotAllowed)
	finishLiveRun(t, harness, "run-a")
	runs = fetchLiveRuns(t, harness)
	for _, run := range runs {
		switch run.RunID {
		case "run-a":
			if !run.Finished {
				t.Fatalf("run-a non terminé: %+v", run)
			}
		case "run-b":
			if run.Finished {
				t.Fatalf("run-b terminé par contamination: %+v", run)
			}
		}
	}

	// La fin détache le couple réel : les paquets ultérieurs restent visibles,
	// mais sans réactivation implicite ni run_id inventé.
	exchangeLiveUDP(t, clientA, fixtureQuery(t, 0x2101, "www.example.com", 1))
	events := fetchLiveEvents(t, harness, "", 0)
	if len(events) != 2 {
		t.Fatalf("événements après finish = %d, attendu 2", len(events))
	}
	for _, event := range events {
		if event.RunID != "" || event.Kind != "unregistered" {
			t.Fatalf("événement après finish = %+v, attendu source unregistered sans run_id", event)
		}
	}
}

func TestEventsAfterIsExclusiveStableAndLossless(t *testing.T) {
	harness := startLiveHarness(t, nil)
	client := dialLiveUDP(t, harness)
	const runID = "run-pagination"
	registerLiveRun(t, harness, runID, "BENIGN_EDNS0_STD", client.LocalAddr().(*net.UDPAddr))
	for i := range 3 {
		exchangeLiveUDP(t, client, fixtureQuery(t, uint16(0x2200+i), "www.example.com", 1))
	}
	all := fetchLiveEvents(t, harness, runID, 0)
	if len(all) != 6 {
		t.Fatalf("événements = %d, attendu 6", len(all))
	}
	for i, event := range all {
		if event.Sequence != uint64(i+1) {
			t.Fatalf("événement %d: sequence=%d, attendu %d", i, event.Sequence, i+1)
		}
		if event.RunID != runID || event.Kind != "BENIGN_EDNS0_STD" {
			t.Fatalf("corrélation pagination: %+v", event)
		}
	}

	afterTwo := fetchLiveEvents(t, harness, runID, 2)
	if !reflect.DeepEqual(afterTwo, all[2:]) {
		t.Fatalf("after=2 différent\nobtenu: %+v\nattendu: %+v", afterTwo, all[2:])
	}
	replayed := fetchLiveEvents(t, harness, runID, 2)
	if !reflect.DeepEqual(replayed, afterTwo) {
		t.Fatalf("after=2 non stable\npremier: %+v\nsecond: %+v", afterTwo, replayed)
	}
	if got := fetchLiveEvents(t, harness, runID, 6); len(got) != 0 {
		t.Fatalf("after=6 = %+v, attendu aucun événement", got)
	}

	for _, invalid := range []string{"-1", "abc", "1.5"} {
		status, _, _ := harness.request(t, http.MethodGet, "/api/v1/events?run_id="+runID+"&after="+invalid, nil, fixtureBearerAuth, fixtureDashboardToken)
		fixtureExpectStatus(t, status, http.StatusBadRequest)
	}
}

func TestDashboardAuthenticationHealthAndNoRawPacket(t *testing.T) {
	harness := startLiveHarness(t, nil)
	client := dialLiveUDP(t, harness)
	const runID = "run-html"
	registerLiveRun(t, harness, runID, "legit_a", client.LocalAddr().(*net.UDPAddr))
	query := fixtureQuery(t, 0x2301, "chunk1a00abcdef0123456789.chunk2b00abcdef0123456789abcdef.m01-volumetric.org", 16)
	exchangeLiveUDP(t, client, query)

	for _, auth := range []fixtureAuthMode{fixtureNoAuth, fixtureBasicAuth} {
		token := fixtureDashboardToken
		if auth == fixtureBasicAuth {
			token = "mauvais-secret"
		}
		status, _, _ := harness.request(t, http.MethodGet, "/", nil, auth, token)
		fixtureExpectStatus(t, status, http.StatusUnauthorized)
	}
	status, _, _ := harness.request(t, http.MethodPost, "/", nil, fixtureBasicAuth, fixtureDashboardToken)
	fixtureExpectStatus(t, status, http.StatusMethodNotAllowed)
	status, _, _ = harness.request(t, http.MethodGet, "/api/v1/events?after=0", nil, fixtureNoAuth, "")
	fixtureExpectStatus(t, status, http.StatusUnauthorized)

	status, headers, body := harness.request(t, http.MethodGet, "/", nil, fixtureBasicAuth, fixtureDashboardToken)
	fixtureExpectStatus(t, status, http.StatusOK)
	if contentType := headers.Get("Content-Type"); !strings.Contains(contentType, "text/html") {
		t.Fatalf("GET / Content-Type=%q, attendu text/html", contentType)
	}
	encoded := base64.StdEncoding.EncodeToString(query)
	rawHex := hex.EncodeToString(query)
	for name, forbidden := range map[string][]byte{
		"champ packet_base64": []byte("packet_base64"),
		"paquet base64":       []byte(encoded),
		"paquet hexadécimal":  []byte(rawHex),
		"octets UDP bruts":    query,
	} {
		if bytes.Contains(body, forbidden) {
			t.Fatalf("HTML contient %s, ce qui expose le paquet brut", name)
		}
	}

	status, _, healthBody := harness.request(t, http.MethodGet, "/healthz", nil, fixtureNoAuth, "")
	fixtureExpectStatus(t, status, http.StatusOK)
	var health struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(healthBody, &health); err != nil {
		t.Fatalf("healthz JSON: %v (%s)", err, healthBody)
	}
	if health.Status != "ok" {
		t.Fatalf("healthz status=%q, attendu ok", health.Status)
	}
}

func TestDashboardLanguageConfiguration(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		language string
	}{
		{name: "default_french"},
		{name: "explicit_french", language: "fr"},
		{name: "english", language: "en"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := startLiveHarness(t, func(config *dnslive.Config) {
				config.Language = testCase.language
			})
			status, _, body := harness.request(t, http.MethodGet, "/", nil, fixtureBasicAuth, fixtureDashboardToken)
			fixtureExpectStatus(t, status, http.StatusOK)
			page := string(body)
			if testCase.language == "en" {
				assertEnglishDNSLiveDashboard(t, page)
				return
			}
			for _, marker := range []string{`<html lang="fr">`, "DNS live", "Runs enregistrés", "Événements DNS", "Pourquoi cette alerte ?", "Faits observés", "Gardes bénignes"} {
				if !strings.Contains(page, marker) {
					t.Errorf("default/explicit French dashboard does not contain %q", marker)
				}
			}
			for _, marker := range []string{"Why this alert?", "Observed facts", "Benign guards"} {
				if strings.Contains(page, marker) {
					t.Errorf("French dashboard contains English marker %q", marker)
				}
			}
		})
	}
}

func assertEnglishDNSLiveDashboard(t *testing.T, page string) {
	t.Helper()
	for _, marker := range []string{`<html lang="en">`, "DNS live", "Runs", "Events", "Why this alert?", "Observed facts", "Benign guards"} {
		if !strings.Contains(page, marker) {
			t.Errorf("English dashboard does not contain %q", marker)
		}
	}
	for _, marker := range []string{"Pourquoi cette alerte ?", "Faits observés", "Gardes bénignes", "Runs enregistrés", "Événements DNS", "Démarrer", "Arrêter"} {
		if strings.Contains(page, marker) {
			t.Errorf("English dashboard retains French marker %q", marker)
		}
	}
}

func TestCommandC2BLUELanguageSelectsEnglishDashboard(t *testing.T) {
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
	)
	command.Env = append(os.Environ(),
		"GOEXPERIMENT=simd",
		"C2BLUE_DASHBOARD_TOKEN="+fixtureDashboardToken,
		"C2BLUE_LANG=en",
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
			if len(payload) > 1<<20 {
				t.Fatal("command dashboard exceeds 1 MiB")
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

type reasonGuide struct {
	ReasonCode   string   `json:"reason_code"`
	Class        string   `json:"class"`
	Mechanism    string   `json:"mechanism"`
	Measurements []string `json:"measurements"`
	Thresholds   []string `json:"thresholds"`
	Windows      []string `json:"windows"`
}

func TestReasonsGuideExplainsMeasurementsThresholdsAndWindows(t *testing.T) {
	harness := startLiveHarness(t, nil)
	status, _, payload := harness.request(t, http.MethodGet, "/api/v1/reasons", nil, fixtureBearerAuth, fixtureDashboardToken)
	fixtureExpectStatus(t, status, http.StatusOK)
	var guides []reasonGuide
	if err := json.Unmarshal(payload, &guides); err != nil {
		t.Fatalf("reasons JSON: %v (%s)", err, payload)
	}
	targets := map[string]struct {
		class            string
		mechanismToken   string
		measurementToken string
	}{
		"REASON_M01_LONG_LABEL":       {class: "M-01", mechanismToken: "label", measurementToken: "label"},
		"REASON_M04_DGA_CONSONANT_NX": {class: "M-04", mechanismToken: "nxdomain", measurementToken: "qname"},
		"REASON_P1_DOWNLINK_EXFIL":    {class: "P1", mechanismToken: "rdata", measurementToken: "rdata"},
		"REASON_P9_EDNS0_PRIVATE":     {class: "P9", mechanismToken: "opt", measurementToken: "option"},
	}
	seen := make(map[string]int, len(targets))
	for _, guide := range guides {
		target, wanted := targets[guide.ReasonCode]
		if !wanted {
			continue
		}
		seen[guide.ReasonCode]++
		if guide.Class != target.class {
			t.Errorf("%s: class=%q, attendu %q", guide.ReasonCode, guide.Class, target.class)
		}
		mechanism := strings.ToLower(strings.TrimSpace(guide.Mechanism))
		if mechanism == "" || mechanism == strings.ToLower(guide.ReasonCode) || !strings.Contains(mechanism, target.mechanismToken) || !strings.Contains(mechanism, " ") {
			t.Errorf("%s: mécanisme insuffisant %q, attendu une explication référençant %q", guide.ReasonCode, guide.Mechanism, target.mechanismToken)
		}
		measurements := strings.ToLower(strings.Join(guide.Measurements, " "))
		if len(guide.Measurements) == 0 || !strings.Contains(measurements, target.measurementToken) {
			t.Errorf("%s: mesures=%v, attendu au moins %q", guide.ReasonCode, guide.Measurements, target.measurementToken)
		}
		if len(guide.Thresholds) == 0 {
			t.Errorf("%s: aucun seuil publié", guide.ReasonCode)
		}
		for _, threshold := range guide.Thresholds {
			if !strings.ContainsAny(threshold, "0123456789") || !strings.ContainsAny(threshold, "<>=") {
				t.Errorf("%s: seuil non opposable %q, attendu une mesure chiffrée et un comparateur", guide.ReasonCode, threshold)
			}
		}
		if len(guide.Windows) == 0 {
			t.Errorf("%s: aucune fenêtre publiée", guide.ReasonCode)
		}
		for _, window := range guide.Windows {
			if strings.TrimSpace(window) == "" {
				t.Errorf("%s: fenêtre vide", guide.ReasonCode)
			}
		}
	}
	for reason := range targets {
		if seen[reason] != 1 {
			t.Errorf("guide %s présent %d fois, attendu exactement 1", reason, seen[reason])
		}
	}

	parseGuides := 0
	for _, guide := range guides {
		if guide.ReasonCode != "REASON_DNS_PARSE_ERROR" {
			continue
		}
		parseGuides++
		mechanism := strings.ToLower(guide.Mechanism)
		if guide.Class != "PARSE_ERR" || !strings.Contains(mechanism, "parse") && !strings.Contains(mechanism, "décod") {
			t.Errorf("guide parse insuffisant: %+v", guide)
		}
	}
	if parseGuides != 1 {
		t.Fatalf("guide REASON_DNS_PARSE_ERROR présent %d fois, attendu 1", parseGuides)
	}
}

func TestEventsMemoryWindowRetainsAllEvidence(t *testing.T) {
	harness := startLiveHarness(t, nil)
	client := dialLiveUDP(t, harness)
	clientAddr := client.LocalAddr().(*net.UDPAddr)
	const (
		runID         = "run-memory-window"
		eventWindow   = 4096
		datagramCount = 4100
		batchSize     = 128
	)
	registerLiveRun(t, harness, runID, "BENIGN_EDNS0_STD", clientAddr)

	// Deux octets ne forment jamais un en-tête DNS : chaque datagramme distinct
	// est donc journalisé comme erreur d'analyse, sans réponse UDP. Les lots et
	// la borne de réception HTTP empêchent l'accumulation dans le tampon noyau.
	packets := make([][2]byte, datagramCount)
	for i := range packets {
		packets[i] = [2]byte{byte(i >> 8), byte(i)}
	}
	eventsPath := "/api/v1/events?run_id=" + runID + "&after=0"
	readEvents := func() ([]liveEvent, http.Header) {
		status, headers, payload := harness.request(t, http.MethodGet, eventsPath, nil, fixtureBearerAuth, fixtureDashboardToken)
		fixtureExpectStatus(t, status, http.StatusOK)
		var events []liveEvent
		if err := json.Unmarshal(payload, &events); err != nil {
			t.Fatalf("GET events JSON: %v (%s)", err, payload)
		}
		return events, headers
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	processingTimer := time.NewTimer(120 * time.Second)
	defer processingTimer.Stop()
	var events []liveEvent
	var headers http.Header
	for sent := 0; sent < datagramCount; {
		batchEnd := min(sent+batchSize, datagramCount)
		for sent < batchEnd {
			written, err := client.Write(packets[sent][:])
			if err != nil || written != len(packets[sent]) {
				t.Fatalf("écriture UDP %d = %d/%d, err=%v", sent+1, written, len(packets[sent]), err)
			}
			sent++
		}
		for {
			events, headers = readEvents()
			if len(events) > 0 && events[len(events)-1].Sequence == uint64(sent) {
				break
			}
			select {
			case <-t.Context().Done():
				t.Fatalf("attente des %d événements: %v", sent, t.Context().Err())
			case <-processingTimer.C:
				t.Fatalf("attente des %d événements expirée après %d événements mémoire", sent, len(events))
			case <-ticker.C:
			}
		}
	}

	if err := client.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("échéance de lecture des réponses: %v", err)
	}
	responseBuffer := make([]byte, 1)
	if read, err := client.Read(responseBuffer); err == nil {
		t.Fatalf("réponse UDP inattendue à un datagramme malformé: %x", responseBuffer[:read])
	} else {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("lecture UDP après datagrammes malformés: %v, attendu une expiration sans réponse", err)
		}
	}

	const evictedCount = datagramCount - eventWindow
	if len(events) != eventWindow {
		t.Errorf("événements mémoire = %d, attendu la fenêtre de %d derniers événements", len(events), eventWindow)
	}
	if len(events) > 0 {
		if first := events[0].Sequence; first != evictedCount+1 {
			t.Errorf("première séquence mémoire = %d, attendu %d après %d évictions", first, evictedCount+1, evictedCount)
		}
		for i, event := range events {
			if want := uint64(i + evictedCount + 1); event.Sequence != want {
				t.Errorf("séquence mémoire à l'indice %d = %d, attendu %d", i, event.Sequence, want)
				break
			}
		}
	}
	if got := headers.Values("X-Events-Evicted"); !reflect.DeepEqual(got, []string{"4"}) {
		t.Errorf("en-tête X-Events-Evicted = %q, attendu exactement %q", got, "4")
	}

	finishLiveRun(t, harness, runID)
	status, _, payload := harness.request(t, http.MethodGet, "/api/v1/evidence/"+runID, nil, fixtureBearerAuth, fixtureDashboardToken)
	fixtureExpectStatus(t, status, http.StatusOK)
	var manifest evidenceManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatalf("manifeste JSON: %v (%s)", err, payload)
	}
	wantRetention := evidenceRetention{Policy: "retain-all", MaxPacketBytes: 0, TruncatedPackets: 0, DroppedPackets: 0}
	if manifest.RunID != runID || manifest.Emitter != "c2blue-dns-live" || manifest.CaptureMode != "udp-reconstructed" || manifest.Retention != wantRetention {
		t.Fatalf("manifeste de preuve = %+v, attendu retain-all sans troncature ni perte", manifest)
	}

	jsonlBytes, err := os.ReadFile(evidenceFilePath(t, harness.evidenceDir, manifest.Files.JSONL))
	if err != nil {
		t.Fatalf("lecture JSONL: %v", err)
	}
	rows := bytes.Split(jsonlBytes, []byte{'\n'})
	if len(rows) > 0 && len(rows[len(rows)-1]) == 0 {
		rows = rows[:len(rows)-1]
	}
	if len(rows) != datagramCount {
		t.Fatalf("JSONL = %d objets, attendu %d objets intégraux", len(rows), datagramCount)
	}
	for i, row := range rows {
		var stored storedLiveEvent
		if err := json.Unmarshal(row, &stored); err != nil {
			t.Fatalf("JSONL ligne %d: %v", i+1, err)
		}
		if stored.Emitter != "c2blue-dns-live" || stored.CaptureMode != "udp-reconstructed" {
			t.Fatalf("JSONL ligne %d: emitter=%q capture_mode=%q", i+1, stored.Emitter, stored.CaptureMode)
		}
		if stored.ParseError == "" {
			t.Errorf("JSONL ligne %d: erreur d'analyse absente", i+1)
		}
		packetSHA, packetBase64 := fixturePacketFields(packets[i][:])
		assertLiveEvent(t, stored.liveEvent, liveEvent{
			Sequence: uint64(i + 1), RunID: runID, Kind: "BENIGN_EDNS0_STD", Direction: fixtureQueryDirection,
			SrcIP: clientAddr.IP.String(), SrcPort: uint16(clientAddr.Port), DstIP: "127.0.0.1", DstPort: uint16(harness.udpAddr.Port),
			TxID: uint16(i), Decision: c2blue55.DecisionEscalateSLM, Class: "PARSE_ERR", ReasonCode: c2blue55.ReasonDNSParseError,
			PacketSHA256: packetSHA, PacketBase64: packetBase64, ParseError: stored.ParseError,
		})
		if i >= evictedCount && len(events) == eventWindow && !reflect.DeepEqual(stored.liveEvent, events[i-evictedCount]) {
			t.Fatalf("événement API %d différent de son objet JSONL intégral\nAPI: %+v\nJSONL: %+v", i+1, events[i-evictedCount], stored.liveEvent)
		}
	}
}
