package dnslive_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/dnslab"
	"github.com/hazyhaar/c2blue55/internal/dnslive"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

const (
	fixtureDashboardToken = "fixture-dashboard-token"
	fixtureQueryDirection = "query"
	fixtureRespDirection  = "response"
)

// liveEvent est le contrat JSON public. Les faits de trafic restent distincts
// des métadonnées run_id et kind, qui ne participent jamais à la détection.
type liveEvent struct {
	Sequence     uint64 `json:"sequence"`
	RunID        string `json:"run_id"`
	Kind         string `json:"kind"`
	TimestampNS  int64  `json:"timestamp_ns"`
	Direction    string `json:"direction"`
	SrcIP        string `json:"src_ip"`
	SrcPort      uint16 `json:"src_port"`
	DstIP        string `json:"dst_ip"`
	DstPort      uint16 `json:"dst_port"`
	TxID         uint16 `json:"txid"`
	QName        string `json:"qname"`
	QType        uint16 `json:"qtype"`
	Decision     uint8  `json:"decision"`
	Class        string `json:"class"`
	ReasonCode   string `json:"reason_code"`
	PacketSHA256 string `json:"packet_sha256"`
	PacketBase64 string `json:"packet_base64"`
	ParseError   string `json:"parse_error"`
	SubdomainLen int    `json:"subdomain_len"`
	LabelCount   int    `json:"label_count"`
	MaxLabelLen  int    `json:"max_label_len"`
	AnswerCount  int    `json:"answer_count"`
	RDataBytes   int    `json:"rdata_bytes"`
}

type liveRun struct {
	RunID      string `json:"run_id"`
	Kind       string `json:"kind"`
	SourceIP   string `json:"source_ip"`
	SourcePort uint16 `json:"source_port"`
	Finished   bool   `json:"finished"`
}

type fixtureAuthMode uint8

const (
	fixtureNoAuth fixtureAuthMode = iota
	fixtureBearerAuth
	fixtureBasicAuth
)

type liveHarness struct {
	serviceLive     *dnslive.ServiceLive
	udpAddr         *net.UDPAddr
	httpBase        string
	evidenceDir     string
	client          *http.Client
	transport       *http.Transport
	allowCloseError bool
	closeOnce       sync.Once
	closeErr        error
}

func startLiveHarness(t *testing.T, adjust func(*dnslive.Config)) *liveHarness {
	t.Helper()
	cfg := dnslive.Config{
		UDPListen:      "127.0.0.1:0",
		HTTPListen:     "127.0.0.1:0",
		EvidenceDir:    t.TempDir(),
		DashboardToken: fixtureDashboardToken,
	}
	if adjust != nil {
		adjust(&cfg)
	}
	serviceLive, err := dnslive.New(cfg)
	if err != nil {
		t.Fatalf("dnslive.New: %v", err)
	}
	if err := serviceLive.Start(); err != nil {
		t.Fatalf("Service.Start: %v", err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", serviceLive.UDPAddr())
	if err != nil {
		t.Fatalf("Service.UDPAddr %q: %v", serviceLive.UDPAddr(), err)
	}
	transport := &http.Transport{DisableKeepAlives: true}
	harness := &liveHarness{
		serviceLive: serviceLive,
		udpAddr:     udpAddr,
		httpBase:    "http://" + serviceLive.HTTPAddr(),
		evidenceDir: cfg.EvidenceDir,
		transport:   transport,
	}
	harness.client = &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	t.Cleanup(func() {
		if err := harness.close(); err != nil && !harness.allowCloseError {
			t.Errorf("Service.Close: %v", err)
		}
	})
	return harness
}

func (h *liveHarness) close() error {
	h.closeOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		h.closeErr = h.serviceLive.Close(ctx)
		h.transport.CloseIdleConnections()
	})
	return h.closeErr
}

func (h *liveHarness) request(t *testing.T, method, path string, body []byte, auth fixtureAuthMode, token string) (int, http.Header, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, h.httpBase+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	switch auth {
	case fixtureBearerAuth:
		req.Header.Set("Authorization", "Bearer "+token)
	case fixtureBasicAuth:
		req.SetBasicAuth("observer", token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	const maxResponseBytes = 8 << 20
	payload, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		t.Fatalf("%s %s lecture: %v", method, path, err)
	}
	if len(payload) > maxResponseBytes {
		t.Fatalf("%s %s: réponse supérieure à %d octets, analyse tronquée refusée", method, path, maxResponseBytes)
	}
	return resp.StatusCode, resp.Header, payload
}

func fixtureExpectStatus(t *testing.T, got int, want ...int) {
	t.Helper()
	if slices.Contains(want, got) {
		return
	}
	t.Fatalf("statut HTTP %d, attendu %v", got, want)
}

func fixtureRegistrationBody(t *testing.T, runID, kind string, addr *net.UDPAddr) []byte {
	body, err := json.Marshal(map[string]any{
		"run_id":      runID,
		"kind":        kind,
		"source_ip":   addr.IP.String(),
		"source_port": addr.Port,
	})
	if err != nil {
		t.Fatalf("fixture d'enregistrement: %v", err)
	}
	return body
}

func registerLiveRun(t *testing.T, harness *liveHarness, runID, kind string, addr *net.UDPAddr) liveRun {
	t.Helper()
	status, _, payload := harness.request(t, http.MethodPost, "/api/v1/registrations", fixtureRegistrationBody(t, runID, kind, addr), fixtureBearerAuth, fixtureDashboardToken)
	fixtureExpectStatus(t, status, http.StatusCreated)
	var registered liveRun
	if err := json.Unmarshal(payload, &registered); err != nil {
		t.Fatalf("enregistrement JSON: %v (%s)", err, payload)
	}
	want := liveRun{RunID: runID, Kind: kind, SourceIP: addr.IP.String(), SourcePort: uint16(addr.Port)}
	if registered != want {
		t.Fatalf("run enregistré = %+v, attendu %+v", registered, want)
	}
	return registered
}

func finishLiveRun(t *testing.T, harness *liveHarness, runID string) {
	t.Helper()
	status, _, _ := harness.request(t, http.MethodPost, "/api/v1/registrations/"+url.PathEscape(runID)+"/finish", nil, fixtureBearerAuth, fixtureDashboardToken)
	fixtureExpectStatus(t, status, http.StatusOK)
}

func fetchLiveRuns(t *testing.T, harness *liveHarness) []liveRun {
	t.Helper()
	status, _, payload := harness.request(t, http.MethodGet, "/api/v1/runs", nil, fixtureBearerAuth, fixtureDashboardToken)
	fixtureExpectStatus(t, status, http.StatusOK)
	var runs []liveRun
	if err := json.Unmarshal(payload, &runs); err != nil {
		t.Fatalf("GET runs JSON: %v (%s)", err, payload)
	}
	return runs
}

func fetchLiveEvents(t *testing.T, harness *liveHarness, runID string, after uint64) []liveEvent {
	t.Helper()
	query := url.Values{"after": {strconv.FormatUint(after, 10)}}
	if runID != "" {
		query.Set("run_id", runID)
	}
	status, _, payload := harness.request(t, http.MethodGet, "/api/v1/events?"+query.Encode(), nil, fixtureBearerAuth, fixtureDashboardToken)
	fixtureExpectStatus(t, status, http.StatusOK)
	var events []liveEvent
	if err := json.Unmarshal(payload, &events); err != nil {
		t.Fatalf("GET events JSON: %v (%s)", err, payload)
	}
	return events
}

func dialLiveUDP(t *testing.T, harness *liveHarness) *net.UDPConn {
	t.Helper()
	server := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: harness.udpAddr.Port}
	client, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}, server)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func fixtureQuery(t *testing.T, txid uint16, qname string, qtype uint16) []byte {
	t.Helper()
	var storage [512]byte
	n, err := dnslab.BuildQuery(txid, []byte(qname), qtype, storage[:])
	if err != nil {
		t.Fatalf("BuildQuery %s: %v", qname, err)
	}
	return bytes.Clone(storage[:n])
}

func exchangeLiveUDP(t *testing.T, client *net.UDPConn, query []byte) []byte {
	t.Helper()
	if err := client.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("échéance UDP: %v", err)
	}
	n, err := client.Write(query)
	if err != nil || n != len(query) {
		t.Fatalf("écriture UDP = %d/%d, err=%v", n, len(query), err)
	}
	storage := make([]byte, 65535)
	n, err = client.Read(storage)
	if err != nil {
		t.Fatalf("lecture UDP: %v", err)
	}
	response := bytes.Clone(storage[:n])
	if len(response) < 12 {
		t.Fatalf("réponse UDP de %d octets", len(response))
	}
	if response[0] != query[0] || response[1] != query[1] {
		t.Fatalf("TXID réponse %x, requête %x", response[:2], query[:2])
	}
	return response
}

func fixturePacketFields(packet []byte) (string, string) {
	digest := sha256.Sum256(packet)
	return hex.EncodeToString(digest[:]), base64.StdEncoding.EncodeToString(packet)
}

func assertLiveEvent(t *testing.T, got, want liveEvent) {
	t.Helper()
	if got.TimestampNS <= 0 {
		t.Errorf("timestamp_ns = %d, attendu une valeur positive", got.TimestampNS)
	}
	want.TimestampNS = got.TimestampNS
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("événement différent\nobtenu: %+v\nattendu: %+v", got, want)
	}
}

func responseEvent(t *testing.T, events []liveEvent, exchangeIndex int) liveEvent {
	t.Helper()
	index := 2*exchangeIndex + 1
	if exchangeIndex < 0 || index >= len(events) {
		t.Fatalf("réponse %d absente de %d événements", exchangeIndex, len(events))
	}
	return events[index]
}

func TestRegisteredEphemeralSourceQuestionResponse(t *testing.T) {
	harness := startLiveHarness(t, nil)
	client := dialLiveUDP(t, harness)
	clientAddr := client.LocalAddr().(*net.UDPAddr)
	const runID = "run-udp-real"
	const kind = "BENIGN_EDNS0_STD"
	registerLiveRun(t, harness, runID, kind, clientAddr)

	query := fixtureQuery(t, 0x1001, "www.example.com", 1)
	response := exchangeLiveUDP(t, client, query)
	var expectedStorage [512]byte
	expectedLen, err := dnslab.BuildLabResponse17Motifs(query, kind, expectedStorage[:])
	if err != nil {
		t.Fatalf("BuildLabResponse17Motifs témoin: %v", err)
	}
	if !bytes.Equal(response, expectedStorage[:expectedLen]) {
		t.Fatalf("réponse UDP différente du répondeur de laboratoire (%d/%d octets)", len(response), expectedLen)
	}

	events := fetchLiveEvents(t, harness, runID, 0)
	if len(events) != 2 {
		t.Fatalf("événements = %d, attendu question et réponse", len(events))
	}
	querySHA, queryB64 := fixturePacketFields(query)
	responseSHA, responseB64 := fixturePacketFields(response)
	clientPort := uint16(clientAddr.Port)
	serverPort := uint16(harness.udpAddr.Port)
	assertLiveEvent(t, events[0], liveEvent{
		Sequence: 1, RunID: runID, Kind: kind, Direction: fixtureQueryDirection,
		SrcIP: "127.0.0.1", SrcPort: clientPort, DstIP: "127.0.0.1", DstPort: serverPort,
		TxID: 0x1001, QName: "www.example.com", QType: 1,
		Decision: c2blue55.DecisionFastPass, Class: "BENIGN", ReasonCode: engine.ReasonNone,
		PacketSHA256: querySHA, PacketBase64: queryB64,
		SubdomainLen: 3, LabelCount: 3, MaxLabelLen: 7,
	})
	assertLiveEvent(t, events[1], liveEvent{
		Sequence: 2, RunID: runID, Kind: kind, Direction: fixtureRespDirection,
		SrcIP: "127.0.0.1", SrcPort: serverPort, DstIP: "127.0.0.1", DstPort: clientPort,
		TxID: 0x1001, QName: "www.example.com", QType: 1,
		Decision: c2blue55.DecisionFastPass, Class: "BENIGN", ReasonCode: engine.ReasonNone,
		PacketSHA256: responseSHA, PacketBase64: responseB64,
		SubdomainLen: 3, LabelCount: 3, MaxLabelLen: 7, AnswerCount: 1, RDataBytes: 4,
	})
}

func TestDetectionUsesBytesRatherThanKind(t *testing.T) {
	t.Run("M-01 sous kind legit_a", func(t *testing.T) {
		harness := startLiveHarness(t, nil)
		client := dialLiveUDP(t, harness)
		const runID = "run-bytes-not-kind"
		registerLiveRun(t, harness, runID, "legit_a", client.LocalAddr().(*net.UDPAddr))
		query := fixtureQuery(t, 0x1101, "chunk1a00abcdef0123456789.chunk2b00abcdef0123456789abcdef.m01-volumetric.org", 16)
		exchangeLiveUDP(t, client, query)
		events := fetchLiveEvents(t, harness, runID, 0)
		if len(events) != 2 {
			t.Fatalf("événements = %d, attendu 2", len(events))
		}
		got := events[0]
		if got.Kind != "legit_a" || got.RunID != runID || got.Class != "M-01" || got.ReasonCode != engine.ReasonM01LongLabel || got.Decision != c2blue55.DecisionEscalateSLM {
			t.Fatalf("kind=%q run_id=%q class=%q reason=%q decision=%d, attendu métadonnées legit_a et détection M-01 depuis les octets", got.Kind, got.RunID, got.Class, got.ReasonCode, got.Decision)
		}
	})

	t.Run("kind M-01 ne condamne pas une requête bénigne", func(t *testing.T) {
		harness := startLiveHarness(t, nil)
		client := dialLiveUDP(t, harness)
		const runID = "run-kind-not-bytes"
		registerLiveRun(t, harness, runID, "M-01", client.LocalAddr().(*net.UDPAddr))
		query := fixtureQuery(t, 0x1102, "www.example.com", 1)
		exchangeLiveUDP(t, client, query)
		events := fetchLiveEvents(t, harness, runID, 0)
		if len(events) != 2 {
			t.Fatalf("événements = %d, attendu 2", len(events))
		}
		for _, got := range events {
			if got.Kind != "M-01" || got.Class != "BENIGN" || got.ReasonCode != engine.ReasonNone || got.Decision != c2blue55.DecisionFastPass {
				t.Fatalf("direction=%s kind=%q class=%q reason=%q decision=%d, l'étiquette M-01 ne doit pas être une entrée de détection", got.Direction, got.Kind, got.Class, got.ReasonCode, got.Decision)
			}
		}
	})
}

func fixtureM04Queries(t *testing.T) [][]byte {
	t.Helper()
	exchanges, _, err := dnslab.BuildIRLDilutedStream17Motifs(0x4D04, 0.80, 240)
	if err != nil {
		t.Fatalf("fixture M-04: %v", err)
	}
	queries := make([][]byte, 0, 4)
	seen := make(map[string]struct{})
	for _, exchange := range exchanges {
		if exchange.Family != "M-04" {
			continue
		}
		var msg c2blue55.DNSMessage
		if err := c2blue55.ParseDNSMessage(exchange.RequestWire, &msg); err != nil {
			t.Fatalf("fixture M-04 illisible: %v", err)
		}
		qname := string(msg.QName[:msg.QNameLen])
		if _, duplicate := seen[qname]; duplicate {
			continue
		}
		seen[qname] = struct{}{}
		queries = append(queries, bytes.Clone(exchange.RequestWire))
		if len(queries) == 4 {
			break
		}
	}
	if len(queries) != 4 {
		t.Fatalf("fixture M-04: %d QNAME distincts, attendu 4", len(queries))
	}
	return queries
}

func TestStatefulAndResponseMotifs(t *testing.T) {
	t.Run("M-04 au quatrième NXDOMAIN DGA distinct", func(t *testing.T) {
		harness := startLiveHarness(t, nil)
		client := dialLiveUDP(t, harness)
		const runID = "run-m04-window"
		registerLiveRun(t, harness, runID, "M-04", client.LocalAddr().(*net.UDPAddr))
		for i, query := range fixtureM04Queries(t) {
			exchangeLiveUDP(t, client, query)
			events := fetchLiveEvents(t, harness, runID, 0)
			if len(events) != 2*(i+1) {
				t.Fatalf("échange %d: %d événements, attendu %d", i+1, len(events), 2*(i+1))
			}
			got := responseEvent(t, events, i)
			if i < 3 && got.ReasonCode == engine.ReasonM04DGAConsonantNX {
				t.Fatalf("M-04 déclenché dès la réponse %d, avant les quatre QNAME distincts", i+1)
			}
			if i == 3 && (got.Class != "M-04" || got.ReasonCode != engine.ReasonM04DGAConsonantNX || got.Decision != c2blue55.DecisionEscalateSLM) {
				t.Fatalf("quatrième réponse: class=%q reason=%q decision=%d, attendu M-04", got.Class, got.ReasonCode, got.Decision)
			}
		}
	})

	t.Run("P1 sur réponse TXT longue", func(t *testing.T) {
		harness := startLiveHarness(t, nil)
		client := dialLiveUDP(t, harness)
		const runID = "run-p1-long-response"
		registerLiveRun(t, harness, runID, "P1", client.LocalAddr().(*net.UDPAddr))
		exchangeLiveUDP(t, client, fixtureQuery(t, 0x1201, "p1dl00.irl-p1-01.org", 16))
		events := fetchLiveEvents(t, harness, runID, 0)
		got := responseEvent(t, events, 0)
		if got.Class != "P1" || got.ReasonCode != engine.ReasonP1DownlinkExfil || got.Decision != c2blue55.DecisionEscalateSLM || got.RDataBytes != 220 || got.AnswerCount != 1 {
			t.Fatalf("réponse P1 = %+v, attendu P1, 220 octets RDATA et une réponse", got)
		}
	})

	t.Run("P9 sur option OPT privée", func(t *testing.T) {
		harness := startLiveHarness(t, nil)
		client := dialLiveUDP(t, harness)
		const runID = "run-p9-private-opt"
		registerLiveRun(t, harness, runID, "P9", client.LocalAddr().(*net.UDPAddr))
		exchangeLiveUDP(t, client, fixtureQuery(t, 0x1202, "p9.example.com", 1))
		events := fetchLiveEvents(t, harness, runID, 0)
		got := responseEvent(t, events, 0)
		if got.Class != "P9" || got.ReasonCode != engine.ReasonP9EDNS0PrivateOption || got.Decision != c2blue55.DecisionEscalateSLM {
			t.Fatalf("réponse P9: class=%q reason=%q decision=%d", got.Class, got.ReasonCode, got.Decision)
		}
	})
}

func TestP20P21SelectBuildResponse(t *testing.T) {
	t.Run("P20 produit NXDOMAIN avec SOA", func(t *testing.T) {
		harness := startLiveHarness(t, nil)
		client := dialLiveUDP(t, harness)
		const runID = "run-p20-soa"
		registerLiveRun(t, harness, runID, "P20", client.LocalAddr().(*net.UDPAddr))
		qnames := [...]string{
			"nx-fixture-a.lab.pound2pound.fr",
			"nx-fixture-b.lab.pound2pound.fr",
			"nx-fixture-c.lab.pound2pound.fr",
		}
		for i, qname := range qnames {
			response := exchangeLiveUDP(t, client, fixtureQuery(t, uint16(0x1301+i), qname, 1))
			var msg c2blue55.DNSMessage
			if err := c2blue55.ParseDNSMessage(response, &msg); err != nil {
				t.Fatalf("réponse P20 %d illisible: %v", i+1, err)
			}
			if msg.RCode != 3 || msg.AuthorityCount != 1 || msg.Authorities[0].Type != 6 {
				t.Fatalf("P20 réponse %d: RCode=%d AuthorityCount=%d type=%d, attendu NXDOMAIN et un SOA", i+1, msg.RCode, msg.AuthorityCount, msg.Authorities[0].Type)
			}
		}
		events := fetchLiveEvents(t, harness, runID, 0)
		if len(events) != 2*len(qnames) {
			t.Fatalf("P20: événements = %d, attendu %d questions et réponses", len(events), 2*len(qnames))
		}
		for i := range qnames {
			got := responseEvent(t, events, i)
			if i < len(qnames)-1 {
				if got.Class == "P20" || got.ReasonCode == engine.ReasonP20SOANegDownlink {
					t.Fatalf("P20 déclenché avant la troisième réponse, réponse %d = %+v", i+1, got)
				}
				continue
			}
			if got.Class != "P20" || got.ReasonCode != engine.ReasonP20SOANegDownlink || got.Decision != c2blue55.DecisionEscalateSLM {
				t.Fatalf("troisième réponse P20: class=%q reason=%q decision=%d, attendu la détection SOA spécialisée", got.Class, got.ReasonCode, got.Decision)
			}
		}
	})

	t.Run("P21 produit des IID AAAA renouvelés", func(t *testing.T) {
		harness := startLiveHarness(t, nil)
		client := dialLiveUDP(t, harness)
		const runID = "run-p21-iid"
		registerLiveRun(t, harness, runID, "P21", client.LocalAddr().(*net.UDPAddr))
		const responseCount = 8
		seenIIDs := make(map[[8]byte]struct{}, responseCount)
		for i := range responseCount {
			response := exchangeLiveUDP(t, client, fixtureQuery(t, uint16(0x1310+i), "host.lab.pound2pound.fr", 28))
			var msg c2blue55.DNSMessage
			if err := c2blue55.ParseDNSMessage(response, &msg); err != nil {
				t.Fatalf("réponse P21 %d: %v", i+1, err)
			}
			if msg.AnswerCount != 1 || msg.Answers[0].Type != 28 || msg.Answers[0].RDataLen != 16 {
				t.Fatalf("P21 réponse %d: réponse AAAA inattendue %+v", i+1, msg.Answers[0])
			}
			var iid [8]byte
			copy(iid[:], msg.Answers[0].RData[8:16])
			if _, duplicate := seenIIDs[iid]; duplicate {
				t.Fatalf("P21: IID identique %x à la réponse %d, BuildResponse/AAAAIIDStego non sélectionné", iid, i+1)
			}
			seenIIDs[iid] = struct{}{}
		}
		events := fetchLiveEvents(t, harness, runID, 0)
		if len(events) != 2*responseCount {
			t.Fatalf("P21: événements = %d, attendu %d questions et réponses", len(events), 2*responseCount)
		}
		for i := range responseCount {
			got := responseEvent(t, events, i)
			if i < responseCount-1 {
				if got.Class == "P21" || got.ReasonCode == engine.ReasonP21AAAAIIDDownlink {
					t.Fatalf("P21 déclenché avant la huitième réponse, réponse %d = %+v", i+1, got)
				}
				continue
			}
			if got.Class != "P21" || got.ReasonCode != engine.ReasonP21AAAAIIDDownlink || got.Decision != c2blue55.DecisionEscalateSLM {
				t.Fatalf("huitième réponse P21: class=%q reason=%q decision=%d, attendu la détection AAAA IID spécialisée", got.Class, got.ReasonCode, got.Decision)
			}
		}
	})
}

func TestSameIPDifferentPortsHaveIndependentPipelines(t *testing.T) {
	harness := startLiveHarness(t, nil)
	clientA := dialLiveUDP(t, harness)
	clientB := dialLiveUDP(t, harness)
	addrA := clientA.LocalAddr().(*net.UDPAddr)
	addrB := clientB.LocalAddr().(*net.UDPAddr)
	if addrA.IP.String() != addrB.IP.String() || addrA.Port == addrB.Port {
		t.Fatalf("témoin invalide: sources %s et %s", addrA, addrB)
	}
	registerLiveRun(t, harness, "run-a", "M-04", addrA)
	registerLiveRun(t, harness, "run-b", "M-04", addrB)
	queries := fixtureM04Queries(t)
	for i := range 3 {
		exchangeLiveUDP(t, clientA, queries[i])
	}

	// Un état mutualisé par seule adresse IP détecterait ici la première trame B.
	exchangeLiveUDP(t, clientB, queries[0])
	eventsB := fetchLiveEvents(t, harness, "run-b", 0)
	firstB := responseEvent(t, eventsB, 0)
	if firstB.Class == "M-04" || firstB.ReasonCode == engine.ReasonM04DGAConsonantNX {
		t.Fatalf("contamination entre ports: première réponse B = %+v après trois réponses A", firstB)
	}
	for _, event := range eventsB {
		if event.RunID != "run-b" || event.SrcPort == uint16(addrA.Port) && event.Direction == fixtureQueryDirection {
			t.Fatalf("corrélation B incorrecte: %+v", event)
		}
	}

	exchangeLiveUDP(t, clientA, queries[3])
	lastA := responseEvent(t, fetchLiveEvents(t, harness, "run-a", 0), 3)
	if lastA.RunID != "run-a" || lastA.Class != "M-04" || lastA.ReasonCode != engine.ReasonM04DGAConsonantNX {
		t.Fatalf("quatrième réponse A = %+v, attendu M-04 dans run-a", lastA)
	}
	for i := 1; i < 4; i++ {
		exchangeLiveUDP(t, clientB, queries[i])
	}
	lastB := responseEvent(t, fetchLiveEvents(t, harness, "run-b", 0), 3)
	if lastB.RunID != "run-b" || lastB.Class != "M-04" || lastB.ReasonCode != engine.ReasonM04DGAConsonantNX {
		t.Fatalf("quatrième réponse B = %+v, attendu M-04 dans run-b", lastB)
	}
}

func TestUnregisteredSourceHasNoInventedRun(t *testing.T) {
	harness := startLiveHarness(t, nil)
	client := dialLiveUDP(t, harness)
	clientAddr := client.LocalAddr().(*net.UDPAddr)
	query := fixtureQuery(t, 0x1401, "www.example.com", 1)
	exchangeLiveUDP(t, client, query)
	events := fetchLiveEvents(t, harness, "", 0)
	if len(events) != 2 {
		t.Fatalf("événements non enregistrés = %d, attendu 2", len(events))
	}
	for _, event := range events {
		if event.RunID != "" || event.Kind != "unregistered" {
			t.Fatalf("source non enregistrée: run_id=%q kind=%q, attendu run_id vide et kind unregistered", event.RunID, event.Kind)
		}
		if event.Direction == fixtureQueryDirection && (event.SrcIP != clientAddr.IP.String() || event.SrcPort != uint16(clientAddr.Port)) {
			t.Fatalf("source réelle perdue: %+v", event)
		}
	}
}

var errFixtureJournal = errors.New("fixture-journal: écriture refusée")

type fixtureFailWriter struct{}

func (fixtureFailWriter) Write([]byte) (int, error) { return 0, errFixtureJournal }

func TestJournalFailurePreventsUDPResponse(t *testing.T) {
	t.Run("témoin fonctionnel", func(t *testing.T) {
		harness := startLiveHarness(t, nil)
		client := dialLiveUDP(t, harness)
		exchangeLiveUDP(t, client, fixtureQuery(t, 0x1501, "www.example.com", 1))
	})
	t.Run("écriture en panne", func(t *testing.T) {
		harness := startLiveHarness(t, func(cfg *dnslive.Config) {
			cfg.EventWriter = fixtureFailWriter{}
		})
		harness.allowCloseError = true
		client := dialLiveUDP(t, harness)
		query := fixtureQuery(t, 0x1502, "www.example.com", 1)
		if _, err := client.Write(query); err != nil {
			t.Fatalf("écriture UDP: %v", err)
		}
		if err := client.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			t.Fatalf("échéance UDP: %v", err)
		}
		storage := make([]byte, 512)
		n, err := client.Read(storage)
		if err == nil {
			t.Fatalf("réponse de %d octets envoyée malgré la panne de journal: %x", n, storage[:n])
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("lecture UDP: err=%v, attendu expiration faute de réponse", err)
		}
	})
}

func TestGracefulShutdownLeavesNoGoroutine(t *testing.T) {
	baseline := runtime.NumGoroutine()
	harness := startLiveHarness(t, nil)
	client := dialLiveUDP(t, harness)
	registerLiveRun(t, harness, "run-shutdown", "legit_a", client.LocalAddr().(*net.UDPAddr))
	exchangeLiveUDP(t, client, fixtureQuery(t, 0x1601, "chunk1a00abcdef0123456789.chunk2b00abcdef0123456789abcdef.m01-volumetric.org", 16))
	_ = client.Close()
	if err := harness.close(); err != nil {
		t.Fatalf("fermeture: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, harness.httpBase+"/healthz", nil)
	if err != nil {
		t.Fatalf("requête post-fermeture: %v", err)
	}
	if resp, err := harness.client.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Fatalf("healthz encore accessible après Service.Close: %s", resp.Status)
	}

	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > baseline && time.Now().Before(deadline) {
		ticker := time.NewTicker(10 * time.Millisecond)
		select {
		case <-t.Context().Done():
			ticker.Stop()
			t.Fatalf("contexte de test terminé en attendant les goroutines: %v", t.Context().Err())
		case <-ticker.C:
		}
		ticker.Stop()
	}
	if got := runtime.NumGoroutine(); got > baseline {
		stack := make([]byte, 1<<20)
		n := runtime.Stack(stack, true)
		t.Fatalf("goroutines résiduelles: avant=%d après=%d\n%s", baseline, got, stack[:n])
	}
}

const p3CadenceTolerance = 3 * time.Millisecond

func countP3Detections(events []liveEvent) int {
	detections := 0
	for _, event := range events {
		if event.Class == "P3" && event.ReasonCode == engine.ReasonP3BeaconMarkov {
			detections++
		}
	}
	return detections
}

// Le scénario régulier est cadencé à 100 QPS : les neuf intervalles
// inter-requêtes sont donc tous proches de 10 ms. Chaque instant d'émission
// réel est noté pour mesurer l'écart entre l'intervalle tenu et le pas voulu.
func emitLiveBeaconScenario(t *testing.T, client *net.UDPConn, qtypes []uint16, pas func(i int) time.Duration) []time.Time {
	t.Helper()
	emissions := make([]time.Time, 0, len(qtypes))
	nextStep := time.Now()
	for i, qtype := range qtypes {
		if i > 0 {
			delay := 10 * time.Millisecond
			if pas != nil {
				delay = pas(i)
			}
			nextStep = nextStep.Add(delay)
			select {
			case <-t.Context().Done():
				t.Fatalf("attente du pas de cadence: %v", t.Context().Err())
			case <-time.After(time.Until(nextStep)):
			}
		}
		query := fixtureQuery(t, uint16(0x1700+i), "rotate.beacon.example", qtype)
		emissions = append(emissions, time.Now())
		exchangeLiveUDP(t, client, query)
	}
	return emissions
}

func largestP3IntervalDeviation(emissions []time.Time, pas func(i int) time.Duration) time.Duration {
	wantedInterval := 10 * time.Millisecond
	worst := time.Duration(0)
	for i := range len(emissions) - 1 {
		wanted := wantedInterval
		if pas != nil {
			wanted = pas(i + 1)
		}
		held := emissions[i+1].Sub(emissions[i])
		worst = max(worst, max(held-wanted, wanted-held))
	}
	return worst
}

func TestLiveP3BeaconMarkovAt100QPS(t *testing.T) {
	scenarios := []struct {
		name   string
		runID  string
		qtypes []uint16
		wantP3 bool
		pas    func(i int) time.Duration
	}{
		{
			name:   "rotation A CNAME AAAA TXT MX NS",
			runID:  "run-p3-beacon-markov",
			qtypes: []uint16{1, 5, 28, 16, 15, 2, 1, 5, 28, 16},
			wantP3: true,
		},
		{
			name:   "témoin négatif à QTYPE constant",
			runID:  "run-p3-beacon-negative",
			qtypes: []uint16{1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			wantP3: false,
		},
		{
			// Les intervalles adjacents alternent 10/30 ms (CV ≈ 0,5, hors
			// seuil) alors que les différences à deux positions seraient
			// parfaitement régulières à 40 ms : seul un calcul sur
			// événements consécutifs doit refuser la détection.
			name:   "témoin négatif à cadence régulière par sauts",
			runID:  "run-p3-skip-regular",
			qtypes: []uint16{1, 5, 28, 16, 15, 2, 1, 5, 28, 16},
			wantP3: false,
			pas: func(i int) time.Duration {
				if i%2 == 0 {
					return 10 * time.Millisecond
				}
				return 30 * time.Millisecond
			},
		},
	}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			if scenario.wantP3 {
				const maxAttempts = 8
				detected := false
				for attempt := 1; attempt <= maxAttempts && !detected; attempt++ {
					harness := startLiveHarness(t, nil)
					client := dialLiveUDP(t, harness)
					runID := fmt.Sprintf("%s-%d", scenario.runID, attempt)
					registerLiveRun(t, harness, runID, "P3", client.LocalAddr().(*net.UDPAddr))
					emissions := emitLiveBeaconScenario(t, client, scenario.qtypes, scenario.pas)
					events := fetchLiveEvents(t, harness, runID, 0)
					if len(events) != 2*len(scenario.qtypes) {
						t.Fatalf("tentative %d: événements live = %d, attendu %d questions et réponses", attempt, len(events), 2*len(scenario.qtypes))
					}
					if countP3Detections(events) > 0 {
						detected = true
						break
					}
					deviation := largestP3IntervalDeviation(emissions, scenario.pas)
					if deviation <= p3CadenceTolerance {
						t.Fatalf("tentative %d: cadence tenue (plus grand écart %s ≤ %s) sans aucune détection P3", attempt, deviation, p3CadenceTolerance)
					}
					t.Logf("tentative %d: aucun P3 et cadence non tenue (plus grand écart %s), rejeu sur serveur neuf", attempt, deviation)
					_ = harness.close()
				}
				if !detected {
					t.Fatalf("cadence jamais tenue en %d tentatives : aucune détection P3 après dix requêtes régulières à 100 QPS par tentative", maxAttempts)
				}
				return
			}
			harness := startLiveHarness(t, nil)
			client := dialLiveUDP(t, harness)
			registerLiveRun(t, harness, scenario.runID, "P3", client.LocalAddr().(*net.UDPAddr))
			emitLiveBeaconScenario(t, client, scenario.qtypes, scenario.pas)
			events := fetchLiveEvents(t, harness, scenario.runID, 0)
			if len(events) != 2*len(scenario.qtypes) {
				t.Fatalf("événements live = %d, attendu %d questions et réponses", len(events), 2*len(scenario.qtypes))
			}
			if detections := countP3Detections(events); detections != 0 {
				t.Fatalf("témoin négatif %s: %d détections P3, attendu 0", scenario.runID, detections)
			}
		})
	}
}
