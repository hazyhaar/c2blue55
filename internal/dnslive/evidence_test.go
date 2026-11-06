package dnslive_test

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55"
)

type evidenceRetention struct {
	Policy           string `json:"policy"`
	MaxPacketBytes   int    `json:"max_packet_bytes"`
	TruncatedPackets uint64 `json:"truncated_packets"`
	DroppedPackets   uint64 `json:"dropped_packets"`
}

type evidenceFiles struct {
	JSONL string `json:"jsonl"`
	PCAP  string `json:"pcap"`
}

type evidenceManifest struct {
	RunID       string            `json:"run_id"`
	Emitter     string            `json:"emitter"`
	CaptureMode string            `json:"capture_mode"`
	Retention   evidenceRetention `json:"retention"`
	Files       evidenceFiles     `json:"files"`
}

type storedLiveEvent struct {
	liveEvent
	Emitter     string `json:"emitter"`
	CaptureMode string `json:"capture_mode"`
}

func evidenceFilePath(t *testing.T, directory, name string) string {
	t.Helper()
	if name == "" || name == "." || filepath.IsAbs(name) || filepath.Base(name) != name || strings.Contains(name, "..") {
		t.Fatalf("nom de preuve non sûr %q", name)
	}
	return filepath.Join(directory, name)
}

func parsePCAPRecords(t *testing.T, payload []byte) [][]byte {
	t.Helper()
	if len(payload) < 24 {
		t.Fatalf("PCAP de %d octets, en-tête global incomplet", len(payload))
	}
	var order binary.ByteOrder
	switch magic := binary.BigEndian.Uint32(payload[:4]); magic {
	case 0xa1b2c3d4, 0xa1b23c4d:
		order = binary.BigEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		order = binary.LittleEndian
	default:
		t.Fatalf("magic PCAP inconnu %#x", magic)
	}
	if major := order.Uint16(payload[4:6]); major != 2 {
		t.Fatalf("version PCAP majeure %d, attendu 2", major)
	}
	records := make([][]byte, 0, 2)
	for cursor := 24; cursor < len(payload); {
		if len(payload)-cursor < 16 {
			t.Fatalf("PCAP: %d octets de queue dans l'en-tête d'enregistrement", len(payload)-cursor)
		}
		included := int(order.Uint32(payload[cursor+8 : cursor+12]))
		original := int(order.Uint32(payload[cursor+12 : cursor+16]))
		if included < 0 || original < included {
			t.Fatalf("PCAP: longueurs incl=%d orig=%d incohérentes", included, original)
		}
		cursor += 16
		if included > len(payload)-cursor {
			t.Fatalf("PCAP: enregistrement tronqué, %d octets annoncés et %d disponibles", included, len(payload)-cursor)
		}
		records = append(records, bytes.Clone(payload[cursor:cursor+included]))
		cursor += included
	}
	return records
}

func TestMalformedPacketAndSmallCampaignEvidenceAreIntegral(t *testing.T) {
	harness := startLiveHarness(t, nil)
	client := dialLiveUDP(t, harness)
	clientAddr := client.LocalAddr().(*net.UDPAddr)
	const runID = "run-malformed-evidence"
	registerLiveRun(t, harness, runID, "BENIGN_EDNS0_STD", clientAddr)

	malformed := []byte{
		0xde, 0xad, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		63, 'a', 'b', 'c', 0x00, 0x01, 0x00, 0x01, 0xf0, 0x0f, 0x55, 0xaa,
	}
	if _, err := client.Write(malformed); err != nil {
		t.Fatalf("envoi malformé: %v", err)
	}

	// Une réponse FORMERR est admise, mais seule la conservation et le verdict
	// fail-closed de la question sont imposés par cette épreuve.
	if err := client.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("échéance malformée: %v", err)
	}
	responseBuffer := make([]byte, 512)
	if n, err := client.Read(responseBuffer); err == nil {
		if n < 2 || responseBuffer[0] != malformed[0] || responseBuffer[1] != malformed[1] {
			t.Fatalf("réponse au paquet malformé sans TXID correspondant: %x", responseBuffer[:n])
		}
	} else {
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			t.Fatalf("lecture après paquet malformé: %v", err)
		}
	}

	var events []liveEvent
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		events = fetchLiveEvents(t, harness, runID, 0)
		if len(events) > 0 {
			break
		}
		ticker := time.NewTicker(10 * time.Millisecond)
		select {
		case <-t.Context().Done():
			ticker.Stop()
			t.Fatalf("attente de l'événement malformé: %v", t.Context().Err())
		case <-ticker.C:
		}
		ticker.Stop()
	}
	if len(events) == 0 {
		t.Fatal("paquet malformé absent du journal")
	}
	queryEvent := events[0]
	sha, encoded := fixturePacketFields(malformed)
	if queryEvent.RunID != runID || queryEvent.Kind != "BENIGN_EDNS0_STD" || queryEvent.Direction != fixtureQueryDirection ||
		queryEvent.Class != "PARSE_ERR" || queryEvent.ReasonCode != c2blue55.ReasonDNSParseError ||
		queryEvent.Decision != c2blue55.DecisionEscalateSLM || queryEvent.ParseError == "" ||
		queryEvent.PacketSHA256 != sha || queryEvent.PacketBase64 != encoded || queryEvent.TxID != 0xdead ||
		queryEvent.SrcIP != clientAddr.IP.String() || queryEvent.SrcPort != uint16(clientAddr.Port) ||
		queryEvent.DstIP != "127.0.0.1" || queryEvent.DstPort != uint16(harness.udpAddr.Port) {
		t.Fatalf("événement malformé incomplet: %+v", queryEvent)
	}
	if queryEvent.QName != "" || queryEvent.QType != 0 || queryEvent.SubdomainLen != 0 || queryEvent.LabelCount != 0 || queryEvent.MaxLabelLen != 0 || queryEvent.AnswerCount != 0 || queryEvent.RDataBytes != 0 {
		t.Fatalf("faits inventés sur une question indécodable: %+v", queryEvent)
	}

	// Après la lecture UDP bornée, la fin de run force la persistance et la
	// fermeture des deux preuves avant leur comparaison avec l'API.
	finishLiveRun(t, harness, runID)
	events = fetchLiveEvents(t, harness, runID, 0)
	status, _, payload := harness.request(t, http.MethodGet, "/api/v1/evidence/"+runID, nil, fixtureBearerAuth, fixtureDashboardToken)
	fixtureExpectStatus(t, status, http.StatusOK)
	var manifest evidenceManifest
	if err := json.Unmarshal(payload, &manifest); err != nil {
		t.Fatalf("evidence JSON: %v (%s)", err, payload)
	}
	wantRetention := evidenceRetention{Policy: "retain-all", MaxPacketBytes: 0, TruncatedPackets: 0, DroppedPackets: 0}
	if manifest.RunID != runID || manifest.Emitter != "c2blue-dns-live" || manifest.CaptureMode != "udp-reconstructed" || manifest.Retention != wantRetention {
		t.Fatalf("manifeste de preuve = %+v, attendu émetteur explicite, UDP reconstitué et conservation intégrale", manifest)
	}

	jsonlBytes, err := os.ReadFile(evidenceFilePath(t, harness.evidenceDir, manifest.Files.JSONL))
	if err != nil {
		t.Fatalf("lecture JSONL: %v", err)
	}
	rows := bytes.Split(jsonlBytes, []byte{'\n'})
	if len(rows) > 0 && len(rows[len(rows)-1]) == 0 {
		rows = rows[:len(rows)-1]
	}
	if len(rows) != len(events) {
		t.Fatalf("JSONL: %d lignes pour %d événements API", len(rows), len(events))
	}
	for i, row := range rows {
		if len(row) == 0 {
			t.Fatalf("JSONL: ligne vide à l'indice %d", i)
		}
		var stored storedLiveEvent
		if err := json.Unmarshal(row, &stored); err != nil {
			t.Fatalf("JSONL ligne %d: %v", i+1, err)
		}
		if stored.Emitter != "c2blue-dns-live" || stored.CaptureMode != "udp-reconstructed" {
			t.Fatalf("JSONL ligne %d: emitter=%q capture_mode=%q", i+1, stored.Emitter, stored.CaptureMode)
		}
		if !reflect.DeepEqual(stored.liveEvent, events[i]) {
			t.Fatalf("JSONL ligne %d différente de l'API\nJSONL: %+v\nAPI: %+v", i+1, stored.liveEvent, events[i])
		}
	}

	pcapBytes, err := os.ReadFile(evidenceFilePath(t, harness.evidenceDir, manifest.Files.PCAP))
	if err != nil {
		t.Fatalf("lecture PCAP: %v", err)
	}
	records := parsePCAPRecords(t, pcapBytes)
	if len(records) != len(events) {
		t.Fatalf("PCAP: %d enregistrements pour %d événements, conservation incomplète", len(records), len(events))
	}
	for i, event := range events {
		packet, err := base64.StdEncoding.DecodeString(event.PacketBase64)
		if err != nil {
			t.Fatalf("événement %d base64: %v", i, err)
		}
		found := false
		for _, record := range records {
			if bytes.Contains(record, packet) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("paquet %d (%d octets) absent ou tronqué dans le PCAP reconstitué", i, len(packet))
		}
	}
	if !bytes.Contains(pcapBytes, malformed) {
		t.Fatalf("les %d octets malformés ne sont pas intégralement présents dans le PCAP", len(malformed))
	}
}
