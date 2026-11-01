package c2blue55_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	c2 "github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

func benchNewObserver(t *testing.T, ports []uint16) *c2.BenchObserver {
	t.Helper()
	observer, err := c2.NewBenchObserver(ports)
	if err != nil {
		t.Fatal(err)
	}
	if observer == nil {
		t.Fatal("observateur nil sans erreur")
	}
	t.Cleanup(func() {
		if err := observer.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return observer
}

func benchObserve(t *testing.T, observer *c2.BenchObserver, packet c2.BenchPacket) c2.BenchObservation {
	t.Helper()
	got, err := observer.ObservePacket(packet)
	if err != nil {
		t.Fatalf("ObservePacket: %v", err)
	}
	digest := sha256.Sum256(packet.Frame)
	if got.TimestampNs != packet.TimestampNs || got.PacketSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("identité de trame inexacte: %+v", got)
	}
	return got
}

func benchIP(t *testing.T, packet c2.BenchPacket) []byte {
	t.Helper()
	frame := packet.Frame
	offset := 0
	switch packet.LinkType {
	case 1:
		offset = 14
	case 101:
	case 113:
		offset = 16
	case 276:
		offset = 20
	default:
		t.Fatalf("lien de référence inconnu: %d", packet.LinkType)
	}
	if len(frame) <= offset {
		t.Fatal("trame réelle sans IP")
	}
	return frame[offset:]
}

func benchAddr(t *testing.T, text string) netip.Addr {
	t.Helper()
	address, err := netip.ParseAddr(text)
	if err != nil {
		t.Fatalf("adresse %q: %v", text, err)
	}
	return address.Unmap()
}

func benchReferenceReasons(t *testing.T, packets []c2.BenchPacket) [][]string {
	t.Helper()
	pipeline, err := c2.NewPipeline(c2.PipelineConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pipeline.Close(); err != nil {
			t.Errorf("pipeline Close: %v", err)
		}
	}()
	var soa engine.SOANegativeTracker
	var aaaa engine.AAAAIIDTracker
	var icmp engine.ICMPEchoParityTracker
	expected := make([][]string, len(packets))
	for index, packet := range packets {
		ip := benchIP(t, packet)
		add := func(reason string) {
			if reason != "" && reason != engine.ReasonNone && !slices.Contains(expected[index], reason) {
				expected[index] = append(expected[index], reason)
			}
		}
		var source, destination [16]byte
		var segment []byte
		var transport byte
		switch ip[0] >> 4 {
		case 4:
			if len(ip) < 20 {
				t.Fatal("référence IPv4 tronquée")
			}
			header, total := int(ip[0]&15)*4, int(binary.BigEndian.Uint16(ip[2:]))
			if header < 20 || total < header || total > len(ip) || binary.BigEndian.Uint16(ip[6:])&0x3fff != 0 {
				t.Fatal("référence IPv4 non admissible")
			}
			if ip[9] == 1 {
				_, reason := icmp.ObserveIPv4(int64(packet.TimestampNs), ip[:total])
				add(reason)
				continue
			}
			source[10], source[11], destination[10], destination[11] = 0xff, 0xff, 0xff, 0xff
			copy(source[12:], ip[12:16])
			copy(destination[12:], ip[16:20])
			transport, segment = ip[9], ip[header:total]
		case 6:
			if len(ip) < 40 {
				t.Fatal("référence IPv6 tronquée")
			}
			total := 40 + int(binary.BigEndian.Uint16(ip[4:]))
			if total > len(ip) {
				t.Fatal("référence IPv6 incomplète")
			}
			copy(source[:], ip[8:24])
			copy(destination[:], ip[24:40])
			transport, segment = ip[6], ip[40:total]
		default:
			t.Fatalf("version IP de référence %x", ip[0])
		}
		if transport != 17 {
			continue
		}
		if len(segment) < 8 {
			t.Fatal("référence UDP tronquée")
		}
		sport, dport := binary.BigEndian.Uint16(segment), binary.BigEndian.Uint16(segment[2:])
		if sport != 53 && sport != 5335 && dport != 53 && dport != 5335 {
			continue
		}
		length := int(binary.BigEndian.Uint16(segment[4:]))
		if length < 8 || length > len(segment) {
			t.Fatal("référence UDP non admissible")
		}
		wire := segment[8:length]
		_, _, reason, err := pipeline.EvaluateDNSMessageWithReason(wire, int64(packet.TimestampNs), source, destination)
		if err != nil {
			t.Fatalf("catalogue existant, paquet %d: %v", index+1, err)
		}
		add(reason)
		_, reason = soa.ObserveResponse(int64(packet.TimestampNs), destination, wire)
		add(reason)
		_, reason = aaaa.ObserveResponse(int64(packet.TimestampNs), destination, wire)
		add(reason)
	}
	return expected
}

func benchCheckEnvelope(t *testing.T, packet c2.BenchPacket, got c2.BenchObservation) {
	t.Helper()
	ip := benchIP(t, packet)
	var source, destination netip.Addr
	var transport byte
	var header int
	if ip[0]>>4 == 4 {
		source = netip.AddrFrom4([4]byte(ip[12:16]))
		destination = netip.AddrFrom4([4]byte(ip[16:20]))
		header, transport = int(ip[0]&15)*4, ip[9]
	} else {
		source = netip.AddrFrom16([16]byte(ip[8:24]))
		destination = netip.AddrFrom16([16]byte(ip[24:40]))
		header, transport = 40, ip[6]
	}
	if benchAddr(t, got.SrcIP) != source.Unmap() || benchAddr(t, got.DstIP) != destination.Unmap() {
		t.Fatalf("adresses: %+v, attendu %s → %s", got, source, destination)
	}
	if transport == 17 {
		if got.SrcPort != binary.BigEndian.Uint16(ip[header:]) || got.DstPort != binary.BigEndian.Uint16(ip[header+2:]) || !strings.EqualFold(got.Protocol, "dns") || got.Status != "observed" {
			t.Fatalf("enveloppe DNS: %+v", got)
		}
	} else if transport == 1 {
		if got.SrcPort != 0 || got.DstPort != 0 || !strings.EqualFold(got.Protocol, "icmp") || got.Status != "observed" {
			t.Fatalf("enveloppe ICMP: %+v", got)
		}
	}
}

func TestBancAObserver_RealCapturesAgainstExistingEngines(t *testing.T) {
	for _, path := range benchRealCaptures(t) {
		t.Run(path, func(t *testing.T) {
			_, packets := benchOraclePCAP(t, path)
			expected := benchReferenceReasons(t, packets)
			// Étalonnage référence contre référence sur la capture intégrale.
			again := benchReferenceReasons(t, packets)
			if len(again) != len(expected) {
				t.Fatal("dénominateur référence instable")
			}
			observer := benchNewObserver(t, []uint16{53, 5335})
			observations := make([]c2.BenchObservation, 0, len(packets))
			for index, packet := range packets {
				if !slices.Equal(expected[index], again[index]) {
					t.Fatalf("référence instable au paquet %d", index+1)
				}
				got := benchObserve(t, observer, packet)
				benchCheckEnvelope(t, packet, got)
				if !slices.Equal(got.Reasons, expected[index]) {
					t.Fatalf("paquet %d: raisons=%q, référence=%q", index+1, got.Reasons, expected[index])
				}
				observations = append(observations, got)
			}
			benchCheckExistingEvaluator(t, path, observations)
		})
	}
}

func benchCheckExistingEvaluator(t *testing.T, path string, observations []c2.BenchObservation) {
	t.Helper()
	var wantedFires uint32
	var wantedFirst uint64
	var reasons []string
	var suffix string
	switch {
	case strings.Contains(path, "n04-"):
		report, err := c2.EvaluateSOANegativePCAP(path)
		if err != nil {
			t.Fatal(err)
		}
		wantedFires, wantedFirst = report.Fires, report.FirstFireTsNs
		reasons, suffix = []string{engine.ReasonP20SOANegDownlink}, ".soa-eval.json"
	case strings.Contains(path, "a04-"):
		if strings.Contains(path, ".client-leg-") {
			// L'ancien évaluateur ne traite que UDP/53; le port 5335 est
			// opposé paquet par paquet par le comparateur précédent.
			return
		}
		report, err := c2.EvaluateAAAAIIDPCAP(path)
		if err != nil {
			t.Fatal(err)
		}
		wantedFires, wantedFirst = report.Fires, report.FirstFireTsNs
		reasons, suffix = []string{engine.ReasonP21AAAAIIDDownlink}, ".aaaa-eval.json"
	default:
		report, err := c2.EvaluateICMPEchoPCAP(path)
		if err != nil {
			t.Fatal(err)
		}
		wantedFires, wantedFirst = report.Fires, report.FirstFireTsNs
		reasons, suffix = []string{engine.ReasonIC01ICMPEchoAsymmetry, engine.ReasonIC02ICMPEchoUnsolicited}, ".icmp-eval.json"
	}
	// La pièce historique est consultée seulement ici, jamais par le moteur.
	content, err := os.ReadFile(strings.TrimSuffix(path, ".pcap") + suffix)
	if err != nil {
		t.Fatal(err)
	}
	var frozen struct {
		SHA256 string `json:"sha256"`
		Fires  uint32 `json:"fires"`
		First  uint64 `json:"first_fire_ts_ns"`
	}
	if err := json.Unmarshal(content, &frozen); err != nil {
		t.Fatal(err)
	}
	pcap, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(pcap)
	if frozen.SHA256 != hex.EncodeToString(digest[:]) || frozen.Fires != wantedFires || frozen.First != wantedFirst {
		t.Fatalf("référence existante différente de sa pièce scellée: %+v, feux=%d premier=%d", frozen, wantedFires, wantedFirst)
	}
	var fires uint32
	var first uint64
	for _, observation := range observations {
		for _, reason := range reasons {
			if slices.Contains(observation.Reasons, reason) {
				fires++
				if first == 0 {
					first = observation.TimestampNs
				}
			}
		}
	}
	if fires != wantedFires || first != wantedFirst {
		t.Fatalf("feux=%d premier=%d, évaluateur existant=%d/%d", fires, first, wantedFires, wantedFirst)
	}
}

func TestBancAObserver_InstancesOwnTheirState(t *testing.T) {
	for _, path := range []string{
		"testdata/n04-20261029/n04-runA-stego-v2.pcap",
		"testdata/a04-20261029/a04-runA-aaaa.pcap",
		"testdata/i03-20261029/i03-runA.pcap",
	} {
		t.Run(filepath.Base(path), func(t *testing.T) {
			_, packets := benchOraclePCAP(t, path)
			expected := benchReferenceReasons(t, packets)
			warm := benchNewObserver(t, []uint16{53, 5335})
			firstFire := -1
			specialized := engine.ReasonP20SOANegDownlink
			if strings.Contains(path, "a04-") {
				specialized = engine.ReasonP21AAAAIIDDownlink
			}
			if strings.Contains(path, "i03-") {
				specialized = engine.ReasonIC01ICMPEchoAsymmetry
			}
			for index, packet := range packets {
				benchObserve(t, warm, packet)
				if firstFire < 0 && slices.Contains(expected[index], specialized) {
					firstFire = index
				}
			}
			if firstFire < 0 {
				t.Fatal("capture sans témoin positif")
			}
			cold := benchNewObserver(t, []uint16{53, 5335})
			standalone := benchReferenceReasons(t, packets[firstFire:firstFire+1])[0]
			got := benchObserve(t, cold, packets[firstFire])
			if !slices.Equal(got.Reasons, standalone) {
				t.Fatalf("état partagé: %q, instance neuve=%q", got.Reasons, standalone)
			}
			if slices.Equal(standalone, expected[firstFire]) {
				t.Fatal("témoin d'indépendance sans écart attendu")
			}
			fresh := benchNewObserver(t, []uint16{53, 5335})
			for index, packet := range packets {
				got := benchObserve(t, fresh, packet)
				if !slices.Equal(got.Reasons, expected[index]) {
					t.Fatalf("rejeu neuf contaminé au paquet %d", index+1)
				}
			}
		})
	}
}

// fixtureBenchEnvelope: emitter: generator;
// generator: bench_observer_banc_test.go:fixtureBenchEnvelope.
// Seule l'enveloppe change; les octets IP proviennent d'une capture versionnée.
func fixtureBenchEnvelope(ip []byte, link uint32) []byte {
	size := map[uint32]int{1: 14, 101: 0, 113: 16, 276: 20}[link]
	frame := make([]byte, size, size+len(ip))
	etherType := uint16(0x0800)
	if ip[0]>>4 == 6 {
		etherType = 0x86dd
	}
	switch link {
	case 1:
		binary.BigEndian.PutUint16(frame[12:], etherType)
	case 113:
		binary.BigEndian.PutUint16(frame[14:], etherType)
	case 276:
		binary.BigEndian.PutUint16(frame, etherType)
	}
	return append(frame, ip...)
}

func TestBancAObserver_LinksDNS5335AndCompleteDigest(t *testing.T) {
	_, packets := benchOraclePCAP(t, "testdata/a04-20261029/a04-benin-fw-aaaa.client-leg-redbo.pcap")
	configured := benchNewObserver(t, []uint16{53, 5335})
	unconfigured := benchNewObserver(t, []uint16{53})
	for _, packet := range packets {
		got := benchObserve(t, configured, packet)
		benchCheckEnvelope(t, packet, got)
		if got.SrcPort != 5335 && got.DstPort != 5335 {
			t.Fatal("pièce client sans port 5335")
		}
		without := benchObserve(t, unconfigured, packet)
		if without.Status != "non_target" || len(without.Reasons) != 0 {
			t.Fatalf("port non configuré: %+v", without)
		}
	}
	_, packets = benchOraclePCAP(t, "testdata/n04-20261029/n04-benin-soa-v2.pcap")
	ip := benchIP(t, packets[0])
	for _, link := range []uint32{1, 101, 113, 276} {
		fixture := c2.BenchPacket{TimestampNs: packets[0].TimestampNs, LinkType: link, Frame: fixtureBenchEnvelope(ip, link)}
		got := benchObserve(t, benchNewObserver(t, []uint16{53, 5335}), fixture)
		benchCheckEnvelope(t, fixture, got)
		// emitter: generator; generator: bench_observer_banc_test.go:TestBancAObserver_LinksDNS5335AndCompleteDigest.
		// Le bourrage d'enveloppe ne participe pas au DNS, mais participe au SHA.
		fixture.Frame = append(bytes.Clone(fixture.Frame), make([]byte, 4096)...)
		fixture.Frame[len(fixture.Frame)-1] = 0xa5
		padded := benchObserve(t, benchNewObserver(t, []uint16{53, 5335}), fixture)
		if padded.PacketSHA256 == got.PacketSHA256 || !slices.Equal(padded.Reasons, got.Reasons) {
			t.Fatal("digest partiel ou bourrage interprété comme DNS")
		}
		fixture.Frame[len(fixture.Frame)-1] ^= 1
		mutated := benchObserve(t, benchNewObserver(t, []uint16{53, 5335}), fixture)
		if mutated.PacketSHA256 == padded.PacketSHA256 {
			t.Fatal("dernier octet exclu du digest")
		}
	}
}

func TestBancAObserver_UnsupportedMalformedAndClock(t *testing.T) {
	_, packets := benchOraclePCAP(t, "testdata/n04-20261029/n04-benin-soa-v2.pcap")
	ip := benchIP(t, packets[0])
	if ip[0] != 0x45 || ip[9] != 17 {
		t.Fatal("la pièce de mutation doit être IPv4 UDP sans options")
	}
	// emitter: generator; generator: bench_observer_banc_test.go:TestBancAObserver_UnsupportedMalformedAndClock.
	// Les mutations fixture ci-dessous opposent le décodage, pas la détection.
	for _, name := range []string{"tcp", "mf", "fragment-offset", "ihl", "ip-short", "ip-total-low", "ip-total-high", "udp-short", "udp-low", "udp-high", "dns-short", "dns-pointer-loop", "ipv6-extension", "ipv6-length"} {
		t.Run(name, func(t *testing.T) {
			fixture := bytes.Clone(ip)
			status := "malformed"
			switch name {
			case "tcp":
				segment := make([]byte, 22, 22+len(ip)-28)
				copy(segment[:4], ip[20:24])
				segment[12], segment[13] = 0x50, 0x18
				binary.BigEndian.PutUint16(segment[20:], uint16(len(ip)-28))
				segment = append(segment, ip[28:]...)
				fixture = append(bytes.Clone(ip[:20]), segment...)
				fixture[9] = 6
				binary.BigEndian.PutUint16(fixture[2:], uint16(len(fixture)))
				status = "unsupported"
			case "mf":
				fixture[6] = 0x20
				status = "unsupported"
			case "fragment-offset":
				fixture[7] = 1
				status = "unsupported"
			case "ihl":
				fixture[0] = 0x44
			case "ip-short":
				fixture = fixture[:19]
			case "ip-total-low":
				binary.BigEndian.PutUint16(fixture[2:], 19)
			case "ip-total-high":
				binary.BigEndian.PutUint16(fixture[2:], uint16(len(fixture)+1))
			case "udp-short":
				fixture = fixture[:27]
				binary.BigEndian.PutUint16(fixture[2:], uint16(len(fixture)))
			case "udp-low":
				binary.BigEndian.PutUint16(fixture[24:], 7)
			case "udp-high":
				binary.BigEndian.PutUint16(fixture[24:], uint16(len(fixture)-19))
			case "dns-short":
				fixture = fixture[:39]
				binary.BigEndian.PutUint16(fixture[2:], 39)
				binary.BigEndian.PutUint16(fixture[24:], 19)
			case "dns-pointer-loop":
				fixture[40], fixture[41] = 0xc0, 0x0c
			case "ipv6-extension", "ipv6-length":
				fixture = make([]byte, 48)
				fixture[0], fixture[6] = 0x60, 0
				binary.BigEndian.PutUint16(fixture[4:], 8)
				status = "unsupported"
				if name == "ipv6-length" {
					binary.BigEndian.PutUint16(fixture[4:], 9)
					status = "malformed"
				}
			}
			packet := c2.BenchPacket{TimestampNs: packets[0].TimestampNs, LinkType: 101, Frame: fixture}
			got := benchObserve(t, benchNewObserver(t, []uint16{53, 5335}), packet)
			if got.Status != status {
				t.Fatalf("%s: état=%q, attendu %q", name, got.Status, status)
			}
			for _, reason := range got.Reasons {
				if strings.HasPrefix(reason, "REASON_P") || strings.HasPrefix(reason, "REASON_IC") {
					t.Fatalf("refus transformé en feu: %+v", got)
				}
			}
		})
	}
	observer := benchNewObserver(t, []uint16{53, 5335})
	packet := c2.BenchPacket{TimestampNs: math.MaxInt64, LinkType: 101, Frame: ip}
	if _, err := observer.ObservePacket(packet); err != nil {
		t.Fatalf("MaxInt64 admissible: %v", err)
	}
	packet.TimestampNs++
	if _, err := observer.ObservePacket(packet); err == nil {
		t.Fatal("horodatage supérieur à MaxInt64 accepté")
	}
	if _, err := c2.NewBenchObserver([]uint16{0}); err == nil {
		t.Fatal("port DNS nul accepté")
	}
}
