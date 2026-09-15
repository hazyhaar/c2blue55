package c2blue55

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Historical name retained; all wire packets below are local fixtures, not captures.
func TestDNS_DecodeWireFormatAuthentic(t *testing.T) {
	// Local fixture 1: A question for "cloudtelemetry.sophosxl.com".
	// ID: 0x4a12, Flags: 0x0100 (Standard query), Questions: 1
	// Name: \x0ecloudtelemetry\x08sophosxl\x03com\x00, QType: 0x0001 (A), QClass: 0x0001 (IN)
	wireSophosHex := "4a1201000001000000000000" + // Header
		"0e636c6f756474656c656d65747279" + // 14 "cloudtelemetry"
		"08736f70686f73786c" + // 8 "sophosxl"
		"03636f6d00" + // 3 "com" + null
		"00010001" // Type A, Class IN

	wireSophos, err := hex.DecodeString(wireSophosHex)
	if err != nil {
		t.Fatalf("hex decode failed: %v", err)
	}

	var ev DNSEvent
	if err := ParseDNSQuery(wireSophos, &ev); err != nil {
		t.Fatalf("ParseDNSQuery failed: %v", err)
	}

	if ev.ID != 0x4a12 {
		t.Errorf("ID = 0x%x, attendu 0x4a12", ev.ID)
	}
	if ev.QType != TypeA {
		t.Errorf("QType = %d, attendu %d (TypeA)", ev.QType, TypeA)
	}
	if ev.FQDN() != "cloudtelemetry.sophosxl.com" {
		t.Errorf("FQDN = %q, attendu %q", ev.FQDN(), "cloudtelemetry.sophosxl.com")
	}
	if ev.Parent() != "sophosxl.com" {
		t.Errorf("Parent = %q, attendu %q", ev.Parent(), "sophosxl.com")
	}
	if ev.Sub() != "cloudtelemetry" {
		t.Errorf("Sub = %q, attendu %q", ev.Sub(), "cloudtelemetry")
	}

	// Local fixture 2: TXT question using a dnscat2-like name, without capture provenance.
	// FQDN: "c2.01636c69656e742d696e666f.tunnel.dnscat2.org"
	// ID: 0x9b3f, Flags: 0x0100, QType: 0x0010 (TXT), QClass: 0x0001 (IN)
	wireDnscatHex := "9b3f01000001000000000000" +
		"026332" + // 2 "c2"
		"18303136333663363936353665373432643639366536363666" + // 24 "01636c69656e742d696e666f"
		"0674756e6e656c" + // 6 "tunnel"
		"07646e7363617432" + // 7 "dnscat2"
		"036f726700" + // 3 "org" + null
		"00100001" // Type TXT, Class IN

	wireDnscat, err := hex.DecodeString(wireDnscatHex)
	if err != nil {
		t.Fatalf("hex decode dnscat failed: %v", err)
	}

	var evDnscat DNSEvent
	if err := ParseDNSQuery(wireDnscat, &evDnscat); err != nil {
		t.Fatalf("ParseDNSQuery dnscat failed: %v", err)
	}

	if evDnscat.QType != TypeTXT {
		t.Errorf("evDnscat.QType = %d, attendu %d (TypeTXT)", evDnscat.QType, TypeTXT)
	}
	if evDnscat.FQDN() != "c2.01636c69656e742d696e666f.tunnel.dnscat2.org" {
		t.Errorf("evDnscat FQDN = %q", evDnscat.FQDN())
	}
	if evDnscat.Parent() != "dnscat2.org" {
		t.Errorf("evDnscat Parent = %q, attendu dnscat2.org", evDnscat.Parent())
	}
	if evDnscat.Sub() != "c2.01636c69656e742d696e666f.tunnel" {
		t.Errorf("evDnscat Sub = %q, attendu c2.01636c69656e742d696e666f.tunnel", evDnscat.Sub())
	}

	// Local fixture 3: TXT question with a DKIM-shaped selector, not a returned key.
	// FQDN: "google._domainkey.example.com"
	wireDKIMHex := "112201000001000000000000" +
		"06676f6f676c65" + // 6 "google"
		"0a5f646f6d61696e6b6579" + // 10 "_domainkey"
		"076578616d706c65" + // 7 "example"
		"03636f6d00" + // 3 "com" + null
		"00100001" // Type TXT, Class IN

	wireDKIM, err := hex.DecodeString(wireDKIMHex)
	if err != nil {
		t.Fatalf("hex decode dkim failed: %v", err)
	}

	var evDKIM DNSEvent
	if err := ParseDNSQuery(wireDKIM, &evDKIM); err != nil {
		t.Fatalf("ParseDNSQuery dkim failed: %v", err)
	}
	if evDKIM.FQDN() != "google._domainkey.example.com" {
		t.Errorf("DKIM FQDN = %q", evDKIM.FQDN())
	}
	if evDKIM.Parent() != "example.com" {
		t.Errorf("DKIM Parent = %q, attendu example.com", evDKIM.Parent())
	}
	if evDKIM.Sub() != "google._domainkey" {
		t.Errorf("DKIM Sub = %q, attendu google._domainkey", evDKIM.Sub())
	}
}

// TestDNS_PointersAndCorruptFrames teste la robustesse contre les paquets corrompus et boucles de compression.
func TestDNS_PointersAndCorruptFrames(t *testing.T) {
	// Paquet trop court (< 12 octets)
	shortPkg := []byte{0x12, 0x34, 0x01, 0x00}
	var ev DNSEvent
	if err := ParseDNSQuery(shortPkg, &ev); err != ErrPacketTooShort {
		t.Errorf("attendu ErrPacketTooShort, obtenu: %v", err)
	}

	// Pointeur hors limites
	badPtr := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0xC0, 0xFF, // Pointeur vers offset 0x3FFF (hors paquet)
		0x00, 0x01, 0x00, 0x01,
	}
	if err := ParseDNSQuery(badPtr, &ev); err != ErrInvalidLabel {
		t.Errorf("attendu ErrInvalidLabel pour pointeur hors limites, obtenu: %v", err)
	}
}

// TestDNS_PointerLabelOver63Rejected est le test de non-régression de la borne RFC 1035
// sur les labels pointés. Un pointeur de compression qui désigne un label de longueur
// supérieure à 63 octets doit être rejeté sans lecture hors bornes ni panique.
func TestDNS_PointerLabelOver63Rejected(t *testing.T) {
	raw := make([]byte, 0, 96)
	// En-tête standard : ID 0x1234, requête récursive, une question.
	raw = append(raw, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// Pointeur de compression vers l'offset 18 (0x0012).
	raw = append(raw, 0xC0, 0x12)
	// QType / QClass de la question portée par le pointeur.
	raw = append(raw, 0x00, 0x01, 0x00, 0x01)
	// À l'offset 18 : longueur de label illégale (64 > 63) suivie de sa charge.
	raw = append(raw, 0x40)
	raw = append(raw, make([]byte, 64)...)

	var ev DNSEvent
	if err := ParseDNSQuery(raw, &ev); err != ErrInvalidLabel {
		t.Fatalf("attendu ErrInvalidLabel pour label pointé > 63, obtenu: %v", err)
	}

	// Troncature immédiate après le pointeur : aucune panique, erreur bornée.
	truncated := raw[:14]
	if err := ParseDNSQuery(truncated, &ev); err == nil {
		t.Fatalf("attendu une erreur sur trame tronquée, obtenu nil")
	}
}

// TestDNS_ZeroAllocation vérifie formellement que le décodage DNS RFC 1035 n'alloue aucun octet sur le tas.
func TestDNS_ZeroAllocation(t *testing.T) {
	wireSophosHex := "4a1201000001000000000000" +
		"0e636c6f756474656c656d65747279" +
		"08736f70686f73786c" +
		"03636f6d00" +
		"00010001"
	wireSophos, _ := hex.DecodeString(wireSophosHex)

	var ev DNSEvent
	allocs := testing.AllocsPerRun(1000, func() {
		if err := ParseDNSQuery(wireSophos, &ev); err != nil {
			t.Fatalf("ParseDNSQuery: %v", err)
		}
	})

	if allocs != 0 {
		t.Errorf("ParseDNSQuery AllocsPerRun = %.2f, attendu 0.0 (0 B/op)", allocs)
	}
}

// buildDNSQueryWire constructs a local DNS wire-format fixture, without compression:
// en-tête standard (ID 0x1234, requête récursive, une question), FQDN découpé en labels,
// puis QType et QClass IN. Protocol conformance does not establish provenance.
func buildDNSQueryWire(fqdn string, qtype uint16) []byte {
	labels := strings.Split(fqdn, ".")
	size := 12 + 1 + 4
	for _, l := range labels {
		size += 1 + len(l)
	}
	pkt := make([]byte, 0, size)
	pkt = append(pkt, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, l := range labels {
		pkt = append(pkt, byte(len(l)))
		pkt = append(pkt, l...)
	}
	pkt = append(pkt, 0x00)
	pkt = append(pkt, byte(qtype>>8), byte(qtype))
	pkt = append(pkt, 0x00, 0x01)
	return pkt
}

// TestDNS_ManyLabelsNoPanic est le test de non-régression de la faille DoS par index hors bornes.
// Un FQDN RFC 1035 de 18 à 25 labels doit être analysé sans panique et sans allocation tas.
// Avant correctif, totalLabelOffsets était borné à 16 entiers et l'accès à l'indice
// labelCount-2 paniquait dès 18 labels.
func TestDNS_ManyLabelsNoPanic(t *testing.T) {
	for n := 18; n <= 25; n++ {
		fqdn := strings.Repeat("a.", n-1) + "a"
		wire := buildDNSQueryWire(fqdn, TypeTXT)

		var ev DNSEvent
		if err := ParseDNSQuery(wire, &ev); err != nil {
			t.Fatalf("ParseDNSQuery(%d labels): %v", n, err)
		}
		if int(ev.LabelCount) != n {
			t.Errorf("LabelCount = %d, attendu %d", ev.LabelCount, n)
		}
		if ev.FQDN() != fqdn {
			t.Errorf("FQDN = %q, attendu %q", ev.FQDN(), fqdn)
		}
		if ev.Parent() != "a.a" {
			t.Errorf("Parent(%d labels) = %q, attendu a.a", n, ev.Parent())
		}
	}

	// Preuve formelle de zéro allocation sur le chemin à 25 labels.
	wire := buildDNSQueryWire(strings.Repeat("a.", 24)+"a", TypeTXT)
	var ev DNSEvent
	allocs := testing.AllocsPerRun(1000, func() {
		if err := ParseDNSQuery(wire, &ev); err != nil {
			t.Fatalf("ParseDNSQuery 25 labels: %v", err)
		}
	})
	if allocs != 0 {
		t.Errorf("ParseDNSQuery 25 labels AllocsPerRun = %.2f, attendu 0.0 (0 B/op)", allocs)
	}
}

// TestDNS_MaxLabelsBoundary éprouve la borne haute du tableau de positions (127 labels,
// maximum RFC 1035 d'un nom encodé sur 255 octets) : aucun débordement d'indice ni panique.
func TestDNS_MaxLabelsBoundary(t *testing.T) {
	const n = 127
	fqdn := strings.Repeat("a.", n-1) + "a"
	wire := buildDNSQueryWire(fqdn, TypeTXT)
	if len(wire) != 12+255+4 {
		t.Fatalf("encodage wire = %d octets, attendu %d (nom RFC 1035 sur 255 octets)", len(wire), 12+255+4)
	}

	var ev DNSEvent
	if err := ParseDNSQuery(wire, &ev); err != nil {
		t.Fatalf("ParseDNSQuery(127 labels): %v", err)
	}
	if int(ev.LabelCount) != n {
		t.Errorf("LabelCount = %d, attendu %d", ev.LabelCount, n)
	}
	if ev.FQDN() != fqdn {
		t.Errorf("FQDN(127 labels) tronqué ou erroné (len=%d)", ev.NameLen)
	}
}
