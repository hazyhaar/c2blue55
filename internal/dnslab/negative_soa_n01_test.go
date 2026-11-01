package dnslab_test

import (
	"encoding/binary"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

// Strate N-01 : réponses négatives avec SOA en section Authority (RFC 2308).
// Convention de laboratoire : une question en zone dont le premier label
// commence par « nx- » rend NXDOMAIN (RCode 3) avec un SOA en Authority
// lorsque zone.Negative vaut NegativeSOA (SOA constant) ou NegativeSOAStego
// (MNAME, RNAME et Serial dérivés de la question, Minimum = 1). En mode
// NegativeNone (valeur zéro), rien ne change par rapport à S-04.

type soaWire struct {
	ownerName string
	mname     string
	rname     string
	serial    uint32
	refresh   uint32
	retry     uint32
	expire    uint32
	minimum   uint32
	ttl       uint32
}

func n01Zone(t *testing.T, mode dnslab.NegativeMode) dnslab.Zone {
	t.Helper()
	zone, err := dnslab.NewZone("lab.pound2pound.fr", [4]byte{10, 55, 0, 1}, "canary", 300)
	if err != nil {
		t.Fatalf("NewZone: %v", err)
	}
	zone.Negative = mode
	zone.NegativeSeed = 0x5EED2026
	return zone
}

func n01Respond(t *testing.T, zone *dnslab.Zone, id uint16, qname string, qtype uint16) ([]byte, dnslab.Decision) {
	t.Helper()
	var q [512]byte
	n, err := dnslab.BuildQuery(id, []byte(qname), qtype, q[:])
	if err != nil {
		t.Fatalf("BuildQuery(%s): %v", qname, err)
	}
	var r [512]byte
	m, decision, err := dnslab.BuildResponse(q[:n], zone, r[:])
	if err != nil {
		t.Fatalf("BuildResponse(%s): %v", qname, err)
	}
	return r[:m], decision
}

// decodeName lit un nom filaire (pointeurs de compression admis, bornés à 8 sauts).
func decodeName(t *testing.T, msg []byte, off int) (string, int) {
	t.Helper()
	name := ""
	next := -1
	jumps := 0
	for {
		if off >= len(msg) {
			t.Fatalf("nom tronqué à %d", off)
		}
		b := int(msg[off])
		if b == 0 {
			off++
			break
		}
		if b&0xC0 == 0xC0 {
			if jumps++; jumps > 8 {
				t.Fatal("trop de sauts de compression")
			}
			ptr := int(binary.BigEndian.Uint16(msg[off:off+2]) & 0x3FFF)
			if next < 0 {
				next = off + 2
			}
			off = ptr
			continue
		}
		off++
		if name != "" {
			name += "."
		}
		name += string(msg[off : off+b])
		off += b
	}
	if next >= 0 {
		return name, next
	}
	return name, off
}

func parseNegative(t *testing.T, resp []byte) (rcode uint8, ancount, nscount uint16, soa soaWire) {
	t.Helper()
	if len(resp) < 12 {
		t.Fatalf("réponse de %d octets", len(resp))
	}
	if resp[2]&0x80 == 0 {
		t.Fatal("QR=0 dans une réponse")
	}
	rcode = resp[3] & 0x0F
	qd := binary.BigEndian.Uint16(resp[4:6])
	ancount = binary.BigEndian.Uint16(resp[6:8])
	nscount = binary.BigEndian.Uint16(resp[8:10])
	off := 12
	for range qd {
		_, off = decodeName(t, resp, off)
		off += 4
	}
	if nscount == 0 {
		return
	}
	soa.ownerName, off = decodeName(t, resp, off)
	rrType := binary.BigEndian.Uint16(resp[off : off+2])
	if rrType != 6 {
		t.Fatalf("premier RR d'Authority de type %d, attendu 6 (SOA)", rrType)
	}
	soa.ttl = binary.BigEndian.Uint32(resp[off+4 : off+8])
	rdlen := int(binary.BigEndian.Uint16(resp[off+8 : off+10]))
	off += 10
	rdEnd := off + rdlen
	soa.mname, off = decodeName(t, resp, off)
	soa.rname, off = decodeName(t, resp, off)
	if rdEnd-off != 20 {
		t.Fatalf("RDATA SOA : %d octets après les noms, attendu 20", rdEnd-off)
	}
	soa.serial = binary.BigEndian.Uint32(resp[off : off+4])
	soa.refresh = binary.BigEndian.Uint32(resp[off+4 : off+8])
	soa.retry = binary.BigEndian.Uint32(resp[off+8 : off+12])
	soa.expire = binary.BigEndian.Uint32(resp[off+12 : off+16])
	soa.minimum = binary.BigEndian.Uint32(resp[off+16 : off+20])
	return
}

func TestNegativeSOA_ConstantAcrossNames(t *testing.T) {
	zone := n01Zone(t, dnslab.NegativeSOA)
	respA, decA := n01Respond(t, &zone, 0x1001, "nx-alpha.lab.pound2pound.fr", 1)
	respB, decB := n01Respond(t, &zone, 0x1002, "nx-beta.lab.pound2pound.fr", 16)
	for _, d := range []dnslab.Decision{decA, decB} {
		if d.Verdict != dnslab.VerdictNXDomain || d.RCode != 3 {
			t.Errorf("verdict = %v rcode = %d, attendu VerdictNXDomain / 3", d.Verdict, d.RCode)
		}
	}
	rc, an, ns, soaA := parseNegative(t, respA)
	if rc != 3 || an != 0 || ns != 1 {
		t.Errorf("A : rcode=%d ancount=%d nscount=%d, attendu 3/0/1", rc, an, ns)
	}
	_, _, _, soaB := parseNegative(t, respB)
	if soaA.ownerName != "lab.pound2pound.fr" {
		t.Errorf("propriétaire du SOA = %q, attendu l'apex", soaA.ownerName)
	}
	if soaA.mname != "ns1.lab.pound2pound.fr" || soaA.rname != "hostmaster.lab.pound2pound.fr" {
		t.Errorf("MNAME/RNAME = %q / %q", soaA.mname, soaA.rname)
	}
	if soaA != soaB {
		t.Errorf("SOA constant attendu entre deux noms : %+v vs %+v", soaA, soaB)
	}
	if soaA.minimum != 300 || soaA.ttl != 300 {
		t.Errorf("Minimum/TTL = %d/%d, attendu 300/300", soaA.minimum, soaA.ttl)
	}
}

func TestNegativeSOA_StegoVariesPerQuestion(t *testing.T) {
	zone := n01Zone(t, dnslab.NegativeSOAStego)
	_, _, _, soaA := parseNegative(t, mustResp(t, &zone, 0x2001, "nx-alpha.lab.pound2pound.fr"))
	_, _, _, soaB := parseNegative(t, mustResp(t, &zone, 0x2002, "nx-beta.lab.pound2pound.fr"))
	_, _, _, soaA2 := parseNegative(t, mustResp(t, &zone, 0x2003, "nx-alpha.lab.pound2pound.fr"))
	if soaA.serial == soaB.serial || soaA.mname == soaB.mname || soaA.rname == soaB.rname {
		t.Errorf("stego : SOA identique entre deux noms : %+v vs %+v", soaA, soaB)
	}
	if soaA != soaA2 {
		t.Errorf("stego : même nom doit rendre le même SOA (déterminisme par graine et nom) : %+v vs %+v", soaA, soaA2)
	}
	if soaA.minimum != 1 || soaA.ttl != 1 {
		t.Errorf("stego : Minimum/TTL = %d/%d, attendu 1/1", soaA.minimum, soaA.ttl)
	}
	for _, s := range []soaWire{soaA, soaB} {
		if s.ownerName != "lab.pound2pound.fr" {
			t.Errorf("propriétaire = %q", s.ownerName)
		}
		if len(s.mname) <= len(".lab.pound2pound.fr") || s.mname[len(s.mname)-len("lab.pound2pound.fr"):] != "lab.pound2pound.fr" {
			t.Errorf("MNAME hors zone : %q", s.mname)
		}
	}
	other := n01Zone(t, dnslab.NegativeSOAStego)
	other.NegativeSeed = 0x0BAD
	_, _, _, soaC := parseNegative(t, mustResp(t, &other, 0x2001, "nx-alpha.lab.pound2pound.fr"))
	if soaC.serial == soaA.serial {
		t.Errorf("stego : la graine doit changer le SOA (%d == %d)", soaC.serial, soaA.serial)
	}
}

func mustResp(t *testing.T, zone *dnslab.Zone, id uint16, qname string) []byte {
	t.Helper()
	resp, dec := n01Respond(t, zone, id, qname, 1)
	if dec.Verdict != dnslab.VerdictNXDomain {
		t.Fatalf("%s : verdict %v, attendu VerdictNXDomain", qname, dec.Verdict)
	}
	return resp
}

func TestNegativeSOA_NoneAndOrdinaryNamesUnchanged(t *testing.T) {
	none := n01Zone(t, dnslab.NegativeNone)
	resp, dec := n01Respond(t, &none, 0x3001, "nx-alpha.lab.pound2pound.fr", 1)
	rc, an, ns, _ := parseNegative(t, resp)
	if dec.Verdict != dnslab.VerdictAnswerA || rc != 0 || an != 1 || ns != 0 {
		t.Errorf("mode None : verdict=%v rcode=%d an=%d ns=%d, attendu AnswerA/0/1/0", dec.Verdict, rc, an, ns)
	}
	for _, mode := range []dnslab.NegativeMode{dnslab.NegativeSOA, dnslab.NegativeSOAStego} {
		zone := n01Zone(t, mode)
		resp, dec := n01Respond(t, &zone, 0x3002, "cdn.lab.pound2pound.fr", 1)
		rc, an, ns, _ := parseNegative(t, resp)
		if dec.Verdict != dnslab.VerdictAnswerA || rc != 0 || an != 1 || ns != 0 {
			t.Errorf("mode %d, nom ordinaire : verdict=%v rcode=%d an=%d ns=%d", mode, dec.Verdict, rc, an, ns)
		}
		_, dec = n01Respond(t, &zone, 0x3003, "nx-alpha.ailleurs.example", 1)
		if dec.Verdict != dnslab.VerdictRefused {
			t.Errorf("mode %d, hors zone : verdict=%v, attendu Refused", mode, dec.Verdict)
		}
	}
}

func TestNegativeSOA_ZeroAlloc(t *testing.T) {
	zone := n01Zone(t, dnslab.NegativeSOAStego)
	var q [512]byte
	n, err := dnslab.BuildQuery(0x4001, []byte("nx-alpha.lab.pound2pound.fr"), 1, q[:])
	if err != nil {
		t.Fatal(err)
	}
	var r [512]byte
	allocs := testing.AllocsPerRun(200, func() {
		if _, _, err := dnslab.BuildResponse(q[:n], &zone, r[:]); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Errorf("BuildResponse en mode stego : %.2f allocs/op, attendu 0", allocs)
	}
}
