package dnslab_test

import (
	"encoding/binary"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

// Strate A-01 : réponses AAAA du serveur de laboratoire. Mode AAAANone
// (valeur zéro) : NODATA comme en S-04. Mode AAAAStatic : une adresse fixe
// zone.AnswerAAAA pour tout nom en zone. Mode AAAAIIDStego : préfixe fixe
// (8 premiers octets de zone.AnswerAAAA), identifiant d'interface (8 derniers
// octets) dérivé de (zone.AAAASeed, zone.AAAACounter, qname) et différent à
// chaque réponse ; zone.AAAACounter est incrémenté à chaque réponse stego.
// Même graine et même suite de questions ⇒ même suite d'adresses.

func a01Zone(t *testing.T, mode dnslab.AAAAMode, seed uint64) dnslab.Zone {
	t.Helper()
	zone, err := dnslab.NewZone("lab.pound2pound.fr", [4]byte{10, 55, 0, 1}, "canary", 0)
	if err != nil {
		t.Fatalf("NewZone: %v", err)
	}
	zone.AAAA = mode
	zone.AnswerAAAA = [16]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	zone.AAAASeed = seed
	return zone
}

// a01Answer lit l'unique enregistrement de réponse et rend (type, classe, ttl, rdata).
func a01Answer(t *testing.T, r []byte) (uint16, uint16, uint32, []byte) {
	t.Helper()
	if binary.BigEndian.Uint16(r[6:8]) != 1 {
		t.Fatalf("ANCOUNT = %d, attendu 1", binary.BigEndian.Uint16(r[6:8]))
	}
	_, off := decodeName(t, r, 12)
	off += 4
	_, off = decodeName(t, r, off)
	if off+10 > len(r) {
		t.Fatal("enregistrement tronqué")
	}
	typ := binary.BigEndian.Uint16(r[off : off+2])
	cls := binary.BigEndian.Uint16(r[off+2 : off+4])
	ttl := binary.BigEndian.Uint32(r[off+4 : off+8])
	rdlen := int(binary.BigEndian.Uint16(r[off+8 : off+10]))
	if off+10+rdlen != len(r) {
		t.Fatalf("RDLENGTH %d ne clôt pas la réponse (fin %d, longueur %d)", rdlen, off+10+rdlen, len(r))
	}
	return typ, cls, ttl, r[off+10 : off+10+rdlen]
}

func TestAAAAMode_NoneKeepsNoData(t *testing.T) {
	zone := a01Zone(t, dnslab.AAAANone, 1)
	r, d := n01Respond(t, &zone, 1, "www.lab.pound2pound.fr", 28)
	if d.Verdict != dnslab.VerdictNoData || d.RCode != 0 || binary.BigEndian.Uint16(r[6:8]) != 0 {
		t.Fatalf("mode none : verdict %v rcode %d ancount %d", d.Verdict, d.RCode, binary.BigEndian.Uint16(r[6:8]))
	}
}

func TestAAAAMode_StaticAnswersFixedAddress(t *testing.T) {
	zone := a01Zone(t, dnslab.AAAAStatic, 1)
	zone.TTL = 300
	r, d := n01Respond(t, &zone, 7, "www.lab.pound2pound.fr", 28)
	if d.Verdict != dnslab.VerdictAnswerAAAA || d.RCode != 0 {
		t.Fatalf("verdict %v rcode %d, attendu VerdictAnswerAAAA/0", d.Verdict, d.RCode)
	}
	if d.Verdict.String() != "answer_aaaa" {
		t.Errorf("String() = %q", d.Verdict.String())
	}
	if r[2]&0x80 == 0 || r[2]&0x04 == 0 {
		t.Errorf("QR ou AA absent : octet 2 = %#x", r[2])
	}
	typ, cls, ttl, rdata := a01Answer(t, r)
	if typ != 28 || cls != 1 || ttl != 300 || len(rdata) != 16 || [16]byte(rdata) != zone.AnswerAAAA {
		t.Errorf("RR = type %d classe %d ttl %d rdata %x", typ, cls, ttl, rdata)
	}
	if ra, da := n01Respond(t, &zone, 8, "www.lab.pound2pound.fr", 1); da.Verdict != dnslab.VerdictAnswerA || binary.BigEndian.Uint16(ra[6:8]) != 1 {
		t.Errorf("question A en mode static : verdict %v", da.Verdict)
	}
	if _, dh := n01Respond(t, &zone, 9, "www.example.org", 28); dh.Verdict != dnslab.VerdictRefused || dh.RCode != 5 {
		t.Errorf("hors zone : verdict %v rcode %d", dh.Verdict, dh.RCode)
	}
	if zone.AAAACounter != 0 {
		t.Errorf("mode static : compteur %d, attendu 0", zone.AAAACounter)
	}
}

func TestAAAAMode_IIDStegoVariesPerResponse(t *testing.T) {
	zone := a01Zone(t, dnslab.AAAAIIDStego, 0x5EED2026)
	seen := map[[8]byte]bool{}
	var first [16]byte
	for i := range 8 {
		r, d := n01Respond(t, &zone, uint16(100+i), "beacon.lab.pound2pound.fr", 28)
		if d.Verdict != dnslab.VerdictAnswerAAAA {
			t.Fatalf("réponse %d : verdict %v", i, d.Verdict)
		}
		typ, _, _, rdata := a01Answer(t, r)
		if typ != 28 || len(rdata) != 16 {
			t.Fatalf("réponse %d : type %d longueur %d", i, typ, len(rdata))
		}
		if [8]byte(rdata[:8]) != [8]byte(zone.AnswerAAAA[:8]) {
			t.Errorf("réponse %d : préfixe %x ≠ %x", i, rdata[:8], zone.AnswerAAAA[:8])
		}
		iid := [8]byte(rdata[8:16])
		if seen[iid] {
			t.Errorf("réponse %d : identifiant d'interface %x déjà rendu", i, iid)
		}
		seen[iid] = true
		if i == 0 {
			first = [16]byte(rdata)
		}
	}
	if zone.AAAACounter != 8 {
		t.Errorf("compteur = %d, attendu 8", zone.AAAACounter)
	}
	// Déterminisme : même graine, même suite.
	again := a01Zone(t, dnslab.AAAAIIDStego, 0x5EED2026)
	r, _ := n01Respond(t, &again, 100, "beacon.lab.pound2pound.fr", 28)
	_, _, _, rdata := a01Answer(t, r)
	if [16]byte(rdata) != first {
		t.Errorf("même graine : première adresse %x ≠ %x", rdata, first)
	}
	other := a01Zone(t, dnslab.AAAAIIDStego, 0x5EED2027)
	r, _ = n01Respond(t, &other, 100, "beacon.lab.pound2pound.fr", 28)
	_, _, _, rdata = a01Answer(t, r)
	if [16]byte(rdata) == first {
		t.Errorf("autre graine : première adresse identique %x", rdata)
	}
}

func TestAAAAMode_IIDStegoKeepsOtherTypes(t *testing.T) {
	zone := a01Zone(t, dnslab.AAAAIIDStego, 3)
	zone.Negative = dnslab.NegativeSOAStego
	zone.NegativeSeed = 9
	if _, d := n01Respond(t, &zone, 1, "www.lab.pound2pound.fr", 1); d.Verdict != dnslab.VerdictAnswerA {
		t.Errorf("A : verdict %v", d.Verdict)
	}
	if _, d := n01Respond(t, &zone, 2, "www.lab.pound2pound.fr", 16); d.Verdict != dnslab.VerdictAnswerTXT {
		t.Errorf("TXT : verdict %v", d.Verdict)
	}
	if _, d := n01Respond(t, &zone, 3, "nx-abc.lab.pound2pound.fr", 28); d.Verdict != dnslab.VerdictNXDomain || d.RCode != 3 {
		t.Errorf("nx- en mode négatif : verdict %v rcode %d", d.Verdict, d.RCode)
	}
	if _, d := n01Respond(t, &zone, 4, "www.lab.pound2pound.fr", 15); d.Verdict != dnslab.VerdictNoData {
		t.Errorf("MX : verdict %v", d.Verdict)
	}
	if zone.AAAACounter != 0 {
		t.Errorf("aucune réponse AAAA stego rendue : compteur %d", zone.AAAACounter)
	}
}

func TestAAAAMode_ZeroAlloc(t *testing.T) {
	for _, mode := range []dnslab.AAAAMode{dnslab.AAAAStatic, dnslab.AAAAIIDStego} {
		zone := a01Zone(t, mode, 5)
		var q, r [512]byte
		n, err := dnslab.BuildQuery(1, []byte("alloc.lab.pound2pound.fr"), 28, q[:])
		if err != nil {
			t.Fatal(err)
		}
		allocs := testing.AllocsPerRun(200, func() {
			if _, _, err := dnslab.BuildResponse(q[:n], &zone, r[:]); err != nil {
				t.Fatal(err)
			}
		})
		if allocs != 0 {
			t.Errorf("mode %d : %.0f allocation(s) par réponse", mode, allocs)
		}
	}
}
