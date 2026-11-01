package engine

import (
	"encoding/binary"
	"fmt"
	"testing"
)

// Strate N-03b : la clé de suivi du SOANegativeTracker devient (client, nom
// propriétaire du RR SOA en Authority), à condition que ce propriétaire soit
// en bailiwick (suffixe du QNAME) et compte au moins deux labels ; la table
// devient associative à 4 voies (quatre clés par alvéole, éviction de la plus
// ancienne), au lieu d'une correspondance directe qui effaçait l'état.
// Constats d'audit du 2026-10-29 : évasion à deux labels variables, faux
// positifs sur les TLD, effacement sur collision.

// n03bNegative construit une réponse négative dont le propriétaire du SOA est
// owner (nom en clair, sans compression), pour isoler la clé de suivi du QNAME.
func n03bQuery(id uint16, qname string) []byte {
	b := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], 0x0100)
	binary.BigEndian.PutUint16(b[4:6], 1)
	var tmp [300]byte
	n := n03EncodeName(qname, tmp[:])
	b = append(b, tmp[:n]...)
	return append(b, 0, 1, 0, 1)
}

func n03bNegative(id uint16, qname, owner string, rcode uint8, soa *n03SOA) []byte {
	b := n03bQuery(id, qname)
	binary.BigEndian.PutUint16(b[2:4], 0x8400|uint16(rcode))
	binary.BigEndian.PutUint16(b[8:10], 1)
	var tmp [300]byte
	n := n03EncodeName(owner, tmp[:])
	b = append(b, tmp[:n]...)
	b = append(b, 0, 6, 0, 1, 0, 0, 0, 1)
	rd := make([]byte, 0, 600)
	n = n03EncodeName(soa.mname, tmp[:])
	rd = append(rd, tmp[:n]...)
	n = n03EncodeName(soa.rname, tmp[:])
	rd = append(rd, tmp[:n]...)
	u := make([]byte, 20)
	binary.BigEndian.PutUint32(u[0:4], soa.serial)
	binary.BigEndian.PutUint32(u[4:8], 3600)
	binary.BigEndian.PutUint32(u[8:12], 900)
	binary.BigEndian.PutUint32(u[12:16], 604800)
	binary.BigEndian.PutUint32(u[16:20], soa.minimum)
	rd = append(rd, u...)
	b = append(b, byte(len(rd)>>8), byte(len(rd)))
	return append(b, rd...)
}

func n03bSOA(i int) *n03SOA {
	return &n03SOA{mname: fmt.Sprintf("m%02d.lab.pound2pound.fr", i), rname: fmt.Sprintf("r%02d.lab.pound2pound.fr", i), serial: uint32(1000 + i), minimum: 1}
}

func TestSOANegativeTracker_KeyIsSOAOwnerNotQNameParent(t *testing.T) {
	var tr SOANegativeTracker
	// Deux labels variables par question : l'ancien découpage (QNAME moins un
	// label) donnait trois clés distinctes et aucun feu ; le propriétaire du
	// SOA est le même pour les trois, donc le feu tombe à la troisième.
	for i := range 3 {
		q := fmt.Sprintf("a.%016x.lab.pound2pound.fr", 0xabc0+i)
		fired, reason := tr.ObserveResponse(int64(i)*1e9, n03Client, n03bNegative(uint16(0x800+i), q, "lab.pound2pound.fr", 3, n03bSOA(i)))
		if i < 2 && fired {
			t.Fatalf("feu prématuré à l'observation %d", i+1)
		}
		if i == 2 && (!fired || reason != ReasonP20SOANegDownlink) {
			t.Fatalf("troisième SOA distinct sous le même propriétaire : fired=%v reason=%q", fired, reason)
		}
	}
}

func TestSOANegativeTracker_TLDOwnerIgnoredAndApexesIndependent(t *testing.T) {
	var tr SOANegativeTracker
	// Trois apex .com en NODATA, chacun avec son propre SOA : trois propriétaires
	// distincts, aucune clé n'atteint trois empreintes.
	for i := range 3 {
		apex := fmt.Sprintf("site%d.com", i)
		if f, _ := tr.ObserveResponse(int64(i)*1e9, n03Client, n03bNegative(uint16(0x900+i), apex, apex, 0, n03bSOA(i))); f {
			t.Fatalf("trois apex distincts ne doivent pas se cumuler (feu à %s)", apex)
		}
	}
	// Un propriétaire à un seul label (TLD) est ignoré même avec trois SOA distincts.
	for i := range 3 {
		if f, _ := tr.ObserveResponse(int64(10+i)*1e9, n03Client, n03bNegative(uint16(0x910+i), fmt.Sprintf("absent%d.com", i), "com", 3, n03bSOA(20+i))); f {
			t.Fatalf("propriétaire TLD « com » : feu interdit (observation %d)", i+1)
		}
	}
	// Un propriétaire hors bailiwick (pas un suffixe du QNAME) est ignoré.
	for i := range 3 {
		if f, _ := tr.ObserveResponse(int64(20+i)*1e9, n03Client, n03bNegative(uint16(0x920+i), "nx.lab.pound2pound.fr", "autre.example", 3, n03bSOA(30+i))); f {
			t.Fatalf("propriétaire hors bailiwick : feu interdit (observation %d)", i+1)
		}
	}
}

func TestSOANegativeTracker_FourWayAssociativityKeepsState(t *testing.T) {
	var tr SOANegativeTracker
	// Cinq propriétaires distincts dont les clés tombent dans la même alvéole.
	base := cleSuiviSOA(n03Client, []byte("lab.pound2pound.fr"))
	cible := indexAlveoleSOA(base)
	var owners []string
	for i := 0; len(owners) < 5 && i < 200000; i++ {
		o := fmt.Sprintf("z%d.example", i)
		if indexAlveoleSOA(cleSuiviSOA(n03Client, []byte(o))) == cible {
			owners = append(owners, o)
		}
	}
	if len(owners) < 5 {
		t.Fatal("impossible de trouver cinq propriétaires en collision d'alvéole")
	}
	// Deux empreintes pour chacun des quatre premiers propriétaires, entrelacées.
	ts := int64(0)
	for round := range 2 {
		for k := range 4 {
			ts += 1e9
			if f, _ := tr.ObserveResponse(ts, n03Client, n03bNegative(uint16(0xA00+ts/1e9), "q."+owners[k], owners[k], 3, n03bSOA(round*10+k))); f {
				t.Fatalf("feu prématuré sur %s", owners[k])
			}
		}
	}
	// Troisième empreinte du premier propriétaire : l'état n'a pas été effacé
	// par les trois autres clés de l'alvéole.
	ts += 1e9
	if f, r := tr.ObserveResponse(ts, n03Client, n03bNegative(0xAFF, "q."+owners[0], owners[0], 3, n03bSOA(99))); !f || r != ReasonP20SOANegDownlink {
		t.Fatalf("quatre clés dans une alvéole doivent coexister : fired=%v reason=%q", f, r)
	}
	// Un cinquième propriétaire évince la clé la plus ancienne (owners[1]), pas la plus récente.
	ts += 1e9
	tr.ObserveResponse(ts, n03Client, n03bNegative(0xB00, "q."+owners[4], owners[4], 3, n03bSOA(50)))
	ts += 1e9
	if f, _ := tr.ObserveResponse(ts, n03Client, n03bNegative(0xB01, "q."+owners[0], owners[0], 3, n03bSOA(98))); !f {
		t.Fatal("le propriétaire le plus récemment actif ne doit pas être évincé")
	}
}

func TestSOANegativeTracker_ZeroAllocWithOwnerKey(t *testing.T) {
	var tr SOANegativeTracker
	resp := n03bNegative(0xC00, "a.b.lab.pound2pound.fr", "lab.pound2pound.fr", 3, n03bSOA(1))
	if allocs := testing.AllocsPerRun(500, func() { tr.ObserveResponse(1e9, n03Client, resp) }); allocs != 0 {
		t.Errorf("%.2f allocs/op, attendu 0", allocs)
	}
}
