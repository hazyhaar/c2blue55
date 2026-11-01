package c2blue55

import (
	"encoding/binary"
	"path/filepath"
	"testing"
)

// Strate N-05c : (1) EvaluateSOANegativePCAP ne compte en NegativeWithSOA que
// les réponses négatives dont la section Authority contient un RR de type 6
// (une délégation NS seule ne compte pas) ; (2) le rapport de c2forge soa-eval
// est écrit de façon atomique (fichier temporaire, fsync, renommage, mode 0600)
// sans fichier temporaire résiduel. Constats d'audit du 2026-10-29.

// n05cDelegation construit une réponse RCode 0, ANCOUNT 0, NSCOUNT 1 dont le
// RR d'Authority est un NS (type 2), pas un SOA.
func n05cDelegation(id uint16, qname string) []byte {
	b := n05Query(id, qname)
	binary.BigEndian.PutUint16(b[2:4], 0x8000)
	binary.BigEndian.PutUint16(b[8:10], 1)
	dot := 0
	for dot < len(qname) && qname[dot] != '.' {
		dot++
	}
	parentOff := uint16(12 + 1 + dot)
	b = append(b, 0xC0|byte(parentOff>>8), byte(parentOff), 0, 2, 0, 1, 0, 0, 14, 16)
	var tmp [300]byte
	n := n05Name("ns1."+qname[dot+1:], tmp[:])
	b = append(b, byte(n>>8), byte(n))
	return append(b, tmp[:n]...)
}

func TestEvaluateSOANegativePCAP_DelegationIsNotNegativeWithSOA(t *testing.T) {
	dir := t.TempDir()
	var frames [][]byte
	var ts []uint64
	base := uint64(1_793_300_000_000_000)
	for i := range 4 {
		q := n05Query(uint16(0x900+i), "www.deleg"+string(rune('a'+i))+".example")
		r := n05cDelegation(uint16(0x900+i), "www.deleg"+string(rune('a'+i))+".example")
		sport := uint16(43000 + i)
		frames = append(frames, n05Frame(n05Client, n05Resolver, sport, 53, q), n05Frame(n05Resolver, n05Client, 53, sport, r))
		ts = append(ts, base+uint64(i)*1_000_000, base+uint64(i)*1_000_000+20_000)
	}
	// Une vraie réponse négative avec SOA, pour contraste.
	q := n05Query(0x9FF, "nx-z.lab.pound2pound.fr")
	r := n05Negative(0x9FF, "nx-z.lab.pound2pound.fr", 3, &n05SOA{mname: "ns1.lab.pound2pound.fr", rname: "hostmaster.lab.pound2pound.fr", serial: 1})
	frames = append(frames, n05Frame(n05Client, n05Resolver, 43999, 53, q), n05Frame(n05Resolver, n05Client, 53, 43999, r))
	ts = append(ts, base+9_000_000, base+9_020_000)
	path := filepath.Join(dir, "deleg.pcap")
	n05WritePCAP(t, path, frames, ts)
	rep, err := EvaluateSOANegativePCAP(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Responses != 5 || rep.NegativeWithSOA != 1 || rep.Fires != 0 {
		t.Errorf("rapport = %+v, attendu Responses=5 NegativeWithSOA=1 Fires=0", rep)
	}
}
