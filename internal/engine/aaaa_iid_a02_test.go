package engine

import (
	"encoding/binary"
	"testing"
)

// Strate A-02 : canal descendant dans l'identifiant d'interface (64 bits bas)
// des réponses AAAA. Clé (client, préfixe /64). Un identifiant « pleine
// largeur » a ses 8 octets tous non nuls. Feu REASON_P21_AAAA_IID_DOWNLINK
// quand au moins 8 identifiants pleine largeur distincts ont été vus sous la
// même clé en 600 s (anneau de 16 empreintes). Les identifiants comportant un
// octet nul (pools ::200e, ::6810:7c60, EUI-64 avec octet nul) ne comptent
// pas. Réponses RCode ≠ 0, questions (QR = 0), enregistrements non AAAA :
// ignorés. Aucune allocation par paquet.

var a02Client = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 55, 0, 2}

func a02Name(name string, dst []byte) int {
	n := 0
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			dst[n] = byte(i - start)
			n++
			n += copy(dst[n:], name[start:i])
			start = i + 1
		}
	}
	dst[n] = 0
	return n + 1
}

// a02Response construit une réponse AAAA (ou A si typ == 1) : question + len(rdatas) enregistrements.
func a02Response(id uint16, qname string, rcode uint8, typ uint16, rdatas ...[]byte) []byte {
	b := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], 0x8180|uint16(rcode))
	binary.BigEndian.PutUint16(b[4:6], 1)
	binary.BigEndian.PutUint16(b[6:8], uint16(len(rdatas)))
	var tmp [300]byte
	n := a02Name(qname, tmp[:])
	b = append(b, tmp[:n]...)
	b = append(b, byte(typ>>8), byte(typ), 0, 1)
	for _, rd := range rdatas {
		b = append(b, 0xC0, 0x0C, byte(typ>>8), byte(typ), 0, 1, 0, 0, 0, 60, byte(len(rd)>>8), byte(len(rd)))
		b = append(b, rd...)
	}
	return b
}

func a02Addr(prefix [8]byte, iid uint64) []byte {
	out := make([]byte, 16)
	copy(out, prefix[:])
	binary.BigEndian.PutUint64(out[8:], iid)
	return out
}

var a02PrefixC2 = [8]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x55, 0, 0}

// a02FullWidth rend un identifiant pleine largeur distinct par i (aucun octet nul).
func a02FullWidth(i int) uint64 {
	v := uint64(0x1111111111111111) * uint64(1+i%15)
	return v ^ uint64(i)<<56 ^ 0x0101010101010101
}

func TestAAAAIIDTracker_FiresOnEighthDistinctFullWidthIID(t *testing.T) {
	var tr AAAAIIDTracker
	for i := range 7 {
		if f, _ := tr.ObserveResponse(int64(i)*1e9, a02Client, a02Response(uint16(i), "b.c2.example", 0, 28, a02Addr(a02PrefixC2, a02FullWidth(i)))); f {
			t.Fatalf("feu prématuré à la réponse %d", i)
		}
	}
	f, r := tr.ObserveResponse(7e9, a02Client, a02Response(7, "b.c2.example", 0, 28, a02Addr(a02PrefixC2, a02FullWidth(7))))
	if !f || r != ReasonP21AAAAIIDDownlink {
		t.Fatalf("8e identifiant : fired=%v reason=%q, attendu %q", f, r, ReasonP21AAAAIIDDownlink)
	}
	if ReasonP21AAAAIIDDownlink != "REASON_P21_AAAA_IID_DOWNLINK" {
		t.Errorf("constante = %q", ReasonP21AAAAIIDDownlink)
	}
}

func TestAAAAIIDTracker_SingleRRsetOfEightFires(t *testing.T) {
	var tr AAAAIIDTracker
	rds := make([][]byte, 8)
	for i := range rds {
		rds[i] = a02Addr(a02PrefixC2, a02FullWidth(i))
	}
	if f, _ := tr.ObserveResponse(1e9, a02Client, a02Response(1, "pool.c2.example", 0, 28, rds...)); !f {
		t.Error("RRset de 8 identifiants pleine largeur : aucun feu")
	}
}

func TestAAAAIIDTracker_BenignPoolsNeverFire(t *testing.T) {
	var tr AAAAIIDTracker
	cf := [8]byte{0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0}
	gg := [8]byte{0x2a, 0x00, 0x14, 0x50, 0x40, 0x07, 0x08, 0x0d}
	for i := range 20 {
		// Cloudflare : ::6810:7c60 + i (quatre octets hauts nuls) ; Google : ::200e (six octets nuls).
		if f, _ := tr.ObserveResponse(int64(i)*1e9, a02Client, a02Response(uint16(i), "site.example", 0, 28, a02Addr(cf, 0x68107c60+uint64(i)))); f {
			t.Fatalf("pool à octets nuls : feu à %d", i)
		}
		if f, _ := tr.ObserveResponse(int64(i)*1e9+1, a02Client, a02Response(uint16(i), "www.google.example", 0, 28, a02Addr(gg, 0x200e))); f {
			t.Fatalf("identifiant constant : feu à %d", i)
		}
	}
	// Même identifiant pleine largeur répété 20 fois : un seul distinct.
	for i := range 20 {
		if f, _ := tr.ObserveResponse(int64(i)*1e9, a02Client, a02Response(uint16(i), "stable.example", 0, 28, a02Addr(a02PrefixC2, 0x0102030405060708))); f {
			t.Fatalf("identifiant pleine largeur répété : feu à %d", i)
		}
	}
}

func TestAAAAIIDTracker_KeyIsClientAndPrefix(t *testing.T) {
	var tr AAAAIIDTracker
	other := [8]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x56, 0, 0}
	for i := range 7 {
		tr.ObserveResponse(int64(i)*1e9, a02Client, a02Response(uint16(i), "b.c2.example", 0, 28, a02Addr(a02PrefixC2, a02FullWidth(i))))
	}
	// 8e identifiant sous un autre préfixe : pas de feu.
	if f, _ := tr.ObserveResponse(7e9, a02Client, a02Response(7, "b.c2.example", 0, 28, a02Addr(other, a02FullWidth(7)))); f {
		t.Error("autre préfixe /64 : feu")
	}
	// 8e identifiant du bon préfixe mais autre client : pas de feu.
	otherClient := a02Client
	otherClient[15] = 3
	if f, _ := tr.ObserveResponse(7e9, otherClient, a02Response(7, "b.c2.example", 0, 28, a02Addr(a02PrefixC2, a02FullWidth(7)))); f {
		t.Error("autre client : feu")
	}
	// Enfin le 8e sous la bonne clé : feu.
	if f, _ := tr.ObserveResponse(8e9, a02Client, a02Response(8, "b.c2.example", 0, 28, a02Addr(a02PrefixC2, a02FullWidth(8)))); !f {
		t.Error("8e identifiant sous la bonne clé : aucun feu")
	}
}

func TestAAAAIIDTracker_WindowExpiry(t *testing.T) {
	var tr AAAAIIDTracker
	for i := range 7 {
		tr.ObserveResponse(int64(i)*1e9, a02Client, a02Response(uint16(i), "b.c2.example", 0, 28, a02Addr(a02PrefixC2, a02FullWidth(i))))
	}
	if f, _ := tr.ObserveResponse(700e9, a02Client, a02Response(7, "b.c2.example", 0, 28, a02Addr(a02PrefixC2, a02FullWidth(7)))); f {
		t.Error("après 600 s : les 7 premiers devaient être expirés")
	}
}

func TestAAAAIIDTracker_IgnoresNonAnswers(t *testing.T) {
	var tr AAAAIIDTracker
	for i := range 10 {
		rd := a02Addr(a02PrefixC2, a02FullWidth(i))
		nx := a02Response(uint16(i), "b.c2.example", 3, 28, rd)
		if f, _ := tr.ObserveResponse(int64(i)*1e9, a02Client, nx); f {
			t.Fatal("RCode 3 : feu")
		}
		q := a02Response(uint16(i), "b.c2.example", 0, 28, rd)
		q[2] &^= 0x80
		if f, _ := tr.ObserveResponse(int64(i)*1e9, a02Client, q); f {
			t.Fatal("question (QR=0) : feu")
		}
		if f, _ := tr.ObserveResponse(int64(i)*1e9, a02Client, a02Response(uint16(i), "b.c2.example", 0, 1, []byte{10, 55, 0, byte(i + 1)})); f {
			t.Fatal("enregistrement A : feu")
		}
	}
	// Enregistrement tronqué : RDLENGTH au-delà du message, sans panique ni feu.
	bad := a02Response(1, "b.c2.example", 0, 28, a02Addr(a02PrefixC2, a02FullWidth(1)))
	bad[len(bad)-17] = 0xff
	if f, _ := tr.ObserveResponse(1, a02Client, bad[:len(bad)-4]); f {
		t.Error("message tronqué : feu")
	}
	if f, _ := tr.ObserveResponse(1, a02Client, bad[:5]); f {
		t.Error("message de 5 octets : feu")
	}
}

func TestAAAAIIDTracker_ZeroAlloc(t *testing.T) {
	var tr AAAAIIDTracker
	msgs := make([][]byte, 16)
	for i := range msgs {
		msgs[i] = a02Response(uint16(i), "b.c2.example", 0, 28, a02Addr(a02PrefixC2, a02FullWidth(i)))
	}
	i := 0
	allocs := testing.AllocsPerRun(500, func() {
		tr.ObserveResponse(int64(i)*1e6, a02Client, msgs[i%16])
		i++
	})
	if allocs != 0 {
		t.Errorf("%.0f allocation(s) par réponse", allocs)
	}
}
