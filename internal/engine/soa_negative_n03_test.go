package engine

import (
	"encoding/binary"
	"testing"
)

// Strate N-03 : détecteur du canal descendant logé dans le SOA des réponses
// négatives (RFC 2308). Entrée : octets filaires d'une réponse. Clé de suivi :
// (client, domaine parent = QNAME privé de son premier label). Empreinte :
// FNV-1a 64 bits de MNAME et RNAME décompressés en minuscules et du Serial.
// Verdict REASON_P20_SOA_NEG_DOWNLINK dès la troisième empreinte distincte
// observée pour une même clé dans une fenêtre de 10 minutes.

type n03SOA struct {
	mname, rname string
	serial       uint32
	minimum      uint32
	compressRoot bool // MNAME/RNAME terminés par un pointeur vers l'apex de la question
}

func n03EncodeName(name string, dst []byte) int {
	off := 0
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			dst[off] = byte(i - start)
			off++
			off += copy(dst[off:], name[start:i])
			start = i + 1
		}
	}
	dst[off] = 0
	return off + 1
}

// n03Negative construit une réponse QR=1 : question qname/A, RCode rcode,
// ANCOUNT 0, et si soa != nil un SOA en Authority dont le propriétaire est le
// parent de qname.
func n03Negative(id uint16, qname string, rcode uint8, soa *n03SOA) []byte {
	buf := make([]byte, 0, 512)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x8400|uint16(rcode))
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	buf = append(buf, hdr...)
	var tmp [512]byte
	n := n03EncodeName(qname, tmp[:])
	buf = append(buf, tmp[:n]...)
	buf = append(buf, 0, 1, 0, 1)
	if soa == nil {
		return buf
	}
	binary.BigEndian.PutUint16(buf[8:10], 1)
	firstDot := 0
	for firstDot < len(qname) && qname[firstDot] != '.' {
		firstDot++
	}
	parentOff := uint16(12 + 1 + firstDot)
	// propriétaire : pointeur vers le parent dans la question
	buf = append(buf, 0xC0|byte(parentOff>>8), byte(parentOff))
	buf = append(buf, 0, 6, 0, 1)
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, soa.minimum)
	buf = append(buf, ttl...)
	rd := make([]byte, 0, 600)
	encodeField := func(name string) {
		if soa.compressRoot {
			// première étiquette en clair puis pointeur vers le parent
			dot := 0
			for dot < len(name) && name[dot] != '.' {
				dot++
			}
			rd = append(rd, byte(dot))
			rd = append(rd, name[:dot]...)
			rd = append(rd, 0xC0|byte(parentOff>>8), byte(parentOff))
			return
		}
		n := n03EncodeName(name, tmp[:])
		rd = append(rd, tmp[:n]...)
	}
	encodeField(soa.mname)
	encodeField(soa.rname)
	u := make([]byte, 20)
	binary.BigEndian.PutUint32(u[0:4], soa.serial)
	binary.BigEndian.PutUint32(u[4:8], 3600)
	binary.BigEndian.PutUint32(u[8:12], 900)
	binary.BigEndian.PutUint32(u[12:16], 604800)
	binary.BigEndian.PutUint32(u[16:20], soa.minimum)
	rd = append(rd, u...)
	rdlen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdlen, uint16(len(rd)))
	buf = append(buf, rdlen...)
	buf = append(buf, rd...)
	return buf
}

var n03Client = [16]byte{10, 55, 0, 2}

func TestSOANegativeTracker_ConstantSOAIsBenign(t *testing.T) {
	var tr SOANegativeTracker
	soa := &n03SOA{mname: "ns1.lab.pound2pound.fr", rname: "hostmaster.lab.pound2pound.fr", serial: 2026102901, minimum: 300}
	for i := range 12 {
		name := "nx-" + string(rune('a'+i)) + ".lab.pound2pound.fr"
		fired, reason := tr.ObserveResponse(int64(i)*1e9, n03Client, n03Negative(uint16(0x100+i), name, 3, soa))
		if fired || reason != ReasonNone {
			t.Fatalf("SOA constant sur %d noms : fired=%v reason=%q", i+1, fired, reason)
		}
	}
}

func TestSOANegativeTracker_ThreeDistinctFingerprintsFire(t *testing.T) {
	var tr SOANegativeTracker
	soas := []*n03SOA{
		{mname: "m1a2b3c4.lab.pound2pound.fr", rname: "r9f8e7d6.lab.pound2pound.fr", serial: 0x11111111, minimum: 1},
		{mname: "m5e6f7a8.lab.pound2pound.fr", rname: "r1c2d3e4.lab.pound2pound.fr", serial: 0x22222222, minimum: 1},
		{mname: "m9b8c7d6.lab.pound2pound.fr", rname: "r5a6b7c8.lab.pound2pound.fr", serial: 0x33333333, minimum: 1},
	}
	for i, soa := range soas {
		fired, reason := tr.ObserveResponse(int64(i)*1e9, n03Client, n03Negative(uint16(0x200+i), "nx-"+string(rune('a'+i))+".lab.pound2pound.fr", 3, soa))
		if i < 2 && (fired || reason != ReasonNone) {
			t.Fatalf("empreinte %d : fired=%v reason=%q, attendu rien avant la troisième", i+1, fired, reason)
		}
		if i == 2 && (!fired || reason != ReasonP20SOANegDownlink) {
			t.Fatalf("troisième empreinte : fired=%v reason=%q, attendu %q", fired, reason, ReasonP20SOANegDownlink)
		}
	}
}

func TestSOANegativeTracker_SerialOnlyAndNODATACount(t *testing.T) {
	var tr SOANegativeTracker
	// Même MNAME/RNAME, Serial différent : trois empreintes distinctes, en NODATA (RCode 0, ANCOUNT 0).
	for i := range 3 {
		soa := &n03SOA{mname: "ns1.lab.pound2pound.fr", rname: "hostmaster.lab.pound2pound.fr", serial: uint32(100 + i), minimum: 1}
		fired, _ := tr.ObserveResponse(int64(i)*1e9, n03Client, n03Negative(uint16(0x300+i), "nx-x.lab.pound2pound.fr", 0, soa))
		if (i < 2) == fired {
			t.Fatalf("NODATA serial %d : fired=%v", 100+i, fired)
		}
	}
}

func TestSOANegativeTracker_CompressedNamesDecoded(t *testing.T) {
	var tr SOANegativeTracker
	// Les mêmes MNAME/RNAME écrits une fois en clair, une fois avec pointeur vers l'apex : même empreinte.
	plain := &n03SOA{mname: "ns1.lab.pound2pound.fr", rname: "hostmaster.lab.pound2pound.fr", serial: 7, minimum: 300}
	comp := &n03SOA{mname: "NS1.lab.pound2pound.fr", rname: "hostmaster.lab.pound2pound.fr", serial: 7, minimum: 300, compressRoot: true}
	for i := range 6 {
		s := plain
		if i%2 == 1 {
			s = comp
		}
		fired, _ := tr.ObserveResponse(int64(i)*1e9, n03Client, n03Negative(uint16(0x400+i), "nx-c.lab.pound2pound.fr", 3, s))
		if fired {
			t.Fatalf("clair et compressé (casse différente) doivent donner une seule empreinte ; feu à l'observation %d", i+1)
		}
	}
}

func TestSOANegativeTracker_IgnoresAnsweredAndParentsAreIndependent(t *testing.T) {
	var tr SOANegativeTracker
	distinct := func(i int) *n03SOA {
		return &n03SOA{mname: "m" + string(rune('a'+i)) + ".z.example", rname: "r" + string(rune('a'+i)) + ".z.example", serial: uint32(i), minimum: 1}
	}
	// Deux parents différents, deux empreintes chacun : aucun feu.
	for i := range 2 {
		if f, _ := tr.ObserveResponse(int64(i)*1e9, n03Client, n03Negative(uint16(0x500+i), "nx-a.one.example", 3, distinct(i))); f {
			t.Fatal("parent one : feu prématuré")
		}
		if f, _ := tr.ObserveResponse(int64(i)*1e9, n03Client, n03Negative(uint16(0x510+i), "nx-a.two.example", 3, distinct(i+5))); f {
			t.Fatal("parent two : feu prématuré")
		}
	}
	// Une réponse sans section Authority, et une réponse avec ANCOUNT > 0, ne comptent pas.
	if f, _ := tr.ObserveResponse(3e9, n03Client, n03Negative(0x520, "nx-a.one.example", 3, nil)); f {
		t.Fatal("NXDOMAIN sans SOA ne doit pas compter")
	}
	answered := n03Negative(0x521, "nx-a.one.example", 0, distinct(9))
	binary.BigEndian.PutUint16(answered[6:8], 1) // ANCOUNT forcé à 1 : réponse positive, section ignorée
	if f, _ := tr.ObserveResponse(4e9, n03Client, answered); f {
		t.Fatal("réponse avec ANCOUNT > 0 ne doit pas compter")
	}
	// Un autre client sur le même parent ne partage pas le compte.
	other := [16]byte{10, 55, 0, 9}
	if f, _ := tr.ObserveResponse(5e9, other, n03Negative(0x530, "nx-b.one.example", 3, distinct(7))); f {
		t.Fatal("client distinct : feu prématuré")
	}
	// Troisième empreinte du client initial sur « one » : feu.
	if f, r := tr.ObserveResponse(6e9, n03Client, n03Negative(0x540, "nx-b.one.example", 3, distinct(2))); !f || r != ReasonP20SOANegDownlink {
		t.Fatalf("troisième empreinte sur one : fired=%v reason=%q", f, r)
	}
}

func TestSOANegativeTracker_WindowExpires(t *testing.T) {
	var tr SOANegativeTracker
	distinct := func(i int) *n03SOA {
		return &n03SOA{mname: "m" + string(rune('a'+i)) + ".lab.pound2pound.fr", rname: "r.lab.pound2pound.fr", serial: uint32(i), minimum: 1}
	}
	tr.ObserveResponse(0, n03Client, n03Negative(0x600, "nx-a.lab.pound2pound.fr", 3, distinct(0)))
	tr.ObserveResponse(1e9, n03Client, n03Negative(0x601, "nx-b.lab.pound2pound.fr", 3, distinct(1)))
	// 11 minutes plus tard : les deux premières empreintes sont hors fenêtre (10 min).
	if f, _ := tr.ObserveResponse(661e9, n03Client, n03Negative(0x602, "nx-c.lab.pound2pound.fr", 3, distinct(2))); f {
		t.Fatal("empreintes expirées ne doivent pas compter")
	}
}

func TestSOANegativeTracker_ZeroAlloc(t *testing.T) {
	var tr SOANegativeTracker
	soa := &n03SOA{mname: "ns1.lab.pound2pound.fr", rname: "hostmaster.lab.pound2pound.fr", serial: 1, minimum: 300}
	resp := n03Negative(0x700, "nx-a.lab.pound2pound.fr", 3, soa)
	allocs := testing.AllocsPerRun(500, func() { tr.ObserveResponse(1e9, n03Client, resp) })
	if allocs != 0 {
		t.Errorf("ObserveResponse : %.2f allocs/op, attendu 0", allocs)
	}
}
