package engine

import (
	"encoding/binary"
	"testing"
)

// Strate I-02 : détecteur d'asymétrie Echo ICMP (RFC 792 : la réponse porte
// la charge utile de la requête à l'identique). Entrée : paquet IPv4 brut
// (type de lien 101, comme les captures wg0 de redhost). Clé : (src, dst, ID,
// Seq) de la requête ; une réponse (type 0) dont la charge utile n'a pas
// l'empreinte FNV-1a mémorisée pour (dst, src, ID, Seq) lève
// REASON_IC01_ICMP_ECHO_ASYMMETRY. Réponse sans requête vue : ignorée.
// Les trames sont construites ici, indépendamment de internal/icmplab.

func i02Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func i02Frame(src, dst [4]byte, typ uint8, id, seq uint16, payload []byte) []byte {
	icmp := make([]byte, 8+len(payload))
	icmp[0] = typ
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], i02Checksum(icmp))
	f := make([]byte, 20+len(icmp))
	f[0] = 0x45
	binary.BigEndian.PutUint16(f[2:4], uint16(len(f)))
	f[8] = 64
	f[9] = 1
	copy(f[12:16], src[:])
	copy(f[16:20], dst[:])
	copy(f[20:], icmp)
	return f
}

var (
	i02Emitter   = [4]byte{10, 55, 0, 2}
	i02Responder = [4]byte{10, 55, 0, 1}
)

func TestICMPEchoParityTracker_BenignPingIsSymmetric(t *testing.T) {
	var tr ICMPEchoParityTracker
	payload := make([]byte, 56)
	for i := range payload {
		payload[i] = byte(i)
	}
	for seq := uint16(1); seq <= 10; seq++ {
		if f, _ := tr.ObserveIPv4(int64(seq)*1e9, i02Frame(i02Emitter, i02Responder, 8, 0x4242, seq, payload)); f {
			t.Fatalf("requête seq %d : feu interdit", seq)
		}
		if f, r := tr.ObserveIPv4(int64(seq)*1e9+500000, i02Frame(i02Responder, i02Emitter, 0, 0x4242, seq, payload)); f || r != ReasonNone {
			t.Fatalf("réponse identique seq %d : fired=%v reason=%q", seq, f, r)
		}
	}
}

func TestICMPEchoParityTracker_AsymmetricReplyFires(t *testing.T) {
	var tr ICMPEchoParityTracker
	req := []byte("c2il\x00\x00\x00\x01payload-chunk-0001")
	rep := append([]byte(nil), req...)
	for i := 4; i < len(rep); i++ {
		rep[i] ^= 0x5A
	}
	if f, _ := tr.ObserveIPv4(1e9, i02Frame(i02Emitter, i02Responder, 8, 0x0101, 1, req)); f {
		t.Fatal("requête : feu interdit")
	}
	f, r := tr.ObserveIPv4(1e9+700000, i02Frame(i02Responder, i02Emitter, 0, 0x0101, 1, rep))
	if !f || r != ReasonIC01ICMPEchoAsymmetry {
		t.Fatalf("réponse transformée : fired=%v reason=%q, attendu %q", f, r, ReasonIC01ICMPEchoAsymmetry)
	}
	// La réponse du noyau (identique) qui arrive aussi pour la même requête ne lève rien.
	if f, _ := tr.ObserveIPv4(1e9+900000, i02Frame(i02Responder, i02Emitter, 0, 0x0101, 1, req)); f {
		t.Error("réponse identique après la réponse transformée : feu interdit")
	}
}

func TestICMPEchoParityTracker_UnknownReplyIgnoredAndWindow(t *testing.T) {
	var tr ICMPEchoParityTracker
	payload := []byte("abcdefgh")
	if f, _ := tr.ObserveIPv4(1e9, i02Frame(i02Responder, i02Emitter, 0, 0x7777, 9, payload)); f {
		t.Error("réponse sans requête connue : feu interdit")
	}
	if f, _ := tr.ObserveIPv4(2e9, i02Frame(i02Emitter, i02Responder, 8, 0x7777, 10, payload)); f {
		t.Error("requête : feu interdit")
	}
	// Réponse différente 61 s plus tard : la requête est expirée (fenêtre 60 s), ignorée.
	altered := []byte("abcdefgX")
	if f, _ := tr.ObserveIPv4(63e9, i02Frame(i02Responder, i02Emitter, 0, 0x7777, 10, altered)); f {
		t.Error("requête expirée : feu interdit")
	}
	// Hors ICMP (UDP) ou IPv4 tronqué : ignoré sans panique.
	udp := i02Frame(i02Emitter, i02Responder, 8, 1, 1, payload)
	udp[9] = 17
	if f, _ := tr.ObserveIPv4(70e9, udp); f {
		t.Error("UDP : feu interdit")
	}
	if f, _ := tr.ObserveIPv4(71e9, udp[:15]); f {
		t.Error("tronqué : feu interdit")
	}
}

func TestICMPEchoParityTracker_ZeroAlloc(t *testing.T) {
	var tr ICMPEchoParityTracker
	payload := make([]byte, 56)
	req := i02Frame(i02Emitter, i02Responder, 8, 0x1111, 1, payload)
	rep := i02Frame(i02Responder, i02Emitter, 0, 0x1111, 1, payload)
	allocs := testing.AllocsPerRun(500, func() {
		tr.ObserveIPv4(1e9, req)
		tr.ObserveIPv4(1e9+1, rep)
	})
	if allocs != 0 {
		t.Errorf("%.2f allocs/op, attendu 0", allocs)
	}
}
