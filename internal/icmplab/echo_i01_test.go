package icmplab_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/icmplab"
)

// Strate I-01 : fonctions filaires du tunnel ICMP Echo de laboratoire
// (RFC 792) : construction d'un Echo (type 8 ou 0) avec somme de contrôle,
// analyse avec vérification de la somme, transformation de charge utile
// (réponse asymétrique du répondeur de laboratoire) et empreinte FNV-1a.
// Le bénin de référence est le ping ordinaire : la réponse porte la charge
// utile identique ; le tunnel de laboratoire la transforme.

func checksumRFC1071(b []byte) uint16 {
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

func TestBuildEcho_HeaderChecksumAndBounds(t *testing.T) {
	var dst [1500]byte
	payload := []byte("c2il\x00\x00\x00\x01hello")
	n, err := icmplab.BuildEcho(8, 0x1234, 7, payload, dst[:])
	if err != nil {
		t.Fatal(err)
	}
	if n != 8+len(payload) {
		t.Fatalf("longueur %d, attendu %d", n, 8+len(payload))
	}
	if dst[0] != 8 || dst[1] != 0 || binary.BigEndian.Uint16(dst[4:6]) != 0x1234 || binary.BigEndian.Uint16(dst[6:8]) != 7 {
		t.Errorf("en-tête = % x", dst[:8])
	}
	if checksumRFC1071(dst[:n]) != 0 {
		t.Errorf("somme de contrôle invalide (vérification RFC 1071 non nulle : %#x)", checksumRFC1071(dst[:n]))
	}
	if _, err := icmplab.BuildEcho(3, 1, 1, payload, dst[:]); !errors.Is(err, icmplab.ErrEchoContract) {
		t.Errorf("type 3 : err = %v, attendu ErrEchoContract", err)
	}
	if _, err := icmplab.BuildEcho(8, 1, 1, make([]byte, 1401), dst[:]); !errors.Is(err, icmplab.ErrEchoContract) {
		t.Errorf("charge de 1401 octets : err = %v, attendu ErrEchoContract", err)
	}
	if _, err := icmplab.BuildEcho(8, 1, 1, payload, dst[:10]); !errors.Is(err, icmplab.ErrEchoContract) {
		t.Errorf("tampon trop court : err = %v, attendu ErrEchoContract", err)
	}
}

func TestParseEcho_RoundTripAndRefusals(t *testing.T) {
	var dst [1500]byte
	payload := []byte("c2il\x00\x00\x00\x02data")
	n, _ := icmplab.BuildEcho(0, 0xBEEF, 42, payload, dst[:])
	var v icmplab.EchoView
	if err := icmplab.ParseEcho(dst[:n], &v); err != nil {
		t.Fatal(err)
	}
	if v.Type != 0 || v.Code != 0 || v.ID != 0xBEEF || v.Seq != 42 || string(v.Payload) != string(payload) || !v.ChecksumOK {
		t.Errorf("vue = %+v", v)
	}
	corrupt := append([]byte(nil), dst[:n]...)
	corrupt[n-1] ^= 0xFF
	if err := icmplab.ParseEcho(corrupt, &v); err != nil || v.ChecksumOK {
		t.Errorf("charge altérée : err=%v ChecksumOK=%v, attendu nil et false", err, v.ChecksumOK)
	}
	if err := icmplab.ParseEcho(dst[:7], &v); !errors.Is(err, icmplab.ErrEchoContract) {
		t.Errorf("7 octets : err = %v", err)
	}
	other := append([]byte(nil), dst[:n]...)
	other[0] = 11 // Time Exceeded
	if err := icmplab.ParseEcho(other, &v); !errors.Is(err, icmplab.ErrEchoContract) {
		t.Errorf("type 11 : err = %v, attendu ErrEchoContract", err)
	}
}

func TestTransformPayload_DeterministicInvertibleAndDifferent(t *testing.T) {
	in := []byte("c2il\x00\x00\x00\x03the quick brown fox")
	out := make([]byte, len(in))
	back := make([]byte, len(in))
	if n := icmplab.TransformPayload(0x5EED, in, out); n != len(in) {
		t.Fatalf("n = %d", n)
	}
	if string(out) == string(in) {
		t.Fatal("la transformation doit changer la charge utile")
	}
	if string(out[:4]) != "c2il" {
		t.Errorf("le préfixe de laboratoire doit être conservé : %q", out[:4])
	}
	icmplab.TransformPayload(0x5EED, out, back)
	if string(back) != string(in) {
		t.Errorf("transformation non involutive : %q", back)
	}
	out2 := make([]byte, len(in))
	icmplab.TransformPayload(0x5EED, in, out2)
	if string(out2) != string(out) {
		t.Error("transformation non déterministe")
	}
	out3 := make([]byte, len(in))
	icmplab.TransformPayload(0x5EEE, in, out3)
	if string(out3) == string(out) {
		t.Error("la clé doit changer la sortie")
	}
	if icmplab.FNV1aPayload(in) == icmplab.FNV1aPayload(out) {
		t.Error("les empreintes de la requête et de la réponse transformée doivent différer")
	}
	if icmplab.FNV1aPayload(in) != icmplab.FNV1aPayload(append([]byte(nil), in...)) {
		t.Error("empreinte non déterministe")
	}
}

func TestTransformPayload_ZeroAlloc(t *testing.T) {
	in := make([]byte, 512)
	out := make([]byte, 512)
	var dst [1500]byte
	var v icmplab.EchoView
	allocs := testing.AllocsPerRun(200, func() {
		icmplab.TransformPayload(1, in, out)
		n, _ := icmplab.BuildEcho(8, 1, 1, out, dst[:])
		_ = icmplab.ParseEcho(dst[:n], &v)
		_ = icmplab.FNV1aPayload(v.Payload)
	})
	if allocs != 0 {
		t.Errorf("%.2f allocs/op, attendu 0", allocs)
	}
}
