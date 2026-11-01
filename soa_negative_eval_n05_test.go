package c2blue55

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Strate N-05a : évaluateur hors ligne du canal SOA négatif sur une capture
// PCAP bidirectionnelle (type de lien 101, IPv4 brut, comme les captures de
// redhost). Il lit les octets filaires de chaque réponse et les passe au
// détecteur SOANegativeTracker (N-03), client = adresse IP destination de la
// réponse. Le rapport compte les réponses, les négatives porteuses de SOA, les
// feux et le rang du premier feu.

type n05SOA struct {
	mname, rname string
	serial       uint32
}

func n05Name(name string, dst []byte) int {
	off, start := 0, 0
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

func n05Query(id uint16, qname string) []byte {
	b := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], 0x0100)
	binary.BigEndian.PutUint16(b[4:6], 1)
	var tmp [300]byte
	n := n05Name(qname, tmp[:])
	b = append(b, tmp[:n]...)
	return append(b, 0, 1, 0, 1)
}

func n05Negative(id uint16, qname string, rcode uint8, soa *n05SOA) []byte {
	b := n05Query(id, qname)
	binary.BigEndian.PutUint16(b[2:4], 0x8400|uint16(rcode))
	if soa == nil {
		return b
	}
	binary.BigEndian.PutUint16(b[8:10], 1)
	dot := 0
	for dot < len(qname) && qname[dot] != '.' {
		dot++
	}
	parentOff := uint16(12 + 1 + dot)
	b = append(b, 0xC0|byte(parentOff>>8), byte(parentOff), 0, 6, 0, 1, 0, 0, 0, 1)
	var tmp [300]byte
	rd := make([]byte, 0, 600)
	n := n05Name(soa.mname, tmp[:])
	rd = append(rd, tmp[:n]...)
	n = n05Name(soa.rname, tmp[:])
	rd = append(rd, tmp[:n]...)
	u := make([]byte, 20)
	binary.BigEndian.PutUint32(u[0:4], soa.serial)
	binary.BigEndian.PutUint32(u[4:8], 3600)
	binary.BigEndian.PutUint32(u[8:12], 900)
	binary.BigEndian.PutUint32(u[12:16], 604800)
	binary.BigEndian.PutUint32(u[16:20], 1)
	rd = append(rd, u...)
	b = append(b, byte(len(rd)>>8), byte(len(rd)))
	return append(b, rd...)
}

// n05Frame construit une trame IPv4 brut + UDP (type de lien 101).
func n05Frame(src, dst [4]byte, sport, dport uint16, payload []byte) []byte {
	total := 20 + 8 + len(payload)
	f := make([]byte, total)
	f[0] = 0x45
	binary.BigEndian.PutUint16(f[2:4], uint16(total))
	f[8] = 64
	f[9] = 17
	copy(f[12:16], src[:])
	copy(f[16:20], dst[:])
	binary.BigEndian.PutUint16(f[20:22], sport)
	binary.BigEndian.PutUint16(f[22:24], dport)
	binary.BigEndian.PutUint16(f[24:26], uint16(8+len(payload)))
	copy(f[28:], payload)
	return f
}

func n05WritePCAP(t *testing.T, path string, frames [][]byte, tsUs []uint64) {
	t.Helper()
	out := make([]byte, 24)
	binary.LittleEndian.PutUint32(out[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(out[4:6], 2)
	binary.LittleEndian.PutUint16(out[6:8], 4)
	binary.LittleEndian.PutUint32(out[16:20], 262144)
	binary.LittleEndian.PutUint32(out[20:24], 101)
	for i, fr := range frames {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], uint32(tsUs[i]/1_000_000))
		binary.LittleEndian.PutUint32(rec[4:8], uint32(tsUs[i]%1_000_000))
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(fr)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(len(fr)))
		out = append(out, rec...)
		out = append(out, fr...)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

var (
	n05Client   = [4]byte{10, 55, 0, 2}
	n05Resolver = [4]byte{10, 55, 0, 1}
)

func n05Capture(t *testing.T, dir string, hostile bool) string {
	t.Helper()
	var frames [][]byte
	var ts []uint64
	base := uint64(1_793_300_000_000_000)
	soaConst := &n05SOA{mname: "ns1.lab.pound2pound.fr", rname: "hostmaster.lab.pound2pound.fr", serial: 2026102901}
	for i := range 6 {
		qname := "nx-" + string(rune('a'+i)) + ".lab.pound2pound.fr"
		soa := soaConst
		if hostile {
			soa = &n05SOA{mname: "m" + string(rune('a'+i)) + "0.lab.pound2pound.fr", rname: "r" + string(rune('a'+i)) + "0.lab.pound2pound.fr", serial: uint32(1000 + i)}
		}
		q := n05Query(uint16(0x700+i), qname)
		r := n05Negative(uint16(0x700+i), qname, 3, soa)
		sport := uint16(40000 + i)
		frames = append(frames, n05Frame(n05Client, n05Resolver, sport, 53, q), n05Frame(n05Resolver, n05Client, 53, sport, r))
		ts = append(ts, base+uint64(i)*1_000_000, base+uint64(i)*1_000_000+20_000)
	}
	// Une réponse positive (A) au milieu, à ignorer.
	q := n05Query(0x7FF, "cdn.lab.pound2pound.fr")
	r := append([]byte{}, q...)
	binary.BigEndian.PutUint16(r[2:4], 0x8400)
	binary.BigEndian.PutUint16(r[6:8], 1)
	r = append(r, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4, 10, 55, 0, 1)
	frames = append(frames, n05Frame(n05Client, n05Resolver, 41000, 53, q), n05Frame(n05Resolver, n05Client, 53, 41000, r))
	ts = append(ts, base+7_000_000, base+7_020_000)
	name := "benin.pcap"
	if hostile {
		name = "stego.pcap"
	}
	path := filepath.Join(dir, name)
	n05WritePCAP(t, path, frames, ts)
	return path
}

func TestEvaluateSOANegativePCAP_BenignAndStego(t *testing.T) {
	dir := t.TempDir()
	benin := n05Capture(t, dir, false)
	stego := n05Capture(t, dir, true)

	rb, err := EvaluateSOANegativePCAP(benin)
	if err != nil {
		t.Fatalf("bénin : %v", err)
	}
	if rb.Responses != 7 || rb.NegativeWithSOA != 6 || rb.Fires != 0 || rb.FiredKeys != 0 {
		t.Errorf("bénin : %+v, attendu Responses=7 NegativeWithSOA=6 Fires=0 FiredKeys=0", rb)
	}

	rs, err := EvaluateSOANegativePCAP(stego)
	if err != nil {
		t.Fatalf("stego : %v", err)
	}
	// Six empreintes distinctes : feu dès la troisième réponse négative, puis à chaque suivante (4 feux), une seule clé.
	if rs.Responses != 7 || rs.NegativeWithSOA != 6 || rs.Fires != 4 || rs.FiredKeys != 1 {
		t.Errorf("stego : %+v, attendu Responses=7 NegativeWithSOA=6 Fires=4 FiredKeys=1", rs)
	}
	if rs.PacketsToFirstFire != 6 {
		t.Errorf("stego : PacketsToFirstFire = %d, attendu 6 (3e réponse = 6e paquet)", rs.PacketsToFirstFire)
	}
	if rs.FirstFireTsNs != 1_793_300_000_000_000*1000+2_020_000*1000 {
		t.Errorf("stego : FirstFireTsNs = %d", rs.FirstFireTsNs)
	}
}

func TestReadPCAPDNSWire_YieldsRawPayloads(t *testing.T) {
	dir := t.TempDir()
	path := n05Capture(t, dir, false)
	packetCount := 0
	var lastLen int
	stats, err := ReadPCAPDNSWire(path, func(meta PCAPMessageMeta, wire []byte) error {
		packetCount++
		lastLen = len(wire)
		if len(wire) < 12 {
			t.Fatalf("charge DNS de %d octets", len(wire))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if packetCount != 14 || stats.TotalPackets != 14 || lastLen < 12 {
		t.Errorf("count=%d stats=%+v lastLen=%d, attendu 14 messages", packetCount, stats, lastLen)
	}
}

func TestEvaluateSOANegativePCAP_Refusals(t *testing.T) {
	if _, err := EvaluateSOANegativePCAP(filepath.Join(t.TempDir(), "absent.pcap")); err == nil {
		t.Error("fichier absent : erreur attendue")
	}
}
