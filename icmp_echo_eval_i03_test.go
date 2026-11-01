package c2blue55

import (
	"encoding/binary"
	"path/filepath"
	"testing"
)

// Strate I-03 : évaluateur hors ligne du détecteur d'asymétrie Echo ICMP sur
// une capture PCAP (type de lien 101 IPv4 brut, ou 1 Ethernet). Rapport :
// paquets IPv4 lus, requêtes Echo, réponses Echo, réponses asymétriques
// (feux), rang et horodatage du premier feu. Les trames sont construites ici.

func i03Checksum(b []byte) uint16 {
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

func i03Frame(src, dst [4]byte, typ uint8, id, seq uint16, payload []byte) []byte {
	icmp := make([]byte, 8+len(payload))
	icmp[0] = typ
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], i03Checksum(icmp))
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

func TestEvaluateICMPEchoPCAP_PingAndTunnel(t *testing.T) {
	dir := t.TempDir()
	client, server := [4]byte{10, 55, 0, 2}, [4]byte{10, 55, 0, 1}
	var frames [][]byte
	var ts []uint64
	base := uint64(1_793_300_000_000_000)
	payload := make([]byte, 56)
	for i := range payload {
		payload[i] = byte(i)
	}
	// Dix pings ordinaires : réponses identiques.
	for seq := uint16(1); seq <= 10; seq++ {
		frames = append(frames, i03Frame(client, server, 8, 0x4242, seq, payload), i03Frame(server, client, 0, 0x4242, seq, payload))
		ts = append(ts, base+uint64(seq)*200_000, base+uint64(seq)*200_000+300)
	}
	// Cinq échanges du tunnel : réponse transformée, puis réponse du noyau identique.
	for seq := uint16(1); seq <= 5; seq++ {
		req := append([]byte("c2il\x00\x00\x00"), byte(seq))
		req = append(req, payload[:24]...)
		rep := append([]byte(nil), req...)
		for i := 4; i < len(rep); i++ {
			rep[i] ^= 0x5A
		}
		frames = append(frames, i03Frame(client, server, 8, 0x0101, seq, req), i03Frame(server, client, 0, 0x0101, seq, rep), i03Frame(server, client, 0, 0x0101, seq, req))
		ts = append(ts, base+5_000_000+uint64(seq)*200_000, base+5_000_000+uint64(seq)*200_000+200, base+5_000_000+uint64(seq)*200_000+400)
	}
	path := filepath.Join(dir, "icmp.pcap")
	n05WritePCAP(t, path, frames, ts)
	rep, err := EvaluateICMPEchoPCAP(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.IPv4Packets != 35 || rep.EchoRequests != 15 || rep.EchoReplies != 20 || rep.Fires != 5 || rep.PacketsToFirstFire != 22 {
		t.Errorf("rapport = %+v, attendu IPv4Packets=35 EchoRequests=15 EchoReplies=20 Fires=5 PacketsToFirstFire=22", rep)
	}
	if rep.FirstFireTsNs != (base+5_000_000+200_000+200)*1000 {
		t.Errorf("FirstFireTsNs = %d", rep.FirstFireTsNs)
	}
	// Capture sans tunnel : zéro feu.
	pingOnly := filepath.Join(dir, "ping.pcap")
	n05WritePCAP(t, pingOnly, frames[:20], ts[:20])
	rep2, err := EvaluateICMPEchoPCAP(pingOnly)
	if err != nil {
		t.Fatal(err)
	}
	if rep2.Fires != 0 || rep2.EchoRequests != 10 || rep2.EchoReplies != 10 {
		t.Errorf("ping seul : %+v", rep2)
	}
}

func TestEvaluateICMPEchoPCAP_Refusals(t *testing.T) {
	if _, err := EvaluateICMPEchoPCAP(filepath.Join(t.TempDir(), "absent.pcap")); err == nil {
		t.Error("fichier absent : erreur attendue")
	}
}
