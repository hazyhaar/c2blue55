package c2blue55

import (
	"encoding/binary"
	"path/filepath"
	"testing"
)

// Strate A-03 : évaluateur hors ligne du canal AAAA IID. EvaluateAAAAIIDPCAP
// rejoue les réponses UDP/53 d'une capture dans engine.AAAAIIDTracker avec
// client = adresse de destination de la réponse. Responses = messages QR=1,
// AAAAAnswers = enregistrements de type 28 dans les sections réponse,
// Fires = réponses ayant déclenché, FiredKeys = couples (destination,
// préfixe /64 du premier AAAA) distincts ayant déclenché, PacketsToFirstFire =
// rang (1-indexé, tous paquets) du premier feu, FirstFireTsNs son horodatage.

func a03Response(id uint16, qname string, typ uint16, rdatas ...[]byte) []byte {
	b := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(b[0:2], id)
	binary.BigEndian.PutUint16(b[2:4], 0x8180)
	binary.BigEndian.PutUint16(b[4:6], 1)
	binary.BigEndian.PutUint16(b[6:8], uint16(len(rdatas)))
	var tmp [300]byte
	n := n05Name(qname, tmp[:])
	b = append(b, tmp[:n]...)
	b = append(b, byte(typ>>8), byte(typ), 0, 1)
	for _, rd := range rdatas {
		b = append(b, 0xC0, 0x0C, byte(typ>>8), byte(typ), 0, 1, 0, 0, 0, 0, byte(len(rd)>>8), byte(len(rd)))
		b = append(b, rd...)
	}
	return b
}

func a03AAAA(prefix [8]byte, iid uint64) []byte {
	out := make([]byte, 16)
	copy(out, prefix[:])
	binary.BigEndian.PutUint64(out[8:], iid)
	return out
}

func TestEvaluateAAAAIIDPCAP_StegoFiresAtEighthResponse(t *testing.T) {
	dir := t.TempDir()
	client, server := [4]byte{10, 55, 0, 2}, [4]byte{10, 55, 0, 1}
	c2 := [8]byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x55, 0, 0}
	cf := [8]byte{0x26, 0x06, 0x47, 0x00, 0, 0, 0, 0}
	var frames [][]byte
	var ts []uint64
	base := uint64(1_793_300_000_000_000)
	add := func(src, dst [4]byte, sport, dport uint16, payload []byte) {
		frames = append(frames, n05Frame(src, dst, sport, dport, payload))
		ts = append(ts, base+uint64(len(ts))*100_000)
	}
	// 5 couples bénins (pool à octets nuls), paquets 1-10.
	for i := range 5 {
		add(client, server, 40000+uint16(i), 53, n05Query(uint16(i), "site.example"))
		add(server, client, 53, 40000+uint16(i), a03Response(uint16(i), "site.example", 28, a03AAAA(cf, 0x68107c60+uint64(i))))
	}
	// 1 couple A, paquets 11-12.
	add(client, server, 41000, 53, n05Query(100, "a.example"))
	add(server, client, 53, 41000, a03Response(100, "a.example", 1, []byte{10, 55, 0, 1}))
	// 10 couples stego à identifiants pleine largeur distincts, paquets 13-32 ; 8e réponse = paquet 28.
	for i := range 10 {
		iid := uint64(0x1111111111111111)*uint64(1+i) ^ 0x0101010101010101
		add(client, server, 42000+uint16(i), 53, n05Query(200+uint16(i), "beacon.lab.pound2pound.fr"))
		add(server, client, 53, 42000+uint16(i), a03Response(200+uint16(i), "beacon.lab.pound2pound.fr", 28, a03AAAA(c2, iid)))
	}
	path := filepath.Join(dir, "stego.pcap")
	n05WritePCAP(t, path, frames, ts)
	rep, err := EvaluateAAAAIIDPCAP(path)
	if err != nil {
		t.Fatal(err)
	}
	want := AAAAIIDEvalReport{Responses: 16, AAAAAnswers: 15, Fires: 3, FiredKeys: 1, PacketsToFirstFire: 28, FirstFireTsNs: (base + 27*100_000) * 1000}
	if rep != want {
		t.Errorf("rapport = %+v\n   attendu %+v", rep, want)
	}
}

func TestEvaluateAAAAIIDPCAP_BenignWorkstationCaptureNoFire(t *testing.T) {
	rep, err := EvaluateAAAAIIDPCAP("testdata/a03-20261029/poste-aaaa-benin-20261029T170630Z.pcap")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Responses < 100 || rep.AAAAAnswers < 300 {
		t.Errorf("capture bénigne : Responses=%d AAAAAnswers=%d, attendus ≥ 100 et ≥ 300", rep.Responses, rep.AAAAAnswers)
	}
	if rep.Fires != 0 || rep.FiredKeys != 0 || rep.PacketsToFirstFire != 0 || rep.FirstFireTsNs != 0 {
		t.Errorf("capture bénigne du poste : %+v, attendu aucun feu", rep)
	}
}

func TestEvaluateAAAAIIDPCAP_Refusals(t *testing.T) {
	if _, err := EvaluateAAAAIIDPCAP(filepath.Join(t.TempDir(), "absent.pcap")); err == nil {
		t.Error("fichier absent : aucune erreur")
	}
}
