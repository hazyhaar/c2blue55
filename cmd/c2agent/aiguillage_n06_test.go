package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Strate N-06 : le binaire c2agent expose ses modes hors ligne par une
// sous-commande en premier argument : `c2agent ingest --pcap … [--manifest …]
// [--audit-out …]` appelle RunAgentCLI, `c2agent record …` appelle
// RunAgentRecordCLI ; sans sous-commande, main() garde son mode d'écoute.
// S-14b avait livré RunAgentCLI sans le brancher dans main.

func n06WritePCAP(t *testing.T, path string, frames [][]byte) {
	t.Helper()
	out := make([]byte, 24)
	binary.LittleEndian.PutUint32(out[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(out[4:6], 2)
	binary.LittleEndian.PutUint16(out[6:8], 4)
	binary.LittleEndian.PutUint32(out[16:20], 262144)
	binary.LittleEndian.PutUint32(out[20:24], 1)
	for i, fr := range frames {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], uint32(1_700_000_000+i))
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(fr)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(len(fr)))
		out = append(out, rec...)
		out = append(out, fr...)
	}
	if err := os.WriteFile(path, out, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestAiguillerCommande_IngestEtRecord(t *testing.T) {
	dir := t.TempDir()
	q := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(q[0:2], 0x1234)
	binary.BigEndian.PutUint16(q[2:4], 0x0100)
	binary.BigEndian.PutUint16(q[4:6], 1)
	q = append(q, buildCLIDNSName("www.example.com")...)
	q = append(q, 0, 1, 0, 1)
	pcap := filepath.Join(dir, "q.pcap")
	n06WritePCAP(t, pcap, [][]byte{buildCLIEthUDPFrame(40000, 53, q)})
	audit := filepath.Join(dir, "audit.jsonl")

	pris, code := aiguillerCommande([]string{"ingest", "--pcap", pcap, "--audit-out", audit})
	if !pris || code != 0 {
		t.Fatalf("ingest : pris=%v code=%d", pris, code)
	}
	if _, err := os.Stat(audit); err != nil {
		t.Fatalf("journal d'audit absent après ingest : %v", err)
	}
	if pris, code := aiguillerCommande([]string{"ingest", "--pcap", filepath.Join(dir, "absent.pcap")}); !pris || code == 0 {
		t.Errorf("ingest sur capture absente : pris=%v code=%d, attendu pris et code != 0", pris, code)
	}
	if pris, _ := aiguillerCommande([]string{"record", "--pcap", filepath.Join(dir, "absent.pcap"), "--record-dir", dir}); !pris {
		t.Error("record doit être pris en charge")
	}
	if pris, _ := aiguillerCommande([]string{"-listen", "127.0.0.1:5353"}); pris {
		t.Error("un drapeau du mode écoute n'est pas une sous-commande")
	}
	if pris, _ := aiguillerCommande(nil); pris {
		t.Error("sans argument : mode écoute")
	}
	if pris, code := aiguillerCommande([]string{"inconnue"}); !pris || code != 2 {
		t.Errorf("sous-commande inconnue : pris=%v code=%d, attendu pris et 2", pris, code)
	}
}
