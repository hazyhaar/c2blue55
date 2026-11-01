package main

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildCLIDNSName(name string) []byte {
	var b []byte
	for label := range strings.SplitSeq(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0)
}

func buildCLIEthUDPFrame(sport, dport uint16, payload []byte) []byte {
	f := make([]byte, 42)
	binary.BigEndian.PutUint16(f[12:], 0x0800)
	ip := f[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(28+len(payload)))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	udp := f[34:42]
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	return append(f, payload...)
}

func TestAgentCLIFullPCAP(t *testing.T) {
	dir := t.TempDir()

	// Scénario hostile SH-S14b-01 : fichier absent ou PCAP tronqué
	if rc := RunAgentCLI([]string{"--pcap", filepath.Join(dir, "absent.pcap")}); rc == 0 {
		t.Error("SH-S14b-01 : code de retour 0 inattendu pour un PCAP absent")
	}

	truncatedPath := filepath.Join(dir, "truncated.pcap")
	if err := os.WriteFile(truncatedPath, []byte{0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00}, 0o600); err != nil {
		t.Fatal(err)
	}
	if rc := RunAgentCLI([]string{"--pcap", truncatedPath}); rc == 0 {
		t.Error("SH-S14b-01 : code de retour 0 inattendu pour un PCAP tronqué")
	}

	// PCAP valide avec requête et réponse DNS
	qwire := append(buildCLIDNSName("api.hazyhaar.fr"), 0, 1, 0, 1)
	hdrQ := make([]byte, 12)
	binary.BigEndian.PutUint16(hdrQ[0:], 0x4242)
	binary.BigEndian.PutUint16(hdrQ[2:], 0x0100)
	binary.BigEndian.PutUint16(hdrQ[4:], 1)
	query := append(hdrQ, qwire...)

	hdrR := make([]byte, 12)
	binary.BigEndian.PutUint16(hdrR[0:], 0x4242)
	binary.BigEndian.PutUint16(hdrR[2:], 0x8180)
	binary.BigEndian.PutUint16(hdrR[4:], 1)
	binary.BigEndian.PutUint16(hdrR[6:], 1)
	reply := append(hdrR, qwire...)
	reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4)

	pcap := make([]byte, 24)
	binary.LittleEndian.PutUint32(pcap[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(pcap[4:], 2)
	binary.LittleEndian.PutUint16(pcap[6:], 4)
	binary.LittleEndian.PutUint32(pcap[16:], 65535)
	binary.LittleEndian.PutUint32(pcap[20:], 1)
	for i, pkt := range [][]byte{
		buildCLIEthUDPFrame(41000, 53, query),
		buildCLIEthUDPFrame(53, 41000, reply),
	} {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:], 1700000000+uint32(i))
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(pkt)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(pkt)))
		pcap = append(pcap, rec...)
		pcap = append(pcap, pkt...)
	}

	pcapPath := filepath.Join(dir, "valid.pcap")
	if err := os.WriteFile(pcapPath, pcap, 0o600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(dir, "audit.jsonl")

	if rc := RunAgentCLI([]string{"--pcap", pcapPath, "--audit-out", auditPath}); rc != 0 {
		t.Fatalf("RunAgentCLI sur PCAP valide : rc = %d, attendu 0", rc)
	}
	info, err := os.Stat(auditPath)
	if err != nil || info.Size() == 0 {
		t.Fatalf("fichier d'audit %s absent ou vide : err=%v", auditPath, err)
	}
}
