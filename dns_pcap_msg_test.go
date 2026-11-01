package c2blue55

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pcapDNSName(name string) []byte {
	var b []byte
	for label := range strings.SplitSeq(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0)
}

func pcapDNSHeader(flags, anCount uint16) []byte {
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[0:], 0x1234)
	binary.BigEndian.PutUint16(h[2:], flags)
	binary.BigEndian.PutUint16(h[4:], 1)
	binary.BigEndian.PutUint16(h[6:], anCount)
	return h
}

func pcapEthFrame(sport, dport uint16, payload []byte) []byte {
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

func TestReadPCAPDNSMessages(t *testing.T) {
	qwire := append(pcapDNSName("api.hazyhaar.fr"), 0, 16, 0, 1)
	query := append(pcapDNSHeader(0x0100, 0), qwire...)

	rdata := append([]byte{199}, strings.Repeat("a", 199)...)
	reply := append(pcapDNSHeader(0x8180, 1), qwire...)
	reply = append(reply, 0xc0, 0x0c)
	reply = binary.BigEndian.AppendUint16(reply, 16)
	reply = binary.BigEndian.AppendUint16(reply, 1)
	reply = binary.BigEndian.AppendUint32(reply, 60)
	reply = binary.BigEndian.AppendUint16(reply, uint16(len(rdata)))
	reply = append(reply, rdata...)

	pkts := [][]byte{
		pcapEthFrame(40000, 53, query),
		pcapEthFrame(53, 40000, reply),
		pcapEthFrame(40000, 53, make([]byte, 5)),
	}

	pcap := make([]byte, 24)
	binary.LittleEndian.PutUint32(pcap[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(pcap[4:], 2)
	binary.LittleEndian.PutUint16(pcap[6:], 4)
	binary.LittleEndian.PutUint32(pcap[16:], 65535)
	binary.LittleEndian.PutUint32(pcap[20:], 1)
	for i, pkt := range pkts {
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:], 1700000000)
		binary.LittleEndian.PutUint32(rec[4:], uint32(i))
		binary.LittleEndian.PutUint32(rec[8:], uint32(len(pkt)))
		binary.LittleEndian.PutUint32(rec[12:], uint32(len(pkt)))
		pcap = append(pcap, rec...)
		pcap = append(pcap, pkt...)
	}

	path := filepath.Join(t.TempDir(), "dns.pcap")
	if err := os.WriteFile(path, pcap, 0o600); err != nil {
		t.Fatal(err)
	}

	var sawQuery, sawReply bool
	stats, err := ReadPCAPDNSMessages(path, func(meta PCAPMessageMeta, msg *DNSMessage) error {
		if !msg.IsResponse {
			sawQuery = true
			return nil
		}
		sawReply = msg.AnswerCount == 1 && msg.Answers[0].RDataLen == 200
		return nil
	})
	if err != nil {
		t.Fatalf("ReadPCAPDNSMessages : %v", err)
	}
	if stats.DecodedQueries != 1 || stats.DecodedReplies != 1 || stats.MalformedCount != 1 {
		t.Errorf("stats = %+v, attendu 1 requête, 1 réponse, 1 malformé", stats)
	}
	if !sawQuery || !sawReply {
		t.Errorf("visit : requête=%v réponse=%v", sawQuery, sawReply)
	}

	missing := filepath.Join(t.TempDir(), "absent.pcap")
	if _, err := ReadPCAPDNSMessages(missing, func(PCAPMessageMeta, *DNSMessage) error { return nil }); err == nil {
		t.Error("erreur attendue pour un chemin inexistant")
	}
}
