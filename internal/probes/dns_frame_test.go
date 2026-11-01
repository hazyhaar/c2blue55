//go:build linux

package probes

import (
	"encoding/binary"
	"testing"
)

func buildDNSFrame(ipv6 bool, srcPort, dstPort uint16, payload []byte) []byte {
	udp := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], dstPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	udp = append(udp, payload...)

	frame := make([]byte, 12)
	if ipv6 {
		frame = binary.BigEndian.AppendUint16(frame, 0x86DD)
		ip := make([]byte, 40)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:], uint16(len(udp)))
		ip[6] = 17
		ip[7] = 64
		frame = append(frame, ip...)
	} else {
		frame = binary.BigEndian.AppendUint16(frame, 0x0800)
		ip := make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)))
		ip[8] = 64
		ip[9] = 17
		frame = append(frame, ip...)
	}
	return append(frame, udp...)
}

func TestDecodeDNSFrame(t *testing.T) {
	var meta DNSFrameMeta

	resp := buildDNSFrame(false, 53, 51234, make([]byte, 380))
	p, code := DecodeDNSFrame(resp, 1, &meta)
	if code != 0 || len(p) != 380 || !meta.IsResponse || meta.SrcPort != 53 {
		t.Fatalf("réponse IPv4: code=%d len=%d meta=%+v", code, len(p), meta)
	}

	req := buildDNSFrame(true, 49152, 53, make([]byte, 64))
	meta = DNSFrameMeta{}
	p, code = DecodeDNSFrame(req, 2, &meta)
	if code != 0 || len(p) != 64 || !meta.IsIPv6 || meta.IsResponse {
		t.Fatalf("requête IPv6: code=%d len=%d meta=%+v", code, len(p), meta)
	}

	other := buildDNSFrame(false, 8080, 443, make([]byte, 32))
	for _, f := range [][]byte{other, resp[:30]} {
		if p, code := DecodeDNSFrame(f, 3, &meta); p != nil || code != -1 {
			t.Fatalf("attendu (nil,-1), obtenu len=%d code=%d", len(p), code)
		}
	}

	if allocs := testing.AllocsPerRun(100, func() {
		DecodeDNSFrame(resp, 4, &meta)
	}); allocs != 0 {
		t.Fatalf("allocations: %v/op, attendu 0", allocs)
	}
}
