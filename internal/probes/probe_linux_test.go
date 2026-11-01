//go:build linux

package probes

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/hazyhaar/c2blue55"
)

func buildIPv4Frame(proto byte, srcPort, dstPort uint16, icmpType byte, payload []byte) []byte {
	frame := make([]byte, 0, 14+20+8+len(payload))
	frame = append(frame, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(payload)))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{8, 8, 8, 8})
	frame = append(frame, ip...)
	l4 := make([]byte, 8)
	if proto == ipProtoUDP {
		binary.BigEndian.PutUint16(l4[0:2], srcPort)
		binary.BigEndian.PutUint16(l4[2:4], dstPort)
		binary.BigEndian.PutUint16(l4[4:6], uint16(8+len(payload)))
	} else {
		l4[0] = icmpType
	}
	frame = append(frame, l4...)
	return append(frame, payload...)
}

func runBPF(prog []unix.SockFilter, pkt []byte) uint32 {
	var a, x uint32
	for pc := 0; pc >= 0 && pc < len(prog); {
		ins := prog[pc]
		switch ins.Code {
		case unix.BPF_LD | unix.BPF_H | unix.BPF_ABS:
			if int(ins.K)+2 > len(pkt) {
				return 0
			}
			a = uint32(binary.BigEndian.Uint16(pkt[ins.K:]))
		case unix.BPF_LD | unix.BPF_B | unix.BPF_ABS:
			if int(ins.K)+1 > len(pkt) {
				return 0
			}
			a = uint32(pkt[ins.K])
		case unix.BPF_LDX | unix.BPF_B | unix.BPF_MSH:
			if int(ins.K)+1 > len(pkt) {
				return 0
			}
			x = uint32(pkt[ins.K]&0x0f) * 4
		case unix.BPF_LD | unix.BPF_H | unix.BPF_IND:
			off := int(ins.K + x)
			if off+2 > len(pkt) {
				return 0
			}
			a = uint32(binary.BigEndian.Uint16(pkt[off:]))
		case unix.BPF_LD | unix.BPF_B | unix.BPF_IND:
			off := int(ins.K + x)
			if off+1 > len(pkt) {
				return 0
			}
			a = uint32(pkt[off])
		case unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K:
			if a == ins.K {
				pc += int(ins.Jt) + 1
			} else {
				pc += int(ins.Jf) + 1
			}
			continue
		case unix.BPF_RET | unix.BPF_K:
			return ins.K
		default:
			panic("instruction cBPF non prise en charge")
		}
		pc++
	}
	return 0
}

func TestDecodeDNSNoAlloc(t *testing.T) {
	payload := []byte{0xab, 0xcd, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e'}
	frame := buildIPv4Frame(ipProtoUDP, 40000, dnsPort, 0, payload)
	var ev c2blue55.Event
	if rc := DecodePacket(frame, 424242, &ev); rc != 0 {
		t.Fatalf("DNS rejete: rc=%d", rc)
	}
	if ev.Subsystem != c2blue55.SubNet || ev.Action != c2blue55.ActConnect {
		t.Fatalf("champs evenement incorrects: %+v", ev)
	}
	if ev.Ts_ns != 424242 {
		t.Fatalf("horodatage incorrect: %d", ev.Ts_ns)
	}
	if ev.Src != 0x0a000001 {
		t.Fatalf("source incorrecte: %#x", ev.Src)
	}
	if !bytes.Equal(ev.Payload[:len(payload)], payload) {
		t.Fatalf("charge utile alteree: %x", ev.Payload[:len(payload)])
	}
	allocs := testing.AllocsPerRun(1000, func() {
		DecodePacket(frame, 424242, &ev)
	})
	if allocs != 0 {
		t.Fatalf("allocations tas sur le decodage = %v, attendu 0", allocs)
	}
}

func TestDecodeICMPNoAlloc(t *testing.T) {
	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	frame := buildIPv4Frame(ipProtoICMP, 0, 0, icmpEchoRequest, payload)
	var ev c2blue55.Event
	if rc := DecodePacket(frame, 7, &ev); rc != 0 {
		t.Fatalf("ICMP Echo Request rejete: rc=%d", rc)
	}
	if !bytes.Equal(ev.Payload[:len(payload)], payload) {
		t.Fatalf("charge utile alteree: %x", ev.Payload[:len(payload)])
	}
	allocs := testing.AllocsPerRun(1000, func() {
		DecodePacket(frame, 7, &ev)
	})
	if allocs != 0 {
		t.Fatalf("allocations tas sur le decodage = %v, attendu 0", allocs)
	}
}

func TestDecodeRejectsNonDNSOrNonEcho(t *testing.T) {
	var ev c2blue55.Event
	cases := map[string][]byte{
		"udp_non_dns":      buildIPv4Frame(ipProtoUDP, 5000, 1234, 0, []byte{1}),
		"icmp_non_echo":    buildIPv4Frame(ipProtoICMP, 0, 0, 3, []byte{1}),
		"trop_court":       {0x08, 0x00},
		"ipv4_sans_charge": {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00},
	}
	for name, frame := range cases {
		if rc := DecodePacket(frame, 0, &ev); rc != -1 {
			t.Fatalf("%s: rc=%d, attendu -1", name, rc)
		}
	}
}

func TestFilterDNSICMP(t *testing.T) {
	prog := BuildFilterDNSICMP()
	accept := uint32(0xFFFFFFFF)
	cases := []struct {
		name string
		pkt  []byte
		want uint32
	}{
		{"dns_query", buildIPv4Frame(ipProtoUDP, 40000, 53, 0, []byte{1, 2, 3}), accept},
		{"dns_reply", buildIPv4Frame(ipProtoUDP, 53, 40000, 0, []byte{1, 2, 3}), accept},
		{"icmp_echo_request", buildIPv4Frame(ipProtoICMP, 0, 0, icmpEchoRequest, []byte{1}), accept},
		{"icmp_echo_reply", buildIPv4Frame(ipProtoICMP, 0, 0, icmpEchoReply, []byte{1}), accept},
		{"interdit", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x86, 0xdd, 0, 0, 0, 0}, 0},
		{"udp_non_dns", buildIPv4Frame(ipProtoUDP, 5000, 80, 0, []byte{1}), 0},
		{"icmp_autre", buildIPv4Frame(ipProtoICMP, 0, 0, 3, []byte{1}), 0},
	}
	for _, tc := range cases {
		if got := runBPF(prog, tc.pkt); got != tc.want {
			t.Fatalf("%s: verdict=%#x, attendu %#x", tc.name, got, tc.want)
		}
	}
}
