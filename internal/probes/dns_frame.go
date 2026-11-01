//go:build linux

package probes

import "encoding/binary"

const (
	DNSFrameCap = 512
	ethTypeIPv6 = 0x86DD
)

// DNSFrameMeta décrit les champs utiles d'une trame DNS décodée.
type DNSFrameMeta struct {
	TimestampNs uint64
	SrcIP       [16]byte
	DstIP       [16]byte
	SrcPort     uint16
	DstPort     uint16
	IsIPv6      bool
	IsResponse  bool
}

// DecodeDNSFrame extrait le payload DNS UDP d'une trame Ethernet, sans allocation.
// Retourne (nil, -1) si la trame n'est pas un paquet DNS UDP exploitable.
func DecodeDNSFrame(frame []byte, tsNs uint64, meta *DNSFrameMeta) ([]byte, int) {
	if meta == nil || len(frame) < ethHdrLen {
		return nil, -1
	}

	etherType := binary.BigEndian.Uint16(frame[12:14])
	ipOff := ethHdrLen
	for etherType == ethTypeVLAN {
		if len(frame) < ipOff+4 {
			return nil, -1
		}
		etherType = binary.BigEndian.Uint16(frame[ipOff+2 : ipOff+4])
		ipOff += 4
	}

	var src, dst [16]byte
	var l4 int
	var isIPv6 bool

	switch etherType {
	case ethTypeIPv4:
		if len(frame) < ipOff+20 {
			return nil, -1
		}
		ihl := int(frame[ipOff]&0x0f) * 4
		if ihl < 20 || len(frame) < ipOff+ihl || frame[ipOff+9] != ipProtoUDP {
			return nil, -1
		}
		copy(src[:4], frame[ipOff+12:ipOff+16])
		copy(dst[:4], frame[ipOff+16:ipOff+20])
		l4 = ipOff + ihl

	case ethTypeIPv6:
		if len(frame) < ipOff+40 || frame[ipOff+6] != ipProtoUDP {
			return nil, -1
		}
		copy(src[:], frame[ipOff+8:ipOff+24])
		copy(dst[:], frame[ipOff+24:ipOff+40])
		isIPv6 = true
		l4 = ipOff + 40

	default:
		return nil, -1
	}

	if len(frame) < l4+8 {
		return nil, -1
	}
	srcPort := binary.BigEndian.Uint16(frame[l4 : l4+2])
	dstPort := binary.BigEndian.Uint16(frame[l4+2 : l4+4])
	udpLen := int(binary.BigEndian.Uint16(frame[l4+4 : l4+6]))
	if (srcPort != dnsPort && dstPort != dnsPort) || udpLen < 8 {
		return nil, -1
	}

	n := udpLen - 8
	if len(frame)-(l4+8) < n {
		return nil, -1
	}
	payload := frame[l4+8 : l4+8+n]
	if len(payload) > DNSFrameCap {
		payload = payload[:DNSFrameCap]
	}

	meta.TimestampNs = tsNs
	meta.SrcIP = src
	meta.DstIP = dst
	meta.SrcPort = srcPort
	meta.DstPort = dstPort
	meta.IsIPv6 = isIPv6
	meta.IsResponse = srcPort == dnsPort

	return payload, 0
}
