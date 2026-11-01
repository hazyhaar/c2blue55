//go:build linux

package probes

import (
	"encoding/binary"

	"github.com/hazyhaar/c2blue55"
)

// PayloadBytes borne la charge utile recopiée dans chaque événement réseau.
const PayloadBytes = 96

const (
	ethHdrLen       = 14
	ethTypeIPv4     = 0x0800
	ethTypeVLAN     = 0x8100
	ipProtoICMP     = 1
	ipProtoUDP      = 17
	dnsPort         = 53
	icmpEchoReply   = 0
	icmpEchoRequest = 8
)

// DecodePacket décode une trame à partir de l'en-tête MAC (frame[0] = octet 0
// du MAC) et remplit out sans aucune allocation tas. Le décodage n'admet que
// le DNS (UDP port 53) et l'ICMP echo (type 8 ou 0) ; toute autre trame
// retourne -1. La charge utile applicative est recopiée sur au plus 96 octets.
func DecodePacket(frame []byte, tsNs uint64, out *c2blue55.Event) int {
	if out == nil {
		return -1
	}
	*out = c2blue55.Event{Ts_ns: tsNs, Subsystem: c2blue55.SubNet, Action: c2blue55.ActConnect}
	if len(frame) < ethHdrLen {
		return -1
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	ipOff := ethHdrLen
	for etherType == ethTypeVLAN {
		if len(frame) < ipOff+4 {
			return -1
		}
		etherType = binary.BigEndian.Uint16(frame[ipOff+2 : ipOff+4])
		ipOff += 4
	}
	if etherType != ethTypeIPv4 || len(frame) < ipOff+20 {
		return -1
	}
	ihl := int(frame[ipOff]&0x0f) * 4
	if ihl < 20 || len(frame) < ipOff+ihl {
		return -1
	}
	proto := frame[ipOff+9]
	l4 := ipOff + ihl
	out.Src = uint64(binary.BigEndian.Uint32(frame[ipOff+12 : ipOff+16]))
	switch proto {
	case ipProtoUDP:
		if len(frame) < l4+8 {
			return -1
		}
		srcPort := binary.BigEndian.Uint16(frame[l4 : l4+2])
		dstPort := binary.BigEndian.Uint16(frame[l4+2 : l4+4])
		if srcPort != dnsPort && dstPort != dnsPort {
			return -1
		}
		copyPayload(out, frame[l4+8:])
		return 0
	case ipProtoICMP:
		if len(frame) < l4+8 {
			return -1
		}
		if icmpType := frame[l4]; icmpType == icmpEchoRequest || icmpType == icmpEchoReply {
			copyPayload(out, frame[l4+8:])
			return 0
		}
	}
	return -1
}

// copyPayload recopie la charge utile sur un tableau préalloué, sans tranche
// intermédiaire ni croissance sur le tas.
func copyPayload(out *c2blue55.Event, payload []byte) {
	out.Payload = [PayloadBytes]byte{}
	copy(out.Payload[:], payload)
}
