package c2blue55

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	pcapMagicUsLE = 0xa1b2c3d4
	pcapMagicNsLE = 0xa1b23c4d
	pcapMagicUsBE = 0xd4c3b2a1
	pcapMagicNsBE = 0x4d3cb2a1

	pcapLinkEthernet = 1
	pcapLinkRawIP    = 101
	pcapLinkLinuxSLL = 113

	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
	etherTypeVLAN = 0x8100

	ipProtoUDP = 17
	dnsPort    = 53
)

// PCAPMessageMeta transporte l'enveloppe réseau d'un message DNS extrait d'un fichier PCAP.
type PCAPMessageMeta struct {
	TimestampNs uint64
	SrcIP       [16]byte
	DstIP       [16]byte
	SrcPort     uint16
	DstPort     uint16
	IsIPv6      bool
}

// PCAPMessageStats résume les compteurs de décodage d'un fichier PCAP DNS bidirectionnel.
type PCAPMessageStats struct {
	TotalPackets   int
	DecodedQueries int
	DecodedReplies int
	MalformedCount int
}

// ReadPCAPDNSWire parcourt une capture PCAP et livre la charge UDP brute de chaque message UDP/53.
func ReadPCAPDNSWire(pcapPath string, visit func(meta PCAPMessageMeta, wire []byte) error) (PCAPMessageStats, error) {
	var stats PCAPMessageStats

	f, err := os.Open(pcapPath)
	if err != nil {
		return stats, err
	}
	defer f.Close()

	r := bufio.NewReaderSize(f, 1<<16)
	var hdr [24]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return stats, fmt.Errorf("en-tête PCAP illisible: %w", err)
	}

	order, nsPerUnit, err := pcapByteOrder(binary.LittleEndian.Uint32(hdr[0:4]))
	if err != nil {
		return stats, err
	}
	linkType := order.Uint32(hdr[20:24])
	switch linkType {
	case pcapLinkEthernet, pcapLinkRawIP, pcapLinkLinuxSLL:
	default:
		return stats, fmt.Errorf("type de lien PCAP non supporté: %d", linkType)
	}

	var rec [16]byte
	for {
		if _, err := io.ReadFull(r, rec[:]); err != nil {
			if err == io.EOF {
				return stats, nil
			}
			return stats, fmt.Errorf("en-tête d'enregistrement tronqué: %w", err)
		}
		tsSec := order.Uint32(rec[0:4])
		tsFrac := order.Uint32(rec[4:8])
		inclLen := order.Uint32(rec[8:12])

		packetBytes := make([]byte, inclLen)
		if _, err := io.ReadFull(r, packetBytes); err != nil {
			return stats, fmt.Errorf("paquet tronqué: %w", err)
		}
		stats.TotalPackets++

		meta, udpPayload, ok := extractDNSPayload(linkType, packetBytes)
		if !ok {
			continue
		}
		meta.TimestampNs = uint64(tsSec)*1e9 + uint64(tsFrac)*nsPerUnit

		if visit != nil {
			if err := visit(meta, udpPayload); err != nil {
				return stats, err
			}
		}
	}
}

// ReadPCAPDNSMessages parcourt une capture PCAP et appelle visit pour chaque message DNS (UDP/53) décodé.
func ReadPCAPDNSMessages(pcapPath string, visit func(meta PCAPMessageMeta, msg *DNSMessage) error) (PCAPMessageStats, error) {
	var statsDecode PCAPMessageStats
	statsFilaire, err := ReadPCAPDNSWire(pcapPath, func(meta PCAPMessageMeta, wire []byte) error {
		var msg DNSMessage
		if err := ParseDNSMessage(wire, &msg); err != nil {
			statsDecode.MalformedCount++
			return nil
		}
		if msg.IsResponse {
			statsDecode.DecodedReplies++
		} else {
			statsDecode.DecodedQueries++
		}
		if visit != nil {
			return visit(meta, &msg)
		}
		return nil
	})
	statsDecode.TotalPackets = statsFilaire.TotalPackets
	return statsDecode, err
}

func pcapByteOrder(magic uint32) (binary.ByteOrder, uint64, error) {
	switch magic {
	case pcapMagicUsLE:
		return binary.LittleEndian, 1000, nil
	case pcapMagicNsLE:
		return binary.LittleEndian, 1, nil
	case pcapMagicUsBE:
		return binary.BigEndian, 1000, nil
	case pcapMagicNsBE:
		return binary.BigEndian, 1, nil
	}
	return nil, 0, fmt.Errorf("magic PCAP inconnu: 0x%08x", magic)
}

func stripL2(linkType uint32, packetBytes []byte) (uint16, []byte, bool) {
	switch linkType {
	case pcapLinkEthernet:
		if len(packetBytes) < 14 {
			return 0, nil, false
		}
		etherType, ip := binary.BigEndian.Uint16(packetBytes[12:14]), packetBytes[14:]
		if etherType == etherTypeVLAN {
			if len(ip) < 4 {
				return 0, nil, false
			}
			etherType, ip = binary.BigEndian.Uint16(ip[2:4]), ip[4:]
		}
		return etherType, ip, true
	case pcapLinkLinuxSLL:
		if len(packetBytes) < 16 {
			return 0, nil, false
		}
		return binary.BigEndian.Uint16(packetBytes[14:16]), packetBytes[16:], true
	}
	return 0, packetBytes, true
}

func extractDNSPayload(linkType uint32, packetBytes []byte) (PCAPMessageMeta, []byte, bool) {
	var meta PCAPMessageMeta

	etherType, ip, ok := stripL2(linkType, packetBytes)
	if !ok || len(ip) == 0 {
		return meta, nil, false
	}

	ver := ip[0] >> 4
	if linkType != pcapLinkRawIP {
		ver = 0
		switch etherType {
		case etherTypeIPv4:
			ver = 4
		case etherTypeIPv6:
			ver = 6
		}
	}

	var udpSeg []byte
	switch ver {
	case 4:
		if len(ip) < 20 {
			return meta, nil, false
		}
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || len(ip) < ihl || ip[9] != ipProtoUDP {
			return meta, nil, false
		}
		meta.SrcIP = v4Mapped(ip[12:16])
		meta.DstIP = v4Mapped(ip[16:20])
		udpSeg = ip[ihl:]
	case 6:
		if len(ip) < 40 || ip[6] != ipProtoUDP {
			return meta, nil, false
		}
		copy(meta.SrcIP[:], ip[8:24])
		copy(meta.DstIP[:], ip[24:40])
		meta.IsIPv6 = true
		udpSeg = ip[40:]
	default:
		return meta, nil, false
	}

	if len(udpSeg) < 8 {
		return meta, nil, false
	}
	srcPort := binary.BigEndian.Uint16(udpSeg[0:2])
	dstPort := binary.BigEndian.Uint16(udpSeg[2:4])
	if srcPort != dnsPort && dstPort != dnsPort {
		return meta, nil, false
	}

	udpLen := int(binary.BigEndian.Uint16(udpSeg[4:6]))
	if udpLen < 8 {
		return meta, nil, false
	}
	payload := udpSeg[8:]
	if udpLen-8 <= len(payload) {
		payload = payload[:udpLen-8]
	}
	meta.SrcPort, meta.DstPort = srcPort, dstPort
	return meta, payload, true
}

func v4Mapped(ip4 []byte) (out [16]byte) {
	out[10], out[11] = 0xff, 0xff
	copy(out[12:], ip4)
	return out
}
