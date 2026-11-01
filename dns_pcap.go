package c2blue55

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// Erreurs de structure du fichier pcap (strate S-03, OBJET-INTEGRAL-001) :
// un fichier qui n'est pas intégralement lisible n'est jamais jugé en partie.
var (
	ErrPCAPBadMagic  = errors.New("c2blue55: fichier pcap sans magic reconnu (0xa1b2c3d4 ou 0xa1b23c4d)")
	ErrPCAPLinkType  = errors.New("c2blue55: type de lien pcap non admis (276, 113, 1, 101, 228, 229 seulement)")
	ErrPCAPTruncated = errors.New("c2blue55: fichier pcap incomplet (en-tete ou enregistrement coupe)")
)

// PCAPIngestStats compte chaque enregistrement du pcap dans exactement une
// catégorie et chaque question UDP/53 dans Accepted ou dans le compteur de sa
// classe de rejet exacte. Invariant : UDPQuestions == Accepted + somme des Rejected*.
// TruncatedPackets compte aussi les enregistrements complets dont incl_len
// dépasse le tampon borné à 262144 octets.
type PCAPIngestStats struct {
	Records              uint32
	LinkType             uint32
	UDPQuestions         uint32
	UDPResponses         uint32
	TCPSegments          uint32
	OtherPackets         uint32
	IPFragments          uint32
	TruncatedPackets     uint32
	Accepted             uint32
	RejectedTooShort     uint32
	RejectedInvalidLabel uint32
	RejectedLoopPointer  uint32
	RejectedNameTooLong  uint32
	RejectedContract     uint32
}

// PCAPQuestionMeta est la provenance d'une question acceptée : numéro
// d'enregistrement (à partir de 1), horodatage en microsecondes Unix,
// adresses (IPv4 sur 4 octets suivis de zéros, IPv6 sur 16) et port source.
type PCAPQuestionMeta struct {
	Record     uint32
	Timestamp  uint64
	SourceIP   [16]byte
	DestIP     [16]byte
	IPv6       bool
	SourcePort uint16
}

// ReadPCAPDNSQuestions lit intégralement un fichier pcap, passe chaque question
// UDP vers le port 53 à ParseDNSQuery (Timestamp et ClientIP prérenseignés) et
// appelle visit pour chaque question acceptée, sans allocation sur le chemin
// chaud. Une erreur rendue par visit interrompt la lecture et est propagée.
func ReadPCAPDNSQuestions(pcapPath string, visit func(meta PCAPQuestionMeta, ev *DNSEvent) error) (PCAPIngestStats, error) {
	return readPCAPDNSQuestionsMode(pcapPath, false, visit)
}

// ReadPCAPDNSQuestionsTolerant lit intégralement un fichier pcap comme
// ReadPCAPDNSQuestions mais passe chaque question UDP/53 à ParseDNSQueryTolerant
// afin d'ingérer les QNAME hors LDH d'encadrement RFC 1035 valide (Base128, DNS-SD, UTF-8).
func ReadPCAPDNSQuestionsTolerant(pcapPath string, visit func(meta PCAPQuestionMeta, ev *DNSEvent) error) (PCAPIngestStats, error) {
	return readPCAPDNSQuestionsMode(pcapPath, true, visit)
}

func readPCAPDNSQuestionsMode(pcapPath string, tolerant bool, visit func(meta PCAPQuestionMeta, ev *DNSEvent) error) (stats PCAPIngestStats, err error) {
	file, err := os.Open(pcapPath)
	if err != nil {
		return stats, err
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("fermeture pcap: %w", cerr)
		}
	}()

	var globalHeader [24]byte
	if _, err = io.ReadFull(file, globalHeader[:]); err != nil {
		return stats, fmt.Errorf("en-tête global pcap: %w: %v", ErrPCAPTruncated, err)
	}
	var order binary.ByteOrder
	var nanoseconds bool
	switch binary.BigEndian.Uint32(globalHeader[:4]) {
	case 0xd4c3b2a1:
		order = binary.LittleEndian
	case 0xa1b2c3d4:
		order = binary.BigEndian
	case 0x4d3cb2a1:
		order, nanoseconds = binary.LittleEndian, true
	case 0xa1b23c4d:
		order, nanoseconds = binary.BigEndian, true
	default:
		return stats, ErrPCAPBadMagic
	}
	stats.LinkType = order.Uint32(globalHeader[20:24])
	switch stats.LinkType {
	case 276, 113, 1, 101, 228, 229:
	default:
		return stats, ErrPCAPLinkType
	}
	snaplen := min(order.Uint32(globalHeader[16:20]), 262144)
	packet := make([]byte, max(1, int(snaplen)))
	var recordHeader [16]byte
	var ev DNSEvent
	var meta PCAPQuestionMeta
	for {
		headerBytes, readErr := io.ReadFull(file, recordHeader[:])
		if readErr == io.EOF && headerBytes == 0 {
			return stats, nil
		}
		if readErr != nil {
			return stats, fmt.Errorf("en-tête d'enregistrement pcap: %w: %v", ErrPCAPTruncated, readErr)
		}
		included := order.Uint32(recordHeader[8:12])
		original := order.Uint32(recordHeader[12:16])
		// Même les captures hors borne sont consommées intégralement avant d'être comptées.
		remaining := included
		for remaining > 0 {
			chunk := min(remaining, uint32(len(packet)))
			if _, err = io.ReadFull(file, packet[:int(chunk)]); err != nil {
				return stats, fmt.Errorf("corps d'enregistrement pcap: %w: %v", ErrPCAPTruncated, err)
			}
			remaining -= chunk
		}
		stats.Records++
		if included > uint32(len(packet)) || original > included {
			stats.TruncatedPackets++
			continue
		}
		stamp := uint64(order.Uint32(recordHeader[0:4])) * 1000000
		fraction := uint64(order.Uint32(recordHeader[4:8]))
		if nanoseconds {
			fraction /= 1000
		}
		meta = PCAPQuestionMeta{Record: stats.Records, Timestamp: stamp + fraction}
		if err = classifyPCAPPacket(packet[:included], stats.LinkType, tolerant, &stats, &meta, &ev, visit); err != nil {
			return stats, err
		}
	}
}

func classifyPCAPPacket(packet []byte, linkType uint32, tolerant bool, stats *PCAPIngestStats, meta *PCAPQuestionMeta, ev *DNSEvent, visit func(PCAPQuestionMeta, *DNSEvent) error) error {
	var protocol uint16
	switch linkType {
	case 276:
		if len(packet) < 20 {
			stats.OtherPackets++
			return nil
		}
		protocol, packet = binary.BigEndian.Uint16(packet[:2]), packet[20:]
	case 113:
		if len(packet) < 16 {
			stats.OtherPackets++
			return nil
		}
		protocol, packet = binary.BigEndian.Uint16(packet[14:16]), packet[16:]
	case 1:
		if len(packet) < 14 {
			stats.OtherPackets++
			return nil
		}
		protocol, packet = binary.BigEndian.Uint16(packet[12:14]), packet[14:]
		if protocol == 0x8100 {
			if len(packet) < 4 {
				stats.OtherPackets++
				return nil
			}
			protocol, packet = binary.BigEndian.Uint16(packet[2:4]), packet[4:]
		}
	case 228:
		protocol = 0x0800
	case 229:
		protocol = 0x86dd
	case 101:
		if len(packet) == 0 {
			stats.OtherPackets++
			return nil
		}
		switch packet[0] >> 4 {
		case 4:
			protocol = 0x0800
		case 6:
			protocol = 0x86dd
		}
	}
	var transport byte
	switch protocol {
	case 0x0800:
		if len(packet) < 20 || packet[0]>>4 != 4 {
			stats.OtherPackets++
			return nil
		}
		headerLen := int(packet[0]&0x0f) * 4
		totalLen := int(binary.BigEndian.Uint16(packet[2:4]))
		if headerLen < 20 || totalLen < headerLen || len(packet) < totalLen {
			stats.OtherPackets++
			return nil
		}
		if binary.BigEndian.Uint16(packet[6:8])&0x1fff != 0 {
			stats.IPFragments++
			return nil
		}
		copy(meta.SourceIP[:], packet[12:16])
		copy(meta.DestIP[:], packet[16:20])
		transport, packet = packet[9], packet[headerLen:totalLen]
	case 0x86dd:
		if len(packet) < 40 || packet[0]>>4 != 6 {
			stats.OtherPackets++
			return nil
		}
		payloadLen := int(binary.BigEndian.Uint16(packet[4:6]))
		if len(packet) < 40+payloadLen {
			stats.OtherPackets++
			return nil
		}
		meta.IPv6 = true
		copy(meta.SourceIP[:], packet[8:24])
		copy(meta.DestIP[:], packet[24:40])
		transport, packet = packet[6], packet[40:40+payloadLen]
	default:
		stats.OtherPackets++
		return nil
	}
	if len(packet) < 4 {
		stats.OtherPackets++
		return nil
	}
	source := binary.BigEndian.Uint16(packet[:2])
	destination := binary.BigEndian.Uint16(packet[2:4])
	switch transport {
	case 6:
		if source == 53 || destination == 53 {
			stats.TCPSegments++
		} else {
			stats.OtherPackets++
		}
	case 17:
		if len(packet) < 8 {
			stats.OtherPackets++
			return nil
		}
		udpLen := int(binary.BigEndian.Uint16(packet[4:6]))
		if udpLen < 8 || udpLen > len(packet) {
			stats.OtherPackets++
			return nil
		}
		if destination == 53 {
			stats.UDPQuestions++
			meta.SourcePort = source
			ev.Timestamp, ev.ClientIP = meta.Timestamp, meta.SourceIP
			var err error
			if tolerant {
				err = ParseDNSQueryTolerant(packet[8:udpLen], ev)
			} else {
				err = ParseDNSQuery(packet[8:udpLen], ev)
			}
			switch {
			case err == nil:
				stats.Accepted++
				return visit(*meta, ev)
			case errors.Is(err, ErrPacketTooShort):
				stats.RejectedTooShort++
			case errors.Is(err, ErrInvalidLabel):
				stats.RejectedInvalidLabel++
			case errors.Is(err, ErrLoopPointer):
				stats.RejectedLoopPointer++
			case errors.Is(err, ErrNameTooLong):
				stats.RejectedNameTooLong++
			case errors.Is(err, ErrQuestionContract):
				stats.RejectedContract++
			default:
				return err
			}
		} else if source == 53 {
			stats.UDPResponses++
		} else {
			stats.OtherPackets++
		}
	default:
		stats.OtherPackets++
	}
	return nil
}
