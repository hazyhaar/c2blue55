package c2blue55

import (
	"encoding/binary"
	"fmt"
	"io"
)

// BenchPacket transporte une trame entière. Frame n'est valide que dans le rappel.
type BenchPacket struct {
	TimestampNs uint64
	LinkType    uint32
	Frame       []byte
}

// BenchPCAPStats compte les trames lues et tous les octets PCAP consommés.
type BenchPCAPStats struct {
	Packets uint64
	Bytes   uint64
}

// ReadBenchPCAP lit le format PCAP classique sans allocation de trame hors borne.
// Cent lectures vides consécutives rendent io.ErrNoProgress ; tout progrès remet
// ce compteur à zéro. Les statistiques comptent les octets consommés même en erreur.
func ReadBenchPCAP(source io.Reader, visit func(BenchPacket) error) (BenchPCAPStats, error) {
	var stats BenchPCAPStats
	if source == nil || visit == nil {
		return stats, fmt.Errorf("bench PCAP: lecteur et visiteur requis")
	}
	readFull := func(destination []byte) (int, error) {
		filled := 0
		emptyReads := 0
		for filled < len(destination) {
			n, err := source.Read(destination[filled:])
			if n < 0 || n > len(destination)-filled {
				return filled, fmt.Errorf("bench PCAP: longueur de lecture invalide: %d", n)
			}
			filled += n
			stats.Bytes += uint64(n)
			if err != nil {
				if err == io.EOF && filled > 0 {
					if filled == len(destination) {
						return filled, nil
					}
					return filled, io.ErrUnexpectedEOF
				}
				// Une erreur autre qu'EOF reste opposée même si elle accompagne
				// le dernier octet demandé ; io.ReadFull l'effacerait dans ce cas.
				return filled, err
			}
			if n > 0 {
				emptyReads = 0
			} else {
				emptyReads++
				if emptyReads == 100 {
					return filled, io.ErrNoProgress
				}
			}
		}
		return filled, nil
	}
	var header [24]byte
	if _, err := readFull(header[:]); err != nil {
		return stats, fmt.Errorf("bench PCAP: en-tête global: %w", err)
	}
	var order binary.ByteOrder
	var factor uint64
	switch string(header[:4]) {
	case "\xd4\xc3\xb2\xa1":
		order, factor = binary.LittleEndian, 1000
	case "\xa1\xb2\xc3\xd4":
		order, factor = binary.BigEndian, 1000
	case "\x4d\x3c\xb2\xa1":
		order, factor = binary.LittleEndian, 1
	case "\xa1\xb2\x3c\x4d":
		order, factor = binary.BigEndian, 1
	default:
		return stats, fmt.Errorf("bench PCAP: magique inconnu")
	}
	if order.Uint16(header[4:]) != 2 || order.Uint16(header[6:]) != 4 {
		return stats, fmt.Errorf("bench PCAP: version différente de 2.4")
	}
	snaplen, link := order.Uint32(header[16:]), order.Uint32(header[20:])
	if snaplen == 0 || snaplen > 1<<20 {
		return stats, fmt.Errorf("bench PCAP: snaplen hors borne: %d", snaplen)
	}
	switch link {
	case 1, 101, 113, 276:
	default:
		return stats, fmt.Errorf("bench PCAP: lien inconnu: %d", link)
	}
	var record [16]byte
	var frame []byte
	for {
		n, err := readFull(record[:])
		if err == io.EOF && n == 0 {
			return stats, nil
		}
		if err != nil {
			return stats, fmt.Errorf("bench PCAP: en-tête de trame: %w", err)
		}
		length, original := order.Uint32(record[8:]), order.Uint32(record[12:])
		fraction := uint64(order.Uint32(record[4:])) * factor
		if fraction >= 1e9 {
			return stats, fmt.Errorf("bench PCAP: fraction d'horodatage invalide")
		}
		if length > snaplen || length != original {
			return stats, fmt.Errorf("bench PCAP: longueurs inadmissibles: incl=%d orig=%d snaplen=%d", length, original, snaplen)
		}
		if uint64(length) > uint64(cap(frame)) {
			frame = make([]byte, int(length))
		} else {
			frame = frame[:int(length)]
		}
		if _, err := readFull(frame); err != nil {
			return stats, fmt.Errorf("bench PCAP: lecture de trame: %w", err)
		}
		stats.Packets++
		if err := visit(BenchPacket{
			TimestampNs: uint64(order.Uint32(record[:]))*1e9 + fraction,
			LinkType:    link,
			Frame:       frame[:len(frame):len(frame)],
		}); err != nil {
			return stats, fmt.Errorf("bench PCAP: visiteur: %w", err)
		}
	}
}
