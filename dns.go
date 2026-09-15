// Package c2blue55 — Décodeur DNS RFC 1035 haute performance, zéro allocation (0 B/op).
package c2blue55

import (
	"encoding/binary"
	"errors"
	"unsafe"
)

var (
	ErrPacketTooShort   = errors.New("c2blue55: paquet dns trop court (< 12 octets)")
	ErrInvalidLabel     = errors.New("c2blue55: label dns invalide ou corrompu")
	ErrLoopPointer      = errors.New("c2blue55: boucle de pointeur de compression dns")
	ErrNameTooLong      = errors.New("c2blue55: fqdn superieur a 255 octets (rfc 1035)")
	ErrQuestionContract = errors.New("c2blue55: une question standard IN complete est requise")
)

// maxDNSLabels borne le nombre maximal de labels d'un nom DNS RFC 1035.
// Un nom est limite a 255 octets ; avec des labels d'un octet et leur separateur,
// le pire cas theorique atteint 128 labels. Le tableau des positions reste donc
// integralement indexable sans aucun debordement possible.
const maxDNSLabels = 128

// Types d'enregistrements DNS canoniques (RFC 1035 / RFC 3596)
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypeNULL  uint16 = 10 // Fréquemment utilisé par les tunnels DNS (ex: Iodine)
	TypePTR   uint16 = 12
	TypeMX    uint16 = 15
	TypeTXT   uint16 = 16 // Fréquemment utilisé par les tunnels DNS (ex: dnscat2)
	TypeAAAA  uint16 = 28
	TypeSRV   uint16 = 33
	TypeANY   uint16 = 255
)

// DNSHeader représente l'en-tête fixe de 12 octets du paquet DNS.
type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// DNSEvent représente un événement réseau DNS analysé, stocké à plat sans pointeurs.
type DNSEvent struct {
	Timestamp       uint64
	ID              uint16
	Flags           uint16
	QType           uint16
	QClass          uint16
	NameLen         uint8
	Name            [256]byte // FQDN canonique en minuscules sans point final
	SubdomainLen    uint8
	Subdomain       [256]byte // Toute la longueur DNS autorisee
	ParentDomainLen uint8
	ParentDomain    [128]byte // Domaine parent (ex: "sophosxl.com", "evil-c2.net")
	LabelCount      uint8
	MaxLabelLen     uint8
	ClientIP        [16]byte
}

// FQDN retourne le nom canonique sous forme de chaîne sans allocation tas (0 B/op).
func (e *DNSEvent) FQDN() string {
	if e.NameLen == 0 {
		return ""
	}
	return unsafe.String(&e.Name[0], e.NameLen)
}

// Parent retourne le domaine parent sous forme de chaîne sans allocation tas (0 B/op).
func (e *DNSEvent) Parent() string {
	if e.ParentDomainLen == 0 {
		return ""
	}
	return unsafe.String(&e.ParentDomain[0], e.ParentDomainLen)
}

// Sub retourne le sous-domaine sous forme de chaîne sans allocation tas (0 B/op).
func (e *DNSEvent) Sub() string {
	if e.SubdomainLen == 0 {
		return ""
	}
	return unsafe.String(&e.Subdomain[0], e.SubdomainLen)
}

// ParseDNSQuery accepts one standard IN question, not responses or RDATA.
// Labels are restricted to ASCII letters, digits, '-' and '_' rather than
// ambiguously flattening arbitrary binary labels. Compression is limited to one hop.
// Parent is only the last two labels, NOT a public-suffix/registrable domain.
// Timestamp and ClientIP are caller metadata; no client identity is inferred here.
func ParseDNSQuery(raw []byte, ev *DNSEvent) (err error) {
	if ev == nil {
		return ErrQuestionContract
	}
	stamp, client := ev.Timestamp, ev.ClientIP
	*ev = DNSEvent{Timestamp: stamp, ClientIP: client}
	defer func() {
		if err != nil {
			*ev = DNSEvent{Timestamp: stamp, ClientIP: client}
		}
	}()
	if len(raw) < 12 {
		return ErrPacketTooShort
	}

	ev.ID = binary.BigEndian.Uint16(raw[0:2])
	ev.Flags = binary.BigEndian.Uint16(raw[2:4])
	qdCount := binary.BigEndian.Uint16(raw[4:6])

	if qdCount != 1 || ev.Flags&0xf800 != 0 {
		return ErrQuestionContract
	}

	offset := 12
	outPos := 0
	labelCount := 0
	maxLabelLen := 0
	totalLabelOffsets := [maxDNSLabels]uint8{}

	for {
		if offset >= len(raw) {
			return ErrPacketTooShort
		}
		lenByte := int(raw[offset])
		if lenByte == 0 {
			offset++
			break
		}

		// Gestion des pointeurs de compression (0xC0)
		if (lenByte & 0xC0) == 0xC0 {
			if offset+1 >= len(raw) {
				return ErrPacketTooShort
			}
			ptrOffset := int(binary.BigEndian.Uint16(raw[offset:offset+2]) & 0x3FFF)
			offset += 2
			// Suivi de pointeur (borné à 1 saut pour éviter toute boucle malveillante)
			if ptrOffset >= len(raw) || ptrOffset < 12 {
				return ErrInvalidLabel
			}
			pOffset := ptrOffset
			for {
				if pOffset >= len(raw) {
					return ErrPacketTooShort
				}
				pLen := int(raw[pOffset])
				if pLen == 0 {
					break
				}
				if (pLen & 0xC0) == 0xC0 {
					return ErrLoopPointer // Refus des pointeurs chaînés en profondeur
				}
				if pLen > 63 {
					return ErrInvalidLabel // Borne RFC 1035 : un label excède 63 octets
				}
				pOffset++
				if pOffset+pLen > len(raw) {
					return ErrPacketTooShort
				}
				if outPos+pLen+1 > 254 {
					return ErrNameTooLong
				}
				if outPos > 0 {
					ev.Name[outPos] = '.'
					outPos++
				}
				if labelCount < maxDNSLabels {
					totalLabelOffsets[labelCount] = uint8(outPos)
				}
				labelCount++
				if pLen > maxLabelLen {
					maxLabelLen = pLen
				}
				for i := 0; i < pLen; i++ {
					b := raw[pOffset+i]
					if b >= 'A' && b <= 'Z' {
						b += 32 // Normalisation ASCII minuscule in-place
					}
					if !dnsLabelByte(b) {
						return ErrInvalidLabel
					}
					ev.Name[outPos] = b
					outPos++
				}
				pOffset += pLen
			}
			break
		}

		// Label normal (longueur <= 63)
		if lenByte > 63 {
			return ErrInvalidLabel
		}
		offset++
		if offset+lenByte > len(raw) {
			return ErrPacketTooShort
		}
		if outPos+lenByte+1 > 254 {
			return ErrNameTooLong
		}

		if outPos > 0 {
			ev.Name[outPos] = '.'
			outPos++
		}

		if labelCount < maxDNSLabels {
			totalLabelOffsets[labelCount] = uint8(outPos)
		}
		if lenByte > maxLabelLen {
			maxLabelLen = lenByte
		}
		labelCount++

		for i := 0; i < lenByte; i++ {
			b := raw[offset+i]
			if b >= 'A' && b <= 'Z' {
				b += 32 // Normalisation minuscule
			}
			if !dnsLabelByte(b) {
				return ErrInvalidLabel
			}
			ev.Name[outPos] = b
			outPos++
		}
		offset += lenByte
	}

	// Lecture QType et QClass
	if offset+4 <= len(raw) {
		ev.QType = binary.BigEndian.Uint16(raw[offset : offset+2])
		ev.QClass = binary.BigEndian.Uint16(raw[offset+2 : offset+4])
	} else {
		return ErrPacketTooShort
	}
	if outPos > 253 {
		return ErrNameTooLong
	}
	if outPos == 0 || ev.QType == 0 || ev.QClass != 1 {
		return ErrQuestionContract
	}

	ev.NameLen = uint8(outPos)
	ev.LabelCount = uint8(labelCount)
	ev.MaxLabelLen = uint8(maxLabelLen)

	// Extraction déterministe du Domaine Parent et du Sous-domaine
	// Ex: "a1b2c3.cloudtelemetry.sophosxl.com" (4 labels)
	// Parent = "sophosxl.com" (2 derniers labels)
	// Subdomain = "a1b2c3.cloudtelemetry"
	if labelCount >= 2 && labelCount-2 < maxDNSLabels {
		parentStartIdx := int(totalLabelOffsets[labelCount-2])
		parentLen := outPos - parentStartIdx
		if parentLen > 0 && parentLen <= 128 {
			copy(ev.ParentDomain[:], ev.Name[parentStartIdx:outPos])
			ev.ParentDomainLen = uint8(parentLen)
		}

		subLen := parentStartIdx - 1 // Sans le point séparateur
		if subLen > 0 && subLen <= len(ev.Subdomain) {
			copy(ev.Subdomain[:], ev.Name[0:subLen])
			ev.SubdomainLen = uint8(subLen)
		}
	} else if labelCount == 1 {
		copy(ev.ParentDomain[:], ev.Name[:outPos])
		ev.ParentDomainLen = uint8(outPos)
		ev.SubdomainLen = 0
	}

	return nil
}

func dnsLabelByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_'
}
