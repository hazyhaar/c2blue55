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
	SLDLen          uint8
	SLD             [64]byte // Label enregistrable de second niveau (ex: "sophosxl", "bbc")
	TLDLen          uint8
	TLD             [64]byte // Suffixe public (ex: "com", "co.uk")
	LabelCount      uint8
	MaxLabelLen     uint8
	HasEncoding     bool
	ClientIP        [16]byte
	// Grammar n'est renseigné que par ParseDNSQueryTolerant ; nul (LDH) sinon.
	Grammar QNameGrammarProfile
}

// RegistrableSLD retourne le label enregistrable de second niveau sans allocation tas (0 B/op).
func (e *DNSEvent) RegistrableSLD() string {
	if e.SLDLen == 0 {
		return ""
	}
	return unsafe.String(&e.SLD[0], e.SLDLen)
}

// PublicSuffix retourne le suffixe public (TLD ou eTLD) sans allocation tas (0 B/op).
func (e *DNSEvent) PublicSuffix() string {
	if e.TLDLen == 0 {
		return ""
	}
	return unsafe.String(&e.TLD[0], e.TLDLen)
}

// ParseDNSName décode un QNAME textuel (issu de journaux Zeek/Suricata, sondes passives ou redhost)
// sans allocation sur le tas (0 B/op) et renseigne Subdomain, ParentDomain, RegistrableSLD et PublicSuffix.
func ParseDNSName(qname []byte, qtype uint16, ev *DNSEvent) (err error) {
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

	if qtype == 0 {
		return ErrQuestionContract
	}
	n := len(qname)
	if n > 0 && qname[n-1] == '.' {
		n--
	}
	if n == 0 {
		return ErrQuestionContract
	}
	if n > 253 {
		return ErrNameTooLong
	}

	labelStart := 0
	labelCount := 0
	maxLabelLen := 0
	totalLabelOffsets := [maxDNSLabels]uint8{}

	for i := range n {
		b := qname[i]
		if b == '.' {
			lLen := i - labelStart
			if lLen == 0 || lLen > 63 {
				return ErrInvalidLabel
			}
			if labelCount < maxDNSLabels {
				totalLabelOffsets[labelCount] = uint8(labelStart)
			}
			labelCount++
			if lLen > maxLabelLen {
				maxLabelLen = lLen
			}
			ev.Name[i] = '.'
			labelStart = i + 1
			continue
		}
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		if !dnsLabelByte(b) {
			if !isDNSEncodingByte(b) {
				return ErrInvalidLabel
			}
			ev.HasEncoding = true
		}
		ev.Name[i] = b
	}

	lastLen := n - labelStart
	if lastLen == 0 || lastLen > 63 {
		return ErrInvalidLabel
	}
	if labelCount < maxDNSLabels {
		totalLabelOffsets[labelCount] = uint8(labelStart)
	}
	labelCount++
	if lastLen > maxLabelLen {
		maxLabelLen = lastLen
	}

	ev.QType = qtype
	ev.QClass = 1
	ev.NameLen = uint8(n)
	ev.LabelCount = uint8(labelCount)
	ev.MaxLabelLen = uint8(maxLabelLen)

	populateDomainParts(ev, n, labelCount, &totalLabelOffsets)
	return nil
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
func ParseDNSQuery(raw []byte, ev *DNSEvent) error {
	return parseDNSQueryWire(raw, ev, false)
}

// ParseDNSQueryTolerant applique exactement les rejets structurels de
// ParseDNSQuery (longueur < 12, label > 63, nom > 253, pointeur invalide,
// chaîné ou bouclé, question hors contrat) mais admet les octets hors LDH d'un
// cadrage valide et les relève intégralement dans ev.Grammar. Zéro allocation.
func ParseDNSQueryTolerant(raw []byte, ev *DNSEvent) error {
	return parseDNSQueryWire(raw, ev, true)
}

func parseDNSQueryWire(raw []byte, ev *DNSEvent, tolerant bool) (err error) {
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
			if ptrOffset == offset-2 {
				return ErrLoopPointer
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
				if err := copierLabelQuestion(ev, raw[pOffset:pOffset+pLen], outPos, tolerant); err != nil {
					return err
				}
				if tolerant {
					observerLabelGrammaire(&ev.Grammar, raw[pOffset:pOffset+pLen], labelCount-1)
				}
				outPos += pLen
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

		if err := copierLabelQuestion(ev, raw[offset:offset+lenByte], outPos, tolerant); err != nil {
			return err
		}
		if tolerant {
			observerLabelGrammaire(&ev.Grammar, raw[offset:offset+lenByte], labelCount-1)
		}
		outPos += lenByte
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
	if tolerant {
		finaliserGrammaire(&ev.Grammar)
	}

	populateDomainParts(ev, outPos, labelCount, &totalLabelOffsets)
	return nil
}

// copierLabelQuestion recopie un label filaire en minuscules ASCII dans ev.Name
// à partir de debutSortie. En mode strict, le premier octet hors LDH, '_' et
// '+/=' rend ErrInvalidLabel, exactement comme la boucle historique.
func copierLabelQuestion(ev *DNSEvent, labelBrut []byte, debutSortie int, tolerant bool) error {
	for indice, octet := range labelBrut {
		if octet >= 'A' && octet <= 'Z' {
			octet += 32
		}
		if !dnsLabelByte(octet) {
			if isDNSEncodingByte(octet) {
				ev.HasEncoding = true
			} else if !tolerant {
				return ErrInvalidLabel
			}
		}
		ev.Name[debutSortie+indice] = octet
	}
	return nil
}

func populateDomainParts(ev *DNSEvent, outPos, labelCount int, totalLabelOffsets *[maxDNSLabels]uint8) {
	if labelCount >= 2 && labelCount-2 < maxDNSLabels {
		tldIdx := labelCount - 1
		sldIdx := labelCount - 2
		if labelCount >= 3 && labelCount-3 < maxDNSLabels {
			twoLvlStart := int(totalLabelOffsets[labelCount-2])
			if isTwoLevelPublicSuffix(ev.Name[twoLvlStart:outPos]) {
				tldIdx = labelCount - 2
				sldIdx = labelCount - 3
			}
		}

		parentStartIdx := int(totalLabelOffsets[sldIdx])
		tldStartIdx := int(totalLabelOffsets[tldIdx])
		parentLen := outPos - parentStartIdx
		if parentLen > 0 && parentLen <= len(ev.ParentDomain) {
			copy(ev.ParentDomain[:], ev.Name[parentStartIdx:outPos])
			ev.ParentDomainLen = uint8(parentLen)
		}

		if tldStartIdx > parentStartIdx+1 {
			sldLen := tldStartIdx - 1 - parentStartIdx
			if sldLen > 0 && sldLen <= len(ev.SLD) {
				copy(ev.SLD[:], ev.Name[parentStartIdx:tldStartIdx-1])
				ev.SLDLen = uint8(sldLen)
			}
		}

		tldLen := outPos - tldStartIdx
		if tldLen > 0 && tldLen <= len(ev.TLD) {
			copy(ev.TLD[:], ev.Name[tldStartIdx:outPos])
			ev.TLDLen = uint8(tldLen)
		}

		if parentStartIdx > 1 {
			subLen := parentStartIdx - 1
			if subLen > 0 && subLen <= len(ev.Subdomain) {
				copy(ev.Subdomain[:], ev.Name[0:subLen])
				ev.SubdomainLen = uint8(subLen)
			}
		}
	} else if labelCount == 1 {
		if outPos <= len(ev.ParentDomain) {
			copy(ev.ParentDomain[:], ev.Name[:outPos])
			ev.ParentDomainLen = uint8(outPos)
		}
		if outPos <= len(ev.SLD) {
			copy(ev.SLD[:], ev.Name[:outPos])
			ev.SLDLen = uint8(outPos)
		}
		ev.SubdomainLen = 0
	}
}

func isTwoLevelPublicSuffix(suffix []byte) bool {
	switch string(suffix) {
	case "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
		"com.br", "net.br", "org.br", "gov.br",
		"com.au", "net.au", "org.au", "edu.au",
		"co.jp", "ne.jp", "or.jp", "ac.jp",
		"co.nz", "co.za", "co.in", "co.kr", "co.il", "co.id", "co.th",
		"com.cn", "net.cn", "org.cn", "com.hk", "com.tw", "com.sg", "com.my",
		"com.mx", "com.ar", "com.co", "com.pe", "com.tr", "com.ua", "com.pl",
		"com.eg", "com.sa", "com.ng", "com.pk", "com.vn", "com.ph":
		return true
	}
	return false
}

func isDNSEncodingByte(b byte) bool {
	return b == '+' || b == '/' || b == '='
}

func dnsLabelByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-' || b == '_'
}
