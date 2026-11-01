package c2blue55

import (
	"encoding/binary"
	"errors"
)

const (
	MaxDNSMessageRRs = 16
	MaxDNSRDataBytes = 1536
	maxPointerJumps  = 8
)

var (
	// ErrTooManyRRs signale une section DNS excédant MaxDNSMessageRRs.
	ErrTooManyRRs = errors.New("dns: section RR count exceeds maximum")
	// ErrRDataTooLong signale un champ RDATA excédant MaxDNSRDataBytes.
	ErrRDataTooLong = errors.New("dns: resource record RDATA exceeds maximum")
)

// DNSRR représente un enregistrement de ressource DNS (Answer, Authority ou Additional) sans pointeurs.
type DNSRR struct {
	NameLen  uint8
	Name     [256]byte
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RDataLen uint16
	RData    [MaxDNSRDataBytes]byte
}

// DNSMessage représente un paquet DNS complet (requête QR=0 ou réponse QR=1) décodé en 0 B/op.
type DNSMessage struct {
	ID                   uint16
	Flags                uint16
	IsResponse           bool
	Opcode               uint8
	AA                   bool
	TC                   bool
	RD                   bool
	RA                   bool
	RCode                uint8
	QDCount              uint16
	ANCount              uint16
	NSCount              uint16
	ARCount              uint16
	QType                uint16
	QClass               uint16
	QNameLen             uint8
	QName                [256]byte
	SubdomainLen         uint8
	Subdomain            [256]byte
	ParentDomainLen      uint8
	ParentDomain         [128]byte
	SLDLen               uint8
	SLD                  [64]byte
	TLDLen               uint8
	TLD                  [64]byte
	LabelCount           uint8
	MaxLabelLen          uint8
	HasNonLDH            bool
	FirstLabelUpper      uint8
	FirstLabelLower      uint8
	FirstLabelDigits     uint8
	FirstLabelHasZeroOIl bool
	FirstLabelHasHyphen  bool
	AnswerCount          uint8
	Answers              [MaxDNSMessageRRs]DNSRR
	AuthorityCount       uint8
	Authorities          [MaxDNSMessageRRs]DNSRR
	AdditionalCount      uint8
	Additionals          [MaxDNSMessageRRs]DNSRR
}

// ParseDNSMessage décode un paquet DNS binaire complet (QR=0 ou QR=1) en zéro allocation tas (0 B/op).
func ParseDNSMessage(raw []byte, msg *DNSMessage) error {
	if msg == nil {
		return ErrQuestionContract
	}
	*msg = DNSMessage{}
	if len(raw) < 12 {
		return ErrPacketTooShort
	}

	flags := binary.BigEndian.Uint16(raw[2:4])
	msg.ID = binary.BigEndian.Uint16(raw[0:2])
	msg.Flags = flags
	msg.IsResponse = (flags & 0x8000) != 0
	msg.Opcode = uint8((flags >> 11) & 0x0F)
	msg.AA = (flags & 0x0400) != 0
	msg.TC = (flags & 0x0200) != 0
	msg.RD = (flags & 0x0100) != 0
	msg.RA = (flags & 0x0080) != 0
	msg.RCode = uint8(flags & 0x000F)
	msg.QDCount = binary.BigEndian.Uint16(raw[4:6])
	msg.ANCount = binary.BigEndian.Uint16(raw[6:8])
	msg.NSCount = binary.BigEndian.Uint16(raw[8:10])
	msg.ARCount = binary.BigEndian.Uint16(raw[10:12])

	if msg.QDCount == 0 {
		return ErrQuestionContract
	}

	var qLabelOffsets [maxDNSLabels]uint8
	qLen, off, lc, maxLbl, nonLDH, err := decodeDNSWireName(raw, 12, &msg.QName, &qLabelOffsets)
	if err != nil {
		return err
	}
	if off+4 > len(raw) {
		return ErrQuestionContract
	}
	msg.QNameLen = qLen
	msg.LabelCount = lc
	msg.MaxLabelLen = maxLbl
	msg.HasNonLDH = nonLDH
	msg.QType = binary.BigEndian.Uint16(raw[off : off+2])
	msg.QClass = binary.BigEndian.Uint16(raw[off+2 : off+4])
	off += 4

	if len(raw) > 13 {
		l0 := int(raw[12])
		if l0 > 0 && l0 <= 63 && 13+l0 <= len(raw) {
			for i := range l0 {
				b := raw[13+i]
				if b >= 'A' && b <= 'Z' {
					msg.FirstLabelUpper++
				} else if b >= 'a' && b <= 'z' {
					msg.FirstLabelLower++
				} else if b >= '0' && b <= '9' {
					msg.FirstLabelDigits++
				}
				if b == '0' || b == 'O' || b == 'I' || b == 'l' {
					msg.FirstLabelHasZeroOIl = true
				}
				if b == '-' {
					msg.FirstLabelHasHyphen = true
				}
			}
		}
	}

	splitWireQName(msg, &qLabelOffsets)

	for q := uint16(1); q < msg.QDCount; q++ {
		var skip [256]byte
		_, nextOff, _, _, _, qErr := decodeDNSWireName(raw, off, &skip, nil)
		if qErr != nil {
			return qErr
		}
		if nextOff+4 > len(raw) {
			return ErrQuestionContract
		}
		off = nextOff + 4
	}

	var rrErr error
	off, msg.AnswerCount, rrErr = decodeRRSection(raw, off, msg.ANCount, &msg.Answers)
	if rrErr != nil {
		return rrErr
	}
	off, msg.AuthorityCount, rrErr = decodeRRSection(raw, off, msg.NSCount, &msg.Authorities)
	if rrErr != nil {
		return rrErr
	}
	_, msg.AdditionalCount, rrErr = decodeRRSection(raw, off, msg.ARCount, &msg.Additionals)
	return rrErr
}

func decodeDNSWireName(raw []byte, startOff int, dst *[256]byte, labelOffsets *[maxDNSLabels]uint8) (uint8, int, uint8, uint8, bool, error) {
	pos := startOff
	nextOff := -1
	jumps := 0
	outLen := 0
	var labelCount, maxLbl uint8
	hasNonLDH := false

	for {
		if pos >= len(raw) {
			return 0, 0, 0, 0, false, ErrInvalidLabel
		}
		b := raw[pos]
		if b == 0 {
			if nextOff < 0 {
				nextOff = pos + 1
			}
			break
		}
		if (b & 0xC0) == 0xC0 {
			if pos+1 >= len(raw) {
				return 0, 0, 0, 0, false, ErrInvalidLabel
			}
			target := int(b&0x3F)<<8 | int(raw[pos+1])
			if target < 12 || target >= pos {
				return 0, 0, 0, 0, false, ErrLoopPointer
			}
			jumps++
			if jumps > maxPointerJumps {
				return 0, 0, 0, 0, false, ErrLoopPointer
			}
			if nextOff < 0 {
				nextOff = pos + 2
			}
			pos = target
			continue
		}
		if (b & 0xC0) != 0 {
			return 0, 0, 0, 0, false, ErrInvalidLabel
		}
		lLen := int(b)
		pos++
		if lLen > 63 || pos+lLen > len(raw) {
			return 0, 0, 0, 0, false, ErrInvalidLabel
		}
		if outLen > 0 {
			if outLen+1 > 253 {
				return 0, 0, 0, 0, false, ErrNameTooLong
			}
			dst[outLen] = '.'
			outLen++
		}
		if outLen+lLen > 253 {
			return 0, 0, 0, 0, false, ErrNameTooLong
		}
		if labelOffsets != nil && int(labelCount) < maxDNSLabels {
			labelOffsets[labelCount] = uint8(outLen)
		}
		for i := range lLen {
			ch := raw[pos+i]
			if ch >= 'A' && ch <= 'Z' {
				ch += 32
			}
			if !((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
				hasNonLDH = true
			}
			dst[outLen] = ch
			outLen++
		}
		labelCount++
		if uint8(lLen) > maxLbl {
			maxLbl = uint8(lLen)
		}
		pos += lLen
	}
	return uint8(outLen), nextOff, labelCount, maxLbl, hasNonLDH, nil
}

func decodeRRSection(raw []byte, off int, rrCount uint16, dst *[MaxDNSMessageRRs]DNSRR) (int, uint8, error) {
	if rrCount > MaxDNSMessageRRs {
		return 0, 0, ErrTooManyRRs
	}
	var stored uint8
	for range rrCount {
		var rr DNSRR
		nLen, nextOff, _, _, _, err := decodeDNSWireName(raw, off, &rr.Name, nil)
		if err != nil {
			return 0, 0, err
		}
		if nextOff+10 > len(raw) {
			return 0, 0, ErrInvalidLabel
		}
		rr.NameLen = nLen
		rr.Type = binary.BigEndian.Uint16(raw[nextOff : nextOff+2])
		rr.Class = binary.BigEndian.Uint16(raw[nextOff+2 : nextOff+4])
		rr.TTL = binary.BigEndian.Uint32(raw[nextOff+4 : nextOff+8])
		rdLen := binary.BigEndian.Uint16(raw[nextOff+8 : nextOff+10])
		rr.RDLength = rdLen
		rdataStart := nextOff + 10
		rdataEnd := rdataStart + int(rdLen)
		if rdataEnd > len(raw) {
			return 0, 0, ErrInvalidLabel
		}
		if int(rdLen) > MaxDNSRDataBytes {
			return 0, 0, ErrRDataTooLong
		}
		copy(rr.RData[:rdLen], raw[rdataStart:rdataEnd])
		rr.RDataLen = rdLen
		dst[stored] = rr
		stored++
		off = rdataEnd
	}
	return off, stored, nil
}

func splitWireQName(msg *DNSMessage, labelOffsets *[maxDNSLabels]uint8) {
	n := int(msg.QNameLen)
	if n == 0 {
		return
	}
	var ev DNSEvent
	if !msg.HasNonLDH && msg.QType != 0 && ParseDNSName(msg.QName[:n], msg.QType, &ev) == nil {
		msg.SubdomainLen = ev.SubdomainLen
		msg.Subdomain = ev.Subdomain
		msg.ParentDomainLen = ev.ParentDomainLen
		msg.ParentDomain = ev.ParentDomain
		msg.SLDLen = ev.SLDLen
		msg.SLD = ev.SLD
		msg.TLDLen = ev.TLDLen
		msg.TLD = ev.TLD
		return
	}
	// Constat A-17 / V1 : découpage exact selon les vraies frontières de labels
	// filaires, immunisé contre un octet 0x2e ('.') interne à un label Base128/binaire.
	if labelOffsets != nil && msg.LabelCount > 0 {
		ev.Name = msg.QName
		populateDomainParts(&ev, n, int(msg.LabelCount), labelOffsets)
		msg.SubdomainLen = ev.SubdomainLen
		msg.Subdomain = ev.Subdomain
		msg.ParentDomainLen = ev.ParentDomainLen
		msg.ParentDomain = ev.ParentDomain
		msg.SLDLen = ev.SLDLen
		msg.SLD = ev.SLD
		msg.TLDLen = ev.TLDLen
		msg.TLD = ev.TLD
		return
	}
	lastDot := -1
	prevDot := -1
	for i := range n {
		if msg.QName[i] == '.' {
			prevDot = lastDot
			lastDot = i
		}
	}
	if lastDot <= 0 {
		msg.SLDLen = uint8(copy(msg.SLD[:], msg.QName[:n]))
		msg.ParentDomainLen = uint8(copy(msg.ParentDomain[:], msg.QName[:n]))
		return
	}
	msg.TLDLen = uint8(copy(msg.TLD[:], msg.QName[lastDot+1:n]))
	pStart := 0
	if prevDot >= 0 {
		pStart = prevDot + 1
		msg.SubdomainLen = uint8(copy(msg.Subdomain[:], msg.QName[:prevDot]))
	}
	msg.SLDLen = uint8(copy(msg.SLD[:], msg.QName[pStart:lastDot]))
	msg.ParentDomainLen = uint8(copy(msg.ParentDomain[:], msg.QName[pStart:n]))
}
