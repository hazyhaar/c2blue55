package dnslab

import "encoding/binary"

func hasSubBytes(haystack []byte, needle string) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	limit := len(haystack) - len(needle)
	for i := 0; i <= limit; i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func fillPseudoRandom(dst []byte, seed uint64, qname []byte, txid uint16) {
	s := seed ^ (uint64(txid) << 16) ^ 0x9e3779b97f4a7c15
	for _, b := range qname {
		s = (s ^ uint64(b)) * 0xbf58476d1ce4e5b9
	}
	for i := range dst {
		s += 0x9e3779b97f4a7c15
		z := s
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		dst[i] = byte(z ^ (z >> 31))
	}
}

// BuildLabResponseP1P4 construit en 0 B/op une réponse DNS de laboratoire couvrant
// la poignée de main NULL iodine sans état (V/L/I/Z/p), les charges descendantes P1
// et les réponses bénignes A/AAAA/TXT (_domainkey/_spf/_acme-challenge).
func BuildLabResponseP1P4(question []byte, seed uint64, response []byte) (int, Decision, error) {
	var decision Decision
	if len(question) < 12 {
		return 0, decision, ErrQueryTooShort
	}
	if question[2]&0x80 != 0 {
		return 0, decision, ErrNotAQuery
	}
	if len(response) < 512 {
		return 0, decision, ErrResponseBufferTooSmall
	}

	txid := binary.BigEndian.Uint16(question[:2])
	end := 12
	valid := binary.BigEndian.Uint16(question[4:6]) == 1
	nameWireLen := 0
	firstLabelLen := 0
	if valid {
		for {
			if end >= len(question) {
				valid = false
				break
			}
			labelLen := int(question[end])
			end++
			nameWireLen++
			if labelLen == 0 {
				break
			}
			if labelLen > 63 || nameWireLen+labelLen+1 > 255 || end+labelLen > len(question) {
				valid = false
				break
			}
			if decision.QNameLen != 0 {
				decision.QName[decision.QNameLen] = '.'
				decision.QNameLen++
			}
			decision.LabelCount++
			if decision.LabelCount == 1 {
				firstLabelLen = labelLen
			}
			if uint8(labelLen) > decision.MaxLabelLen {
				decision.MaxLabelLen = uint8(labelLen)
			}
			for _, c := range question[end : end+labelLen] {
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				decision.QName[decision.QNameLen] = c
				decision.QNameLen++
			}
			end += labelLen
			nameWireLen += labelLen
		}
		if end+4 > len(question) {
			valid = false
		}
	}

	if !valid {
		decision.Verdict = VerdictFormErr
		decision.RCode = 1
		copy(response[:2], question[:2])
		binary.BigEndian.PutUint16(response[2:4], 0x8001)
		clear(response[4:12])
		return 12, decision, nil
	}

	decision.QType = binary.BigEndian.Uint16(question[end : end+2])
	decision.QClass = binary.BigEndian.Uint16(question[end+2 : end+4])
	end += 4
	decision.InZone = true

	copy(response[:2], question[:2])
	binary.BigEndian.PutUint16(response[2:4], 0x8400)
	clear(response[4:12])
	response[5] = 1
	copy(response[12:end], question[12:end])

	if decision.QClass != 1 {
		decision.Verdict = VerdictRefused
		decision.RCode = 5
		binary.BigEndian.PutUint16(response[2:4], 0x8005)
		return end, decision, nil
	}

	qname := decision.QName[:decision.QNameLen]
	response[7] = 1
	response[end], response[end+1] = 0xc0, 0x0c
	binary.BigEndian.PutUint16(response[end+2:end+4], decision.QType)
	binary.BigEndian.PutUint16(response[end+4:end+6], 1)

	switch decision.QType {
	case 10: // NULL (iodine handshake & P1 NULL downlink)
		decision.Verdict = VerdictAnswerTXT
		first := byte(0)
		if len(qname) > 0 {
			first = qname[0]
		}
		switch first {
		case 'v':
			const vack = "VACK-IODINE-502"
			binary.BigEndian.PutUint32(response[end+6:end+10], 0)
			binary.BigEndian.PutUint16(response[end+10:end+12], uint16(len(vack)))
			copy(response[end+12:], vack)
			return end + 12 + len(vack), decision, nil
		case 'l':
			const lack = "LACK-OK-TUNNEL55"
			binary.BigEndian.PutUint32(response[end+6:end+10], 0)
			binary.BigEndian.PutUint16(response[end+10:end+12], uint16(len(lack)))
			copy(response[end+12:], lack)
			return end + 12 + len(lack), decision, nil
		case 'i':
			const iack = "10.55.99.1-10.55.99.2-27-1130"
			binary.BigEndian.PutUint32(response[end+6:end+10], 0)
			binary.BigEndian.PutUint16(response[end+10:end+12], uint16(len(iack)))
			copy(response[end+12:], iack)
			return end + 12 + len(iack), decision, nil
		case 'z':
			const zack = "ZACK-RAW-CODEC"
			binary.BigEndian.PutUint32(response[end+6:end+10], 0)
			binary.BigEndian.PutUint16(response[end+10:end+12], uint16(len(zack)))
			copy(response[end+12:], zack)
			return end + 12 + len(zack), decision, nil
		default:
			if first == 'p' && firstLabelLen <= 12 {
				const rdLen = 220
				binary.BigEndian.PutUint32(response[end+6:end+10], 2)
				binary.BigEndian.PutUint16(response[end+10:end+12], rdLen)
				fillPseudoRandom(response[end+12:end+12+rdLen], seed, qname, txid)
				return end + 12 + rdLen, decision, nil
			}
			const nullAck = "ack-ok"
			binary.BigEndian.PutUint32(response[end+6:end+10], 5)
			binary.BigEndian.PutUint16(response[end+10:end+12], uint16(len(nullAck)))
			copy(response[end+12:], nullAck)
			return end + 12 + len(nullAck), decision, nil
		}

	case 16: // TXT (RFC benign vs P1 downlink vs short ACK for upload/sharding/beacon)
		decision.Verdict = VerdictAnswerTXT
		if hasSubBytes(qname, "_domainkey") || hasSubBytes(qname, "_spf") ||
			hasSubBytes(qname, "_dmarc") || hasSubBytes(qname, "_acme-challenge") {
			const txt = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4"
			binary.BigEndian.PutUint32(response[end+6:end+10], 300)
			binary.BigEndian.PutUint16(response[end+10:end+12], uint16(1+len(txt)))
			response[end+12] = byte(len(txt))
			copy(response[end+13:], txt)
			return end + 13 + len(txt), decision, nil
		}
		first := byte(0)
		if len(qname) > 0 {
			first = qname[0]
		}
		if first == 'p' && firstLabelLen <= 12 {
			const txtLen = 220
			binary.BigEndian.PutUint32(response[end+6:end+10], 2)
			binary.BigEndian.PutUint16(response[end+10:end+12], txtLen+1)
			response[end+12] = txtLen
			fillPseudoRandom(response[end+13:end+13+txtLen], seed, qname, txid)
			return end + 13 + txtLen, decision, nil
		}
		const shortAck = "ack-ok"
		binary.BigEndian.PutUint32(response[end+6:end+10], 5)
		binary.BigEndian.PutUint16(response[end+10:end+12], uint16(1+len(shortAck)))
		response[end+12] = byte(len(shortAck))
		copy(response[end+13:], shortAck)
		return end + 13 + len(shortAck), decision, nil

	case 1: // A
		decision.Verdict = VerdictAnswerA
		binary.BigEndian.PutUint32(response[end+6:end+10], 60)
		binary.BigEndian.PutUint16(response[end+10:end+12], 4)
		response[end+12], response[end+13], response[end+14], response[end+15] = 10, 55, byte(seed), byte(end)
		return end + 16, decision, nil

	case 28: // AAAA
		decision.Verdict = VerdictAnswerA
		binary.BigEndian.PutUint32(response[end+6:end+10], 60)
		binary.BigEndian.PutUint16(response[end+10:end+12], 16)
		clear(response[end+12 : end+28])
		response[end+12], response[end+13], response[end+27] = 0xfd, 0x55, byte(seed)
		return end + 28, decision, nil

	case 5: // CNAME
		decision.Verdict = VerdictAnswerA
		binary.BigEndian.PutUint32(response[end+6:end+10], 5)
		binary.BigEndian.PutUint16(response[end+10:end+12], 2)
		response[end+12], response[end+13] = 0xc0, 0x0c
		return end + 14, decision, nil

	default:
		response[7] = 0
		decision.Verdict = VerdictNoData
		return end, decision, nil
	}
}
