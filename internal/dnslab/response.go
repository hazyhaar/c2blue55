package dnslab

import "encoding/binary"

// Verdict est la décision prise sur une question.
type Verdict uint8

const (
	VerdictIgnored Verdict = iota
	VerdictFormErr
	VerdictNotImp
	VerdictRefused
	VerdictAnswerA
	VerdictAnswerTXT
	VerdictNoData
	VerdictNXDomain
	VerdictAnswerAAAA
)

// String rend le nom du verdict pour le journal.
func (v Verdict) String() string {
	switch v {
	case VerdictIgnored:
		return "ignored"
	case VerdictFormErr:
		return "formerr"
	case VerdictNotImp:
		return "notimp"
	case VerdictRefused:
		return "refused"
	case VerdictAnswerA:
		return "answer_a"
	case VerdictAnswerTXT:
		return "answer_txt"
	case VerdictNoData:
		return "no_data"
	case VerdictNXDomain:
		return "nxdomain"
	case VerdictAnswerAAAA:
		return "answer_aaaa"
	}
	return "unknown"
}

// Decision décrit la question lue et la réponse construite.
type Decision struct {
	Verdict     Verdict
	RCode       uint8
	QType       uint16
	QClass      uint16
	QNameLen    uint8
	QName       [256]byte
	InZone      bool
	Encoded     bool
	LabelCount  uint8
	MaxLabelLen uint8
}

// BuildResponse lit une question (charge UDP) et écrit la réponse dans
// response (au moins 512 octets) sans allocation ; n == 0 quand aucune réponse
// ne doit être envoyée (ErrQueryTooShort, ErrNotAQuery).
func BuildResponse(question []byte, zone *Zone, response []byte) (n int, decision Decision, err error) {
	if len(question) < 12 {
		return 0, decision, ErrQueryTooShort
	}
	if question[2]&0x80 != 0 {
		return 0, decision, ErrNotAQuery
	}
	if len(response) < 512 {
		return 0, decision, ErrResponseBufferTooSmall
	}
	decision.Verdict = VerdictFormErr
	decision.RCode = 1
	opcodeUnsupported := question[2]&0x78 != 0
	if opcodeUnsupported {
		decision.Verdict, decision.RCode = VerdictNotImp, 4
	}
	end := 12
	valid := binary.BigEndian.Uint16(question[4:6]) == 1
	nameWireLen := 0
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
			if uint8(labelLen) > decision.MaxLabelLen {
				decision.MaxLabelLen = uint8(labelLen)
			}
			for _, c := range question[end : end+labelLen] {
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
					decision.Encoded = true
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
	if valid {
		decision.QType = binary.BigEndian.Uint16(question[end : end+2])
		decision.QClass = binary.BigEndian.Uint16(question[end+2 : end+4])
		end += 4
		name := decision.QName[:decision.QNameLen]
		apex := zone.Apex
		if len(name) >= len(apex) {
			start := len(name) - len(apex)
			matched := start == 0 || name[start-1] == '.'
			for i, c := range apex {
				other := name[start+i]
				if other >= 'A' && other <= 'Z' {
					other += 'a' - 'A'
				}
				if c >= 'A' && c <= 'Z' {
					c += 'a' - 'A'
				}
				matched = matched && c == other
			}
			decision.InZone = matched
		}
		switch {
		case opcodeUnsupported:
			decision.Verdict, decision.RCode = VerdictNotImp, 4
		case decision.QClass != 1:
			decision.Verdict, decision.RCode = VerdictRefused, 5
		case decision.QType == 255:
			decision.Verdict, decision.RCode = VerdictNotImp, 4
		case decision.QType == 251 || decision.QType == 252:
			decision.Verdict, decision.RCode = VerdictRefused, 5
		case !decision.InZone:
			decision.Verdict, decision.RCode = VerdictRefused, 5
		case zone.Negative != NegativeNone && len(name) >= 3 && name[0] == 'n' && name[1] == 'x' && name[2] == '-':
			decision.Verdict, decision.RCode = VerdictNXDomain, 3
		case decision.QType == 28 && zone.AAAA != AAAANone:
			decision.Verdict, decision.RCode = VerdictAnswerAAAA, 0
		case decision.QType == 1:
			decision.Verdict, decision.RCode = VerdictAnswerA, 0
		case decision.QType == 16:
			decision.Verdict, decision.RCode = VerdictAnswerTXT, 0
		default:
			decision.Verdict, decision.RCode = VerdictNoData, 0
		}
	}
	if end > 12+255+4 {
		valid = false
	}
	// Une question malformée ne fournit aucune section fiable à recopier.
	if !valid {
		if !opcodeUnsupported {
			decision.Verdict, decision.RCode = VerdictFormErr, 1
		}
		end = 12
	}
	if decision.Verdict == VerdictAnswerTXT && end+13+len(zone.AnswerTXT) >= 512 {
		// Réponse hors borne de 512 octets refusée plutôt que tronquée.
		decision.Verdict, decision.RCode = VerdictRefused, 5
	}
	var rdataSOA [600]byte
	var rdataLongueur int
	var ttlSOA uint32
	if decision.Verdict == VerdictNXDomain {
		var mnamePrefixe [18]byte
		var rnamePrefixe [18]byte
		var mnamePrefLen, rnamePrefLen int
		var serialSOA, minimumSOA uint32
		if zone.Negative == NegativeSOAStego {
			const chiffresHex = "0123456789abcdef"
			var graineOctets [8]byte
			binary.BigEndian.PutUint64(graineOctets[:], zone.NegativeSeed)
			empreinte := uint64(14695981039346656037)
			for _, b := range graineOctets {
				empreinte ^= uint64(b)
				empreinte *= 1099511628211
			}
			for _, b := range decision.QName[:decision.QNameLen] {
				empreinte ^= uint64(b)
				empreinte *= 1099511628211
			}
			empreinteRname := empreinte * 0x9E3779B97F4A7C15
			mnamePrefixe[0] = 'm'
			rnamePrefixe[0] = 'r'
			for i := range 16 {
				decalage := uint((15 - i) * 4)
				mnamePrefixe[1+i] = chiffresHex[(empreinte>>decalage)&0x0F]
				rnamePrefixe[1+i] = chiffresHex[(empreinteRname>>decalage)&0x0F]
			}
			mnamePrefLen = 17
			rnamePrefLen = 17
			serialSOA = uint32(empreinte)
			minimumSOA = 1
		} else {
			copy(mnamePrefixe[:], "ns1")
			mnamePrefLen = 3
			copy(rnamePrefixe[:], "hostmaster")
			rnamePrefLen = 10
			serialSOA = 2026102901
			minimumSOA = 300
		}
		ttlSOA = minimumSOA
		apexFilaireMax := len(zone.Apex) + 2
		tailleRequiseRData := 1 + mnamePrefLen + apexFilaireMax + 1 + rnamePrefLen + apexFilaireMax + 20
		if tailleRequiseRData > len(rdataSOA) {
			decision.Verdict, decision.RCode = VerdictRefused, 5
		} else {
			rdataSOA[rdataLongueur] = byte(mnamePrefLen)
			rdataLongueur++
			copy(rdataSOA[rdataLongueur:], mnamePrefixe[:mnamePrefLen])
			rdataLongueur += mnamePrefLen
			ecritMName := ecrireApexFilaire(rdataSOA[rdataLongueur:], zone.Apex)
			if ecritMName < 0 {
				decision.Verdict, decision.RCode = VerdictRefused, 5
			} else {
				rdataLongueur += ecritMName
				rdataSOA[rdataLongueur] = byte(rnamePrefLen)
				rdataLongueur++
				copy(rdataSOA[rdataLongueur:], rnamePrefixe[:rnamePrefLen])
				rdataLongueur += rnamePrefLen
				ecritRName := ecrireApexFilaire(rdataSOA[rdataLongueur:], zone.Apex)
				if ecritRName < 0 || rdataLongueur+ecritRName+20 > len(rdataSOA) {
					decision.Verdict, decision.RCode = VerdictRefused, 5
				} else {
					rdataLongueur += ecritRName
					binary.BigEndian.PutUint32(rdataSOA[rdataLongueur:rdataLongueur+4], serialSOA)
					binary.BigEndian.PutUint32(rdataSOA[rdataLongueur+4:rdataLongueur+8], 3600)
					binary.BigEndian.PutUint32(rdataSOA[rdataLongueur+8:rdataLongueur+12], 900)
					binary.BigEndian.PutUint32(rdataSOA[rdataLongueur+12:rdataLongueur+16], 604800)
					binary.BigEndian.PutUint32(rdataSOA[rdataLongueur+16:rdataLongueur+20], minimumSOA)
					rdataLongueur += 20
					decalageApex := 12 + int(decision.QNameLen) - len(zone.Apex)
					longueurProprietaire := 2
					if decalageApex < 12 || decalageApex > 0x3FFF {
						longueurProprietaire = len(zone.Apex) + 2
					}
					if end+longueurProprietaire+10+rdataLongueur > len(response) {
						decision.Verdict, decision.RCode = VerdictRefused, 5
					}
				}
			}
		}
	}
	if end > 12 {
		copy(response[12:], question[12:end])
	}
	copy(response[:2], question[:2])
	flags := uint16(0x8000) | uint16(question[2]&0x78)<<8 | uint16(question[2]&1)<<8 | uint16(decision.RCode)
	if decision.Verdict == VerdictAnswerA || decision.Verdict == VerdictAnswerTXT || decision.Verdict == VerdictAnswerAAAA || decision.Verdict == VerdictNoData || decision.Verdict == VerdictNXDomain {
		flags |= 0x0400
	}
	binary.BigEndian.PutUint16(response[2:4], flags)
	for i := 4; i < 12; i++ {
		response[i] = 0
	}
	if valid {
		response[5] = 1
	}
	n = end
	if decision.Verdict == VerdictAnswerA || decision.Verdict == VerdictAnswerTXT || decision.Verdict == VerdictAnswerAAAA {
		response[7] = 1
		response[n], response[n+1] = 0xc0, 0x0c
		binary.BigEndian.PutUint16(response[n+2:n+4], decision.QType)
		binary.BigEndian.PutUint16(response[n+4:n+6], 1)
		binary.BigEndian.PutUint32(response[n+6:n+10], zone.TTL)
		if decision.Verdict == VerdictAnswerA {
			binary.BigEndian.PutUint16(response[n+10:n+12], 4)
			copy(response[n+12:n+16], zone.AnswerA[:])
			n += 16
		} else if decision.Verdict == VerdictAnswerAAAA {
			binary.BigEndian.PutUint16(response[n+10:n+12], 16)
			if zone.AAAA == AAAAIIDStego {
				copy(response[n+12:n+20], zone.AnswerAAAA[:8])
				var octetsEnteteStego [16]byte
				binary.BigEndian.PutUint64(octetsEnteteStego[:8], zone.AAAASeed)
				binary.BigEndian.PutUint64(octetsEnteteStego[8:16], zone.AAAACounter)
				empreinteIID := uint64(14695981039346656037)
				for _, b := range octetsEnteteStego {
					empreinteIID ^= uint64(b)
					empreinteIID *= 1099511628211
				}
				for _, b := range decision.QName[:decision.QNameLen] {
					empreinteIID ^= uint64(b)
					empreinteIID *= 1099511628211
				}
				if empreinteIID == 0 {
					empreinteIID = 1
				}
				binary.BigEndian.PutUint64(response[n+20:n+28], empreinteIID)
				zone.AAAACounter++
			} else {
				copy(response[n+12:n+28], zone.AnswerAAAA[:])
			}
			n += 28
		} else {
			binary.BigEndian.PutUint16(response[n+10:n+12], uint16(1+len(zone.AnswerTXT)))
			response[n+12] = byte(len(zone.AnswerTXT))
			copy(response[n+13:], zone.AnswerTXT)
			n += 13 + len(zone.AnswerTXT)
		}
	} else if decision.Verdict == VerdictNXDomain {
		decalageApex := 12 + int(decision.QNameLen) - len(zone.Apex)
		longueurProprietaire := 2
		if decalageApex < 12 || decalageApex > 0x3FFF {
			longueurProprietaire = len(zone.Apex) + 2
		}
		if n+longueurProprietaire+10+rdataLongueur > len(response) {
			response[8] = 0
			response[9] = 0
			decision.Verdict, decision.RCode = VerdictRefused, 5
			flagsRefus := uint16(0x8000) | uint16(question[2]&0x78)<<8 | uint16(question[2]&1)<<8 | uint16(decision.RCode)
			binary.BigEndian.PutUint16(response[2:4], flagsRefus)
			return end, decision, nil
		}
		response[9] = 1
		if decalageApex >= 12 && decalageApex <= 0x3FFF {
			binary.BigEndian.PutUint16(response[n:n+2], 0xC000|uint16(decalageApex))
			n += 2
		} else {
			ecritApex := ecrireApexFilaire(response[n:], zone.Apex)
			if ecritApex < 0 || n+ecritApex+10+rdataLongueur > len(response) {
				response[8] = 0
				response[9] = 0
				decision.Verdict, decision.RCode = VerdictRefused, 5
				flagsRefus := uint16(0x8000) | uint16(question[2]&0x78)<<8 | uint16(question[2]&1)<<8 | uint16(decision.RCode)
				binary.BigEndian.PutUint16(response[2:4], flagsRefus)
				return end, decision, nil
			}
			n += ecritApex
		}
		binary.BigEndian.PutUint16(response[n:n+2], 6)
		binary.BigEndian.PutUint16(response[n+2:n+4], 1)
		binary.BigEndian.PutUint32(response[n+4:n+8], ttlSOA)
		binary.BigEndian.PutUint16(response[n+8:n+10], uint16(rdataLongueur))
		copy(response[n+10:n+10+rdataLongueur], rdataSOA[:rdataLongueur])
		n += 10 + rdataLongueur
	}
	return n, decision, nil
}

// ecrireApexFilaire encode un nom de domaine en clair (format filaire DNS terminé par 0).
func ecrireApexFilaire(cible []byte, apex []byte) int {
	curseur := 0
	debutLabel := 0
	for i := 0; i <= len(apex); i++ {
		if i == len(apex) || apex[i] == '.' {
			longueurLabel := i - debutLabel
			if curseur+1+longueurLabel+1 > len(cible) {
				return -1
			}
			cible[curseur] = byte(longueurLabel)
			curseur++
			copy(cible[curseur:], apex[debutLabel:i])
			curseur += longueurLabel
			debutLabel = i + 1
		}
	}
	if curseur >= len(cible) {
		return -1
	}
	cible[curseur] = 0
	curseur++
	return curseur
}
