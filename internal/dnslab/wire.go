package dnslab

import (
	"encoding/binary"
	"errors"
)

// ErrQueryContract signale un nom de question hors contrat (vide, > 253
// octets, label > 63 octets) ou un tampon de question trop petit.
var ErrQueryContract = errors.New("dnslab: question hors contrat (nom vide, > 253 octets, label > 63, tampon < 512)")

// BuildQuery écrit dans query (au moins 512 octets) une question DNS standard
// (RD=0, QCLASS IN, sans OPT) pour qname et qtype, et rend sa longueur.
func BuildQuery(id uint16, qname []byte, qtype uint16, query []byte) (int, error) {
	if len(query) < 512 || len(qname) == 0 {
		return 0, ErrQueryContract
	}
	name := qname
	if name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	if len(name) == 0 || len(name) > 253 {
		return 0, ErrQueryContract
	}
	labelStart := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			if i-labelStart == 0 || i-labelStart > 63 {
				return 0, ErrQueryContract
			}
			labelStart = i + 1
		}
	}
	clear(query[:12])
	binary.BigEndian.PutUint16(query[:2], id)
	query[5] = 1
	position := 12
	labelStart = 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			query[position] = byte(i - labelStart)
			position++
			position += copy(query[position:], name[labelStart:i])
			labelStart = i + 1
		}
	}
	query[position] = 0
	position++
	binary.BigEndian.PutUint16(query[position:position+2], qtype)
	position += 2
	binary.BigEndian.PutUint16(query[position:position+2], 1)
	return position + 2, nil
}
