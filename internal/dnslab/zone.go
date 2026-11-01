// Package dnslab est le serveur DNS de laboratoire faisant autorité seule
// (strate S-04 de l'agent DNS) : réponses fixes sur une zone de laboratoire,
// refus hors zone, limitation de débit, journal typé. Aucune récursion, aucun
// relais, aucune réponse supérieure à 512 octets.
package dnslab

import "errors"

// Erreurs de BuildResponse et de construction.
var (
	ErrQueryTooShort          = errors.New("dnslab: question de moins de 12 octets")
	ErrNotAQuery              = errors.New("dnslab: datagramme portant le bit QR (réponse)")
	ErrResponseBufferTooSmall = errors.New("dnslab: tampon de réponse inférieur à 512 octets")
	ErrZoneContract           = errors.New("dnslab: zone hors contrat (apex vide ou label > 63, TXT > 255 octets)")
	ErrRateLimiterContract    = errors.New("dnslab: limiteur hors contrat (débit ou rafale nuls, seaux non puissance de deux)")
)

// NegativeMode règle la génération de réponses NXDOMAIN avec SOA en section Authority.
type NegativeMode uint8

const (
	NegativeNone NegativeMode = iota
	NegativeSOA
	NegativeSOAStego
)

// AAAAMode règle la génération des réponses AAAA (type 28).
type AAAAMode uint8

const (
	AAAANone AAAAMode = iota
	AAAAStatic
	AAAAIIDStego
)

// Zone est la zone de laboratoire servie : apex en minuscules, réponse A fixe,
// réponse TXT fixe (une chaîne de 255 octets au plus) et TTL.
type Zone struct {
	Apex         []byte
	AnswerA      [4]byte
	AnswerTXT    []byte
	TTL          uint32
	Negative     NegativeMode
	NegativeSeed uint64
	AAAA         AAAAMode
	AnswerAAAA   [16]byte
	AAAASeed     uint64
	AAAACounter  uint64
}

// NewZone valide et construit la zone (apex abaissé en minuscules ASCII).
func NewZone(apex string, answerA [4]byte, answerTXT string, ttl uint32) (Zone, error) {
	if len(apex) == 0 || len(apex) > 253 || len(answerTXT) > 255 {
		return Zone{}, ErrZoneContract
	}
	name := make([]byte, len(apex))
	labelLen := 0
	for i := range apex {
		c := apex[i]
		if c == '.' {
			if labelLen == 0 || labelLen > 63 {
				return Zone{}, ErrZoneContract
			}
			labelLen = 0
		} else {
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return Zone{}, ErrZoneContract
			}
			labelLen++
		}
		name[i] = c
	}
	if labelLen == 0 || labelLen > 63 {
		return Zone{}, ErrZoneContract
	}
	return Zone{Apex: name, AnswerA: answerA, AnswerTXT: []byte(answerTXT), TTL: ttl}, nil
}
