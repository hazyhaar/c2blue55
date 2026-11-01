package icmplab

import (
	"encoding/binary"
	"errors"
)

const (
	fnvBase64    uint64 = 14695981039346656037
	fnvPremier64 uint64 = 1099511628211
	tailleEntete        = 8
	chargeMax           = 1400
)

// ErrEchoContract signale un paquet ou des paramètres hors contrat filaire.
var ErrEchoContract = errors.New("icmplab: echo hors contrat (type, taille, tampon)")

// EchoView expose une vue sans allocation sur un paquet ICMP Echo.
type EchoView struct {
	Type       uint8
	Code       uint8
	ID         uint16
	Seq        uint16
	ChecksumOK bool
	Payload    []byte
}

func sommeControleRFC1071(trame []byte) uint16 {
	var somme uint32
	longueur := len(trame)
	for i := 0; i+1 < longueur; i += 2 {
		somme += uint32(binary.BigEndian.Uint16(trame[i : i+2]))
	}
	if longueur%2 == 1 {
		somme += uint32(trame[longueur-1]) << 8
	}
	for somme>>16 != 0 {
		somme = (somme & 0xFFFF) + (somme >> 16)
	}
	return ^uint16(somme)
}

// BuildEcho assemble un paquet ICMP Echo (type 0 ou 8, code 0) dans cible.
func BuildEcho(typ uint8, id, seq uint16, charge, cible []byte) (int, error) {
	if typ != 0 && typ != 8 {
		return 0, ErrEchoContract
	}
	if len(charge) > chargeMax {
		return 0, ErrEchoContract
	}
	longueurTotale := tailleEntete + len(charge)
	if len(cible) < longueurTotale {
		return 0, ErrEchoContract
	}
	cible[0] = typ
	cible[1] = 0
	cible[2] = 0
	cible[3] = 0
	binary.BigEndian.PutUint16(cible[4:6], id)
	binary.BigEndian.PutUint16(cible[6:8], seq)
	copy(cible[tailleEntete:longueurTotale], charge)
	somme := sommeControleRFC1071(cible[:longueurTotale])
	binary.BigEndian.PutUint16(cible[2:4], somme)
	return longueurTotale, nil
}

// ParseEcho décode un paquet ICMP Echo sans copier la charge utile.
func ParseEcho(icmp []byte, vue *EchoView) error {
	if len(icmp) < tailleEntete || vue == nil {
		return ErrEchoContract
	}
	typ := icmp[0]
	if typ != 0 && typ != 8 {
		return ErrEchoContract
	}
	vue.Type = typ
	vue.Code = icmp[1]
	vue.ID = binary.BigEndian.Uint16(icmp[4:6])
	vue.Seq = binary.BigEndian.Uint16(icmp[6:8])
	vue.ChecksumOK = sommeControleRFC1071(icmp) == 0
	vue.Payload = icmp[tailleEntete:]
	return nil
}

func octetFluxFNV1a(cle uint64, position int) byte {
	empreinte := fnvBase64
	for decalage := 0; decalage < 64; decalage += 8 {
		empreinte ^= (cle >> decalage) & 0xFF
		empreinte *= fnvPremier64
	}
	indice := uint64(position)
	for decalage := 0; decalage < 64; decalage += 8 {
		empreinte ^= (indice >> decalage) & 0xFF
		empreinte *= fnvPremier64
	}
	return byte(empreinte ^ (empreinte >> 32))
}

// TransformPayload conserve les 4 premiers octets et applique un XOR FNV-1a 64 sur la suite.
func TransformPayload(cle uint64, entree, sortie []byte) int {
	longueur := min(len(sortie), len(entree))
	prefixe := min(longueur, 4)
	for i := range prefixe {
		sortie[i] = entree[i]
	}
	for i := prefixe; i < longueur; i++ {
		sortie[i] = entree[i] ^ octetFluxFNV1a(cle, i)
	}
	return longueur
}

// FNV1aPayload calcule l'empreinte FNV-1a 64 bits de la charge utile.
func FNV1aPayload(charge []byte) uint64 {
	empreinte := fnvBase64
	for i := range charge {
		empreinte ^= uint64(charge[i])
		empreinte *= fnvPremier64
	}
	return empreinte
}

// SourceAutoriseeLaboratoire retourne vrai si et seulement si ip appartient à 10.55.0.0/24.
func SourceAutoriseeLaboratoire(ip [4]byte) bool {
	return ip[0] == 10 && ip[1] == 55 && ip[2] == 0
}
