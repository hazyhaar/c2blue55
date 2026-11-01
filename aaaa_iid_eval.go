package c2blue55

import (
	"encoding/binary"

	"github.com/hazyhaar/c2blue55/internal/engine"
)

// AAAAIIDEvalReport rassemble les compteurs d'évaluation des réponses AAAA IID.
type AAAAIIDEvalReport struct {
	Responses          uint32
	AAAAAnswers        uint32
	Fires              uint32
	FiredKeys          uint32
	PacketsToFirstFire uint32
	FirstFireTsNs      uint64
}

// sauterNomAAAAIID vérifie le nom comprimé et borne les suivis de pointeur.
func sauterNomAAAAIID(charge []byte, position int) (int, bool) {
	finNom := -1
	sauts := 0
	longueur := 1
	for {
		if position >= len(charge) {
			return 0, false
		}
		octet := charge[position]
		position++
		if octet == 0 {
			if finNom >= 0 {
				return finNom, true
			}
			return position, true
		}
		if octet&0xc0 == 0xc0 {
			if position >= len(charge) || sauts >= 8 {
				return 0, false
			}
			cible := int(octet&0x3f)<<8 | int(charge[position])
			position++
			if cible >= len(charge) {
				return 0, false
			}
			if finNom < 0 {
				finNom = position
			}
			position = cible
			sauts++
			continue
		}
		if octet&0xc0 != 0 || longueur+int(octet)+1 > 255 || int(octet) > len(charge)-position {
			return 0, false
		}
		longueur += int(octet) + 1
		position += int(octet)
	}
}

// compterReponsesAAAAIID parcourt seulement la section réponse, sans compter un message tronqué.
func compterReponsesAAAAIID(charge []byte) (uint32, [8]byte, bool, bool) {
	var prefixe [8]byte
	position := 12
	for indice := 0; indice < int(binary.BigEndian.Uint16(charge[4:6])); indice++ {
		finNom, valide := sauterNomAAAAIID(charge, position)
		if !valide || len(charge)-finNom < 4 {
			return 0, prefixe, false, false
		}
		position = finNom + 4
	}
	var nombre uint32
	premierTrouve := false
	for indice := 0; indice < int(binary.BigEndian.Uint16(charge[6:8])); indice++ {
		finNom, valide := sauterNomAAAAIID(charge, position)
		if !valide || len(charge)-finNom < 10 {
			return 0, prefixe, false, false
		}
		longueur := int(binary.BigEndian.Uint16(charge[finNom+8 : finNom+10]))
		position = finNom + 10
		if longueur > len(charge)-position {
			return 0, prefixe, false, false
		}
		if binary.BigEndian.Uint16(charge[finNom:finNom+2]) == 28 {
			nombre++
			if !premierTrouve && longueur >= len(prefixe) {
				copy(prefixe[:], charge[position:position+len(prefixe)])
				premierTrouve = true
			}
		}
		position += longueur
	}
	return nombre, prefixe, premierTrouve, true
}

// EvaluateAAAAIIDPCAP rejoue les réponses DNS d'une capture dans le détecteur AAAA IID.
func EvaluateAAAAIIDPCAP(pcapPath string) (AAAAIIDEvalReport, error) {
	var rapport AAAAIIDEvalReport
	var detecteur engine.AAAAIIDTracker
	var clesDejaComptees [1024]uint64
	var rangPaquet uint32

	_, err := ReadPCAPDNSWire(pcapPath, func(enveloppe PCAPMessageMeta, charge []byte) error {
		rangPaquet++
		if len(charge) < 12 || charge[2]&0x80 == 0 {
			return nil
		}
		rapport.Responses++
		nombre, prefixe, premierTrouve, valide := compterReponsesAAAAIID(charge)
		if !valide {
			return nil
		}
		rapport.AAAAAnswers += nombre
		feu, _ := detecteur.ObserveResponse(int64(enveloppe.TimestampNs), enveloppe.DstIP, charge)
		if !feu {
			return nil
		}
		rapport.Fires++
		if rapport.Fires == 1 {
			rapport.PacketsToFirstFire = rangPaquet
			rapport.FirstFireTsNs = enveloppe.TimestampNs
		}
		if !premierTrouve {
			return nil
		}
		cle := uint64(decalageBaseFNV64)
		for _, octet := range enveloppe.DstIP {
			cle ^= uint64(octet)
			cle *= facteurPremierFNV
		}
		for _, octet := range prefixe {
			cle ^= uint64(octet)
			cle *= facteurPremierFNV
		}
		for indice := uint32(0); indice < rapport.FiredKeys; indice++ {
			if clesDejaComptees[indice] == cle {
				return nil
			}
		}
		if rapport.FiredKeys < uint32(len(clesDejaComptees)) {
			clesDejaComptees[rapport.FiredKeys] = cle
			rapport.FiredKeys++
		}
		return nil
	})
	return rapport, err
}
