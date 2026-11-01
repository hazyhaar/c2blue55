package c2blue55

import (
	"encoding/binary"

	"github.com/hazyhaar/c2blue55/internal/engine"
)

const (
	decalageBaseFNV64 = 14695981039346656037
	facteurPremierFNV = 1099511628211
)

// SOANegativeEvalReport synthétise les compteurs d'évaluation hors ligne du canal SOA négatif sur une capture PCAP.
type SOANegativeEvalReport struct {
	Responses                 uint32
	NegativeWithSOA           uint32
	NegativeWithAnswerPayload uint32
	Fires                     uint32
	FiredKeys                 uint32
	PacketsToFirstFire        uint32
	FirstFireTsNs             uint64
}

// NegativeAnswerPayloadPackets retourne le nombre de réponses NXDOMAIN portant une section Answer non permise par RFC 2308/4035.
func NegativeAnswerPayloadPackets(report SOANegativeEvalReport) uint32 {
	return report.NegativeWithAnswerPayload
}

func extraireParentMinuscules(paquetFilaire []byte) ([255]byte, int) {
	var tamponParent [255]byte
	posCourante := 12
	nbSauts := 0
	longueurFilaire := 0
	longueurNom := 0
	indiceEtiquette := 0

	for {
		if posCourante >= len(paquetFilaire) {
			return tamponParent, 0
		}
		octetLongueur := paquetFilaire[posCourante]
		if octetLongueur == 0 {
			return tamponParent, longueurNom
		}
		if (octetLongueur & 0xC0) == 0xC0 {
			if posCourante+1 >= len(paquetFilaire) {
				return tamponParent, 0
			}
			nbSauts++
			if nbSauts > 8 {
				return tamponParent, 0
			}
			ciblePointeur := (int(octetLongueur&0x3F) << 8) | int(paquetFilaire[posCourante+1])
			if ciblePointeur >= len(paquetFilaire) {
				return tamponParent, 0
			}
			posCourante = ciblePointeur
			continue
		}
		if (octetLongueur & 0xC0) != 0 {
			return tamponParent, 0
		}
		longueurEtiquette := int(octetLongueur)
		if posCourante+1+longueurEtiquette > len(paquetFilaire) {
			return tamponParent, 0
		}
		longueurFilaire += 1 + longueurEtiquette
		if longueurFilaire > 255 {
			return tamponParent, 0
		}
		if indiceEtiquette > 0 {
			if longueurNom > 0 {
				if longueurNom >= 255 {
					return tamponParent, 0
				}
				tamponParent[longueurNom] = '.'
				longueurNom++
			}
			if longueurNom+longueurEtiquette > 255 {
				return tamponParent, 0
			}
			for indiceOctet := range longueurEtiquette {
				octetCaractere := paquetFilaire[posCourante+1+indiceOctet]
				if octetCaractere >= 'A' && octetCaractere <= 'Z' {
					octetCaractere += 'a' - 'A'
				}
				tamponParent[longueurNom] = octetCaractere
				longueurNom++
			}
		}
		indiceEtiquette++
		posCourante += 1 + longueurEtiquette
	}
}

func calculerCleCoupleParent(adresseDest [16]byte, paquetFilaire []byte) uint64 {
	tamponParent, longueurParent := extraireParentMinuscules(paquetFilaire)
	hachageCle := uint64(decalageBaseFNV64)
	for indiceOctet := range 16 {
		hachageCle ^= uint64(adresseDest[indiceOctet])
		hachageCle *= facteurPremierFNV
	}
	for indiceOctet := range longueurParent {
		hachageCle ^= uint64(tamponParent[indiceOctet])
		hachageCle *= facteurPremierFNV
	}
	if hachageCle == 0 {
		hachageCle = 1
	}
	return hachageCle
}

func sauterNomDNS(paquetFilaire []byte, position int) (int, bool) {
	longueurNom := 1
	for {
		if position >= len(paquetFilaire) {
			return 0, false
		}
		longueurEtiquette := paquetFilaire[position]
		position++
		if longueurEtiquette == 0 {
			return position, true
		}
		if longueurEtiquette&0xC0 == 0xC0 {
			if position >= len(paquetFilaire) {
				return 0, false
			}
			cible := int(longueurEtiquette&0x3F)<<8 | int(paquetFilaire[position])
			if cible >= len(paquetFilaire) {
				return 0, false
			}
			return position + 1, true
		}
		if longueurEtiquette&0xC0 != 0 || longueurNom+int(longueurEtiquette)+1 > 255 || int(longueurEtiquette) > len(paquetFilaire)-position {
			return 0, false
		}
		longueurNom += int(longueurEtiquette) + 1
		position += int(longueurEtiquette)
	}
}

func contientSOAAutorite(paquetFilaire []byte) bool {
	position := 12
	questions := int(binary.BigEndian.Uint16(paquetFilaire[4:6]))
	reponses := int(binary.BigEndian.Uint16(paquetFilaire[6:8]))
	autorites := int(binary.BigEndian.Uint16(paquetFilaire[8:10]))
	for range questions {
		var valide bool
		position, valide = sauterNomDNS(paquetFilaire, position)
		if !valide || len(paquetFilaire)-position < 4 {
			return false
		}
		position += 4
	}
	for indice := 0; indice < reponses+autorites; indice++ {
		var valide bool
		position, valide = sauterNomDNS(paquetFilaire, position)
		if !valide || len(paquetFilaire)-position < 10 {
			return false
		}
		typeRessource := binary.BigEndian.Uint16(paquetFilaire[position : position+2])
		longueurDonnees := int(binary.BigEndian.Uint16(paquetFilaire[position+8 : position+10]))
		position += 10
		if longueurDonnees > len(paquetFilaire)-position {
			return false
		}
		if indice >= reponses && typeRessource == 6 {
			return true
		}
		position += longueurDonnees
	}
	return false
}

func contientChargeReponseIllegitimeNXDOMAIN(paquetFilaire []byte) bool {
	position := 12
	questions := int(binary.BigEndian.Uint16(paquetFilaire[4:6]))
	reponses := int(binary.BigEndian.Uint16(paquetFilaire[6:8]))
	if questions == 0 {
		return true
	}
	for range questions {
		var valide bool
		position, valide = sauterNomDNS(paquetFilaire, position)
		if !valide || len(paquetFilaire)-position < 4 {
			return true
		}
		position += 4
	}
	for range reponses {
		var valide bool
		position, valide = sauterNomDNS(paquetFilaire, position)
		if !valide || len(paquetFilaire)-position < 10 {
			return true
		}
		typeRessource := binary.BigEndian.Uint16(paquetFilaire[position : position+2])
		longueurDonnees := int(binary.BigEndian.Uint16(paquetFilaire[position+8 : position+10]))
		position += 10
		if longueurDonnees > len(paquetFilaire)-position {
			return true
		}
		if typeRessource != 5 && typeRessource != 39 && typeRessource != 46 {
			return true
		}
		position += longueurDonnees
	}
	return false
}

// EvaluateSOANegativePCAP évalue une capture PCAP bidirectionnelle contre le détecteur SOANegativeTracker.
func EvaluateSOANegativePCAP(pcapPath string) (SOANegativeEvalReport, error) {
	var rapport SOANegativeEvalReport
	var detecteurSOA engine.SOANegativeTracker
	var clesDejaComptees [1024]uint64
	var rangPaquet uint32

	_, err := ReadPCAPDNSWire(pcapPath, func(enveloppePaquet PCAPMessageMeta, chargeFilaire []byte) error {
		rangPaquet++
		if len(chargeFilaire) < 12 {
			return nil
		}
		if (chargeFilaire[2] & 0x80) == 0 {
			return nil
		}
		rapport.Responses++

		codeOperation := (chargeFilaire[2] >> 3) & 0x0F
		codeReponse := chargeFilaire[3] & 0x0F
		nbReponses := binary.BigEndian.Uint16(chargeFilaire[6:8])
		nbAutorites := binary.BigEndian.Uint16(chargeFilaire[8:10])
		if codeOperation == 0 && codeReponse == 3 && nbReponses >= 1 && contientChargeReponseIllegitimeNXDOMAIN(chargeFilaire) {
			rapport.NegativeWithAnswerPayload++
		}
		if nbReponses == 0 && (codeReponse == 0 || codeReponse == 3) && nbAutorites >= 1 && contientSOAAutorite(chargeFilaire) {
			rapport.NegativeWithSOA++
		}

		feuDeclenche, _ := detecteurSOA.ObserveResponse(int64(enveloppePaquet.TimestampNs), enveloppePaquet.DstIP, chargeFilaire)
		if !feuDeclenche {
			return nil
		}

		rapport.Fires++
		if rapport.Fires == 1 {
			rapport.PacketsToFirstFire = rangPaquet
			rapport.FirstFireTsNs = enveloppePaquet.TimestampNs
		}

		cleCouple := calculerCleCoupleParent(enveloppePaquet.DstIP, chargeFilaire)
		dejaVue := false
		for indiceCle := uint32(0); indiceCle < rapport.FiredKeys && indiceCle < 1024; indiceCle++ {
			if clesDejaComptees[indiceCle] == cleCouple {
				dejaVue = true
				break
			}
		}
		if !dejaVue {
			if rapport.FiredKeys < 1024 {
				clesDejaComptees[rapport.FiredKeys] = cleCouple
			}
			rapport.FiredKeys++
		}
		return nil
	})
	if err != nil {
		return rapport, err
	}
	return rapport, nil
}
