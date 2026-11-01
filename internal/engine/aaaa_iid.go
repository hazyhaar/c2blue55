package engine

import "slices"

import "encoding/binary"

// ReasonP21AAAAIIDDownlink signale des identifiants d'interface AAAA distincts sous un même préfixe.
const ReasonP21AAAAIIDDownlink = "REASON_P21_AAAA_IID_DOWNLINK"

// AAAAIIDTracker conserve les identifiants récents par couple (client, préfixe /64).
type AAAAIIDTracker struct {
	tableCreneaux [256][4]struct {
		cleSuivi      uint64
		identifiants  [16]uint64
		horodatagesNs [16]int64
	}
}

func cleSuiviAAAAIID(clientIP [16]byte, prefixe []byte) uint64 {
	hachageCle := uint64(fnvOffset64)
	for _, octetIP := range clientIP {
		hachageCle ^= uint64(octetIP)
		hachageCle *= fnvPrime64
	}
	for _, octetPrefixe := range prefixe {
		hachageCle ^= uint64(octetPrefixe)
		hachageCle *= fnvPrime64
	}
	return hachageCle
}

// lireEnregistrementAAAAIID vérifie les bornes du nom, de l'en-tête et des données.
func lireEnregistrementAAAAIID(paquetFilaire []byte, decalageCourant int) (decalageSuivant int, debutDonnees int, admissible bool, valide bool) {
	finNom, _, nomValide := decompresserNomDNS(paquetFilaire, decalageCourant, len(paquetFilaire), false, nil)
	if !nomValide || finNom+10 > len(paquetFilaire) {
		return 0, 0, false, false
	}
	longueurDonnees := int(binary.BigEndian.Uint16(paquetFilaire[finNom+8 : finNom+10]))
	debutDonnees = finNom + 10
	decalageSuivant = debutDonnees + longueurDonnees
	if decalageSuivant > len(paquetFilaire) {
		return 0, 0, false, false
	}
	admissible = binary.BigEndian.Uint16(paquetFilaire[finNom:finNom+2]) == 28 &&
		binary.BigEndian.Uint16(paquetFilaire[finNom+2:finNom+4]) == 1 && longueurDonnees == 16
	return decalageSuivant, debutDonnees, admissible, true
}

func identifiantPleineLargeurAAAAIID(paquetFilaire []byte, debutDonnees int) bool {
	return !slices.Contains(paquetFilaire[debutDonnees+8:debutDonnees+16], 0)
}

func (t *AAAAIIDTracker) insererIdentifiant(cleSuivi uint64, identifiant uint64, tsNs int64) {
	alveoleCourante := &t.tableCreneaux[cleSuivi&255]
	indiceVoie := -1
	indiceVoieLibre := -1
	indiceVoieAncienne := 0
	var dateVoieAncienne int64
	for indiceCandidat := range alveoleCourante {
		voieCandidate := &alveoleCourante[indiceCandidat]
		dateRecente := int64(0)
		dateTrouvee := false
		for indiceIdentifiant, valeurIdentifiant := range voieCandidate.identifiants {
			if valeurIdentifiant != 0 && (!dateTrouvee || voieCandidate.horodatagesNs[indiceIdentifiant] > dateRecente) {
				dateRecente = voieCandidate.horodatagesNs[indiceIdentifiant]
				dateTrouvee = true
			}
		}
		if !dateTrouvee {
			if indiceVoieLibre < 0 {
				indiceVoieLibre = indiceCandidat
			}
			continue
		}
		if voieCandidate.cleSuivi == cleSuivi {
			indiceVoie = indiceCandidat
			break
		}
		if indiceCandidat == 0 || dateRecente < dateVoieAncienne {
			indiceVoieAncienne = indiceCandidat
			dateVoieAncienne = dateRecente
		}
	}
	if indiceVoie < 0 {
		indiceVoie = indiceVoieLibre
		if indiceVoie < 0 {
			indiceVoie = indiceVoieAncienne
		}
		voieRemplacee := &alveoleCourante[indiceVoie]
		voieRemplacee.cleSuivi = cleSuivi
		voieRemplacee.identifiants = [16]uint64{}
		voieRemplacee.horodatagesNs = [16]int64{}
	}
	voieCourante := &alveoleCourante[indiceVoie]
	seuilExpirationNs := tsNs - 600_000_000_000
	indiceLibre := -1
	indiceAncien := 0
	for indiceCase := range voieCourante.identifiants {
		if voieCourante.identifiants[indiceCase] != 0 && voieCourante.horodatagesNs[indiceCase] < seuilExpirationNs {
			voieCourante.identifiants[indiceCase] = 0
			voieCourante.horodatagesNs[indiceCase] = 0
		}
		if voieCourante.identifiants[indiceCase] == identifiant {
			voieCourante.horodatagesNs[indiceCase] = tsNs
			return
		}
		if voieCourante.identifiants[indiceCase] == 0 && indiceLibre < 0 {
			indiceLibre = indiceCase
		}
		if voieCourante.horodatagesNs[indiceCase] < voieCourante.horodatagesNs[indiceAncien] {
			indiceAncien = indiceCase
		}
	}
	if indiceLibre >= 0 {
		indiceAncien = indiceLibre
	}
	voieCourante.identifiants[indiceAncien] = identifiant
	voieCourante.horodatagesNs[indiceAncien] = tsNs
}

// ObserveResponse analyse tous les AAAA d'une réponse valide avant de décider du déclenchement.
func (t *AAAAIIDTracker) ObserveResponse(tsNs int64, clientIP [16]byte, respWire []byte) (fired bool, reason string) {
	if len(respWire) < 12 || respWire[2]&0x80 == 0 || respWire[3]&0x0f != 0 {
		return false, ReasonNone
	}
	nbQuestions := int(binary.BigEndian.Uint16(respWire[4:6]))
	nbReponses := int(binary.BigEndian.Uint16(respWire[6:8]))
	if nbQuestions == 0 || nbReponses == 0 {
		return false, ReasonNone
	}
	decalageCourant := 12
	for range nbQuestions {
		finQuestion, _, questionValide := decompresserNomDNS(respWire, decalageCourant, len(respWire), false, nil)
		if !questionValide || finQuestion+4 > len(respWire) {
			return false, ReasonNone
		}
		decalageCourant = finQuestion + 4
	}
	debutReponses := decalageCourant
	for range nbReponses {
		decalageSuivant, _, _, valide := lireEnregistrementAAAAIID(respWire, decalageCourant)
		if !valide {
			return false, ReasonNone
		}
		decalageCourant = decalageSuivant
	}
	for indiceReponse, decalageReponse := 0, debutReponses; indiceReponse < nbReponses; indiceReponse++ {
		decalageSuivant, debutDonnees, admissible, _ := lireEnregistrementAAAAIID(respWire, decalageReponse)
		if admissible && identifiantPleineLargeurAAAAIID(respWire, debutDonnees) {
			cleSuivi := cleSuiviAAAAIID(clientIP, respWire[debutDonnees:debutDonnees+8])
			identifiant := binary.BigEndian.Uint64(respWire[debutDonnees+8 : debutDonnees+16])
			t.insererIdentifiant(cleSuivi, identifiant, tsNs)
		}
		decalageReponse = decalageSuivant
	}
	for indiceReponse, decalageReponse := 0, debutReponses; indiceReponse < nbReponses; indiceReponse++ {
		decalageSuivant, debutDonnees, admissible, _ := lireEnregistrementAAAAIID(respWire, decalageReponse)
		if admissible && identifiantPleineLargeurAAAAIID(respWire, debutDonnees) {
			cleSuivi := cleSuiviAAAAIID(clientIP, respWire[debutDonnees:debutDonnees+8])
			for indiceVoie := range t.tableCreneaux[cleSuivi&255] {
				voieCandidate := &t.tableCreneaux[cleSuivi&255][indiceVoie]
				if voieCandidate.cleSuivi != cleSuivi {
					continue
				}
				nbIdentifiantsVivants := 0
				for indiceCase, identifiant := range voieCandidate.identifiants {
					if identifiant != 0 && voieCandidate.horodatagesNs[indiceCase] >= tsNs-600_000_000_000 {
						nbIdentifiantsVivants++
					}
				}
				if nbIdentifiantsVivants >= 8 {
					return true, ReasonP21AAAAIIDDownlink
				}
			}
		}
		decalageReponse = decalageSuivant
	}
	return false, ReasonNone
}
