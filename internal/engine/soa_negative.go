package engine

import "encoding/binary"

// ReasonP20SOANegDownlink identifie le canal descendant logé dans les champs SOA des réponses DNS négatives.
const ReasonP20SOANegDownlink = "REASON_P20_SOA_NEG_DOWNLINK"

// SOANegativeTracker suit par couple (client, propriétaire SOA) la diversité des empreintes SOA négatives.
type SOANegativeTracker struct {
	tableCreneaux [256][4]struct {
		cleSuivi      uint64
		empreintesSOA [8]uint64
		horodatagesNs [8]int64
	}
}

func cleSuiviSOA(clientIP [16]byte, proprietaire []byte) uint64 {
	hachageCle := uint64(fnvOffset64)
	for _, octetIP := range clientIP {
		hachageCle ^= uint64(octetIP)
		hachageCle *= fnvPrime64
	}
	for _, octetNom := range proprietaire {
		if octetNom >= 'A' && octetNom <= 'Z' {
			octetNom += 'a' - 'A'
		}
		hachageCle ^= uint64(octetNom)
		hachageCle *= fnvPrime64
	}
	return hachageCle
}

func indexAlveoleSOA(cle uint64) int {
	return int(cle & 255)
}

func decompresserNomDNS(paquetFilaire []byte, decalageInitial int, borneInline int, ignorerPremierLabel bool, tamponNom *[255]byte, frontieresLabels ...*[255]bool) (int, int, bool) {
	posCourante := decalageInitial
	finInline := -1
	nbSauts := 0
	longueurFilaire := 0
	longueurNom := 0
	indiceEtiquette := 0

	for {
		if nbSauts == 0 {
			if posCourante >= borneInline {
				return 0, 0, false
			}
		} else if posCourante >= len(paquetFilaire) {
			return 0, 0, false
		}

		octetLongueur := paquetFilaire[posCourante]
		if octetLongueur == 0 {
			longueurFilaire++
			if longueurFilaire > 255 {
				return 0, 0, false
			}
			if nbSauts == 0 {
				finInline = posCourante + 1
			}
			return finInline, longueurNom, true
		}

		if (octetLongueur & 0xC0) == 0xC0 {
			if nbSauts == 0 {
				if posCourante+1 >= borneInline {
					return 0, 0, false
				}
				finInline = posCourante + 2
			} else if posCourante+1 >= len(paquetFilaire) {
				return 0, 0, false
			}
			nbSauts++
			if nbSauts > 8 {
				return 0, 0, false
			}
			ciblePointeur := (int(octetLongueur&0x3F) << 8) | int(paquetFilaire[posCourante+1])
			if ciblePointeur >= len(paquetFilaire) {
				return 0, 0, false
			}
			posCourante = ciblePointeur
			continue
		}

		if (octetLongueur & 0xC0) != 0 {
			return 0, 0, false
		}

		longueurEtiquette := int(octetLongueur)
		if nbSauts == 0 {
			if posCourante+1+longueurEtiquette > borneInline {
				return 0, 0, false
			}
		} else if posCourante+1+longueurEtiquette > len(paquetFilaire) {
			return 0, 0, false
		}

		longueurFilaire += 1 + longueurEtiquette
		if longueurFilaire > 255 {
			return 0, 0, false
		}

		if tamponNom != nil && (!ignorerPremierLabel || indiceEtiquette > 0) {
			if longueurNom > 0 {
				if longueurNom >= 255 {
					return 0, 0, false
				}
				tamponNom[longueurNom] = '.'
				longueurNom++
			}
			if longueurNom+longueurEtiquette > 255 {
				return 0, 0, false
			}
			if len(frontieresLabels) > 0 {
				frontieresLabels[0][longueurNom] = true
			}
			for indiceOctet := range longueurEtiquette {
				octetCaractere := paquetFilaire[posCourante+1+indiceOctet]
				if octetCaractere >= 'A' && octetCaractere <= 'Z' {
					octetCaractere += 'a' - 'A'
				}
				tamponNom[longueurNom] = octetCaractere
				longueurNom++
			}
		}

		indiceEtiquette++
		posCourante += 1 + longueurEtiquette
	}
}

// ObserveResponse inspecte une réponse DNS filaire et déclenche ReasonP20SOANegDownlink dès 3 SOA distincts en 10 minutes.
func (t *SOANegativeTracker) ObserveResponse(tsNs int64, clientIP [16]byte, respWire []byte) (fired bool, reason string) {
	if len(respWire) < 12 {
		return false, ReasonNone
	}
	if (respWire[2] & 0x80) == 0 {
		return false, ReasonNone
	}
	codeReponse := respWire[3] & 0x0F
	if codeReponse != 0 && codeReponse != 3 {
		return false, ReasonNone
	}
	nbQuestions := int(binary.BigEndian.Uint16(respWire[4:6]))
	nbReponses := int(binary.BigEndian.Uint16(respWire[6:8]))
	nbAutorites := int(binary.BigEndian.Uint16(respWire[8:10]))
	if nbQuestions == 0 || nbReponses > 0 || nbAutorites == 0 {
		return false, ReasonNone
	}

	var tamponQuestion [255]byte
	var frontieresQuestion [255]bool
	decalageCourant, longueurQuestion, nomValide := decompresserNomDNS(respWire, 12, len(respWire), false, &tamponQuestion, &frontieresQuestion)
	if !nomValide || decalageCourant+4 > len(respWire) {
		return false, ReasonNone
	}
	decalageCourant += 4

	for indiceQuestion := 1; indiceQuestion < nbQuestions; indiceQuestion++ {
		finQuestion, _, questionValide := decompresserNomDNS(respWire, decalageCourant, len(respWire), false, nil)
		if !questionValide || finQuestion+4 > len(respWire) {
			return false, ReasonNone
		}
		decalageCourant = finQuestion + 4
	}

	var tamponMName [255]byte
	var tamponRName [255]byte
	var tamponProprietaire [255]byte
	var frontieresProprietaire [255]bool
	longueurProprietaire := 0
	longueurMName := 0
	longueurRName := 0
	decalageSerial := -1

	for range nbAutorites {
		finProprietaire, _, proprietaireValide := decompresserNomDNS(respWire, decalageCourant, len(respWire), false, nil)
		if !proprietaireValide || finProprietaire+10 > len(respWire) {
			return false, ReasonNone
		}
		typeEnregistrement := binary.BigEndian.Uint16(respWire[finProprietaire : finProprietaire+2])
		longueurDonnees := int(binary.BigEndian.Uint16(respWire[finProprietaire+8 : finProprietaire+10]))
		debutDonnees := finProprietaire + 10
		finDonnees := debutDonnees + longueurDonnees
		if finDonnees > len(respWire) {
			return false, ReasonNone
		}
		if typeEnregistrement == 6 {
			_, tailleProprietaire, nomProprietaireValide := decompresserNomDNS(respWire, decalageCourant, finProprietaire, false, &tamponProprietaire, &frontieresProprietaire)
			if !nomProprietaireValide || tailleProprietaire > longueurQuestion {
				return false, ReasonNone
			}
			nombreLabels := 0
			for _, debutLabel := range frontieresProprietaire[:tailleProprietaire] {
				if debutLabel {
					nombreLabels++
				}
			}
			debutSuffixe := longueurQuestion - tailleProprietaire
			if nombreLabels < 2 || !frontieresQuestion[debutSuffixe] {
				return false, ReasonNone
			}
			for indiceOctet := range tailleProprietaire {
				if tamponQuestion[debutSuffixe+indiceOctet] != tamponProprietaire[indiceOctet] || frontieresQuestion[debutSuffixe+indiceOctet] != frontieresProprietaire[indiceOctet] {
					return false, ReasonNone
				}
			}
			longueurProprietaire = tailleProprietaire
			finMName, tailleMName, mnameValide := decompresserNomDNS(respWire, debutDonnees, finDonnees, false, &tamponMName)
			if !mnameValide {
				return false, ReasonNone
			}
			finRName, tailleRName, rnameValide := decompresserNomDNS(respWire, finMName, finDonnees, false, &tamponRName)
			if !rnameValide || finRName+20 > finDonnees {
				return false, ReasonNone
			}
			longueurMName = tailleMName
			longueurRName = tailleRName
			decalageSerial = finRName
			break
		}
		decalageCourant = finDonnees
	}

	if decalageSerial < 0 {
		return false, ReasonNone
	}

	hachageCle := cleSuiviSOA(clientIP, tamponProprietaire[:longueurProprietaire])

	empreinteSOA := uint64(fnvOffset64)
	for indiceNom := 0; indiceNom < longueurMName; indiceNom++ {
		empreinteSOA ^= uint64(tamponMName[indiceNom])
		empreinteSOA *= fnvPrime64
	}
	empreinteSOA ^= 0
	empreinteSOA *= fnvPrime64
	for indiceNom := 0; indiceNom < longueurRName; indiceNom++ {
		empreinteSOA ^= uint64(tamponRName[indiceNom])
		empreinteSOA *= fnvPrime64
	}
	empreinteSOA ^= 0
	empreinteSOA *= fnvPrime64
	for indiceSerial := range 4 {
		empreinteSOA ^= uint64(respWire[decalageSerial+indiceSerial])
		empreinteSOA *= fnvPrime64
	}
	if empreinteSOA == 0 {
		empreinteSOA = 1
	}

	alveoleCourante := &t.tableCreneaux[indexAlveoleSOA(hachageCle)]
	indiceVoie := -1
	indiceVoieLibre := -1
	indiceVoieAncienne := 0
	var dateVoieAncienne int64
	for indiceCandidat := range alveoleCourante {
		voieCandidate := &alveoleCourante[indiceCandidat]
		if voieCandidate.empreintesSOA == [8]uint64{} {
			if indiceVoieLibre < 0 {
				indiceVoieLibre = indiceCandidat
			}
			continue
		}
		if voieCandidate.cleSuivi == hachageCle {
			indiceVoie = indiceCandidat
			break
		}
		var dateRecente int64
		dateTrouvee := false
		for indiceEmpreinte, empreinte := range voieCandidate.empreintesSOA {
			if empreinte != 0 && (!dateTrouvee || voieCandidate.horodatagesNs[indiceEmpreinte] > dateRecente) {
				dateRecente = voieCandidate.horodatagesNs[indiceEmpreinte]
				dateTrouvee = true
			}
		}
		if indiceCandidat == 0 || dateRecente < dateVoieAncienne {
			indiceVoieAncienne = indiceCandidat
			dateVoieAncienne = dateRecente
		}
	}
	cleAbsente := indiceVoie < 0
	if cleAbsente {
		indiceVoie = indiceVoieLibre
		if indiceVoie < 0 {
			indiceVoie = indiceVoieAncienne
		}
	}
	creneauCourant := &alveoleCourante[indiceVoie]
	if cleAbsente {
		creneauCourant.cleSuivi = hachageCle
		creneauCourant.empreintesSOA = [8]uint64{}
		creneauCourant.horodatagesNs = [8]int64{}
	}

	seuilExpirationNs := tsNs - 600_000_000_000
	empreinteConnue := false
	indiceLibre := -1
	indicePlusAncien := 0

	for indiceSlot := range 8 {
		if creneauCourant.empreintesSOA[indiceSlot] != 0 && creneauCourant.horodatagesNs[indiceSlot] < seuilExpirationNs {
			creneauCourant.empreintesSOA[indiceSlot] = 0
			creneauCourant.horodatagesNs[indiceSlot] = 0
		}
		if creneauCourant.empreintesSOA[indiceSlot] == empreinteSOA {
			creneauCourant.horodatagesNs[indiceSlot] = tsNs
			empreinteConnue = true
		} else if creneauCourant.empreintesSOA[indiceSlot] == 0 && indiceLibre < 0 {
			indiceLibre = indiceSlot
		}
	}

	if !empreinteConnue {
		if indiceLibre >= 0 {
			creneauCourant.empreintesSOA[indiceLibre] = empreinteSOA
			creneauCourant.horodatagesNs[indiceLibre] = tsNs
		} else {
			for indiceSlot := 1; indiceSlot < 8; indiceSlot++ {
				if creneauCourant.horodatagesNs[indiceSlot] < creneauCourant.horodatagesNs[indicePlusAncien] {
					indicePlusAncien = indiceSlot
				}
			}
			creneauCourant.empreintesSOA[indicePlusAncien] = empreinteSOA
			creneauCourant.horodatagesNs[indicePlusAncien] = tsNs
		}
	}

	nbEmpreintesVivantes := 0
	for indiceSlot := range 8 {
		if creneauCourant.empreintesSOA[indiceSlot] != 0 {
			nbEmpreintesVivantes++
		}
	}

	if nbEmpreintesVivantes >= 3 {
		return true, ReasonP20SOANegDownlink
	}
	return false, ReasonNone
}
