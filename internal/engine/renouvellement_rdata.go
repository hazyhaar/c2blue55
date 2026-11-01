// Package engine — renouvellement_rdata.go
// Détecteur P15 sans allocation (0 B/op) du renouvellement anormal d'empreintes RRset
// de grande taille en section Answer sur réponses DNS positives (NS, MX, TXT, SRV, CAA).
package engine

import "encoding/binary"

const (
	fenetreRenouvellementRDataNs       int64 = 600_000_000_000
	seuilReponsesRenouvellementRData   int   = 8
	seuilPermilleRenouvellementRData   int64 = 750
	seuilMoyenneRDLengthRenouvellement       = uint16(128)
)

// RenouvellementRDataObs résume l'observation glissante du renouvellement RDATA d'un couple (client, apex, qtype).
type RenouvellementRDataObs struct {
	Reponses        uint16
	Distinctes      uint8
	MoyenneRDLength uint16
	Permille        int64
	Valide          bool
}

type voieRenouvellementRData struct {
	cleCouple        uint64
	dernierAccesNs   int64
	empreintesAnneau [16]uint64
	horodatagesNs    [16]int64
	taillesRData     [16]uint16
	debutAnneau      uint8
	nbEntrees        uint8
}

// RenouvellementRDataTracker maintient en mémoire fixe (256 ensembles x 4 voies associatives LRU)
// les 16 dernières empreintes RRset canoniques par couple (client normalisé, apex insensible à la casse, qtype).
type RenouvellementRDataTracker struct {
	alveoles [256][4]voieRenouvellementRData
}

func qtypeAdmissibleRenouvellementRData(qtype uint16) bool {
	switch qtype {
	case 2, 15, 16, 33, 257:
		return true
	default:
		return false
	}
}

func normaliserCleClientRData(clientIP [16]byte) [16]byte {
	var normalisee [16]byte
	estIPv4Mappee := clientIP[10] == 0xff && clientIP[11] == 0xff
	if estIPv4Mappee {
		for indice := range 10 {
			if clientIP[indice] != 0 {
				estIPv4Mappee = false
				break
			}
		}
	}
	if estIPv4Mappee {
		copy(normalisee[0:4], clientIP[12:16])
		return normalisee
	}
	estIPv6Reelle := false
	for indice := 4; indice < 16; indice++ {
		if clientIP[indice] != 0 {
			estIPv6Reelle = true
			break
		}
	}
	if estIPv6Reelle {
		copy(normalisee[0:8], clientIP[0:8])
		return normalisee
	}
	copy(normalisee[0:4], clientIP[0:4])
	return normalisee
}

func melangerSplitMix64(entree uint64) uint64 {
	etat := entree + 0x9e3779b97f4a7c15
	etat = (etat ^ (etat >> 30)) * 0xbf58476d1ce4e5b9
	etat = (etat ^ (etat >> 27)) * 0x94d049bb133111eb
	return etat ^ (etat >> 31)
}

func calculerCleRenouvellementRData(clientIP [16]byte, parentApex []byte, qtype uint16) uint64 {
	cleClient := normaliserCleClientRData(clientIP)
	hachage := uint64(fnvOffset64)
	for _, octetIP := range cleClient {
		hachage ^= uint64(octetIP)
		hachage *= fnvPrime64
	}
	hachage ^= 0
	hachage *= fnvPrime64

	longueurApex := len(parentApex)
	for longueurApex > 0 && parentApex[longueurApex-1] == '.' {
		longueurApex--
	}
	for indice := range longueurApex {
		caractere := parentApex[indice]
		if caractere >= 'A' && caractere <= 'Z' {
			caractere += 'a' - 'A'
		}
		hachage ^= uint64(caractere)
		hachage *= fnvPrime64
	}
	hachage ^= 0
	hachage *= fnvPrime64
	hachage ^= uint64(byte(qtype >> 8))
	hachage *= fnvPrime64
	hachage ^= uint64(byte(qtype))
	hachage *= fnvPrime64

	cleFinale := melangerSplitMix64(hachage)
	if cleFinale == 0 {
		return 1
	}
	return cleFinale
}

func hacherOctetsFNV64a(etatInitial uint64, octets []byte) uint64 {
	hachage := etatInitial
	for _, octetCourant := range octets {
		hachage ^= uint64(octetCourant)
		hachage *= fnvPrime64
	}
	return hachage
}

func hacherEnregistrementAnswerCanonique(
	paquetFilaire []byte,
	typeRR uint16,
	classeRR uint16,
	debutRData int,
	finRData int,
	espaceNom *[255]byte,
) uint64 {
	hachage := uint64(fnvOffset64)
	hachage ^= uint64(byte(typeRR >> 8))
	hachage *= fnvPrime64
	hachage ^= uint64(byte(typeRR))
	hachage *= fnvPrime64
	hachage ^= uint64(byte(classeRR >> 8))
	hachage *= fnvPrime64
	hachage ^= uint64(byte(classeRR))
	hachage *= fnvPrime64

	switch typeRR {
	case 2, 5, 12:
		finInline, tailleNom, nomValide := decompresserNomDNS(paquetFilaire, debutRData, finRData, false, espaceNom)
		if nomValide && finInline == finRData {
			hachage = hacherOctetsFNV64a(hachage, espaceNom[:tailleNom])
		} else {
			hachage = hacherOctetsFNV64a(hachage, paquetFilaire[debutRData:finRData])
		}
	case 15:
		if finRData-debutRData >= 3 {
			hachage = hacherOctetsFNV64a(hachage, paquetFilaire[debutRData:debutRData+2])
			hachage ^= 0
			hachage *= fnvPrime64
			finInline, tailleNom, nomValide := decompresserNomDNS(paquetFilaire, debutRData+2, finRData, false, espaceNom)
			if nomValide && finInline == finRData {
				hachage = hacherOctetsFNV64a(hachage, espaceNom[:tailleNom])
			} else {
				hachage = hacherOctetsFNV64a(hachage, paquetFilaire[debutRData+2:finRData])
			}
		} else {
			hachage = hacherOctetsFNV64a(hachage, paquetFilaire[debutRData:finRData])
		}
	case 33:
		if finRData-debutRData >= 7 {
			hachage = hacherOctetsFNV64a(hachage, paquetFilaire[debutRData:debutRData+6])
			hachage ^= 0
			hachage *= fnvPrime64
			finInline, tailleNom, nomValide := decompresserNomDNS(paquetFilaire, debutRData+6, finRData, false, espaceNom)
			if nomValide && finInline == finRData {
				hachage = hacherOctetsFNV64a(hachage, espaceNom[:tailleNom])
			} else {
				hachage = hacherOctetsFNV64a(hachage, paquetFilaire[debutRData+6:finRData])
			}
		} else {
			hachage = hacherOctetsFNV64a(hachage, paquetFilaire[debutRData:finRData])
		}
	default:
		hachage = hacherOctetsFNV64a(hachage, paquetFilaire[debutRData:finRData])
	}

	empreinteRR := melangerSplitMix64(hachage)
	if empreinteRR == 0 {
		return 1
	}
	return empreinteRR
}

func extraireEmpreinteRRsetAnswer(paquetFilaire []byte) (uint64, uint16, bool) {
	if len(paquetFilaire) < 12 {
		return 0, 0, false
	}
	drapeaux := binary.BigEndian.Uint16(paquetFilaire[2:4])
	if (drapeaux&0x8000) == 0 || ((drapeaux>>11)&0x0F) != 0 || (drapeaux&0x0200) != 0 || (drapeaux&0x000F) != 0 {
		return 0, 0, false
	}
	nbQuestions := int(binary.BigEndian.Uint16(paquetFilaire[4:6]))
	nbReponses := int(binary.BigEndian.Uint16(paquetFilaire[6:8]))
	if nbQuestions == 0 || nbReponses == 0 {
		return 0, 0, false
	}

	curseur := 12
	for range nbQuestions {
		finQuestion, _, questionValide := decompresserNomDNS(paquetFilaire, curseur, len(paquetFilaire), false, nil)
		if !questionValide || finQuestion+4 > len(paquetFilaire) {
			return 0, 0, false
		}
		curseur = finQuestion + 4
	}

	var espaceNom [255]byte
	var empreintesVuesPaquet [16]uint64
	nbVuesPaquet := 0
	var sommeCommutative uint64
	sommeRDLength := 0
	nbRRsRetenus := 0

	for range nbReponses {
		finProprietaire, _, proprietaireValide := decompresserNomDNS(paquetFilaire, curseur, len(paquetFilaire), false, nil)
		if !proprietaireValide || finProprietaire+10 > len(paquetFilaire) {
			return 0, 0, false
		}
		typeRR := binary.BigEndian.Uint16(paquetFilaire[finProprietaire : finProprietaire+2])
		classeRR := binary.BigEndian.Uint16(paquetFilaire[finProprietaire+2 : finProprietaire+4])
		longueurRData := int(binary.BigEndian.Uint16(paquetFilaire[finProprietaire+8 : finProprietaire+10]))
		debutRData := finProprietaire + 10
		finRData := debutRData + longueurRData
		if finRData > len(paquetFilaire) {
			return 0, 0, false
		}
		curseur = finRData

		if typeRR == 46 {
			continue
		}
		nbRRsRetenus++
		sommeRDLength += longueurRData

		empreinteRR := hacherEnregistrementAnswerCanonique(paquetFilaire, typeRR, classeRR, debutRData, finRData, &espaceNom)
		dejaPresent := false
		for indiceVu := range nbVuesPaquet {
			if empreintesVuesPaquet[indiceVu] == empreinteRR {
				dejaPresent = true
				break
			}
		}
		if !dejaPresent {
			if nbVuesPaquet < len(empreintesVuesPaquet) {
				empreintesVuesPaquet[nbVuesPaquet] = empreinteRR
				nbVuesPaquet++
			}
			sommeCommutative += empreinteRR
		}
	}

	if nbRRsRetenus == 0 {
		return 0, 0, false
	}
	if sommeCommutative == 0 {
		sommeCommutative = 1
	}
	if sommeRDLength > 65535 {
		sommeRDLength = 65535
	}
	return sommeCommutative, uint16(sommeRDLength), true
}

func purgerEntreesExpireesRData(voie *voieRenouvellementRData, tsNs int64) {
	if voie.nbEntrees == 0 {
		return
	}
	aExpire := false
	for decalage := uint8(0); decalage < voie.nbEntrees; decalage++ {
		indiceAnneau := (voie.debutAnneau + decalage) & 15
		horodatage := voie.horodatagesNs[indiceAnneau]
		if tsNs > horodatage && tsNs-horodatage > fenetreRenouvellementRDataNs {
			aExpire = true
			break
		}
	}
	if !aExpire {
		return
	}

	var empreintesConservees [16]uint64
	var horodatagesConserves [16]int64
	var taillesConservees [16]uint16
	nbConservees := uint8(0)

	for decalage := uint8(0); decalage < voie.nbEntrees; decalage++ {
		indiceAnneau := (voie.debutAnneau + decalage) & 15
		horodatage := voie.horodatagesNs[indiceAnneau]
		if tsNs > horodatage && tsNs-horodatage > fenetreRenouvellementRDataNs {
			continue
		}
		empreintesConservees[nbConservees] = voie.empreintesAnneau[indiceAnneau]
		horodatagesConserves[nbConservees] = horodatage
		taillesConservees[nbConservees] = voie.taillesRData[indiceAnneau]
		nbConservees++
	}

	voie.empreintesAnneau = empreintesConservees
	voie.horodatagesNs = horodatagesConserves
	voie.taillesRData = taillesConservees
	voie.debutAnneau = 0
	voie.nbEntrees = nbConservees
}

func mesurerFenetreAnneauRData(voie *voieRenouvellementRData, decalageLogique int, longueurFenetre int) RenouvellementRDataObs {
	if longueurFenetre <= 0 {
		return RenouvellementRDataObs{}
	}
	var empreintesDistinctes [16]uint64
	nbDistinctes := 0
	sommeTailles := 0

	for pas := range longueurFenetre {
		indiceAnneau := (int(voie.debutAnneau) + decalageLogique + pas) & 15
		empreinte := voie.empreintesAnneau[indiceAnneau]
		sommeTailles += int(voie.taillesRData[indiceAnneau])
		dejaVue := false
		for indiceDistinct := range nbDistinctes {
			if empreintesDistinctes[indiceDistinct] == empreinte {
				dejaVue = true
				break
			}
		}
		if !dejaVue {
			empreintesDistinctes[nbDistinctes] = empreinte
			nbDistinctes++
		}
	}

	moyenne := min(sommeTailles/longueurFenetre, 65535)
	permille := (int64(nbDistinctes) * 1000) / int64(longueurFenetre)
	return RenouvellementRDataObs{
		Reponses:        uint16(longueurFenetre),
		Distinctes:      uint8(nbDistinctes),
		MoyenneRDLength: uint16(moyenne),
		Permille:        permille,
		Valide:          longueurFenetre >= seuilReponsesRenouvellementRData,
	}
}

// ObserveResponse met à jour en 0 B/op la fenêtre glissante du couple (clientIP, parentApex, qtype)
// sur une réponse DNS valide (QR=1, OPCODE=0, TC=0, RCODE=0, ANCOUNT>0) et retourne vrai lorsque
// le critère P15 (au moins 8 réponses, >= 750 permille d'empreintes RRset distinctes, RDLength moyen >= 128) est franchi.
func (tracker *RenouvellementRDataTracker) ObserveResponse(
	tsNs int64,
	clientIP [16]byte,
	parentApex []byte,
	qtype uint16,
	respWire []byte,
) (bool, RenouvellementRDataObs) {
	if !qtypeAdmissibleRenouvellementRData(qtype) {
		return false, RenouvellementRDataObs{}
	}
	empreinteRRset, tailleReponse, exploitable := extraireEmpreinteRRsetAnswer(respWire)
	if !exploitable {
		return false, RenouvellementRDataObs{}
	}

	cleCouple := calculerCleRenouvellementRData(clientIP, parentApex, qtype)
	alveole := &tracker.alveoles[cleCouple&255]

	indiceTrouve := -1
	indiceLibre := -1
	indiceVictimeLRU := 0
	horodatageVictimeLRU := int64(0)
	victimeInitialisee := false

	for indiceVoie := range alveole {
		voieCandidate := &alveole[indiceVoie]
		if voieCandidate.cleCouple == cleCouple {
			indiceTrouve = indiceVoie
			break
		}
		if voieCandidate.cleCouple == 0 || voieCandidate.nbEntrees == 0 ||
			(tsNs > voieCandidate.dernierAccesNs && tsNs-voieCandidate.dernierAccesNs > fenetreRenouvellementRDataNs) {
			if indiceLibre < 0 {
				indiceLibre = indiceVoie
			}
			continue
		}
		if !victimeInitialisee || voieCandidate.dernierAccesNs < horodatageVictimeLRU {
			indiceVictimeLRU = indiceVoie
			horodatageVictimeLRU = voieCandidate.dernierAccesNs
			victimeInitialisee = true
		}
	}

	var voieActive *voieRenouvellementRData
	if indiceTrouve >= 0 {
		voieActive = &alveole[indiceTrouve]
		purgerEntreesExpireesRData(voieActive, tsNs)
	} else {
		indiceCible := indiceLibre
		if indiceCible < 0 {
			indiceCible = indiceVictimeLRU
		}
		voieActive = &alveole[indiceCible]
		*voieActive = voieRenouvellementRData{cleCouple: cleCouple}
	}

	if voieActive.nbEntrees < 16 {
		indiceEcriture := (voieActive.debutAnneau + voieActive.nbEntrees) & 15
		voieActive.empreintesAnneau[indiceEcriture] = empreinteRRset
		voieActive.horodatagesNs[indiceEcriture] = tsNs
		voieActive.taillesRData[indiceEcriture] = tailleReponse
		voieActive.nbEntrees++
	} else {
		indiceEcriture := voieActive.debutAnneau & 15
		voieActive.empreintesAnneau[indiceEcriture] = empreinteRRset
		voieActive.horodatagesNs[indiceEcriture] = tsNs
		voieActive.taillesRData[indiceEcriture] = tailleReponse
		voieActive.debutAnneau = (voieActive.debutAnneau + 1) & 15
	}
	voieActive.dernierAccesNs = tsNs

	nbActives := int(voieActive.nbEntrees)
	obsAnneau := mesurerFenetreAnneauRData(voieActive, 0, nbActives)
	if obsAnneau.Valide &&
		obsAnneau.Permille >= seuilPermilleRenouvellementRData &&
		obsAnneau.MoyenneRDLength >= seuilMoyenneRDLengthRenouvellement {
		return true, obsAnneau
	}

	if nbActives > seuilReponsesRenouvellementRData {
		obsRecentes := mesurerFenetreAnneauRData(
			voieActive,
			nbActives-seuilReponsesRenouvellementRData,
			seuilReponsesRenouvellementRData,
		)
		if obsRecentes.Valide &&
			obsRecentes.Permille >= seuilPermilleRenouvellementRData &&
			obsRecentes.MoyenneRDLength >= seuilMoyenneRDLengthRenouvellement {
			return true, obsRecentes
		}
	}

	return false, obsAnneau
}
