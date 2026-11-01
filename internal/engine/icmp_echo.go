package engine

const ReasonIC01ICMPEchoAsymmetry = "REASON_IC01_ICMP_ECHO_ASYMMETRY"
const ReasonIC02ICMPEchoUnsolicited = "REASON_IC02_ICMP_ECHO_UNSOLICITED"

type creneauEchoICMP struct {
	cle        uint64
	empreinte  uint64
	horodatage int64
	occupe     bool
}

type creneauIdentifiantEchoICMP struct {
	cle        uint64
	horodatage int64
	occupe     bool
}

// ICMPEchoParityTracker rapproche les réponses Echo des requêtes IPv4 observées.
type ICMPEchoParityTracker struct {
	alveoles            [1024][4]creneauEchoICMP
	identifiantsRequete [256][4]creneauIdentifiantEchoICMP
}

// ObserveIPv4 examine un paquet IPv4 brut sans conserver sa tranche d'entrée.
func (t *ICMPEchoParityTracker) ObserveIPv4(tsNs int64, frame []byte) (fired bool, reason string) {
	if len(frame) < 20 || frame[0]>>4 != 4 || frame[9] != 1 {
		return false, ReasonNone
	}
	entete := int(frame[0]&0x0f) * 4
	longueur := int(frame[2])<<8 | int(frame[3])
	if entete < 20 || entete > len(frame) || longueur > len(frame) || longueur < entete+8 {
		return false, ReasonNone
	}
	icmp := frame[entete:longueur]
	if (icmp[0] != 0 && icmp[0] != 8) || icmp[1] != 0 {
		return false, ReasonNone
	}

	// FNV-1a sur les adresses dans l'ordre de la requête, puis ID et séquence.
	cle := uint64(14695981039346656037)
	debut, fin := 12, 16
	if icmp[0] == 0 {
		debut, fin = 16, 12
	}
	for indice := debut; indice < debut+4; indice++ {
		cle = (cle ^ uint64(frame[indice])) * 1099511628211
	}
	for indice := fin; indice < fin+4; indice++ {
		cle = (cle ^ uint64(frame[indice])) * 1099511628211
	}
	for indice := 4; indice < 6; indice++ {
		cle = (cle ^ uint64(icmp[indice])) * 1099511628211
	}
	cleIdentifiant := cle
	for indice := 6; indice < 8; indice++ {
		cle = (cle ^ uint64(icmp[indice])) * 1099511628211
	}
	empreinte := uint64(14695981039346656037)
	for _, octet := range icmp[8:] {
		empreinte = (empreinte ^ uint64(octet)) * 1099511628211
	}

	voies := &t.alveoles[cle&1023]
	if icmp[0] == 8 {
		choix := 0
		for indice := range voies {
			if voies[indice].occupe && voies[indice].cle == cle {
				choix = indice
				break
			}
			if !voies[indice].occupe || (voies[choix].occupe && voies[indice].horodatage < voies[choix].horodatage) {
				choix = indice
			}
		}
		voies[choix] = creneauEchoICMP{cle: cle, empreinte: empreinte, horodatage: tsNs, occupe: true}
		voiesIdentifiant := &t.identifiantsRequete[cleIdentifiant&255]
		choix = 0
		for indice := range voiesIdentifiant {
			if voiesIdentifiant[indice].occupe && voiesIdentifiant[indice].cle == cleIdentifiant {
				choix = indice
				break
			}
			if !voiesIdentifiant[indice].occupe || (voiesIdentifiant[choix].occupe && voiesIdentifiant[indice].horodatage < voiesIdentifiant[choix].horodatage) {
				choix = indice
			}
		}
		voiesIdentifiant[choix] = creneauIdentifiantEchoICMP{cle: cleIdentifiant, horodatage: tsNs, occupe: true}
		return false, ReasonNone
	}
	for indice := range voies {
		entree := &voies[indice]
		if entree.occupe && entree.cle == cle {
			if tsNs < entree.horodatage || tsNs-entree.horodatage > 60_000_000_000 {
				return false, ReasonNone
			}
			if entree.empreinte != empreinte {
				return true, ReasonIC01ICMPEchoAsymmetry
			}
			return false, ReasonNone
		}
	}
	voiesIdentifiant := &t.identifiantsRequete[cleIdentifiant&255]
	for indice := range voiesIdentifiant {
		entree := &voiesIdentifiant[indice]
		if entree.occupe && entree.cle == cleIdentifiant && tsNs >= entree.horodatage && tsNs-entree.horodatage < 60_000_000_000 {
			return true, ReasonIC02ICMPEchoUnsolicited
		}
	}
	return false, ReasonNone
}
