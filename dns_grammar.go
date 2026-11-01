package c2blue55

import "unicode/utf8"

// QNameGrammar qualifie la grammaire d'un QNAME dont le cadrage RFC 1035 est
// valide. La qualification ne rejette jamais : elle renseigne le juge.
type QNameGrammar uint8

const (
	// QNameGrammarLDH : lettres, chiffres, '-', '_' et octets d'encodage '+/='.
	QNameGrammarLDH QNameGrammar = iota
	// QNameGrammarDNSSDInstance : seul le premier label est hors LDH, en UTF-8
	// valide sans octet de contrôle, suivi de _service._tcp|_udp (RFC 6763 §4.3).
	QNameGrammarDNSSDInstance
	// QNameGrammarUTF8Local : octets haut-bit formant un UTF-8 valide (nom local
	// non converti en punycode), sans octet de contrôle ni point interne.
	QNameGrammarUTF8Local
	// QNameGrammarASCIIOutsideLDH : ASCII imprimable hors LDH (espace, '*', '!').
	QNameGrammarASCIIOutsideLDH
	// QNameGrammarBinary : octet de contrôle, point brut interne à un label ou
	// séquence haut-bit invalide en UTF-8 (Base128, binaire brut).
	QNameGrammarBinary
)

// String rend le jeton canonique de la grammaire, sans allocation.
func (grammaire QNameGrammar) String() string {
	switch grammaire {
	case QNameGrammarLDH:
		return "LDH"
	case QNameGrammarDNSSDInstance:
		return "DNSSD_INSTANCE"
	case QNameGrammarUTF8Local:
		return "UTF8_LOCAL"
	case QNameGrammarASCIIOutsideLDH:
		return "ASCII_HORS_LDH"
	case QNameGrammarBinary:
		return "BINAIRE"
	}
	return "INCONNUE"
}

// QNameGrammarProfile est le relevé intégral, à plat et sans pointeur, des
// octets hors LDH d'un QNAME. Sa valeur nulle décrit un QNAME LDH.
type QNameGrammarProfile struct {
	Classe                  QNameGrammar
	OctetsHorsLDH           uint8
	OctetsHautBit           uint8
	OctetsControle          uint8
	PointsInternes          uint8
	LabelsHorsLDH           uint8
	PremierLabelHorsLDH     bool
	SecondLabelService      bool
	TroisiemeLabelTransport bool
	UTF8Invalide            bool
}

// observerLabelGrammaire relève les octets hors LDH d'un label filaire brut
// (avant passage en minuscules) d'indice indiceLabel. Zéro allocation tas.
func observerLabelGrammaire(profil *QNameGrammarProfile, labelBrut []byte, indiceLabel int) {
	octetsHorsLDHLabel := 0
	hautBitPresent := false
	for _, octet := range labelBrut {
		minuscule := octet
		if minuscule >= 'A' && minuscule <= 'Z' {
			minuscule += 32
		}
		if dnsLabelByte(minuscule) || isDNSEncodingByte(minuscule) {
			continue
		}
		octetsHorsLDHLabel++
		switch {
		case octet >= 0x80:
			hautBitPresent = true
			profil.OctetsHautBit++
		case octet < 0x20 || octet == 0x7f:
			profil.OctetsControle++
		case octet == '.':
			profil.PointsInternes++
		}
	}
	if octetsHorsLDHLabel > 0 {
		profil.OctetsHorsLDH += uint8(octetsHorsLDHLabel)
		profil.LabelsHorsLDH++
		if indiceLabel == 0 {
			profil.PremierLabelHorsLDH = true
		}
		if hautBitPresent && !utf8.Valid(labelBrut) {
			profil.UTF8Invalide = true
		}
	}
	switch indiceLabel {
	case 1:
		profil.SecondLabelService = octetsHorsLDHLabel == 0 && len(labelBrut) >= 2 && labelBrut[0] == '_'
	case 2:
		profil.TroisiemeLabelTransport = labelEgalInsensible(labelBrut, "_tcp") || labelEgalInsensible(labelBrut, "_udp")
	}
}

// finaliserGrammaire fixe la classe à partir du relevé complet du QNAME.
func finaliserGrammaire(profil *QNameGrammarProfile) {
	switch {
	case profil.OctetsHorsLDH == 0:
		profil.Classe = QNameGrammarLDH
	case profil.LabelsHorsLDH == 1 && profil.PremierLabelHorsLDH && profil.SecondLabelService &&
		profil.TroisiemeLabelTransport && profil.OctetsControle == 0 && !profil.UTF8Invalide:
		profil.Classe = QNameGrammarDNSSDInstance
	case profil.OctetsControle > 0 || profil.UTF8Invalide || profil.PointsInternes > 0:
		profil.Classe = QNameGrammarBinary
	case profil.OctetsHautBit > 0:
		profil.Classe = QNameGrammarUTF8Local
	default:
		profil.Classe = QNameGrammarASCIIOutsideLDH
	}
}

func labelEgalInsensible(labelBrut []byte, attendu string) bool {
	if len(labelBrut) != len(attendu) {
		return false
	}
	for indice, octet := range labelBrut {
		if octet >= 'A' && octet <= 'Z' {
			octet += 32
		}
		if octet != attendu[indice] {
			return false
		}
	}
	return true
}

// ProfileWireQName relève la grammaire d'un QNAME filaire non compressé
// (suite de labels terminée par l'octet nul). Réservé aux tests et aux outils.
func ProfileWireQName(nomFilaire []byte) (QNameGrammarProfile, bool) {
	var profil QNameGrammarProfile
	position, indiceLabel := 0, 0
	for position < len(nomFilaire) {
		longueurLabel := int(nomFilaire[position])
		if longueurLabel == 0 {
			finaliserGrammaire(&profil)
			return profil, true
		}
		if longueurLabel > 63 || position+1+longueurLabel > len(nomFilaire) {
			return QNameGrammarProfile{}, false
		}
		observerLabelGrammaire(&profil, nomFilaire[position+1:position+1+longueurLabel], indiceLabel)
		position += 1 + longueurLabel
		indiceLabel++
	}
	return QNameGrammarProfile{}, false
}
