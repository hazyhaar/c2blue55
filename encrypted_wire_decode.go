package c2blue55

import "encoding/binary"

// EncryptedTransport classe un segment selon son port de service. DoH3 et
// HTTP/3 sont indiscernables sur le fil : c'est l'objet des régimes R0b/R1a.
type EncryptedTransport uint8

const (
	EncryptedTransportUnknown EncryptedTransport = iota
	EncryptedTransportDoQ                        // UDP/853, UDP/784 et UDP/8853 (RFC 9250 / maillage)
	EncryptedTransportQUIC                       // UDP/443, UDP/8443, UDP/8444, UDP/9443 et UDP/9444 (DoH3 ou HTTP/3)
	EncryptedTransportTLS                        // TCP/443, TCP/8443, TCP/8444, TCP/9443 et TCP/9444 (DoH2 ou HTTPS)
	EncryptedTransportDoT                        // TCP/853 et TCP/8853 (RFC 7858 / maillage)
)

// EncryptedFrameStatus est l'issue exacte du décodage d'une trame.
type EncryptedFrameStatus uint8

const (
	EncryptedFrameRetained EncryptedFrameStatus = iota + 1
	EncryptedFrameOutOfScope
	EncryptedFrameIPFragment
	EncryptedFrameMalformed
)

const (
	quicVersionNegociation uint32 = 0x00000000
	quicVersion1           uint32 = 0x00000001
	quicVersion2           uint32 = 0x6b3343cf // RFC 9369
	quicLongueurCIDMax            = 20

	// QUICLongTypeInitial et suivants suivent la numérotation v1 (RFC 9000 §17.2) ;
	// les types v2 (RFC 9369 §3.2) y sont ramenés.
	QUICLongTypeInitial   uint8 = 0
	QUICLongType0RTT      uint8 = 1
	QUICLongTypeHandshake uint8 = 2
	QUICLongTypeRetry     uint8 = 3

	enTetesExtensionIPv6Max = 8
)

// QUICPublicHeader est l'en-tête public d'un datagramme QUIC, à plat.
type QUICPublicHeader struct {
	Present            bool
	FormeLongue        bool
	NegociationVersion bool
	Version            uint32
	TypeLong           uint8
	LongueurDCID       uint8
	DCID               [quicLongueurCIDMax]byte
	LongueurSCID       uint8
	SCID               [quicLongueurCIDMax]byte
}

// EncryptedWireFrame est la vue décodée d'un segment chiffré ; elle ne retient
// aucun pointeur vers la trame, valide seulement pendant le rappel.
type EncryptedWireFrame struct {
	TimestampNs  uint64
	Transport    EncryptedTransport
	IPv6         bool
	Montant      bool // client vers serveur
	SourceIP     [16]byte
	DestIP       [16]byte
	SourcePort   uint16
	DestPort     uint16
	ChargeUtile  uint16 // octets de charge UDP ou TCP
	DrapeauxTCP  uint8
	QUICInvalide bool
	QUIC         QUICPublicHeader
}

// DecodeEncryptedWireFrame décode Loopback BSD (DLT_NULL), Ethernet (VLAN
// 802.1Q/802.1ad), Linux SLL et SLL2, IP brut, IPv4/IPv6 (en-têtes d'extension
// bornés), UDP/TCP et l'en-tête public QUIC v1/v2. Zéro allocation tas.
func DecodeEncryptedWireFrame(paquet BenchPacket, trame *EncryptedWireFrame) EncryptedFrameStatus {
	*trame = EncryptedWireFrame{TimestampNs: paquet.TimestampNs}
	versionIP, couche3, statut := depouillerLiaison(paquet.LinkType, paquet.Frame)
	if statut != EncryptedFrameRetained {
		return statut
	}
	var protocole uint8
	var segment []byte
	switch versionIP {
	case 4:
		if len(couche3) < 20 || couche3[0]>>4 != 4 {
			return EncryptedFrameMalformed
		}
		longueurEnTete := int(couche3[0]&0x0f) * 4
		longueurTotale := int(binary.BigEndian.Uint16(couche3[2:4]))
		if longueurEnTete < 20 || longueurTotale < longueurEnTete || longueurTotale > len(couche3) {
			return EncryptedFrameMalformed
		}
		if binary.BigEndian.Uint16(couche3[6:8])&0x3fff != 0 {
			return EncryptedFrameIPFragment
		}
		copy(trame.SourceIP[:4], couche3[12:16])
		copy(trame.DestIP[:4], couche3[16:20])
		protocole, segment = couche3[9], couche3[longueurEnTete:longueurTotale]
	case 6:
		if len(couche3) < 40 || couche3[0]>>4 != 6 {
			return EncryptedFrameMalformed
		}
		longueurCharge := int(binary.BigEndian.Uint16(couche3[4:6]))
		if longueurCharge == 0 || 40+longueurCharge > len(couche3) {
			return EncryptedFrameMalformed
		}
		trame.IPv6 = true
		copy(trame.SourceIP[:], couche3[8:24])
		copy(trame.DestIP[:], couche3[24:40])
		var statutExtensions EncryptedFrameStatus
		protocole, segment, statutExtensions = sauterExtensionsIPv6(couche3[6], couche3[40:40+longueurCharge])
		if statutExtensions != EncryptedFrameRetained {
			return statutExtensions
		}
	default:
		return EncryptedFrameOutOfScope
	}

	var charge []byte
	switch protocole {
	case 17:
		if len(segment) < 8 {
			return EncryptedFrameMalformed
		}
		longueurUDP := int(binary.BigEndian.Uint16(segment[4:6]))
		if longueurUDP < 8 || longueurUDP > len(segment) {
			return EncryptedFrameMalformed
		}
		charge = segment[8:longueurUDP]
	case 6:
		if len(segment) < 20 {
			return EncryptedFrameMalformed
		}
		decalage := int(segment[12]>>4) * 4
		if decalage < 20 || decalage > len(segment) {
			return EncryptedFrameMalformed
		}
		trame.DrapeauxTCP = segment[13]
		charge = segment[decalage:]
	default:
		return EncryptedFrameOutOfScope
	}
	trame.SourcePort = binary.BigEndian.Uint16(segment[0:2])
	trame.DestPort = binary.BigEndian.Uint16(segment[2:4])
	if transport := classerPortChiffre(protocole, trame.DestPort); transport != EncryptedTransportUnknown {
		trame.Transport, trame.Montant = transport, true
	} else if transport := classerPortChiffre(protocole, trame.SourcePort); transport != EncryptedTransportUnknown {
		trame.Transport, trame.Montant = transport, false
	} else {
		return EncryptedFrameOutOfScope
	}
	trame.ChargeUtile = uint16(min(len(charge), 0xffff))
	if protocole == 17 && len(charge) > 0 {
		trame.QUICInvalide = !decoderEnTeteQUIC(charge, &trame.QUIC)
	}
	return EncryptedFrameRetained
}

func classerPortChiffre(protocole uint8, port uint16) EncryptedTransport {
	switch {
	case protocole == 17 && (port == 853 || port == 784 || port == 8853):
		return EncryptedTransportDoQ
	case protocole == 17 && (port == 443 || port == 8443 || port == 8444 || port == 9443 || port == 9444):
		return EncryptedTransportQUIC
	case protocole == 6 && (port == 443 || port == 8443 || port == 8444 || port == 9443 || port == 9444):
		return EncryptedTransportTLS
	case protocole == 6 && (port == 853 || port == 8853):
		return EncryptedTransportDoT
	}
	return EncryptedTransportUnknown
}

func depouillerLiaison(typeLien uint32, trameBrute []byte) (uint8, []byte, EncryptedFrameStatus) {
	var typeEther uint16
	var couche3 []byte
	switch typeLien {
	case 0:
		if len(trameBrute) < 4 {
			return 0, nil, EncryptedFrameMalformed
		}
		famille := binary.LittleEndian.Uint32(trameBrute[0:4])
		if famille > 0xffff {
			famille = binary.BigEndian.Uint32(trameBrute[0:4])
		}
		switch famille {
		case 2:
			return 4, trameBrute[4:], EncryptedFrameRetained
		case 24, 28, 30:
			return 6, trameBrute[4:], EncryptedFrameRetained
		default:
			return 0, nil, EncryptedFrameOutOfScope
		}
	case 1:
		if len(trameBrute) < 14 {
			return 0, nil, EncryptedFrameMalformed
		}
		typeEther, couche3 = binary.BigEndian.Uint16(trameBrute[12:14]), trameBrute[14:]
		for etiquettes := 0; etiquettes < 2 && (typeEther == 0x8100 || typeEther == 0x88a8); etiquettes++ {
			if len(couche3) < 4 {
				return 0, nil, EncryptedFrameMalformed
			}
			typeEther, couche3 = binary.BigEndian.Uint16(couche3[2:4]), couche3[4:]
		}
	case 113:
		if len(trameBrute) < 16 {
			return 0, nil, EncryptedFrameMalformed
		}
		typeEther, couche3 = binary.BigEndian.Uint16(trameBrute[14:16]), trameBrute[16:]
	case 276:
		if len(trameBrute) < 20 {
			return 0, nil, EncryptedFrameMalformed
		}
		typeEther, couche3 = binary.BigEndian.Uint16(trameBrute[0:2]), trameBrute[20:]
	case 101:
		if len(trameBrute) == 0 {
			return 0, nil, EncryptedFrameMalformed
		}
		return trameBrute[0] >> 4, trameBrute, EncryptedFrameRetained
	default:
		return 0, nil, EncryptedFrameOutOfScope
	}
	switch typeEther {
	case 0x0800:
		return 4, couche3, EncryptedFrameRetained
	case 0x86dd:
		return 6, couche3, EncryptedFrameRetained
	}
	return 0, nil, EncryptedFrameOutOfScope
}

// sauterExtensionsIPv6 franchit au plus enTetesExtensionIPv6Max en-têtes
// Hop-by-Hop (0), Routing (43), Destination (60), AH (51) et Fragment (44).
func sauterExtensionsIPv6(suivant uint8, charge []byte) (uint8, []byte, EncryptedFrameStatus) {
	for range enTetesExtensionIPv6Max {
		switch suivant {
		case 0, 43, 60:
			if len(charge) < 8 {
				return 0, nil, EncryptedFrameMalformed
			}
			longueurExtension := (int(charge[1]) + 1) * 8
			if longueurExtension > len(charge) {
				return 0, nil, EncryptedFrameMalformed
			}
			suivant, charge = charge[0], charge[longueurExtension:]
		case 51:
			if len(charge) < 8 {
				return 0, nil, EncryptedFrameMalformed
			}
			longueurExtension := (int(charge[1]) + 2) * 4
			if longueurExtension > len(charge) {
				return 0, nil, EncryptedFrameMalformed
			}
			suivant, charge = charge[0], charge[longueurExtension:]
		case 44:
			if len(charge) < 8 {
				return 0, nil, EncryptedFrameMalformed
			}
			if binary.BigEndian.Uint16(charge[2:4])&0xfff9 != 0 {
				return 0, nil, EncryptedFrameIPFragment
			}
			suivant, charge = charge[0], charge[8:]
		default:
			return suivant, charge, EncryptedFrameRetained
		}
	}
	return 0, nil, EncryptedFrameMalformed
}

// decoderEnTeteQUIC lit l'en-tête public (RFC 8999, RFC 9000 §17, RFC 9369).
// Un en-tête court ne porte pas la longueur de son DCID : seul le bit de forme
// est retenu. Rend faux si l'en-tête long est incohérent.
func decoderEnTeteQUIC(charge []byte, entete *QUICPublicHeader) bool {
	premier := charge[0]
	if premier&0x80 == 0 {
		if len(charge) < 2 {
			return false
		}
		entete.Present = true
		return true
	}
	if len(charge) < 7 {
		return false
	}
	entete.Version = binary.BigEndian.Uint32(charge[1:5])
	if entete.Version == quicVersionNegociation {
		entete.Present, entete.FormeLongue, entete.NegociationVersion = true, true, true
		return true
	}
	longueurDCID := int(charge[5])
	position := 6
	if longueurDCID > quicLongueurCIDMax || position+longueurDCID+1 > len(charge) {
		return false
	}
	copy(entete.DCID[:], charge[position:position+longueurDCID])
	position += longueurDCID
	longueurSCID := int(charge[position])
	position++
	if longueurSCID > quicLongueurCIDMax || position+longueurSCID > len(charge) {
		return false
	}
	copy(entete.SCID[:], charge[position:position+longueurSCID])
	entete.Present, entete.FormeLongue = true, true
	entete.LongueurDCID, entete.LongueurSCID = uint8(longueurDCID), uint8(longueurSCID)
	typeBrut := (premier >> 4) & 0x03
	if entete.Version == quicVersion2 {
		typeBrut = (typeBrut + 3) & 0x03
	}
	entete.TypeLong = typeBrut
	return true
}
