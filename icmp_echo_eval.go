package c2blue55

import (
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/hazyhaar/c2blue55/internal/engine"
)

// ICMPEchoEvalReport rassemble les mesures de l'évaluation ICMP Echo d'une capture.
type ICMPEchoEvalReport struct {
	IPv4Packets        uint32
	EchoRequests       uint32
	EchoReplies        uint32
	Fires              uint32
	AsymmetricFires    uint32
	UnsolicitedFires   uint32
	PacketsToFirstFire uint32
	FirstFireTsNs      uint64
}

// EvaluateICMPEchoPCAP parcourt les trames IPv4 brutes ou Ethernet d'un PCAP classique.
func EvaluateICMPEchoPCAP(pcapPath string) (ICMPEchoEvalReport, error) {
	var rapport ICMPEchoEvalReport
	capture, err := os.Open(pcapPath)
	if err != nil {
		return rapport, err
	}
	defer capture.Close()

	var enteteGlobal [24]byte
	if _, err := io.ReadFull(capture, enteteGlobal[:]); err != nil {
		return rapport, fmt.Errorf("en-tête PCAP tronqué : %w", err)
	}
	var ordre binary.ByteOrder
	var multiplicateur uint64
	switch {
	case binary.LittleEndian.Uint32(enteteGlobal[:4]) == 0xa1b2c3d4:
		ordre, multiplicateur = binary.LittleEndian, 1000
	case binary.BigEndian.Uint32(enteteGlobal[:4]) == 0xa1b2c3d4:
		ordre, multiplicateur = binary.BigEndian, 1000
	case binary.LittleEndian.Uint32(enteteGlobal[:4]) == 0xa1b23c4d:
		ordre, multiplicateur = binary.LittleEndian, 1
	case binary.BigEndian.Uint32(enteteGlobal[:4]) == 0xa1b23c4d:
		ordre, multiplicateur = binary.BigEndian, 1
	default:
		return rapport, fmt.Errorf("magic PCAP inconnu : %x", enteteGlobal[:4])
	}
	typeLien := ordre.Uint32(enteteGlobal[20:24])
	if typeLien != 101 && typeLien != 1 {
		return rapport, fmt.Errorf("type de lien PCAP non pris en charge : %d", typeLien)
	}
	const longueurMaximale = 1 << 20
	limiteCapture := ordre.Uint32(enteteGlobal[16:20])
	if limiteCapture == 0 || limiteCapture > longueurMaximale {
		limiteCapture = longueurMaximale
	}
	var enteteEnregistrement [16]byte
	var trame []byte
	var detecteur engine.ICMPEchoParityTracker
	var rangPaquet uint32
	for {
		_, err := io.ReadFull(capture, enteteEnregistrement[:])
		if err == io.EOF {
			return rapport, nil
		}
		if err != nil {
			return rapport, fmt.Errorf("en-tête d'enregistrement PCAP tronqué : %w", err)
		}
		rangPaquet++
		longueur := ordre.Uint32(enteteEnregistrement[8:12])
		if longueur > limiteCapture || longueur > ordre.Uint32(enteteEnregistrement[12:16]) {
			return rapport, fmt.Errorf("longueur d'enregistrement PCAP invalide au rang %d : %d", rangPaquet, longueur)
		}
		fraction := ordre.Uint32(enteteEnregistrement[4:8])
		if uint64(fraction)*multiplicateur >= 1_000_000_000 {
			return rapport, fmt.Errorf("horodatage PCAP invalide au rang %d", rangPaquet)
		}
		if cap(trame) < int(longueur) {
			trame = make([]byte, longueur)
		}
		trame = trame[:longueur]
		if _, err := io.ReadFull(capture, trame); err != nil {
			return rapport, fmt.Errorf("trame PCAP tronquée au rang %d : %w", rangPaquet, err)
		}
		paquetIPv4 := trame
		if typeLien == 1 {
			if len(trame) < 14 || binary.BigEndian.Uint16(trame[12:14]) != 0x0800 {
				continue
			}
			paquetIPv4 = trame[14:]
		}
		if len(paquetIPv4) < 20 || paquetIPv4[0]>>4 != 4 {
			continue
		}
		longueurEntete := int(paquetIPv4[0]&0x0f) * 4
		longueurIP := int(binary.BigEndian.Uint16(paquetIPv4[2:4]))
		if longueurEntete < 20 || longueurEntete > len(paquetIPv4) || longueurIP < longueurEntete || longueurIP > len(paquetIPv4) {
			continue
		}
		rapport.IPv4Packets++
		if paquetIPv4[9] == 1 && longueurIP >= longueurEntete+8 {
			switch paquetIPv4[longueurEntete] {
			case 8:
				rapport.EchoRequests++
			case 0:
				rapport.EchoReplies++
			}
		}
		horodatage := uint64(ordre.Uint32(enteteEnregistrement[:4]))*1_000_000_000 + uint64(fraction)*multiplicateur
		feu, raison := detecteur.ObserveIPv4(int64(horodatage), paquetIPv4)
		if feu {
			rapport.Fires++
			switch raison {
			case engine.ReasonIC01ICMPEchoAsymmetry:
				rapport.AsymmetricFires++
			case engine.ReasonIC02ICMPEchoUnsolicited:
				rapport.UnsolicitedFires++
			}
			if rapport.Fires == 1 {
				rapport.PacketsToFirstFire = rangPaquet
				rapport.FirstFireTsNs = horodatage
			}
		}
	}
}
