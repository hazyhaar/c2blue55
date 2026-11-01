package c2blue55

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
)

// Générateur de fixtures protocolaires déterministes (aucun fichier de testdata/ lu ;
// toutes les captures construites ici sont explicitement préfixées fixture-*).

var (
	adresseFixtureClient  = [4]byte{10, 0, 0, 2}
	adresseFixtureServeur = [4]byte{192, 0, 2, 53}
)

type fixturePaquetChiffre struct {
	instantNs  uint64
	montant    bool
	charge     int
	portClient uint16
	quic       []byte // en-tête QUIC à placer en tête de charge (nil : charge opaque)
}

func trameFixtureIPv4(protocole uint8, source, destination [4]byte, portSource, portDestination uint16, charge []byte) []byte {
	longueurTransport := 8
	if protocole == 6 {
		longueurTransport = 20
	}
	trameBrute := make([]byte, 14+20+longueurTransport+len(charge))
	binary.BigEndian.PutUint16(trameBrute[12:], 0x0800)
	ip := trameBrute[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+longueurTransport+len(charge)))
	ip[8], ip[9] = 64, protocole
	copy(ip[12:16], source[:])
	copy(ip[16:20], destination[:])
	segment := ip[20:]
	binary.BigEndian.PutUint16(segment[0:], portSource)
	binary.BigEndian.PutUint16(segment[2:], portDestination)
	if protocole == 17 {
		binary.BigEndian.PutUint16(segment[4:], uint16(8+len(charge)))
	} else {
		segment[12], segment[13] = 5<<4, 0x18
	}
	copy(segment[longueurTransport:], charge)
	return trameBrute
}

func enTeteFixtureQUICLong(version uint32, typeBrut uint8, dcid, scid []byte) []byte {
	entete := []byte{0xc0 | typeBrut<<4, 0, 0, 0, 0, byte(len(dcid))}
	binary.BigEndian.PutUint32(entete[1:], version)
	entete = append(entete, dcid...)
	entete = append(entete, byte(len(scid)))
	return append(entete, scid...)
}

func construireFixtureCapture(t *testing.T, transport uint8, portServeur uint16, paquets []fixturePaquetChiffre) []byte {
	t.Helper()
	longueurTransport := 8
	if transport == 6 {
		longueurTransport = 20
	}
	var tampon bytes.Buffer
	tampon.Grow(24 + len(paquets)*256)
	var enteteGlobale [24]byte
	binary.LittleEndian.PutUint32(enteteGlobale[0:], 0xa1b23c4d) // nanosecondes, petit-boutiste
	binary.LittleEndian.PutUint16(enteteGlobale[4:], 2)
	binary.LittleEndian.PutUint16(enteteGlobale[6:], 4)
	binary.LittleEndian.PutUint32(enteteGlobale[16:], 65535)
	binary.LittleEndian.PutUint32(enteteGlobale[20:], 1)
	tampon.Write(enteteGlobale[:])

	var gabarit [2048]byte
	var enregistrement [16]byte
	for _, paquet := range paquets {
		tailleTrame := 14 + 20 + longueurTransport + paquet.charge
		trameBrute := gabarit[:tailleTrame]
		clear(trameBrute)
		binary.BigEndian.PutUint16(trameBrute[12:], 0x0800)
		ip := trameBrute[14:]
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:], uint16(20+longueurTransport+paquet.charge))
		ip[8], ip[9] = 64, transport

		portClient := paquet.portClient
		if portClient == 0 {
			portClient = 50000
		}
		segment := ip[20:]
		if paquet.montant {
			copy(ip[12:16], adresseFixtureClient[:])
			copy(ip[16:20], adresseFixtureServeur[:])
			binary.BigEndian.PutUint16(segment[0:], portClient)
			binary.BigEndian.PutUint16(segment[2:], portServeur)
		} else {
			copy(ip[12:16], adresseFixtureServeur[:])
			copy(ip[16:20], adresseFixtureClient[:])
			binary.BigEndian.PutUint16(segment[0:], portServeur)
			binary.BigEndian.PutUint16(segment[2:], portClient)
		}
		if transport == 17 {
			binary.BigEndian.PutUint16(segment[4:], uint16(8+paquet.charge))
		} else {
			segment[12], segment[13] = 5<<4, 0x18
		}
		charge := segment[longueurTransport : longueurTransport+paquet.charge]
		if paquet.quic != nil {
			copy(charge, paquet.quic)
		} else if transport == 17 && len(charge) > 0 {
			charge[0] = 0x40 // en-tête court QUIC
		}

		binary.LittleEndian.PutUint32(enregistrement[0:], uint32(paquet.instantNs/1e9))
		binary.LittleEndian.PutUint32(enregistrement[4:], uint32(paquet.instantNs%1e9))
		binary.LittleEndian.PutUint32(enregistrement[8:], uint32(tailleTrame))
		binary.LittleEndian.PutUint32(enregistrement[12:], uint32(tailleTrame))
		tampon.Write(enregistrement[:])
		tampon.Write(trameBrute)
	}
	return tampon.Bytes()
}

const secondeFixture = uint64(1_000_000_000)

// R0a : résolutions DoQ sporadiques, silences humains irréguliers.
func fixtureR0a(generateur *rand.Rand) []fixturePaquetChiffre {
	var paquets []fixturePaquetChiffre
	instant := 1 * secondeFixture
	for range 25 {
		instant += uint64(generateur.ExpFloat64() * 30 * float64(secondeFixture))
		for requete := range 1 + generateur.IntN(4) {
			decalage := instant + uint64(requete)*20_000_000
			paquets = append(paquets,
				fixturePaquetChiffre{instantNs: decalage, montant: true, charge: 90 + generateur.IntN(50)},
				fixturePaquetChiffre{instantNs: decalage + 15_000_000, charge: 150 + generateur.IntN(350)})
		}
	}
	return paquets
}

// R0b : téléchargement HTTP/3 massif, accusés montants minuscules.
func fixtureR0b(generateur *rand.Rand) []fixturePaquetChiffre {
	var paquets []fixturePaquetChiffre
	instant := 1 * secondeFixture
	for requete := range 4 {
		paquets = append(paquets, fixturePaquetChiffre{instantNs: instant, montant: true, charge: 300 + generateur.IntN(200)})
		for rang := range 600 {
			instant += 100_000 + uint64(generateur.IntN(50_000))
			paquets = append(paquets, fixturePaquetChiffre{instantNs: instant, charge: 1350})
			if rang%2 == 1 {
				paquets = append(paquets, fixturePaquetChiffre{instantNs: instant + 10_000, montant: true, charge: 45})
			}
		}
		instant += uint64(requete+1) * 3 * secondeFixture
	}
	return paquets
}

// R0b-DASH : segments vidéo périodiques (jumeau négatif de R1b).
func fixtureDASH(generateur *rand.Rand) []fixturePaquetChiffre {
	var paquets []fixturePaquetChiffre
	instant := 1 * secondeFixture
	for range 120 {
		paquets = append(paquets, fixturePaquetChiffre{instantNs: instant, montant: true, charge: 380 + generateur.IntN(40)})
		for rang := range 60 {
			paquets = append(paquets, fixturePaquetChiffre{instantNs: instant + 5_000_000 + uint64(rang)*150_000, charge: 1350})
			if rang%2 == 1 {
				paquets = append(paquets, fixturePaquetChiffre{instantNs: instant + 5_010_000 + uint64(rang)*150_000, montant: true, charge: 45})
			}
		}
		instant += 4*secondeFixture + uint64(generateur.IntN(200_000_000))
	}
	return paquets
}

// Keepalive QUIC : PING de 45 octets toutes les 15 s (jumeau négatif de R1b).
func fixtureKeepalive(generateur *rand.Rand) []fixturePaquetChiffre {
	var paquets []fixturePaquetChiffre
	instant := 1 * secondeFixture
	for range 120 {
		paquets = append(paquets,
			fixturePaquetChiffre{instantNs: instant, montant: true, charge: 45},
			fixturePaquetChiffre{instantNs: instant + 20_000_000, charge: 45})
		instant += 15*secondeFixture + uint64(generateur.IntN(50_000_000))
	}
	return paquets
}

// R1a : tunnel interactif pipeliné sur DoQ/DoH2, alternance soutenue.
func fixtureR1a(generateur *rand.Rand) []fixturePaquetChiffre {
	var paquets []fixturePaquetChiffre
	instant := 1 * secondeFixture
	for range 2400 {
		instant += 30_000_000 + uint64(generateur.ExpFloat64()*70_000_000)
		paquets = append(paquets,
			fixturePaquetChiffre{instantNs: instant, montant: true, charge: 200 + generateur.IntN(600)},
			fixturePaquetChiffre{instantNs: instant + 25_000_000, charge: 200 + generateur.IntN(1000)})
	}
	return paquets
}

// R1b : balise lente toutes les 60 s ± 5 %, nouvelle connexion et nouveau port à chaque réveil.
func fixtureR1b(generateur *rand.Rand) []fixturePaquetChiffre {
	var paquets []fixturePaquetChiffre
	instant := 1 * secondeFixture
	for reveil := range 40 {
		dcid := []byte{0xbe, 0xac, byte(reveil), 1, 2, 3, 4, 5}
		port := uint16(40000 + reveil)
		paquets = append(paquets,
			fixturePaquetChiffre{instantNs: instant, montant: true, charge: 1200, portClient: port, quic: enTeteFixtureQUICLong(quicVersion1, 0, dcid, []byte{9})},
			fixturePaquetChiffre{instantNs: instant + 30_000_000, charge: 1200, portClient: port, quic: enTeteFixtureQUICLong(quicVersion1, 0, []byte{9}, []byte{7, 7, 7, 7})},
			fixturePaquetChiffre{instantNs: instant + 60_000_000, montant: true, charge: 300 + generateur.IntN(20), portClient: port},
			fixturePaquetChiffre{instantNs: instant + 90_000_000, charge: 400 + generateur.IntN(40), portClient: port})
		instant += 60*secondeFixture + uint64((generateur.Float64()-0.5)*6*float64(secondeFixture))
	}
	return paquets
}

func evaluerFixtureScenario(t *testing.T, transport uint8, portServeur uint16, paquets []fixturePaquetChiffre) ConversationVerdict {
	t.Helper()
	chemin := filepath.Join(t.TempDir(), "fixture-capture.pcap")
	if err := os.WriteFile(chemin, construireFixtureCapture(t, transport, portServeur, paquets), 0o600); err != nil {
		t.Fatal(err)
	}
	constat, err := EvaluateEncryptedWirePCAP(chemin, EncryptedWireConfig{CapaciteConversations: 32})
	if err != nil {
		t.Fatalf("EvaluateEncryptedWirePCAP: %v", err)
	}
	if len(constat.Conversations) != 1 {
		t.Fatalf("conversations=%d, attendu 1", len(constat.Conversations))
	}
	return constat.Conversations[0]
}

func TestFixtureCapture_DeterministicWire(t *testing.T) {
	firstBytes := construireFixtureCapture(t, 17, 853, fixtureR0a(rand.New(rand.NewPCG(11, 19))))
	secondBytes := construireFixtureCapture(t, 17, 853, fixtureR0a(rand.New(rand.NewPCG(11, 19))))
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("construireFixtureCapture non reproductible à graine identique")
	}
	if len(firstBytes) <= 24 || binary.LittleEndian.Uint32(firstBytes[0:4]) != 0xa1b23c4d {
		t.Fatalf("en-tête PCAP nanoseconde invalide: len=%d", len(firstBytes))
	}
	tcpBytes := construireFixtureCapture(t, 6, 443, []fixturePaquetChiffre{
		{instantNs: secondeFixture, montant: true, charge: 120},
		{instantNs: secondeFixture + 10_000_000, charge: 240},
	})
	if len(tcpBytes) <= 24 {
		t.Fatalf("capture TCP vide: len=%d", len(tcpBytes))
	}
}
