package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hazyhaar/c2blue55"
)

func rat02bForgeConstruireCaptureDoHMultipath(t *testing.T, chemin string, portA, portB uint16) {
	t.Helper()
	var tampon bytes.Buffer
	var enteteGlobale [24]byte
	binary.LittleEndian.PutUint32(enteteGlobale[0:4], 0xa1b23c4d)
	binary.LittleEndian.PutUint16(enteteGlobale[4:6], 2)
	binary.LittleEndian.PutUint16(enteteGlobale[6:8], 4)
	binary.LittleEndian.PutUint32(enteteGlobale[16:20], 65535)
	binary.LittleEndian.PutUint32(enteteGlobale[20:24], 1)
	tampon.Write(enteteGlobale[:])

	ajouterTrame := func(horodatageNs uint64, montant bool, ipServeur [4]byte, portClient, portServeur uint16, taille int) {
		trame := make([]byte, 14+20+8+taille)
		binary.BigEndian.PutUint16(trame[12:14], 0x0800)
		enteteIP := trame[14:34]
		enteteIP[0] = 0x45
		binary.BigEndian.PutUint16(enteteIP[2:4], uint16(20+8+taille))
		enteteIP[8] = 64
		enteteIP[9] = 17
		segmentUDP := trame[34:]
		ipClient := [4]byte{10, 0, 0, 2}
		if montant {
			copy(enteteIP[12:16], ipClient[:])
			copy(enteteIP[16:20], ipServeur[:])
			binary.BigEndian.PutUint16(segmentUDP[0:2], portClient)
			binary.BigEndian.PutUint16(segmentUDP[2:4], portServeur)
		} else {
			copy(enteteIP[12:16], ipServeur[:])
			copy(enteteIP[16:20], ipClient[:])
			binary.BigEndian.PutUint16(segmentUDP[0:2], portServeur)
			binary.BigEndian.PutUint16(segmentUDP[2:4], portClient)
		}
		binary.BigEndian.PutUint16(segmentUDP[4:6], uint16(8+taille))
		if taille >= 2 {
			segmentUDP[8] = 0x40
		}
		var enreg [16]byte
		binary.LittleEndian.PutUint32(enreg[0:4], uint32(horodatageNs/1_000_000_000))
		binary.LittleEndian.PutUint32(enreg[4:8], uint32(horodatageNs%1_000_000_000))
		binary.LittleEndian.PutUint32(enreg[8:12], uint32(len(trame)))
		binary.LittleEndian.PutUint32(enreg[12:16], uint32(len(trame)))
		tampon.Write(enreg[:])
		tampon.Write(trame)
	}

	serveurA := [4]byte{192, 0, 2, 53}
	serveurB := [4]byte{192, 0, 2, 54}
	const debutNs = uint64(1_000_000_000)
	for tour := range 80 {
		instant := debutNs + uint64(tour)*20_000_000
		ajouterTrame(instant, true, serveurA, 53101, portA, 256)
		ajouterTrame(instant+2_000_000, true, serveurB, 53102, portB, 256)
		ajouterTrame(instant+5_000_000, false, serveurA, 53101, portA, 516)
		ajouterTrame(instant+7_000_000, false, serveurB, 53102, portB, 516)
	}

	if err := os.WriteFile(chemin, tampon.Bytes(), 0o600); err != nil {
		t.Fatalf("écriture capture DoH multipath %s : %v", chemin, err)
	}
}

func TestRatiosWireForge_MultipathHoteEtJumeauSansDrapeau(t *testing.T) {
	cheminCapture := filepath.Join("..", "..", "testdata", "rat-20261101", "slipstream-2doq-multipath-transit.pcap")
	repertoire := t.TempDir()

	// 1. Mode -hote activé : fichier 0600, len(Hotes) == 1 et RegimeHoteLabel == "R1a".
	cheminHoteJSON := filepath.Join(repertoire, "hote.json")
	var sortieHote bytes.Buffer
	code, err := runEncryptedEval([]string{"-pcap", cheminCapture, "-out", cheminHoteJSON, "-hote"}, &sortieHote)
	if code != 0 || err != nil {
		t.Fatalf("runEncryptedEval -hote : code=%d err=%v", code, err)
	}
	etatHote, errStat := os.Stat(cheminHoteJSON)
	if errStat != nil {
		t.Fatalf("os.Stat(%s) : %v", cheminHoteJSON, errStat)
	}
	if etatHote.Mode().Perm() != 0o600 {
		t.Errorf("permissions %s = %#o, attendu 0600", cheminHoteJSON, etatHote.Mode().Perm())
	}

	var constatAvecHote c2blue55.EncryptedWireCapture
	if errDecode := json.Unmarshal(lireFichierJSONBorne(t, cheminHoteJSON), &constatAvecHote); errDecode != nil {
		t.Fatalf("décodage JSON %s : %v", cheminHoteJSON, errDecode)
	}
	if len(constatAvecHote.Conversations) != 2 {
		t.Fatalf("len(Conversations) = %d, attendu 2", len(constatAvecHote.Conversations))
	}
	if len(constatAvecHote.Hotes) != 1 {
		t.Fatalf("len(Hotes) = %d, attendu 1", len(constatAvecHote.Hotes))
	}
	if constatAvecHote.Hotes[0].RegimeHoteLabel != "R1a" || constatAvecHote.Hotes[0].RegimeHote != c2blue55.RegimeR1aTunnelInteractif {
		t.Errorf("Hotes[0] = %+v, attendu RegimeHoteLabel=\"R1a\"", constatAvecHote.Hotes[0])
	}
	if constatAvecHote.Hotes[0].PersistanceBidirectionnelleHote < 4.30 {
		t.Errorf("Hotes[0].PersistanceBidirectionnelleHote = %v, attendu >= 4.30", constatAvecHote.Hotes[0].PersistanceBidirectionnelleHote)
	}

	// 2. Jumeau négatif sans -hote : len(Hotes) == 0.
	cheminSansHoteJSON := filepath.Join(repertoire, "sans-hote.json")
	var sortieSansHote bytes.Buffer
	codeSans, errSans := runEncryptedEval([]string{"-pcap", cheminCapture, "-out", cheminSansHoteJSON}, &sortieSansHote)
	if codeSans != 0 || errSans != nil {
		t.Fatalf("runEncryptedEval sans -hote : code=%d err=%v", codeSans, errSans)
	}
	etatSans, errStatSans := os.Stat(cheminSansHoteJSON)
	if errStatSans != nil {
		t.Fatalf("os.Stat(%s) : %v", cheminSansHoteJSON, errStatSans)
	}
	if etatSans.Mode().Perm() != 0o600 {
		t.Errorf("permissions %s = %#o, attendu 0600", cheminSansHoteJSON, etatSans.Mode().Perm())
	}

	var constatSansHote c2blue55.EncryptedWireCapture
	if errDecode := json.Unmarshal(lireFichierJSONBorne(t, cheminSansHoteJSON), &constatSansHote); errDecode != nil {
		t.Fatalf("décodage JSON %s : %v", cheminSansHoteJSON, errDecode)
	}
	if len(constatSansHote.Hotes) != 0 {
		t.Fatalf("sans -hote : len(Hotes) = %d, attendu 0 (%+v)", len(constatSansHote.Hotes), constatSansHote.Hotes)
	}
}

func TestRatiosWireForge_DoHPortsValidesEtRejetsFailClosed(t *testing.T) {
	repertoire := t.TempDir()
	cheminCaptureDoH := filepath.Join(repertoire, "doh3-8443-9443.pcap")
	rat02bForgeConstruireCaptureDoHMultipath(t, cheminCaptureDoH, 8443, 9443)

	// Jumeau sans -doh-ports : 8443 et 9443 restent hors agrégation hôte par défaut.
	cheminSansPorts := filepath.Join(repertoire, "hote-sans-doh-ports.json")
	var tamponSortie bytes.Buffer
	codeDefaut, errDefaut := runEncryptedEval([]string{"-pcap", cheminCaptureDoH, "-out", cheminSansPorts, "-hote"}, &tamponSortie)
	if codeDefaut != 0 || errDefaut != nil {
		t.Fatalf("runEncryptedEval -hote sans -doh-ports : code=%d err=%v", codeDefaut, errDefaut)
	}
	var constatDefaut c2blue55.EncryptedWireCapture
	if err := json.Unmarshal(lireFichierJSONBorne(t, cheminSansPorts), &constatDefaut); err != nil {
		t.Fatalf("décodage JSON sans -doh-ports : %v", err)
	}
	if len(constatDefaut.Hotes) != 0 {
		t.Fatalf("sans -doh-ports : len(Hotes) = %d, attendu 0", len(constatDefaut.Hotes))
	}

	// Cas valide : -doh-ports 8443,9443 active l'agrégation hôte sur ces deux ports QUIC.
	cheminAvecPorts := filepath.Join(repertoire, "hote-avec-doh-ports.json")
	tamponSortie.Reset()
	codeValide, errValide := runEncryptedEval([]string{"-pcap", cheminCaptureDoH, "-out", cheminAvecPorts, "-hote", "-doh-ports", "8443,9443"}, &tamponSortie)
	if codeValide != 0 || errValide != nil {
		t.Fatalf("runEncryptedEval -doh-ports 8443,9443 : code=%d err=%v", codeValide, errValide)
	}
	var constatValide c2blue55.EncryptedWireCapture
	if err := json.Unmarshal(lireFichierJSONBorne(t, cheminAvecPorts), &constatValide); err != nil {
		t.Fatalf("décodage JSON avec -doh-ports : %v", err)
	}
	if len(constatValide.Hotes) != 1 || constatValide.Hotes[0].RegimeHoteLabel != "R1a" {
		t.Fatalf("-doh-ports 8443,9443 : Hotes=%+v, attendu 1 hôte R1a", constatValide.Hotes)
	}

	// Rejets fail-closed (code == 2, err != nil, aucun fichier de sortie créé).
	casInvalides := []struct {
		nom     string
		valeur  string
		fichier string
	}{
		{nom: "NonNumerique_abc", valeur: "abc", fichier: "rejet-abc.json"},
		{nom: "HorsPlageUint16_70000", valeur: "70000", fichier: "rejet-70000.json"},
		{nom: "DepassementCapacite_9Ports", valeur: "443,8443,8444,9443,9444,444,8445,9445,10443", fichier: "rejet-9ports.json"},
	}

	for _, cas := range casInvalides {
		t.Run(cas.nom, func(t *testing.T) {
			cheminSortieRejet := filepath.Join(repertoire, cas.fichier)
			var sortieRejet bytes.Buffer
			codeRejet, errRejet := runEncryptedEval([]string{
				"-pcap", cheminCaptureDoH,
				"-out", cheminSortieRejet,
				"-hote",
				"-doh-ports", cas.valeur,
			}, &sortieRejet)
			if codeRejet != 2 || errRejet == nil {
				t.Fatalf("-doh-ports %q : code=%d err=%v, attendu code=2 et err != nil", cas.valeur, codeRejet, errRejet)
			}
			if _, errStat := os.Stat(cheminSortieRejet); !errors.Is(errStat, os.ErrNotExist) {
				t.Fatalf("-doh-ports %q : le fichier %s ne devait pas être créé en cas d'erreur (stat=%v)", cas.valeur, cheminSortieRejet, errStat)
			}
		})
	}
}
