package c2blue55

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"math"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func construirePaquetIPv6UDP(portSource, portDestination uint16, charge []byte) []byte {
	longueurUDP := 8 + len(charge)
	paquet := make([]byte, 40+longueurUDP)
	paquet[0] = 0x60
	binary.BigEndian.PutUint16(paquet[4:6], uint16(longueurUDP))
	paquet[6] = 17
	paquet[7] = 64
	paquet[8], paquet[23] = 0x20, 0x02
	paquet[24], paquet[39] = 0x20, 0x53
	udp := paquet[40:]
	binary.BigEndian.PutUint16(udp[0:2], portSource)
	binary.BigEndian.PutUint16(udp[2:4], portDestination)
	binary.BigEndian.PutUint16(udp[4:6], uint16(longueurUDP))
	copy(udp[8:], charge)
	return paquet
}

func encapsulerLoopbackBSD(famille uint32, grandBoutiste bool, couche3 []byte) []byte {
	trame := make([]byte, 4+len(couche3))
	if grandBoutiste {
		binary.BigEndian.PutUint32(trame[0:4], famille)
	} else {
		binary.LittleEndian.PutUint32(trame[0:4], famille)
	}
	copy(trame[4:], couche3)
	return trame
}

func TestV21_DecodePortsEtLoopbackBSD(t *testing.T) {
	chargeQUIC := make([]byte, 120)
	chargeQUIC[0] = 0x40
	chargeTCP := make([]byte, 120)

	casPorts := []struct {
		protocole uint8
		port      uint16
		attendu   EncryptedTransport
	}{
		{17, 853, EncryptedTransportDoQ},
		{17, 784, EncryptedTransportDoQ},
		{17, 8853, EncryptedTransportDoQ},
		{17, 443, EncryptedTransportQUIC},
		{17, 8443, EncryptedTransportQUIC},
		{17, 8444, EncryptedTransportQUIC},
		{17, 9443, EncryptedTransportQUIC},
		{17, 9444, EncryptedTransportQUIC},
		{6, 443, EncryptedTransportTLS},
		{6, 8443, EncryptedTransportTLS},
		{6, 8444, EncryptedTransportTLS},
		{6, 9443, EncryptedTransportTLS},
		{6, 9444, EncryptedTransportTLS},
		{6, 853, EncryptedTransportDoT},
		{6, 8853, EncryptedTransportDoT},
	}

	var trame EncryptedWireFrame
	for _, cas := range casPorts {
		charge := chargeQUIC
		if cas.protocole == 6 {
			charge = chargeTCP
		}
		bruteMontante := trameFixtureIPv4(cas.protocole, adresseFixtureClient, adresseFixtureServeur, 51234, cas.port, charge)
		statut := DecodeEncryptedWireFrame(BenchPacket{LinkType: 1, Frame: bruteMontante}, &trame)
		if statut != EncryptedFrameRetained || trame.Transport != cas.attendu || !trame.Montant {
			t.Errorf("montant proto=%d port=%d: statut=%d transport=%d montant=%t, attendu Retained/%d/true",
				cas.protocole, cas.port, statut, trame.Transport, trame.Montant, cas.attendu)
		}
		bruteDescendante := trameFixtureIPv4(cas.protocole, adresseFixtureServeur, adresseFixtureClient, cas.port, 51234, charge)
		statut = DecodeEncryptedWireFrame(BenchPacket{LinkType: 1, Frame: bruteDescendante}, &trame)
		if statut != EncryptedFrameRetained || trame.Transport != cas.attendu || trame.Montant {
			t.Errorf("descendant proto=%d port=%d: statut=%d transport=%d montant=%t, attendu Retained/%d/false",
				cas.protocole, cas.port, statut, trame.Transport, trame.Montant, cas.attendu)
		}
	}

	// DLT_NULL (LinkType == 0) IPv4 en petit-boutiste et grand-boutiste.
	ipv4Brut := trameFixtureIPv4(17, adresseFixtureClient, adresseFixtureServeur, 53000, 8853, chargeQUIC)[14:]
	for _, grandBoutiste := range []bool{false, true} {
		trameLoopback := encapsulerLoopbackBSD(2, grandBoutiste, ipv4Brut)
		statut := DecodeEncryptedWireFrame(BenchPacket{LinkType: 0, Frame: trameLoopback}, &trame)
		if statut != EncryptedFrameRetained || trame.Transport != EncryptedTransportDoQ || trame.IPv6 || !trame.Montant {
			t.Errorf("DLT_NULL IPv4 grandBoutiste=%t: statut=%d transport=%d ipv6=%t montant=%t",
				grandBoutiste, statut, trame.Transport, trame.IPv6, trame.Montant)
		}
	}

	// DLT_NULL (LinkType == 0) IPv6 pour les familles BSD 24, 28 et 30.
	ipv6Brut := construirePaquetIPv6UDP(53000, 9443, chargeQUIC)
	for _, familleBSD := range []uint32{24, 28, 30} {
		for _, grandBoutiste := range []bool{false, true} {
			trameLoopback := encapsulerLoopbackBSD(familleBSD, grandBoutiste, ipv6Brut)
			statut := DecodeEncryptedWireFrame(BenchPacket{LinkType: 0, Frame: trameLoopback}, &trame)
			if statut != EncryptedFrameRetained || trame.Transport != EncryptedTransportQUIC || !trame.IPv6 || !trame.Montant {
				t.Errorf("DLT_NULL IPv6 famille=%d grandBoutiste=%t: statut=%d transport=%d ipv6=%t",
					familleBSD, grandBoutiste, statut, trame.Transport, trame.IPv6)
			}
		}
	}

	// Rejets structurels et jumeaux négatifs hors périmètre (UDP/53, TCP/53, DLT_NULL court ou hors IP).
	if statut := DecodeEncryptedWireFrame(BenchPacket{LinkType: 0, Frame: []byte{2, 0, 0}}, &trame); statut != EncryptedFrameMalformed {
		t.Errorf("DLT_NULL < 4 octets: statut=%d, attendu EncryptedFrameMalformed", statut)
	}
	if statut := DecodeEncryptedWireFrame(BenchPacket{LinkType: 0, Frame: encapsulerLoopbackBSD(18, false, ipv4Brut)}, &trame); statut != EncryptedFrameOutOfScope {
		t.Errorf("DLT_NULL famille AF_LINK=18: statut=%d, attendu EncryptedFrameOutOfScope", statut)
	}
	udp53Ethernet := trameFixtureIPv4(17, adresseFixtureClient, adresseFixtureServeur, 53000, 53, make([]byte, 40))
	if statut := DecodeEncryptedWireFrame(BenchPacket{LinkType: 1, Frame: udp53Ethernet}, &trame); statut != EncryptedFrameOutOfScope {
		t.Errorf("Ethernet UDP/53: statut=%d, attendu EncryptedFrameOutOfScope", statut)
	}
	if statut := DecodeEncryptedWireFrame(BenchPacket{LinkType: 0, Frame: encapsulerLoopbackBSD(2, false, udp53Ethernet[14:])}, &trame); statut != EncryptedFrameOutOfScope {
		t.Errorf("DLT_NULL UDP/53: statut=%d, attendu EncryptedFrameOutOfScope", statut)
	}
	tcp53Ethernet := trameFixtureIPv4(6, adresseFixtureClient, adresseFixtureServeur, 53000, 53, make([]byte, 40))
	if statut := DecodeEncryptedWireFrame(BenchPacket{LinkType: 1, Frame: tcp53Ethernet}, &trame); statut != EncryptedFrameOutOfScope {
		t.Errorf("Ethernet TCP/53: statut=%d, attendu EncryptedFrameOutOfScope", statut)
	}

	trameZeroAlloc := encapsulerLoopbackBSD(2, false, ipv4Brut)
	allocations := testing.AllocsPerRun(1000, func() {
		if DecodeEncryptedWireFrame(BenchPacket{LinkType: 0, Frame: trameZeroAlloc}, &trame) != EncryptedFrameRetained {
			t.Fatal("décodage DLT_NULL refusé")
		}
	})
	if allocations != 0 {
		t.Fatalf("DecodeEncryptedWireFrame DLT_NULL allocations=%v, attendu 0", allocations)
	}
}

func TestV21_JSONMarshalSansInfiniConversationCourte(t *testing.T) {
	repertoire := t.TempDir()

	// Capture 1 : 1 seule rafale porteuse (4 paquets en 60 ms -> 0 intervalle inter-rafale, 1 rafale montante).
	uneRafale := []fixturePaquetChiffre{
		{instantNs: secondeFixture, montant: true, charge: 110},
		{instantNs: secondeFixture + 15_000_000, charge: 240},
		{instantNs: secondeFixture + 35_000_000, montant: true, charge: 120},
		{instantNs: secondeFixture + 50_000_000, charge: 260},
	}
	// Capture 2 : 2 rafales porteuses séparées de 2 s (1 seul intervalle inter-rafale < 2, 2 rafales montantes >= 2).
	deuxRafales := []fixturePaquetChiffre{
		{instantNs: secondeFixture, montant: true, charge: 110},
		{instantNs: secondeFixture + 15_000_000, charge: 240},
		{instantNs: 3 * secondeFixture, montant: true, charge: 150},
		{instantNs: 3*secondeFixture + 15_000_000, charge: 280},
	}

	ctx, annuler := context.WithTimeout(t.Context(), 60*time.Second)
	defer annuler()
	cheminBinaire := filepath.Join(repertoire, "c2forge-test")
	construction := exec.CommandContext(ctx, "go", "build", "-o", cheminBinaire, "./cmd/c2forge")
	if sortieBuild, errBuild := construction.CombinedOutput(); errBuild != nil {
		t.Fatalf("construction c2forge: %v\n%s", errBuild, sortieBuild)
	}

	cas := []struct {
		nom                       string
		paquets                   []fixturePaquetChiffre
		attenduInterRafalesDefini bool
		attenduChargeDefinie      bool
	}{
		{"fixture-une-rafale.pcap", uneRafale, false, false},
		{"fixture-deux-rafales.pcap", deuxRafales, false, true},
	}

	for _, scenario := range cas {
		cheminCapture := filepath.Join(repertoire, scenario.nom)
		if err := os.WriteFile(cheminCapture, construireFixtureCapture(t, 17, 853, scenario.paquets), 0o600); err != nil {
			t.Fatal(err)
		}
		constat, err := EvaluateEncryptedWirePCAP(cheminCapture, EncryptedWireConfig{})
		if err != nil {
			t.Fatalf("%s EvaluateEncryptedWirePCAP: %v", scenario.nom, err)
		}
		if len(constat.Conversations) != 1 {
			t.Fatalf("%s conversations=%d, attendu 1", scenario.nom, len(constat.Conversations))
		}
		verdict := constat.Conversations[0]
		if math.IsNaN(verdict.CVInterRafales) || math.IsInf(verdict.CVInterRafales, 0) ||
			math.IsNaN(verdict.CVChargeMontante) || math.IsInf(verdict.CVChargeMontante, 0) {
			t.Fatalf("%s CV non fini: inter=%v charge=%v", scenario.nom, verdict.CVInterRafales, verdict.CVChargeMontante)
		}
		for indiceTrait, valeurTrait := range verdict.Vecteur.Traits() {
			if math.IsNaN(valeurTrait) || math.IsInf(valeurTrait, 0) {
				t.Fatalf("%s trait[%d] non fini: %v", scenario.nom, indiceTrait, valeurTrait)
			}
		}

		octetsJSON, errMarshal := json.Marshal(constat)
		if errMarshal != nil {
			t.Fatalf("%s json.Marshal a échoué: %v", scenario.nom, errMarshal)
		}
		texteJSON := string(octetsJSON)
		if strings.Contains(texteJSON, "+Inf") || strings.Contains(texteJSON, "-Inf") || strings.Contains(texteJSON, "NaN") {
			t.Fatalf("%s JSON contient ±Inf/NaN: %s", scenario.nom, texteJSON)
		}

		var brut map[string]any
		if errUnmarshal := json.Unmarshal(octetsJSON, &brut); errUnmarshal != nil {
			t.Fatalf("%s json.Unmarshal générique: %v", scenario.nom, errUnmarshal)
		}
		conversationsJSON, okConv := brut["Conversations"].([]any)
		if !okConv || len(conversationsJSON) != 1 {
			t.Fatalf("%s Conversations JSON inattendu: %v", scenario.nom, brut["Conversations"])
		}
		objetVerdict, okMap := conversationsJSON[0].(map[string]any)
		if !okMap {
			t.Fatalf("%s verdict JSON non objet", scenario.nom)
		}
		interDefini, okInter := objetVerdict["CVInterRafalesDefini"].(bool)
		chargeDefinie, okCharge := objetVerdict["CVChargeMontanteDefini"].(bool)
		if !okInter || !okCharge {
			t.Fatalf("%s champs booléens CV*Defini absents du JSON: %v", scenario.nom, objetVerdict)
		}
		if interDefini != scenario.attenduInterRafalesDefini || chargeDefinie != scenario.attenduChargeDefinie {
			t.Fatalf("%s CVDefini=(%t,%t), attendu (%t,%t)",
				scenario.nom, interDefini, chargeDefinie, scenario.attenduInterRafalesDefini, scenario.attenduChargeDefinie)
		}

		// Exécution réelle de la sous-commande CLI c2forge encrypted-eval -pcap.
		commande := exec.CommandContext(ctx, cheminBinaire, "encrypted-eval", "-pcap", cheminCapture)
		sortieCLI, errCLI := commande.CombinedOutput()
		if errCLI != nil {
			t.Fatalf("%s c2forge encrypted-eval -pcap a échoué: %v\n%s", scenario.nom, errCLI, sortieCLI)
		}
		var constatCLI EncryptedWireCapture
		if errDecode := json.Unmarshal(sortieCLI, &constatCLI); errDecode != nil {
			t.Fatalf("%s sortie CLI JSON invalide: %v\n%s", scenario.nom, errDecode, sortieCLI)
		}
		if len(constatCLI.Conversations) != 1 || constatCLI.SHA256 != constat.SHA256 {
			t.Fatalf("%s constat CLI incohérent: %+v", scenario.nom, constatCLI)
		}
	}
}

func fixtureR0a20s(generateur *rand.Rand) []fixturePaquetChiffre {
	var paquets []fixturePaquetChiffre
	instant := secondeFixture
	for range 10 {
		instant += 1_500_000_000 + uint64(generateur.IntN(1_000_000_000))
		paquets = append(paquets,
			fixturePaquetChiffre{instantNs: instant, montant: true, charge: 90 + generateur.IntN(40)},
			fixturePaquetChiffre{instantNs: instant + 12_000_000, charge: 160 + generateur.IntN(160)},
		)
	}
	return paquets
}

func fixtureR0bRapide04s(generateur *rand.Rand) []fixturePaquetChiffre {
	var paquets []fixturePaquetChiffre
	instant := secondeFixture
	for requete := range 4 {
		debutRequete := instant + uint64(requete)*90_000_000
		paquets = append(paquets, fixturePaquetChiffre{
			instantNs: debutRequete,
			montant:   true,
			charge:    320 + generateur.IntN(80),
		})
		for segment := range 1125 {
			horodatage := debutRequete + uint64(segment+1)*70_000
			paquets = append(paquets, fixturePaquetChiffre{instantNs: horodatage, charge: 1350})
			if segment%2 == 1 {
				paquets = append(paquets, fixturePaquetChiffre{instantNs: horodatage + 5_000, montant: true, charge: 45})
			}
		}
	}
	return paquets
}

func fixtureTunnelCourtLAN(generateur *rand.Rand) []fixturePaquetChiffre {
	var paquets []fixturePaquetChiffre
	instant := secondeFixture
	for range 500 {
		instant += 2_200_000 + uint64(generateur.IntN(400_000))
		paquets = append(paquets,
			fixturePaquetChiffre{instantNs: instant, montant: true, charge: 180 + generateur.IntN(40)},
			fixturePaquetChiffre{instantNs: instant + 600_000, charge: 400 + generateur.IntN(60)},
		)
	}
	return paquets
}

func TestV21_ShortLANTunnelInvariance(t *testing.T) {
	type familleCourte struct {
		nom       string
		hostile   bool
		attendu   EncryptedRegime
		transport uint8
		port      uint16
		scenario  func(*rand.Rand) []fixturePaquetChiffre
	}
	familles := []familleCourte{
		{"fixture-doq-r0a-20s", false, RegimeR0aResolutionSporadique, 17, 853, fixtureR0a20s},
		{"fixture-h3-r0b-04s", false, RegimeR0bTelechargement, 17, 443, fixtureR0bRapide04s},
		{"fixture-tunnel-court-lan", true, RegimeR1aTunnelInteractif, 17, 853, fixtureTunnelCourtLAN},
	}

	var echantillons []EncryptedWireSample
	var vecteursBenins []KineticVector
	var vecteursTunnel []KineticVector

	for rangFamille, famille := range familles {
		for graine := range 24 {
			verdict := evaluerFixtureScenario(t, famille.transport, famille.port,
				famille.scenario(rand.New(rand.NewPCG(uint64(100+rangFamille), uint64(graine)))))
			if verdict.RegimeEstime != famille.attendu {
				t.Fatalf("%s graine=%d régime=%s, attendu %s (vecteur=%+v relevé=%+v)",
					famille.nom, graine, verdict.RegimeEstime, famille.attendu, verdict.Vecteur, verdict.Releve)
			}
			if famille.hostile {
				dureeS := float64(verdict.Releve.DernierNs-verdict.Releve.PremierNs) / 1e9
				if dureeS < 1.0 || dureeS > 1.5 {
					t.Fatalf("tunnel court LAN hors enveloppe temporelle: %.3fs", dureeS)
				}
				vecteursTunnel = append(vecteursTunnel, verdict.Vecteur)
			} else {
				vecteursBenins = append(vecteursBenins, verdict.Vecteur)
			}
			echantillons = append(echantillons, EncryptedWireSample{
				Famille:       famille.nom,
				RunID:         famille.nom + "-" + string(rune('a'+graine)),
				Hostile:       famille.hostile,
				RegimeAttendu: famille.attendu,
				RegimeConnu:   true,
				Verdict:       verdict,
			})
		}
	}

	calibrage, errCal := CalibrateEncryptedWire(vecteursBenins)
	if errCal != nil {
		t.Fatalf("CalibrateEncryptedWire: %v", errCal)
	}
	maxBenin := math.Inf(-1)
	for indice := range vecteursBenins {
		maxBenin = max(maxBenin, ScoreEncryptedWire(&vecteursBenins[indice], &calibrage))
	}
	minTunnel := math.Inf(1)
	for indice := range vecteursTunnel {
		minTunnel = min(minTunnel, ScoreEncryptedWire(&vecteursTunnel[indice], &calibrage))
	}
	if minTunnel <= maxBenin {
		t.Fatalf("tunnel court LAN non séparé des bénins: minTunnel=%.3f <= maxBenin=%.3f", minTunnel, maxBenin)
	}

	rapport, errRapport := EvaluateEncryptedWireSamples(echantillons)
	if errRapport != nil {
		t.Fatalf("EvaluateEncryptedWireSamples: %v", errRapport)
	}
	if len(rapport.FamillesHostiles) != 1 {
		t.Fatalf("FamillesHostiles=%d, attendu 1", len(rapport.FamillesHostiles))
	}
	bilanHostile := rapport.FamillesHostiles[0]
	if bilanHostile.ROCAUC != 1.0 || bilanHostile.TPR != 1.0 || bilanHostile.FPR != 0.0 {
		t.Fatalf("bilan tunnel court LAN=%+v, attendu ROCAUC=1 TPR=1 FPR=0", bilanHostile)
	}
	for _, bilanBenin := range rapport.FamillesBenignes {
		if bilanBenin.FPR != 0.0 {
			t.Fatalf("bilan bénin %s FPR=%v, attendu 0", bilanBenin.Famille, bilanBenin.FPR)
		}
	}
	matriceAttendue := [4][4]int{
		{24, 0, 0, 0},
		{0, 24, 0, 0},
		{0, 0, 24, 0},
		{0, 0, 0, 0},
	}
	if rapport.MatriceRegimes != matriceAttendue {
		t.Fatalf("MatriceRegimes=%v, attendu %v", rapport.MatriceRegimes, matriceAttendue)
	}

	// Équivalence de régime sur les ports maillage UDP/8853 (DoQ) et UDP/9443 (QUIC).
	verdictMaillageTunnel := evaluerFixtureScenario(t, 17, 8853, fixtureTunnelCourtLAN(rand.New(rand.NewPCG(77, 1))))
	verdictMaillageR0b := evaluerFixtureScenario(t, 17, 9443, fixtureR0bRapide04s(rand.New(rand.NewPCG(77, 2))))
	if verdictMaillageTunnel.RegimeEstime != RegimeR1aTunnelInteractif || verdictMaillageR0b.RegimeEstime != RegimeR0bTelechargement {
		t.Fatalf("ports maillage 8853/9443: tunnel=%s r0b=%s", verdictMaillageTunnel.RegimeEstime, verdictMaillageR0b.RegimeEstime)
	}
}
