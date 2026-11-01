package c2blue55

import (
	"errors"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDecodeEncryptedWireFrame_QUICv1InitialDoQ(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	charge := append(enTeteFixtureQUICLong(quicVersion1, 0, dcid, []byte{0xaa}), make([]byte, 1200)...)
	var trame EncryptedWireFrame
	statut := DecodeEncryptedWireFrame(BenchPacket{LinkType: 1, Frame: trameFixtureIPv4(17, adresseFixtureClient, adresseFixtureServeur, 50000, 853, charge)}, &trame)
	if statut != EncryptedFrameRetained || trame.Transport != EncryptedTransportDoQ || !trame.Montant {
		t.Fatalf("statut=%d transport=%d montant=%t", statut, trame.Transport, trame.Montant)
	}
	if !trame.QUIC.FormeLongue || trame.QUIC.Version != quicVersion1 || trame.QUIC.TypeLong != QUICLongTypeInitial ||
		trame.QUIC.LongueurDCID != 8 || string(trame.QUIC.DCID[:8]) != string(dcid) || trame.QUIC.LongueurSCID != 1 {
		t.Fatalf("en-tête QUIC=%+v", trame.QUIC)
	}
}

func TestDecodeEncryptedWireFrame_QUICv2TypeMapping(t *testing.T) {
	for typeBrut, attendu := range map[uint8]uint8{1: QUICLongTypeInitial, 2: QUICLongType0RTT, 3: QUICLongTypeHandshake, 0: QUICLongTypeRetry} {
		var entete QUICPublicHeader
		if !decoderEnTeteQUIC(enTeteFixtureQUICLong(quicVersion2, typeBrut, []byte{1}, nil), &entete) || entete.TypeLong != attendu {
			t.Errorf("v2 type brut %d: TypeLong=%d, attendu %d", typeBrut, entete.TypeLong, attendu)
		}
	}
}

func TestDecodeEncryptedWireFrame_RejetsStructurels(t *testing.T) {
	trop := append(enTeteFixtureQUICLong(quicVersion1, 0, make([]byte, 21), nil), make([]byte, 64)...)
	var trame EncryptedWireFrame
	if DecodeEncryptedWireFrame(BenchPacket{LinkType: 1, Frame: trameFixtureIPv4(17, adresseFixtureClient, adresseFixtureServeur, 50000, 443, trop)}, &trame) != EncryptedFrameRetained || !trame.QUICInvalide {
		t.Error("DCID de 21 octets en v1 : datagramme retenu mais QUICInvalide attendu")
	}
	fragment := trameFixtureIPv4(17, adresseFixtureClient, adresseFixtureServeur, 50000, 443, make([]byte, 100))
	fragment[14+6] = 0x20 // MF
	if statut := DecodeEncryptedWireFrame(BenchPacket{LinkType: 1, Frame: fragment}, &trame); statut != EncryptedFrameIPFragment {
		t.Errorf("fragment IPv4: statut=%d", statut)
	}
	coupee := trameFixtureIPv4(17, adresseFixtureClient, adresseFixtureServeur, 50000, 443, make([]byte, 100))
	if statut := DecodeEncryptedWireFrame(BenchPacket{LinkType: 1, Frame: coupee[:60]}, &trame); statut != EncryptedFrameMalformed {
		t.Errorf("longueur IP > trame: statut=%d", statut)
	}
	horsPerimetre := trameFixtureIPv4(17, adresseFixtureClient, adresseFixtureServeur, 50000, 53, make([]byte, 40))
	if statut := DecodeEncryptedWireFrame(BenchPacket{LinkType: 1, Frame: horsPerimetre}, &trame); statut != EncryptedFrameOutOfScope {
		t.Errorf("UDP/53: statut=%d", statut)
	}
}

func TestDecodeEncryptedWireFrame_RawIPv6HopByHop(t *testing.T) {
	charge := make([]byte, 300)
	charge[0] = 0x41
	paquetIP := make([]byte, 40+8+8+len(charge))
	paquetIP[0] = 0x60
	paquetIP[6] = 0 // Hop-by-Hop
	paquetIP[4], paquetIP[5] = byte((8+8+len(charge))>>8), byte(8+8+len(charge))
	paquetIP[40] = 17 // suivant : UDP
	udp := paquetIP[48:]
	udp[0], udp[1], udp[2], udp[3] = 0xc3, 0x50, 0x20, 0xfb // 50000 -> 8443
	udp[4], udp[5] = byte((8+len(charge))>>8), byte(8+len(charge))
	copy(udp[8:], charge)
	var trame EncryptedWireFrame
	if statut := DecodeEncryptedWireFrame(BenchPacket{LinkType: 101, Frame: paquetIP}, &trame); statut != EncryptedFrameRetained ||
		trame.Transport != EncryptedTransportQUIC || !trame.IPv6 || trame.QUIC.FormeLongue || trame.ChargeUtile != 300 {
		t.Fatalf("statut=%d trame=%+v", statut, trame)
	}
}

func TestEncryptedWire_TruncatedPCAPNotJudged(t *testing.T) {
	capture := construireFixtureCapture(t, 17, 853, fixtureR0a(rand.New(rand.NewPCG(1, 2))))
	chemin := filepath.Join(t.TempDir(), "coupee.pcap")
	if err := os.WriteFile(chemin, capture[:len(capture)-7], 0o600); err != nil {
		t.Fatal(err)
	}
	constat, err := EvaluateEncryptedWirePCAP(chemin, EncryptedWireConfig{CapaciteConversations: 16})
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err=%v, attendu io.ErrUnexpectedEOF", err)
	}
	if constat.SHA256 != "" || constat.Conversations != nil {
		t.Fatal("une capture tronquée ne doit produire aucun constat partiel")
	}
}

func TestEncryptedWire_ObserveZeroAlloc(t *testing.T) {
	evaluateur, err := NewEncryptedWireEvaluator(EncryptedWireConfig{CapaciteConversations: 32})
	if err != nil {
		t.Fatal(err)
	}
	trameBrute := trameFixtureIPv4(17, adresseFixtureClient, adresseFixtureServeur, 50000, 853, append(enTeteFixtureQUICLong(quicVersion1, 0, []byte{1, 2}, nil), make([]byte, 200)...))
	instant := uint64(1)
	allocations := testing.AllocsPerRun(1000, func() {
		instant += 10_000_000
		if err := evaluateur.Observe(BenchPacket{TimestampNs: instant, LinkType: 1, Frame: trameBrute}); err != nil {
			t.Fatal(err)
		}
	})
	if allocations != 0 {
		t.Fatalf("allocations=%v par trame, attendu 0", allocations)
	}
}

func TestEncryptedWire_PortRebindingSameConversation(t *testing.T) {
	paquets := []fixturePaquetChiffre{
		{instantNs: secondeFixture, montant: true, charge: 1200, quic: enTeteFixtureQUICLong(quicVersion1, 0, []byte{1, 2, 3, 4}, []byte{5})},
		{instantNs: secondeFixture + 1e7, charge: 300},
		{instantNs: secondeFixture + 2e7, montant: true, charge: 200, portClient: 61000},
		{instantNs: secondeFixture + 3e7, charge: 300, portClient: 61000},
	}
	verdict := evaluerFixtureScenario(t, 17, 443, paquets)
	if verdict.Releve.ConnexionsInitiales != 1 || verdict.Releve.ReassociationsPort != 1 {
		t.Fatalf("connexions=%d reassociations=%d, attendu 1 et 1", verdict.Releve.ConnexionsInitiales, verdict.Releve.ReassociationsPort)
	}
}

func TestEncryptedWire_RegimesPhysiques(t *testing.T) {
	cas := []struct {
		nom       string
		transport uint8
		port      uint16
		scenario  func(*rand.Rand) []fixturePaquetChiffre
		attendu   EncryptedRegime
		jeton     string
	}{
		{"R0a_DoQ_sporadique", 17, 853, fixtureR0a, RegimeR0aResolutionSporadique, "R0a"},
		{"R0b_H3_telechargement", 17, 443, fixtureR0b, RegimeR0bTelechargement, "R0b"},
		{"R0b_DASH_periodique_jumeau_R1b", 17, 443, fixtureDASH, RegimeR0bTelechargement, "R0b"},
		{"R0a_keepalive_QUIC_jumeau_R1b", 17, 853, fixtureKeepalive, RegimeR0aResolutionSporadique, "R0a"},
		{"R1a_tunnel_DoQ", 17, 853, fixtureR1a, RegimeR1aTunnelInteractif, "R1a"},
		{"R1a_tunnel_DoH2", 6, 443, fixtureR1a, RegimeR1aTunnelInteractif, "R1a"},
		{"R1b_balise_multiconnexion", 17, 443, fixtureR1b, RegimeR1bBalisageLent, "R1b"},
	}
	for _, scenario := range cas {
		t.Run(scenario.nom, func(t *testing.T) {
			verdict := evaluerFixtureScenario(t, scenario.transport, scenario.port, scenario.scenario(rand.New(rand.NewPCG(7, 11))))
			if verdict.RegimeEstime != scenario.attendu || verdict.RegimeLabel != scenario.jeton {
				t.Fatalf("régime=%s (%q), attendu %s (%q) ; vecteur=%+v relevé=%+v",
					verdict.RegimeEstime, verdict.RegimeLabel, scenario.attendu, scenario.jeton, verdict.Vecteur, verdict.Releve)
			}
		})
	}
}

func TestExactROCAUC_ExAequo(t *testing.T) {
	aire := ExactROCAUC([]float64{1, 2, 2, 0}, []bool{true, true, false, false})
	if aire != 0.625 {
		t.Fatalf("AUC=%v, attendu 0,625", aire)
	}
	if ExactROCAUC([]float64{1}, []bool{true}) != 0 || ExactROCAUC([]float64{1}, []bool{true, false}) != 0 {
		t.Fatal("classe vide ou longueurs divergentes : AUC 0 attendue")
	}
}

func TestEvaluateEncryptedWireSamples_StrictLOFO(t *testing.T) {
	debut := time.Now()
	type familleFixture struct {
		nom       string
		hostile   bool
		regime    EncryptedRegime
		transport uint8
		port      uint16
		scenario  func(*rand.Rand) []fixturePaquetChiffre
	}
	familles := []familleFixture{
		{"fixture-doq-resolutions", false, RegimeR0aResolutionSporadique, 17, 853, fixtureR0a},
		{"fixture-h3-telechargement", false, RegimeR0bTelechargement, 17, 443, fixtureR0b},
		{"fixture-h3-dash", false, RegimeR0bTelechargement, 17, 443, fixtureDASH},
		{"fixture-doq-keepalive", false, RegimeR0aResolutionSporadique, 17, 853, fixtureKeepalive},
		{"fixture-redhost-tunnel-doq", true, RegimeR1aTunnelInteractif, 17, 853, fixtureR1a},
		{"fixture-redhost-balise-h3", true, RegimeR1bBalisageLent, 17, 443, fixtureR1b},
	}
	var echantillons []EncryptedWireSample
	for rangFamille, famille := range familles {
		for graine := range 24 {
			verdict := evaluerFixtureScenario(t, famille.transport, famille.port, famille.scenario(rand.New(rand.NewPCG(uint64(rangFamille), uint64(graine)))))
			echantillons = append(echantillons, EncryptedWireSample{
				Famille:       famille.nom,
				RunID:         famille.nom + "-" + string(rune('a'+graine)),
				Hostile:       famille.hostile,
				RegimeAttendu: famille.regime,
				RegimeConnu:   true,
				Verdict:       verdict,
			})
		}
	}
	rapport, err := EvaluateEncryptedWireSamples(echantillons)
	if err != nil {
		t.Fatal(err)
	}
	duree := time.Since(debut)
	if duree >= 15*time.Second {
		t.Errorf("durée LOFO=%v, attendu < 15s", duree)
	}
	for _, bilan := range rapport.FamillesHostiles {
		if bilan.EffectifHostile != 24 || bilan.EffectifBenin != 96 || bilan.InsuffisantPourSeuil || bilan.InsuffisantPourAUC {
			t.Errorf("%s effectifs=%d/%d seuils=%t/%t", bilan.Famille, bilan.EffectifHostile, bilan.EffectifBenin, bilan.InsuffisantPourSeuil, bilan.InsuffisantPourAUC)
		}
		if bilan.MajorityClassRate != 0.8 {
			t.Errorf("%s MajorityClassRate=%v, attendu 0.8", bilan.Famille, bilan.MajorityClassRate)
		}
		if bilan.TPR != 1 || bilan.FPR != 0 || bilan.ROCAUC != 1 {
			t.Errorf("%s TPR=%v FPR=%v ROCAUC=%v, attendu 1 / 0 / 1", bilan.Famille, bilan.TPR, bilan.FPR, bilan.ROCAUC)
		}
	}
	for _, bilan := range rapport.FamillesBenignes {
		if bilan.EffectifBenin != 24 || bilan.FPR != 0 {
			t.Errorf("%s bénin EffectifBenin=%d FPR=%v, attendu 24 et 0", bilan.Famille, bilan.EffectifBenin, bilan.FPR)
		}
	}
	matriceAttendue := [4][4]int{
		{48, 0, 0, 0},
		{0, 48, 0, 0},
		{0, 0, 24, 0},
		{0, 0, 0, 24},
	}
	if rapport.MatriceRegimes != matriceAttendue {
		t.Errorf("MatriceRegimes=%v, attendu %v", rapport.MatriceRegimes, matriceAttendue)
	}
}

func TestEvaluateEncryptedWireSamples_CalibrationExcludesOwnFamily(t *testing.T) {
	base := []EncryptedWireSample{
		{Famille: "b1", Verdict: ConversationVerdict{Vecteur: KineticVector{TournantsParKioPorteur: 1}}},
		{Famille: "b2", Verdict: ConversationVerdict{Vecteur: KineticVector{TournantsParKioPorteur: 2}}},
		{Famille: "redhost-x", Hostile: true, Verdict: ConversationVerdict{Vecteur: KineticVector{TournantsParKioPorteur: 9}}},
	}
	calibrageAvant, errAvant := CalibrateEncryptedWire(vecteursBeninsHorsFamille(base, "b1"))
	if errAvant != nil {
		t.Fatal(errAvant)
	}
	base[0].Verdict.Vecteur.TournantsParKioPorteur = 1e6
	calibrageApres, errApres := CalibrateEncryptedWire(vecteursBeninsHorsFamille(base, "b1"))
	if errApres != nil {
		t.Fatal(errApres)
	}
	if calibrageAvant != calibrageApres {
		t.Fatal("la calibration qui juge b1 dépend des conversations de b1")
	}
	if _, err := EvaluateEncryptedWireSamples(base[1:]); !errors.Is(err, ErrEncryptedWireContract) {
		t.Fatalf("une seule famille bénigne : err=%v, attendu ErrEncryptedWireContract", err)
	}
}
