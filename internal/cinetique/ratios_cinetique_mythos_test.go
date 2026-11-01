//go:build linux

package cinetique_test

import (
	"context"
	"math"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/cinetique"
	"golang.org/x/sys/unix"
)

func construireEpisodeCinetiqueRAT03(
	t *testing.T,
	execNs uint64,
	rssDebutKio uint64,
	rssFinKio uint64,
	octetsLusLog uint64,
	octetsBloc uint64,
	reseau cinetique.CompteursReseauEpisode,
	cfg cinetique.ConfigPlanchersCinetiques,
) cinetique.QuotientsEpisode {
	t.Helper()

	topo := cinetique.TopologieHybride{
		MasquePerformance: 0x00FF,
		MasqueEfficience:  0xFF00,
		EstHybride:        true,
	}
	debut := cinetique.InstantaneTache{
		PID:                     9403,
		HorodatageNs:            1_000_000_000,
		DebutTacheTicks:         88888,
		CoeurDerniereExecution:  2,
		VmHWMKio:                max(rssDebutKio, rssFinKio),
		VmRSSKio:                rssDebutKio,
		NombreFils:              1,
		CommutationsVolontaires: 100,
		CommutationsSubies:      10,
	}
	fin := debut
	fin.HorodatageNs = debut.HorodatageNs + int64(execNs+2_000_000)
	fin.TempsExecutionNs = execNs
	fin.AttenteFileNs = 200_000
	fin.VmRSSKio = rssFinKio
	fin.VmHWMKio = max(rssDebutKio, rssFinKio)
	fin.OctetsLusLogiques = octetsLusLog
	fin.OctetsEcritsLogiques = 131_072
	fin.AppelsLecture = 32
	fin.AppelsEcriture = 32
	fin.OctetsLusBloc = 0
	fin.OctetsEcritsBloc = octetsBloc
	fin.CommutationsVolontaires = 132
	fin.CommutationsSubies = 12

	psiDebut := cinetique.InstantanePressionPSI{HorodatageNs: debut.HorodatageNs, CPUSomeTotalUs: 10_000}
	psiFin := cinetique.InstantanePressionPSI{HorodatageNs: fin.HorodatageNs, CPUSomeTotalUs: 10_100}

	ep, err := cinetique.EvaluerEpisodeCinetique(debut, fin, psiDebut, psiFin, reseau, topo, cfg)
	if err != nil {
		t.Fatalf("EvaluerEpisodeCinetique: %v", err)
	}
	return ep
}

func TestConstantesEtConfigQuotientsRAT03(t *testing.T) {
	if cinetique.IndicePartResolveurPermille != 10 {
		t.Fatalf("IndicePartResolveurPermille attendu 10, obtenu %d", cinetique.IndicePartResolveurPermille)
	}
	if got := cinetique.NomQuotient(cinetique.IndicePartResolveurPermille); got != "part_resolveur_permille" {
		t.Fatalf("NomQuotient(10) attendu part_resolveur_permille, obtenu %q", got)
	}
	if cinetique.IndiceAbsorptionDescriptivePermille != 11 {
		t.Fatalf("IndiceAbsorptionDescriptivePermille attendu 11, obtenu %d", cinetique.IndiceAbsorptionDescriptivePermille)
	}
	if got := cinetique.NomQuotient(cinetique.IndiceAbsorptionDescriptivePermille); got != "absorption_reseau_permille" {
		t.Fatalf("NomQuotient(11) attendu absorption_reseau_permille, obtenu %q", got)
	}
	if cinetique.NombreQuotientsEpisode != 12 {
		t.Fatalf("NombreQuotientsEpisode attendu 12, obtenu %d", cinetique.NombreQuotientsEpisode)
	}
	if got := cinetique.NomQuotient(cinetique.NombreQuotientsEpisode); got != "quotient_inconnu" {
		t.Fatalf("NomQuotient hors bornes attendu quotient_inconnu, obtenu %q", got)
	}

	masqueAttendu := uint16(1 << cinetique.IndiceAbsorptionDescriptivePermille)
	var masqueDescriptif uint16 = cinetique.MasqueQuotientsDescriptifs
	if masqueDescriptif != masqueAttendu {
		t.Fatalf("MasqueQuotientsDescriptifs attendu 0x%04x, obtenu 0x%04x", masqueAttendu, masqueDescriptif)
	}

	cfg := cinetique.ConfigPlanchersParDefaut()
	minOctetsResolveur, minOctetsAbsorption := cinetique.PlanchersResolveurEtAbsorption(cfg)
	if minOctetsResolveur != 16384 {
		t.Fatalf("MinOctetsReseauResolveur par defaut attendu 16384, obtenu %d", minOctetsResolveur)
	}
	if minOctetsAbsorption != (1 << 20) {
		t.Fatalf("MinOctetsEntrantsAbsorption par defaut attendu 1048576, obtenu %d", minOctetsAbsorption)
	}

	ep := construireEpisodeCinetiqueRAT03(
		t,
		8_000_000,
		30_000,
		30_000,
		1_048_576,
		131_072,
		cinetique.ConstruireCompteursReseauResolveur(36_864, 2<<20, 32_768, 4_096, 3, 2, 0, true, true),
		cfg,
	)
	octResEp, octHorsEp, connHorsEp, ecouteEp, fluxEp := cinetique.LireCompteursResolveurEpisode(ep)
	if octResEp != 32_768 ||
		octHorsEp != 4_096 ||
		connHorsEp != 2 ||
		!ecouteEp ||
		!fluxEp {
		t.Fatalf("propagation CompteursReseauEpisode -> QuotientsEpisode incomplete: %+v", ep)
	}
}

func TestConnexionSansDNSSousDoQDoHEtJumeauDirect(t *testing.T) {
	cfgPlanchers := cinetique.ConfigPlanchersParDefaut()

	// 1. Poste sain en DoQ/DoH signalé par FluxResolveurChiffrePresent.
	epDoQDrapeau := construireEpisodeCinetiqueRAT03(
		t,
		8_000_000,
		30_000,
		30_000,
		1_048_576,
		131_072,
		cinetique.ConstruireCompteursReseauResolveur(8_192, 0, 0, 8_192, 4, 3, 0, false, true),
		cfgPlanchers,
	)
	if epDoQDrapeau.ConnexionSansDNS {
		t.Fatalf("poste DoQ/DoH (FluxResolveurChiffrePresent=true) marque a tort ConnexionSansDNS=true: %+v", epDoQDrapeau)
	}

	// 2. Poste sain en DoQ/DoH signalé par OctetsVersResolveurChiffre > 0.
	epDoQOctets := construireEpisodeCinetiqueRAT03(
		t,
		8_000_000,
		30_000,
		30_000,
		1_048_576,
		131_072,
		cinetique.ConstruireCompteursReseauResolveur(10_240, 0, 2_048, 8_192, 4, 3, 0, false, false),
		cfgPlanchers,
	)
	if epDoQOctets.ConnexionSansDNS {
		t.Fatalf("poste DoQ/DoH (OctetsVersResolveurChiffre=2048) marque a tort ConnexionSansDNS=true: %+v", epDoQOctets)
	}

	// 3. Hors amorçage avec hausse franche CPU/RAM : un poste DoQ/DoH à ResolutionsDNS==0
	// ne bascule jamais en OrientationCompromissionReseau de ce seul fait.
	tableDoQ := cinetique.NouvelleTableProfilsCinetiques(cinetique.ConfigProfilParDefaut())
	cleDoQ := cinetique.HashIdentifiantBinaire("agent_poste_doq_sain")
	for i := range 8 {
		diagAmorce := tableDoQ.ObserverEpisode(cleDoQ, uint64(i+1)*1_000_000, epDoQOctets)
		if diagAmorce.Orientation != cinetique.OrientationAmorcage {
			t.Fatalf("amorcage DoQ %d attendu AMORCAGE, obtenu %s", i, diagAmorce.Orientation)
		}
	}
	epDoQHausseCPURAM := construireEpisodeCinetiqueRAT03(
		t,
		24_000_000,
		48_000,
		48_000,
		1_048_576,
		131_072,
		cinetique.ConstruireCompteursReseauResolveur(10_240, 0, 2_048, 8_192, 4, 3, 0, false, true),
		cfgPlanchers,
	)
	if epDoQHausseCPURAM.ConnexionSansDNS {
		t.Fatalf("attendu ConnexionSansDNS=false sous DoQ/DoH")
	}
	diagDoQHausse := tableDoQ.ObserverEpisode(cleDoQ, 9_000_000, epDoQHausseCPURAM)
	if diagDoQHausse.Orientation == cinetique.OrientationCompromissionReseau {
		t.Fatalf("faux positif OrientationCompromissionReseau sous DoQ/DoH malgre flux resolveur chiffre: %+v", diagDoQHausse)
	}

	// 4. Jumeau positif : connexion directe sans DNS clair ni flux résolveur chiffré.
	epDirectSansDNS := construireEpisodeCinetiqueRAT03(
		t,
		24_000_000,
		48_000,
		48_000,
		1_048_576,
		131_072,
		cinetique.ConstruireCompteursReseauResolveur(10_240, 0, 0, 10_240, 2, 2, 0, false, false),
		cfgPlanchers,
	)
	if !epDirectSansDNS.ConnexionSansDNS {
		t.Fatalf("jumeau positif attendu ConnexionSansDNS=true sur connexion directe sans DNS ni DoQ/DoH: %+v", epDirectSansDNS)
	}
	diagDirect := tableDoQ.ObserverEpisode(cleDoQ, 10_000_000, epDirectSansDNS)
	if diagDirect.Orientation != cinetique.OrientationCompromissionReseau {
		t.Fatalf("jumeau positif direct sans DNS avec pic CPU/RAM attendu OrientationCompromissionReseau, obtenu %s", diagDirect.Orientation)
	}
}

func TestPartResolveurConfinementJumeauxEtDifferentiel(t *testing.T) {
	cfgPlanchers := cinetique.ConfigPlanchersParDefaut()
	cfgProfil := cinetique.ConfigProfilParDefaut()

	amorcerTableCalme := func(identifiant string, reseauAmorce cinetique.CompteursReseauEpisode, rssDebutAmorce uint64) (*cinetique.TableProfilsCinetiques, uint64) {
		table := cinetique.NouvelleTableProfilsCinetiques(cfgProfil)
		cle := cinetique.HashIdentifiantBinaire(identifiant)
		for i := range 8 {
			ep := construireEpisodeCinetiqueRAT03(
				t,
				8_000_000+uint64((i%2)*10_000),
				rssDebutAmorce,
				30_000,
				1_048_576,
				0,
				reseauAmorce,
				cfgPlanchers,
			)
			_ = table.ObserverEpisode(cle, uint64(i+1)*1_000_000, ep)
		}
		return table, cle
	}

	// Cas positif : confinement exclusif vers le résolveur chiffré (32 768 o, 0 hors résolveur, !EcouteDNSClairLocale).
	tableTunnel, cleTunnel := amorcerTableCalme("client_tunnel_doq", cinetique.CompteursReseauEpisode{}, 30_000)
	epTunnel := construireEpisodeCinetiqueRAT03(
		t,
		8_000_000,
		30_000,
		30_000,
		1_048_576,
		0,
		cinetique.ConstruireCompteursReseauResolveur(32_768, 0, 32_768, 0, 0, 0, 0, false, true),
		cfgPlanchers,
	)
	if !epTunnel.EstValide(cinetique.IndicePartResolveurPermille) {
		t.Fatalf("attendu IndicePartResolveurPermille valide pour 32768 octets")
	}
	if got := epTunnel.Valeurs[cinetique.IndicePartResolveurPermille]; got != 1000 {
		t.Fatalf("Valeurs[IndicePartResolveurPermille] attendu 1000, obtenu %d", got)
	}
	if !cinetique.EstConfinementResolveur(epTunnel) {
		t.Fatalf("attendu ConfinementResolveur=true sur client tunnel confine")
	}
	diagTunnel := tableTunnel.ObserverEpisode(cleTunnel, 9_000_000, epTunnel)
	if diagTunnel.Orientation != cinetique.OrientationCompromissionReseau {
		t.Fatalf("confinement resolveur hors amorcage attendu OrientationCompromissionReseau, obtenu %s", diagTunnel.Orientation)
	}

	// Jumeau négatif (a) : forwarder local type unbound (EcouteDNSClairLocale == true).
	reseauUnbound := cinetique.ConstruireCompteursReseauResolveur(32_768, 0, 32_768, 0, 0, 0, 0, true, true)
	tableUnbound, cleUnbound := amorcerTableCalme("relais_unbound_local", reseauUnbound, 30_000)
	epUnbound := construireEpisodeCinetiqueRAT03(t, 8_000_000, 30_000, 30_000, 1_048_576, 0, reseauUnbound, cfgPlanchers)
	if cinetique.EstConfinementResolveur(epUnbound) {
		t.Fatalf("forwarder local (EcouteDNSClairLocale=true) marque a tort ConfinementResolveur=true")
	}
	diagUnbound := tableUnbound.ObserverEpisode(cleUnbound, 9_000_000, epUnbound)
	if diagUnbound.Orientation != cinetique.OrientationNominale {
		t.Fatalf("forwarder local attendu OrientationNominale, obtenu %s", diagUnbound.Orientation)
	}

	// Jumeau négatif (b) : navigateur en coalescence HTTP/3 (4096 vers résolveur, 65536 hors résolveur).
	reseauHTTP3 := cinetique.ConstruireCompteursReseauResolveur(4_096, 0, 4_096, 65_536, 0, 0, 0, false, true)
	tableHTTP3, cleHTTP3 := amorcerTableCalme("navigateur_coalescence_h3", reseauHTTP3, 30_000)
	epHTTP3 := construireEpisodeCinetiqueRAT03(t, 8_000_000, 30_000, 30_000, 1_048_576, 0, reseauHTTP3, cfgPlanchers)
	if !epHTTP3.EstValide(cinetique.IndicePartResolveurPermille) {
		t.Fatalf("attendu IndicePartResolveurPermille valide sur total 69632 >= 16384")
	}
	if got := epHTTP3.Valeurs[cinetique.IndicePartResolveurPermille]; got != 58 || got >= 500 {
		t.Fatalf("part resolveur navigateur HTTP/3 attendue 58 (< 500), obtenu %d", got)
	}
	if cinetique.EstConfinementResolveur(epHTTP3) {
		t.Fatalf("navigateur HTTP/3 marque a tort ConfinementResolveur=true")
	}
	diagHTTP3 := tableHTTP3.ObserverEpisode(cleHTTP3, 9_000_000, epHTTP3)
	if diagHTTP3.Orientation != cinetique.OrientationNominale {
		t.Fatalf("navigateur HTTP/3 attendu OrientationNominale, obtenu %s", diagHTTP3.Orientation)
	}

	// Jumeau négatif (c) : volume sous plancher (8192 < 16384).
	epSousPlancher := construireEpisodeCinetiqueRAT03(
		t,
		8_000_000,
		30_000,
		30_000,
		1_048_576,
		0,
		cinetique.ConstruireCompteursReseauResolveur(8_192, 0, 8_192, 0, 0, 0, 0, false, true),
		cfgPlanchers,
	)
	if epSousPlancher.EstValide(cinetique.IndicePartResolveurPermille) {
		t.Fatalf("volume 8192 < 16384 ne doit pas valider IndicePartResolveurPermille")
	}
	if cinetique.EstConfinementResolveur(epSousPlancher) {
		t.Fatalf("volume sous plancher ne doit jamais activer ConfinementResolveur")
	}

	// Jumeau négatif (d) : quotient descriptif IndiceAbsorptionDescriptivePermille
	// (amorcé avec croissance intra-épisode VmRSS de 28 000 -> 30 000 Kio pour faire varier
	// fortement le seul quotient descriptif au 9e épisode où VmRSS est stable à 30 000 Kio).
	reseauAbsorption := cinetique.CompteursReseauEpisode{
		OctetsEntrants: 2 << 20,
	}
	tableAbs, cleAbs := amorcerTableCalme("lecteur_flux_entrant", reseauAbsorption, 28_000)
	epAbsorption := construireEpisodeCinetiqueRAT03(
		t,
		8_000_000,
		30_000,
		30_000,
		1_048_576,
		0,
		reseauAbsorption,
		cfgPlanchers,
	)
	if !epAbsorption.EstValide(cinetique.IndiceAbsorptionDescriptivePermille) {
		t.Fatalf("attendu IndiceAbsorptionDescriptivePermille valide pour 2 Mio entrants")
	}
	if got := epAbsorption.Valeurs[cinetique.IndiceAbsorptionDescriptivePermille]; got != 0 {
		t.Fatalf("Valeurs[IndiceAbsorptionDescriptivePermille] attendu 0 (DeltaOctetsBloc=0, VmRSS stable), obtenu %d", got)
	}
	diagAbs := tableAbs.ObserverEpisode(cleAbs, 9_000_000, epAbsorption)
	if (diagAbs.MasqueQuotientsAlerte & cinetique.MasqueQuotientsDescriptifs) != 0 {
		t.Fatalf("MasqueQuotientsDescriptifs ne doit jamais figurer dans MasqueQuotientsAlerte: 0x%04x", diagAbs.MasqueQuotientsAlerte)
	}
	if diagAbs.Orientation == cinetique.OrientationEcartStructurel || diagAbs.Orientation != cinetique.OrientationNominale {
		t.Fatalf("quotient descriptif a declenche une orientation non nominale: %s (masque=0x%04x)",
			diagAbs.Orientation, diagAbs.MasqueQuotientsAlerte)
	}

	// Sérialisation différentielle aux bornes extrêmes int64 (< 512 octets, 0 B/op, jeton |RESOLVEUR_PERMILLE=).
	var diagExtreme cinetique.DiagnosticEpisodeCinetique
	diagExtreme.ClasseCoeur = cinetique.ClasseCoeurPerformance
	diagExtreme.Orientation = cinetique.OrientationAbstention
	diagExtreme.PasDeriveMonotoneRSS = math.MaxUint16
	for i := range cinetique.NombreQuotientsEpisode {
		diagExtreme.VariationsPct[i] = math.MinInt64
		diagExtreme.Episode.Valeurs[i] = math.MaxInt64
	}
	diagExtreme.Episode.PressionCPUPermille = 1000
	diagExtreme.Episode.ConnexionSansDNS = true
	diagExtreme.Episode.CodeRaisonDNS = math.MaxUint8
	nomExtreme := strings.Repeat("x", 48)

	var tampon [512]byte
	jeton, errFmt := cinetique.FormaterDifferentielEpisode(tampon[:0], nomExtreme, diagExtreme)
	if errFmt != nil {
		t.Fatalf("FormaterDifferentielEpisode bornes extremes: %v", errFmt)
	}
	if len(jeton) == 0 || len(jeton) >= 512 {
		t.Fatalf("longueur FormaterDifferentielEpisode hors budget (< 512): %d", len(jeton))
	}
	if !strings.Contains(string(jeton), "|RESOLVEUR_PERMILLE=") {
		t.Fatalf("jeton |RESOLVEUR_PERMILLE= absent du differentiel: %s", string(jeton))
	}
	allocsDiff := testing.AllocsPerRun(200, func() {
		if _, err := cinetique.FormaterDifferentielEpisode(tampon[:0], nomExtreme, diagExtreme); err != nil {
			t.Fatal(err)
		}
	})
	if allocsDiff != 0 {
		t.Fatalf("FormaterDifferentielEpisode pire cas doit rester 0 B/op, mesure %.2f allocs/op", allocsDiff)
	}
}

func TestCacheTuplesEtCollecteurResolveurZeroAlloc(t *testing.T) {
	resolveur, errRes := cinetique.OuvrirResolveurSocketProcessus()
	if errRes != nil {
		t.Fatalf("OuvrirResolveurSocketProcessus: %v", errRes)
	}
	t.Cleanup(func() {
		_ = resolveur.Fermer()
	})

	srvUDP, errSrv := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if errSrv != nil {
		t.Fatalf("ListenUDP loopback: %v", errSrv)
	}
	t.Cleanup(func() {
		_ = srvUDP.Close()
	})

	adrSrv := srvUDP.LocalAddr().(*net.UDPAddr)
	cliUDP, errCli := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, adrSrv)
	if errCli != nil {
		t.Fatalf("DialUDP loopback: %v", errCli)
	}
	t.Cleanup(func() {
		_ = cliUDP.Close()
	})

	if _, errW := cliUDP.Write([]byte("sonde-cache-tuple")); errW != nil {
		t.Fatalf("Write UDP: %v", errW)
	}
	var rx [32]byte
	if _, _, errR := srvUDP.ReadFromUDP(rx[:]); errR != nil {
		t.Fatalf("ReadFromUDP: %v", errR)
	}

	portLocal := uint16(cliUDP.LocalAddr().(*net.UDPAddr).Port)
	portDistant := uint16(adrSrv.Port)
	pidAttendu := os.Getpid()

	var derniereIdentite cinetique.IdentiteProcessusSocket
	for i := range 20 {
		ident, errTuple := resolveur.ResoudreTupleIPv4(unix.IPPROTO_UDP, portLocal, portDistant, 0)
		if errTuple != nil {
			t.Fatalf("ResoudreTupleIPv4 appel %d: %v", i, errTuple)
		}
		if ident.PID != pidAttendu || ident.DebutTacheTicks == 0 || ident.InodeSocket == 0 {
			t.Fatalf("identite resolue invalide a l'appel %d: %+v", i, ident)
		}
		derniereIdentite = ident
	}

	var succes, defauts uint64 = cinetique.StatistiquesCacheTuplesResolveur(resolveur)
	if defauts != 1 || succes < 19 {
		t.Fatalf("statistiques cache tuples inattendues apres 20 appels: succes=%d (attendu >=19) defauts=%d (attendu 1)",
			succes, defauts)
	}

	allocsHitCache := testing.AllocsPerRun(200, func() {
		if _, err := resolveur.ResoudreTupleIPv4(unix.IPPROTO_UDP, portLocal, portDistant, 0); err != nil {
			t.Fatal(err)
		}
	})
	if allocsHitCache != 0 {
		t.Fatalf("hit du cache tuple doit etre 0 B/op, mesure %.2f allocs/op", allocsHitCache)
	}

	var ecouteDNS bool
	var errEcoute error
	ecouteDNS, errEcoute = cinetique.DetecterEcouteDNSClairProcessus(resolveur, derniereIdentite.PID, derniereIdentite.DebutTacheTicks)
	if errEcoute != nil {
		t.Fatalf("DetecterEcouteDNSClairLocale: %v", errEcoute)
	}
	if ecouteDNS {
		t.Fatalf("le processus de test courant ne detient aucune socket d'ecoute DNS clair locale")
	}

	collecteur := cinetique.NouveauCollecteurReseauParProcessus()
	cinetique.EnregistrerObservationResolveurProcessus(collecteur, derniereIdentite.PID, derniereIdentite.DebutTacheTicks, 20_000, 4_096, true, false, true)
	cinetique.EnregistrerObservationResolveurProcessus(collecteur, derniereIdentite.PID, derniereIdentite.DebutTacheTicks, 12_768, 0, false, true, true)
	recolte := collecteur.RecolterEtPurger(derniereIdentite.PID, derniereIdentite.DebutTacheTicks)
	octResRec, octHorsRec, connHorsRec, ecouteRec, fluxRec := cinetique.LireCompteursResolveurRecolte(recolte)
	if octResRec != 32_768 ||
		octHorsRec != 4_096 ||
		connHorsRec != 1 ||
		!ecouteRec ||
		!fluxRec {
		t.Fatalf("agregation EnregistrerObservationResolveur inexacte: %+v", recolte)
	}

	allocsObs := testing.AllocsPerRun(200, func() {
		cinetique.EnregistrerObservationResolveurProcessus(collecteur, derniereIdentite.PID, derniereIdentite.DebutTacheTicks, 1024, 512, true, false, true)
	})
	_ = collecteur.RecolterEtPurger(derniereIdentite.PID, derniereIdentite.DebutTacheTicks)
	if allocsObs != 0 {
		t.Fatalf("EnregistrerObservationResolveur doit etre 0 B/op, mesure %.2f allocs/op", allocsObs)
	}
}

func TestBancConfinementResolveurHoteEtEntrantsChaineComplete(t *testing.T) {
	ctxAnnule, annuler := context.WithCancel(t.Context())
	annuler()
	if _, errAnnule := cinetique.ExecuterBancConfinementResolveurHote(ctxAnnule, t.TempDir()); errAnnule == nil {
		t.Fatalf("ExecuterBancConfinementResolveurHote devait echouer sur un contexte annule")
	}

	var rapportHote cinetique.RapportConfinementResolveurHote
	var errHote error
	rapportHote, errHote = cinetique.ExecuterBancConfinementResolveurHote(t.Context(), t.TempDir())
	if errHote != nil {
		t.Fatalf("ExecuterBancConfinementResolveurHote: %v", errHote)
	}
	pidAttendu := os.Getpid()
	if rapportHote.PIDProcessus != pidAttendu || rapportHote.DebutTacheTicks == 0 {
		t.Fatalf("en-tete RapportConfinementResolveurHote invalide: %+v", rapportHote)
	}
	if len(rapportHote.Chaines) != 4 {
		t.Fatalf("attendu 4 chaines vivantes dans RapportConfinementResolveurHote, obtenu %d", len(rapportHote.Chaines))
	}

	orientationCompromission := cinetique.OrientationCompromissionReseau.String()

	var ch0 cinetique.EtapeConfinementResolveurHote = rapportHote.Chaines[0]
	if ch0.NomChaine != "tunnel_doq_confine" ||
		ch0.AttributionSocket.PID != pidAttendu ||
		!ch0.ConfinementResolveur ||
		ch0.ConnexionSansDNS ||
		ch0.OrientationMoteur != orientationCompromission {
		t.Fatalf("chaine 0 tunnel_doq_confine non conforme: %+v", ch0)
	}

	ch1 := rapportHote.Chaines[1]
	if ch1.NomChaine != "forwarder_local_dns_clair" ||
		ch1.AttributionSocket.PID != pidAttendu ||
		!ch1.EcouteDNSClairLocale ||
		ch1.ConfinementResolveur ||
		ch1.ConnexionSansDNS ||
		ch1.OrientationMoteur == orientationCompromission {
		t.Fatalf("chaine 1 forwarder_local_dns_clair non conforme: %+v", ch1)
	}

	ch2 := rapportHote.Chaines[2]
	if ch2.NomChaine != "absorption_http3_web" ||
		ch2.AttributionSocket.PID != pidAttendu ||
		!ch2.Episode.EstValide(cinetique.IndiceAbsorptionDescriptivePermille) ||
		ch2.ConfinementResolveur ||
		ch2.ConnexionSansDNS ||
		ch2.OrientationMoteur == orientationCompromission {
		t.Fatalf("chaine 2 absorption_http3_web non conforme: %+v", ch2)
	}

	ch3 := rapportHote.Chaines[3]
	_, _, _, _, fluxCh3 := cinetique.LireCompteursResolveurEpisode(ch3.Episode)
	if ch3.NomChaine != "poste_doq_navigation_saine" ||
		ch3.AttributionSocket.PID != pidAttendu ||
		!fluxCh3 ||
		ch3.ConfinementResolveur ||
		ch3.ConnexionSansDNS ||
		ch3.OrientationMoteur == orientationCompromission {
		t.Fatalf("chaine 3 poste_doq_navigation_saine non conforme: %+v", ch3)
	}

	rapportComplet, errComplet := cinetique.ExecuterBancChaineComplete(t.Context(), t.TempDir(), "")
	if errComplet != nil {
		t.Fatalf("ExecuterBancChaineComplete sans modele Qwen: %v", errComplet)
	}
	var etapeUDP cinetique.EtapeChaineDetection
	trouveeUDP := false
	for _, etape := range rapportComplet.Chaines {
		if etape.NomChaine == "3_exfiltration_udp_attribuee_inet_diag" {
			etapeUDP = etape
			trouveeUDP = true
			break
		}
	}
	if !trouveeUDP {
		t.Fatalf("etape 3_exfiltration_udp_attribuee_inet_diag absente de RapportChaineComplete")
	}
	if cinetique.OctetsReseauEntrantsEtape(etapeUDP) == 0 {
		t.Fatalf("DeltaOctetsReseauEntrants demeure nul sur 3_exfiltration_udp_attribuee_inet_diag: %+v", etapeUDP)
	}
}
