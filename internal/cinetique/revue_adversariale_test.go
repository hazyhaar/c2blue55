//go:build linux

package cinetique

import (
	"context"
	"crypto/sha256"
	"errors"
	"math"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestRevuePMUHybrideDetectee vérifie que VerifierDisponibiliteCapteursNoyau
// détecte la PMU matérielle sur architecture hybride cpu_core/cpu_atom (Mythos C-02).
func TestRevuePMUHybrideDetectee(t *testing.T) {
	etat := VerifierDisponibiliteCapteursNoyau()
	if etat.TopologieHybridePresent && !etat.PMUMateriellePresente {
		if _, errCore := os.Stat("/sys/bus/event_source/devices/cpu_core"); errCore == nil {
			t.Fatalf("PMUMateriellePresente=false alors que /sys/bus/event_source/devices/cpu_core existe")
		}
	}
}

// TestRevueProcessusMultiFilsSchedstat vérifie que LireInstantaneProcessus agrège
// le temps d'exécution CPU de tous les fils du processus et non du seul leader tgid (Mythos C-03).
func TestRevueProcessusMultiFilsSchedstat(t *testing.T) {
	capteur, err := OuvrirCapteurProcLinux()
	if err != nil {
		t.Fatalf("ouverture capteur: %v", err)
	}
	defer func() { _ = capteur.Fermer() }()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	pid := os.Getpid()
	snapDebut, errDebut := capteur.LireInstantaneProcessus(pid, time.Now().UnixNano())
	if errDebut != nil {
		t.Fatalf("snapDebut: %v", errDebut)
	}

	pret := make(chan struct{})
	fini := make(chan [32]byte, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		close(pret)
		debut := time.Now()
		var bloc [4096]byte
		var h [32]byte
		for time.Since(debut) < 40*time.Millisecond {
			for range 64 {
				bloc[0] ^= h[0]
				h = sha256.Sum256(bloc[:])
			}
		}
		fini <- h
	}()
	<-pret
	condensat := <-fini
	if condensat[0] == 0xFF && pid < 0 {
		t.Fatal("impossible")
	}

	snapFin, errFin := capteur.LireInstantaneProcessus(pid, time.Now().UnixNano())
	if errFin != nil {
		t.Fatalf("snapFin: %v", errFin)
	}
	deltaExecNs := snapFin.TempsExecutionNs - snapDebut.TempsExecutionNs
	if deltaExecNs < 20_000_000 {
		t.Fatalf("LireInstantaneProcessus a manque le CPU du fil secondaire: deltaExecNs=%d ns (< 20 ms)", deltaExecNs)
	}
	allocsMultiFils := testing.AllocsPerRun(100, func() {
		if _, errA := capteur.LireInstantaneProcessus(pid, 100); errA != nil {
			t.Fatal(errA)
		}
	})
	if allocsMultiFils != 0 {
		t.Fatalf("LireInstantaneProcessus multi-fils doit rester en 0 B/op, mesure %.2f allocs/op", allocsMultiFils)
	}
}

// TestRevueTopologiePlusDe64Coeurs vérifie le classement des coeurs >= 64 (GLM C-02).
func TestRevueTopologiePlusDe64Coeurs(t *testing.T) {
	indicesCore, masqueCore, errCore := AnalyserListeCPUs("0-3,64-67")
	if errCore != nil || len(indicesCore) != 8 || masqueCore != 0x0F {
		t.Fatalf("AnalyserListeCPUs inattendu: len=%d masque=0x%X err=%v", len(indicesCore), masqueCore, errCore)
	}
	indicesAtom, masqueAtom, errAtom := AnalyserListeCPUs("4-7,68-71")
	if errAtom != nil || len(indicesAtom) != 8 || masqueAtom != 0xF0 {
		t.Fatalf("AnalyserListeCPUs atom inattendu: len=%d masque=0x%X err=%v", len(indicesAtom), masqueAtom, errAtom)
	}
	topo := ConstruireTopologieHybride(indicesCore, indicesAtom)
	if !topo.EstHybride {
		t.Fatalf("attendu EstHybride=true")
	}
	if got := topo.ClasseDuCoeur(65); got != ClasseCoeurPerformance {
		t.Fatalf("coeur 65 attendu ClasseCoeurPerformance, obtenu %v", got)
	}
	if got := topo.ClasseDuCoeur(70); got != ClasseCoeurEfficience {
		t.Fatalf("coeur 70 attendu ClasseCoeurEfficience, obtenu %v", got)
	}
	// Jumeau négatif : coeur hors liste et indice hors bornes.
	if got := topo.ClasseDuCoeur(200); got != ClasseCoeurInconnue {
		t.Fatalf("coeur 200 attendu ClasseCoeurInconnue, obtenu %v", got)
	}
	if got := topo.ClasseDuCoeur(2048); got != ClasseCoeurInconnue {
		t.Fatalf("coeur 2048 attendu ClasseCoeurInconnue, obtenu %v", got)
	}
}

// TestRevueDebordementAdditionDeltas vérifie l'absence d'enroulement uint64 sur
// les sommes de compteurs cumulatifs d'un épisode (GPT-6-Sol C-05).
func TestRevueDebordementAdditionDeltas(t *testing.T) {
	debut := InstantaneTache{
		PID:             42,
		DebutTacheTicks: 1000,
		HorodatageNs:    1_000_000,
	}
	fin := InstantaneTache{
		PID:                  42,
		DebutTacheTicks:      1000,
		HorodatageNs:         10_000_000,
		TempsExecutionNs:     2_000_000,
		OctetsLusLogiques:    math.MaxUint64,
		OctetsEcritsLogiques: 1,
		AppelsLecture:        math.MaxUint64,
		AppelsEcriture:       1,
		VmRSSKio:             16384,
		NombreFils:           1,
	}
	ep, err := EvaluerEpisodeCinetique(
		debut,
		fin,
		InstantanePressionPSI{},
		InstantanePressionPSI{},
		CompteursReseauEpisode{},
		TopologieHybride{},
		ConfigPlanchersParDefaut(),
	)
	if err != nil {
		t.Fatalf("EvaluerEpisodeCinetique: %v", err)
	}
	if !ep.EstValide(IndicePartEcriturePermille) || !ep.EstValide(IndiceOctetsParAppelES) {
		t.Fatalf("enroulement uint64 a invalide les quotients logiques: masque=%b", ep.MasqueValidite)
	}
}

// TestRevueBaliseReseauSansLectureDisque vérifie qu'une exfiltration ou balise C2
// en mémoire pure (< 1024 octets lus sur disque) conserve ses octets sortants et
// n'est jamais annulée par VETO_ZERO_NETWORK (Mythos C-04, GPT-6-Sol C-07, GLM C-11).
func TestRevueBaliseReseauSansLectureDisque(t *testing.T) {
	debut := InstantaneTache{
		PID:             77,
		DebutTacheTicks: 900,
		HorodatageNs:    1_000_000,
	}
	fin := InstantaneTache{
		PID:              77,
		DebutTacheTicks:  900,
		HorodatageNs:     20_000_000,
		TempsExecutionNs: 5_000_000,
		OctetsLusLogiques: 512, // sous MinOctetsLogiques (1024)
		AppelsLecture:    2,
		VmRSSKio:         24576,
		NombreFils:       1,
	}
	ep, err := EvaluerEpisodeCinetique(
		debut,
		fin,
		InstantanePressionPSI{},
		InstantanePressionPSI{},
		CompteursReseauEpisode{
			OctetsSortants:      1 << 20,
			ConnexionsSortantes: 1,
			ResolutionsDNS:      1,
		},
		TopologieHybride{},
		ConfigPlanchersParDefaut(),
	)
	if err != nil {
		t.Fatalf("EvaluerEpisodeCinetique: %v", err)
	}
	if ep.OctetsSortantsNuls() {
		t.Fatalf("OctetsSortantsNuls()=true alors que 1 Mio sont sortis sur le reseau")
	}
	diag := DiagnosticEpisodeCinetique{
		Orientation: OrientationEcartStructurel,
		Episode:     ep,
	}
	final, veto, motif := AppliquerVetoPhysiqueCinetique(diag, VerdictSLMCompromissionExfil)
	if final != VerdictSLMCompromissionExfil || veto {
		t.Fatalf("veto abusif sur balise C2 memoire: final=%s veto=%v motif=%s", final, veto, motif)
	}
}

// TestRevueFuiteMemoireRapideNonGelee vérifie qu'une fuite mémoire dépassant le seuil
// d'alerte intrinsèque incrémente bien PasDeriveMonotoneRSS et atteint DERIVE_ORGANIQUE_MONOTONE (Mythos C-05).
func TestRevueFuiteMemoireRapideNonGelee(t *testing.T) {
	table := NouvelleTableProfilsCinetiques(ConfigProfilParDefaut())
	cle := HashIdentifiantBinaire("daemon_fuite_rapide")

	for i := range 8 {
		ep := construireEpisodeReference(t, 0, 2_000_000, 100_000, 500_000, 30_000, 0, CompteursReseauEpisode{})
		_ = table.ObserverEpisode(cle, uint64(i+1)*1_000_000, ep)
	}

	rss := uint64(30_000)
	atteintDerive := false
	for k := 1; k <= 8; k++ {
		rss = (rss * 14) / 10 // +40 % par pas
		ep := construireEpisodeReference(t, 0, 2_000_000, 100_000, 500_000, rss, 0, CompteursReseauEpisode{})
		diag := table.ObserverEpisode(cle, uint64(10+k)*1_000_000, ep)
		if diag.Orientation == OrientationDeriveOrganique {
			atteintDerive = true
		}
	}
	if !atteintDerive {
		t.Fatalf("OrientationDeriveOrganique jamais atteinte sur une croissance monotone de +40%%/pas")
	}
}

// TestRevueCompromissionPendantAmorcageEtAbstentionAmorcage vérifie que :
// 1. un code DNS hostile ou port suspect déclenche COMPROMISSION dès le 1er épisode sans empoisonner la base (Mythos C-06) ;
// 2. des épisodes sous forte pression PSI CPU pendant l'amorçage ne polluent pas les quotients CPU (Mythos C-08).
func TestRevueCompromissionPendantAmorcageEtAbstentionAmorcage(t *testing.T) {
	table := NouvelleTableProfilsCinetiques(ConfigProfilParDefaut())
	cle := HashIdentifiantBinaire("service_compromis_au_demarrage")

	epHostile := construireEpisodeReference(t, 0, 4_000_000, 100_000, 400_000, 32_000, 0, CompteursReseauEpisode{
		OctetsSortants:      32768,
		ConnexionsSortantes: 1,
		PortSuspect:         53,
		ProtocoleSuspectUDP: true,
		CodeRaisonDNS:       4,
	})
	diagHostile := table.ObserverEpisode(cle, 1_000_000, epHostile)
	if diagHostile.Orientation != OrientationCompromissionReseau || !DoitEscaladeSLM(diagHostile) {
		t.Fatalf("compromission au demarrage masquee par l'amorcage: orientation=%s escalade=%v",
			diagHostile.Orientation, DoitEscaladeSLM(diagHostile))
	}
	if diagHostile.EpisodesObserves != 0 {
		t.Fatalf("l'episode hostile ne devait pas etre integre a la ligne de base: EpisodesObserves=%d", diagHostile.EpisodesObserves)
	}

	// Mythos C-08 : 8 épisodes sous PSI CPU 45 % (15 750 us sur 35 ms).
	tablePSI := NouvelleTableProfilsCinetiques(ConfigProfilParDefaut())
	clePSI := HashIdentifiantBinaire("service_sous_psi_initial")
	for i := range 8 {
		epContention := construireEpisodeReference(t, 0, 2_000_000, 8_000_000, 25_000_000, 20_000, 16_000, CompteursReseauEpisode{})
		if !epContention.AbstentionPSICPU {
			t.Fatalf("attendu AbstentionPSICPU=true")
		}
		_ = tablePSI.ObserverEpisode(clePSI, uint64(i+1)*1_000_000, epContention)
	}
	// Le 9e épisode calme ne doit pas voir une médiane CPU/dilatation déjà figée par les 8 épisodes sous contention.
	epCalme := construireEpisodeReference(t, 0, 2_000_000, 100_000, 300_000, 20_000, 200, CompteursReseauEpisode{})
	diagCalme := tablePSI.ObserverEpisode(clePSI, 9_000_000, epCalme)
	if diagCalme.VariationsPct[IndiceDilatationHorsCPU] != 0 {
		t.Fatalf("quotient sensible au CPU contamine pendant l'amorcage sous PSI: variation=%d%%",
			diagCalme.VariationsPct[IndiceDilatationHorsCPU])
	}
}

// TestRevueDebordementEvaluerEcartEtPermille vérifie l'absence d'enroulement int64
// lorsque l'observation atteint math.MaxInt64 (Mythos C-07, GLM C-04 & C-09).
func TestRevueDebordementEvaluerEcartEtPermille(t *testing.T) {
	var suivi SuiviQuotientRobuste
	for range 8 {
		suivi.Enregistrer(0)
	}
	varPct, scoreMilli := suivi.EvaluerEcart(math.MaxInt64)
	if varPct <= 0 || scoreMilli <= 0 {
		t.Fatalf("enroulement int64 detecte dans EvaluerEcart(MaxInt64): varPct=%d scoreMilli=%d", varPct, scoreMilli)
	}
	if got := quotientPermilleAbs(math.MaxInt64, 1); got <= 0 {
		t.Fatalf("enroulement int64 detecte dans quotientPermilleAbs(MaxInt64, 1): %d", got)
	}
}

// TestRevueZeroAllocDifferentielPireCas vérifie le budget 0 B/op de FormaterDifferentielEpisode
// sur les bornes extrêmes int64/uint16 (GLM C-05).
func TestRevueZeroAllocDifferentielPireCas(t *testing.T) {
	var diag DiagnosticEpisodeCinetique
	diag.ClasseCoeur = ClasseCoeurPerformance
	diag.Orientation = OrientationAbstention // libellé le plus long (34 octets)
	diag.PasDeriveMonotoneRSS = 65535
	for i := range NombreQuotientsEpisode {
		diag.VariationsPct[i] = math.MinInt64
		diag.Episode.Valeurs[i] = math.MaxInt64
	}
	diag.Episode.PressionCPUPermille = 1000
	diag.Episode.ConnexionSansDNS = true
	diag.Episode.CodeRaisonDNS = 255
	nomLong := strings.Repeat("x", 48)

	var dst [512]byte
	sortie, err := FormaterDifferentielEpisode(dst[:0], nomLong, diag)
	if err != nil || len(sortie) == 0 {
		t.Fatalf("FormaterDifferentielEpisode pire cas en echec: err=%v len=%d", err, len(sortie))
	}
	allocs := testing.AllocsPerRun(200, func() {
		_, errFmt := FormaterDifferentielEpisode(dst[:0], nomLong, diag)
		if errFmt != nil {
			t.Fatal(errFmt)
		}
	})
	if allocs != 0 {
		t.Fatalf("allocation sur le tas dans FormaterDifferentielEpisode pire cas: %.2f allocs/op", allocs)
	}
}

// TestRevueLRUMonotoneTableProfils vérifie que l'éviction LRU ne dépend pas
// d'un recul de l'horodatage fourni par l'appelant (GPT-6-Sol C-08).
func TestRevueLRUMonotoneTableProfils(t *testing.T) {
	table := NouvelleTableProfilsCinetiques(ConfigProfilParDefaut())
	ep := construireEpisodeReference(t, 0, 2_000_000, 100_000, 300_000, 20_000, 0, CompteursReseauEpisode{})

	// 4 clés tombant exactement dans le même ensemble (pas de 256 laisse (cle^(cle>>17))&63 à 0).
	cles := [5]uint64{0 * 256, 1 * 256, 2 * 256, 3 * 256, 4 * 256}
	for i := range 4 {
		_ = table.ObserverEpisode(cles[i], uint64(100+i), ep)
	}
	// On consulte cles[0] en dernier, mais avec un horodatage appelant plus petit (ex. 1).
	// cles[1] est désormais la vraie entrée la plus anciennement consultée, pas cles[0].
	diag0 := table.ObserverEpisode(cles[0], 1, ep)
	if diag0.EpisodesObserves != 2 {
		t.Fatalf("attendu 2 episodes sur cles[0], obtenu %d", diag0.EpisodesObserves)
	}
	// L'insertion de cles[4] doit évincer cles[1], pas cles[0] tout juste consultée.
	_ = table.ObserverEpisode(cles[4], 200, ep)
	diagApres := table.ObserverEpisode(cles[0], 201, ep)
	if diagApres.EpisodesObserves != 3 {
		t.Fatalf("cles[0] recemment consultee a ete evincee a tort: EpisodesObserves=%d (attendu 3)", diagApres.EpisodesObserves)
	}
}

// TestRevueSommeilSansESNonClasseStockage vérifie qu'un sommeil hors-CPU sans aucune
// opération E/S disque ni bloc n'est jamais qualifié de panne de stockage (GPT-6-Sol C-01).
func TestRevueSommeilSansESNonClasseStockage(t *testing.T) {
	table := NouvelleTableProfilsCinetiques(ConfigProfilParDefaut())
	cle := HashIdentifiantBinaire("processus_dormeur_pur")

	construireEpisodeSansDisque := func(horsCPUNs uint64) QuotientsEpisode {
		debut := InstantaneTache{PID: 55, DebutTacheTicks: 777, HorodatageNs: 1_000_000}
		fin := InstantaneTache{
			PID:                     55,
			DebutTacheTicks:         777,
			HorodatageNs:            1_000_000 + int64(2_000_000+100_000+horsCPUNs),
			TempsExecutionNs:        2_000_000,
			AttenteFileNs:           100_000,
			CommutationsVolontaires: 8,
			CommutationsSubies:      1,
			VmRSSKio:                16_000,
			NombreFils:              1,
		}
		ep, err := EvaluerEpisodeCinetique(debut, fin, InstantanePressionPSI{}, InstantanePressionPSI{}, CompteursReseauEpisode{}, TopologieHybride{}, ConfigPlanchersParDefaut())
		if err != nil {
			t.Fatalf("EvaluerEpisodeCinetique: %v", err)
		}
		return ep
	}

	for i := range 8 {
		_ = table.ObserverEpisode(cle, uint64(i+1), construireEpisodeSansDisque(500_000))
	}
	diag := table.ObserverEpisode(cle, 9, construireEpisodeSansDisque(25_000_000))
	if diag.Orientation == OrientationDegradationES {
		t.Fatalf("sommeil pur sans aucune E/S disque classe a tort en OrientationDegradationES")
	}
	arbitre := NouvelArbitreEncodeurCinetique()
	defer func() { _ = arbitre.Fermer() }()
	dec, err := arbitre.ArbitrerEpisode(t.Context(), "processus_dormeur_pur", diag)
	if err != nil {
		t.Fatalf("ArbitrerEpisode: %v", err)
	}
	if dec.VerdictFinal == VerdictSLMDegradationMaterielle {
		t.Fatalf("sommeil pur sans E/S disque arbitre a tort en HARDWARE_STORAGE_DEGRADATION")
	}
}

// TestRevueVetoMemoireNulleAvecTraficBenin vérifie qu'une proposition erronée
// ORGANIC_RESOURCE_DRIFT sans hausse mémoire et avec 3 permille d'egress bénin
// (sans port suspect ni alerte DNS) n'est jamais transformée en compromission C2 (Mythos C-15).
func TestRevueVetoMemoireNulleAvecTraficBenin(t *testing.T) {
	ep := construireEpisodeReference(t, 0, 2_000_000, 100_000, 400_000, 20_000, 0, CompteursReseauEpisode{
		OctetsSortants:      400, // ~3 permille sur 131 Kio lus
		ConnexionsSortantes: 1,
		ResolutionsDNS:      1,
	})
	diag := DiagnosticEpisodeCinetique{
		Orientation:          OrientationEcartStructurel,
		PasDeriveMonotoneRSS: 0,
		Episode:              ep,
	}
	final, veto, motif := AppliquerVetoPhysiqueCinetique(diag, VerdictSLMDeriveOrganique)
	if !veto {
		t.Fatalf("attendu veto sur ORGANIC_RESOURCE_DRIFT sans hausse memoire")
	}
	if final == VerdictSLMCompromissionExfil {
		t.Fatalf("veto a converti un trafic benin (3 permille) en PROCESS_C2_OR_EXFILTRATION (motif=%s)", motif)
	}
	if final != VerdictSLMContentionOuInsuff {
		t.Fatalf("attendu CONTENTION_OR_INSUFFICIENT, obtenu %s", final)
	}
}

// TestRevueSocketDoublePileIPv4DansAFInet6 vérifie que ResoudreTupleIPv4 résout
// une socket double pile Go ("udp") enregistrée par Linux sous AF_INET6 (Mythos C-13).
func TestRevueSocketDoublePileIPv4DansAFInet6(t *testing.T) {
	resolveur, err := OuvrirResolveurSocketProcessus()
	if err != nil {
		t.Fatalf("ouverture resolveur: %v", err)
	}
	defer func() { _ = resolveur.Fermer() }()

	srv, errSrv := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if errSrv != nil {
		t.Fatalf("ListenUDP serveur: %v", errSrv)
	}
	defer func() { _ = srv.Close() }()
	adrSrv := srv.LocalAddr().(*net.UDPAddr)

	// Socket double pile par défaut de Go ("udp" sur adresse wildcard).
	cliDual, errCli := net.ListenUDP("udp", &net.UDPAddr{Port: 0})
	if errCli != nil {
		t.Fatalf("ListenUDP dual-stack: %v", errCli)
	}
	defer func() { _ = cliDual.Close() }()
	portLocal := uint16(cliDual.LocalAddr().(*net.UDPAddr).Port)

	if _, errW := cliDual.WriteToUDP([]byte("sonde-dual-stack"), adrSrv); errW != nil {
		t.Fatalf("WriteToUDP: %v", errW)
	}

	ident, errRes := resolveur.ResoudreTupleIPv4(unix.IPPROTO_UDP, portLocal, uint16(adrSrv.Port), 0)
	if errRes != nil {
		t.Fatalf("ResoudreTupleIPv4 a echoue sur socket double pile AF_INET6: %v", errRes)
	}
	if ident.PID != os.Getpid() {
		t.Fatalf("PID resolu %d != %d", ident.PID, os.Getpid())
	}

	// Jumeau négatif réel sur inet_diag (Mythos C-24, GLM C-20) : fermeture puis interrogation.
	_ = cliDual.Close()
	if _, errAbsent := resolveur.ResoudreTupleIPv4(unix.IPPROTO_UDP, portLocal, uint16(adrSrv.Port), 0); !errors.Is(errAbsent, ErrSocketIntrouvable) {
		t.Fatalf("attendu ErrSocketIntrouvable apres fermeture socket UDP, obtenu %v", errAbsent)
	}
}

type arbitreStubErreur struct {
	echouer atomic.Bool
}

func (s *arbitreStubErreur) ArbitrerEpisode(_ context.Context, _ string, _ DiagnosticEpisodeCinetique) (DecisionArbitrageCinetique, error) {
	if s.echouer.Load() {
		return DecisionArbitrageCinetique{}, errors.New("erreur simulacre arbitre")
	}
	return DecisionArbitrageCinetique{
		ModeleInvoque:     true,
		VerdictBrutModele: VerdictSLMDegradationMaterielle,
		VerdictFinal:      VerdictSLMDegradationMaterielle,
		Confiance:         0.95,
	}, nil
}

func (s *arbitreStubErreur) Fermer() error { return nil }

// TestRevueFileArbitrageCourseFermetureEtCompteurs vérifie qu'aucun dossier accepté
// (err == nil) n'est perdu lors d'un Fermer() concurrent et que les erreurs et rejets
// sont exactement réconciliables avec TotalSoumis (GPT-6-Sol C-04, Mythos C-20, GLM C-16 & C-17).
func TestRevueFileArbitrageCourseFermetureEtCompteurs(t *testing.T) {
	for iter := range 40 {
		stub := &arbitreStubErreur{}
		var recues atomic.Uint64
		file := NouvelleFileArbitrageCinetique(stub, 4, func(_ DossierEscaladeCinetique, _ DecisionArbitrageCinetique) {
			recues.Add(1)
		})

		diag := DiagnosticEpisodeCinetique{Orientation: OrientationDegradationES}
		var acceptesSucces atomic.Uint64
		var wg sync.WaitGroup
		for range 8 {
			wg.Go(func() {
				for range 60 {
					if err := file.SoumettreNonBloquant("job", diag); err == nil {
						acceptesSucces.Add(1)
					}
				}
			})
		}
		runtime.Gosched()
		file.Fermer()
		wg.Wait()

		gotAcceptes := acceptesSucces.Load()
		gotArbitres := file.TotalArbitres.Load()
		gotSoumis := file.TotalSoumis.Load()
		if gotAcceptes != gotArbitres || gotArbitres != recues.Load() || gotSoumis != gotAcceptes {
			t.Fatalf("iter %d: perte ou discordance de compteurs a la fermeture: acceptes=%d arbitres=%d recues=%d TotalSoumis=%d",
				iter, gotAcceptes, gotArbitres, recues.Load(), gotSoumis)
		}
	}

	// Jumeau négatif : erreurs de l'arbitre comptabilisées dans TotalErreursArbitrage.
	stubErr := &arbitreStubErreur{}
	stubErr.echouer.Store(true)
	fileErr := NouvelleFileArbitrageCinetique(stubErr, 8, nil)
	diagErr := DiagnosticEpisodeCinetique{Orientation: OrientationDegradationES}
	for range 5 {
		if err := fileErr.SoumettreNonBloquant("job_err", diagErr); err != nil {
			t.Fatalf("SoumettreNonBloquant inattendu: %v", err)
		}
	}
	fileErr.Fermer()
	if fileErr.TotalSoumis.Load() != 5 || fileErr.TotalErreursArbitrage.Load() != 5 || fileErr.TotalArbitres.Load() != 0 {
		t.Fatalf("comptabilite d'erreur invalide: soumis=%d erreurs=%d arbitres=%d",
			fileErr.TotalSoumis.Load(), fileErr.TotalErreursArbitrage.Load(), fileErr.TotalArbitres.Load())
	}
}

// TestRevuePowerlogCoupureHorodatage vérifie que construireEpisodesDisjoints ne fusionne
// jamais deux tranches séparées par une interruption temporelle de plusieurs heures (GPT-6-Sol C-11).
func TestRevuePowerlogCoupureHorodatage(t *testing.T) {
	var bDeg, bNom strings.Builder
	bDeg.WriteString("ts,cpu_pkg_w,cpu_pkg_temp_c,load1\n")
	bNom.WriteString("ts,cpu_pkg_w,cpu_pkg_temp_c,load1\n")
	base := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	// 30 mesures à 10h00 puis coupure de 4 heures et 30 mesures à 14h00 -> 0 épisode continu de 60 points.
	for i := range 30 {
		ts := base.Add(time.Duration(i) * time.Second).Format(time.RFC3339)
		bDeg.WriteString(ts + ",65.0,88.0,8.0\n")
	}
	for i := range 30 {
		ts := base.Add(4*time.Hour + time.Duration(i)*time.Second).Format(time.RFC3339)
		bDeg.WriteString(ts + ",65.0,88.0,8.0\n")
	}
	// Journal nominal continu de 60 points.
	for i := range 60 {
		ts := base.Add(time.Duration(i) * time.Second).Format(time.RFC3339)
		bNom.WriteString(ts + ",65.0,60.0,8.0\n")
	}

	jDeg, errD := LireJournalPuissanceCSV(strings.NewReader(bDeg.String()))
	if errD != nil {
		t.Fatalf("LireJournalPuissanceCSV deg: %v", errD)
	}
	jNom, errN := LireJournalPuissanceCSV(strings.NewReader(bNom.String()))
	if errN != nil {
		t.Fatalf("LireJournalPuissanceCSV nom: %v", errN)
	}
	cfg := ConfigPowerlogParDefaut()
	cfg.FenetreEpisode = 60
	if _, errEval := EvaluerCampagnePowerlog(jDeg, jNom, cfg); !errors.Is(errEval, ErrEchantillonVide) {
		t.Fatalf("attendu ErrEchantillonVide face a une coupure de 4h au milieu de 60 points, obtenu %v", errEval)
	}
}

// TestRevueBriefSLMEgressMineurEtObservablesNeutres vérifie que FormaterBriefCausalSLM
// n'émet ni étiquette tautologique pré-jugée (SEVERE_DISK_IO_STALL, STEADY_MONOTONIC_MEMORY_LEAK)
// ni alerte SUSPICIOUS_OUTBOUND sur un egress mineur bénin < SeuilEgressPermille (Mythos C-09/C-10, GPT-6-Sol C-02).
func TestRevueBriefSLMEgressMineurEtObservablesNeutres(t *testing.T) {
	ep := construireEpisodeReference(t, 0, 2_000_000, 100_000, 300_000, 20_000, 0, CompteursReseauEpisode{
		OctetsSortants:      400, // ~3 permille < 50 permille
		ConnexionsSortantes: 1,
		ResolutionsDNS:      1,
	})
	diag := DiagnosticEpisodeCinetique{
		Orientation:          OrientationDeriveOrganique,
		PasDeriveMonotoneRSS: 6,
		Episode:              ep,
	}
	diag.VariationsPct[IndiceDilatationHorsCPU] = 350

	var dst [512]byte
	briefOctets, err := FormaterBriefCausalSLM(dst[:0], "backup_job", diag)
	if err != nil {
		t.Fatalf("FormaterBriefCausalSLM: %v", err)
	}
	brief := string(briefOctets)
	if strings.Contains(brief, "SUSPICIOUS_OUTBOUND") {
		t.Fatalf("egress mineur (3 permille) qualifie a tort de SUSPICIOUS_OUTBOUND dans le brief:\n%s", brief)
	}
	if strings.Contains(brief, "SEVERE_DISK_IO_STALL") || strings.Contains(brief, "STEADY_MONOTONIC_MEMORY_LEAK") {
		t.Fatalf("le brief SLM contient encore des conclusions pre-digerees au lieu d'observables neutres:\n%s", brief)
	}
}

// TestRevueSentinelleProcEINTR vérifie sur de vrais tubes noyau Linux que lireFluxCompletFD
// détecte exactement la fin de flux à taille pleine, le dépassement d'un octet (ErrTamponProcSature),
// les lectures fragmentées et les erreurs noyau sans confusion de signe ^uintptr(0) (Mythos C-01, GLM C-01).
func TestRevueSentinelleProcEINTR(t *testing.T) {
	// Cas 1 : tube noyau contenant exactement 8 octets puis EOF -> lecture sentinelle lit 0 octet, succès.
	var fdsExact [2]int
	if err := unix.Pipe2(fdsExact[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("Pipe2 exact: %v", err)
	}
	defer func() { _ = unix.Close(fdsExact[0]) }()
	go func() {
		_, _ = unix.Write(fdsExact[1], []byte("1234"))
		runtime.Gosched()
		_, _ = unix.Write(fdsExact[1], []byte("567\n"))
		_ = unix.Close(fdsExact[1])
	}()
	var tampon [8]byte
	nLus, errEOF := lireFluxCompletFD(uintptr(fdsExact[0]), tampon[:])
	if errEOF != nil || nLus != 8 || string(tampon[:nLus]) != "1234567\n" {
		t.Fatalf("attendu nLus=8 sans erreur sur tube exact, obtenu n=%d err=%v contenu=%q", nLus, errEOF, string(tampon[:nLus]))
	}

	// Cas 2 : jumeau hostile : tube noyau contenant 9 octets pour un tampon de 8 -> ErrTamponProcSature.
	var fdsSature [2]int
	if err := unix.Pipe2(fdsSature[:], unix.O_CLOEXEC); err != nil {
		t.Fatalf("Pipe2 sature: %v", err)
	}
	defer func() {
		_ = unix.Close(fdsSature[0])
		_ = unix.Close(fdsSature[1])
	}()
	if _, errW := unix.Write(fdsSature[1], []byte("123456789")); errW != nil {
		t.Fatalf("Write sature: %v", errW)
	}
	_ = unix.Close(fdsSature[1])
	if _, errSat := lireFluxCompletFD(uintptr(fdsSature[0]), tampon[:]); !errors.Is(errSat, ErrTamponProcSature) {
		t.Fatalf("attendu ErrTamponProcSature sur 9 octets dans tampon[8], obtenu %v", errSat)
	}

	// Cas 3 : jumeau négatif : descripteur noyau invalide (-1) -> unix.EBADF sans panique ni faux EOF.
	if _, errBadFD := lireFluxCompletFD(^uintptr(0), tampon[:]); !errors.Is(errBadFD, unix.EBADF) {
		t.Fatalf("attendu unix.EBADF sur fd=-1, obtenu %v", errBadFD)
	}
}

// TestRevueInspecteurDNSFilaireEtJumeauBenin vérifie l'encodage RFC 1035 et l'inspection
// filaire 0 B/op des trames DNS de tunnelisation contre des requêtes bénignes et tronquées
// (GPT-6-Sol C-03/C-09, Mythos C-12/C-21, GLM C-08/C-12).
func TestRevueInspecteurDNSFilaireEtJumeauBenin(t *testing.T) {
	var tamponFil [512]byte
	// 1. Trame TXT de tunnelisation portant deux labels hexadécimaux SHA-256 (32 + 32 chars).
	nomTunnel := "9f86d081884c7d659a2feaa0c55ad015.a3bf4f1b2b0b822cd15d6c15b0f00a08.t.c2test.internal"
	trameTunnel, errT := ConstruireRequeteDNSFil(tamponFil[:0], 0x4201, nomTunnel, 16)
	if errT != nil {
		t.Fatalf("ConstruireRequeteDNSFil tunnel: %v", errT)
	}
	inspTunnel, okT := InspecterDatagrammeDNSFil(trameTunnel)
	if !okT || inspTunnel.CodeRaisonDNS == 0 || inspTunnel.LongueurMaxLabel != 32 || inspTunnel.QType != 16 {
		t.Fatalf("tunnel DNS TXT non detecte sur le fil: ok=%v insp=%+v", okT, inspTunnel)
	}

	// 2. Jumeau bénin : requête A standard vers ntp.ubuntu.com -> CodeRaisonDNS == 0.
	var tamponBenin [512]byte
	trameBenigne, errB := ConstruireRequeteDNSFil(tamponBenin[:0], 0x1001, "ntp.ubuntu.com", 1)
	if errB != nil {
		t.Fatalf("ConstruireRequeteDNSFil benin: %v", errB)
	}
	inspBenin, okB := InspecterDatagrammeDNSFil(trameBenigne)
	if !okB || inspBenin.CodeRaisonDNS != 0 {
		t.Fatalf("faux positif DNS sur ntp.ubuntu.com: ok=%v insp=%+v", okB, inspBenin)
	}

	// 3. Jumeau malformé : trame tronquée au milieu du QNAME -> ok == false.
	if _, okTronque := InspecterDatagrammeDNSFil(trameTunnel[:18]); okTronque {
		t.Fatalf("trame DNS tronquee acceptee a tort")
	}

	// 4. Budget 0 B/op sur l'inspecteur filaire.
	allocs := testing.AllocsPerRun(500, func() {
		_, ok := InspecterDatagrammeDNSFil(trameTunnel)
		if !ok {
			t.Fatal("echec inattendu")
		}
	})
	if allocs != 0 {
		t.Fatalf("InspecterDatagrammeDNSFil doit etre 0 B/op, mesure %.2f allocs/op", allocs)
	}
}

// TestRevuePowerlogCalibrationTambControleNominal vérifie que la calibration affine
// de T_repos sur le seul journal nominal élimine le biais hyperbolique (T_0 - 25)/P
// entre faible et forte charge nominale tout en séparant la vraie dégradation (Mythos C-11).
func TestRevuePowerlogCalibrationTambControleNominal(t *testing.T) {
	var bDeg, bNom strings.Builder
	bDeg.WriteString("ts,cpu_pkg_w,cpu_pkg_temp_c,load1\n")
	bNom.WriteString("ts,cpu_pkg_w,cpu_pkg_temp_c,load1\n")
	base := time.Date(2026, 10, 29, 8, 0, 0, 0, time.UTC)

	// Loi nominale saine : T(P) = 38.0 °C + 0.35 °C/W * P.
	// - À 60 W : T = 59.0 °C
	// - À 130 W : T = 83.5 °C
	for i := range 30 {
		ts := base.Add(time.Duration(i) * time.Second).Format(time.RFC3339)
		bNom.WriteString(ts + ",60.0,59.0,4.0\n")
	}
	for i := range 30 {
		ts := base.Add(time.Duration(30+i) * time.Second).Format(time.RFC3339)
		bNom.WriteString(ts + ",130.0,83.5,12.0\n")
	}
	// Régime dégradé à 60 W : T = 83.5 °C (exactement la même température brute que le nominal à 130 W !).
	for i := range 30 {
		ts := base.Add(time.Duration(i) * time.Second).Format(time.RFC3339)
		bDeg.WriteString(ts + ",60.0,83.5,4.0\n")
	}

	jDeg, errD := LireJournalPuissanceCSV(strings.NewReader(bDeg.String()))
	if errD != nil {
		t.Fatalf("jDeg: %v", errD)
	}
	jNom, errN := LireJournalPuissanceCSV(strings.NewReader(bNom.String()))
	if errN != nil {
		t.Fatalf("jNom: %v", errN)
	}

	cfg := ConfigPowerlogParDefaut()
	cfg.FenetreEpisode = 10
	bilan, errEval := EvaluerCampagnePowerlog(jDeg, jNom, cfg)
	if errEval != nil {
		t.Fatalf("EvaluerCampagnePowerlog: %v", errEval)
	}
	if !bilan.CalibrationTempReposActive || math.Abs(bilan.TemperatureReposEffectiveC-38.0) > 0.05 {
		t.Fatalf("calibration T_repos nominale inexacte: active=%v T_eff=%.3f (attendu 38.0)",
			bilan.CalibrationTempReposActive, bilan.TemperatureReposEffectiveC)
	}
	if len(bilan.ControleAutoNominalModereVsFort) != 2 {
		t.Fatalf("ControleAutoNominalModereVsFort absent")
	}
	// Contrôle négatif intra-nominal (60 W sain vs 130 W sain) : la résistance calibrée doit valoir AUC == 0.50 !
	aucAutoNom := bilan.ControleAutoNominalModereVsFort[1].AUCMannWhitney
	if math.Abs(aucAutoNom-0.5) > 1e-6 {
		t.Fatalf("biais hyperbolique residuel sur controle auto-nominal: AUC=%.4f (attendu 0.5000)", aucAutoNom)
	}
	// Tandis que la vraie dégradation (60 W dégradé vs 130 W sain, et iso-puissance 60 W vs 60 W) vaut AUC == 1.00 !
	if bilan.EpreuveConfusionForteCharge[1].AUCMannWhitney != 1.0 ||
		bilan.ComparaisonsIsoPuissance50a90W[1].AUCMannWhitney != 1.0 {
		t.Fatalf("perte de pouvoir discriminant apres calibration: stress=%+v iso=%+v",
			bilan.EpreuveConfusionForteCharge[1], bilan.ComparaisonsIsoPuissance50a90W[1])
	}
}

// TestRevueQwenQuatreClassesSansVetoEtPlafondContexte vérifie sur le modèle réel Qwen2.5-0.5B
// (lorsque C2_TEST_QWEN_GGUF est défini) :
// 1. la prédiction directe des 4 classes ("storage", "network", "memory", "normal") SANS intervention du veto ;
// 2. la reproductibilité exacte des logits entre appels successifs (zéro pollution KVCache, Mythos C-17) ;
// 3. le rejet fail-closed ErrBriefSLMTropLong sans troncature (Mythos C-18, GLM C-15).
func TestRevueQwenQuatreClassesSansVetoEtPlafondContexte(t *testing.T) {
	var tamponVide [512]byte
	for idx := range NombreSondesCalibrationSLM {
		sonde, errSq := FormaterSondeCalibrationSLM(tamponVide[:0], idx)
		if errSq != nil || !strings.Contains(string(sonde), "process: demo") {
			t.Fatalf("FormaterSondeCalibrationSLM(%d) invalide: err=%v texte=%q", idx, errSq, string(sonde))
		}
	}

	cheminModele := os.Getenv("C2_TEST_QWEN_GGUF")
	if cheminModele == "" {
		return
	}

	arbitre, errQ := NouvelArbitreQwenCinetique(cheminModele)
	if errQ != nil {
		t.Fatalf("NouvelArbitreQwenCinetique: %v", errQ)
	}
	defer func() { _ = arbitre.Fermer() }()

	// Cas 1 : "storage" (disque actif, hors-CPU prolongé, réseau nul, hôte calme).
	epStorage := construireEpisodeReference(t, 0, 8_000_000, 100_000, 45_000_000, 30_000, 100, CompteursReseauEpisode{})
	diagStorage := DiagnosticEpisodeCinetique{
		Orientation: OrientationDegradationES,
		Episode:     epStorage,
	}
	diagStorage.VariationsPct[IndiceDilatationHorsCPU] = 480

	// Cas 2 : "network" (flux UDP/53 suspect + code raison DNS).
	epNetwork := construireEpisodeReference(t, 0, 24_000_000, 100_000, 300_000, 32_000, 100, CompteursReseauEpisode{
		OctetsSortants:      32_768,
		ConnexionsSortantes: 1,
		ResolutionsDNS:      4,
		PortSuspect:         53,
		ProtocoleSuspectUDP: true,
		CodeRaisonDNS:       5,
	})
	diagNetwork := DiagnosticEpisodeCinetique{
		Orientation: OrientationCompromissionReseau,
		Episode:     epNetwork,
	}
	diagNetwork.VariationsPct[IndiceNsCPUParKioLogique] = 220

	// Cas 3 : "memory" sous hôte calme (LOW) et sous hôte chargé (HIGH, PSI > 200 permille).
	epMemory := construireEpisodeReference(t, 0, 8_000_000, 100_000, 300_000, 38_000, 100, CompteursReseauEpisode{})
	diagMemory := DiagnosticEpisodeCinetique{
		Orientation:          OrientationDeriveOrganique,
		PasDeriveMonotoneRSS: 6,
		Episode:              epMemory,
	}
	diagMemory.VariationsPct[IndiceKioPicRSSParFil] = 26

	epMemoryPSI := construireEpisodeReference(t, 0, 8_000_000, 100_000, 300_000, 38_000, 15_000, CompteursReseauEpisode{})
	diagMemoryPSI := DiagnosticEpisodeCinetique{
		Orientation:          OrientationDeriveOrganique,
		PasDeriveMonotoneRSS: 6,
		Episode:              epMemoryPSI,
	}
	diagMemoryPSI.VariationsPct[IndiceKioPicRSSParFil] = 26

	// Cas 4 : "normal" escaladé en OrientationEcartStructurel (sommeil sans E/S disque sous contention hôte).
	debutIdle := InstantaneTache{PID: 88, DebutTacheTicks: 444, HorodatageNs: 1_000_000}
	finIdle := InstantaneTache{
		PID:                     88,
		DebutTacheTicks:         444,
		HorodatageNs:            31_000_000,
		TempsExecutionNs:        2_000_000,
		AttenteFileNs:           8_000_000,
		CommutationsVolontaires: 10,
		CommutationsSubies:      20,
		VmRSSKio:                20_000,
		NombreFils:              1,
	}
	epNormal, errIdle := EvaluerEpisodeCinetique(
		debutIdle,
		finIdle,
		InstantanePressionPSI{HorodatageNs: 1_000_000},
		InstantanePressionPSI{HorodatageNs: 31_000_000, CPUSomeTotalUs: 12_000},
		CompteursReseauEpisode{OctetsSortants: 200, ConnexionsSortantes: 1, ResolutionsDNS: 1},
		TopologieHybride{},
		ConfigPlanchersParDefaut(),
	)
	if errIdle != nil {
		t.Fatalf("epNormal: %v", errIdle)
	}
	diagNormal := DiagnosticEpisodeCinetique{
		Orientation: OrientationEcartStructurel,
		Episode:     epNormal,
	}
	diagNormal.VariationsPct[IndiceDilatationHorsCPU] = 310

	// Noms d'exécutables volontairement neutres ou adversariaux (ex. "storage_sync" sur un cas mémoire)
	// afin de prouver l'absence totale de fuite lexicale par le nom du binaire.
	cas := []struct {
		nom     string
		diag    DiagnosticEpisodeCinetique
		attendu string
	}{
		{"daemon_alpha", diagStorage, VerdictSLMDegradationMaterielle},
		{"daemon_beta", diagNetwork, VerdictSLMCompromissionExfil},
		{"storage_sync_ trompeur", diagMemory, VerdictSLMDeriveOrganique},
		{"daemon_gamma_psi", diagMemoryPSI, VerdictSLMDeriveOrganique},
		{"daemon_delta", diagNormal, VerdictSLMContentionOuInsuff},
	}

	var logitsPremierStorage [4]float32
	for i, c := range cas {
		dec, errA := arbitre.ArbitrerEpisode(t.Context(), c.nom, c.diag)
		if errA != nil {
			t.Fatalf("ArbitrerEpisode(%s): %v", c.nom, errA)
		}
		if dec.VerdictBrutModele != c.attendu || dec.VerdictFinal != c.attendu || dec.VetoPhysiqueApplique {
			t.Errorf("classe %s: attendu verdict brut=final=%s sans veto, obtenu brut=%s final=%s veto=%v (%s)\nlogits=%v biais=%v delta=%v\nbrief:\n%s",
				c.nom, c.attendu, dec.VerdictBrutModele, dec.VerdictFinal, dec.VetoPhysiqueApplique, dec.MotifVeto,
				dec.LogitsBrutsModele, dec.BiaisNeutreModele, dec.DeltaLogitsModele, dec.DifferentielTransmis)
		}
		var sommeBrute, sommeCal float32
		for k := range 4 {
			sommeBrute += dec.ProbabilitesBrutes[k]
			sommeCal += dec.Probabilites[k]
		}
		if math.Abs(float64(sommeBrute)-1.0) > 1e-3 || math.Abs(float64(sommeCal)-1.0) > 1e-3 {
			t.Fatalf("sommes softmax invalides (%s): brute=%f cal=%f", c.nom, sommeBrute, sommeCal)
		}
		if i == 0 {
			logitsPremierStorage = dec.LogitsBrutsModele
		}
	}

	// Re-évaluation de daemon_alpha après 3 autres tours : les logits doivent être identiques (rembobinage KVCache exact).
	decRejeu, errRejeu := arbitre.ArbitrerEpisode(t.Context(), "daemon_alpha", diagStorage)
	if errRejeu != nil {
		t.Fatalf("ArbitrerEpisode rejeu: %v", errRejeu)
	}
	if decRejeu.LogitsBrutsModele != logitsPremierStorage {
		t.Fatalf("derive du KVCache entre deux appels identiques: avant=%v apres=%v",
			logitsPremierStorage, decRejeu.LogitsBrutsModele)
	}

	// Garde fail-closed anti-troncature (OBJET-INTEGRAL-001) lorsque le plafond de contexte est dépassé.
	sauvegardePlafond := arbitre.plafondTokensTour
	arbitre.plafondTokensTour = 4
	_, errTropLong := arbitre.ArbitrerEpisode(t.Context(), "job_storage", diagStorage)
	arbitre.plafondTokensTour = sauvegardePlafond
	if !errors.Is(errTropLong, ErrBriefSLMTropLong) {
		t.Fatalf("attendu ErrBriefSLMTropLong sur depassement de contexte, obtenu %v", errTropLong)
	}
}

func construireEpisodeReference(
	t *testing.T,
	coeur int32,
	execNs, attenteNs, horsCPUNs, rssKio, psiCPUUs uint64,
	reseau CompteursReseauEpisode,
) QuotientsEpisode {
	t.Helper()
	debut := InstantaneTache{
		PID:                    1000,
		DebutTacheTicks:        12345,
		HorodatageNs:           1_000_000,
		CoeurDerniereExecution: coeur,
	}
	fin := InstantaneTache{
		PID:                     1000,
		DebutTacheTicks:         12345,
		HorodatageNs:            1_000_000 + int64(execNs+attenteNs+horsCPUNs),
		CoeurDerniereExecution:  coeur,
		TempsExecutionNs:        execNs,
		AttenteFileNs:           attenteNs,
		OctetsLusLogiques:       131_072,
		OctetsEcritsLogiques:    131_072,
		AppelsLecture:           32,
		AppelsEcriture:          32,
		OctetsEcritsBloc:        131_072,
		CommutationsVolontaires: 16,
		CommutationsSubies:      2,
		VmHWMKio:                rssKio,
		VmRSSKio:                rssKio,
		NombreFils:              1,
	}
	psiDebut := InstantanePressionPSI{HorodatageNs: debut.HorodatageNs}
	psiFin := InstantanePressionPSI{
		HorodatageNs:   fin.HorodatageNs,
		CPUSomeTotalUs: psiCPUUs,
	}
	ep, err := EvaluerEpisodeCinetique(debut, fin, psiDebut, psiFin, reseau, TopologieHybride{}, ConfigPlanchersParDefaut())
	if err != nil {
		t.Fatalf("EvaluerEpisodeCinetique: %v", err)
	}
	return ep
}
