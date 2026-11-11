//go:build linux

package cinetique_test

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55/internal/cinetique"
	"golang.org/x/sys/unix"
)

const exempleStatComplexe = "4242 (agent (c2) furtif) S 1 4242 4242 0 -1 4194304 512 0 3 0 140 60 0 0 20 0 4 0 9876543 16777216 2048 18446744073709551615 1 2 3 0 0 0 0 0 0 0 0 0 17 18 0 0 0 0 0 1 2 3 4 5 6 7 0\n"

const exempleSchedstat = "25000000 1250000 80\n"

const exempleStatus = "Name:\tagent\nVmHWM:\t   32768 kB\nVmRSS:\t   28672 kB\nThreads:\t4\nvoluntary_ctxt_switches:\t120\nnonvoluntary_ctxt_switches:\t30\n"

const exempleIO = "rchar: 262144\nwchar: 131072\nsyscr: 64\nsyscw: 32\nread_bytes: 65536\nwrite_bytes: 131072\ncancelled_write_bytes: 0\n"

const exemplePSI = "some avg10=12.34 avg60=5.10 avg300=2.00 total=450000\nfull avg10=0.50 avg60=0.10 avg300=0.00 total=12000\n"

func TestAnalyseursProcEtJumeauxHostiles(t *testing.T) {
	var snap cinetique.InstantaneTache
	if err := cinetique.AnalyserStatProc([]byte(exempleStatComplexe), &snap); err != nil {
		t.Fatalf("AnalyserStatProc nominal: %v", err)
	}
	if snap.PID != 4242 || snap.FautesMineures != 512 || snap.FautesMajeures != 3 ||
		snap.UtilisateurTicks != 140 || snap.SystemeTicks != 60 || snap.NombreFils != 4 ||
		snap.DebutTacheTicks != 9876543 || snap.CoeurDerniereExecution != 18 {
		t.Fatalf("champs stat inattendus: %+v", snap)
	}

	if err := cinetique.AnalyserSchedstatProc([]byte(exempleSchedstat), &snap); err != nil {
		t.Fatalf("AnalyserSchedstatProc nominal: %v", err)
	}
	if snap.TempsExecutionNs != 25_000_000 || snap.AttenteFileNs != 1_250_000 || snap.TranchesOrdonnanceur != 80 {
		t.Fatalf("champs schedstat inattendus: %+v", snap)
	}

	if err := cinetique.AnalyserStatusProc([]byte(exempleStatus), &snap); err != nil {
		t.Fatalf("AnalyserStatusProc nominal: %v", err)
	}
	if snap.VmHWMKio != 32768 || snap.VmRSSKio != 28672 || snap.CommutationsVolontaires != 120 || snap.CommutationsSubies != 30 {
		t.Fatalf("champs status inattendus: %+v", snap)
	}

	if err := cinetique.AnalyserIOProc([]byte(exempleIO), &snap); err != nil {
		t.Fatalf("AnalyserIOProc nominal: %v", err)
	}
	if snap.OctetsLusLogiques != 262144 || snap.OctetsEcritsLogiques != 131072 ||
		snap.AppelsLecture != 64 || snap.AppelsEcriture != 32 ||
		snap.OctetsLusBloc != 65536 || snap.OctetsEcritsBloc != 131072 {
		t.Fatalf("champs io inattendus: %+v", snap)
	}

	someTot, fullTot, avg10, errPSI := cinetique.AnalyserFichierPSI([]byte(exemplePSI))
	if errPSI != nil {
		t.Fatalf("AnalyserFichierPSI nominal: %v", errPSI)
	}
	if someTot != 450_000 || fullTot != 12_000 || avg10 != 1234 {
		t.Fatalf("champs PSI inattendus: some=%d full=%d avg10=%d", someTot, fullTot, avg10)
	}

	// Jumeaux hostiles : troncature sans '\n' final (OBJET-INTEGRAL-001).
	sansFinLigne := strings.TrimSuffix(exempleStatComplexe, "\n")
	if err := cinetique.AnalyserStatProc([]byte(sansFinLigne), &snap); !errors.Is(err, cinetique.ErrTamponProcSature) {
		t.Fatalf("attendu ErrTamponProcSature sur stat tronque, obtenu %v", err)
	}
	if err := cinetique.AnalyserSchedstatProc([]byte("10 20 30"), &snap); !errors.Is(err, cinetique.ErrTamponProcSature) {
		t.Fatalf("attendu ErrTamponProcSature sur schedstat tronque, obtenu %v", err)
	}
	if err := cinetique.AnalyserStatusProc([]byte("VmRSS:\t100 kB"), &snap); !errors.Is(err, cinetique.ErrTamponProcSature) {
		t.Fatalf("attendu ErrTamponProcSature sur status tronque, obtenu %v", err)
	}
	if err := cinetique.AnalyserIOProc([]byte("rchar: 10"), &snap); !errors.Is(err, cinetique.ErrTamponProcSature) {
		t.Fatalf("attendu ErrTamponProcSature sur io tronque, obtenu %v", err)
	}
	if _, _, _, err := cinetique.AnalyserFichierPSI([]byte("some avg10=1.00 total=5")); !errors.Is(err, cinetique.ErrTamponProcSature) {
		t.Fatalf("attendu ErrTamponProcSature sur PSI tronque, obtenu %v", err)
	}

	// Jumeaux hostiles : contenu incomplet mais terminé par '\n'.
	if err := cinetique.AnalyserIOProc([]byte("rchar: 10\nwchar: 20\n"), &snap); !errors.Is(err, cinetique.ErrFormatIOInvalide) {
		t.Fatalf("attendu ErrFormatIOInvalide sur io incomplet, obtenu %v", err)
	}

	coeurs, masque, errCPU := cinetique.AnalyserListeCPUs("0-7,10-15\n")
	if errCPU != nil || len(coeurs) != 14 || masque != 0xFCFF {
		t.Fatalf("AnalyserListeCPUs inattendu: n=%d masque=0x%X err=%v", len(coeurs), masque, errCPU)
	}
	if _, _, err := cinetique.AnalyserListeCPUs("7-3"); !errors.Is(err, cinetique.ErrListeCPUInvalide) {
		t.Fatalf("attendu ErrListeCPUInvalide sur intervalle inverse, obtenu %v", err)
	}
}

func TestGardesMonotonieEtReutilisationPID(t *testing.T) {
	cfg := cinetique.ConfigPlanchersParDefaut()
	topo := cinetique.TopologieHybride{MasquePerformance: 0xFF, MasqueEfficience: 0xFF00, EstHybride: true}

	debut := cinetique.InstantaneTache{
		PID:                    1050,
		HorodatageNs:           1_000_000_000,
		DebutTacheTicks:        555_000,
		CoeurDerniereExecution: 2,
		TempsExecutionNs:       10_000_000,
		AttenteFileNs:          500_000,
		OctetsLusLogiques:      100_000,
		OctetsEcritsLogiques:   50_000,
		AppelsLecture:          25,
		AppelsEcriture:         10,
		VmHWMKio:               16_384,
		NombreFils:             2,
	}
	finMemePIDAutreNaissance := debut
	finMemePIDAutreNaissance.HorodatageNs = 2_000_000_000
	finMemePIDAutreNaissance.DebutTacheTicks = 555_001

	if _, err := cinetique.EvaluerEpisodeCinetique(debut, finMemePIDAutreNaissance, cinetique.InstantanePressionPSI{}, cinetique.InstantanePressionPSI{}, cinetique.CompteursReseauEpisode{}, topo, cfg); !errors.Is(err, cinetique.ErrReutilisationPID) {
		t.Fatalf("attendu ErrReutilisationPID, obtenu %v", err)
	}

	finHorlogeInverse := debut
	if _, err := cinetique.EvaluerEpisodeCinetique(debut, finHorlogeInverse, cinetique.InstantanePressionPSI{}, cinetique.InstantanePressionPSI{}, cinetique.CompteursReseauEpisode{}, topo, cfg); !errors.Is(err, cinetique.ErrHorlogeNonMonotone) {
		t.Fatalf("attendu ErrHorlogeNonMonotone, obtenu %v", err)
	}

	finCompteurRecule := debut
	finCompteurRecule.HorodatageNs = 2_000_000_000
	finCompteurRecule.OctetsLusLogiques = 99_999
	if _, err := cinetique.EvaluerEpisodeCinetique(debut, finCompteurRecule, cinetique.InstantanePressionPSI{}, cinetique.InstantanePressionPSI{}, cinetique.CompteursReseauEpisode{}, topo, cfg); !errors.Is(err, cinetique.ErrCompteurNonMonotone) {
		t.Fatalf("attendu ErrCompteurNonMonotone, obtenu %v", err)
	}

	// Épisode quasi-inactif sous tous les planchers : seul le pic RSS (>0) est valide.
	finRepos := debut
	finRepos.HorodatageNs = 2_000_000_000
	epRepos, errRepos := cinetique.EvaluerEpisodeCinetique(debut, finRepos, cinetique.InstantanePressionPSI{}, cinetique.InstantanePressionPSI{}, cinetique.CompteursReseauEpisode{}, topo, cfg)
	if errRepos != nil {
		t.Fatalf("EvaluerEpisodeCinetique repos: %v", errRepos)
	}
	if epRepos.EstValide(cinetique.IndiceOctetsParAppelES) || epRepos.EstValide(cinetique.IndiceDilatationHorsCPU) {
		t.Fatalf("quotients inactifs ne doivent pas etre marques valides: masque=0x%X", epRepos.MasqueValidite)
	}
	if !epRepos.EstValide(cinetique.IndiceKioPicRSSParFil) || epRepos.Valeurs[cinetique.IndiceKioPicRSSParFil] != 8192 {
		t.Fatalf("KioPicRSSParFil inattendu: %+v", epRepos)
	}

	// Test arithmétique 128 bits sans débordement sur pétaoctets.
	finGeant := debut
	finGeant.HorodatageNs = 10_000_000_000
	finGeant.TempsExecutionNs = debut.TempsExecutionNs + 4_000_000_000
	finGeant.OctetsLusLogiques = debut.OctetsLusLogiques + (uint64(1) << 52)
	finGeant.OctetsEcritsLogiques = debut.OctetsEcritsLogiques + (uint64(1) << 52)
	finGeant.AppelsLecture = debut.AppelsLecture + (uint64(1) << 40)
	finGeant.AppelsEcriture = debut.AppelsEcriture + (uint64(1) << 40)
	epGeant, errGeant := cinetique.EvaluerEpisodeCinetique(debut, finGeant, cinetique.InstantanePressionPSI{}, cinetique.InstantanePressionPSI{}, cinetique.CompteursReseauEpisode{}, topo, cfg)
	if errGeant != nil {
		t.Fatalf("EvaluerEpisodeCinetique geant: %v", errGeant)
	}
	if epGeant.Valeurs[cinetique.IndicePartEcriturePermille] != 500 || epGeant.Valeurs[cinetique.IndiceOctetsParAppelES] != 4096 {
		t.Fatalf("calcul 128 bits inexact: partEcr=%d tailleES=%d",
			epGeant.Valeurs[cinetique.IndicePartEcriturePermille],
			epGeant.Valeurs[cinetique.IndiceOctetsParAppelES])
	}
}

func construireEpisodeReference(
	dureeHorlogeNs uint64,
	execNs uint64,
	attenteNs uint64,
	picRSSKio uint64,
	coeurDebut, coeurFin int32,
	pressionCPUUs uint64,
	reseau cinetique.CompteursReseauEpisode,
) (cinetique.QuotientsEpisode, error) {
	topo := cinetique.TopologieHybride{
		MasquePerformance: 0x00FF,
		MasqueEfficience:  0xFF00,
		EstHybride:        true,
	}
	debut := cinetique.InstantaneTache{
		PID:                     9001,
		HorodatageNs:            1_000_000_000,
		DebutTacheTicks:         77777,
		CoeurDerniereExecution:  coeurDebut,
		VmHWMKio:                picRSSKio,
		VmRSSKio:                picRSSKio,
		NombreFils:              1,
		CommutationsVolontaires: 100,
		CommutationsSubies:      10,
	}
	fin := debut
	fin.HorodatageNs = debut.HorodatageNs + int64(dureeHorlogeNs)
	fin.CoeurDerniereExecution = coeurFin
	fin.TempsExecutionNs = execNs
	fin.AttenteFileNs = attenteNs
	fin.OctetsLusLogiques = 131_072
	fin.OctetsEcritsLogiques = 131_072
	fin.AppelsLecture = 32
	fin.AppelsEcriture = 32
	fin.OctetsLusBloc = 0
	fin.OctetsEcritsBloc = 131_072
	fin.CommutationsVolontaires = 132
	fin.CommutationsSubies = 12

	psiDebut := cinetique.InstantanePressionPSI{HorodatageNs: debut.HorodatageNs, CPUSomeTotalUs: 10_000}
	psiFin := cinetique.InstantanePressionPSI{HorodatageNs: fin.HorodatageNs, CPUSomeTotalUs: 10_000 + pressionCPUUs}
	return cinetique.EvaluerEpisodeCinetique(debut, fin, psiDebut, psiFin, reseau, topo, cinetique.ConfigPlanchersParDefaut())
}

func TestOrientationArchetypesEtAbstentionPSI(t *testing.T) {
	cfg := cinetique.ConfigProfilParDefaut()
	cfg.MinEpisodesAmorcage = 8
	table := cinetique.NouvelleTableProfilsCinetiques(cfg)
	cleBin := cinetique.HashIdentifiantBinaire("/usr/local/bin/sauvegarde_quotidienne")

	// 1. Amorçage de 8 épisodes nominaux stables (~10 ms wall, 8 ms CPU, 0.2 ms runqueue, 1.8 ms I/O).
	for i := range 8 {
		variationInfime := uint64((i % 3) * 20_000)
		ep, err := construireEpisodeReference(
			10_000_000+variationInfime,
			8_000_000+variationInfime/2,
			200_000,
			30_000,
			2, 2,
			100, // 1 % PSI CPU
			cinetique.CompteursReseauEpisode{},
		)
		if err != nil {
			t.Fatalf("episode amorcage %d: %v", i, err)
		}
		diag := table.ObserverEpisode(cleBin, uint64(i+1)*1_000_000, ep)
		if diag.Orientation != cinetique.OrientationAmorcage {
			t.Fatalf("episode %d attendu AMORCAGE, obtenu %s", i, diag.Orientation)
		}
	}

	// 2. Épisode nominal après amorçage.
	epNominal, err := construireEpisodeReference(10_020_000, 8_010_000, 200_000, 30_000, 2, 2, 100, cinetique.CompteursReseauEpisode{})
	if err != nil {
		t.Fatalf("epNominal: %v", err)
	}
	diagNominal := table.ObserverEpisode(cleBin, 9_000_000, epNominal)
	if diagNominal.Orientation != cinetique.OrientationNominale {
		t.Fatalf("attendu NOMINAL, obtenu %s", diagNominal.Orientation)
	}

	// 3. Voisin bruyant (PSI CPU = 45 % > 20 %) dilatant l'épisode : abstention obligatoire.
	epPression, err := construireEpisodeReference(35_000_000, 8_000_000, 12_000_000, 30_000, 2, 2, 15_750, cinetique.CompteursReseauEpisode{})
	if err != nil {
		t.Fatalf("epPression: %v", err)
	}
	diagPression := table.ObserverEpisode(cleBin, 10_000_000, epPression)
	if diagPression.Orientation != cinetique.OrientationAbstention {
		t.Fatalf("attendu ABSTENTION sous forte pression PSI CPU, obtenu %s", diagPression.Orientation)
	}

	// 4. Migration hybride P-core (2) -> E-core (9) ralentissant le CPU : abstention obligatoire.
	epMigration, err := construireEpisodeReference(22_000_000, 18_000_000, 200_000, 30_000, 2, 9, 100, cinetique.CompteursReseauEpisode{})
	if err != nil {
		t.Fatalf("epMigration: %v", err)
	}
	diagMigration := table.ObserverEpisode(cleBin, 11_000_000, epMigration)
	if diagMigration.Orientation != cinetique.OrientationAbstention {
		t.Fatalf("attendu ABSTENTION sur migration P->E, obtenu %s", diagMigration.Orientation)
	}

	// 5. Archétype A : dégradation stockage (même CPU 8 ms, même écriture 128 Kio, runqueue 0.2 ms, mais horloge 50 ms -> dilatation hors-CPU x23).
	epDisqueLent, err := construireEpisodeReference(50_000_000, 8_000_000, 200_000, 30_000, 2, 2, 100, cinetique.CompteursReseauEpisode{})
	if err != nil {
		t.Fatalf("epDisqueLent: %v", err)
	}
	diagDisque := table.ObserverEpisode(cleBin, 12_000_000, epDisqueLent)
	if diagDisque.Orientation != cinetique.OrientationDegradationES {
		t.Fatalf("attendu DEGRADATION_MATERIELLE_ES, obtenu %s", diagDisque.Orientation)
	}

	// 6. Archétype B : compromission / exfiltration UDP/53 (RAM +45%, CPU x3, egress DNS hostile), même sous forte pression PSI !
	epCompromis, err := construireEpisodeReference(
		34_000_000,
		26_000_000,
		200_000,
		43_500,
		2, 2,
		15_000, // PSI élevée : ne doit PAS masquer une compromission réseau/DNS !
		cinetique.CompteursReseauEpisode{
			OctetsSortants:      32_768,
			ConnexionsSortantes: 1,
			ResolutionsDNS:      12,
			PortSuspect:         53,
			ProtocoleSuspectUDP: true,
			CodeRaisonDNS:       4,
		},
	)
	if err != nil {
		t.Fatalf("epCompromis: %v", err)
	}
	diagCompromis := table.ObserverEpisode(cleBin, 13_000_000, epCompromis)
	if diagCompromis.Orientation != cinetique.OrientationCompromissionReseau {
		t.Fatalf("attendu COMPROMISSION_OU_EXFILTRATION, obtenu %s", diagCompromis.Orientation)
	}

	var tamponTropPetit [24]byte
	if _, errCourt := cinetique.FormaterDifferentielEpisode(tamponTropPetit[:0], "backup_job", diagCompromis); !errors.Is(errCourt, cinetique.ErrTamponTropCourt) {
		t.Fatalf("attendu ErrTamponTropCourt, obtenu %v", errCourt)
	}

	var tamponComplet [384]byte
	jeton, errFmt := cinetique.FormaterDifferentielEpisode(tamponComplet[:0], "backup_job", diagCompromis)
	if errFmt != nil {
		t.Fatalf("FormaterDifferentielEpisode: %v", errFmt)
	}
	texteJeton := string(jeton)
	if !strings.Contains(texteJeton, "ORIENTATION=COMPROMISSION_OU_EXFILTRATION") ||
		!strings.Contains(texteJeton, "SOCKET=UDP/53") ||
		!strings.Contains(texteJeton, "RAISON_DNS=4") {
		t.Fatalf("jeton differentiel incomplet: %s", texteJeton)
	}

	// 7. Archétype C : dérive organique monotone douce (+200 Kio par épisode sur 5 épisodes, sous le seuil brutal de +35 %).
	for pas := 1; pas <= 5; pas++ {
		epDerive, errD := construireEpisodeReference(
			10_010_000,
			8_005_000,
			200_000,
			30_000+uint64(pas*200),
			2, 2,
			100,
			cinetique.CompteursReseauEpisode{},
		)
		if errD != nil {
			t.Fatalf("epDerive %d: %v", pas, errD)
		}
		diagDerive := table.ObserverEpisode(cleBin, uint64(20+pas)*1_000_000, epDerive)
		if pas == 5 && diagDerive.Orientation != cinetique.OrientationDeriveOrganique {
			t.Fatalf("attendu DERIVE_ORGANIQUE_MONOTONE au pas 5, obtenu %s", diagDerive.Orientation)
		}
	}
}

func TestZeroAllocationCheminChaudEtCapteurLinux(t *testing.T) {
	octetsStat := []byte(exempleStatComplexe)
	octetsSched := []byte(exempleSchedstat)
	octetsStatus := []byte(exempleStatus)
	octetsIO := []byte(exempleIO)
	octetsPSI := []byte(exemplePSI)

	var snap cinetique.InstantaneTache
	allocsParseurs := testing.AllocsPerRun(1000, func() {
		if err := cinetique.AnalyserStatProc(octetsStat, &snap); err != nil {
			t.Fatal(err)
		}
		if err := cinetique.AnalyserSchedstatProc(octetsSched, &snap); err != nil {
			t.Fatal(err)
		}
		if err := cinetique.AnalyserStatusProc(octetsStatus, &snap); err != nil {
			t.Fatal(err)
		}
		if err := cinetique.AnalyserIOProc(octetsIO, &snap); err != nil {
			t.Fatal(err)
		}
		if _, _, _, err := cinetique.AnalyserFichierPSI(octetsPSI); err != nil {
			t.Fatal(err)
		}
	})
	if allocsParseurs != 0 {
		t.Fatalf("les parseurs /proc doivent etre 0 B/op, mesure %.2f allocs/op", allocsParseurs)
	}

	capteur, errCap := cinetique.OuvrirCapteurProcLinux()
	if errCap != nil {
		t.Fatalf("OuvrirCapteurProcLinux: %v", errCap)
	}
	defer func() { _ = capteur.Fermer() }()

	pid := os.Getpid()
	tid := unix.Gettid()
	allocsCapteurNoyau := testing.AllocsPerRun(500, func() {
		if _, err := capteur.LireInstantaneFil(pid, tid, 100); err != nil {
			t.Fatal(err)
		}
		if _, err := capteur.LirePressionPSI(100); err != nil {
			t.Fatal(err)
		}
	})
	if allocsCapteurNoyau != 0 {
		t.Fatalf("LireInstantaneFil + LirePressionPSI doivent etre 0 B/op, mesure %.2f allocs/op", allocsCapteurNoyau)
	}

	table := cinetique.NouvelleTableProfilsCinetiques(cinetique.ConfigProfilParDefaut())
	cle := cinetique.HashIdentifiantBinaire("service_critique")
	topo := cinetique.TopologieHybride{MasquePerformance: 0xFF, EstHybride: false}
	cfgPlanchers := cinetique.ConfigPlanchersParDefaut()
	debut := snap
	debut.HorodatageNs = 1_000_000
	fin := snap
	fin.HorodatageNs = 9_000_000
	fin.TempsExecutionNs += 5_000_000
	fin.OctetsLusLogiques += 65_536
	fin.OctetsEcritsLogiques += 65_536
	fin.AppelsLecture += 16
	fin.AppelsEcriture += 16
	var psiVide cinetique.InstantanePressionPSI
	var reseauVide cinetique.CompteursReseauEpisode
	var tamponDiff [384]byte

	allocsMoteur := testing.AllocsPerRun(1000, func() {
		ep, err := cinetique.EvaluerEpisodeCinetique(debut, fin, psiVide, psiVide, reseauVide, topo, cfgPlanchers)
		if err != nil {
			t.Fatal(err)
		}
		diag := table.ObserverEpisode(cle, uint64(fin.HorodatageNs), ep)
		if _, err := cinetique.FormaterDifferentielEpisode(tamponDiff[:0], "service_critique", diag); err != nil {
			t.Fatal(err)
		}
	})
	if allocsMoteur != 0 {
		t.Fatalf("EvaluerEpisodeCinetique + ObserverEpisode + FormaterDifferentielEpisode doivent etre 0 B/op, mesure %.2f allocs/op", allocsMoteur)
	}
}

func TestBancInvarianceHybrideReel(t *testing.T) {
	debutTest := time.Now()
	const tentativesBancMax = 20
	var rapport cinetique.RapportInvarianceHybride
	var preuveControleDerniere cinetique.PreuveArchetypeReel
	var preuveAmorcageDerniere cinetique.PreuveArchetypeReel
	var aEuAmorcageDernier bool
	tentativeJugeable := false
	for tentative := 1; tentative <= tentativesBancMax && !tentativeJugeable; tentative++ {
		rapportTentative, err := cinetique.ExecuterBancInvarianceHybride(t.TempDir(), 8)
		if err != nil {
			t.Fatalf("ExecuterBancInvarianceHybride (tentative %d/%d): %v", tentative, tentativesBancMax, err)
		}
		if len(rapportTentative.Quotients) != cinetique.NombreQuotientsEpisode {
			t.Fatalf("tentative %d/%d : attendu %d quotients, obtenu %d", tentative, tentativesBancMax, cinetique.NombreQuotientsEpisode, len(rapportTentative.Quotients))
		}
		if len(rapportTentative.PreuvesArchetypesReels) != 3 {
			t.Fatalf("tentative %d/%d : attendu 3 preuves d'archetypes reels, obtenu %d", tentative, tentativesBancMax, len(rapportTentative.PreuvesArchetypesReels))
		}
		preuveControleDerniere = rapportTentative.PreuvesArchetypesReels[0]
		// D-C2B-L1-08 : sur une machine chargée, le contrôle nominal peut s'abstenir
		// à bon droit quand l'épisode a été disputé au processeur alors que la pression
		// PSI moyenne reste sous le seuil ; de même, une preuve restée en AMORCAGE_PROFIL
		// signale un profil qui n'a rendu aucun jugement. Une telle tentative ne prouve
		// rien sur les autres scénarios : elle est consignée puis le banc est rejoué.
		aEuAmorcageDernier = false
		for idxPreuve := range rapportTentative.PreuvesArchetypesReels {
			if rapportTentative.PreuvesArchetypesReels[idxPreuve].Orientation == "AMORCAGE_PROFIL" {
				preuveAmorcageDerniere = rapportTentative.PreuvesArchetypesReels[idxPreuve]
				aEuAmorcageDernier = true
			}
		}
		controleConforme := preuveControleDerniere.Orientation == "NOMINAL" ||
			preuveControleDerniere.Orientation == "ABSTENTION_CONTENTION_OU_MIGRATION"
		if !controleConforme || aEuAmorcageDernier {
			t.Logf("tentative %d/%d non jugeable : controle=%s (duree=%dus attente_file=%dus pression=%d‰) amorcage_profil=%v (%s), banc rejoue",
				tentative, tentativesBancMax, preuveControleDerniere.Orientation,
				preuveControleDerniere.DureeHorlogeUs, preuveControleDerniere.AttenteFileUs,
				preuveControleDerniere.PressionCPUPermille, aEuAmorcageDernier, preuveAmorcageDerniere.Scenario)
			continue
		}
		rapport = rapportTentative
		tentativeJugeable = true
	}
	if !tentativeJugeable {
		t.Fatalf("aucune tentative jugeable apres %d tentatives : dernier controle %+v ; derniere preuve AMORCAGE_PROFIL %+v", tentativesBancMax, preuveControleDerniere, preuveAmorcageDerniere)
	}

	// Les quotients purement logiques (taille d'appel E/S incluant l'auto-lecture /proc
	// dont la représentation décimale varie de 1 octet entre coeur #1 et coeur #16,
	// et part d'écriture) doivent demeurer invariants (dérive <= 1 permille, MADM <= 1).
	qTaille := rapport.Quotients[cinetique.IndiceOctetsParAppelES]
	qPartEcr := rapport.Quotients[cinetique.IndicePartEcriturePermille]
	if qTaille.MedianeCore < 3000 || qTaille.MADMCore > 1 || qTaille.MADMAtom > 1 || qTaille.DeriveInterCoeursPermille > 1 {
		t.Fatalf("invariance violee sur octets_par_appel_es: %+v", qTaille)
	}
	if qPartEcr.MedianeCore < 490 || qPartEcr.MADMCore > 1 || qPartEcr.MADMAtom > 1 || qPartEcr.DeriveInterCoeursPermille > 1 {
		t.Fatalf("invariance violee sur part_ecriture_permille: %+v", qPartEcr)
	}

	if len(rapport.PreuvesArchetypesReels) != 3 {
		t.Fatalf("attendu 3 preuves d'archetypes reels, obtenu %d", len(rapport.PreuvesArchetypesReels))
	}
	if rapport.PreuvesArchetypesReels[0].Orientation != "NOMINAL" &&
		rapport.PreuvesArchetypesReels[0].Orientation != "ABSTENTION_CONTENTION_OU_MIGRATION" {
		t.Fatalf("controle nominal attendu NOMINAL ou ABSTENTION sous charge hote, obtenu %+v", rapport.PreuvesArchetypesReels[0])
	}
	preuveBarriere := rapport.PreuvesArchetypesReels[1]
	if preuveBarriere.PressionCPUPermille <= 200 {
		// D-C2B-L1-08 : la dispute du processeur se lit dans la preuve elle-même ;
		// quand l'épisode barrière a subi une attente en file dominante alors que la
		// pression PSI moyenne reste sous le seuil, l'abstention du profil est admise.
		if preuveBarriere.AttenteFileDominante() {
			if preuveBarriere.Orientation != "DEGRADATION_MATERIELLE_ES" &&
				preuveBarriere.Orientation != "ABSTENTION_CONTENTION_OU_MIGRATION" {
				t.Fatalf("scenario barriere fdatasync x32 hors surcharge PSI avec attente en file dominante attendu DEGRADATION_MATERIELLE_ES ou ABSTENTION, obtenu %+v", preuveBarriere)
			}
		} else if preuveBarriere.Orientation != "DEGRADATION_MATERIELLE_ES" {
			t.Fatalf("scenario barriere fdatasync x32 hors surcharge PSI sans attente dominante attendu DEGRADATION_MATERIELLE_ES, obtenu %+v", preuveBarriere)
		}
	} else if preuveBarriere.Orientation != "ABSTENTION_CONTENTION_OU_MIGRATION" {
		t.Fatalf("scenario barriere sous surcharge PSI (%d‰) attendu ABSTENTION, obtenu %+v", preuveBarriere.PressionCPUPermille, preuveBarriere)
	}
	if rapport.PreuvesArchetypesReels[2].Orientation != "COMPROMISSION_OU_EXFILTRATION" {
		t.Fatalf("scenario greffe CPU+UDP attendu COMPROMISSION_OU_EXFILTRATION, obtenu %+v", rapport.PreuvesArchetypesReels[2])
	}
	t.Logf("Banc hybride reel execute en %s : core=%d(obs=%d) atom=%d(obs=%d) derive_cpu_kio=%d‰ barriere=%s",
		time.Since(debutTest).Round(time.Millisecond),
		rapport.CoeurPerformanceTeste, rapport.CoeurObserveFinCore,
		rapport.CoeurEfficienceTeste, rapport.CoeurObserveFinAtom,
		rapport.Quotients[cinetique.IndiceNsCPUParKioLogique].DeriveInterCoeursPermille,
		rapport.PreuvesArchetypesReels[1].Orientation,
	)
}

func TestEvaluationPowerlogQuarantaineEtROCExacte(t *testing.T) {
	// Schéma 12 colonnes incluant 2 lignes "Nodeviceswerefound" (7 champs) en quarantaine
	// et des mesures réelles de régime dégradé (60 W -> 88 °C) contre un schéma 23 colonnes
	// en régime nominal incluant une forte charge (140 W -> 88 °C) pour éprouver la confusion.
	var csvDegrade strings.Builder
	csvDegrade.WriteString("ts,gpu_w,gpu_limit_w,gpu_temp_c,gpu_util_pct,gpu_mem_mib,gpu_sm_mhz,cpu_pkg_w,cpu_core_w,cpu_pkg_temp_c,cpu_core_max_c,load1\n")
	csvDegrade.WriteString("2026-10-28T21:44:27.750Z,Nodeviceswerefound,57.0,55.7,91,91,2.10\n")
	csvDegrade.WriteString("2026-10-28T21:44:28.860Z,Nodeviceswerefound,56.9,55.6,89,93,2.17\n")
	for range 24 {
		csvDegrade.WriteString("2026-10-28T20:00:00.000Z,45.0,450.0,55,1,300,350,65.0,63.0,88,89,2.40\n")
	}

	var csvNominal strings.Builder
	csvNominal.WriteString("ts,gpu_w,gpu_limit_w,gpu_temp_c,gpu_util_pct,gpu_mem_mib,gpu_sm_mhz,gpu_fan_pct,cpu_pkg_w,cpu_core_w,cpu_pkg_temp_c,cpu_core_max_c,load1,mb_fan1_rpm,mb_fan2_rpm,mb_fan3_rpm,mb_fan4_rpm,mb_fan5_rpm,mb_pwm1,mb_pwm2,mb_pwm3,mb_pwm4,mb_pwm5\n")
	for range 12 {
		// Régime nominal courant : 65 W -> 58 °C
		csvNominal.WriteString("2026-10-29T10:00:00.000Z,50.0,450.0,40,0,200,300,30,65.0,63.0,58,59,1.60,0,0,600,0,0,66,63,63,63,66\n")
	}
	for range 12 {
		// Régime nominal sous forte charge : 140 W -> 88 °C (même température brute que le dégradé à 65 W !)
		csvNominal.WriteString("2026-10-29T11:00:00.000Z,50.0,450.0,40,0,200,300,30,140.0,136.0,88,89,4.20,0,0,900,0,0,66,63,63,63,66\n")
	}

	jDeg, errDeg := cinetique.LireJournalPuissanceCSV(strings.NewReader(csvDegrade.String()))
	if errDeg != nil {
		t.Fatalf("LireJournalPuissanceCSV degrade: %v", errDeg)
	}
	if jDeg.LignesTotales != 26 || jDeg.LignesValides != 24 || jDeg.LignesQuarantaineSchema != 2 {
		t.Fatalf("comptabilite quarantaine inattendue: %+v", jDeg)
	}

	jNom, errNom := cinetique.LireJournalPuissanceCSV(strings.NewReader(csvNominal.String()))
	if errNom != nil {
		t.Fatalf("LireJournalPuissanceCSV nominal: %v", errNom)
	}
	if jNom.LignesValides != 24 || jNom.LignesQuarantaineSchema != 0 {
		t.Fatalf("comptabilite nominale inattendue: %+v", jNom)
	}

	cfg := cinetique.ConfigPowerlogParDefaut()
	cfg.FenetreEpisode = 6
	bilan, errEval := cinetique.EvaluerCampagnePowerlog(jDeg, jNom, cfg)
	if errEval != nil {
		t.Fatalf("EvaluerCampagnePowerlog: %v", errEval)
	}

	// Sur l'épreuve de confusion forte charge (65 W @ 88 °C vs 140 W @ 88 °C) :
	// la température brute est identique (AUC exacte avec ex-aequo = 0.50),
	// tandis que la résistance thermique (T-25)/W sépare à AUC = 1.00 !
	if len(bilan.EpreuveConfusionForteCharge) != 2 {
		t.Fatalf("EpreuveConfusionForteCharge absente: %+v", bilan)
	}
	rocTempBrute := bilan.EpreuveConfusionForteCharge[0]
	rocQuotient := bilan.EpreuveConfusionForteCharge[1]
	if rocTempBrute.AUCMannWhitney != 0.5 {
		t.Fatalf("AUC temperature brute sur ex-aequo attendue 0.5, obtenu %.4f", rocTempBrute.AUCMannWhitney)
	}
	if rocQuotient.AUCMannWhitney != 1.0 || rocQuotient.RappelAFPRZero != 1.0 {
		t.Fatalf("AUC resistance thermique attendue 1.0, obtenu %+v", rocQuotient)
	}
}
