//go:build linux

package cinetique

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// ErrAffiniteImpossible signale qu'aucun coeur utilisable n'a pu être épinglé.
var ErrAffiniteImpossible = errors.New("cinetique: impossible d'epingler le fil sur les coeurs demandes")

// BilanInvarianceQuotient synthétise la stabilité intra-coeur (MADM/médiane) et
// la dérive inter-architecture (cpu_core vs cpu_atom) d'un quotient invariant.
type BilanInvarianceQuotient struct {
	IndiceQuotient            int    `json:"indice_quotient"`
	NomQuotient               string `json:"nom_quotient"`
	SensibleContentionCPU     bool   `json:"sensible_contention_cpu"`
	ObservationsCore          int    `json:"observations_core"`
	ObservationsAtom          int    `json:"observations_atom"`
	MedianeCore               int64  `json:"mediane_core"`
	MADMCore                  int64  `json:"madm_core"`
	DispersionCorePermille    int64  `json:"dispersion_core_permille"`
	MedianeAtom               int64  `json:"mediane_atom"`
	MADMAtom                  int64  `json:"madm_atom"`
	DispersionAtomPermille    int64  `json:"dispersion_atom_permille"`
	DeriveInterCoeursPermille int64  `json:"derive_inter_coeurs_permille"`
}

// PreuveArchetypeReel consigne le diagnostic et le jeton différentiel produits
// sur une exécution système réelle (nominal, latence stockage fdatasync, greffe CPU+UDP).
type PreuveArchetypeReel struct {
	Scenario              string `json:"scenario"`
	Orientation           string `json:"orientation"`
	DureeHorlogeUs        uint64 `json:"duree_horloge_us"`
	ExecutionCPUUs        uint64 `json:"execution_cpu_us"`
	AttenteFileUs         uint64 `json:"attente_file_us"`
	DilatationHorsCPUUs   uint64 `json:"dilatation_hors_cpu_us"`
	PressionCPUPermille   uint32 `json:"pression_cpu_permille"`
	ScoreRobusteMaxMilli  int64  `json:"score_robuste_max_milli"`
	DifferentielStructure string `json:"differentiel_structure"`
}

// AttenteFileDominante signale qu'un épisode a été disputé au processeur :
// l'attente en file d'exécution vaut au moins un dixième de la durée d'horloge
// de l'épisode, borne incluse. Une durée d'horloge nulle n'a jamais d'attente
// dominante.
func (preuve PreuveArchetypeReel) AttenteFileDominante() bool {
	return preuve.DureeHorlogeUs > 0 && preuve.AttenteFileUs*10 >= preuve.DureeHorlogeUs
}

// RapportInvarianceHybride regroupe l'état des capteurs noyau, la comparaison
// réelle P-core vs E-core et les preuves d'orientation causale sur traces OS.
type RapportInvarianceHybride struct {
	CapteursNoyau          EtatCapteursNoyau         `json:"capteurs_noyau"`
	CoeurPerformanceTeste  int                       `json:"coeur_performance_teste"`
	CoeurEfficienceTeste   int                       `json:"coeur_efficience_teste"`
	CoeurObserveDebutCore  int32                     `json:"coeur_observe_debut_core"`
	CoeurObserveFinCore    int32                     `json:"coeur_observe_fin_core"`
	CoeurObserveDebutAtom  int32                     `json:"coeur_observe_debut_atom"`
	CoeurObserveFinAtom    int32                     `json:"coeur_observe_fin_atom"`
	RepetitionsParDomaine  int                       `json:"repetitions_par_domaine"`
	Quotients              []BilanInvarianceQuotient `json:"quotients"`
	PreuvesArchetypesReels []PreuveArchetypeReel     `json:"preuves_archetypes_reels"`
}

type modeChargeReelle uint8

const (
	chargeNominale modeChargeReelle = iota
	chargeBarriereStockage
	chargeGreffeCPUExfiltration
)

// ExecuterBancInvarianceHybride exécute des charges système réelles (pwrite,
// pread, fdatasync NVMe, SHA-256 et UDP loopback) successivement épinglées sur
// un coeur performance puis sur un coeur efficience.
func ExecuterBancInvarianceHybride(dossierTravail string, repetitions int) (RapportInvarianceHybride, error) {
	var rapport RapportInvarianceHybride
	if repetitions < 8 {
		repetitions = 8
	}
	if dossierTravail == "" {
		return rapport, fmt.Errorf("cinetique: dossier de travail requis")
	}

	rapport.CapteursNoyau = VerifierDisponibiliteCapteursNoyau()
	topologie, listeCore, listeAtom := ChargerTopologieHybride()

	coeurPerf, coeurEff, errChoix := choisirPaireCoeursDisponibles(listeCore, listeAtom)
	if errChoix != nil {
		return rapport, errChoix
	}
	rapport.CoeurPerformanceTeste = coeurPerf
	rapport.CoeurEfficienceTeste = coeurEff
	rapport.RepetitionsParDomaine = repetitions

	capteur, errCapteur := OuvrirCapteurProcLinux()
	if errCapteur != nil {
		return rapport, errCapteur
	}
	defer func() { _ = capteur.Fermer() }()

	connServeur, errUDP := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if errUDP != nil {
		return rapport, fmt.Errorf("cinetique: ecoute UDP loopback: %w", errUDP)
	}
	defer func() { _ = connServeur.Close() }()

	adrServeur, okAdr := connServeur.LocalAddr().(*net.UDPAddr)
	if !okAdr {
		return rapport, fmt.Errorf("cinetique: adresse UDP locale invalide")
	}
	connClient, errClient := net.DialUDP("udp4", nil, adrServeur)
	if errClient != nil {
		return rapport, fmt.Errorf("cinetique: client UDP loopback: %w", errClient)
	}
	defer func() { _ = connClient.Close() }()

	runtime.LockOSThread()
	tid := unix.Gettid()
	pid := os.Getpid()
	var masqueInitial unix.CPUSet
	errGetAff := unix.SchedGetaffinity(tid, &masqueInitial)
	defer func() {
		if errGetAff == nil {
			_ = unix.SchedSetaffinity(tid, &masqueInitial)
		}
		runtime.UnlockOSThread()
	}()
	if errGetAff != nil {
		return rapport, fmt.Errorf("cinetique: lecture affinite initiale: %w", errGetAff)
	}

	cheminFichierCore := filepath.Join(dossierTravail, "banc_cinetique_core.bin")
	cheminFichierAtom := filepath.Join(dossierTravail, "banc_cinetique_atom.bin")

	cfgPlanchers := ConfigPlanchersParDefaut()
	episodesCore := make([]QuotientsEpisode, 0, repetitions)
	episodesAtom := make([]QuotientsEpisode, 0, repetitions)

	if err := epinglerFilSurCoeur(tid, coeurPerf); err != nil {
		return rapport, err
	}
	// Amorce de migration effective sur le coeur cible avant la première mesure.
	if _, err := executerEpisodeChargeReelle(capteur, pid, tid, cheminFichierCore, connClient, connServeur, topologie, cfgPlanchers, chargeNominale); err != nil {
		return rapport, err
	}
	snapAmorceCore, errAmorceCore := capteur.LireInstantaneFil(pid, tid, time.Now().UnixNano())
	if errAmorceCore != nil {
		return rapport, errAmorceCore
	}
	rapport.CoeurObserveDebutCore = snapAmorceCore.CoeurDerniereExecution
	for i := 0; i < repetitions; i++ {
		ep, errEp := executerEpisodeChargeReelle(capteur, pid, tid, cheminFichierCore, connClient, connServeur, topologie, cfgPlanchers, chargeNominale)
		if errEp != nil {
			return rapport, errEp
		}
		episodesCore = append(episodesCore, ep)
	}
	snapFinCore, errFinCore := capteur.LireInstantaneFil(pid, tid, time.Now().UnixNano())
	if errFinCore != nil {
		return rapport, errFinCore
	}
	rapport.CoeurObserveFinCore = snapFinCore.CoeurDerniereExecution

	// Évaluation des 3 archétypes réels sur le coeur performance à partir de la base apprise.
	cfgProfil := ConfigProfilParDefaut()
	cfgProfil.MinEpisodesAmorcage = uint32(repetitions)
	// Tolérer la gigue naturelle du sous-système NVMe lors de l'amorçage nominal
	// tout en détectant une multiplication par >3x de la dilatation E/S ou CPU.
	cfgProfil.SeuilHausseRelativePct = 80
	table := NouvelleTableProfilsCinetiques(cfgProfil)
	cleBin := HashIdentifiantBinaire("c2cinetique_tache_reference")
	calmesCore := 0
	for idx, ep := range episodesCore {
		if !ep.AbstentionPSICPU && !ep.MigrationHybride {
			calmesCore++
		}
		_ = table.ObserverEpisode(cleBin, uint64(idx+1)*1_000_000, ep)
	}
	horodatageSeq := uint64(len(episodesCore) + 1)
	for extra := 0; calmesCore < repetitions && extra < 20; extra++ {
		epExtra, errEx := executerEpisodeChargeReelle(capteur, pid, tid, cheminFichierCore, connClient, connServeur, topologie, cfgPlanchers, chargeNominale)
		if errEx != nil {
			return rapport, errEx
		}
		if !epExtra.AbstentionPSICPU && !epExtra.MigrationHybride {
			calmesCore++
		}
		_ = table.ObserverEpisode(cleBin, horodatageSeq*1_000_000, epExtra)
		horodatageSeq++
	}

	epNomVerif, errNom := executerEpisodeChargeReelle(capteur, pid, tid, cheminFichierCore, connClient, connServeur, topologie, cfgPlanchers, chargeNominale)
	if errNom != nil {
		return rapport, errNom
	}
	diagNom := table.ObserverEpisode(cleBin, horodatageSeq*1_000_000, epNomVerif)
	horodatageSeq++
	preuveNom, errFmtNom := construirePreuveArchetype("nominal_controle", "tache_sauvegarde", diagNom)
	if errFmtNom != nil {
		return rapport, errFmtNom
	}

	epBarriere, errBar := executerEpisodeChargeReelle(capteur, pid, tid, cheminFichierCore, connClient, connServeur, topologie, cfgPlanchers, chargeBarriereStockage)
	if errBar != nil {
		return rapport, errBar
	}
	diagBar := table.ObserverEpisode(cleBin, horodatageSeq*1_000_000, epBarriere)
	horodatageSeq++
	preuveBar, errFmtBar := construirePreuveArchetype("latence_stockage_fdatasync_x32", "tache_sauvegarde", diagBar)
	if errFmtBar != nil {
		return rapport, errFmtBar
	}

	epGreffe, errGrf := executerEpisodeChargeReelle(capteur, pid, tid, cheminFichierCore, connClient, connServeur, topologie, cfgPlanchers, chargeGreffeCPUExfiltration)
	if errGrf != nil {
		return rapport, errGrf
	}
	diagGreffe := table.ObserverEpisode(cleBin, horodatageSeq*1_000_000, epGreffe)
	preuveGreffe, errFmtGrf := construirePreuveArchetype("greffe_cpu_exfiltration_dns_udp", "tache_sauvegarde", diagGreffe)
	if errFmtGrf != nil {
		return rapport, errFmtGrf
	}
	rapport.PreuvesArchetypesReels = []PreuveArchetypeReel{preuveNom, preuveBar, preuveGreffe}

	// Bascule sur le coeur efficience (ou second coeur disponible sur hôte homogène).
	if err := epinglerFilSurCoeur(tid, coeurEff); err != nil {
		return rapport, err
	}
	if _, err := executerEpisodeChargeReelle(capteur, pid, tid, cheminFichierAtom, connClient, connServeur, topologie, cfgPlanchers, chargeNominale); err != nil {
		return rapport, err
	}
	snapAmorceAtom, errAmorceAtom := capteur.LireInstantaneFil(pid, tid, time.Now().UnixNano())
	if errAmorceAtom != nil {
		return rapport, errAmorceAtom
	}
	rapport.CoeurObserveDebutAtom = snapAmorceAtom.CoeurDerniereExecution
	for i := 0; i < repetitions; i++ {
		ep, errEp := executerEpisodeChargeReelle(capteur, pid, tid, cheminFichierAtom, connClient, connServeur, topologie, cfgPlanchers, chargeNominale)
		if errEp != nil {
			return rapport, errEp
		}
		episodesAtom = append(episodesAtom, ep)
	}
	snapFinAtom, errFinAtom := capteur.LireInstantaneFil(pid, tid, time.Now().UnixNano())
	if errFinAtom != nil {
		return rapport, errFinAtom
	}
	rapport.CoeurObserveFinAtom = snapFinAtom.CoeurDerniereExecution

	rapport.Quotients = compilerBilanInvariance(episodesCore, episodesAtom)
	return rapport, nil
}

func construirePreuveArchetype(nomScenario, nomBin string, diag DiagnosticEpisodeCinetique) (PreuveArchetypeReel, error) {
	var tamponDiff [512]byte
	octetsDiff, err := FormaterDifferentielEpisode(tamponDiff[:0], nomBin, diag)
	if err != nil {
		return PreuveArchetypeReel{}, err
	}
	return PreuveArchetypeReel{
		Scenario:              nomScenario,
		Orientation:           diag.Orientation.String(),
		DureeHorlogeUs:        diag.Episode.DureeHorlogeNs / 1000,
		ExecutionCPUUs:        diag.Episode.DeltaExecutionNs / 1000,
		AttenteFileUs:         diag.Episode.DeltaAttenteFileNs / 1000,
		DilatationHorsCPUUs:   diag.Episode.DeltaHorsCPUNs / 1000,
		PressionCPUPermille:   diag.Episode.PressionCPUPermille,
		ScoreRobusteMaxMilli:  diag.ScoreRobusteMaxMilli,
		DifferentielStructure: string(octetsDiff),
	}, nil
}

func construireDomaineTunnelHex(condensat [32]byte, seq uint8) string {
	melange := condensat
	melange[0] ^= seq
	melange[16] ^= seq * 37
	var buf [76]byte
	hex.Encode(buf[0:32], melange[0:16])
	buf[32] = '.'
	hex.Encode(buf[33:65], melange[16:32])
	copy(buf[65:], ".c2.invalid")
	return string(buf[:])
}

func executerEpisodeChargeReelle(
	capteur *CapteurProcLinux,
	pid, tid int,
	cheminFichier string,
	connUDP *net.UDPConn,
	connServeur *net.UDPConn,
	topologie TopologieHybride,
	cfgPlanchers ConfigPlanchersCinetiques,
	mode modeChargeReelle,
) (QuotientsEpisode, error) {
	fd, errOpen := unix.Open(cheminFichier, unix.O_CREAT|unix.O_RDWR|unix.O_TRUNC|unix.O_CLOEXEC, 0600)
	if errOpen != nil {
		return QuotientsEpisode{}, fmt.Errorf("cinetique: ouverture fichier banc: %w", errOpen)
	}

	psiDebut, _ := capteur.LirePressionPSI(time.Now().UnixNano())
	snapDebut, errDebut := capteur.LireInstantaneFil(pid, tid, time.Now().UnixNano())
	if errDebut != nil {
		_ = unix.Close(fd)
		return QuotientsEpisode{}, errDebut
	}

	const nbBlocs = 32
	const tailleBloc = 4096
	var blocDonnees [tailleBloc]byte
	for i := range tailleBloc {
		blocDonnees[i] = byte((i*31 + 17) & 0xFF)
	}

	rondesHachage := 96
	if mode == chargeGreffeCPUExfiltration {
		rondesHachage = 384
	}

	var etatCondensat [32]byte
	for b := range nbBlocs {
		blocDonnees[0] = byte(b)
		blocDonnees[1] = etatCondensat[0]
		if _, errW := unix.Pwrite(fd, blocDonnees[:], int64(b*tailleBloc)); errW != nil {
			_ = unix.Close(fd)
			return QuotientsEpisode{}, errW
		}
		if mode == chargeBarriereStockage {
			if errSync := unix.Fdatasync(fd); errSync != nil {
				_ = unix.Close(fd)
				return QuotientsEpisode{}, errSync
			}
		}
	}
	if mode != chargeBarriereStockage {
		if errSync := unix.Fdatasync(fd); errSync != nil {
			_ = unix.Close(fd)
			return QuotientsEpisode{}, errSync
		}
	}

	var tamponRelecture [tailleBloc]byte
	for b := range nbBlocs {
		if _, errR := unix.Pread(fd, tamponRelecture[:], int64(b*tailleBloc)); errR != nil {
			_ = unix.Close(fd)
			return QuotientsEpisode{}, errR
		}
		etatCondensat = sha256.Sum256(tamponRelecture[:])
		for r := 1; r < rondesHachage; r++ {
			tamponRelecture[r&(tailleBloc-1)] ^= etatCondensat[r&31]
			etatCondensat = sha256.Sum256(tamponRelecture[:])
		}
	}

	var compteursReseau CompteursReseauEpisode
	if mode == chargeGreffeCPUExfiltration && connUDP != nil && connServeur != nil {
		_ = connServeur.SetReadDeadline(time.Now().Add(2 * time.Second))
		portServeurReel := uint16(connServeur.LocalAddr().(*net.UDPAddr).Port)
		var tamponTx [512]byte
		var tamponRx [512]byte
		var totalRecus uint64
		var nbRequetesDNS uint32
		var codeRaisonMesure uint8
		var portSuspectMesure uint16

		for p := range 24 {
			domaineExfil := construireDomaineTunnelHex(etatCondensat, uint8(p))
			trameDNS, errTrame := ConstruireRequeteDNSFil(tamponTx[:0], uint16(0x4100+p), domaineExfil, 16)
			if errTrame != nil {
				_ = unix.Close(fd)
				return QuotientsEpisode{}, errTrame
			}
			if _, errEnv := connUDP.Write(trameDNS); errEnv != nil {
				_ = unix.Close(fd)
				return QuotientsEpisode{}, errEnv
			}
			nRx, _, errRx := connServeur.ReadFromUDP(tamponRx[:])
			if errRx != nil {
				_ = unix.Close(fd)
				return QuotientsEpisode{}, errRx
			}
			totalRecus += uint64(nRx)
			if insp, okDNS := InspecterDatagrammeDNSFil(tamponRx[:nRx]); okDNS {
				nbRequetesDNS++
				codeRaisonMesure |= insp.CodeRaisonDNS
				if insp.CodeRaisonDNS != 0 {
					portSuspectMesure = portServeurReel
				}
			}
		}
		compteursReseau = CompteursReseauEpisode{
			OctetsSortants:      totalRecus,
			ConnexionsSortantes: 1,
			ResolutionsDNS:      nbRequetesDNS,
			PortSuspect:         portSuspectMesure,
			ProtocoleSuspectUDP: portSuspectMesure != 0,
			CodeRaisonDNS:       codeRaisonMesure,
		}
	}

	if errClose := unix.Close(fd); errClose != nil {
		return QuotientsEpisode{}, errClose
	}
	_ = os.Remove(cheminFichier)

	snapFin, errFin := capteur.LireInstantaneFil(pid, tid, time.Now().UnixNano())
	if errFin != nil {
		return QuotientsEpisode{}, errFin
	}
	psiFin, _ := capteur.LirePressionPSI(time.Now().UnixNano())

	// Empêcher l'optimiseur d'éliminer l'accumulateur SHA-256.
	if etatCondensat[0] == 0xFF && snapFin.PID < 0 {
		return QuotientsEpisode{}, ErrFormatStatInvalide
	}
	return EvaluerEpisodeCinetique(snapDebut, snapFin, psiDebut, psiFin, compteursReseau, topologie, cfgPlanchers)
}

func compilerBilanInvariance(episodesCore, episodesAtom []QuotientsEpisode) []BilanInvarianceQuotient {
	bilans := make([]BilanInvarianceQuotient, 0, NombreQuotientsEpisode)
	for q := range NombreQuotientsEpisode {
		var suiviCore, suiviAtom SuiviQuotientRobuste
		for _, ep := range episodesCore {
			if ep.EstValide(q) {
				suiviCore.Enregistrer(ep.Valeurs[q])
			}
		}
		for _, ep := range episodesAtom {
			if ep.EstValide(q) {
				suiviAtom.Enregistrer(ep.Valeurs[q])
			}
		}
		medCore, madmCore := suiviCore.MedianeEtMADM()
		medAtom, madmAtom := suiviAtom.MedianeEtMADM()

		dispCore := quotientPermilleAbs(madmCore, medCore)
		dispAtom := quotientPermilleAbs(madmAtom, medAtom)
		diffInterMag := distanceAbsInt64(medCore, medAtom)
		var deriveInter int64
		if absCore := magnitudeInt64(medCore); absCore > 0 {
			deriveInter = diviserEchelle64(diffInterMag, 1000, absCore)
		}
		bitQ := uint16(1) << uint(q)

		bilans = append(bilans, BilanInvarianceQuotient{
			IndiceQuotient:            q,
			NomQuotient:               NomQuotient(q),
			SensibleContentionCPU:     (MasqueQuotientsSensiblesCPU & bitQ) != 0,
			ObservationsCore:          int(suiviCore.NombreObservations),
			ObservationsAtom:          int(suiviAtom.NombreObservations),
			MedianeCore:               medCore,
			MADMCore:                  madmCore,
			DispersionCorePermille:    dispCore,
			MedianeAtom:               medAtom,
			MADMAtom:                  madmAtom,
			DispersionAtomPermille:    dispAtom,
			DeriveInterCoeursPermille: deriveInter,
		})
	}
	return bilans
}

func quotientPermilleAbs(numerateur, reference int64) int64 {
	numMag := magnitudeInt64(numerateur)
	refMag := magnitudeInt64(reference)
	if numMag == 0 || refMag == 0 {
		return 0
	}
	return diviserEchelle64(numMag, 1000, refMag)
}

func choisirPaireCoeursDisponibles(listeCore, listeAtom []int) (int, int, error) {
	var masqueAutorise unix.CPUSet
	if err := unix.SchedGetaffinity(0, &masqueAutorise); err != nil {
		return 0, 0, err
	}
	premierCore := premierCoeurDansMasque(listeCore, &masqueAutorise, -1)
	premierAtom := premierCoeurDansMasque(listeAtom, &masqueAutorise, premierCore)
	if premierCore >= 0 && premierAtom >= 0 {
		return premierCore, premierAtom, nil
	}
	// Repli sur hôte homogène : choisir deux coeurs distincts dans le masque autorisé.
	var disponibles []int
	for cpu := range 1024 {
		if masqueAutorise.IsSet(cpu) {
			disponibles = append(disponibles, cpu)
			if len(disponibles) == 2 {
				break
			}
		}
	}
	if len(disponibles) == 0 {
		return 0, 0, ErrAffiniteImpossible
	}
	if len(disponibles) == 1 {
		return disponibles[0], disponibles[0], nil
	}
	return disponibles[0], disponibles[1], nil
}

func premierCoeurDansMasque(candidats []int, masque *unix.CPUSet, exclure int) int {
	for _, cpu := range candidats {
		if cpu > 0 && cpu != exclure && masque.IsSet(cpu) {
			return cpu
		}
	}
	for _, cpu := range candidats {
		if cpu != exclure && cpu >= 0 && masque.IsSet(cpu) {
			return cpu
		}
	}
	return -1
}

func epinglerFilSurCoeur(tid, coeur int) error {
	var masque unix.CPUSet
	masque.Set(coeur)
	if err := unix.SchedSetaffinity(tid, &masque); err != nil {
		return fmt.Errorf("%w (coeur %d): %v", ErrAffiniteImpossible, coeur, err)
	}
	runtime.Gosched()
	return nil
}
