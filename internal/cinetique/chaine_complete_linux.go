//go:build linux

package cinetique

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// EtapeChaineDetection consigne l'intégralité des preuves d'une chaîne réelle
// (attribution socket inet_diag, orientation 0 B/op, jeton différentiel,
// décision DecisionHead SIMD et décision Qwen2.5-0.5B si modèle chargé).
type EtapeChaineDetection struct {
	NomChaine             string                      `json:"nom_chaine"`
	AttributionSocket     *IdentiteProcessusSocket    `json:"attribution_socket,omitempty"`
	OrientationMoteur     string                      `json:"orientation_moteur"`
	EscaladeSLM           bool                        `json:"escalade_slm"`
	PressionCPUPermille   uint32                      `json:"pression_cpu_permille"`
	MigrationHybride      bool                        `json:"migration_hybride"`
	CodeRaisonDNS         uint8                       `json:"code_raison_dns"`
	DifferentielStructure string                      `json:"differentiel_structure"`
	DecisionEncodeur      DecisionArbitrageCinetique  `json:"decision_encodeur"`
	DecisionQwen          *DecisionArbitrageCinetique `json:"decision_qwen,omitempty"`
}

// RapportChaineComplete rassemble l'exécution de bout en bout des 5 chaînes
// (nominal, abstention migration hybride, panne stockage NVMe, compromission UDP
// résolue via inet_diag -> /proc/pid/fd, et dérive organique monotone).
type RapportChaineComplete struct {
	PIDProcessus     int                    `json:"pid_processus"`
	DebutTacheTicks  uint64                 `json:"debut_tache_ticks"`
	NomExecutable    string                 `json:"nom_executable"`
	ModeleQwenCharge bool                   `json:"modele_qwen_charge"`
	CheminModeleQwen string                 `json:"chemin_modele_qwen,omitempty"`
	Chaines          []EtapeChaineDetection `json:"chaines"`
}

type dossierChaineCapturee struct {
	nomChaine   string
	attribution *IdentiteProcessusSocket
	diagnostic  DiagnosticEpisodeCinetique
}

// ExecuterBancChaineComplete exécute sur le système Linux réel la chaîne
// complète Socket -> inet_diag -> /proc -> Ratios 0 B/op -> Encodeur + Qwen2.5-0.5B.
// Les 5 épisodes OS sont capturés en premier sous affinité CPU maîtrisée, puis
// l'affinité du fil est restaurée avant l'initialisation et l'inférence multi-coeurs
// de Qwen2.5-0.5B afin d'éviter toute auto-perturbation de /proc/pressure/cpu.
func ExecuterBancChaineComplete(
	ctx context.Context,
	dossierTravail string,
	cheminModeleQwen string,
) (RapportChaineComplete, error) {
	var rapport RapportChaineComplete
	if dossierTravail == "" {
		return rapport, fmt.Errorf("cinetique: dossier de travail requis")
	}

	resolveur, errRes := OuvrirResolveurSocketProcessus()
	if errRes != nil {
		return rapport, errRes
	}
	defer func() { _ = resolveur.Fermer() }()

	capteur := resolveur.CapteurProc()
	collecteur := NouveauCollecteurReseauParProcessus()

	identiteSocket, dossiersCaptures, cfgProfilCapture, errCapture := capturerCinqChainesReelles(ctx, resolveur, capteur, collecteur, dossierTravail)
	if errCapture != nil {
		return rapport, errCapture
	}
	rapport.PIDProcessus = identiteSocket.PID
	rapport.DebutTacheTicks = identiteSocket.DebutTacheTicks
	rapport.NomExecutable = identiteSocket.NomExecutable

	arbitreEncodeur := NouvelArbitreEncodeurCinetique()
	defer func() { _ = arbitreEncodeur.Fermer() }()

	var arbitreQwen *ArbitreQwenCinetique
	if cheminModeleQwen != "" {
		if err := ctx.Err(); err != nil {
			return rapport, err
		}
		charge, errQwen := NouvelArbitreQwenCinetique(cheminModeleQwen)
		if errQwen != nil {
			return rapport, errQwen
		}
		charge.DefinirConfigBrief(cfgProfilCapture)
		arbitreQwen = charge
		rapport.ModeleQwenCharge = true
		rapport.CheminModeleQwen = cheminModeleQwen
		defer func() { _ = arbitreQwen.Fermer() }()
	}

	for _, d := range dossiersCaptures {
		if err := ctx.Err(); err != nil {
			return rapport, err
		}
		var tamponDiff [512]byte
		octetsDiff, errFmt := FormaterDifferentielEpisode(tamponDiff[:0], identiteSocket.NomExecutable, d.diagnostic)
		if errFmt != nil {
			return rapport, errFmt
		}
		decEnc, errEnc := arbitreEncodeur.ArbitrerEpisode(ctx, identiteSocket.NomExecutable, d.diagnostic)
		if errEnc != nil {
			return rapport, errEnc
		}
		etape := EtapeChaineDetection{
			NomChaine:             d.nomChaine,
			AttributionSocket:     d.attribution,
			OrientationMoteur:     d.diagnostic.Orientation.String(),
			EscaladeSLM:           DoitEscaladeSLM(d.diagnostic),
			PressionCPUPermille:   d.diagnostic.Episode.PressionCPUPermille,
			MigrationHybride:      d.diagnostic.Episode.MigrationHybride,
			CodeRaisonDNS:         d.diagnostic.Episode.CodeRaisonDNS,
			DifferentielStructure: string(octetsDiff),
			DecisionEncodeur:      decEnc,
		}
		if arbitreQwen != nil {
			decQwen, errQwen := arbitreQwen.ArbitrerEpisode(ctx, identiteSocket.NomExecutable, d.diagnostic)
			if errQwen != nil {
				return rapport, errQwen
			}
			etape.DecisionQwen = &decQwen
		}
		rapport.Chaines = append(rapport.Chaines, etape)
	}

	return rapport, nil
}

func capturerCinqChainesReelles(
	ctx context.Context,
	resolveur *ResolveurSocketProcessus,
	capteur *CapteurProcLinux,
	collecteur *CollecteurReseauParProcessus,
	dossierTravail string,
) (IdentiteProcessusSocket, []dossierChaineCapturee, ConfigProfilCinetique, error) {
	var identiteZero IdentiteProcessusSocket
	var cfgZero ConfigProfilCinetique
	if err := ctx.Err(); err != nil {
		return identiteZero, nil, cfgZero, err
	}

	// Ouverture d'une paire UDP locale réelle pour l'attribution Netlink inet_diag.
	serveurUDP, errSrv := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if errSrv != nil {
		return identiteZero, nil, cfgZero, errSrv
	}
	defer func() { _ = serveurUDP.Close() }()

	adrSrv := serveurUDP.LocalAddr().(*net.UDPAddr)
	clientUDP, errCli := net.DialUDP("udp4", nil, adrSrv)
	if errCli != nil {
		return identiteZero, nil, cfgZero, errCli
	}
	defer func() { _ = clientUDP.Close() }()
	adrCli := clientUDP.LocalAddr().(*net.UDPAddr)

	// Vérification de la résolution complète (PortSource, PortDest, IPPROTO_UDP) -> Inode -> PID sans indice candidat (pidCandidat=0).
	identiteSocket, errIdent := resolveur.ResoudreTupleIPv4(
		unix.IPPROTO_UDP,
		uint16(adrCli.Port),
		uint16(adrSrv.Port),
		0,
	)
	if errIdent != nil {
		return identiteZero, nil, cfgZero, fmt.Errorf("cinetique: echec attribution inet_diag UDP (%d->%d): %w", adrCli.Port, adrSrv.Port, errIdent)
	}

	topologie, listeCore, listeAtom := ChargerTopologieHybride()
	coeurPerf, coeurEff, errCoeurs := choisirPaireCoeursDisponibles(listeCore, listeAtom)
	if errCoeurs != nil {
		return identiteZero, nil, cfgZero, errCoeurs
	}

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
		return identiteZero, nil, cfgZero, errGetAff
	}

	if err := epinglerFilSurCoeur(tid, coeurPerf); err != nil {
		return identiteZero, nil, cfgZero, err
	}

	cheminFichier := filepath.Join(dossierTravail, "chaine_complete_io.bin")
	cfgPlanchers := ConfigPlanchersParDefaut()
	cfgProfil := ConfigProfilParDefaut()
	cfgProfil.MinEpisodesAmorcage = 8
	cfgProfil.SeuilHausseRelativePct = 80
	table := NouvelleTableProfilsCinetiques(cfgProfil)
	cleBinaire := HashIdentifiantBinaire(identiteSocket.NomExecutable)

	// Amorçage jusqu'à disposer d'au moins 8 épisodes nominaux calmes (hors pic PSI transitoire).
	if _, err := executerEpisodeChargeReelle(capteur, pid, tid, cheminFichier, nil, nil, topologie, cfgPlanchers, chargeNominale); err != nil {
		return identiteZero, nil, cfgZero, err
	}
	calmesAmorce := 0
	seqAmorce := uint64(1)
	for i := 0; i < 8 || (calmesAmorce < 8 && i < 28); i++ {
		if err := ctx.Err(); err != nil {
			return identiteZero, nil, cfgZero, err
		}
		epAmorce, errEp := executerEpisodeChargeReelle(capteur, pid, tid, cheminFichier, nil, nil, topologie, cfgPlanchers, chargeNominale)
		if errEp != nil {
			return identiteZero, nil, cfgZero, errEp
		}
		if !epAmorce.AbstentionPSICPU && !epAmorce.MigrationHybride {
			calmesAmorce++
		}
		_ = table.ObserverEpisode(cleBinaire, seqAmorce*1_000_000, epAmorce)
		seqAmorce++
	}

	dossiers := make([]dossierChaineCapturee, 0, 5)

	// Chaîne 0 : contrôle nominal (aucun réveil SLM).
	if err := ctx.Err(); err != nil {
		return identiteZero, nil, cfgZero, err
	}
	epNom, errNom := executerEpisodeChargeReelle(capteur, pid, tid, cheminFichier, nil, nil, topologie, cfgPlanchers, chargeNominale)
	if errNom != nil {
		return identiteZero, nil, cfgZero, errNom
	}
	diagNom := table.ObserverEpisode(cleBinaire, 12_000_000, epNom)
	dossiers = append(dossiers, dossierChaineCapturee{nomChaine: "0_controle_nominal", diagnostic: diagNom})

	// Chaîne 1 : migration hybride réelle P-core -> E-core en milieu d'épisode (abstention, zéro réveil SLM).
	if topologie.EstHybride && coeurPerf != coeurEff {
		if err := ctx.Err(); err != nil {
			return identiteZero, nil, cfgZero, err
		}
		epMig, errMig := executerEpisodeMigrationReelle(capteur, pid, tid, coeurPerf, coeurEff, cheminFichier, topologie, cfgPlanchers)
		if errMig != nil {
			return identiteZero, nil, cfgZero, errMig
		}
		if err := epinglerFilSurCoeur(tid, coeurPerf); err != nil {
			return identiteZero, nil, cfgZero, err
		}
		diagMig := table.ObserverEpisode(cleBinaire, 13_000_000, epMig)
		dossiers = append(dossiers, dossierChaineCapturee{nomChaine: "1_abstention_migration_hybride", diagnostic: diagMig})
	}

	// Chaîne 2 : panne / latence stockage réelle (32 fdatasync NVMe, 0 activité réseau).
	if err := ctx.Err(); err != nil {
		return identiteZero, nil, cfgZero, err
	}
	epPanne, errPanne := executerEpisodeChargeReelle(capteur, pid, tid, cheminFichier, nil, nil, topologie, cfgPlanchers, chargeBarriereStockage)
	if errPanne != nil {
		return identiteZero, nil, cfgZero, errPanne
	}
	diagPanne := table.ObserverEpisode(cleBinaire, 14_000_000, epPanne)
	dossiers = append(dossiers, dossierChaineCapturee{nomChaine: "2_degradation_stockage_nvme", diagnostic: diagPanne})

	// Chaîne 3 : compromission / exfiltration DNS-UDP réelle lue depuis le noyau, inspectée
	// au fil (RFC 1035) et attribuée en aveugle (pidCandidat=0) via inet_diag -> /proc/pid/fd.
	if err := ctx.Err(); err != nil {
		return identiteZero, nil, cfgZero, err
	}
	epExfil, attributionLive, errExfil := executerEpisodeExfiltrationAttribuee(
		resolveur,
		collecteur,
		pid,
		tid,
		cheminFichier,
		clientUDP,
		serveurUDP,
		topologie,
		cfgPlanchers,
	)
	if errExfil != nil {
		return identiteZero, nil, cfgZero, errExfil
	}
	diagExfil := table.ObserverEpisode(cleBinaire, 15_000_000, epExfil)
	copieAttr := attributionLive
	dossiers = append(dossiers, dossierChaineCapturee{
		nomChaine:   "3_exfiltration_udp_attribuee_inet_diag",
		attribution: &copieAttr,
		diagnostic:  diagExfil,
	})

	// Chaîne 4 : dérive organique monotone réelle (6 épisodes consécutifs matérialisant
	// chacun 512 Kio supplémentaires de pages anonymes réelles via mmap + touch, libérées en defer).
	var segmentsFuite [][]byte
	defer func() {
		for _, seg := range segmentsFuite {
			_ = unix.Munmap(seg)
		}
	}()
	var diagDerive DiagnosticEpisodeCinetique
	for pas := 1; pas <= 6; pas++ {
		if err := ctx.Err(); err != nil {
			return identiteZero, nil, cfgZero, err
		}
		seg, errMmap := unix.Mmap(-1, 0, 512*1024, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
		if errMmap != nil {
			return identiteZero, nil, cfgZero, fmt.Errorf("cinetique: mmap derive reelle pas %d: %w", pas, errMmap)
		}
		for offset := 0; offset < len(seg); offset += 4096 {
			seg[offset] = byte(pas)
		}
		segmentsFuite = append(segmentsFuite, seg)

		epPas, errPas := executerEpisodeChargeReelle(capteur, pid, tid, cheminFichier, nil, nil, topologie, cfgPlanchers, chargeNominale)
		if errPas != nil {
			return identiteZero, nil, cfgZero, errPas
		}
		diagDerive = table.ObserverEpisode(cleBinaire, uint64(20+pas)*1_000_000, epPas)
	}
	dossiers = append(dossiers, dossierChaineCapturee{nomChaine: "4_derive_organique_monotone", diagnostic: diagDerive})

	return identiteSocket, dossiers, cfgProfil, nil
}

func executerEpisodeMigrationReelle(
	capteur *CapteurProcLinux,
	pid, tid int,
	coeurDepart, coeurArrivee int,
	cheminFichier string,
	topologie TopologieHybride,
	cfgPlanchers ConfigPlanchersCinetiques,
) (QuotientsEpisode, error) {
	if err := epinglerFilSurCoeur(tid, coeurDepart); err != nil {
		return QuotientsEpisode{}, err
	}
	// Courte boucle CPU pour garantir CoeurDerniereExecution == coeurDepart avant snapDebut.
	var etatCondensat [32]byte
	for i := range 64 {
		etatCondensat[0] ^= byte(i)
		etatCondensat = sha256.Sum256(etatCondensat[:])
	}
	fd, errOpen := unix.Open(cheminFichier, unix.O_CREAT|unix.O_RDWR|unix.O_TRUNC|unix.O_CLOEXEC, 0600)
	if errOpen != nil {
		return QuotientsEpisode{}, errOpen
	}

	psiDebut, _ := capteur.LirePressionPSI(time.Now().UnixNano())
	snapDebut, errDebut := capteur.LireInstantaneFil(pid, tid, time.Now().UnixNano())
	if errDebut != nil {
		_ = unix.Close(fd)
		return QuotientsEpisode{}, errDebut
	}

	// Même charge logique exacte que chargeNominale (32 Pwrite + 1 Fdatasync + 32 Pread),
	// mais avec bascule réelle de coeur P-core -> E-core à mi-parcours.
	const nbBlocs = 32
	const tailleBloc = 4096
	var blocDonnees [tailleBloc]byte
	for i := range tailleBloc {
		blocDonnees[i] = byte((i*31 + 17) & 0xFF)
	}
	for b := range nbBlocs {
		if b == nbBlocs/2 {
			if err := epinglerFilSurCoeur(tid, coeurArrivee); err != nil {
				_ = unix.Close(fd)
				return QuotientsEpisode{}, err
			}
		}
		blocDonnees[0] = byte(b)
		blocDonnees[1] = etatCondensat[0]
		if _, errW := unix.Pwrite(fd, blocDonnees[:], int64(b*tailleBloc)); errW != nil {
			_ = unix.Close(fd)
			return QuotientsEpisode{}, errW
		}
	}
	if errSync := unix.Fdatasync(fd); errSync != nil {
		_ = unix.Close(fd)
		return QuotientsEpisode{}, errSync
	}
	var tamponRelecture [tailleBloc]byte
	for b := range nbBlocs {
		if _, errR := unix.Pread(fd, tamponRelecture[:], int64(b*tailleBloc)); errR != nil {
			_ = unix.Close(fd)
			return QuotientsEpisode{}, errR
		}
		etatCondensat = sha256.Sum256(tamponRelecture[:])
		for r := 1; r < 96; r++ {
			tamponRelecture[r&(tailleBloc-1)] ^= etatCondensat[r&31]
			etatCondensat = sha256.Sum256(tamponRelecture[:])
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
	return EvaluerEpisodeCinetique(snapDebut, snapFin, psiDebut, psiFin, CompteursReseauEpisode{}, topologie, cfgPlanchers)
}

func executerEpisodeExfiltrationAttribuee(
	resolveur *ResolveurSocketProcessus,
	collecteur *CollecteurReseauParProcessus,
	pid, tid int,
	cheminFichier string,
	clientUDP *net.UDPConn,
	serveurUDP *net.UDPConn,
	topologie TopologieHybride,
	cfgPlanchers ConfigPlanchersCinetiques,
) (QuotientsEpisode, IdentiteProcessusSocket, error) {
	capteur := resolveur.CapteurProc()
	fd, errOpen := unix.Open(cheminFichier, unix.O_CREAT|unix.O_RDWR|unix.O_TRUNC|unix.O_CLOEXEC, 0600)
	if errOpen != nil {
		return QuotientsEpisode{}, IdentiteProcessusSocket{}, errOpen
	}

	psiDebut, _ := capteur.LirePressionPSI(time.Now().UnixNano())
	snapDebut, errDebut := capteur.LireInstantaneFil(pid, tid, time.Now().UnixNano())
	if errDebut != nil {
		_ = unix.Close(fd)
		return QuotientsEpisode{}, IdentiteProcessusSocket{}, errDebut
	}

	var bloc [4096]byte
	for b := range 32 {
		bloc[0] = byte(b)
		if _, errW := unix.Pwrite(fd, bloc[:], int64(b*4096)); errW != nil {
			_ = unix.Close(fd)
			return QuotientsEpisode{}, IdentiteProcessusSocket{}, errW
		}
	}
	if errSync := unix.Fdatasync(fd); errSync != nil {
		_ = unix.Close(fd)
		return QuotientsEpisode{}, IdentiteProcessusSocket{}, errSync
	}

	var condensat [32]byte
	for b := range 32 {
		if _, errR := unix.Pread(fd, bloc[:], int64(b*4096)); errR != nil {
			_ = unix.Close(fd)
			return QuotientsEpisode{}, IdentiteProcessusSocket{}, errR
		}
		for r := range 384 {
			bloc[r&4095] ^= condensat[r&31]
			condensat = sha256.Sum256(bloc[:])
		}
	}
	if errClose := unix.Close(fd); errClose != nil {
		return QuotientsEpisode{}, IdentiteProcessusSocket{}, errClose
	}
	_ = os.Remove(cheminFichier)

	// Émission filaire DNS TXT RFC 1035 réelle sur la socket cliente, capture noyau
	// sur serveurUDP, inspection filaire des octets reçus (InspecterDatagrammeDNSFil)
	// et attribution Netlink inet_diag en aveugle (pidCandidat = 0) depuis les ports
	// réels lus à la réception : aucune constante de port ni de raison DNS n'est injectée.
	_ = serveurUDP.SetReadDeadline(time.Now().Add(2 * time.Second))
	portServeurReel := uint16(serveurUDP.LocalAddr().(*net.UDPAddr).Port)
	var tamponTx [512]byte
	var tamponRx [512]byte
	var identite IdentiteProcessusSocket

	for p := range 24 {
		domaineExfil := construireDomaineTunnelHex(condensat, uint8(p))
		trameDNS, errTrame := ConstruireRequeteDNSFil(tamponTx[:0], uint16(0x5200+p), domaineExfil, 16)
		if errTrame != nil {
			return QuotientsEpisode{}, IdentiteProcessusSocket{}, errTrame
		}
		if _, errEnv := clientUDP.Write(trameDNS); errEnv != nil {
			return QuotientsEpisode{}, IdentiteProcessusSocket{}, errEnv
		}
		nRx, adrExp, errRx := serveurUDP.ReadFromUDP(tamponRx[:])
		if errRx != nil {
			return QuotientsEpisode{}, IdentiteProcessusSocket{}, errRx
		}
		if p == 0 {
			resolue, errAttr := resolveur.ResoudreTupleIPv4(
				unix.IPPROTO_UDP,
				uint16(adrExp.Port),
				portServeurReel,
				0,
			)
			if errAttr != nil {
				return QuotientsEpisode{}, IdentiteProcessusSocket{}, errAttr
			}
			identite = resolue
		}
		insp, okDNS := InspecterDatagrammeDNSFil(tamponRx[:nRx])
		portSuspectMesure := uint16(0)
		codeDNSMesure := uint8(0)
		if okDNS && insp.CodeRaisonDNS != 0 {
			portSuspectMesure = portServeurReel
			codeDNSMesure = insp.CodeRaisonDNS
		}
		collecteur.EnregistrerObservationReseau(
			identite.PID,
			identite.DebutTacheTicks,
			uint64(nRx),
			0,
			p == 0,
			okDNS,
			portSuspectMesure,
			portSuspectMesure != 0,
			codeDNSMesure,
		)
	}

	snapFin, errFin := capteur.LireInstantaneFil(pid, tid, time.Now().UnixNano())
	if errFin != nil {
		return QuotientsEpisode{}, IdentiteProcessusSocket{}, errFin
	}
	psiFin, _ := capteur.LirePressionPSI(time.Now().UnixNano())

	compteursAttribues := collecteur.RecolterEtPurger(identite.PID, identite.DebutTacheTicks)
	episode, errEp := EvaluerEpisodeCinetique(snapDebut, snapFin, psiDebut, psiFin, compteursAttribues, topologie, cfgPlanchers)
	return episode, identite, errEp
}
