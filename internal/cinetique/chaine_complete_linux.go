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
	NomChaine                 string                      `json:"nom_chaine"`
	AttributionSocket         *IdentiteProcessusSocket    `json:"attribution_socket,omitempty"`
	OrientationMoteur         string                      `json:"orientation_moteur"`
	EscaladeSLM               bool                        `json:"escalade_slm"`
	PressionCPUPermille       uint32                      `json:"pression_cpu_permille"`
	MigrationHybride          bool                        `json:"migration_hybride"`
	CodeRaisonDNS             uint8                       `json:"code_raison_dns"`
	DeltaOctetsReseauEntrants uint64                      `json:"delta_octets_reseau_entrants"`
	DifferentielStructure     string                      `json:"differentiel_structure"`
	DecisionEncodeur          DecisionArbitrageCinetique  `json:"decision_encodeur"`
	DecisionQwen              *DecisionArbitrageCinetique `json:"decision_qwen,omitempty"`
}

// EtapeConfinementResolveurHote consigne les preuves noyau d'une chaîne vivante
// d'évaluation du confinement vers résolveur chiffré et de ses jumeaux bénins.
type EtapeConfinementResolveurHote struct {
	NomChaine             string                  `json:"nom_chaine"`
	AttributionSocket     IdentiteProcessusSocket `json:"attribution_socket"`
	Episode               QuotientsEpisode        `json:"episode"`
	ConfinementResolveur  bool                    `json:"confinement_resolveur"`
	EcouteDNSClairLocale  bool                    `json:"ecoute_dns_clair_locale"`
	ConnexionSansDNS      bool                    `json:"connexion_sans_dns"`
	OrientationMoteur     string                  `json:"orientation_moteur"`
	EscaladeSLM           bool                    `json:"escalade_slm"`
	DifferentielStructure string                  `json:"differentiel_structure"`
}

// RapportConfinementResolveurHote regroupe l'exécution réelle sur sockets loopback,
// inet_diag et /proc des 4 chaînes RAT-03 (tunnel DoQ confiné, forwarder DNS clair
// local, absorption HTTP/3 web et poste DoQ en navigation saine).
type RapportConfinementResolveurHote struct {
	PIDProcessus    int                             `json:"pid_processus"`
	DebutTacheTicks uint64                          `json:"debut_tache_ticks"`
	NomExecutable   string                          `json:"nom_executable"`
	Chaines         []EtapeConfinementResolveurHote `json:"chaines"`
}

// OctetsReseauEntrantsEtape retourne le compteur d'octets réseau entrants mesurés sur une étape de chaîne complète.
func OctetsReseauEntrantsEtape(etape EtapeChaineDetection) uint64 {
	return etape.DeltaOctetsReseauEntrants
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
			NomChaine:                 d.nomChaine,
			AttributionSocket:         d.attribution,
			OrientationMoteur:         d.diagnostic.Orientation.String(),
			EscaladeSLM:               DoitEscaladeSLM(d.diagnostic),
			PressionCPUPermille:       d.diagnostic.Episode.PressionCPUPermille,
			MigrationHybride:          d.diagnostic.Episode.MigrationHybride,
			CodeRaisonDNS:             d.diagnostic.Episode.CodeRaisonDNS,
			DeltaOctetsReseauEntrants: d.diagnostic.Episode.DeltaOctetsReseauEntrants,
			DifferentielStructure:     string(octetsDiff),
			DecisionEncodeur:          decEnc,
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
	_ = clientUDP.SetReadDeadline(time.Now().Add(2 * time.Second))
	portServeurReel := uint16(serveurUDP.LocalAddr().(*net.UDPAddr).Port)
	var tamponTx [512]byte
	var tamponRx [512]byte
	var tamponReponseDNS [512]byte
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

		// Émission réelle d'une réponse DNS RFC 1035 (QR=1, RA=1) par serveurUDP et
		// lecture effective côté clientUDP pour mesurer le volume réseau entrant réel.
		longueurReponse := copy(tamponReponseDNS[:], tamponRx[:nRx])
		if longueurReponse >= 12 {
			tamponReponseDNS[2] |= 0x80
			tamponReponseDNS[3] |= 0x80
		}
		if _, errEcritureReponse := serveurUDP.WriteToUDP(tamponReponseDNS[:longueurReponse], adrExp); errEcritureReponse != nil {
			return QuotientsEpisode{}, IdentiteProcessusSocket{}, errEcritureReponse
		}
		octetsReponseLus, errLectureReponse := clientUDP.Read(tamponReponseDNS[:])
		if errLectureReponse != nil {
			return QuotientsEpisode{}, IdentiteProcessusSocket{}, errLectureReponse
		}

		collecteur.EnregistrerObservationReseau(
			identite.PID,
			identite.DebutTacheTicks,
			uint64(nRx),
			uint64(octetsReponseLus),
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

type modeChaineResolveurHote uint8

const (
	modeCalmeLectureCache modeChaineResolveurHote = iota
	modeTunnelConfine
	modeForwarderLocalDNSClair
	modeAbsorptionHTTP3Web
	modePosteDoQNavigationSaine
)

// ExecuterBancConfinementResolveurHote exécute sur sockets loopback réelles,
// Netlink inet_diag et /proc les 4 chaînes vivantes RAT-03 :
//   - tunnel_doq_confine : confinement exclusif vers résolveur chiffré sans écoute DNS claire locale ;
//   - forwarder_local_dns_clair : relais amont chiffré légitime détenant un port DNS clair local ;
//   - absorption_http3_web : réception massive >= 1 Mio descriptive sans alerte réseau ;
//   - poste_doq_navigation_saine : client DoQ (0 DNS clair) naviguant hors résolveur sans faux positif ConnexionSansDNS.
func ExecuterBancConfinementResolveurHote(
	ctx context.Context,
	dossierTravail string,
) (RapportConfinementResolveurHote, error) {
	var rapport RapportConfinementResolveurHote
	if errCtx := ctx.Err(); errCtx != nil {
		return rapport, errCtx
	}
	if dossierTravail == "" {
		return rapport, fmt.Errorf("cinetique: dossier de travail requis")
	}

	resolveur, errResolveur := OuvrirResolveurSocketProcessus()
	if errResolveur != nil {
		return rapport, errResolveur
	}
	defer func() { _ = resolveur.Fermer() }()

	serveurResolveur, errServeurResolveur := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if errServeurResolveur != nil {
		return rapport, errServeurResolveur
	}
	defer func() { _ = serveurResolveur.Close() }()

	adrServeurResolveur := serveurResolveur.LocalAddr().(*net.UDPAddr)
	clientResolveur, errClientResolveur := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, adrServeurResolveur)
	if errClientResolveur != nil {
		return rapport, errClientResolveur
	}
	defer func() { _ = clientResolveur.Close() }()

	serveurWeb, errSrvWeb := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if errSrvWeb != nil {
		return rapport, errSrvWeb
	}
	defer func() { _ = serveurWeb.Close() }()

	adrServeurWeb := serveurWeb.LocalAddr().(*net.UDPAddr)
	clientWeb, errCliWeb := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, adrServeurWeb)
	if errCliWeb != nil {
		return rapport, errCliWeb
	}
	defer func() { _ = clientWeb.Close() }()

	identiteInitiale, errIdentite := resolveur.ResoudreTupleIPv4(
		unix.IPPROTO_UDP,
		uint16(clientResolveur.LocalAddr().(*net.UDPAddr).Port),
		uint16(adrServeurResolveur.Port),
		0,
	)
	if errIdentite != nil {
		return rapport, fmt.Errorf("cinetique: attribution initiale client resolveur: %w", errIdentite)
	}
	rapport.PIDProcessus = identiteInitiale.PID
	rapport.DebutTacheTicks = identiteInitiale.DebutTacheTicks
	rapport.NomExecutable = identiteInitiale.NomExecutable

	topologie, listeCore, listeAtom := ChargerTopologieHybride()
	coeurPerf, _, errCoeurs := choisirPaireCoeursDisponibles(listeCore, listeAtom)
	if errCoeurs != nil {
		return rapport, errCoeurs
	}

	runtime.LockOSThread()
	tid := unix.Gettid()
	pid := os.Getpid()
	var masqueInitial unix.CPUSet
	errLectureAffinite := unix.SchedGetaffinity(tid, &masqueInitial)
	defer func() {
		if errLectureAffinite == nil {
			_ = unix.SchedSetaffinity(tid, &masqueInitial)
		}
		runtime.UnlockOSThread()
	}()
	if errLectureAffinite != nil {
		return rapport, errLectureAffinite
	}
	if errEpingle := epinglerFilSurCoeur(tid, coeurPerf); errEpingle != nil {
		return rapport, errEpingle
	}

	cheminCacheLecture := filepath.Join(dossierTravail, "confinement_hote_cache_lecture.bin")
	fdCacheLecture, errCache := preparerFichierCacheLecture(cheminCacheLecture, 1<<20)
	if errCache != nil {
		return rapport, errCache
	}
	defer func() {
		_ = unix.Close(fdCacheLecture)
		_ = os.Remove(cheminCacheLecture)
	}()

	cfgPlanchers := ConfigPlanchersParDefaut()
	cfgProfil := ConfigProfilParDefaut()
	cfgProfil.MinEpisodesAmorcage = 8
	cfgProfil.SeuilHausseRelativePct = 80
	table := NouvelleTableProfilsCinetiques(cfgProfil)
	collecteur := NouveauCollecteurReseauParProcessus()

	// Chaîne 0 : tunnel_doq_confine.
	if errCtx := ctx.Err(); errCtx != nil {
		return rapport, errCtx
	}
	cleChaine0 := HashIdentifiantBinaire(identiteInitiale.NomExecutable + ":tunnel_doq_confine")
	if errAmorce := amorcerProfilConfinementHote(
		ctx,
		table,
		cleChaine0,
		resolveur,
		collecteur,
		pid,
		tid,
		fdCacheLecture,
		clientResolveur,
		serveurResolveur,
		clientWeb,
		serveurWeb,
		nil,
		nil,
		topologie,
		cfgPlanchers,
		modeCalmeLectureCache,
	); errAmorce != nil {
		return rapport, errAmorce
	}
	epCh0, attrCh0, errCh0 := executerEpisodeConfinementHote(
		resolveur,
		collecteur,
		pid,
		tid,
		fdCacheLecture,
		clientResolveur,
		serveurResolveur,
		clientWeb,
		serveurWeb,
		nil,
		nil,
		topologie,
		cfgPlanchers,
		modeTunnelConfine,
	)
	if errCh0 != nil {
		return rapport, errCh0
	}
	diagCh0 := table.ObserverEpisode(cleChaine0, 20_000_000, epCh0)
	etapeCh0, errFmt0 := construireEtapeConfinementHote("tunnel_doq_confine", identiteInitiale.NomExecutable, attrCh0, diagCh0)
	if errFmt0 != nil {
		return rapport, errFmt0
	}
	rapport.Chaines = append(rapport.Chaines, etapeCh0)

	// Chaîne 1 : forwarder_local_dns_clair (socket UDP réelle liée sur port DNS clair local, refermée sitôt l'étape finie).
	if errCtx := ctx.Err(); errCtx != nil {
		return rapport, errCtx
	}
	ecouteDNSClair, clientStubLocal, errEcouteDNS := ouvrirPaireForwarderDNSClairLoopback()
	if errEcouteDNS != nil {
		return rapport, errEcouteDNS
	}
	fermerForwarderLocal := func() {
		if clientStubLocal != nil {
			_ = clientStubLocal.Close()
			clientStubLocal = nil
		}
		if ecouteDNSClair != nil {
			_ = ecouteDNSClair.Close()
			ecouteDNSClair = nil
		}
	}
	defer fermerForwarderLocal()

	cleChaine1 := HashIdentifiantBinaire(identiteInitiale.NomExecutable + ":forwarder_local_dns_clair")
	if errAmorce1 := amorcerProfilConfinementHote(
		ctx,
		table,
		cleChaine1,
		resolveur,
		collecteur,
		pid,
		tid,
		fdCacheLecture,
		clientResolveur,
		serveurResolveur,
		clientWeb,
		serveurWeb,
		ecouteDNSClair,
		clientStubLocal,
		topologie,
		cfgPlanchers,
		modeForwarderLocalDNSClair,
	); errAmorce1 != nil {
		return rapport, errAmorce1
	}
	epCh1, attrCh1, errCh1 := executerEpisodeConfinementHote(
		resolveur,
		collecteur,
		pid,
		tid,
		fdCacheLecture,
		clientResolveur,
		serveurResolveur,
		clientWeb,
		serveurWeb,
		ecouteDNSClair,
		clientStubLocal,
		topologie,
		cfgPlanchers,
		modeForwarderLocalDNSClair,
	)
	fermerForwarderLocal()
	if errCh1 != nil {
		return rapport, errCh1
	}
	diagCh1 := table.ObserverEpisode(cleChaine1, 20_000_000, epCh1)
	etapeCh1, errFmt1 := construireEtapeConfinementHote("forwarder_local_dns_clair", identiteInitiale.NomExecutable, attrCh1, diagCh1)
	if errFmt1 != nil {
		return rapport, errFmt1
	}
	rapport.Chaines = append(rapport.Chaines, etapeCh1)

	// Chaîne 2 : absorption_http3_web (>= 1 Mio reçu sur socket web loopback sans écriture bloc).
	if errCtx := ctx.Err(); errCtx != nil {
		return rapport, errCtx
	}
	cleChaine2 := HashIdentifiantBinaire(identiteInitiale.NomExecutable + ":absorption_http3_web")
	if errAmorce2 := amorcerProfilConfinementHote(
		ctx,
		table,
		cleChaine2,
		resolveur,
		collecteur,
		pid,
		tid,
		fdCacheLecture,
		clientResolveur,
		serveurResolveur,
		clientWeb,
		serveurWeb,
		nil,
		nil,
		topologie,
		cfgPlanchers,
		modeAbsorptionHTTP3Web,
	); errAmorce2 != nil {
		return rapport, errAmorce2
	}
	epCh2, attrCh2, errCh2 := executerEpisodeConfinementHote(
		resolveur,
		collecteur,
		pid,
		tid,
		fdCacheLecture,
		clientResolveur,
		serveurResolveur,
		clientWeb,
		serveurWeb,
		nil,
		nil,
		topologie,
		cfgPlanchers,
		modeAbsorptionHTTP3Web,
	)
	if errCh2 != nil {
		return rapport, errCh2
	}
	diagCh2 := table.ObserverEpisode(cleChaine2, 20_000_000, epCh2)
	etapeCh2, errFmt2 := construireEtapeConfinementHote("absorption_http3_web", identiteInitiale.NomExecutable, attrCh2, diagCh2)
	if errFmt2 != nil {
		return rapport, errFmt2
	}
	rapport.Chaines = append(rapport.Chaines, etapeCh2)

	// Chaîne 3 : poste_doq_navigation_saine (DoQ chiffré sans DNS clair + trafic web sortant/entrant).
	if errCtx := ctx.Err(); errCtx != nil {
		return rapport, errCtx
	}
	cleChaine3 := HashIdentifiantBinaire(identiteInitiale.NomExecutable + ":poste_doq_navigation_saine")
	if errAmorce3 := amorcerProfilConfinementHote(
		ctx,
		table,
		cleChaine3,
		resolveur,
		collecteur,
		pid,
		tid,
		fdCacheLecture,
		clientResolveur,
		serveurResolveur,
		clientWeb,
		serveurWeb,
		nil,
		nil,
		topologie,
		cfgPlanchers,
		modePosteDoQNavigationSaine,
	); errAmorce3 != nil {
		return rapport, errAmorce3
	}
	epCh3, attrCh3, errCh3 := executerEpisodeConfinementHote(
		resolveur,
		collecteur,
		pid,
		tid,
		fdCacheLecture,
		clientResolveur,
		serveurResolveur,
		clientWeb,
		serveurWeb,
		nil,
		nil,
		topologie,
		cfgPlanchers,
		modePosteDoQNavigationSaine,
	)
	if errCh3 != nil {
		return rapport, errCh3
	}
	diagCh3 := table.ObserverEpisode(cleChaine3, 20_000_000, epCh3)
	etapeCh3, errFmt3 := construireEtapeConfinementHote("poste_doq_navigation_saine", identiteInitiale.NomExecutable, attrCh3, diagCh3)
	if errFmt3 != nil {
		return rapport, errFmt3
	}
	rapport.Chaines = append(rapport.Chaines, etapeCh3)

	return rapport, nil
}

func construireEtapeConfinementHote(
	nomChaine string,
	nomExecutable string,
	attribution IdentiteProcessusSocket,
	diag DiagnosticEpisodeCinetique,
) (EtapeConfinementResolveurHote, error) {
	var tamponDiff [512]byte
	octetsDiff, errFmt := FormaterDifferentielEpisode(tamponDiff[:0], nomExecutable, diag)
	if errFmt != nil {
		return EtapeConfinementResolveurHote{}, errFmt
	}
	return EtapeConfinementResolveurHote{
		NomChaine:             nomChaine,
		AttributionSocket:     attribution,
		Episode:               diag.Episode,
		ConfinementResolveur:  diag.Episode.ConfinementResolveur,
		EcouteDNSClairLocale:  diag.Episode.EcouteDNSClairLocale,
		ConnexionSansDNS:      diag.Episode.ConnexionSansDNS,
		OrientationMoteur:     diag.Orientation.String(),
		EscaladeSLM:           DoitEscaladeSLM(diag),
		DifferentielStructure: string(octetsDiff),
	}, nil
}

func preparerFichierCacheLecture(chemin string, tailleOctets int) (int, error) {
	fd, errOpen := unix.Open(chemin, unix.O_CREAT|unix.O_RDWR|unix.O_TRUNC|unix.O_CLOEXEC, 0600)
	if errOpen != nil {
		return -1, errOpen
	}
	var page [4096]byte
	for idx := range len(page) {
		page[idx] = byte((idx*19 + 7) & 0xFF)
	}
	for decalage := 0; decalage < tailleOctets; decalage += len(page) {
		page[0] = byte(decalage >> 12)
		if _, errWrite := unix.Pwrite(fd, page[:], int64(decalage)); errWrite != nil {
			_ = unix.Close(fd)
			return -1, errWrite
		}
	}
	return fd, nil
}

func ouvrirPaireForwarderDNSClairLoopback() (*net.UDPConn, *net.UDPConn, error) {
	portsCandidats := [3]int{5354, 5335, 5353}
	var derniereErreur error
	for decalageHote := byte(1); decalageHote <= 24; decalageHote++ {
		ipCandidate := net.IPv4(127, 0, 53, decalageHote)
		if decalageHote == 1 {
			ipCandidate = net.IPv4(127, 0, 0, 1)
		}
		for _, portCandidat := range portsCandidats {
			ecoute, errListen := net.ListenUDP("udp4", &net.UDPAddr{IP: ipCandidate, Port: portCandidat})
			if errListen != nil {
				derniereErreur = errListen
				continue
			}
			adrEcoute := ecoute.LocalAddr().(*net.UDPAddr)
			clientStub, errClient := net.DialUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0}, adrEcoute)
			if errClient != nil {
				_ = ecoute.Close()
				derniereErreur = errClient
				continue
			}
			return ecoute, clientStub, nil
		}
	}
	return nil, nil, fmt.Errorf("cinetique: aucun port DNS clair loopback disponible (5354/5335/5353): %w", derniereErreur)
}

func amorcerProfilConfinementHote(
	ctx context.Context,
	table *TableProfilsCinetiques,
	cleProfil uint64,
	resolveur *ResolveurSocketProcessus,
	collecteur *CollecteurReseauParProcessus,
	pid, tid int,
	fdCacheLecture int,
	clientResolveur, serveurResolveur *net.UDPConn,
	clientWeb, serveurWeb *net.UDPConn,
	ecouteDNSClair, clientStubLocal *net.UDPConn,
	topologie TopologieHybride,
	cfgPlanchers ConfigPlanchersCinetiques,
	mode modeChaineResolveurHote,
) error {
	calmes := 0
	seq := uint64(1)
	for iteration := 0; iteration < 8 || (calmes < 8 && iteration < 24); iteration++ {
		if errCtx := ctx.Err(); errCtx != nil {
			return errCtx
		}
		episode, _, errEp := executerEpisodeConfinementHote(
			resolveur,
			collecteur,
			pid,
			tid,
			fdCacheLecture,
			clientResolveur,
			serveurResolveur,
			clientWeb,
			serveurWeb,
			ecouteDNSClair,
			clientStubLocal,
			topologie,
			cfgPlanchers,
			mode,
		)
		if errEp != nil {
			return errEp
		}
		if !episode.AbstentionPSICPU && !episode.MigrationHybride {
			calmes++
		}
		_ = table.ObserverEpisode(cleProfil, seq*1_000_000, episode)
		seq++
	}
	return nil
}

func executerEpisodeConfinementHote(
	resolveur *ResolveurSocketProcessus,
	collecteur *CollecteurReseauParProcessus,
	pid, tid int,
	fdCacheLecture int,
	clientResolveur, serveurResolveur *net.UDPConn,
	clientWeb, serveurWeb *net.UDPConn,
	ecouteDNSClair, clientStubLocal *net.UDPConn,
	topologie TopologieHybride,
	cfgPlanchers ConfigPlanchersCinetiques,
	mode modeChaineResolveurHote,
) (QuotientsEpisode, IdentiteProcessusSocket, error) {
	capteur := resolveur.CapteurProc()
	echeance := time.Now().Add(2 * time.Second)
	_ = clientResolveur.SetDeadline(echeance)
	_ = serveurResolveur.SetDeadline(echeance)
	_ = clientWeb.SetDeadline(echeance)
	_ = serveurWeb.SetDeadline(echeance)
	if ecouteDNSClair != nil {
		_ = ecouteDNSClair.SetDeadline(echeance)
	}
	if clientStubLocal != nil {
		_ = clientStubLocal.SetDeadline(echeance)
	}

	var blocLecture4K [4096]byte
	var trameResolveur2K [2048]byte
	var trameWeb16K [16384]byte
	var tamponReception16K [16384]byte
	var tamponDNS [512]byte
	for idx := range len(trameResolveur2K) {
		trameResolveur2K[idx] = byte((idx*13 + 5) & 0xFF)
	}
	for idx := range len(trameWeb16K) {
		trameWeb16K[idx] = byte((idx*29 + 11) & 0xFF)
	}

	portServeurResolveur := uint16(serveurResolveur.LocalAddr().(*net.UDPAddr).Port)
	portServeurWeb := uint16(serveurWeb.LocalAddr().(*net.UDPAddr).Port)

	psiDebut, _ := capteur.LirePressionPSI(time.Now().UnixNano())
	snapDebut, errDebut := capteur.LireInstantaneFil(pid, tid, time.Now().UnixNano())
	if errDebut != nil {
		return QuotientsEpisode{}, IdentiteProcessusSocket{}, errDebut
	}

	// Travail CPU + lecture logique de base en mémoire cache OS (zéro écriture bloc disque).
	var condensat [32]byte
	nbLecturesCache := 64
	if mode == modeForwarderLocalDNSClair {
		nbLecturesCache = 256 // 1 Mio lu en cache pour maintenir egress/lecture < 50 permille
	}
	for b := range nbLecturesCache {
		decalage := int64((b * 4096) & ((1 << 20) - 1))
		if _, errRead := unix.Pread(fdCacheLecture, blocLecture4K[:], decalage); errRead != nil {
			return QuotientsEpisode{}, IdentiteProcessusSocket{}, errRead
		}
		if b < 16 {
			blocLecture4K[0] ^= condensat[0]
			condensat = sha256.Sum256(blocLecture4K[:])
		}
	}

	var identiteAttribuee IdentiteProcessusSocket
	var totalSortantsResolveur uint64
	var totalHorsResolveur uint64
	var totalEntrants uint64
	var nbResolutionsDNSClaires uint32
	nouvelleConnHorsResolveur := false
	fluxChiffreObserve := false

	echangerResolveurChiffre := func(nbTrames int, tailleTrame int, tailleReponse int) error {
		for idx := range nbTrames {
			trameResolveur2K[0] = byte(idx)
			trameResolveur2K[1] = condensat[idx&31]
			nEmis, errEmis := clientResolveur.Write(trameResolveur2K[:tailleTrame])
			if errEmis != nil {
				return errEmis
			}
			nSrv, adrExp, errSrv := serveurResolveur.ReadFromUDP(tamponReception16K[:])
			if errSrv != nil {
				return errSrv
			}
			if identiteAttribuee.PID == 0 {
				resolue, errAttr := resolveur.ResoudreTupleIPv4(
					unix.IPPROTO_UDP,
					uint16(adrExp.Port),
					portServeurResolveur,
					0,
				)
				if errAttr != nil {
					return errAttr
				}
				identiteAttribuee = resolue
			}
			_ = nSrv
			if _, errRep := serveurResolveur.WriteToUDP(trameResolveur2K[:tailleReponse], adrExp); errRep != nil {
				return errRep
			}
			nRecus, errCli := clientResolveur.Read(tamponReception16K[:])
			if errCli != nil {
				return errCli
			}
			totalSortantsResolveur += uint64(nEmis)
			totalEntrants += uint64(nRecus)
			fluxChiffreObserve = true
		}
		return nil
	}

	echangerWebHorsResolveur := func(nbTramesSortantes int, tailleSortante int, nbTramesEntrantes int, tailleEntrante int) error {
		var adrClientWeb *net.UDPAddr
		for idx := range nbTramesSortantes {
			trameWeb16K[0] = byte(idx)
			nEmis, errEmis := clientWeb.Write(trameWeb16K[:tailleSortante])
			if errEmis != nil {
				return errEmis
			}
			_, adrExp, errSrv := serveurWeb.ReadFromUDP(tamponReception16K[:])
			if errSrv != nil {
				return errSrv
			}
			adrClientWeb = adrExp
			if identiteAttribuee.PID == 0 {
				resolue, errAttr := resolveur.ResoudreTupleIPv4(
					unix.IPPROTO_UDP,
					uint16(adrExp.Port),
					portServeurWeb,
					0,
				)
				if errAttr != nil {
					return errAttr
				}
				identiteAttribuee = resolue
			}
			totalHorsResolveur += uint64(nEmis)
			nouvelleConnHorsResolveur = true
		}
		for idx := range nbTramesEntrantes {
			trameWeb16K[1] = byte(idx)
			if _, errSrv := serveurWeb.WriteToUDP(trameWeb16K[:tailleEntrante], adrClientWeb); errSrv != nil {
				return errSrv
			}
			nRecus, errCli := clientWeb.Read(tamponReception16K[:])
			if errCli != nil {
				return errCli
			}
			totalEntrants += uint64(nRecus)
		}
		return nil
	}

	switch mode {
	case modeCalmeLectureCache:
		resolue, errAttr := resolveur.ResoudreTupleIPv4(
			unix.IPPROTO_UDP,
			uint16(clientResolveur.LocalAddr().(*net.UDPAddr).Port),
			portServeurResolveur,
			0,
		)
		if errAttr != nil {
			return QuotientsEpisode{}, IdentiteProcessusSocket{}, errAttr
		}
		identiteAttribuee = resolue

	case modeTunnelConfine:
		if errEx := echangerResolveurChiffre(16, 2048, 256); errEx != nil {
			return QuotientsEpisode{}, IdentiteProcessusSocket{}, errEx
		}

	case modeForwarderLocalDNSClair:
		for q := range 4 {
			requeteDNS, errReq := ConstruireRequeteDNSFil(tamponDNS[:0], uint16(0x6100+q), "intranet.exemple.fr", 1)
			if errReq != nil {
				return QuotientsEpisode{}, IdentiteProcessusSocket{}, errReq
			}
			if _, errW := clientStubLocal.Write(requeteDNS); errW != nil {
				return QuotientsEpisode{}, IdentiteProcessusSocket{}, errW
			}
			nDNS, adrStub, errR := ecouteDNSClair.ReadFromUDP(tamponReception16K[:])
			if errR != nil {
				return QuotientsEpisode{}, IdentiteProcessusSocket{}, errR
			}
			if _, okDNS := InspecterDatagrammeDNSFil(tamponReception16K[:nDNS]); okDNS {
				nbResolutionsDNSClaires++
			}
			longueurRep := copy(tamponDNS[:], tamponReception16K[:nDNS])
			if longueurRep >= 12 {
				tamponDNS[2] |= 0x80
				tamponDNS[3] |= 0x80
			}
			if _, errRep := ecouteDNSClair.WriteToUDP(tamponDNS[:longueurRep], adrStub); errRep != nil {
				return QuotientsEpisode{}, IdentiteProcessusSocket{}, errRep
			}
			if _, errStubRead := clientStubLocal.Read(tamponReception16K[:]); errStubRead != nil {
				return QuotientsEpisode{}, IdentiteProcessusSocket{}, errStubRead
			}
		}
		if errEx := echangerResolveurChiffre(16, 2048, 256); errEx != nil {
			return QuotientsEpisode{}, IdentiteProcessusSocket{}, errEx
		}

	case modeAbsorptionHTTP3Web:
		if errEchangeResolveur := echangerResolveurChiffre(2, 2048, 256); errEchangeResolveur != nil {
			return QuotientsEpisode{}, IdentiteProcessusSocket{}, errEchangeResolveur
		}
		// 68 * 16384 = 1 114 112 octets entrants (>= 1 Mio) sans écriture bloc disque.
		if errWeb := echangerWebHorsResolveur(2, 16384, 68, 16384); errWeb != nil {
			return QuotientsEpisode{}, IdentiteProcessusSocket{}, errWeb
		}

	case modePosteDoQNavigationSaine:
		if errEchangeResolveur := echangerResolveurChiffre(2, 2048, 256); errEchangeResolveur != nil {
			return QuotientsEpisode{}, IdentiteProcessusSocket{}, errEchangeResolveur
		}
		if errWeb := echangerWebHorsResolveur(2, 12288, 64, 16384); errWeb != nil {
			return QuotientsEpisode{}, IdentiteProcessusSocket{}, errWeb
		}
	}

	ecouteDNSLocaleActive, errDetect := resolveur.DetecterEcouteDNSClairLocale(
		identiteAttribuee.PID,
		identiteAttribuee.DebutTacheTicks,
	)
	if errDetect != nil {
		return QuotientsEpisode{}, IdentiteProcessusSocket{}, errDetect
	}

	if mode != modeCalmeLectureCache {
		collecteur.EnregistrerObservationResolveur(
			identiteAttribuee.PID,
			identiteAttribuee.DebutTacheTicks,
			totalSortantsResolveur,
			totalHorsResolveur,
			nouvelleConnHorsResolveur,
			ecouteDNSLocaleActive,
			fluxChiffreObserve,
		)
		nouvelleConnGenerale := !nouvelleConnHorsResolveur && totalSortantsResolveur > 0
		collecteur.EnregistrerObservationReseau(
			identiteAttribuee.PID,
			identiteAttribuee.DebutTacheTicks,
			0,
			totalEntrants,
			nouvelleConnGenerale,
			nbResolutionsDNSClaires > 0,
			0,
			false,
			0,
		)
	}

	snapFin, errFin := capteur.LireInstantaneFil(pid, tid, time.Now().UnixNano())
	if errFin != nil {
		return QuotientsEpisode{}, IdentiteProcessusSocket{}, errFin
	}
	psiFin, _ := capteur.LirePressionPSI(time.Now().UnixNano())

	compteurs := collecteur.RecolterEtPurger(identiteAttribuee.PID, identiteAttribuee.DebutTacheTicks)
	episode, errEval := EvaluerEpisodeCinetique(snapDebut, snapFin, psiDebut, psiFin, compteurs, topologie, cfgPlanchers)
	return episode, identiteAttribuee, errEval
}
