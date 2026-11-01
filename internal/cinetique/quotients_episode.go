package cinetique

import (
	"errors"
	"math"
	"math/bits"
)

// Indices canoniques des 10 quotients invariants d'épisode.
const (
	IndiceOctetsParAppelES          = 0
	IndicePartEcriturePermille      = 1
	IndiceAmplificationBlocPermille = 2
	IndiceNsCPUParKioLogique        = 3
	IndiceKioPicRSSParFil           = 4
	IndiceEgressSurLecturePermille  = 5
	IndiceConnexionsParMilleDNS     = 6
	IndicePartPreemptionPermille    = 7
	IndiceAttenteOrdonnanceur       = 8
	IndiceDilatationHorsCPU         = 9

	NombreQuotientsEpisode = 10
)

// Masque des quotients sensibles à la contention CPU ou à une migration P/E-core.
const MasqueQuotientsSensiblesCPU uint16 = (1 << IndiceNsCPUParKioLogique) |
	(1 << IndicePartPreemptionPermille) |
	(1 << IndiceAttenteOrdonnanceur) |
	(1 << IndiceDilatationHorsCPU)

var (
	// ErrReutilisationPID signale une discordance de PID ou de starttime entre début et fin.
	ErrReutilisationPID = errors.New("cinetique: discordance PID ou starttime (reutilisation de PID detectee)")
	// ErrHorlogeNonMonotone signale un intervalle temporel nul ou négatif.
	ErrHorlogeNonMonotone = errors.New("cinetique: horodatage d'episode non monotone")
	// ErrCompteurNonMonotone signale le recul d'un compteur cumulatif noyau.
	ErrCompteurNonMonotone = errors.New("cinetique: recul d'un compteur cumulatif noyau")
)

// NomQuotient rend l'identifiant stable d'un indice de quotient pour les rapports.
func NomQuotient(indice int) string {
	switch indice {
	case IndiceOctetsParAppelES:
		return "octets_par_appel_es"
	case IndicePartEcriturePermille:
		return "part_ecriture_permille"
	case IndiceAmplificationBlocPermille:
		return "amplification_bloc_permille"
	case IndiceNsCPUParKioLogique:
		return "ns_cpu_par_kio_logique"
	case IndiceKioPicRSSParFil:
		return "kio_pic_rss_par_fil"
	case IndiceEgressSurLecturePermille:
		return "egress_sur_lecture_permille"
	case IndiceConnexionsParMilleDNS:
		return "connexions_par_mille_dns"
	case IndicePartPreemptionPermille:
		return "part_preemption_permille"
	case IndiceAttenteOrdonnanceur:
		return "attente_ordonnanceur_permille"
	case IndiceDilatationHorsCPU:
		return "dilatation_hors_cpu_permille"
	default:
		return "quotient_inconnu"
	}
}

// ConfigPlanchersCinetiques fixe les dénominateurs minimaux requis pour valider
// chaque famille de quotient et le plafond d'abstention PSI CPU.
type ConfigPlanchersCinetiques struct {
	MinAppelsES           uint64
	MinOctetsLogiques     uint64
	MinTempsExecutionNs   uint64
	MinCommutations       uint64
	MinResolutionsDNS     uint64
	PlafondPSICPUPermille uint32
}

// ConfigPlanchersParDefaut fournit des seuils prudents évitant toute division
// sur bruit de repos tout en acceptant des épisodes courts calibrés.
func ConfigPlanchersParDefaut() ConfigPlanchersCinetiques {
	return ConfigPlanchersCinetiques{
		MinAppelsES:           4,
		MinOctetsLogiques:     1024,
		MinTempsExecutionNs:   100_000, // 100 microsecondes d'exécution effective
		MinCommutations:       4,
		MinResolutionsDNS:     1,
		PlafondPSICPUPermille: 200, // abstention au-delà de 20 % de pression CPU some
	}
}

// CompteursReseauEpisode transporte hors bande les compteurs réseau et DNS
// agrégés sur la même fenêtre temporelle que l'épisode processus.
type CompteursReseauEpisode struct {
	OctetsSortants      uint64
	OctetsEntrants      uint64
	ConnexionsSortantes uint32
	ResolutionsDNS      uint32
	SousProcessusCrees  uint32
	PortSuspect         uint16
	ProtocoleSuspectUDP bool
	CodeRaisonDNS       uint8
}

// QuotientsEpisode rassemble les variations brutes vérifiées et les 10 quotients
// invariants à virgule fixe d'un épisode d'exécution.
type QuotientsEpisode struct {
	PID                       int
	DebutTacheTicks           uint64
	DureeHorlogeNs            uint64
	DeltaExecutionNs          uint64
	DeltaAttenteFileNs        uint64
	DeltaHorsCPUNs            uint64
	DeltaOctetsLusLogiques    uint64
	DeltaOctetsEcritsLog      uint64
	DeltaOctetsBloc           uint64
	DeltaOctetsReseauSortants uint64
	DeltaOctetsReseauEntrants uint64
	PicRSSKio                 uint64
	RSSResidentFinKio         uint64
	UnitesConcurrence         uint32
	ConnexionsSortantes       uint32
	ResolutionsDNS            uint32
	PressionCPUPermille       uint32
	PressionIOPermille        uint32
	ClasseCoeurDebut          ClasseCoeurCPU
	ClasseCoeurFin            ClasseCoeurCPU
	MigrationHybride          bool
	AbstentionPSICPU          bool
	ConnexionSansDNS          bool
	PortSuspect               uint16
	ProtocoleSuspectUDP       bool
	CodeRaisonDNS             uint8
	MasqueValidite            uint16
	Valeurs                   [NombreQuotientsEpisode]int64
}

// EstValide indique si le quotient d'indice donné a franchi son plancher d'activité.
func (q QuotientsEpisode) EstValide(indice int) bool {
	if indice < 0 || indice >= NombreQuotientsEpisode {
		return false
	}
	return (q.MasqueValidite & (uint16(1) << uint(indice))) != 0
}

// ActiviteDisquePresente indique si au moins un octet logique ou bloc a été transféré sur l'épisode.
func (q QuotientsEpisode) ActiviteDisquePresente() bool {
	return q.DeltaOctetsLusLogiques > 0 || q.DeltaOctetsEcritsLog > 0 || q.DeltaOctetsBloc > 0
}

// OctetsSortantsNuls indique qu'aucun octet réseau sortant n'a été observé sur l'épisode,
// indépendamment du franchissement éventuel du plancher de lecture disque (MinOctetsLogiques).
func (q QuotientsEpisode) OctetsSortantsNuls() bool {
	if q.DeltaOctetsReseauSortants > 0 {
		return false
	}
	return !q.EstValide(IndiceEgressSurLecturePermille) || q.Valeurs[IndiceEgressSurLecturePermille] <= 0
}

// AucuneActiviteReseau indique l'absence totale d'octets échangés, de sockets sortantes et d'indices DNS.
func (q QuotientsEpisode) AucuneActiviteReseau() bool {
	return q.OctetsSortantsNuls() &&
		q.DeltaOctetsReseauEntrants == 0 &&
		q.ConnexionsSortantes == 0 &&
		q.ResolutionsDNS == 0 &&
		q.PortSuspect == 0 &&
		q.CodeRaisonDNS == 0 &&
		!q.ConnexionSansDNS
}

func additionnerSatureU64(a, b uint64) uint64 {
	somme, retenue := bits.Add64(a, b, 0)
	if retenue != 0 {
		return math.MaxUint64
	}
	return somme
}

func additionnerSatureU32(a, b uint32) uint32 {
	if uint64(a)+uint64(b) > math.MaxUint32 {
		return math.MaxUint32
	}
	return a + b
}

// EvaluerEpisodeCinetique calcule en 0 B/op et en arithmétique 128 bits sans
// débordement les quotients invariants entre deux instantanés de la même tâche.
func EvaluerEpisodeCinetique(
	debut, fin InstantaneTache,
	psiDebut, psiFin InstantanePressionPSI,
	reseau CompteursReseauEpisode,
	topologie TopologieHybride,
	cfg ConfigPlanchersCinetiques,
) (QuotientsEpisode, error) {
	var bilan QuotientsEpisode
	if debut.PID <= 0 || debut.PID != fin.PID || debut.DebutTacheTicks != fin.DebutTacheTicks {
		return bilan, ErrReutilisationPID
	}
	if fin.HorodatageNs <= debut.HorodatageNs {
		return bilan, ErrHorlogeNonMonotone
	}
	if !compteursMonotones(debut, fin) {
		return bilan, ErrCompteurNonMonotone
	}

	dureeHorlogeNs := uint64(fin.HorodatageNs - debut.HorodatageNs)
	deltaExecNs := fin.TempsExecutionNs - debut.TempsExecutionNs
	deltaAttenteNs := fin.AttenteFileNs - debut.AttenteFileNs
	var deltaHorsCPUNs uint64
	occupesNs := additionnerSatureU64(deltaExecNs, deltaAttenteNs)
	if dureeHorlogeNs > occupesNs {
		deltaHorsCPUNs = dureeHorlogeNs - occupesNs
	}

	deltaLusLog := fin.OctetsLusLogiques - debut.OctetsLusLogiques
	deltaEcritsLog := fin.OctetsEcritsLogiques - debut.OctetsEcritsLogiques
	deltaTotalLog := additionnerSatureU64(deltaLusLog, deltaEcritsLog)

	deltaAppelsES := additionnerSatureU64(
		fin.AppelsLecture-debut.AppelsLecture,
		fin.AppelsEcriture-debut.AppelsEcriture,
	)
	deltaBloc := additionnerSatureU64(
		fin.OctetsLusBloc-debut.OctetsLusBloc,
		fin.OctetsEcritsBloc-debut.OctetsEcritsBloc,
	)
	deltaVolontaires := fin.CommutationsVolontaires - debut.CommutationsVolontaires
	deltaSubies := fin.CommutationsSubies - debut.CommutationsSubies
	deltaCommutations := additionnerSatureU64(deltaVolontaires, deltaSubies)

	picRSS := max(fin.VmRSSKio, fin.VmHWMKio)
	rssRetenu := fin.VmRSSKio
	if rssRetenu == 0 {
		rssRetenu = picRSS
	}
	concurrence := additionnerSatureU32(fin.NombreFils, reseau.SousProcessusCrees)
	if concurrence == 0 {
		concurrence = 1
	}

	bilan.PID = fin.PID
	bilan.DebutTacheTicks = fin.DebutTacheTicks
	bilan.DureeHorlogeNs = dureeHorlogeNs
	bilan.DeltaExecutionNs = deltaExecNs
	bilan.DeltaAttenteFileNs = deltaAttenteNs
	bilan.DeltaHorsCPUNs = deltaHorsCPUNs
	bilan.DeltaOctetsLusLogiques = deltaLusLog
	bilan.DeltaOctetsEcritsLog = deltaEcritsLog
	bilan.DeltaOctetsBloc = deltaBloc
	bilan.DeltaOctetsReseauSortants = reseau.OctetsSortants
	bilan.DeltaOctetsReseauEntrants = reseau.OctetsEntrants
	bilan.PicRSSKio = picRSS
	bilan.RSSResidentFinKio = rssRetenu
	bilan.UnitesConcurrence = concurrence
	bilan.ConnexionsSortantes = reseau.ConnexionsSortantes
	bilan.ResolutionsDNS = reseau.ResolutionsDNS
	bilan.ClasseCoeurDebut = topologie.ClasseDuCoeur(int(debut.CoeurDerniereExecution))
	bilan.ClasseCoeurFin = topologie.ClasseDuCoeur(int(fin.CoeurDerniereExecution))
	if topologie.EstHybride &&
		bilan.ClasseCoeurDebut != ClasseCoeurInconnue &&
		bilan.ClasseCoeurFin != ClasseCoeurInconnue &&
		bilan.ClasseCoeurDebut != bilan.ClasseCoeurFin {
		bilan.MigrationHybride = true
	}
	bilan.ConnexionSansDNS = reseau.ConnexionsSortantes > 0 && reseau.ResolutionsDNS == 0
	bilan.PortSuspect = reseau.PortSuspect
	bilan.ProtocoleSuspectUDP = reseau.ProtocoleSuspectUDP
	bilan.CodeRaisonDNS = reseau.CodeRaisonDNS

	// Pression PSI sur l'intervalle si l'échantillon PSI est valide et monotone.
	if psiFin.HorodatageNs > psiDebut.HorodatageNs {
		dureePSIUs := uint64(psiFin.HorodatageNs-psiDebut.HorodatageNs) / 1000
		if dureePSIUs > 0 {
			if psiFin.CPUSomeTotalUs >= psiDebut.CPUSomeTotalUs {
				deltaCPUSome := psiFin.CPUSomeTotalUs - psiDebut.CPUSomeTotalUs
				pressionCPU := min(diviserEchelle64(deltaCPUSome, 1000, dureePSIUs), 1000)
				bilan.PressionCPUPermille = uint32(pressionCPU)
			}
			if psiFin.IOSomeTotalUs >= psiDebut.IOSomeTotalUs {
				deltaIOSome := psiFin.IOSomeTotalUs - psiDebut.IOSomeTotalUs
				pressionIO := min(diviserEchelle64(deltaIOSome, 1000, dureePSIUs), 1000)
				bilan.PressionIOPermille = uint32(pressionIO)
			}
		}
	} else if psiFin.CPUSomeAvg10Cent > 0 {
		// Repli explicite sur avg10 converti en permille (100.00 % = 10000 centièmes -> 1000 permille).
		bilan.PressionCPUPermille = psiFin.CPUSomeAvg10Cent / 10
	}
	if cfg.PlafondPSICPUPermille > 0 && bilan.PressionCPUPermille > cfg.PlafondPSICPUPermille {
		bilan.AbstentionPSICPU = true
	}

	if deltaAppelsES >= cfg.MinAppelsES && deltaAppelsES > 0 {
		bilan.Valeurs[IndiceOctetsParAppelES] = diviserEchelle64(deltaTotalLog, 1, deltaAppelsES)
		bilan.MasqueValidite |= 1 << IndiceOctetsParAppelES
	}
	if deltaTotalLog >= cfg.MinOctetsLogiques && deltaTotalLog > 0 {
		bilan.Valeurs[IndicePartEcriturePermille] = diviserEchelle64(deltaEcritsLog, 1000, deltaTotalLog)
		bilan.MasqueValidite |= 1 << IndicePartEcriturePermille

		bilan.Valeurs[IndiceAmplificationBlocPermille] = diviserEchelle64(deltaBloc, 1000, deltaTotalLog)
		bilan.MasqueValidite |= 1 << IndiceAmplificationBlocPermille

		bilan.Valeurs[IndiceNsCPUParKioLogique] = diviserEchelle64(deltaExecNs, 1024, deltaTotalLog)
		bilan.MasqueValidite |= 1 << IndiceNsCPUParKioLogique
	}
	if picRSS > 0 {
		bilan.Valeurs[IndiceKioPicRSSParFil] = diviserEchelle64(picRSS, 1, uint64(concurrence))
		bilan.MasqueValidite |= 1 << IndiceKioPicRSSParFil
	}
	if deltaLusLog >= cfg.MinOctetsLogiques && deltaLusLog > 0 {
		bilan.Valeurs[IndiceEgressSurLecturePermille] = diviserEchelle64(reseau.OctetsSortants, 1000, deltaLusLog)
		bilan.MasqueValidite |= 1 << IndiceEgressSurLecturePermille
	}
	if uint64(reseau.ResolutionsDNS) >= cfg.MinResolutionsDNS && reseau.ResolutionsDNS > 0 {
		bilan.Valeurs[IndiceConnexionsParMilleDNS] = diviserEchelle64(
			uint64(reseau.ConnexionsSortantes),
			1000,
			uint64(reseau.ResolutionsDNS),
		)
		bilan.MasqueValidite |= 1 << IndiceConnexionsParMilleDNS
	}
	if deltaCommutations >= cfg.MinCommutations && deltaCommutations > 0 {
		bilan.Valeurs[IndicePartPreemptionPermille] = diviserEchelle64(deltaSubies, 1000, deltaCommutations)
		bilan.MasqueValidite |= 1 << IndicePartPreemptionPermille
	}
	if deltaExecNs >= cfg.MinTempsExecutionNs && deltaExecNs > 0 {
		bilan.Valeurs[IndiceAttenteOrdonnanceur] = diviserEchelle64(deltaAttenteNs, 1000, deltaExecNs)
		bilan.MasqueValidite |= 1 << IndiceAttenteOrdonnanceur

		bilan.Valeurs[IndiceDilatationHorsCPU] = diviserEchelle64(deltaHorsCPUNs, 1000, deltaExecNs)
		bilan.MasqueValidite |= 1 << IndiceDilatationHorsCPU
	}

	return bilan, nil
}

func compteursMonotones(debut, fin InstantaneTache) bool {
	return fin.TempsExecutionNs >= debut.TempsExecutionNs &&
		fin.AttenteFileNs >= debut.AttenteFileNs &&
		fin.TranchesOrdonnanceur >= debut.TranchesOrdonnanceur &&
		fin.OctetsLusLogiques >= debut.OctetsLusLogiques &&
		fin.OctetsEcritsLogiques >= debut.OctetsEcritsLogiques &&
		fin.AppelsLecture >= debut.AppelsLecture &&
		fin.AppelsEcriture >= debut.AppelsEcriture &&
		fin.OctetsLusBloc >= debut.OctetsLusBloc &&
		fin.OctetsEcritsBloc >= debut.OctetsEcritsBloc &&
		fin.CommutationsVolontaires >= debut.CommutationsVolontaires &&
		fin.CommutationsSubies >= debut.CommutationsSubies &&
		fin.UtilisateurTicks >= debut.UtilisateurTicks &&
		fin.SystemeTicks >= debut.SystemeTicks
}

// diviserEchelle64 calcule floor((numerateur * facteur) / denominateur) en
// arithmétique entière 128 bits saturée à math.MaxInt64 sans débordement.
func diviserEchelle64(numerateur, facteur, denominateur uint64) int64 {
	if denominateur == 0 || numerateur == 0 || facteur == 0 {
		return 0
	}
	haut, bas := bits.Mul64(numerateur, facteur)
	if haut >= denominateur {
		return math.MaxInt64
	}
	quotient, _ := bits.Div64(haut, bas, denominateur)
	if quotient > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(quotient)
}
