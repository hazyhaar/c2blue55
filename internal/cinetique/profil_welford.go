package cinetique

import (
	"errors"
	"math"
	"strconv"
)

const (
	// TailleAnneauRobuste fixe le nombre d'observations récentes retenues par
	// quotient pour le calcul exact sur pile de la médiane et du MADM (0 B/op).
	TailleAnneauRobuste = 32

	nombreEnsemblesProfils = 64
	voiesParEnsembleProfil = 4
)

// ErrTamponTropCourt signale que la capacité du tampon fourni à FormaterDifferentielEpisode
// ne permet pas d'écrire le différentiel complet sans réallocation ni troncature.
var ErrTamponTropCourt = errors.New("cinetique: capacite du tampon insuffisante pour le differentiel complet")

// OrientationCinetique qualifie hors chemin chaud la famille causale dominante
// observée sur l'épisode avant arbitrage éventuel par c2slm.
type OrientationCinetique uint8

const (
	// OrientationAmorcage indique que le profil n'a pas encore atteint le nombre minimal d'épisodes.
	OrientationAmorcage OrientationCinetique = 0
	// OrientationNominale indique que tous les quotients valides demeurent dans leur couloir robuste.
	OrientationNominale OrientationCinetique = 1
	// OrientationAbstention indique qu'une pression CPU PSI ou une migration P/E-core empêche de juger les quotients temporels.
	OrientationAbstention OrientationCinetique = 2
	// OrientationDegradationES désigne l'Archétype A (travail logique stable, dilatation hors-CPU en hausse sans contention CPU ni socket suspecte).
	OrientationDegradationES OrientationCinetique = 3
	// OrientationCompromissionReseau désigne l'Archétype B (dérive CPU/RAM ou egress couplée à une activité socket/DNS anormale).
	OrientationCompromissionReseau OrientationCinetique = 4
	// OrientationDeriveOrganique désigne l'Archétype C (croissance monotone multi-épisodes à quotients structurels constants).
	OrientationDeriveOrganique OrientationCinetique = 5
	// OrientationEcartStructurel désigne un écart franc des quotients logiques sans signature réseau ni blocage E/S pur.
	OrientationEcartStructurel OrientationCinetique = 6
)

// String rend le jeton canonique transmis à l'arbitre c2slm ou au journal SOC.
func (o OrientationCinetique) String() string {
	switch o {
	case OrientationAmorcage:
		return "AMORCAGE_PROFIL"
	case OrientationNominale:
		return "NOMINAL"
	case OrientationAbstention:
		return "ABSTENTION_CONTENTION_OU_MIGRATION"
	case OrientationDegradationES:
		return "DEGRADATION_MATERIELLE_ES"
	case OrientationCompromissionReseau:
		return "COMPROMISSION_OU_EXFILTRATION"
	case OrientationDeriveOrganique:
		return "DERIVE_ORGANIQUE_MONOTONE"
	case OrientationEcartStructurel:
		return "ECART_STRUCTUREL_LOGIQUE"
	default:
		return "INCONNU"
	}
}

// ConfigProfilCinetique paramètre l'apprentissage en ligne et les seuils robustes.
type ConfigProfilCinetique struct {
	MinEpisodesAmorcage    uint32
	SeuilScoreRobusteMilli int64
	SeuilHausseRelativePct int64
	SeuilEgressPermille    int64
	SeuilPasDeriveMonotone uint16
	FigerBaseSurAnomalie   bool
}

// ConfigProfilParDefaut rend une configuration prudente (amorçage 8 épisodes,
// seuil robuste 3,5 sigma équivalent MADM = 3500 millièmes, hausse relative >= 35 %).
func ConfigProfilParDefaut() ConfigProfilCinetique {
	return ConfigProfilCinetique{
		MinEpisodesAmorcage:    8,
		SeuilScoreRobusteMilli: 3500,
		SeuilHausseRelativePct: 35,
		SeuilEgressPermille:    50,
		SeuilPasDeriveMonotone: 5,
		FigerBaseSurAnomalie:   true,
	}
}

// SuiviQuotientRobuste combine l'algorithme de Welford (O(1), 0 B/op) et une
// fenêtre circulaire fixe permettant le calcul exact sur pile de la médiane et du MADM.
type SuiviQuotientRobuste struct {
	NombreObservations uint64
	Moyenne            float64
	M2                 float64
	Anneau             [TailleAnneauRobuste]int64
	CurseurAnneau      uint8
	TailleAnneau       uint8
}

// Enregistrer intègre en 0 B/op une nouvelle observation entière valide.
func (s *SuiviQuotientRobuste) Enregistrer(observation int64) {
	s.NombreObservations++
	obsFlottante := float64(observation)
	ecartAvant := obsFlottante - s.Moyenne
	s.Moyenne += ecartAvant / float64(s.NombreObservations)
	ecartApres := obsFlottante - s.Moyenne
	s.M2 += ecartAvant * ecartApres

	s.Anneau[s.CurseurAnneau] = observation
	s.CurseurAnneau = (s.CurseurAnneau + 1) % TailleAnneauRobuste
	if s.TailleAnneau < TailleAnneauRobuste {
		s.TailleAnneau++
	}
}

// EcartType rend l'écart-type empirique de Welford.
func (s *SuiviQuotientRobuste) EcartType() float64 {
	if s.NombreObservations < 2 {
		return 0
	}
	return math.Sqrt(s.M2 / float64(s.NombreObservations-1))
}

// ZScoreMilli rend le Z-score signé en millièmes d'écart-type.
func (s *SuiviQuotientRobuste) ZScoreMilli(observation int64) int64 {
	sigma := s.EcartType()
	plancher := math.Max(1.0, 0.05*math.Abs(s.Moyenne))
	if sigma < plancher {
		sigma = plancher
	}
	return int64(math.Round(1000.0 * (float64(observation) - s.Moyenne) / sigma))
}

// MedianeEtMADM calcule sur pile en 0 B/op la médiane entière et le MADM entier
// (Median Absolute Deviation from the Median) des observations de l'anneau.
// Pour un effectif pair, la médiane entière utilise l'arrondi par défaut floor((a+b)/2)
// avec une erreur bornée à <= 0,5 unité de virgule fixe.
func (s *SuiviQuotientRobuste) MedianeEtMADM() (mediane int64, madm int64) {
	n := int(s.TailleAnneau)
	if n == 0 {
		return 0, 0
	}
	var copie [TailleAnneauRobuste]int64
	for i := range n {
		copie[i] = s.Anneau[i]
	}
	trierInsertionInt64(copie[:n])
	mediane = medianeTrancheTriee(copie[:n])

	var ecarts [TailleAnneauRobuste]int64
	for i := range n {
		mag := distanceAbsInt64(copie[i], mediane)
		if mag > math.MaxInt64 {
			ecarts[i] = math.MaxInt64
		} else {
			ecarts[i] = int64(mag)
		}
	}
	trierInsertionInt64(ecarts[:n])
	madm = medianeTrancheTriee(ecarts[:n])
	return mediane, madm
}

func magnitudeInt64(v int64) uint64 {
	if v >= 0 {
		return uint64(v)
	}
	return ^uint64(v) + 1
}

func distanceAbsInt64(a, b int64) uint64 {
	if a >= b {
		return uint64(a) - uint64(b)
	}
	return uint64(b) - uint64(a)
}

// EvaluerEcart calcule en 0 B/op et en arithmétique 128 bits sans débordement
// l'écart relatif en pourcent par rapport à la médiane et le score robuste absolu
// en millièmes d'échelle MADM normalisée.
func (s *SuiviQuotientRobuste) EvaluerEcart(observation int64) (variationPct int64, scoreRobusteMilli int64) {
	if s.TailleAnneau == 0 {
		return 0, 0
	}
	mediane, madm := s.MedianeEtMADM()
	absMediane := magnitudeInt64(mediane)
	denomPct := max(absMediane, uint64(1))
	diffMag := distanceAbsInt64(observation, mediane)

	pctAbs := diviserEchelle64(diffMag, 100, denomPct)
	if observation < mediane {
		variationPct = -pctAbs
	} else {
		variationPct = pctAbs
	}

	// Échelle normale équivalente : 1.4826 * MADM ~= (1483 * madm) / 1000,
	// bornée inférieurement à max(1, 5 % de |médiane|) pour éviter une sur-sensibilité
	// sur les compteurs entiers parfaitement constants (ex. blocs fixes de 4096 octets).
	echelle := uint64(diviserEchelle64(magnitudeInt64(madm), 1483, 1000))
	plancher := max(absMediane/20, uint64(1))
	if echelle < plancher {
		echelle = plancher
	}
	scoreRobusteMilli = diviserEchelle64(diffMag, 1000, echelle)
	return variationPct, scoreRobusteMilli
}

func trierInsertionInt64(tranche []int64) {
	for i := 1; i < len(tranche); i++ {
		cle := tranche[i]
		j := i - 1
		for j >= 0 && tranche[j] > cle {
			tranche[j+1] = tranche[j]
			j--
		}
		tranche[j+1] = cle
	}
}

func medianeTrancheTriee(triee []int64) int64 {
	n := len(triee)
	if n == 0 {
		return 0
	}
	milieu := n / 2
	if n%2 == 1 {
		return triee[milieu]
	}
	// Moyenne entière floor((a+b)/2) sans débordement sur deux int64.
	a, b := triee[milieu-1], triee[milieu]
	return (a & b) + ((a ^ b) >> 1)
}

// DiagnosticEpisodeCinetique résume en structure plate (0 B/op) le différentiel
// d'un épisode par rapport à sa ligne de base pour le moteur ou c2slm.
type DiagnosticEpisodeCinetique struct {
	CleExecutable         uint64
	ClasseCoeur           ClasseCoeurCPU
	Orientation           OrientationCinetique
	EpisodesObserves      uint64
	MasqueQuotientsAlerte uint16
	ScoreRobusteMaxMilli  int64
	PasDeriveMonotoneRSS  uint16
	VariationsPct         [NombreQuotientsEpisode]int64
	ScoresRobustesMilli   [NombreQuotientsEpisode]int64
	Episode               QuotientsEpisode
}

type entreeProfilCinetique struct {
	occupee              bool
	cleComposite         uint64
	ordreAcces           uint64
	horodatageAccesNs    uint64
	episodesTotaux       uint64
	dernierPicRSSKio     uint64
	pasHausseMonotoneRSS uint16
	quotients            [NombreQuotientsEpisode]SuiviQuotientRobuste
}

// TableProfilsCinetiques maintient en mémoire bornée (256 profils, 4 voies par
// ensemble, 0 B/op) les références cinétiques par exécutable et classe de coeur.
type TableProfilsCinetiques struct {
	cfg       ConfigProfilCinetique
	seqAcces  uint64
	ensembles [nombreEnsemblesProfils][voiesParEnsembleProfil]entreeProfilCinetique
}

// NouvelleTableProfilsCinetiques alloue une unique fois la table bornée de profils.
func NouvelleTableProfilsCinetiques(cfg ConfigProfilCinetique) *TableProfilsCinetiques {
	return &TableProfilsCinetiques{cfg: cfg}
}

// HashIdentifiantBinaire calcule en 0 B/op un condensat FNV-1a 64 bits d'un chemin ou nom d'exécutable.
func HashIdentifiantBinaire(identifiant string) uint64 {
	const offset64 = 14695981039346656037
	const prime64 = 1099511628211
	empreinte := uint64(offset64)
	for i := 0; i < len(identifiant); i++ {
		empreinte ^= uint64(identifiant[i])
		empreinte *= prime64
	}
	return empreinte
}

func composerCleProfil(cleExecutable uint64, classe ClasseCoeurCPU) uint64 {
	return (cleExecutable &^ uint64(0x3)) | uint64(classe&0x3)
}

// ObserverEpisode compare en 0 B/op un épisode à son profil historique, produit
// le diagnostic différentiel et met à jour la référence selon la politique configurée.
func (t *TableProfilsCinetiques) ObserverEpisode(
	cleExecutable uint64,
	horodatageObservationNs uint64,
	episode QuotientsEpisode,
) DiagnosticEpisodeCinetique {
	classeProfil := episode.ClasseCoeurFin
	if episode.MigrationHybride {
		classeProfil = episode.ClasseCoeurDebut
	}
	cle := composerCleProfil(cleExecutable, classeProfil)
	idxEnsemble := int((cle ^ (cle >> 17)) & (nombreEnsemblesProfils - 1))
	ensemble := &t.ensembles[idxEnsemble]

	t.seqAcces++
	ordreCourant := t.seqAcces

	voieCible := -1
	voieLRU := 0
	plusAncien := ensemble[0].ordreAcces

	for v := range voiesParEnsembleProfil {
		if ensemble[v].occupee && ensemble[v].cleComposite == cle {
			voieCible = v
			break
		}
		if !ensemble[v].occupee {
			voieLRU = v
			plusAncien = 0
			continue
		}
		if plusAncien > 0 && ensemble[v].ordreAcces < plusAncien {
			plusAncien = ensemble[v].ordreAcces
			voieLRU = v
		}
	}
	if voieCible < 0 {
		voieCible = voieLRU
		ensemble[voieCible] = entreeProfilCinetique{
			occupee:      true,
			cleComposite: cle,
		}
	}
	entree := &ensemble[voieCible]
	entree.ordreAcces = ordreCourant
	entree.horodatageAccesNs = horodatageObservationNs

	var diag DiagnosticEpisodeCinetique
	diag.CleExecutable = cleExecutable
	diag.ClasseCoeur = classeProfil
	diag.Episode = episode

	minAmorcage := uint64(t.cfg.MinEpisodesAmorcage)
	minQuorum := max(uint64(4), minAmorcage/2)
	if minAmorcage > 0 && minQuorum > minAmorcage {
		minQuorum = minAmorcage
	}
	abstentionTemporelle := episode.AbstentionPSICPU || episode.MigrationHybride
	enAmorcage := entree.episodesTotaux < minAmorcage
	if !enAmorcage && !abstentionTemporelle {
		quotientsTemporelsValides := 0
		quotientsTemporelsPrets := 0
		for q := range NombreQuotientsEpisode {
			if !episode.EstValide(q) {
				continue
			}
			bitQ := uint16(1) << uint(q)
			if (MasqueQuotientsSensiblesCPU & bitQ) == 0 {
				continue
			}
			quotientsTemporelsValides++
			if entree.quotients[q].NombreObservations >= minQuorum {
				quotientsTemporelsPrets++
			}
		}
		if quotientsTemporelsValides > 0 && quotientsTemporelsPrets == 0 {
			enAmorcage = true
		}
	}

	// Suivi monotone de l'empreinte mémoire résidente retenue hors amorçage (Archétype C) :
	// on suit RSSResidentFinKio (VmRSS en fin d'épisode, avec repli sur PicRSSKio si non renseigné)
	// afin qu'un ancien pic historique VmHWM sur un démon longue durée n'aveugle pas la détection
	// d'une fuite mémoire réelle retenue d'épisode en épisode.
	rssRetenuCourant := episode.RSSResidentFinKio
	if rssRetenuCourant == 0 {
		rssRetenuCourant = episode.PicRSSKio
	}
	pasMonotoneCourant := entree.pasHausseMonotoneRSS
	if enAmorcage {
		pasMonotoneCourant = 0
	} else if rssRetenuCourant > entree.dernierPicRSSKio {
		if pasMonotoneCourant < 65535 {
			pasMonotoneCourant++
		}
	} else {
		pasMonotoneCourant = 0
	}
	diag.PasDeriveMonotoneRSS = pasMonotoneCourant

	if !enAmorcage {
		for q := range NombreQuotientsEpisode {
			if !episode.EstValide(q) {
				continue
			}
			suivi := &entree.quotients[q]
			if suivi.NombreObservations >= minQuorum {
				varPct, scoreMilli := suivi.EvaluerEcart(episode.Valeurs[q])
				diag.VariationsPct[q] = varPct
				diag.ScoresRobustesMilli[q] = scoreMilli

				bitQ := uint16(1) << uint(q)
				ignoreParAbstention := abstentionTemporelle && ((MasqueQuotientsSensiblesCPU & bitQ) != 0)
				absPct := varPct
				if absPct < 0 {
					absPct = -absPct
				}
				if !ignoreParAbstention &&
					scoreMilli >= t.cfg.SeuilScoreRobusteMilli &&
					absPct >= t.cfg.SeuilHausseRelativePct {
					diag.MasqueQuotientsAlerte |= bitQ
					if scoreMilli > diag.ScoreRobusteMaxMilli {
						diag.ScoreRobusteMaxMilli = scoreMilli
					}
				}
			}
		}
	}

	diag.Orientation = determinerOrientation(t.cfg, enAmorcage, abstentionTemporelle, diag)

	// Protection anti-empoisonnement : une anomalie ponctuelle franche (compromission,
	// blocage E/S, écart structurel) n'écrase jamais la ligne de base si FigerBaseSurAnomalie
	// est actif, y compris lorsqu'une compromission survient dès l'amorçage.
	anomalieGelee := t.cfg.FigerBaseSurAnomalie && (diag.Orientation == OrientationCompromissionReseau ||
		diag.Orientation == OrientationDegradationES ||
		diag.Orientation == OrientationEcartStructurel)
	mettreAJourBase := !anomalieGelee

	if mettreAJourBase {
		for q := range NombreQuotientsEpisode {
			if !episode.EstValide(q) {
				continue
			}
			bitQ := uint16(1) << uint(q)
			if abstentionTemporelle && ((MasqueQuotientsSensiblesCPU & bitQ) != 0) {
				continue
			}
			if diag.Orientation == OrientationDeriveOrganique && q == IndiceKioPicRSSParFil {
				continue
			}
			entree.quotients[q].Enregistrer(episode.Valeurs[q])
		}
		entree.episodesTotaux++
		if enAmorcage {
			entree.dernierPicRSSKio = rssRetenuCourant
			entree.pasHausseMonotoneRSS = 0
		}
	}
	// Hors amorçage et hors compromission hostile, le curseur temporel de RAM suit
	// toujours l'évolution réelle afin qu'une fuite rapide (+40 %/pas) ne reste
	// jamais figée à 1 pas derrière FigerBaseSurAnomalie.
	if !enAmorcage && diag.Orientation != OrientationCompromissionReseau {
		entree.dernierPicRSSKio = rssRetenuCourant
		entree.pasHausseMonotoneRSS = pasMonotoneCourant
	}
	diag.EpisodesObserves = entree.episodesTotaux

	return diag
}

func determinerOrientation(
	cfg ConfigProfilCinetique,
	enAmorcage bool,
	abstentionTemporelle bool,
	diag DiagnosticEpisodeCinetique,
) OrientationCinetique {
	const masqueContentionExogene uint16 = (1 << IndiceAttenteOrdonnanceur) | (1 << IndicePartPreemptionPermille)
	const masqueQuotientsESLogiques uint16 = (1 << IndiceOctetsParAppelES) |
		(1 << IndicePartEcriturePermille) |
		(1 << IndiceAmplificationBlocPermille)

	ep := diag.Episode
	preuveHostileIntrinseque := ep.CodeRaisonDNS != 0 || ep.PortSuspect != 0
	indiceReseauSuspect := preuveHostileIntrinseque ||
		ep.ConnexionSansDNS ||
		(ep.EstValide(IndiceEgressSurLecturePermille) && ep.Valeurs[IndiceEgressSurLecturePermille] >= cfg.SeuilEgressPermille)

	// Archétype B prioritaire : une preuve réseau/DNS intrinsèque s'applique dès le
	// premier épisode (même en amorçage), et toute activité suspecte couplée à une
	// hausse mémoire/CPU/egress prime sur la contention CPU.
	alerteCPUouRAMouEgress := (diag.MasqueQuotientsAlerte & ((1 << IndiceNsCPUParKioLogique) |
		(1 << IndiceKioPicRSSParFil) |
		(1 << IndiceEgressSurLecturePermille) |
		(1 << IndiceConnexionsParMilleDNS))) != 0

	if preuveHostileIntrinseque || (!enAmorcage && indiceReseauSuspect && alerteCPUouRAMouEgress) {
		return OrientationCompromissionReseau
	}

	if enAmorcage {
		return OrientationAmorcage
	}

	// Archétype A : dilatation hors-CPU franche accompagnée d'une activité E/S disque réelle,
	// dominant l'exécution CPU (>= 1000 permille) et la file CPU (> 2x runqueue), sans contention.
	alerteDilatation := ep.ActiviteDisquePresente() &&
		(diag.MasqueQuotientsAlerte&(1<<IndiceDilatationHorsCPU)) != 0 &&
		diag.VariationsPct[IndiceDilatationHorsCPU] >= cfg.SeuilHausseRelativePct &&
		ep.Valeurs[IndiceDilatationHorsCPU] >= 1000
	dominanceHorsCPU := ep.DeltaHorsCPUNs > 2*ep.DeltaAttenteFileNs

	if !abstentionTemporelle && !indiceReseauSuspect && alerteDilatation && dominanceHorsCPU {
		return OrientationDegradationES
	}

	// Archétype C (fuite/dérive mémoire monotone) : évalué avant l'écart structurel générique
	// lorsqu'aucun quotient logique E/S ni réseau suspect n'est en alerte, afin qu'une croissance
	// mémoire rapide (> SeuilHausseRelativePct par pas) aboutisse bien à DERIVE_ORGANIQUE_MONOTONE.
	if !indiceReseauSuspect &&
		cfg.SeuilPasDeriveMonotone > 0 &&
		diag.PasDeriveMonotoneRSS >= cfg.SeuilPasDeriveMonotone &&
		(diag.MasqueQuotientsAlerte&masqueQuotientsESLogiques) == 0 {
		return OrientationDeriveOrganique
	}

	// Un sommeil pur sans la moindre opération E/S disque, les fluctuations sous-unitaires
	// de dilatation hors-CPU (< 1000 permille) et la contention exogène de file CPU ne
	// constituent pas un écart structurel logique.
	masqueNonStructurel := masqueContentionExogene
	if !ep.ActiviteDisquePresente() || ep.Valeurs[IndiceDilatationHorsCPU] < 1000 {
		masqueNonStructurel |= 1 << IndiceDilatationHorsCPU
	}
	alertesIntrinseques := diag.MasqueQuotientsAlerte &^ masqueNonStructurel
	if alertesIntrinseques != 0 {
		if ep.DeltaAttenteFileNs >= ep.DeltaExecutionNs && (alertesIntrinseques&^MasqueQuotientsSensiblesCPU) == 0 {
			return OrientationAbstention
		}
		return OrientationEcartStructurel
	}

	if abstentionTemporelle || (ep.DeltaAttenteFileNs >= ep.DeltaExecutionNs && (diag.MasqueQuotientsAlerte&masqueContentionExogene) != 0) {
		return OrientationAbstention
	}

	return OrientationNominale
}

// FormaterDifferentielEpisode sérialise en 0 B/op dans dst[:0] le différentiel
// sémantique structuré destiné à c2slm ou aux journaux d'audit SOC.
// Retourne ErrTamponTropCourt sans rien tronquer si cap(dst) ne suffit pas.
func FormaterDifferentielEpisode(
	dst []byte,
	nomExecutable string,
	diag DiagnosticEpisodeCinetique,
) ([]byte, error) {
	var assemblage [512]byte
	curseur := assemblage[:0]

	curseur = append(curseur, "BIN="...)
	curseur = appendIdentifiantSain(curseur, nomExecutable)
	curseur = append(curseur, "|COEUR="...)
	curseur = append(curseur, diag.ClasseCoeur.String()...)
	curseur = append(curseur, "|ORIENTATION="...)
	curseur = append(curseur, diag.Orientation.String()...)
	curseur = append(curseur, "|RAM_PCT="...)
	curseur = appendPourcentSigne(curseur, diag.VariationsPct[IndiceKioPicRSSParFil])
	curseur = append(curseur, "|CPU_KIO_PCT="...)
	curseur = appendPourcentSigne(curseur, diag.VariationsPct[IndiceNsCPUParKioLogique])
	curseur = append(curseur, "|TAILLE_ES_PCT="...)
	curseur = appendPourcentSigne(curseur, diag.VariationsPct[IndiceOctetsParAppelES])
	curseur = append(curseur, "|AMPLI_BLOC_PCT="...)
	curseur = appendPourcentSigne(curseur, diag.VariationsPct[IndiceAmplificationBlocPermille])
	curseur = append(curseur, "|ATTENTE_ORD_PCT="...)
	curseur = appendPourcentSigne(curseur, diag.VariationsPct[IndiceAttenteOrdonnanceur])
	curseur = append(curseur, "|DILATATION_ES_PCT="...)
	curseur = appendPourcentSigne(curseur, diag.VariationsPct[IndiceDilatationHorsCPU])
	curseur = append(curseur, "|EGRESS_PERMILLE="...)
	curseur = strconv.AppendInt(curseur, diag.Episode.Valeurs[IndiceEgressSurLecturePermille], 10)
	curseur = append(curseur, "|PSI_CPU_PERMILLE="...)
	curseur = strconv.AppendUint(curseur, uint64(diag.Episode.PressionCPUPermille), 10)
	curseur = append(curseur, "|DERIVE_PAS="...)
	curseur = strconv.AppendUint(curseur, uint64(diag.PasDeriveMonotoneRSS), 10)
	curseur = append(curseur, "|SOCKET="...)
	if diag.Episode.PortSuspect > 0 {
		if diag.Episode.ProtocoleSuspectUDP {
			curseur = append(curseur, "UDP/"...)
		} else {
			curseur = append(curseur, "TCP/"...)
		}
		curseur = strconv.AppendUint(curseur, uint64(diag.Episode.PortSuspect), 10)
	} else if diag.Episode.ConnexionSansDNS {
		curseur = append(curseur, "DIRECT_SANS_DNS"...)
	} else {
		curseur = append(curseur, "AUCUNE"...)
	}
	curseur = append(curseur, "|RAISON_DNS="...)
	curseur = strconv.AppendUint(curseur, uint64(diag.Episode.CodeRaisonDNS), 10)

	if cap(dst) < len(curseur) {
		return nil, ErrTamponTropCourt
	}
	sortie := dst[:len(curseur)]
	copy(sortie, curseur)
	return sortie, nil
}

// NombreSondesCalibrationSLM fixe l'effectif de la grille orthogonale d'étalonnage
// marginal d'a priori (Domain-Context Calibration, Fei et al. ACL 2023 & Menon et al. ICLR 2021) :
// 4 sondes équilibrées hors-ligne (1 sonde par classe, soit 25 % chacune, avec répartition
// orthogonale 2/4 entre attente prolongée et attente brève) permettant d'estimer sans biais
// le vecteur de log-a-priori marginal mu_i des 4 jetons candidats.
const NombreSondesCalibrationSLM = 4

// FormaterSondeCalibrationSLM écrit en 0 B/op dans dst[:0] la sonde d'indice idx (0..3)
// de la grille équilibrée de domaine utilisée au chargement de Qwen2.5-0.5B.
func FormaterSondeCalibrationSLM(dst []byte, idx int) ([]byte, error) {
	var sonde string
	switch idx & 3 {
	case 0:
		sonde = "process: demo\ncpu_work_per_kib: NORMAL (+0%)\ndisk_io: ACTIVE (+0%)\noff_cpu_wait: ELEVATED (+400%)\nrss_memory: STABLE\nnetwork_channel: NONE\nhost_cpu_contention: LOW"
	case 1:
		sonde = "process: demo\ncpu_work_per_kib: ELEVATED (+200%)\ndisk_io: ACTIVE (+0%)\noff_cpu_wait: NORMAL (+0%)\nrss_memory: STABLE\nnetwork_channel: ANOMALOUS_SOCKET (UDP/53, dns_code=4)\nhost_cpu_contention: LOW"
	case 2:
		sonde = "process: demo\ncpu_work_per_kib: NORMAL (+0%)\ndisk_io: ACTIVE (+0%)\noff_cpu_wait: NORMAL (+0%)\nrss_memory: MONOTONIC_GROWTH (steps=6)\nnetwork_channel: NONE\nhost_cpu_contention: LOW"
	default:
		sonde = "process: demo\ncpu_work_per_kib: NORMAL (+0%)\ndisk_io: NONE\noff_cpu_wait: ELEVATED (+300%)\nrss_memory: STABLE\nnetwork_channel: BENIGN\nhost_cpu_contention: HIGH"
	}
	if cap(dst) < len(sonde) {
		return nil, ErrTamponTropCourt
	}
	sortie := dst[:len(sonde)]
	copy(sortie, sonde)
	return sortie, nil
}

// FormaterBriefCausalSLM sérialise en 0 B/op dans dst[:0] les observables physiques
// par capteur selon ConfigProfilParDefaut().
func FormaterBriefCausalSLM(
	dst []byte,
	nomExecutable string,
	diag DiagnosticEpisodeCinetique,
) ([]byte, error) {
	return FormaterBriefCausalSLMAvecConfig(dst, nomExecutable, diag, ConfigProfilParDefaut())
}

// FormaterBriefCausalSLMAvecConfig sérialise en 0 B/op dans dst[:0] six observables
// physiques indépendants (un par famille de capteur, paramétrés par cfg, avec identifiant
// constant neutre "demo" excluant toute fuite lexicale par le nom du binaire et sans libellé
// de conclusion pré-jugé) afin que c2slm arbitre par croisement multi-capteurs. L'identité
// réelle du binaire demeure portée hors prompt dans DossierEscaladeCinetique et FormaterDifferentielEpisode.
func FormaterBriefCausalSLMAvecConfig(
	dst []byte,
	_ string,
	diag DiagnosticEpisodeCinetique,
	cfg ConfigProfilCinetique,
) ([]byte, error) {
	var assemblage [512]byte
	curseur := assemblage[:0]
	ep := diag.Episode

	seuilPct := cfg.SeuilHausseRelativePct
	if seuilPct <= 0 {
		seuilPct = 35
	}
	seuilEgress := cfg.SeuilEgressPermille
	if seuilEgress <= 0 {
		seuilEgress = 50
	}
	seuilPas := cfg.SeuilPasDeriveMonotone
	if seuilPas == 0 {
		seuilPas = 5
	}

	curseur = append(curseur, "process: demo"...)

	// Capteur 1 : travail CPU consommé par Kio logique traité.
	curseur = append(curseur, "\ncpu_work_per_kib: "...)
	varCPU := diag.VariationsPct[IndiceNsCPUParKioLogique]
	if varCPU >= seuilPct {
		curseur = append(curseur, "ELEVATED ("...)
	} else if varCPU <= -seuilPct {
		curseur = append(curseur, "REDUCED ("...)
	} else {
		curseur = append(curseur, "NORMAL ("...)
	}
	curseur = appendPourcentSigne(curseur, varCPU)
	curseur = append(curseur, ')')

	// Capteur 2 : activité E/S disque effective (/proc/[pid]/io) et régularité par appel.
	curseur = append(curseur, "\ndisk_io: "...)
	varTaille := diag.VariationsPct[IndiceOctetsParAppelES]
	if !ep.ActiviteDisquePresente() {
		curseur = append(curseur, "NONE"...)
	} else if varTaille >= seuilPct || varTaille <= -seuilPct {
		curseur = append(curseur, "SHIFTED ("...)
		curseur = appendPourcentSigne(curseur, varTaille)
		curseur = append(curseur, ')')
	} else {
		curseur = append(curseur, "ACTIVE ("...)
		curseur = appendPourcentSigne(curseur, varTaille)
		curseur = append(curseur, ')')
	}

	// Capteur 3 : attente hors-CPU et hors file d'ordonnancement (sommeil, verrou, réseau ou bloc).
	curseur = append(curseur, "\noff_cpu_wait: "...)
	varDilat := diag.VariationsPct[IndiceDilatationHorsCPU]
	attenteElevee := varDilat >= seuilPct && ep.Valeurs[IndiceDilatationHorsCPU] >= 1000 && ep.DeltaHorsCPUNs > 2*ep.DeltaAttenteFileNs
	if attenteElevee {
		curseur = append(curseur, "ELEVATED ("...)
	} else {
		curseur = append(curseur, "NORMAL ("...)
	}
	curseur = appendPourcentSigne(curseur, varDilat)
	curseur = append(curseur, ')')

	// Capteur 4 : trajectoire de la mémoire résidente VmRSS.
	curseur = append(curseur, "\nrss_memory: "...)
	varRAM := diag.VariationsPct[IndiceKioPicRSSParFil]
	if diag.PasDeriveMonotoneRSS >= seuilPas {
		curseur = append(curseur, "MONOTONIC_GROWTH (steps="...)
		curseur = strconv.AppendUint(curseur, uint64(diag.PasDeriveMonotoneRSS), 10)
		curseur = append(curseur, ')')
	} else if varRAM >= seuilPct {
		curseur = append(curseur, "STEP_SPIKE ("...)
		curseur = appendPourcentSigne(curseur, varRAM)
		curseur = append(curseur, ')')
	} else {
		curseur = append(curseur, "STABLE"...)
	}

	// Capteur 5 : activité socket sortante et inspection filaire DNS attribuée au processus.
	curseur = append(curseur, "\nnetwork_channel: "...)
	egressImportant := ep.EstValide(IndiceEgressSurLecturePermille) && ep.Valeurs[IndiceEgressSurLecturePermille] >= seuilEgress
	if ep.PortSuspect > 0 || ep.CodeRaisonDNS > 0 || ep.ConnexionSansDNS || egressImportant {
		curseur = append(curseur, "ANOMALOUS_SOCKET ("...)
		if ep.PortSuspect > 0 {
			if ep.ProtocoleSuspectUDP {
				curseur = append(curseur, "UDP/"...)
			} else {
				curseur = append(curseur, "TCP/"...)
			}
			curseur = strconv.AppendUint(curseur, uint64(ep.PortSuspect), 10)
		} else if ep.ConnexionSansDNS {
			curseur = append(curseur, "DIRECT_IP_NO_DNS"...)
		} else {
			curseur = append(curseur, "HIGH_EGRESS"...)
		}
		curseur = append(curseur, ", dns_code="...)
		curseur = strconv.AppendUint(curseur, uint64(ep.CodeRaisonDNS), 10)
		curseur = append(curseur, ')')
	} else if !ep.OctetsSortantsNuls() || ep.ConnexionsSortantes > 0 {
		curseur = append(curseur, "BENIGN"...)
	} else {
		curseur = append(curseur, "NONE"...)
	}

	// Capteur 6 : distorsion d'attente par contention CPU de l'hôte ou migration hybride
	// (pertinente lorsqu'une attente hors-CPU élevée est observée sur l'épisode).
	curseur = append(curseur, "\nhost_cpu_contention: "...)
	contentionHote := ep.AbstentionPSICPU || ep.MigrationHybride || (ep.DeltaExecutionNs > 0 && ep.DeltaAttenteFileNs >= ep.DeltaExecutionNs)
	if contentionHote && attenteElevee {
		curseur = append(curseur, "HIGH"...)
	} else {
		curseur = append(curseur, "LOW"...)
	}

	if cap(dst) < len(curseur) {
		return nil, ErrTamponTropCourt
	}
	sortie := dst[:len(curseur)]
	copy(sortie, curseur)
	return sortie, nil
}

func appendPourcentSigne(dst []byte, pct int64) []byte {
	if pct >= 0 {
		dst = append(dst, '+')
	}
	dst = strconv.AppendInt(dst, pct, 10)
	dst = append(dst, '%')
	return dst
}

func appendIdentifiantSain(dst []byte, texte string) []byte {
	if len(texte) == 0 {
		return append(dst, "inconnu"...)
	}
	limite := min(len(texte), 48)
	for i := range limite {
		c := texte[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' {
			dst = append(dst, c)
		} else {
			dst = append(dst, '_')
		}
	}
	return dst
}
