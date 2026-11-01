package c2blue55

import (
	"cmp"
	"fmt"
	"math"
	"slices"
)

// Orientation : +1 quand la croissance du trait va vers l'hostilité.
var orientationTraitsChiffres = [NombreTraitsChiffres]float64{-1, -1, +1, +1, +1, +1, +1, +1, -1}

// Planchers d'échelle robustes, en unités du trait, pour un MAD nul.
var plancherEchelleTraitsChiffres = [NombreTraitsChiffres]float64{0.5, 0.05, 0.1, 0.10, 0.5, 0.5, 0.25, 0.25, 0.25}

const (
	ecartRobusteBorne        = 8.0
	quantileSeuilBenin       = 0.99
	effectifBeninSeuilMin    = 20
	effectifClasseAUCMinimal = 20
	// asymetrieBaliseMax : une balise ne télécharge pas (descendant <= 16 × montant).
	asymetrieBaliseMax = 4.0
	// asymetrieTunnelPolleMax et quasiMTUTunnelPolleMax délimitent l'enveloppe
	// d'un tunnel DNS pollé au-delà de laquelle s'applique la pénalité de téléchargement.
	asymetrieTunnelPolleMax = 3.0
	quasiMTUTunnelPolleMax  = 0.60
	// plancherSeuilDecision : une conversation n'est condamnée que si sa branche
	// dépasse d'au moins 2 écarts robustes la référence bénigne.
	// Une famille bénigne inédite, absente de la calibration, ne doit pas
	// abaisser le seuil vers zéro (constat du LOFO strict synthétique).
	plancherSeuilDecision = 2.0
)

// EncryptedWireCalibration est la calibration robuste apprise sur des
// conversations bénignes seulement : médianes, échelles 1,4826·MAD planchées
// et seuil au quantile 0,99 des scores bénins d'apprentissage.
type EncryptedWireCalibration struct {
	Mediane              [NombreTraitsChiffres]float64
	Echelle              [NombreTraitsChiffres]float64
	SeuilDecision        float64
	EffectifBenin        int
	InsuffisantPourSeuil bool
}

// EncryptedWireSample est une conversation jugeable et étiquetée du laboratoire.
type EncryptedWireSample struct {
	Famille       string
	RunID         string
	Hostile       bool
	RegimeAttendu EncryptedRegime
	RegimeConnu   bool
	Verdict       ConversationVerdict
}

// CalibrateEncryptedWire calibre sur les vecteurs bénins fournis.
func CalibrateEncryptedWire(vecteursBenins []KineticVector) (EncryptedWireCalibration, error) {
	calibrage := EncryptedWireCalibration{EffectifBenin: len(vecteursBenins)}
	if len(vecteursBenins) == 0 {
		return calibrage, fmt.Errorf("%w: aucune conversation bénigne d'apprentissage", ErrEncryptedWireContract)
	}
	colonne := make([]float64, len(vecteursBenins))
	for trait := range NombreTraitsChiffres {
		for indice := range vecteursBenins {
			colonne[indice] = vecteursBenins[indice].Traits()[trait]
		}
		mediane := medianeTriee(colonne)
		for indice := range colonne {
			colonne[indice] = math.Abs(colonne[indice] - mediane)
		}
		calibrage.Mediane[trait] = mediane
		calibrage.Echelle[trait] = max(1.4826*medianeTriee(colonne), plancherEchelleTraitsChiffres[trait])
	}
	scoresBenins := make([]float64, len(vecteursBenins))
	for indice := range vecteursBenins {
		scoresBenins[indice] = ScoreEncryptedWire(&vecteursBenins[indice], &calibrage)
	}
	slices.Sort(scoresBenins)
	calibrage.InsuffisantPourSeuil = len(scoresBenins) < effectifBeninSeuilMin
	rang := int(math.Ceil(quantileSeuilBenin*float64(len(scoresBenins)))) - 1
	if calibrage.InsuffisantPourSeuil {
		rang = len(scoresBenins) - 1
	}
	calibrage.SeuilDecision = assainirFlottantChiffre(max(math.Nextafter(scoresBenins[max(rang, 0)], math.Inf(1)), plancherSeuilDecision))
	return calibrage, nil
}

// medianeTriee trie colonne en place et rend sa médiane.
func medianeTriee(colonne []float64) float64 {
	slices.Sort(colonne)
	milieu := len(colonne) / 2
	if len(colonne)%2 == 1 {
		return colonne[milieu]
	}
	return (colonne[milieu-1] + colonne[milieu]) / 2
}

// ScoreEncryptedWire rend le score d'hostilité : maximum d'une branche tunnel
// (R1a : volume bidirectionnel net couplé sous garde d'alternance et de charge
// intermédiaire) et d'une branche balise (R1b : activée uniquement lorsque les
// régularités inter-rafales et de charge montante sont toutes deux positives),
// pénalisées hors enveloppe de polling par le téléchargement asymétrique.
// Zéro allocation tas.
func ScoreEncryptedWire(vecteur *KineticVector, calibrage *EncryptedWireCalibration) float64 {
	traits := vecteur.Traits()
	var ecarts [NombreTraitsChiffres]float64
	for trait := range NombreTraitsChiffres {
		ecart := (traits[trait] - calibrage.Mediane[trait]) / calibrage.Echelle[trait] * orientationTraitsChiffres[trait]
		ecarts[trait] = min(max(ecart, -ecartRobusteBorne), ecartRobusteBorne)
	}
	var penaliteTelechargement float64
	if vecteur.AsymetrieDescendanteLog2 > asymetrieTunnelPolleMax {
		penaliteTelechargement += 0.5 * min(ecarts[0], 0)
	}
	if vecteur.FractionQuasiMTUDescendante > quasiMTUTunnelPolleMax {
		penaliteTelechargement += 0.5 * min(ecarts[1], 0)
	}
	penaliteDialogue := min(ecarts[2], 0) + min(ecarts[3], 0)
	brancheTunnel := ecarts[5] + penaliteDialogue + penaliteTelechargement
	brancheBalise := -ecartRobusteBorne
	if vecteur.RegulariteInterRafales > 0 && vecteur.RegulariteChargeMontante > 0 && vecteur.AsymetrieDescendanteLog2 <= asymetrieBaliseMax {
		brancheBalise = min(ecarts[6], ecarts[7]) + penaliteTelechargement
	}
	return assainirFlottantChiffre(max(brancheTunnel, brancheBalise))
}

// EncryptedWireFamilyMetrics rapporte une famille tenue à l'écart.
type EncryptedWireFamilyMetrics struct {
	Famille              string
	Hostile              bool
	Captures             int
	EffectifHostile      int
	EffectifBenin        int
	VraisPositifs        int
	FauxPositifs         int
	VraisNegatifs        int
	FauxNegatifs         int
	MajorityClassRate    float64
	Accuracy             float64
	TPR                  float64
	FPR                  float64
	ROCAUC               float64
	InsuffisantPourAUC   bool
	SeuilDecision        float64
	InsuffisantPourSeuil bool
}

// EncryptedWireLabReport est le rapport intégral LOFO : une ligne par famille
// hostile (contre tous les bénins), une ligne par famille bénigne (FPR propre)
// et la matrice régime attendu × régime estimé.
type EncryptedWireLabReport struct {
	FamillesHostiles  []EncryptedWireFamilyMetrics
	FamillesBenignes  []EncryptedWireFamilyMetrics
	MatriceRegimes    [4][4]int
	SansRegimeAttendu int
}

// EvaluateEncryptedWireSamples applique le Leave-One-Family-Out strict :
// chaque conversation, bénigne ou hostile, est jugée par une calibration
// apprise sur les seules familles bénignes distinctes de la sienne.
func EvaluateEncryptedWireSamples(echantillons []EncryptedWireSample) (EncryptedWireLabReport, error) {
	var rapport EncryptedWireLabReport
	famillesBenignes, famillesHostiles := famillesDistinctes(echantillons)
	if len(famillesBenignes) < 2 || len(famillesHostiles) == 0 {
		return rapport, fmt.Errorf("%w: LOFO strict exige >= 2 familles bénignes et >= 1 hostile (%d, %d)",
			ErrEncryptedWireContract, len(famillesBenignes), len(famillesHostiles))
	}
	calibrages := make(map[string]EncryptedWireCalibration)
	for _, famille := range append(slices.Clone(famillesBenignes), famillesHostiles...) {
		calibrage, err := CalibrateEncryptedWire(vecteursBeninsHorsFamille(echantillons, famille))
		if err != nil {
			return rapport, fmt.Errorf("famille %s: %w", famille, err)
		}
		calibrages[famille] = calibrage
	}
	scores := make([]float64, len(echantillons))
	decisions := make([]bool, len(echantillons))
	for indice := range echantillons {
		calibrage := calibrages[echantillons[indice].Famille]
		scores[indice] = ScoreEncryptedWire(&echantillons[indice].Verdict.Vecteur, &calibrage)
		decisions[indice] = scores[indice] >= calibrage.SeuilDecision
		if echantillons[indice].RegimeConnu {
			rapport.MatriceRegimes[echantillons[indice].RegimeAttendu][echantillons[indice].Verdict.RegimeEstime]++
		} else {
			rapport.SansRegimeAttendu++
		}
	}
	for _, famille := range famillesHostiles {
		rapport.FamillesHostiles = append(rapport.FamillesHostiles,
			bilanFamille(famille, true, echantillons, scores, decisions, calibrages[famille]))
	}
	for _, famille := range famillesBenignes {
		rapport.FamillesBenignes = append(rapport.FamillesBenignes,
			bilanFamille(famille, false, echantillons, scores, decisions, calibrages[famille]))
	}
	return rapport, nil
}

func famillesDistinctes(echantillons []EncryptedWireSample) (benignes, hostiles []string) {
	for indice := range echantillons {
		famille := echantillons[indice].Famille
		if echantillons[indice].Hostile {
			if !slices.Contains(hostiles, famille) {
				hostiles = append(hostiles, famille)
			}
		} else if !slices.Contains(benignes, famille) {
			benignes = append(benignes, famille)
		}
	}
	slices.Sort(benignes)
	slices.Sort(hostiles)
	return benignes, hostiles
}

func vecteursBeninsHorsFamille(echantillons []EncryptedWireSample, familleExclue string) []KineticVector {
	vecteurs := make([]KineticVector, 0, len(echantillons))
	for indice := range echantillons {
		if !echantillons[indice].Hostile && echantillons[indice].Famille != familleExclue {
			vecteurs = append(vecteurs, echantillons[indice].Verdict.Vecteur)
		}
	}
	return vecteurs
}

// bilanFamille : pour une famille hostile, positifs = ses conversations et
// négatifs = toutes les bénignes ; pour une famille bénigne, négatifs = ses
// seules conversations (TPR et AUC sans objet, laissés à zéro).
func bilanFamille(famille string, hostile bool, echantillons []EncryptedWireSample, scores []float64, decisions []bool, calibrage EncryptedWireCalibration) EncryptedWireFamilyMetrics {
	bilan := EncryptedWireFamilyMetrics{Famille: famille, Hostile: hostile,
		SeuilDecision: calibrage.SeuilDecision, InsuffisantPourSeuil: calibrage.InsuffisantPourSeuil}
	captures := make(map[string]bool)
	scoresRetenus := make([]float64, 0, len(echantillons))
	etiquettesRetenues := make([]bool, 0, len(echantillons))
	for indice := range echantillons {
		echantillon := &echantillons[indice]
		retenu := (echantillon.Hostile && echantillon.Famille == famille && hostile) ||
			(!echantillon.Hostile && (hostile || echantillon.Famille == famille))
		if !retenu {
			continue
		}
		if echantillon.Famille == famille {
			captures[echantillon.RunID] = true
		}
		scoresRetenus = append(scoresRetenus, scores[indice])
		etiquettesRetenues = append(etiquettesRetenues, echantillon.Hostile)
		switch {
		case echantillon.Hostile && decisions[indice]:
			bilan.VraisPositifs++
		case echantillon.Hostile:
			bilan.FauxNegatifs++
		case decisions[indice]:
			bilan.FauxPositifs++
		default:
			bilan.VraisNegatifs++
		}
	}
	bilan.Captures = len(captures)
	bilan.EffectifHostile = bilan.VraisPositifs + bilan.FauxNegatifs
	bilan.EffectifBenin = bilan.VraisNegatifs + bilan.FauxPositifs
	effectifTotal := bilan.EffectifHostile + bilan.EffectifBenin
	if effectifTotal > 0 {
		bilan.MajorityClassRate = float64(max(bilan.EffectifHostile, bilan.EffectifBenin)) / float64(effectifTotal)
		bilan.Accuracy = float64(bilan.VraisPositifs+bilan.VraisNegatifs) / float64(effectifTotal)
	}
	if bilan.EffectifHostile > 0 {
		bilan.TPR = float64(bilan.VraisPositifs) / float64(bilan.EffectifHostile)
	}
	if bilan.EffectifBenin > 0 {
		bilan.FPR = float64(bilan.FauxPositifs) / float64(bilan.EffectifBenin)
	}
	bilan.ROCAUC = ExactROCAUC(scoresRetenus, etiquettesRetenues)
	bilan.InsuffisantPourAUC = bilan.EffectifHostile < effectifClasseAUCMinimal || bilan.EffectifBenin < effectifClasseAUCMinimal
	return bilan
}

// ExactROCAUC rend l'aire exacte de Mann-Whitney avec rangs moyens des
// ex-aequo ; 0 si une classe est vide ou si les longueurs diffèrent.
func ExactROCAUC(scores []float64, hostiles []bool) float64 {
	if len(scores) != len(hostiles) || len(scores) == 0 {
		return 0
	}
	type paireNotee struct {
		score   float64
		hostile bool
	}
	paires := make([]paireNotee, len(scores))
	positifs := 0
	for indice := range scores {
		paires[indice] = paireNotee{scores[indice], hostiles[indice]}
		if hostiles[indice] {
			positifs++
		}
	}
	negatifs := len(scores) - positifs
	if positifs == 0 || negatifs == 0 {
		return 0
	}
	slices.SortFunc(paires, func(gauche, droite paireNotee) int { return cmp.Compare(gauche.score, droite.score) })
	sommeRangsPositifs := 0.0
	for debut := 0; debut < len(paires); {
		fin := debut + 1
		for fin < len(paires) && paires[fin].score == paires[debut].score {
			fin++
		}
		rangMoyen := float64(debut+1+fin) / 2
		for position := debut; position < fin; position++ {
			if paires[position].hostile {
				sommeRangsPositifs += rangMoyen
			}
		}
		debut = fin
	}
	statistiqueU := sommeRangsPositifs - float64(positifs)*float64(positifs+1)/2
	return statistiqueU / (float64(positifs) * float64(negatifs))
}
