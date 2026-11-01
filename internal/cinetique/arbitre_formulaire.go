package cinetique

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/hazyhaar/c2slm"
	"github.com/hazyhaar/c2slm/form"
)

// ArbitreFormulaireCinetique conserve le préfixe causal dans le cache du modèle
// et projette les quatre réponses admissibles au moyen d'un formulaire compilé.
type ArbitreFormulaireCinetique struct {
	moteur          *c2slm.Engine
	longueurPrefixe int
	compilation     *form.Compile
	biaisNeutre     [nombreVerdictsCausaux]float32
	configBrief     ConfigProfilCinetique
	nomModele       string
	penserVide      bool
	verrouGate      chan struct{}
	arret           chan struct{}
	fermerUneFois   sync.Once
}

func (a *ArbitreFormulaireCinetique) construireTour(brief string) string {
	tour := construireTourUtilisateurQwen(brief)
	if a.penserVide {
		return strings.Replace(tour, "<|im_start|>assistant\n", "<|im_start|>assistant\n<think>\n\n</think>\n\n", 1)
	}
	return tour
}

// NouvelArbitreFormulaireCinetique charge le modèle, ingère le préfixe une
// seule fois et centre les logits sur les sondes de calibration à vide.
func NouvelArbitreFormulaireCinetique(cheminGGUF string) (*ArbitreFormulaireCinetique, error) {
	moteur, err := c2slm.NewEngine(cheminGGUF)
	if err != nil {
		return nil, fmt.Errorf("cinetique: initialisation c2slm: %w", err)
	}
	fermerSurErreur := func(err error) (*ArbitreFormulaireCinetique, error) {
		_ = moteur.Close()
		return nil, err
	}
	vide := ""
	compilation, err := form.Compiler(moteur.Tokenizer, form.Formulaire{Cases: []form.Case{{
		Nom: "cause", Valeurs: jetonsSemantiquesSLM[:], Libelle: &vide,
	}}})
	if err != nil {
		return fermerSurErreur(err)
	}
	jetonsPrefixe := moteur.Tokenizer.Encode(promptSystemeQwenCinetique)
	if len(jetonsPrefixe) == 0 || len(jetonsPrefixe)+256 >= moteur.KVCache.MaxTokens {
		return fermerSurErreur(fmt.Errorf("cinetique: taille de prefixe systeme invalide (%d tokens)", len(jetonsPrefixe)))
	}
	if err := moteur.Ingest(jetonsPrefixe); err != nil {
		return fermerSurErreur(err)
	}
	a := &ArbitreFormulaireCinetique{
		moteur: moteur, longueurPrefixe: moteur.KVCache.SeqLen,
		compilation: compilation, configBrief: ConfigProfilParDefaut(),
		nomModele: filepath.Base(cheminGGUF), penserVide: len(moteur.Tokenizer.Encode("<think>")) == 1,
		verrouGate: make(chan struct{}, 1), arret: make(chan struct{}),
	}
	var tamponSonde [512]byte
	for indiceSonde := range NombreSondesCalibrationSLM {
		sonde, err := FormaterSondeCalibrationSLM(tamponSonde[:0], indiceSonde)
		if err != nil {
			return fermerSurErreur(err)
		}
		jetons := moteur.Tokenizer.Encode(a.construireTour(string(sonde)))
		if len(jetons) == 0 || len(jetons)+a.longueurPrefixe+compilation.JetonsIngeres() > moteur.KVCache.MaxTokens {
			return fermerSurErreur(ErrBriefSLMTropLong)
		}
		choix, err := form.RemplirDepuis(moteur, compilation, a.longueurPrefixe, jetons)
		if err != nil {
			return fermerSurErreur(err)
		}
		for indice, logit := range choix[0].Logits {
			a.biaisNeutre[indice] += logit / float32(NombreSondesCalibrationSLM)
		}
	}
	moteur.KVCache.Rewind(moteur.KVCache.SeqLen - a.longueurPrefixe)
	return a, nil
}

// DefinirConfigBrief règle les seuils de sérialisation des capteurs.
func (a *ArbitreFormulaireCinetique) DefinirConfigBrief(config ConfigProfilCinetique) {
	if a == nil {
		return
	}
	a.verrouGate <- struct{}{}
	a.configBrief = config
	<-a.verrouGate
}

// Fermer attend l'inférence en cours avant de libérer le modèle.
func (a *ArbitreFormulaireCinetique) Fermer() error {
	if a == nil {
		return nil
	}
	var err error
	a.fermerUneFois.Do(func() {
		close(a.arret)
		a.verrouGate <- struct{}{}
		defer func() { <-a.verrouGate }()
		err = a.moteur.Close()
	})
	return err
}

// ArbitrerEpisode classe le brief physique par logits calibrés, puis applique
// le veto physique aux seuls verdicts produits par le formulaire.
func (a *ArbitreFormulaireCinetique) ArbitrerEpisode(ctx context.Context, nomExecutable string, diag DiagnosticEpisodeCinetique) (DecisionArbitrageCinetique, error) {
	if a == nil {
		return DecisionArbitrageCinetique{}, ErrArbitreFerme
	}
	if err := ctx.Err(); err != nil {
		return DecisionArbitrageCinetique{}, err
	}
	if !DoitEscaladeSLM(diag) {
		return DecisionArbitrageCinetique{
			MoteurArbitre:     "Formulaire:" + a.nomModele,
			VerdictBrutModele: VerdictSLMContentionOuInsuff,
			VerdictFinal:      VerdictSLMContentionOuInsuff, Confiance: 1,
			ActionRecommandee: ActionPourVerdictCinetique(VerdictSLMContentionOuInsuff),
		}, nil
	}
	select {
	case <-ctx.Done():
		return DecisionArbitrageCinetique{}, ctx.Err()
	case <-a.arret:
		return DecisionArbitrageCinetique{}, ErrArbitreFerme
	case a.verrouGate <- struct{}{}:
	}
	defer func() { <-a.verrouGate }()
	if err := ctx.Err(); err != nil {
		return DecisionArbitrageCinetique{}, err
	}
	select {
	case <-a.arret:
		return DecisionArbitrageCinetique{}, ErrArbitreFerme
	default:
	}
	var tamponBrief [512]byte
	brief, err := FormaterBriefCausalSLMAvecConfig(tamponBrief[:0], nomExecutable, diag, a.configBrief)
	if err != nil {
		return DecisionArbitrageCinetique{}, err
	}
	texteBrief := string(brief)
	debut := time.Now()
	jetons := a.moteur.Tokenizer.Encode(a.construireTour(texteBrief))
	if len(jetons) == 0 {
		return DecisionArbitrageCinetique{}, ErrInferenceSLMVide
	}
	if len(jetons)+a.longueurPrefixe+a.compilation.JetonsIngeres() > a.moteur.KVCache.MaxTokens {
		return DecisionArbitrageCinetique{}, ErrBriefSLMTropLong
	}
	choix, err := form.RemplirDepuis(a.moteur, a.compilation, a.longueurPrefixe, jetons)
	if err != nil {
		return DecisionArbitrageCinetique{}, err
	}
	duree := uint64(time.Since(debut).Microseconds())
	var bruts, deltas [nombreVerdictsCausaux]float32
	indiceBrut, indiceCalibre := 0, 0
	for indice, logit := range choix[0].Logits {
		bruts[indice] = logit
		deltas[indice] = logit - a.biaisNeutre[indice]
		if bruts[indice] > bruts[indiceBrut] {
			indiceBrut = indice
		}
		if deltas[indice] > deltas[indiceCalibre] {
			indiceCalibre = indice
		}
	}
	var sommeBrute, sommeCalibree float64
	for indice := range bruts {
		sommeBrute += math.Exp(float64(bruts[indice] - bruts[indiceBrut]))
		sommeCalibree += math.Exp(float64(deltas[indice] - deltas[indiceCalibre]))
	}
	var probabilitesBrutes, probabilites [nombreVerdictsCausaux]float32
	for indice := range bruts {
		probabilitesBrutes[indice] = float32(math.Exp(float64(bruts[indice]-bruts[indiceBrut])) / sommeBrute)
		probabilites[indice] = float32(math.Exp(float64(deltas[indice]-deltas[indiceCalibre])) / sommeCalibree)
	}
	verdictModele := etiquettesVerdictsSLM[indiceCalibre]
	verdictFinal, veto, motif := AppliquerVetoPhysiqueCinetique(diag, verdictModele)
	confiance := float64(probabilites[indiceCalibre])
	if veto {
		if indiceFinal := indiceDuVerdict(verdictFinal); indiceFinal >= 0 {
			confiance = math.Max(0.85, float64(probabilites[indiceFinal]))
		}
	}
	return DecisionArbitrageCinetique{
		ModeleInvoque: true, MoteurArbitre: "Formulaire:" + a.nomModele,
		VerdictBrutNonCalibre: etiquettesVerdictsSLM[indiceBrut], VerdictBrutModele: verdictModele,
		VerdictFinal: verdictFinal, Confiance: confiance, VetoPhysiqueApplique: veto, MotifVeto: motif,
		LogitsBrutsModele: bruts, BiaisNeutreModele: a.biaisNeutre, DeltaLogitsModele: deltas,
		ProbabilitesBrutes: probabilitesBrutes, Probabilites: probabilites,
		DureeInferenceUs: duree, ActionRecommandee: ActionPourVerdictCinetique(verdictFinal),
		DifferentielTransmis: texteBrief,
	}, nil
}
