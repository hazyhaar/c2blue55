package cinetique

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hazyhaar/c2slm"
	"github.com/hazyhaar/c2slm/engine"
)

const (
	dimensionEncodeurCinetique = 16
	nombreVerdictsCausaux      = 4
	temperatureEncodeur        = 0.7
)

// Verdicts causaux officiels (options à token unique A, B, C, D).
const (
	VerdictSLMDegradationMaterielle = "HARDWARE_STORAGE_DEGRADATION" // A
	VerdictSLMCompromissionExfil    = "PROCESS_C2_OR_EXFILTRATION"   // B
	VerdictSLMDeriveOrganique       = "ORGANIC_RESOURCE_DRIFT"       // C
	VerdictSLMContentionOuInsuff    = "CONTENTION_OR_INSUFFICIENT"   // D
)

var (
	// ErrArbitreFerme signale un appel sur un arbitre déjà clos.
	ErrArbitreFerme = errors.New("cinetique: arbitre SLM ferme")
	// ErrFileArbitragePleine signale le rejet non bloquant d'un dossier faute de place dans la file.
	ErrFileArbitragePleine = errors.New("cinetique: file d'arbitrage SLM pleine")
	// ErrBriefSLMTropLong signale que le brief encodé dépasse la capacité du contexte SLM (fail-closed, OBJET-INTEGRAL-001).
	ErrBriefSLMTropLong = errors.New("cinetique: brief causal SLM depasse la capacite de contexte autorisee")
	// ErrInferenceSLMVide signale un vecteur d'état caché vide retourné par le moteur d'inférence.
	ErrInferenceSLMVide = errors.New("cinetique: vecteur d'etat cache SLM vide")
)

// Jetons sémantiques natifs à 1 seul token BPE Qwen2 alignés sur les noms des capteurs
// (évitant le goulot d'indirection symbolique A/B/C/D des modèles 0.5B en 1 passe forward).
var jetonsSemantiquesSLM = [nombreVerdictsCausaux]string{"storage", "network", "memory", "normal"}

var etiquettesVerdictsSLM = [nombreVerdictsCausaux]string{
	VerdictSLMDegradationMaterielle,
	VerdictSLMCompromissionExfil,
	VerdictSLMDeriveOrganique,
	VerdictSLMContentionOuInsuff,
}

// DecisionArbitrageCinetique consigne de manière transparente la sortie brute du
// modèle, l'étalonnage contextuel sans contenu (delta_logits = logits_bruts - biais_neutre),
// la distribution brute softmax(logits_bruts) et la distribution calibrée softmax(delta_logits)
// dans Probabilites, l'application éventuelle du veto physique souverain et l'action recommandée.
type DecisionArbitrageCinetique struct {
	ModeleInvoque         bool                           `json:"modele_invoque"`
	MoteurArbitre         string                         `json:"moteur_arbitre"`
	VerdictBrutNonCalibre string                         `json:"verdict_brut_non_calibre,omitempty"`
	VerdictBrutModele     string                         `json:"verdict_brut_modele"`
	VerdictFinal          string                         `json:"verdict_final"`
	Confiance             float64                        `json:"confiance"`
	VetoPhysiqueApplique  bool                           `json:"veto_physique_applique"`
	MotifVeto             string                         `json:"motif_veto,omitempty"`
	LogitsBrutsModele     [nombreVerdictsCausaux]float32 `json:"logits_bruts_modele"`
	BiaisNeutreModele     [nombreVerdictsCausaux]float32 `json:"biais_neutre_modele,omitempty"`
	DeltaLogitsModele     [nombreVerdictsCausaux]float32 `json:"delta_logits_modele,omitempty"`
	ProbabilitesBrutes    [nombreVerdictsCausaux]float32 `json:"probabilites_brutes,omitempty"`
	Probabilites          [nombreVerdictsCausaux]float32 `json:"probabilites"`
	DureeInferenceUs      uint64                         `json:"duree_inference_us"`
	ActionRecommandee     string                         `json:"action_recommandee"`
	DifferentielTransmis  string                         `json:"differentiel_transmis,omitempty"`
}

// ArbitreCausalCinetique abstrait l'arbitrage hors chemin chaud d'un épisode anormal
// (encodeur SIMD DecisionHead 0 B/op ou modèle GGUF Qwen2.5-0.5B à préfixe mis en cache).
type ArbitreCausalCinetique interface {
	ArbitrerEpisode(ctx context.Context, nomExecutable string, diag DiagnosticEpisodeCinetique) (DecisionArbitrageCinetique, error)
	Fermer() error
}

// DoitEscaladeSLM filtre en amont 0 B/op les épisodes nominaux, en amorçage ou
// en abstention de contention CPU afin de ne jamais réveiller l'arbitre inutilement.
func DoitEscaladeSLM(diag DiagnosticEpisodeCinetique) bool {
	switch diag.Orientation {
	case OrientationDegradationES,
		OrientationCompromissionReseau,
		OrientationDeriveOrganique,
		OrientationEcartStructurel:
		return true
	default:
		return false
	}
}

// ActionPourVerdictCinetique associe chaque verdict causal à la réponse opérationnelle adaptée.
func ActionPourVerdictCinetique(verdict string) string {
	switch verdict {
	case VerdictSLMDegradationMaterielle:
		return "INSPECT_STORAGE_SMART_NVME_NO_QUARANTINE"
	case VerdictSLMCompromissionExfil:
		return "ISOLATE_PID_SOCKET_AND_CAPTURE_FORENSICS"
	case VerdictSLMDeriveOrganique:
		return "OPEN_MAINTENANCE_MEMORY_PROFILE_TICKET"
	default:
		return "PASSIVE_OBSERVATION_NO_ALERT"
	}
}

// AppliquerVetoPhysiqueCinetique garantit que la proposition neuronale n'est
// jamais souveraine face à une impossibilité physique ou une preuve matérielle d'exfiltration.
func AppliquerVetoPhysiqueCinetique(diag DiagnosticEpisodeCinetique, verdictPropose string) (verdictFinal string, veto bool, motif string) {
	ep := diag.Episode
	aucunEgressOuCanalSuspect := ep.OctetsSortantsNuls() &&
		ep.PortSuspect == 0 &&
		ep.CodeRaisonDNS == 0 &&
		!ep.ConnexionSansDNS

	indiceReseauHostile := ep.CodeRaisonDNS != 0 || ep.PortSuspect != 0 || ep.ConnexionSansDNS
	deriveRessource := (ep.EstValide(IndiceEgressSurLecturePermille) && ep.Valeurs[IndiceEgressSurLecturePermille] >= 50) ||
		diag.VariationsPct[IndiceNsCPUParKioLogique] >= 50 ||
		diag.VariationsPct[IndiceKioPicRSSParFil] >= 35 ||
		ep.CodeRaisonDNS != 0
	preuveCompromissionConvergente := indiceReseauHostile && deriveRessource

	// 1. Impossibilité physique d'une panne stockage sans le moindre octet disque/bloc transféré.
	if !ep.ActiviteDisquePresente() && verdictPropose == VerdictSLMDegradationMaterielle {
		if preuveCompromissionConvergente {
			return VerdictSLMCompromissionExfil, true, "VETO_ZERO_DISK_IO_CONVERGENT_NETWORK"
		}
		if diag.Orientation == OrientationDeriveOrganique {
			return VerdictSLMDeriveOrganique, true, "VETO_ZERO_DISK_IO_MONOTONIC_DRIFT"
		}
		return VerdictSLMContentionOuInsuff, true, "VETO_ZERO_DISK_IO_ACTIVITY"
	}

	// 2. Impossibilité physique d'exfiltration réseau sans le moindre canal sortant ni alerte socket/DNS.
	if aucunEgressOuCanalSuspect && verdictPropose == VerdictSLMCompromissionExfil {
		if diag.Orientation == OrientationDegradationES && ep.ActiviteDisquePresente() {
			return VerdictSLMDegradationMaterielle, true, "VETO_ZERO_NETWORK_STORAGE_STALL"
		}
		if diag.Orientation == OrientationDeriveOrganique {
			return VerdictSLMDeriveOrganique, true, "VETO_ZERO_NETWORK_MONOTONIC_DRIFT"
		}
		return VerdictSLMContentionOuInsuff, true, "VETO_ZERO_NETWORK_NO_C2_CHANNEL"
	}

	// 3. Impossibilité physique d'une fuite mémoire organique sans hausse mémoire ni dérive monotone.
	// Un léger trafic réseau régulier non hostile ne doit jamais être transformé en compromission C2.
	aucuneHausseMemoire := diag.PasDeriveMonotoneRSS < 3 && diag.VariationsPct[IndiceKioPicRSSParFil] <= 20
	if aucuneHausseMemoire && verdictPropose == VerdictSLMDeriveOrganique {
		if diag.Orientation == OrientationDegradationES && ep.ActiviteDisquePresente() && aucunEgressOuCanalSuspect {
			return VerdictSLMDegradationMaterielle, true, "VETO_ZERO_MEMORY_GROWTH_STORAGE_STALL"
		}
		if preuveCompromissionConvergente {
			return VerdictSLMCompromissionExfil, true, "VETO_ZERO_MEMORY_GROWTH_HOSTILE_NETWORK"
		}
		return VerdictSLMContentionOuInsuff, true, "VETO_ZERO_MEMORY_GROWTH"
	}

	// 4. Anti-blanchiment : preuve convergente réseau/DNS + dérive de ressource.
	if preuveCompromissionConvergente && verdictPropose != VerdictSLMCompromissionExfil {
		return VerdictSLMCompromissionExfil, true, "VETO_CONVERGENT_NETWORK_AND_KINETIC_HOSTILE"
	}

	// 5. Invariance mémoire : une dérive monotone de RAM avérée (>= seuil de pas)
	// sans activité réseau suspecte ni blocage E/S réel (< 1000 permille) ne peut être
	// ni une contention CPU ni une panne matérielle de stockage.
	if aucunEgressOuCanalSuspect &&
		diag.Orientation == OrientationDeriveOrganique &&
		ep.Valeurs[IndiceDilatationHorsCPU] < 1000 &&
		verdictPropose != VerdictSLMDeriveOrganique {
		return VerdictSLMDeriveOrganique, true, "VETO_MONOTONIC_MEMORY_NO_IO_STALL"
	}

	// 6. Anti-hallucination sous surcharge PSI ou migration P<->E sans indice réseau ni dérive mémoire prouvée.
	if (ep.AbstentionPSICPU || ep.MigrationHybride) &&
		aucunEgressOuCanalSuspect &&
		diag.Orientation != OrientationDeriveOrganique &&
		verdictPropose != VerdictSLMContentionOuInsuff {
		return VerdictSLMContentionOuInsuff, true, "VETO_CPU_PRESSURE_OR_HYBRID_MIGRATION"
	}

	return verdictPropose, false, ""
}

// Indices des 16 composantes normalisées [0,1] de l'encodeur cinétique.
const (
	compDilatationHorsCPU = iota
	compDominanceHorsCPU
	compZeroReseau
	compTravailLogiqueStable
	compHausseCPUParKio
	compHaussePicRSS
	compEgressActif
	compSocketSuspecte
	compRaisonDNSActive
	compConnexionSansDNS
	compDeriveMonotone
	compEcartTailleES
	compPressionPSICPU
	compAttenteRunqueue
	compMigrationHybride
	compSansActiviteDisque
)

var poidsEncodeurCinetique = [nombreVerdictsCausaux][dimensionEncodeurCinetique]float32{
	{ // A — HARDWARE_STORAGE_DEGRADATION
		compDilatationHorsCPU:    2.6,
		compDominanceHorsCPU:     1.8,
		compZeroReseau:           1.4,
		compTravailLogiqueStable: 1.2,
		compSocketSuspecte:       -3.0,
		compRaisonDNSActive:      -3.0,
		compPressionPSICPU:       -2.2,
		compAttenteRunqueue:      -1.8,
		compSansActiviteDisque:   -3.5,
	},
	{ // B — PROCESS_C2_OR_EXFILTRATION
		compHausseCPUParKio:  1.6,
		compHaussePicRSS:     1.4,
		compEgressActif:      2.2,
		compSocketSuspecte:   2.4,
		compRaisonDNSActive:  2.8,
		compConnexionSansDNS: 1.8,
		compZeroReseau:       -3.5,
	},
	{ // C — ORGANIC_RESOURCE_DRIFT
		compDeriveMonotone:       3.2,
		compZeroReseau:           1.2,
		compTravailLogiqueStable: 1.0,
		compDilatationHorsCPU:    -1.2,
		compSocketSuspecte:       -2.5,
		compRaisonDNSActive:      -2.5,
	},
	{ // D — CONTENTION_OR_INSUFFICIENT
		compPressionPSICPU:     2.6,
		compAttenteRunqueue:    2.2,
		compMigrationHybride:   2.4,
		compSansActiviteDisque: 2.5,
		compEcartTailleES:      0.6,
	},
}

var biaisEncodeurCinetique = [nombreVerdictsCausaux]float32{-0.4, -0.5, -0.5, 0.25}

// ArbitreEncodeurCinetique exécute en 0 B/op et < 1 µs la projection SIMD
// DecisionHead (C2_tensor_logit_gather_softmax) suivie du veto physique souverain.
type ArbitreEncodeurCinetique struct {
	tete  *engine.DecisionHead
	ferme atomic.Bool
}

// NouvelArbitreEncodeurCinetique construit l'arbitre déterministe SIMD sans verrou.
func NouvelArbitreEncodeurCinetique() *ArbitreEncodeurCinetique {
	poids := make([]float32, nombreVerdictsCausaux*dimensionEncodeurCinetique)
	for r := range nombreVerdictsCausaux {
		copy(poids[r*dimensionEncodeurCinetique:(r+1)*dimensionEncodeurCinetique], poidsEncodeurCinetique[r][:])
	}
	biais := make([]float32, nombreVerdictsCausaux)
	copy(biais, biaisEncodeurCinetique[:])
	return &ArbitreEncodeurCinetique{
		tete: &engine.DecisionHead{
			Weights:     poids,
			Biases:      biais,
			HiddenDim:   dimensionEncodeurCinetique,
			Temperature: temperatureEncodeur,
		},
	}
}

// Fermer marque l'arbitre encodeur comme clos de façon idempotente.
func (a *ArbitreEncodeurCinetique) Fermer() error {
	if a != nil {
		a.ferme.Store(true)
	}
	return nil
}

// ArbitrerEpisode évalue en 0 B/op un épisode cinétique via DecisionHead + veto.
func (a *ArbitreEncodeurCinetique) ArbitrerEpisode(
	ctx context.Context,
	nomExecutable string,
	diag DiagnosticEpisodeCinetique,
) (DecisionArbitrageCinetique, error) {
	if a == nil || a.ferme.Load() {
		return DecisionArbitrageCinetique{}, ErrArbitreFerme
	}
	if err := ctx.Err(); err != nil {
		return DecisionArbitrageCinetique{}, err
	}
	if !DoitEscaladeSLM(diag) {
		return DecisionArbitrageCinetique{
			ModeleInvoque:     false,
			MoteurArbitre:     "DecisionHead_SIMD_0B",
			VerdictBrutModele: VerdictSLMContentionOuInsuff,
			VerdictFinal:      VerdictSLMContentionOuInsuff,
			Confiance:         1.0,
			ActionRecommandee: ActionPourVerdictCinetique(VerdictSLMContentionOuInsuff),
		}, nil
	}

	var etatCache [dimensionEncodeurCinetique]float32
	var probs [nombreVerdictsCausaux]float32
	encoderCaracteristiquesCinetiques(diag, &etatCache)

	_, proposition, conf32, _ := a.tete.DecideChoice(etatCache[:], nombreVerdictsCausaux, etiquettesVerdictsSLM[:], probs[:])
	verdictFinal, veto, motif := AppliquerVetoPhysiqueCinetique(diag, proposition)
	confiance := float64(conf32)
	if veto {
		idxFinal := indiceDuVerdict(verdictFinal)
		if idxFinal >= 0 {
			confiance = math.Max(0.85, float64(probs[idxFinal]))
		}
	}

	_ = nomExecutable
	return DecisionArbitrageCinetique{
		ModeleInvoque:        true,
		MoteurArbitre:        "DecisionHead_SIMD_0B",
		VerdictBrutModele:    proposition,
		VerdictFinal:         verdictFinal,
		Confiance:            confiance,
		VetoPhysiqueApplique: veto,
		MotifVeto:            motif,
		Probabilites:         probs,
		ActionRecommandee:    ActionPourVerdictCinetique(verdictFinal),
	}, nil
}

// EvaluerZeroAlloc effectue l'inférence SIMD + veto sans construire de chaîne ni utiliser time.Now,
// pour l'intégration directe dans les boucles à budget 0 B/op strict.
func (a *ArbitreEncodeurCinetique) EvaluerZeroAlloc(diag DiagnosticEpisodeCinetique) (verdict string, confiance float32, veto bool) {
	if a == nil || a.ferme.Load() || !DoitEscaladeSLM(diag) {
		return VerdictSLMContentionOuInsuff, 1.0, false
	}
	var etatCache [dimensionEncodeurCinetique]float32
	var probs [nombreVerdictsCausaux]float32
	encoderCaracteristiquesCinetiques(diag, &etatCache)
	_, proposition, conf32, _ := a.tete.DecideChoice(etatCache[:], nombreVerdictsCausaux, etiquettesVerdictsSLM[:], probs[:])
	final, v, _ := AppliquerVetoPhysiqueCinetique(diag, proposition)
	if v {
		return final, 0.90, true
	}
	return final, conf32, false
}

func encoderCaracteristiquesCinetiques(diag DiagnosticEpisodeCinetique, cible *[dimensionEncodeurCinetique]float32) {
	ep := diag.Episode
	aucuneRes := ep.OctetsSortantsNuls() && ep.PortSuspect == 0 && ep.CodeRaisonDNS == 0 && !ep.ConnexionSansDNS

	if ep.ActiviteDisquePresente() {
		if ep.Valeurs[IndiceDilatationHorsCPU] >= 1000 {
			cible[compDilatationHorsCPU] = borner01(float32(diag.VariationsPct[IndiceDilatationHorsCPU]) / 300.0)
		}
		if ep.DeltaHorsCPUNs > 2*ep.DeltaAttenteFileNs && ep.Valeurs[IndiceDilatationHorsCPU] >= 1000 {
			cible[compDominanceHorsCPU] = 1.0
		}
	} else {
		cible[compSansActiviteDisque] = 1.0
	}
	if aucuneRes {
		cible[compZeroReseau] = 1.0
	}
	absTaille := diag.VariationsPct[IndiceOctetsParAppelES]
	if absTaille < 0 {
		absTaille = -absTaille
	}
	if ep.ActiviteDisquePresente() && absTaille <= 20 {
		cible[compTravailLogiqueStable] = 1.0
	}
	cible[compHausseCPUParKio] = borner01(float32(diag.VariationsPct[IndiceNsCPUParKioLogique]) / 200.0)
	cible[compHaussePicRSS] = borner01(float32(diag.VariationsPct[IndiceKioPicRSSParFil]) / 100.0)
	if ep.EstValide(IndiceEgressSurLecturePermille) {
		cible[compEgressActif] = borner01(float32(ep.Valeurs[IndiceEgressSurLecturePermille]) / 100.0)
	} else if !ep.OctetsSortantsNuls() {
		cible[compEgressActif] = 1.0
	}
	if ep.PortSuspect > 0 {
		cible[compSocketSuspecte] = 1.0
	}
	if ep.CodeRaisonDNS > 0 {
		cible[compRaisonDNSActive] = 1.0
	}
	if ep.ConnexionSansDNS {
		cible[compConnexionSansDNS] = 1.0
	}
	cible[compDeriveMonotone] = borner01(float32(diag.PasDeriveMonotoneRSS) / 5.0)
	cible[compEcartTailleES] = borner01(float32(absTaille) / 100.0)
	invariantAuCPU := diag.Orientation == OrientationDeriveOrganique || diag.Orientation == OrientationCompromissionReseau
	if !invariantAuCPU {
		if ep.AbstentionPSICPU {
			cible[compPressionPSICPU] = 1.0
		}
		if ep.DeltaExecutionNs > 0 && ep.DeltaAttenteFileNs >= ep.DeltaExecutionNs {
			cible[compAttenteRunqueue] = 1.0
		}
		if ep.MigrationHybride {
			cible[compMigrationHybride] = 1.0
		}
	}
}

func borner01(x float32) float32 {
	if !(x > 0) {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

func indiceDuVerdict(verdict string) int {
	for i, v := range etiquettesVerdictsSLM {
		if v == verdict {
			return i
		}
	}
	return -1
}

const promptSystemeQwenCinetique = `<|im_start|>system
You classify Linux process telemetry into one JSON cause: "storage", "network", "memory", or "normal".
Rules:
1. If off_cpu_wait is ELEVATED and disk_io is ACTIVE or SHIFTED and host_cpu_contention is LOW and network_channel is NONE or BENIGN -> {"cause":"storage"}
2. If network_channel is ANOMALOUS_SOCKET -> {"cause":"network"}
3. If rss_memory is MONOTONIC_GROWTH and network_channel is NONE or BENIGN -> {"cause":"memory"}
4. Otherwise -> {"cause":"normal"}<|im_end|>
<|im_start|>user
process: demo
cpu_work_per_kib: NORMAL (+0%)
disk_io: ACTIVE (+0%)
off_cpu_wait: ELEVATED (+900%)
rss_memory: STABLE
network_channel: NONE
host_cpu_contention: LOW<|im_end|>
<|im_start|>assistant
{"cause":"storage"}<|im_end|>
<|im_start|>user
process: demo
cpu_work_per_kib: ELEVATED (+250%)
disk_io: ACTIVE (+0%)
off_cpu_wait: NORMAL (-10%)
rss_memory: STABLE
network_channel: ANOMALOUS_SOCKET (UDP/53, dns_code=2)
host_cpu_contention: LOW<|im_end|>
<|im_start|>assistant
{"cause":"network"}<|im_end|>
<|im_start|>user
process: demo
cpu_work_per_kib: NORMAL (+0%)
disk_io: ACTIVE (+0%)
off_cpu_wait: NORMAL (+0%)
rss_memory: MONOTONIC_GROWTH (steps=6)
network_channel: NONE
host_cpu_contention: LOW<|im_end|>
<|im_start|>assistant
{"cause":"memory"}<|im_end|>
`

func construireTourUtilisateurQwen(briefPhysique string) string {
	return "<|im_start|>user\n" + briefPhysique + "<|im_end|>\n<|im_start|>assistant\n{\"cause\":\""
}

// ArbitreQwenCinetique pilote le modèle pur Go Qwen2.5-0.5B-Instruct (c2slm)
// avec préfixe système pré-ingéré en KVCache, étalonnage bayésien d'a priori sur grille
// orthogonale équilibrée (Domain-Context Calibration, Fei et al. ACL 2023), prefill tuilé
// IngestFrom (avec rembobinage automatique KVCache) et projection contrainte ComputeLogits
// sur les 4 jetons sémantiques à 1 token.
type ArbitreQwenCinetique struct {
	moteur                 *c2slm.Engine
	verrouGate             chan struct{}
	arret                  chan struct{}
	fermerUneFois          sync.Once
	tokensCandidats        []int32
	longueurPrefixeSysteme int
	plafondTokensTour      int
	cfgBrief               ConfigProfilCinetique
	biaisNeutre            [nombreVerdictsCausaux]float32
}

// NouvelArbitreQwenCinetique charge le modèle GGUF, valide l'unicité à 1 token BPE des
// 4 jetons sémantiques, pré-calcule le KVCache du prompt système et mesure le vecteur de
// log-a-priori marginal mu_0 sur la grille orthogonale équilibrée des 4 classes.
func NouvelArbitreQwenCinetique(cheminModeleGGUF string) (*ArbitreQwenCinetique, error) {
	if _, errStat := os.Stat(cheminModeleGGUF); errStat != nil {
		return nil, fmt.Errorf("cinetique: modele GGUF introuvable (%s): %w", cheminModeleGGUF, errStat)
	}
	eng, errEng := c2slm.NewEngine(cheminModeleGGUF)
	if errEng != nil {
		return nil, fmt.Errorf("cinetique: initialisation c2slm: %w", errEng)
	}

	candidats := make([]int32, nombreVerdictsCausaux)
	vus := make(map[int32]string, nombreVerdictsCausaux)
	for i, jeton := range jetonsSemantiquesSLM {
		toks := eng.Tokenizer.Encode(jeton)
		if len(toks) != 1 {
			_ = eng.Close()
			return nil, fmt.Errorf("cinetique: le jeton %q s'encode en %d tokens (attendu 1)", jeton, len(toks))
		}
		if existant, collision := vus[toks[0]]; collision {
			_ = eng.Close()
			return nil, fmt.Errorf("cinetique: collision de token %d entre %q et %q", toks[0], jeton, existant)
		}
		vus[toks[0]] = jeton
		candidats[i] = toks[0]
	}

	tokensPrefixe := eng.Tokenizer.Encode(promptSystemeQwenCinetique)
	if len(tokensPrefixe) == 0 || len(tokensPrefixe)+256 >= engine.MaxContextLen {
		_ = eng.Close()
		return nil, fmt.Errorf("cinetique: taille de prefixe systeme invalide (%d tokens)", len(tokensPrefixe))
	}
	eng.KVCache.Reset()
	etatPrefixe := eng.IngestFrom(0, tokensPrefixe)
	if len(etatPrefixe) == 0 {
		_ = eng.Close()
		return nil, ErrInferenceSLMVide
	}
	longueurPrefixe := eng.KVCache.SeqLen

	// Étalonnage bayésien d'a priori sur grille orthogonale équilibrée (Domain-Context
	// Calibration, Fei et al. ACL 2023 & Menon et al. ICLR 2021) : on mesure sur les 4 sondes
	// équilibrées (25 % par classe, 50/50 sur l'attente hors-CPU) le log-a-priori marginal mu_i
	// de chaque jeton candidat afin de centrer additivement les logits sans pénaliser "normal".
	var biaisNeutre [nombreVerdictsCausaux]float32
	var tamponSonde [512]byte
	for idxSonde := range NombreSondesCalibrationSLM {
		briefSonde, errSonde := FormaterSondeCalibrationSLM(tamponSonde[:0], idxSonde)
		if errSonde != nil {
			_ = eng.Close()
			return nil, errSonde
		}
		tokensSonde := eng.Tokenizer.Encode(construireTourUtilisateurQwen(string(briefSonde)))
		etatSonde := eng.IngestFrom(longueurPrefixe, tokensSonde)
		if len(etatSonde) == 0 {
			_ = eng.Close()
			return nil, ErrInferenceSLMVide
		}
		engine.ComputeLogits(eng.Model, eng.Arena, etatSonde, eng.Arena.Logits, candidats)
		for i, tokID := range candidats {
			biaisNeutre[i] += eng.Arena.Logits[tokID] / float32(NombreSondesCalibrationSLM)
		}
	}
	eng.KVCache.Rewind(eng.KVCache.SeqLen - longueurPrefixe)

	return &ArbitreQwenCinetique{
		moteur:                 eng,
		verrouGate:             make(chan struct{}, 1),
		arret:                  make(chan struct{}),
		tokensCandidats:        candidats,
		longueurPrefixeSysteme: longueurPrefixe,
		plafondTokensTour:      engine.MaxContextLen - longueurPrefixe - 2,
		cfgBrief:               ConfigProfilParDefaut(),
		biaisNeutre:            biaisNeutre,
	}, nil
}

// DefinirConfigBrief aligne les seuils d'émission du brief SLM sur une configuration
// de profil cinétique personnalisée.
func (a *ArbitreQwenCinetique) DefinirConfigBrief(cfg ConfigProfilCinetique) {
	if a == nil {
		return
	}
	a.verrouGate <- struct{}{}
	a.cfgBrief = cfg
	<-a.verrouGate
}

// Fermer attend la fin de toute inférence active puis libère les segments mmap du modèle.
func (a *ArbitreQwenCinetique) Fermer() error {
	if a == nil {
		return nil
	}
	var errFermeture error
	a.fermerUneFois.Do(func() {
		close(a.arret)
		a.verrouGate <- struct{}{}
		defer func() { <-a.verrouGate }()
		if a.moteur != nil {
			errFermeture = a.moteur.Close()
		}
	})
	return errFermeture
}

// ArbitrerEpisode transmet uniquement sur escalade les observables physiques neutres (sans
// l'orientation du moteur Go) à Qwen2.5-0.5B, extrait ses logits bruts et calibrés à 1 token,
// puis applique le veto physique souverain. Échoue explicitement (ErrBriefSLMTropLong) sans
// jamais tronquer le brief si le plafond de tokens du contexte est dépassé (OBJET-INTEGRAL-001).
func (a *ArbitreQwenCinetique) ArbitrerEpisode(
	ctx context.Context,
	nomExecutable string,
	diag DiagnosticEpisodeCinetique,
) (DecisionArbitrageCinetique, error) {
	if a == nil {
		return DecisionArbitrageCinetique{}, ErrArbitreFerme
	}
	if err := ctx.Err(); err != nil {
		return DecisionArbitrageCinetique{}, err
	}
	if !DoitEscaladeSLM(diag) {
		return DecisionArbitrageCinetique{
			ModeleInvoque:     false,
			MoteurArbitre:     "Qwen2.5-0.5B_PrefillCache",
			VerdictBrutModele: VerdictSLMContentionOuInsuff,
			VerdictFinal:      VerdictSLMContentionOuInsuff,
			Confiance:         1.0,
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
	octetsBrief, errFmt := FormaterBriefCausalSLMAvecConfig(tamponBrief[:0], nomExecutable, diag, a.cfgBrief)
	if errFmt != nil {
		return DecisionArbitrageCinetique{}, errFmt
	}
	texteBrief := string(octetsBrief)
	tourPrompt := construireTourUtilisateurQwen(texteBrief)

	debutInf := time.Now()
	tokensTour := a.moteur.Tokenizer.Encode(tourPrompt)
	if len(tokensTour) == 0 {
		return DecisionArbitrageCinetique{}, ErrInferenceSLMVide
	}
	if a.plafondTokensTour <= 0 || len(tokensTour) > a.plafondTokensTour {
		return DecisionArbitrageCinetique{}, ErrBriefSLMTropLong
	}

	// IngestFrom rembobine automatiquement e.KVCache à a.longueurPrefixeSysteme avant d'ingérer tokensTour.
	dernierEtat := a.moteur.IngestFrom(a.longueurPrefixeSysteme, tokensTour)
	if len(dernierEtat) == 0 {
		return DecisionArbitrageCinetique{}, ErrInferenceSLMVide
	}
	engine.ComputeLogits(a.moteur.Model, a.moteur.Arena, dernierEtat, a.moteur.Arena.Logits, a.tokensCandidats)
	dureeUs := uint64(time.Since(debutInf).Microseconds())

	var logitsQwen [nombreVerdictsCausaux]float32
	var deltaLogits [nombreVerdictsCausaux]float32
	idxNonCalibre := 0
	maxNonCalibre := float32(-1e30)
	idxCalibre := 0
	maxCalibre := float32(-1e30)

	for i, tokID := range a.tokensCandidats {
		logit := a.moteur.Arena.Logits[tokID]
		logitsQwen[i] = logit
		if logit > maxNonCalibre {
			maxNonCalibre = logit
			idxNonCalibre = i
		}
		delta := logit - a.biaisNeutre[i]
		deltaLogits[i] = delta
		if delta > maxCalibre {
			maxCalibre = delta
			idxCalibre = i
		}
	}
	verdictNonCalibre := etiquettesVerdictsSLM[idxNonCalibre]
	verdictModele := etiquettesVerdictsSLM[idxCalibre]

	var sommeExpBrut, sommeExpCalibre float64
	for i := range nombreVerdictsCausaux {
		sommeExpBrut += math.Exp(float64(logitsQwen[i] - maxNonCalibre))
		sommeExpCalibre += math.Exp(float64(deltaLogits[i] - maxCalibre))
	}
	var probsBrutes [nombreVerdictsCausaux]float32
	var probsCalibrees [nombreVerdictsCausaux]float32
	for i := range nombreVerdictsCausaux {
		probsBrutes[i] = float32(math.Exp(float64(logitsQwen[i]-maxNonCalibre)) / sommeExpBrut)
		probsCalibrees[i] = float32(math.Exp(float64(deltaLogits[i]-maxCalibre)) / sommeExpCalibre)
	}

	verdictFinal, veto, motif := AppliquerVetoPhysiqueCinetique(diag, verdictModele)
	confiance := float64(probsCalibrees[idxCalibre])
	if veto {
		idxFinal := indiceDuVerdict(verdictFinal)
		if idxFinal >= 0 {
			confiance = math.Max(0.85, float64(probsCalibrees[idxFinal]))
		}
	}

	return DecisionArbitrageCinetique{
		ModeleInvoque:         true,
		MoteurArbitre:         "Qwen2.5-0.5B_PrefillCache",
		VerdictBrutNonCalibre: verdictNonCalibre,
		VerdictBrutModele:     verdictModele,
		VerdictFinal:          verdictFinal,
		Confiance:             confiance,
		VetoPhysiqueApplique:  veto,
		MotifVeto:             motif,
		LogitsBrutsModele:     logitsQwen,
		BiaisNeutreModele:     a.biaisNeutre,
		DeltaLogitsModele:     deltaLogits,
		ProbabilitesBrutes:    probsBrutes,
		Probabilites:          probsCalibrees,
		DureeInferenceUs:      dureeUs,
		ActionRecommandee:     ActionPourVerdictCinetique(verdictFinal),
		DifferentielTransmis:  texteBrief,
	}, nil
}

// DossierEscaladeCinetique transporte hors bande un épisode anormal vers la file d'arbitrage SLM.
type DossierEscaladeCinetique struct {
	NomExecutable string
	Diagnostic    DiagnosticEpisodeCinetique
}

// FileArbitrageCinetique découple le moteur d'observation temps réel de la latence
// d'inférence SLM via une file bornée non bloquante comptabilisant chaque issue sans perte
// (invariant exact après Fermer : TotalSoumis == TotalArbitres + TotalErreursArbitrage).
type FileArbitrageCinetique struct {
	arbitre                ArbitreCausalCinetique
	muSoumission           sync.RWMutex
	fermee                 bool
	file                   chan DossierEscaladeCinetique
	attente                sync.WaitGroup
	fermerUneFois          sync.Once
	recepteurVerdict       func(DossierEscaladeCinetique, DecisionArbitrageCinetique)
	TotalSoumis            atomic.Uint64
	TotalIgnoresNominal    atomic.Uint64
	TotalEcartesFilePleine atomic.Uint64
	TotalArbitres          atomic.Uint64
	TotalErreursArbitrage  atomic.Uint64
}

// NouvelleFileArbitrageCinetique démarre un travailleur asynchrone unique drainant une file de capacité bornée.
func NouvelleFileArbitrageCinetique(
	arbitre ArbitreCausalCinetique,
	capacite int,
	surVerdict func(DossierEscaladeCinetique, DecisionArbitrageCinetique),
) *FileArbitrageCinetique {
	if capacite <= 0 {
		capacite = 32
	}
	f := &FileArbitrageCinetique{
		arbitre:          arbitre,
		file:             make(chan DossierEscaladeCinetique, capacite),
		recepteurVerdict: surVerdict,
	}
	f.attente.Add(1)
	go f.boucleTravailleur()
	return f
}

// SoumettreNonBloquant filtre les épisodes nominaux et pousse sans jamais bloquer
// les seuls épisodes nécessitant un arbitrage causal. TotalSoumis n'est incrémenté
// que lorsque le dossier est effectivement accepté dans la file.
func (f *FileArbitrageCinetique) SoumettreNonBloquant(nomExecutable string, diag DiagnosticEpisodeCinetique) error {
	if f == nil {
		return ErrArbitreFerme
	}
	f.muSoumission.RLock()
	defer f.muSoumission.RUnlock()
	if f.fermee {
		return ErrArbitreFerme
	}
	if !DoitEscaladeSLM(diag) {
		f.TotalIgnoresNominal.Add(1)
		return nil
	}
	select {
	case f.file <- DossierEscaladeCinetique{NomExecutable: nomExecutable, Diagnostic: diag}:
		f.TotalSoumis.Add(1)
		return nil
	default:
		f.TotalEcartesFilePleine.Add(1)
		return ErrFileArbitragePleine
	}
}

func (f *FileArbitrageCinetique) boucleTravailleur() {
	defer f.attente.Done()
	for dossier := range f.file {
		f.traiterDossier(dossier)
	}
}

func (f *FileArbitrageCinetique) traiterDossier(dossier DossierEscaladeCinetique) {
	ctx, annuler := context.WithTimeout(context.Background(), 30*time.Second)
	decision, err := f.arbitre.ArbitrerEpisode(ctx, dossier.NomExecutable, dossier.Diagnostic)
	annuler()
	if err != nil {
		f.TotalErreursArbitrage.Add(1)
		return
	}
	f.TotalArbitres.Add(1)
	if f.recepteurVerdict != nil {
		f.recepteurVerdict(dossier, decision)
	}
}

// Fermer clôt atomiquement les nouvelles soumissions, draine 100 % des dossiers déjà
// acceptés dans la file et attend la terminaison du travailleur asynchrone.
func (f *FileArbitrageCinetique) Fermer() {
	if f == nil {
		return
	}
	f.fermerUneFois.Do(func() {
		f.muSoumission.Lock()
		f.fermee = true
		close(f.file)
		f.muSoumission.Unlock()
		f.attente.Wait()
	})
}
