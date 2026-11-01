// Arbitre médico-légal à encodeur pur Go (CGO=0, passe unique).
//
// PureGoEncoderArbitrator remplace RealSLMArbitrator : au lieu de détourner un
// modèle autoregressif Qwen2.5-0.5B (verrou unitaire, sérialisation ChatML,
// 250 à 450 ms), il ingère directement le dossier d'incident SLMIncident,
// l'encode en une passe déterministe sans allocation de tas et projette l'état
// latent sur les quatre verdicts officiels via le micro-noyau AVX2
// c2_tensor_logit_gather_softmax (repli scalaire inclus), exposé par la tête de
// décision typée du moteur c2slm.
//
// La décision neuronale n'est jamais souveraine : le veto déterministe Go
// (Pipeline.ApplyDeterministicVeto) est appliqué avant toute sortie, et un cas
// aux métriques physiques hostiles (entropie >= 4.0 bits/octet, gigue faible,
// prolifération de sous-domaines) ne peut être blanchi par un verdict bénin.
// Aucune chaîne d'invite n'est construite : l'injection de prompt est sans objet.
package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync/atomic"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2slm/engine"
)

// encoderFeatureDim est la largeur de l'état latent produit par l'encodeur.
const encoderFeatureDim = 16

// encoderNumVerdicts est le nombre de verdicts officiels projetés.
const encoderNumVerdicts = 4

// encoderTemperature durcit la distribution softmax des verdicts.
const encoderTemperature = 0.7

// encoderMaxLatencyNanos borne la latence unitaire d'une passe d'encodage
// (10 ms). Valeur de contrôle opposable pour les tests de non-régression.
const encoderMaxLatencyNanos = 10 * 1000 * 1000

// Indices des composantes de l'état latent. Chaque composante est une mesure
// normalisée de [0,1] ou un indicateur binaire déterministe.
const (
	featHostileEntropy = iota
	featLowJitter
	featSubdomainFlood
	featBeaconVolume
	featDensePayload
	featTunnelRecord
	featVendorTelemetry
	featDkimSelector
	featWeakSample
	featEntropyMagnitude
	featJitterMagnitude
	featSubdomainMagnitude
	featQueryMagnitude
	featQTypeTXT
	featQTypeNULL
	featIndicatorDense
)

// encoderVerdictLabels respecte l'ordre officiel A, B, C, D.
var encoderVerdictLabels = [encoderNumVerdicts]string{
	"DNS_TUNNEL_CONFIRMED",  // A
	"BENIGN_AV_TELEMETRY",   // B
	"BENIGN_DKIM_KEY",       // C
	"INSUFFICIENT_EVIDENCE", // D
}

// encoderCandidateWeights est la table de projection précalculée : quatre
// rangées (une par verdict), largeur encoderFeatureDim. Table déclarée avant la
// compilation, conforme à la règle ARCHTIME (aucun apprentissage au runtime).
var encoderCandidateWeights = [encoderNumVerdicts][encoderFeatureDim]float32{
	{ // A — DNS_TUNNEL_CONFIRMED
		featHostileEntropy:     1.2,
		featLowJitter:          1.0,
		featSubdomainFlood:     1.2,
		featBeaconVolume:       0.8,
		featDensePayload:       0.8,
		featTunnelRecord:       0.4,
		featEntropyMagnitude:   1.5,
		featSubdomainMagnitude: 0.8,
		featQTypeNULL:          0.3,
		featIndicatorDense:     0.6,
	},
	{ // B — BENIGN_AV_TELEMETRY
		featVendorTelemetry: 3.0,
	},
	{ // C — BENIGN_DKIM_KEY
		featDkimSelector: 3.0,
	},
	{ // D — INSUFFICIENT_EVIDENCE
		featWeakSample: 2.5,
	},
}

// encoderCandidateBiases est le biais fixe par verdict. Le biais positif de D
// garantit qu'un dossier sans signal conclut à la preuve insuffisante plutôt
// qu'à un tunnel par égalité stricte.
var encoderCandidateBiases = [encoderNumVerdicts]float32{-0.5, -0.6, -0.6, 0.3}

// encoderVendorMarkers identifie la télémétrie éditeur légitime.
var encoderVendorMarkers = []string{
	"sophos", "avast", "mcafee", "crowdstrike", "sentinelone", "eset",
	"kaspersky", "defender", "trendmicro", "paloaltonetworks", "fortinet",
	"symantec", "bitdefender", "telemetry",
}

// encoderDkimMarkers identifie les sélecteurs d'authentification email.
var encoderDkimMarkers = []string{"domainkey", "dkim", "selector1", "selector2"}

// encoderDenseMarkers identifie les indicateurs de charge utile dense.
var encoderDenseMarkers = []string{"payload_dense", "hex", "base64", "entropy"}

// PureGoEncoderArbitrator est l'arbitre à encodeur pur Go. Il est immuable après
// construction : la tête de décision est en lecture seule et chaque appel
// Arbitrate utilise ses propres tableaux sur pile, ce qui le rend sûr en
// concurrence sans verrou.
type PureGoEncoderArbitrator struct {
	head     *engine.DecisionHead
	pipeline *c2blue55.Pipeline
	closed   atomic.Bool
}

// NewPureGoEncoderArbitrator construit l'arbitre au-dessus d'un pipeline, qui
// fournit le veto déterministe et la fiche HITL. Un pipeline nul est refusé :
// le veto est obligatoire, jamais optionnel.
func NewPureGoEncoderArbitrator(p *c2blue55.Pipeline) (*PureGoEncoderArbitrator, error) {
	if p == nil {
		return nil, errors.New("PureGoEncoderArbitrator: pipeline de veto obligatoire")
	}
	weights := make([]float32, encoderNumVerdicts*encoderFeatureDim)
	for i := range encoderNumVerdicts {
		copy(weights[i*encoderFeatureDim:(i+1)*encoderFeatureDim], encoderCandidateWeights[i][:])
	}
	biases := make([]float32, encoderNumVerdicts)
	copy(biases, encoderCandidateBiases[:])
	return &PureGoEncoderArbitrator{
		head: &engine.DecisionHead{
			Weights:     weights,
			Biases:      biases,
			HiddenDim:   encoderFeatureDim,
			Temperature: encoderTemperature,
		},
		pipeline: p,
	}, nil
}

// Close marque l'arbitre comme clos. L'opération est idempotente. Elle ne ferme
// pas le pipeline, dont la propriété reste à l'appelant.
func (a *PureGoEncoderArbitrator) Close() error {
	if a != nil {
		a.closed.Store(true)
	}
	return nil
}

// Arbitrate implémente c2blue55.SLMArbitrator. L'encodage est une passe unique
// déterministe ; aucun verrou d'exclusion n'est requis.
func (a *PureGoEncoderArbitrator) Arbitrate(ctx context.Context, inc *c2blue55.SLMIncident) (c2blue55.SLMArbitrationResponse, error) {
	if a == nil {
		return c2blue55.SLMArbitrationResponse{}, errors.New("PureGoEncoderArbitrator: nil receiver")
	}
	if err := ctx.Err(); err != nil {
		return c2blue55.SLMArbitrationResponse{}, err
	}
	if a.closed.Load() {
		return c2blue55.SLMArbitrationResponse{}, errors.New("PureGoEncoderArbitrator: closed")
	}
	if inc == nil {
		return c2blue55.SLMArbitrationResponse{}, errors.New("PureGoEncoderArbitrator: nil incident")
	}

	proposed, confidence, _ := a.infer(inc)

	// Veto déterministe obligatoire : valide le vocabulaire et borne les
	// heuristiques physiques avant toute sortie. Le veto enrichit le dossier
	// reçu ; une copie locale évite toute mutation du dossier de l'appelant et
	// rend l'arbitre sûr en concurrence sur un dossier partagé.
	local := *inc
	finalVerdict, vetoConf, reason := a.pipeline.ApplyDeterministicVeto(&local, proposed)
	if reason != "MODEL_PROPOSAL_NOT_PROOF" {
		confidence = vetoConf
	}
	confidence = sanitizeConfidence(confidence)

	return c2blue55.SLMArbitrationResponse{
		Verdict:           finalVerdict,
		Confidence:        confidence,
		Thought:           buildEncoderThought(inc, finalVerdict, confidence, reason),
		HumanSummary:      c2blue55.BuildHumanSummary(inc),
		RecommendedAction: c2blue55.RecommendedActionForVerdict(finalVerdict),
	}, nil
}

// infer encode le dossier d'incident en une passe et projette l'état latent sur
// les quatre verdicts. Aucun tampon n'est alloué sur le tas : l'état latent et
// les probabilités sont des tableaux locaux. Le garde-fou physique force le
// verdict tunnel dès que les métriques sont hostiles, de sorte qu'un verdict
// bénin halluciné ne puisse jamais blanchi un tunnel avéré.
func (a *PureGoEncoderArbitrator) infer(inc *c2blue55.SLMIncident) (verdict string, confidence float64, hostile bool) {
	var hidden [encoderFeatureDim]float32
	var probs [encoderNumVerdicts]float32
	encodeIncidentFeatures(inc, &hidden)

	_, label, conf, _ := a.head.DecideChoice(hidden[:], encoderNumVerdicts, encoderVerdictLabels[:], probs[:])

	hostile = hostilePhysicalMetrics(inc)
	if hostile && isBenignVerdict(label) {
		verdict = encoderVerdictLabels[0]
		confidence = float64(probs[0])
		return verdict, confidence, hostile
	}
	return label, float64(conf), hostile
}

// encodeIncidentFeatures remplit l'état latent à partir du dossier d'incident.
// Aucune allocation de tas : les correspondances de chaînes se font sans
// minuscule intermédiaire (containsFold / hasPrefixFold).
func encodeIncidentFeatures(inc *c2blue55.SLMIncident, hidden *[encoderFeatureDim]float32) {
	if inc == nil {
		return
	}
	entropy := inc.EntropyBits
	fqdn := inc.FQDN
	sub := inc.Subdomain
	indicator := inc.SuspectedIndicator

	hostile := entropy >= 4.0
	hidden[featHostileEntropy] = bool32(hostile)
	hidden[featLowJitter] = bool32(inc.JitterPct <= 20)
	hidden[featSubdomainFlood] = bool32(inc.UniqueSubdomains >= 5)
	hidden[featBeaconVolume] = clamp01(float32(inc.QueryCount) / 16.0)
	hidden[featDensePayload] = bool32(inc.PayloadClass == c2blue55.PayloadClassHex || inc.PayloadClass == c2blue55.PayloadClassBase64)
	hidden[featTunnelRecord] = bool32(inc.QType == c2blue55.TypeTXT || inc.QType == c2blue55.TypeNULL)
	hidden[featVendorTelemetry] = bool32(containsAnyFold(fqdn, encoderVendorMarkers) || containsAnyFold(sub, encoderVendorMarkers))
	hidden[featDkimSelector] = bool32(containsAnyFold(fqdn, encoderDkimMarkers) || containsAnyFold(sub, encoderDkimMarkers) ||
		hasPrefixFold(sub, "k1") || hasPrefixFold(sub, "k2") || hasPrefixFold(sub, "k3"))
	hidden[featWeakSample] = bool32(entropy < 3.5 && inc.UniqueSubdomains <= 2 && inc.QueryCount < 3)
	hidden[featEntropyMagnitude] = normMagnitude(entropy, 8.0)
	hidden[featJitterMagnitude] = clamp01(float32(inc.JitterPct) / 100.0)
	hidden[featSubdomainMagnitude] = clamp01(float32(inc.UniqueSubdomains) / 16.0)
	hidden[featQueryMagnitude] = clamp01(float32(inc.QueryCount) / 16.0)
	hidden[featQTypeTXT] = bool32(inc.QType == c2blue55.TypeTXT)
	hidden[featQTypeNULL] = bool32(inc.QType == c2blue55.TypeNULL)
	hidden[featIndicatorDense] = bool32(containsAnyFold(indicator, encoderDenseMarkers))
}

// hostilePhysicalMetrics caractérise un cas physiquement hostile : forte
// entropie et gigue faible ou prolifération de sous-domaines. C'est ce triplet
// que le veto doit rendre impossible à blanchir.
func hostilePhysicalMetrics(inc *c2blue55.SLMIncident) bool {
	if inc == nil || math.IsNaN(inc.EntropyBits) || math.IsInf(inc.EntropyBits, 0) {
		return false
	}
	return inc.EntropyBits >= 4.0 && (inc.UniqueSubdomains >= 5 || inc.JitterPct <= 20)
}

// isBenignVerdict reconnaît les verdicts de blanchiment.
func isBenignVerdict(verdict string) bool {
	switch verdict {
	case "BENIGN_AV_TELEMETRY", "BENIGN_DKIM_KEY", "BENIGN_CRYPTO_KEY":
		return true
	}
	return false
}

// buildEncoderThought assemble la pensée d'analyse de la fiche médico-légale.
func buildEncoderThought(inc *c2blue55.SLMIncident, verdict string, confidence float64, reason string) string {
	if inc == nil {
		return ""
	}
	var motif string
	switch verdict {
	case "DNS_TUNNEL_CONFIRMED":
		motif = "tunnel C2 confirmé par encodeur pur Go"
	case "BENIGN_AV_TELEMETRY":
		motif = "télémétrie antivirus bénigne"
	case "BENIGN_DKIM_KEY":
		motif = "clé d'authentification email DKIM"
	case "BENIGN_CRYPTO_KEY":
		motif = "clé cryptographique normalisée bénigne"
	default:
		motif = "preuve insuffisante pour conclure"
	}
	return fmt.Sprintf(
		"Arbitrage encodeur pur Go (option %s, %s) : confiance calibrée %.2f%%, entropie %.2f bits/octet, jigue %d%%, sous-domaines uniques %d, requêtes %d, motif déterministe %s.",
		verdictLetter(verdict), motif, confidence*100, inc.EntropyBits, inc.JitterPct, inc.UniqueSubdomains, inc.QueryCount, reason,
	)
}

// verdictLetter associe le verdict à son étiquette officielle A, B, C ou D.
func verdictLetter(verdict string) string {
	switch verdict {
	case "DNS_TUNNEL_CONFIRMED":
		return "A"
	case "BENIGN_AV_TELEMETRY":
		return "B"
	case "BENIGN_DKIM_KEY":
		return "C"
	default:
		return "D"
	}
}

// sanitizeConfidence borne la confiance à [0,1] et neutralise NaN/Inf.
func sanitizeConfidence(v float64) float64 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// bool32 convertit un booléen en composante 0/1.
func bool32(b bool) float32 {
	if b {
		return 1
	}
	return 0
}

// clamp01 borne une composante à [0,1], NaN inclus.
func clamp01(v float32) float32 {
	if math.IsNaN(float64(v)) || v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// normMagnitude normalise une grandeur physique par sa borne.
func normMagnitude(v, max float64) float32 {
	if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 || max <= 0 {
		return 0
	}
	return clamp01(float32(v / max))
}

// containsAnyFold teste, sans allocation, la présence d'un marqueur parmi une
// liste, en repliant ASCII la casse à la volée.
func containsAnyFold(hay string, needles []string) bool {
	for _, needle := range needles {
		if containsFold(hay, needle) {
			return true
		}
	}
	return false
}

// containsFold est un strings.Contains insensible à la casse ASCII, sans
// allocation.
func containsFold(hay, needle string) bool {
	n := len(needle)
	if n == 0 {
		return true
	}
	if n > len(hay) {
		return false
	}
	for i := 0; i+n <= len(hay); i++ {
		match := true
		for j := range n {
			if foldASCII(hay[i+j]) != foldASCII(needle[j]) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// hasPrefixFold teste un préfixe insensible à la casse ASCII, sans allocation.
func hasPrefixFold(hay, prefix string) bool {
	if len(prefix) > len(hay) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if foldASCII(hay[i]) != foldASCII(prefix[i]) {
			return false
		}
	}
	return true
}

// foldASCII replie une lettre majuscule ASCII en minuscule.
func foldASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}
