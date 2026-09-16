// Package main — Arbitre médico-légal SLM in-process (Qwen2.5-0.5B-Instruct Q4_K_M).
// Exécute l'inférence sous projection ARCHTIME en Pur Go (Zero CGo, Zero Wasm).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55"
	"github.com/hazyhaar/c2slm"
	"github.com/hazyhaar/c2slm/engine"
)

// RealSLMArbitrator encapsule le moteur d'inférence Go pur Qwen2.5-0.5B (c2slm).
type RealSLMArbitrator struct {
	engine            *c2slm.Engine
	gate              chan struct{}
	stop              chan struct{}
	closeOnce         sync.Once
	options           []VerdictOption
	candidateIDs      []int32
	onInferenceActive func() // Hook de test pour attester du chevauchement réel d'inférence avant Close()
}

// VerdictOption associe une étiquette autorégressive à token unique à un verdict médico-légal
type VerdictOption struct {
	Letter  string
	TokenID int32
	Verdict string
}

var defaultCandidateOptions = []VerdictOption{
	{Letter: "A", Verdict: "DNS_TUNNEL_CONFIRMED"},
	{Letter: "B", Verdict: "BENIGN_AV_TELEMETRY"},
	{Letter: "C", Verdict: "BENIGN_DKIM_KEY"},
	{Letter: "D", Verdict: "INSUFFICIENT_EVIDENCE"},
}

// NewRealSLMArbitrator charge les poids quantifiés GGUF et initialise le contexte d'inférence pur Go.
func NewRealSLMArbitrator(modelPath string) (*RealSLMArbitrator, error) {
	if _, err := os.Stat(modelPath); err != nil {
		return nil, fmt.Errorf("modèle SLM introuvable à %s: %w", modelPath, err)
	}

	eng, err := c2slm.NewEngine(modelPath)
	if err != nil {
		return nil, fmt.Errorf("c2slm.NewEngine: %w", err)
	}

	// Copie locale des options pour garantir l'immutabilité et l'absence de mutation d'état global
	localOptions := make([]VerdictOption, len(defaultCandidateOptions))
	copy(localOptions, defaultCandidateOptions)

	// Vérification stricte au chargement : chaque étiquette de choix doit être un token unique distinct
	var optionTokenIDs []int32
	seenTokens := make(map[int32]string)
	for i := range localOptions {
		toks := eng.Tokenizer.Encode(localOptions[i].Letter)
		if len(toks) != 1 {
			return nil, fmt.Errorf("l'option %s doit être encodée en 1 seul token, got %d", localOptions[i].Letter, len(toks))
		}
		tID := toks[0]
		if prev, exists := seenTokens[tID]; exists {
			return nil, fmt.Errorf("collision de token entre option %s et %s (token %d)", localOptions[i].Letter, prev, tID)
		}
		seenTokens[tID] = localOptions[i].Letter
		localOptions[i].TokenID = tID
		optionTokenIDs = append(optionTokenIDs, tID)
	}

	return &RealSLMArbitrator{
		engine:       eng,
		gate:         make(chan struct{}, 1),
		stop:         make(chan struct{}),
		options:      localOptions,
		candidateIDs: optionTokenIDs,
	}, nil
}

// Close libère les ressources mmap de l'inféreur pur Go en garantissant l'idempotence et l'absence d'inférence concurrente.
func (a *RealSLMArbitrator) Close() error {
	var err error
	a.closeOnce.Do(func() {
		close(a.stop)
		// Acquérir le verrou gate pour attendre la fin de toute inférence en cours avant munmap
		a.gate <- struct{}{}
		defer func() { <-a.gate }()
		if a.engine != nil {
			err = a.engine.Close()
		}
	})
	return err
}

// sanitizePromptInput neutralise les tentatives d'injection de prompt et les caractères hors RFC 1035.
func sanitizePromptInput(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for i := 0; i < len(input); i++ {
		ch := input[i]
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-' {
			b.WriteByte(ch)
		}
	}
	res := b.String()
	if len(res) > 253 {
		res = res[:253]
	}
	return res
}

// Arbitrate exécute l'inférence sous projection ARCHTIME pour rendre un verdict médico-légal.
func (a *RealSLMArbitrator) Arbitrate(ctx context.Context, inc *c2blue55.SLMIncident) (c2blue55.SLMArbitrationResponse, error) {
	if err := ctx.Err(); err != nil {
		return c2blue55.SLMArbitrationResponse{}, err
	}
	select {
	case <-ctx.Done():
		return c2blue55.SLMArbitrationResponse{}, ctx.Err()
	case <-a.stop:
		return c2blue55.SLMArbitrationResponse{}, fmt.Errorf("SLM closed")
	case a.gate <- struct{}{}:
	}
	defer func() { <-a.gate }()

	// Vérification immédiate de fermeture et de contexte une fois le verrou acquis
	if err := ctx.Err(); err != nil {
		return c2blue55.SLMArbitrationResponse{}, err
	}
	select {
	case <-a.stop:
		return c2blue55.SLMArbitrationResponse{}, fmt.Errorf("SLM closed")
	default:
	}

	// Signalement d'inférence active sous section critique verrouillée
	if a.onInferenceActive != nil {
		a.onInferenceActive()
	}
	if inc == nil {
		return c2blue55.SLMArbitrationResponse{}, fmt.Errorf("nil incident")
	}

	fqdn := sanitizePromptInput(inc.FQDN)
	parent := sanitizePromptInput(inc.ParentDomain)
	subdomain := sanitizePromptInput(inc.Subdomain)
	indicator := sanitizePromptInput(inc.SuspectedIndicator)

	prompt := fmt.Sprintf(`<|im_start|>system
Tu es un arbitre médico-légal DNS pour la détection de tunnels et d'exfiltration C2.
Tu analyses un cas limite rapporté par la sonde SIMD amont.
Réponds exclusivement par l'option choisie.<|im_end|>
<|im_start|>user
[DOSSIER MÉDICO-LÉGAL INCIDENT DNS]
FQDN: %s
Domaine_Parent: %s
Sous_Domaine: %s
RR_Type: %d
Entropie_Shannon_Q8: %d (%.2f bits/octet)
Classe_Payload: %d
Jitter_Beaconing: %d%%
Sous_Domaines_Uniques: %d
Nombre_Requetes: %d
Indicateur_Suspect: %s

Options de verdict :
A: DNS_TUNNEL_CONFIRMED
B: BENIGN_AV_TELEMETRY
C: BENIGN_DKIM_KEY
D: INSUFFICIENT_EVIDENCE

Arbitre ce cas limite en choisissant l'option correspondante (A, B, C ou D).<|im_end|>
<|im_start|>assistant
{"verdict_option": "`, fqdn, parent, subdomain, inc.QType, inc.EntropyQ8, inc.EntropyBits, inc.PayloadClass, inc.JitterPct, inc.UniqueSubdomains, inc.QueryCount, indicator)

	// Ingestion et vérification coopérative de contexte
	tokens := a.engine.Tokenizer.Encode(prompt)
	if len(tokens) >= engine.MaxContextLen {
		tokens = tokens[:engine.MaxContextLen-1]
	}

	a.engine.KVCache.Reset()

	var lastNormX []float32
	for pos, tokID := range tokens {
		if err := ctx.Err(); err != nil {
			a.engine.KVCache.Reset()
			return c2blue55.SLMArbitrationResponse{}, err
		}
		select {
		case <-a.stop:
			return c2blue55.SLMArbitrationResponse{}, fmt.Errorf("SLM closed")
		default:
		}
		lastNormX = engine.Forward(a.engine.Model, a.engine.KVCache, a.engine.Arena, tokID, pos)
	}

	// Échantillonnage ARCHTIME : Projection autorégressive des logits du SLM sur les options A, B, C, D
	verdict, confidence, thought := a.arbitrateModelLogits(inc, lastNormX)

	resp := localHITLResponse(inc, verdict, confidence, thought)
	return resp, nil
}

// arbitrateModelLogits utilise les activations réelles du modèle (normX) et la projection ARCHTIME
func (a *RealSLMArbitrator) arbitrateModelLogits(inc *c2blue55.SLMIncident, normX []float32) (string, float64, string) {
	// Calcul des logits pour chaque option autorégressive à token unique distinct (A, B, C, D)
	scores := make([]float32, len(a.options))
	engine.ComputeLogits(a.engine.Model, a.engine.Arena, normX, a.engine.Arena.Logits, a.candidateIDs)

	maxLogit := float32(-1e9)
	bestIdx := 0

	for i, opt := range a.options {
		// Logit neuronal pur du token d'option autorégressif
		modelLogit := a.engine.Arena.Logits[opt.TokenID]

		// A priori médico-légal structurel de la sonde SIMD
		var prior float32
		switch opt.Verdict {
		case "DNS_TUNNEL_CONFIRMED":
			if inc.EntropyBits >= 4.0 && (inc.UniqueSubdomains >= 5 || inc.JitterPct <= 20) {
				prior = 5.0
			}
		case "BENIGN_AV_TELEMETRY":
			if strings.Contains(strings.ToLower(inc.FQDN), "sophos") || strings.Contains(strings.ToLower(inc.FQDN), "avast") {
				prior = 6.0
			}
		case "BENIGN_DKIM_KEY":
			if strings.Contains(strings.ToLower(inc.FQDN), "domainkey") || inc.QType == c2blue55.TypeTXT && strings.Contains(inc.Subdomain, "k1") {
				prior = 6.0
			}
		case "INSUFFICIENT_EVIDENCE":
			if inc.EntropyBits < 3.5 && inc.UniqueSubdomains <= 2 {
				prior = 4.0
			}
		}

		totalScore := modelLogit + prior
		scores[i] = totalScore
		if totalScore > maxLogit {
			maxLogit = totalScore
			bestIdx = i
		}
	}

	// Normalisation Softmax pure sur la distribution des options candidates autorégressives
	var sumExp float64
	for _, s := range scores {
		sumExp += math.Exp(float64(s - maxLogit))
	}
	prob := 1.0 / sumExp

	selectedVerdict := a.options[bestIdx].Verdict

	var thought string
	switch selectedVerdict {
	case "DNS_TUNNEL_CONFIRMED":
		thought = fmt.Sprintf("Arbitrage SLM Qwen2.5 (Option %s) : Probabilité de tunnel %.2f%% confirmée sur profil d'entropie %.2f bits et indicateur %s.",
			a.options[bestIdx].Letter, prob*100, inc.EntropyBits, inc.SuspectedIndicator)
	case "BENIGN_AV_TELEMETRY":
		thought = fmt.Sprintf("Arbitrage SLM Qwen2.5 (Option %s) : Télémesure antivirus bénigne classifiée avec confiance %.2f%%.",
			a.options[bestIdx].Letter, prob*100)
	case "BENIGN_DKIM_KEY":
		thought = fmt.Sprintf("Arbitrage SLM Qwen2.5 (Option %s) : Clé d'authentification email DKIM validée avec confiance %.2f%%.",
			a.options[bestIdx].Letter, prob*100)
	default:
		thought = fmt.Sprintf("Arbitrage SLM Qwen2.5 (Option %s) : Preuve insuffisante pour conclure à une menace active (confiance %.2f%%).",
			a.options[bestIdx].Letter, prob*100)
	}

	return selectedVerdict, prob, thought
}

// ParseJSONResponse extrait les champs structurés si du JSON brut est fourni
func ParseJSONResponse(raw string) (verdict string, confidence float64, thought string, err error) {
	var parsed struct {
		Verdict    string  `json:"verdict"`
		Confidence float64 `json:"confidence"`
		Thought    string  `json:"thought"`
	}
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return "", 0, "", err
	}
	return parsed.Verdict, parsed.Confidence, parsed.Thought, nil
}
