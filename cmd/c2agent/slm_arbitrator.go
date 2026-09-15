// Package main — Arbitre médico-légal SLM in-process (Qwen2.5-0.5B-Instruct Q4_K_M).
// Exécute l'inférence sous contrainte GBNF en Pur Go (Zero CGo, Wasm2Go).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55"
	"github.com/goccy/go-llama"
)

const gbnfGrammar = `root ::= "{" ws "\"verdict\":" ws verdict "," ws "\"confidence\":" ws number "," ws "\"thought\":" ws string "}"
verdict ::= "\"BENIGN_AV_TELEMETRY\"" | "\"BENIGN_DKIM_KEY\"" | "\"DNS_TUNNEL_CONFIRMED\"" | "\"INSUFFICIENT_EVIDENCE\""
string ::= "\"" [^"\\\r\n]* "\""
number ::= [0-9]+ ("." [0-9]+)?
ws ::= [ \t\n]*
`

// RealSLMArbitrator encapsule le moteur d'inférence Go pur Qwen2.5-0.5B.
type RealSLMArbitrator struct {
	l         *llama.Llama
	model     *llama.Model
	ctx       *llama.Context
	gate      chan struct{}
	stop      chan struct{}
	closeOnce sync.Once
}

// NewRealSLMArbitrator charge les poids quantifiés GGUF et initialise le contexte d'inférence.
func NewRealSLMArbitrator(modelPath string) (*RealSLMArbitrator, error) {
	if _, err := os.Stat(modelPath); err != nil {
		return nil, fmt.Errorf("modèle SLM introuvable à %s: %w", modelPath, err)
	}

	l, err := llama.New(
		llama.WithStderr(os.Stderr),
		llama.WithMaxMemory(1200<<20),
	)
	if err != nil {
		return nil, fmt.Errorf("llama.New: %w", err)
	}

	model, err := l.LoadModel(modelPath)
	if err != nil {
		_ = l.Close()
		return nil, fmt.Errorf("LoadModel: %w", err)
	}

	ctxParams := llama.ContextParams{
		NCtx:     512, // Context bound; not a guarantee about process RSS.
		NThreads: 4,
	}
	ctx, err := model.NewContext(ctxParams)
	if err != nil {
		_ = model.Close()
		_ = l.Close()
		return nil, fmt.Errorf("NewContext: %w", err)
	}

	return &RealSLMArbitrator{
		l:     l,
		model: model,
		ctx:   ctx,
		gate:  make(chan struct{}, 1),
		stop:  make(chan struct{}),
	}, nil
}

// maxSanitizedPromptLen borne la sortie assainie à 253 octets, longueur maximale d'un
// nom (FQDN) RFC 1035 une fois le point terminal exclu.
const maxSanitizedPromptLen = 253

// sanitizePromptInput neutralise toute tentative d'injection ChatML, de rupture de rôle
// ou d'injection sémantique dans un champ textuel interpolé au prompt. Seuls les
// caractères canoniques d'un nom DNS sont conservés : les lettres minuscules a-z, les
// chiffres 0-9, le point et le tiret (RFC 1035). Les majuscules A-Z sont repliées en
// minuscules ; tout autre octet (espaces, ponctuation, chevrons, balises de contrôle,
// caractères non ASCII ou non imprimables) est supprimé. Le résultat est borné à 253 octets.
func sanitizePromptInput(s string) string {
	if len(s) == 0 {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s) && b.Len() < maxSanitizedPromptLen; i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '-':
			b.WriteByte(c)
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + 32)
		}
	}
	return b.String()
}

// Arbitrate exécute l'inférence sous grammaire formelle GBNF pour rendre un verdict médico-légal.
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
	if err := ctx.Err(); err != nil {
		return c2blue55.SLMArbitrationResponse{}, err
	}
	select {
	case <-a.stop:
		return c2blue55.SLMArbitrationResponse{}, fmt.Errorf("SLM closed")
	default:
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
Réponds exclusivement au format JSON strict imposé.<|im_end|>
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

Arbitre ce cas limite : détermine si c'est un tunnel C2, une télémesure bénigne ou une preuve insuffisante.<|im_end|>
<|im_start|>assistant
`, fqdn, parent, subdomain, inc.QType, inc.EntropyQ8, inc.EntropyBits, inc.PayloadClass, inc.JitterPct, inc.UniqueSubdomains, inc.QueryCount, indicator)

	params := llama.Params{
		Grammar:       gbnfGrammar,
		Temperature:   0.0, // Inférence greedy déterministe
		RepeatPenalty: 1.15,
		RepeatLastN:   64,
		NPredict:      256,
	}

	var sb strings.Builder
	finished := make(chan struct{})
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-finished:
			return
		case <-ctx.Done():
		case <-a.stop:
		}
		// Stream resets its interrupt flag at entry. Repeat until it returns
		// to cover cancellation racing with that reset, and join before reuse.
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			_ = a.ctx.Interrupt()
			select {
			case <-finished:
				return
			case <-tick.C:
			}
		}
	}()
	_, err := a.ctx.Stream(prompt, params, func(piece string) {
		if ctx.Err() == nil {
			sb.WriteString(piece)
		}
	})
	close(finished)
	<-joined
	if cancelErr := ctx.Err(); cancelErr != nil {
		// Interrupted decode leaves the KV context unusable in this engine.
		// Release it only after Stream and its interrupt watcher have joined.
		_ = a.ctx.Close()
		a.ctx, err = a.model.NewContext(llama.ContextParams{NCtx: 512, NThreads: 4})
		if err != nil {
			a.closeOnce.Do(func() { close(a.stop) })
			return c2blue55.SLMArbitrationResponse{}, fmt.Errorf("%w; restore inference context: %v", cancelErr, err)
		}
		return c2blue55.SLMArbitrationResponse{}, cancelErr
	}
	select {
	case <-a.stop:
		return c2blue55.SLMArbitrationResponse{}, fmt.Errorf("SLM closed")
	default:
	}
	if err != nil {
		return c2blue55.SLMArbitrationResponse{}, fmt.Errorf("inférence SLM: %w", err)
	}

	outputStr := sb.String()
	var parsed struct {
		Verdict    string  `json:"verdict"`
		Confidence float64 `json:"confidence"`
		Thought    string  `json:"thought"`
	}
	if err := json.Unmarshal([]byte(outputStr), &parsed); err != nil {
		return c2blue55.SLMArbitrationResponse{
			Verdict:           "INSUFFICIENT_EVIDENCE",
			Confidence:        0.0,
			Thought:           "Sortie SLM non conforme au schéma: " + outputStr,
			HumanSummary:      c2blue55.BuildHumanSummary(inc),
			RecommendedAction: c2blue55.RecommendedActionForVerdict("INSUFFICIENT_EVIDENCE"),
		}, nil
	}

	if parsed.Confidence > 1.0 {
		parsed.Confidence /= 100.0
	}

	return c2blue55.SLMArbitrationResponse{
		Verdict:           parsed.Verdict,
		Confidence:        parsed.Confidence,
		Thought:           parsed.Thought,
		HumanSummary:      c2blue55.BuildHumanSummary(inc),
		RecommendedAction: c2blue55.RecommendedActionForVerdict(parsed.Verdict),
	}, nil
}

// Close libère les ressources et contextes Wasm2Go.
func (a *RealSLMArbitrator) Close() {
	a.closeOnce.Do(func() { close(a.stop) })
	a.gate <- struct{}{}
	defer func() { <-a.gate }()
	if a.ctx != nil {
		_ = a.ctx.Close()
		a.ctx = nil
	}
	if a.model != nil {
		_ = a.model.Close()
		a.model = nil
	}
	if a.l != nil {
		_ = a.l.Close()
		a.l = nil
	}
}
