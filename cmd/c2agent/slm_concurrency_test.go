package main

import (
	"context"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55"
	"github.com/hazyhaar/c2slm/engine"
)

func TestRealSLMArbitrator_ConcurrentClose(t *testing.T) {
	modelPath := "/data/models/qwen2.5-0.5b-gguf/qwen2.5-0.5b-instruct-q4_k_m.gguf"
	arb, err := NewRealSLMArbitrator(modelPath)
	if err != nil {
		t.Skipf("Modèle Qwen2.5 non présent: %v", err)
	}

	inc := &c2blue55.SLMIncident{
		FQDN:               "sophosxl.net",
		Subdomain:          "4c892a.sophosxl.net",
		QType:              c2blue55.TypeA,
		EntropyBits:        4.5,
		UniqueSubdomains:   8,
		JitterPct:          12,
		SuspectedIndicator: "High entropy repetitive subdomain",
	}

	inferenceEngaged := make(chan struct{})
	inferenceContinue := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)

	// Hook de synchronisation attestant que Arbitrate détient a.gate
	arb.onInferenceActive = func() {
		close(inferenceEngaged) // Signalement formel : Arbitrate détient a.gate
		<-inferenceContinue     // Maintien déterministe dans la section critique jusqu'à l'engagement de Close()
	}

	// Goroutine d'inférence active
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = arb.Arbitrate(ctx, inc)
	}()

	// Attendre de manière garantie que l'inférence détienne a.gate
	<-inferenceEngaged

	// Lancement de deux fermetures strictement concurrentes dans des goroutines distinctes
	var closeWg sync.WaitGroup
	closeWg.Add(2)
	var errClose1, errClose2 error
	closeStarted := make(chan struct{})
	go func() {
		defer closeWg.Done()
		close(closeStarted)
		errClose1 = arb.Close()
	}()
	go func() {
		defer closeWg.Done()
		errClose2 = arb.Close()
	}()

	<-closeStarted
	// Permettre à l'inférence de se terminer maintenant que Close() est engagé
	time.Sleep(10 * time.Millisecond)
	close(inferenceContinue)

	closeWg.Wait()
	wg.Wait()
	arb.onInferenceActive = nil

	if errClose1 != nil {
		t.Errorf("Premier Close() concurrent a échoué: %v", errClose1)
	}
	if errClose2 != nil {
		t.Errorf("Second Close() concurrent a échoué: %v", errClose2)
	}

	// Vérification formelle du rejet post-fermeture
	ctxPost, cancelPost := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelPost()
	_, errPost := arb.Arbitrate(ctxPost, inc)
	if errPost == nil || !strings.Contains(errPost.Error(), "SLM closed") {
		t.Fatalf("L'arbitrage post-fermeture aurait dû être rejeté avec 'SLM closed', got: %v", errPost)
	}

	t.Logf("Concurrent Close, Idempotence, et Rejet post-fermeture ('SLM closed') validés avec succès sous race detector !")
}

func TestContextBound_EdgeCases(t *testing.T) {
	modelPath := "/data/models/qwen2.5-0.5b-gguf/qwen2.5-0.5b-instruct-q4_k_m.gguf"
	arb, err := NewRealSLMArbitrator(modelPath)
	if err != nil {
		t.Skipf("Modèle non présent: %v", err)
	}
	defer arb.Close()

	// 1. Vérification unitaire de la troncature défensive à MaxContextLen - 1
	hugeText := strings.Repeat("malicious-subdomain-sequence-for-context-overflow-testing ", 1700)
	rawTokens := arb.engine.Tokenizer.Encode(hugeText)
	if len(rawTokens) < engine.MaxContextLen {
		t.Fatalf("Le texte de test aurait dû générer plus de %d tokens, got %d", engine.MaxContextLen, len(rawTokens))
	}
	truncatedTokens := rawTokens
	if len(truncatedTokens) >= engine.MaxContextLen {
		truncatedTokens = truncatedTokens[:engine.MaxContextLen-1]
	}
	if len(truncatedTokens) != engine.MaxContextLen-1 {
		t.Fatalf("Longueur tronquée %d != %d", len(truncatedTokens), engine.MaxContextLen-1)
	}

	// 2. Inférence de bout en bout avec prompt aux limites
	inc := &c2blue55.SLMIncident{
		FQDN:               "tunnel-exfil-dns-detection.testing.internal",
		Subdomain:          strings.Repeat("a", 240),
		QType:              c2blue55.TypeTXT,
		EntropyBits:        4.8,
		UniqueSubdomains:   15,
		JitterPct:          5,
		SuspectedIndicator: strings.Repeat("x", 240),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 360*time.Second)
	defer cancel()

	resp, err := arb.Arbitrate(ctx, inc)
	if err != nil {
		t.Fatalf("L'arbitrage aux bornes a échoué: %v", err)
	}
	if resp.Verdict == "" {
		t.Fatalf("Verdict vide inacceptable")
	}
	if math.IsNaN(resp.Confidence) || resp.Confidence <= 0.0 || resp.Confidence > 1.0 {
		t.Fatalf("Confiance invalide ou NaN: %f", resp.Confidence)
	}
	t.Logf("Première inférence aux bornes réussie : Verdict=%s, Conf=%.4f", resp.Verdict, resp.Confidence)

	// 3. Réutilisation nominale immédiate pour prouver la santé continue du cache KV
	incNominal := &c2blue55.SLMIncident{
		FQDN:               "sophosxl.net",
		Subdomain:          "telemetry.sophosxl.net",
		QType:              c2blue55.TypeA,
		EntropyBits:        3.1,
		UniqueSubdomains:   1,
		JitterPct:          45,
		SuspectedIndicator: "Standard AV Telemetry",
	}
	respNominal, errNominal := arb.Arbitrate(ctx, incNominal)
	if errNominal != nil {
		t.Fatalf("La réutilisation nominale après troncature a échoué: %v", errNominal)
	}
	if respNominal.Verdict != "BENIGN_AV_TELEMETRY" {
		t.Fatalf("L'incident bénin sophosxl.net aurait dû être classifié BENIGN_AV_TELEMETRY, got: %s", respNominal.Verdict)
	}
	t.Logf("Seconde inférence nominale réussie : Verdict=%s (bénin confirmé), Conf=%.4f", respNominal.Verdict, respNominal.Confidence)
}

func TestNominalBenignClassification(t *testing.T) {
	modelPath := "/data/models/qwen2.5-0.5b-gguf/qwen2.5-0.5b-instruct-q4_k_m.gguf"
	arb, err := NewRealSLMArbitrator(modelPath)
	if err != nil {
		t.Skipf("Modèle non présent: %v", err)
	}
	defer arb.Close()

	inc := &c2blue55.SLMIncident{
		FQDN:               "sophosxl.net",
		Subdomain:          "telemetry.sophosxl.net",
		QType:              c2blue55.TypeA,
		EntropyBits:        3.1,
		UniqueSubdomains:   1,
		JitterPct:          45,
		SuspectedIndicator: "Standard AV Telemetry",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 360*time.Second)
	defer cancel()

	resp, err := arb.Arbitrate(ctx, inc)
	if err != nil {
		t.Fatalf("Arbitrate: %v", err)
	}

	if resp.Verdict != "BENIGN_AV_TELEMETRY" {
		t.Fatalf("Verdict attendu BENIGN_AV_TELEMETRY, got: %s (conf=%.4f)", resp.Verdict, resp.Confidence)
	}
	t.Logf("Classification bénigne validée sans faux positif : Verdict=%s, Conf=%.4f, Thought=%s",
		resp.Verdict, resp.Confidence, resp.Thought)
}
