package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55"
)

func newEncoderArbiter(t *testing.T) *PureGoEncoderArbitrator {
	t.Helper()
	pipe, err := c2blue55.NewPipeline(c2blue55.PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	arb, err := NewPureGoEncoderArbitrator(pipe)
	if err != nil {
		t.Fatalf("NewPureGoEncoderArbitrator: %v", err)
	}
	return arb
}

func tunnelIncident() *c2blue55.SLMIncident {
	return &c2blue55.SLMIncident{
		FQDN:               "c2.01636c69656e742d696e666f.tunnel.dnscat2.org",
		ParentDomain:       "dnscat2.org",
		Subdomain:          "c2.01636c69656e742d696e666f.tunnel",
		QType:              c2blue55.TypeTXT,
		EntropyQ8:          1150,
		EntropyBits:        4.5,
		PayloadClass:       c2blue55.PayloadClassHex,
		JitterPct:          12,
		UniqueSubdomains:   8,
		QueryCount:         15,
		SuspectedIndicator: "HEX_BASE64_PAYLOAD_DENSE",
	}
}

func avTelemetryIncident() *c2blue55.SLMIncident {
	return &c2blue55.SLMIncident{
		FQDN:               "telemetry.sophosxl.net",
		ParentDomain:       "sophosxl.net",
		Subdomain:          "telemetry",
		QType:              c2blue55.TypeA,
		EntropyBits:        3.1,
		JitterPct:          45,
		UniqueSubdomains:   1,
		QueryCount:         5,
		SuspectedIndicator: "STANDARD_AV_TELEMETRY",
	}
}

func dkimIncident() *c2blue55.SLMIncident {
	return &c2blue55.SLMIncident{
		FQDN:               "k1._domainkey.company.org",
		ParentDomain:       "company.org",
		Subdomain:          "k1",
		QType:              c2blue55.TypeTXT,
		EntropyBits:        2.5,
		JitterPct:          40,
		UniqueSubdomains:   1,
		QueryCount:         5,
		SuspectedIndicator: "DKIM_SELECTOR",
	}
}

func weakIncident() *c2blue55.SLMIncident {
	return &c2blue55.SLMIncident{
		FQDN:               "a.weak-signal.invalid",
		ParentDomain:       "weak-signal.invalid",
		Subdomain:          "a",
		QType:              c2blue55.TypeA,
		EntropyBits:        2.0,
		JitterPct:          100,
		UniqueSubdomains:   0,
		QueryCount:         1,
		SuspectedIndicator: "HIGH_ENTROPY",
	}
}

// hostileDkimIncident cumule le marqueur bénin DKIM et des métriques physiques
// hostiles : c'est le cas de figure qu'aucune hallucination ne doit blanchir.
func hostileDkimIncident() *c2blue55.SLMIncident {
	return &c2blue55.SLMIncident{
		FQDN:               "k1._domainkey.exfil-evil.tunnel",
		ParentDomain:       "exfil-evil.tunnel",
		Subdomain:          "k1._domainkey.exfil-evil",
		QType:              c2blue55.TypeTXT,
		EntropyQ8:          1228,
		EntropyBits:        4.8,
		PayloadClass:       c2blue55.PayloadClassHex,
		JitterPct:          5,
		UniqueSubdomains:   15,
		QueryCount:         20,
		SuspectedIndicator: "HEX_BASE64_PAYLOAD_DENSE",
	}
}

func validEncoderVerdict(v string) bool {
	switch v {
	case "BENIGN_AV_TELEMETRY", "BENIGN_DKIM_KEY", "BENIGN_CRYPTO_KEY", "DNS_TUNNEL_CONFIRMED", "INSUFFICIENT_EVIDENCE":
		return true
	}
	return false
}

// TestPureGoEncoderArbitrator_Verdicts vérifie la classification des quatre
// verdicts officiels et l'enrichissement de la fiche médico-légale HITL.
func TestPureGoEncoderArbitrator_Verdicts(t *testing.T) {
	arb := newEncoderArbiter(t)
	defer arb.Close()
	ctx := context.Background()

	cases := []struct {
		name    string
		inc     *c2blue55.SLMIncident
		verdict string
		action  string
	}{
		{"tunnel", tunnelIncident(), "DNS_TUNNEL_CONFIRMED", "BLOCK_IMMEDIATE"},
		{"av", avTelemetryIncident(), "BENIGN_AV_TELEMETRY", "ALLOW_VENDOR"},
		{"dkim", dkimIncident(), "BENIGN_DKIM_KEY", "MONITOR_ONLY"},
		{"weak", weakIncident(), "INSUFFICIENT_EVIDENCE", "MONITOR_ONLY"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := arb.Arbitrate(ctx, tc.inc)
			if err != nil {
				t.Fatalf("Arbitrate: %v", err)
			}
			if resp.Verdict != tc.verdict {
				t.Fatalf("verdict = %q, attendu %q", resp.Verdict, tc.verdict)
			}
			if resp.Confidence < 0 || resp.Confidence > 1 {
				t.Fatalf("confiance hors [0,1]: %f", resp.Confidence)
			}
			if resp.Thought == "" {
				t.Fatal("pensée d'analyse vide")
			}
			if resp.HumanSummary == "" {
				t.Fatal("résumé humain vide")
			}
			if resp.RecommendedAction != tc.action {
				t.Errorf("action = %q, attendu %q", resp.RecommendedAction, tc.action)
			}
			// Le dossier de l'appelant ne doit pas être muté par l'arbitre.
			if tc.inc.HumanSummary != "" || tc.inc.RecommendedAction != "" {
				t.Errorf("le dossier appelant a été muté: %q / %q", tc.inc.HumanSummary, tc.inc.RecommendedAction)
			}
		})
	}
}

// TestPureGoEncoderArbitrator_HostileNotWhitelisted constitue la preuve de
// non-régression du veto : un marqueur DKIM bénin porté par des métriques
// hostiles ne peut produire un verdict de blanchiment.
func TestPureGoEncoderArbitrator_HostileNotWhitelisted(t *testing.T) {
	arb := newEncoderArbiter(t)
	defer arb.Close()

	resp, err := arb.Arbitrate(context.Background(), hostileDkimIncident())
	if err != nil {
		t.Fatalf("Arbitrate: %v", err)
	}
	if isBenignVerdict(resp.Verdict) {
		t.Fatalf("métriques hostiles blanchies à tort: %q", resp.Verdict)
	}
	if resp.Verdict != "DNS_TUNNEL_CONFIRMED" {
		t.Fatalf("verdict = %q, attendu DNS_TUNNEL_CONFIRMED", resp.Verdict)
	}
	if resp.RecommendedAction != "BLOCK_IMMEDIATE" {
		t.Errorf("action = %q, attendu BLOCK_IMMEDIATE", resp.RecommendedAction)
	}
}

// TestPureGoEncoderArbitrator_Guards couvre l'annulation de contexte, le dossier
// nul, le pipeline nul et le rejet post-fermeture.
func TestPureGoEncoderArbitrator_Guards(t *testing.T) {
	arb := newEncoderArbiter(t)
	defer arb.Close()

	preCancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := arb.Arbitrate(preCancelled, tunnelIncident()); !errors.Is(err, context.Canceled) {
		t.Fatalf("contexte pré-annulé: %v", err)
	}
	if _, err := arb.Arbitrate(context.Background(), nil); err == nil {
		t.Fatal("un dossier nul doit être refusé")
	}
	if _, err := NewPureGoEncoderArbitrator(nil); err == nil {
		t.Fatal("un pipeline nul doit être refusé (veto obligatoire)")
	}
	if err := arb.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := arb.Arbitrate(context.Background(), tunnelIncident()); err == nil {
		t.Fatal("l'arbitrage post-fermeture doit être refusé")
	}
}

// TestPureGoEncoderArbitrator_Concurrent éprouve la résistance à la concurrence
// sous détection de courses : plusieurs goroutines partagent le même arbitre et
// les mêmes dossiers.
func TestPureGoEncoderArbitrator_Concurrent(t *testing.T) {
	arb := newEncoderArbiter(t)
	defer arb.Close()

	incidents := []*c2blue55.SLMIncident{
		tunnelIncident(),
		avTelemetryIncident(),
		dkimIncident(),
		weakIncident(),
		hostileDkimIncident(),
	}

	const goroutines = 16
	const perGoroutine = 200

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	for g := range goroutines {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			ctx := context.Background()
			for i := range perGoroutine {
				inc := incidents[(seed+i)%len(incidents)]
				resp, err := arb.Arbitrate(ctx, inc)
				if err != nil {
					errCh <- fmt.Errorf("g%d i%d: %w", seed, i, err)
					return
				}
				if !validEncoderVerdict(resp.Verdict) {
					errCh <- fmt.Errorf("g%d i%d: verdict invalide %q", seed, i, resp.Verdict)
					return
				}
				if resp.Confidence < 0 || resp.Confidence > 1 {
					errCh <- fmt.Errorf("g%d i%d: confiance %f", seed, i, resp.Confidence)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// TestPureGoEncoderArbitrator_HotPathZeroAlloc atteste que le chemin chaud
// d'encodage et de décision n'alloue rien sur le tas.
func TestPureGoEncoderArbitrator_HotPathZeroAlloc(t *testing.T) {
	arb := newEncoderArbiter(t)
	defer arb.Close()
	inc := tunnelIncident()

	allocs := testing.AllocsPerRun(200, func() {
		arb.infer(inc)
	})
	if allocs != 0 {
		t.Fatalf("infer a alloué %v objets sur le tas, attendu 0", allocs)
	}
}

// TestPureGoEncoderArbitrator_LatencySinglePass atteste la borne de 10 ms.
func TestPureGoEncoderArbitrator_LatencySinglePass(t *testing.T) {
	arb := newEncoderArbiter(t)
	defer arb.Close()
	ctx := context.Background()
	inc := tunnelIncident()

	for range 100 {
		if _, err := arb.Arbitrate(ctx, inc); err != nil {
			t.Fatalf("échauffement: %v", err)
		}
	}

	const iters = 1000
	start := time.Now()
	for range iters {
		if _, err := arb.Arbitrate(ctx, inc); err != nil {
			t.Fatalf("Arbitrate: %v", err)
		}
	}
	perCall := time.Since(start) / iters
	if perCall > encoderMaxLatencyNanos {
		t.Fatalf("latence unitaire %v > borne %v", perCall, time.Duration(encoderMaxLatencyNanos))
	}
	t.Logf("latence unitaire moyenne = %v sur %d passes", perCall, iters)
}
