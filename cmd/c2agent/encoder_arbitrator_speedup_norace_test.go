//go:build !race

package main

import (
	"context"
	"os"
	"testing"
	"time"
)

// TestPureGoEncoderArbitrator_SpeedupVsRealSLM prouve l'accélération d'au moins
// 10x par rapport à l'ancien arbitre autorégressif. Le test est ignoré si les
// poids ne sont pas présents sur disque ou en mode court.
func TestPureGoEncoderArbitrator_SpeedupVsRealSLM(t *testing.T) {
	if testing.Short() {
		t.Skip("preuve d'accélération ignorée en mode court")
	}
	modelPath := resolveDefaultModelPath()
	if _, err := os.Stat(modelPath); err != nil {
		t.Skipf("modèle autorégressif absent (%s): %v", modelPath, err)
	}
	old, err := NewRealSLMArbitrator(modelPath)
	if err != nil {
		t.Skipf("RealSLMArbitrator indisponible: %v", err)
	}
	defer old.Close()

	fast := newEncoderArbiter(t)
	defer fast.Close()
	inc := tunnelIncident()

	ctx, cancel := context.WithTimeout(context.Background(), 360*time.Second)
	defer cancel()

	if _, err := old.Arbitrate(ctx, inc); err != nil {
		t.Skipf("échauffement RealSLM: %v", err)
	}
	for range 100 {
		if _, err := fast.Arbitrate(ctx, inc); err != nil {
			t.Fatalf("échauffement encodeur: %v", err)
		}
	}

	bestOld := time.Duration(1) << 62
	for range 2 {
		start := time.Now()
		if _, err := old.Arbitrate(ctx, inc); err != nil {
			t.Fatalf("RealSLMArbitrator: %v", err)
		}
		if d := time.Since(start); d < bestOld {
			bestOld = d
		}
	}

	bestFast := time.Duration(1) << 62
	for range 200 {
		start := time.Now()
		if _, err := fast.Arbitrate(ctx, inc); err != nil {
			t.Fatalf("PureGoEncoderArbitrator: %v", err)
		}
		if d := time.Since(start); d < bestFast {
			bestFast = d
		}
	}

	ratioVitesse := float64(bestOld) / float64(bestFast)
	t.Logf("latence autorégressive = %v, latence encodeur = %v, ratio = %.1fx", bestOld, bestFast, ratioVitesse)
	if ratioVitesse < 10 {
		t.Fatalf("accélération insuffisante: %.1fx < 10x", ratioVitesse)
	}
}
