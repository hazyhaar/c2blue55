// Package engine — drift_guard.go
// Verrou anti-empoisonnement à mémoire bornée et détecteur CUSUM directionnel.
// Empêche l'attaque de la « grenouille ébouillantée » lors de l'auto-apprentissage
// en plafonnant la dérive cumulée des centroïdes et en traquant les dérives asymétriques.
package engine

import (
	"fmt"
	"math"
	"sync"
)

// DriftGuardConfig calibre les seuils de dérive tolérés.
type DriftGuardConfig struct {
	MaxDriftBudget float64 // Plafond cumulé global B (somme des déplacements)
	CusumThreshold float64 // Seuil d'alarme CUSUM (h)
	CusumSlack     float64 // Paramètre d'adoucissement CUSUM (k)
	MaxRadius      float64 // Rayon de dispersion maximal autorisé (r_max)
}

// DefaultDriftGuardConfig rend une configuration standard calibree.
func DefaultDriftGuardConfig() DriftGuardConfig {
	return DriftGuardConfig{
		MaxDriftBudget: 50.0,
		CusumThreshold: 5.0,
		CusumSlack:     0.1,
		MaxRadius:      15.0,
	}
}

// CusumDriftGuard surveille l'évolution des centroïdes dans le temps.
type CusumDriftGuard struct {
	mu           sync.Mutex
	cfg          DriftGuardConfig
	lastCentroid [EmbeddingDim]float32
	hasBaseline  bool
	cumulDrift   float64
	cusumPos     float64
	alertCount   uint64
}

// NewCusumDriftGuard initialise le garde de dérive.
func NewCusumDriftGuard(cfg DriftGuardConfig) *CusumDriftGuard {
	if cfg.MaxDriftBudget <= 0 {
		cfg.MaxDriftBudget = 50.0
	}
	if cfg.CusumThreshold <= 0 {
		cfg.CusumThreshold = 5.0
	}
	return &CusumDriftGuard{cfg: cfg}
}

// CheckUpdate soumet un nouveau centroïde calculé lors de l'adaptation en ligne.
// Retourne vrai si l'adaptation est acceptée, ou faux si elle est rejetée pour cause
// de tentative d'empoisonnement graduel (CUSUM ou épuisement du budget de dérive).
func (g *CusumDriftGuard) CheckUpdate(newCentroid []float32) (accepted bool, reason string) {
	if len(newCentroid) < EmbeddingDim {
		return false, "vecteur de centroïde de dimension insuffisante"
	}

	g.mu.Lock()
	defer g.mu.Unlock()

	if !g.hasBaseline {
		for i := 0; i < EmbeddingDim; i++ {
			g.lastCentroid[i] = newCentroid[i]
		}
		g.hasBaseline = true
		return true, "baseline initiale établie"
	}

	// 1. Calcul du déplacement euclidien instantané ||mu_t - mu_{t-1}||
	var distSq float64
	for i := 0; i < EmbeddingDim; i++ {
		diff := float64(newCentroid[i] - g.lastCentroid[i])
		distSq += diff * diff
	}
	stepDist := math.Sqrt(distSq)

	// 2. Contrôle du rayon maximal unitaire
	if stepDist > g.cfg.MaxRadius {
		g.alertCount++
		return false, fmt.Sprintf("déplacement instantané excessif (%.2f > %.2f)", stepDist, g.cfg.MaxRadius)
	}

	// 3. Contrôle du budget de dérive cumulée \sum ||mu_t - mu_{t-1}|| <= B
	if g.cumulDrift+stepDist > g.cfg.MaxDriftBudget {
		g.alertCount++
		return false, fmt.Sprintf("budget de dérive cumulée épuisé (%.2f + %.2f > %.2f)", g.cumulDrift, stepDist, g.cfg.MaxDriftBudget)
	}

	// 4. Détecteur CUSUM directionnel
	// S_t^+ = max(0, S_{t-1}^+ + (X_t - mu_0 - k))
	delta := stepDist - g.cfg.CusumSlack
	newCusumPos := g.cusumPos + delta
	if newCusumPos < 0 {
		newCusumPos = 0
	}

	if newCusumPos > g.cfg.CusumThreshold {
		g.alertCount++
		return false, fmt.Sprintf("alarme CUSUM : étirement orienté hostile détecté (CUSUM+=%.2f > %.2f)", newCusumPos, g.cfg.CusumThreshold)
	}

	// Mise à jour de l'état nominal
	g.cumulDrift += stepDist
	g.cusumPos = newCusumPos
	for i := 0; i < EmbeddingDim; i++ {
		g.lastCentroid[i] = newCentroid[i]
	}

	return true, "adaptation validée par le verrou anti-dérive"
}

// Stats retourne l'état courant de dérive cumulée et le compteur d'alarmes.
func (g *CusumDriftGuard) Stats() (cumulDrift float64, cusumPos float64, alerts uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cumulDrift, g.cusumPos, g.alertCount
}
