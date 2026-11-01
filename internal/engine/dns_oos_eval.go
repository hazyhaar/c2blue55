package engine

import (
	"errors"
	"math"
)

// ErrSameRunLeak signale un RunID identique ou une fuite inter-run (SH-S13-01).
var ErrSameRunLeak = errors.New("engine: RunID identique ou fuite inter-run entre Run-A et Run-B")

type EpisodeVectorSample struct {
	Family     string // "P1", "P2", "P3", "P4", "BENIGN"
	DomainApex string
	Features   [8]float32
}

type EpisodeRunCorpus struct {
	RunID   string
	Samples []EpisodeVectorSample
}

type FamilyOOSMetrics struct {
	Family         string
	Recall         float64
	FalsePositives int
	AUC            float64
	LODO_AUC       float64
	MaxSphereRad   float32
}

type OOSPatternProof struct {
	Families map[string]FamilyOOSMetrics
	AllPass  bool
}

type oosSphere struct {
	center [8]float32
	radius float64
	apex   string
}

var oosFamilies = []string{"P1", "P2", "P3", "P4"}

const sphereCapRatio = 0.85

// ProvePatternOutOfSample calibre des sphères sur runA et les évalue hors-échantillon sur runB.
func ProvePatternOutOfSample(runA, runB *EpisodeRunCorpus) (OOSPatternProof, error) {
	if runA == nil || runB == nil || runA.RunID == "" || runB.RunID == "" || runA.RunID == runB.RunID {
		return OOSPatternProof{}, ErrSameRunLeak
	}

	apexA := make(map[string]bool)
	var benignA, benignB [][8]float32
	for _, s := range runA.Samples {
		if s.DomainApex != "" {
			apexA[s.DomainApex] = true
		}
		if s.Family == "BENIGN" {
			benignA = append(benignA, s.Features)
		}
	}
	for _, s := range runB.Samples {
		if s.DomainApex != "" && apexA[s.DomainApex] {
			return OOSPatternProof{}, ErrSameRunLeak
		}
		if s.Family == "BENIGN" {
			benignB = append(benignB, s.Features)
		}
	}

	proof := OOSPatternProof{
		Families: make(map[string]FamilyOOSMetrics, len(oosFamilies)),
		AllPass:  len(benignA) > 0 && len(benignB) > 0,
	}
	for _, fam := range oosFamilies {
		spheres := calibrateSpheres(runA.Samples, fam, benignA)
		m, posCount := evalFamily(fam, spheres, runB.Samples, benignB)
		proof.Families[fam] = m
		if len(spheres) == 0 || posCount == 0 || len(benignB) == 0 ||
			!(m.Recall >= 0.90 && m.FalsePositives == 0 && m.AUC >= 0.90 && m.LODO_AUC >= 0.90) {
			proof.AllPass = false
		}
	}
	if len(proof.Families) != len(oosFamilies) {
		proof.AllPass = false
	}
	return proof, nil
}

func calibrateSpheres(samples []EpisodeVectorSample, fam string, benignA [][8]float32) []oosSphere {
	var spheres []oosSphere
	for _, c := range samples {
		if c.Family != fam {
			continue
		}
		dmin := 0.0
		for i, b := range benignA {
			if d := oosDist(c.Features, b); i == 0 || d < dmin {
				dmin = d
			}
		}
		spheres = append(spheres, oosSphere{center: c.Features, radius: sphereCapRatio * dmin, apex: c.DomainApex})
	}
	return spheres
}

func evalFamily(fam string, spheres []oosSphere, samplesB []EpisodeVectorSample, benignB [][8]float32) (FamilyOOSMetrics, int) {
	m := FamilyOOSMetrics{Family: fam}
	for _, s := range spheres {
		if r := float32(s.radius); r > m.MaxSphereRad {
			m.MaxSphereRad = r
		}
	}

	var posB []EpisodeVectorSample
	for _, s := range samplesB {
		if s.Family == fam {
			posB = append(posB, s)
		}
	}

	hits := 0
	posScores := make([]float64, len(posB))
	for i, p := range posB {
		posScores[i] = oosScore(p.Features, spheres)
		if posScores[i] > 0 {
			hits++
		}
	}
	negScores := make([]float64, len(benignB))
	for i, b := range benignB {
		negScores[i] = oosScore(b, spheres)
		if negScores[i] > 0 {
			m.FalsePositives++
		}
	}
	if len(posB) > 0 {
		m.Recall = float64(hits) / float64(len(posB))
	}
	m.AUC = mannWhitney(posScores, negScores)

	apexes := make(map[string]bool)
	for _, p := range posB {
		apexes[p.DomainApex] = true
	}
	var sum float64
	for apex := range apexes {
		var kept []oosSphere
		for _, s := range spheres {
			if s.apex != apex {
				kept = append(kept, s)
			}
		}
		var heldPos, heldNeg []float64
		for _, p := range posB {
			if p.DomainApex == apex {
				heldPos = append(heldPos, oosScore(p.Features, kept))
			}
		}
		for _, b := range benignB {
			heldNeg = append(heldNeg, oosScore(b, kept))
		}
		sum += mannWhitney(heldPos, heldNeg)
	}
	if len(apexes) > 0 {
		m.LODO_AUC = sum / float64(len(apexes))
	}
	return m, len(posB)
}

func oosScore(x [8]float32, spheres []oosSphere) float64 {
	best := math.Inf(-1)
	for _, s := range spheres {
		if v := s.radius - oosDist(x, s.center); v > best {
			best = v
		}
	}
	return best
}

func mannWhitney(pos, neg []float64) float64 {
	if len(pos) == 0 || len(neg) == 0 {
		return 0
	}
	var wins float64
	for _, p := range pos {
		for _, n := range neg {
			switch {
			case p > n:
				wins++
			case p == n:
				wins += 0.5
			}
		}
	}
	return wins / float64(len(pos)*len(neg))
}

func oosDist(a, b [8]float32) float64 {
	var sum float64
	for i := range a {
		d := float64(a[i]) - float64(b[i])
		sum += d * d
	}
	return math.Sqrt(sum)
}
