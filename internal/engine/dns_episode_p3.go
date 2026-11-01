package engine

import "math"

// EpisodeP3Features résume les descripteurs temporels et de rotation QTYPE (famille P3).
type EpisodeP3Features struct {
	CollapsedCount   int
	DualStackPairs   int
	InterArrivalCV   float32
	MarkovEntropy    float32
	BurstIdleRatio   float32
	CompositeP3Score float32
}

func qtypeBucket(qt uint16) int {
	switch qt {
	case 1:
		return 0
	case 28:
		return 1
	case 16:
		return 2
	case 10:
		return 3
	case 5:
		return 4
	default:
		return 5
	}
}

func isDualStackPair(a, b uint16) bool {
	return (a == 1 && b == 28) || (a == 28 && b == 1)
}

// ComputeEpisodeP3TimingFeatures calcule les features P3 après fusion des paires dual-stack A+AAAA (SH-S10b-01).
func ComputeEpisodeP3TimingFeatures(intervalsNs []int64, qtypes []uint16, dualStackWindowNs int64) EpisodeP3Features {
	var f EpisodeP3Features
	n := len(qtypes)
	if n == 0 {
		return f
	}

	var trans [6][6]uint16
	var totalTrans int
	prevBucket := -1

	var ivCount int
	var mean, m2 float64
	var burstCount, idleCount int

	for i := 0; i < n; {
		curBucket := qtypeBucket(qtypes[i])
		step := 1
		if i+1 < n && i < len(intervalsNs) && isDualStackPair(qtypes[i], qtypes[i+1]) &&
			intervalsNs[i] >= 0 && intervalsNs[i] <= dualStackWindowNs {
			f.DualStackPairs++
			curBucket = 0 // événement dual-stack fusionné
			step = 2
		}
		f.CollapsedCount++
		if prevBucket >= 0 {
			trans[prevBucket][curBucket]++
			totalTrans++
		}
		prevBucket = curBucket

		// Intervalle menant au prochain événement (après la paire fusionnée éventuelle)
		ivIdx := i + step - 1
		if ivIdx < len(intervalsNs) && i+step < n {
			dt := float64(intervalsNs[ivIdx])
			if dt < 0 {
				dt = 0
			}
			ivCount++
			delta := dt - mean
			mean += delta / float64(ivCount)
			m2 += delta * (dt - mean)
			if intervalsNs[ivIdx] <= 100_000_000 {
				burstCount++
			} else {
				idleCount++
			}
		}
		i += step
	}

	if ivCount > 1 && mean > 0 {
		variance := m2 / float64(ivCount)
		f.InterArrivalCV = float32(math.Sqrt(variance) / mean)
	} else {
		f.InterArrivalCV = 1.0
	}

	if totalTrans > 0 {
		var h float64
		invN := 1.0 / float64(totalTrans)
		for r := range 6 {
			for c := range 6 {
				cnt := trans[r][c]
				if cnt == 0 {
					continue
				}
				p := float64(cnt) * invN
				h -= p * math.Log2(p)
			}
		}
		norm := h / math.Log2(6.0)
		if norm > 1.0 {
			norm = 1.0
		}
		f.MarkovEntropy = float32(norm)
	}

	f.BurstIdleRatio = float32(burstCount) / float32(max(idleCount, 1))

	isPeriodic := ivCount >= 4 && f.InterArrivalCV < 0.12
	isRotating := f.MarkovEntropy > 0.40
	if !isPeriodic && !isRotating {
		f.CompositeP3Score = -0.50
		return f
	}
	var regScore float32
	if f.InterArrivalCV < 0.50 {
		regScore = (0.50 - f.InterArrivalCV) * 2.0
	}
	f.CompositeP3Score = 0.50*regScore + 0.50*f.MarkovEntropy
	return f
}
