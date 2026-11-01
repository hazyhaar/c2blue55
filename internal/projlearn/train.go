package projlearn

import (
	"fmt"

	"github.com/hazyhaar/c2pkg/c2projlearn"
)

// LossWeights pondère les trois pertes.
type LossWeights struct {
	Separation    float32
	Triplet       float32
	BitBalance    float32
	Margin        float32
	TripletMargin float32
}

// TrainStats rapporte les comptes bruts d'une époque.
type TrainStats struct {
	Examples       int
	Batches        int
	SeparationLoss float64
	TripletLoss    float64
	BitBalanceLoss float64
	Steps          int
}

// TrainEpoch exécute une époque déterministe (lots de 64, mélange par rng).
func TrainEpoch(p, grads, m, v *Params, cfg Config, ws *Workspace, batch []Example, triplets [][3]int, w LossWeights, adam c2projlearn.AdamWConfig, step int, rng *PCG64) (TrainStats, error) {
	var stats TrainStats
	if rng == nil || step < 1 || p == nil || grads == nil || m == nil || v == nil || ws == nil {
		return stats, ErrConfigContract
	}
	stats.Examples = len(batch)
	for i := range batch {
		if err := CheckExample(cfg, ws, &batch[i]); err != nil {
			return stats, fmt.Errorf("exemple %d: %w", i, err)
		}
	}
	for i, tri := range triplets {
		if tri[0] < 0 || tri[1] < 0 || tri[2] < 0 || tri[0] >= len(batch) || tri[1] >= len(batch) || tri[2] >= len(batch) {
			return stats, fmt.Errorf("triplet %d: %w", i, ErrConfigContract)
		}
	}
	order := make([]int, len(batch))
	for i := range order {
		order[i] = i
	}
	for i := len(order) - 1; i > 0; i-- {
		j := int(rng.Uint64() % uint64(i+1))
		order[i], order[j] = order[j], order[i]
	}
	hidden := make([]float32, 64*cfg.CodeBits)
	directions := make([]float32, len(hidden))
	balanced := make([]float32, len(hidden))
	scores, labels, scoreGrad := make([]float32, 64), make([]float32, 64), make([]float32, 64)
	var triA, triP, triN []float32
	triA, triP, triN = make([]float32, cfg.CodeBits), make([]float32, cfg.CodeBits), make([]float32, cfg.CodeBits)
	triHidden := make([]float32, 3*cfg.CodeBits)
	triDirection := make([]float32, cfg.CodeBits)
	positions := make([]int, len(batch))
	var triTotal float64
	triNUsed := 0
	for start := 0; start < len(batch); start += 64 {
		end := min(start+64, len(batch))
		size := end - start
		clear(directions[:size*cfg.CodeBits])
		for i := range positions {
			positions[i] = -1
		}
		for i := range size {
			index := order[start+i]
			positions[index] = i
			_, row, score := Forward(p, cfg, &batch[index], ws)
			copy(hidden[i*cfg.CodeBits:(i+1)*cfg.CodeBits], row)
			scores[i], labels[i] = score, batch[index].Label
		}
		sep, err := c2projlearn.LossSeparationHinge(scores[:size], labels[:size], w.Margin, scoreGrad[:size])
		if err != nil {
			return stats, fmt.Errorf("separation: %w", err)
		}
		stats.SeparationLoss += float64(sep)
		bal, err := c2projlearn.LossBitBalance(hidden[:size*cfg.CodeBits], size, cfg.CodeBits, balanced[:size*cfg.CodeBits])
		if err != nil {
			return stats, fmt.Errorf("equilibre: %w", err)
		}
		stats.BitBalanceLoss += float64(bal)
		for i := 0; i < size*cfg.CodeBits; i++ {
			directions[i] += w.BitBalance * balanced[i]
		}
		for _, slot := range paramSlots(grads) {
			clear(slot)
		}
		for i := range size {
			index := order[start+i]
			Forward(p, cfg, &batch[index], ws)
			Backward(p, cfg, &batch[index], ws, directions[i*cfg.CodeBits:(i+1)*cfg.CodeBits], w.Separation*scoreGrad[i], grads)
		}
		for _, tri := range triplets {
			if positions[tri[0]] < 0 {
				continue
			}
			for member, index := range tri {
				_, row, _ := Forward(p, cfg, &batch[index], ws)
				copy(triHidden[member*cfg.CodeBits:(member+1)*cfg.CodeBits], row)
			}
			loss, err := c2projlearn.LossTriplet(triHidden[:cfg.CodeBits], triHidden[cfg.CodeBits:2*cfg.CodeBits], triHidden[2*cfg.CodeBits:], w.TripletMargin, triA, triP, triN)
			if err != nil {
				return stats, fmt.Errorf("triplet: %w", err)
			}
			triTotal += float64(loss)
			triNUsed++
			for member, index := range tri {
				var direction []float32
				switch member {
				case 0:
					direction = triA
				case 1:
					direction = triP
				default:
					direction = triN
				}
				for d := range triDirection {
					triDirection[d] = w.Triplet * direction[d]
				}
				Forward(p, cfg, &batch[index], ws)
				Backward(p, cfg, &batch[index], ws, triDirection, 0, grads)
			}
		}
		ps, gs, ms, vs := paramSlots(p), paramSlots(grads), paramSlots(m), paramSlots(v)
		for i := range ps {
			if err := c2projlearn.AdamWStep(ps[i], ms[i], vs[i], gs[i], adam, step+stats.Steps); err != nil {
				return stats, fmt.Errorf("adamw: %w", err)
			}
		}
		stats.Batches++
		stats.Steps++
	}
	if stats.Batches > 0 {
		stats.SeparationLoss /= float64(stats.Batches)
		stats.BitBalanceLoss /= float64(stats.Batches)
	}
	if triNUsed > 0 {
		stats.TripletLoss = triTotal / float64(triNUsed)
	}
	return stats, nil
}

func paramSlots(p *Params) [9][]float32 {
	return [9][]float32{p.Embed, p.ConvW, p.ConvB, p.Dense1W, p.Dense1B, p.Dense2W, p.Dense2B, p.ReadoutW, p.ReadoutB}
}
