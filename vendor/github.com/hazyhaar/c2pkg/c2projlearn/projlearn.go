// SPDX-License-Identifier: Apache-2.0 OR MIT
// Fichier écrit main, non transpilé : façade Go au-dessus des noyaux émis par
// sgoiter (*_gen.go, sources de vérité sources/*.c). Aucun calcul numérique
// n'est écrit ici : la façade vérifie les dimensions, calcule les scalaires
// que le sous-ensemble C ne sait pas produire (inverses 1/n, corrections de
// biais AdamW) et appelle le noyau.
//
// CLAUDE:SUMMARY c2projlearn — noyaux float32 du projecteur DNS appris
// (c2blue55, strates K-0 à K-3) : convolution 1D sur octets, mise en commun par
// maximum sur segments, couche dense, tangente hyperbolique, binarisation en
// code de Hamming, pertes sans logarithme et pas AdamW. Scalaire émis, parité
// bit-exacte gcc -O2 -ffp-contract=off, ordre de sommation fixe.
//
// CLAUDE:WARN Aucune fusion multiplication-addition (FMA) n'est tolérée, aucune
// division flottante dans les sources C (inverse par Newton), aucun appel libm.
package c2projlearn

import (
	"errors"
	"math"
)

// ErrShape signale des longueurs de tranches incompatibles avec les dimensions
// annoncées ; aucun noyau n'est appelé dans ce cas.
var ErrShape = errors.New("c2projlearn: dimensions incompatibles")

// AdamWConfig porte les hyperparamètres du pas AdamW découplé.
type AdamWConfig struct {
	LearningRate float32
	Beta1        float32
	Beta2        float32
	Epsilon      float32
	WeightDecay  float32
}

// Conv1DForward calcule y[t*cout+o] = b[o] + Σ_j Σ_c w[(o*k+j)*cin+c] * x[(t+j-k/2)*cin+c]
// avec rembourrage par zéros (« same »). Longueurs exigées : x = tlen*cin, w = cout*k*cin,
// b = cout, y = tlen*cout ; k impair et >= 1.
func Conv1DForward(x []float32, tlen, cin int, w, b []float32, cout, k int, y []float32) error {
	if tlen < 0 || cin <= 0 || cout <= 0 || k < 1 || k%2 == 0 ||
		len(x) != tlen*cin || len(w) != cout*k*cin || len(b) != cout || len(y) != tlen*cout {
		return ErrShape
	}
	if tlen == 0 {
		return nil
	}
	c2pl_conv1d_fwd(x, tlen, cin, w, b, cout, k, y)
	return nil
}

// Conv1DBackward remet dx, dw, db à zéro puis les accumule à partir de dy
// (longueur tlen*cout) : dx = tlen*cin, dw = cout*k*cin, db = cout.
func Conv1DBackward(x []float32, tlen, cin int, w []float32, cout, k int, dy, dx, dw, db []float32) error {
	if tlen < 0 || cin <= 0 || cout <= 0 || k < 1 || k%2 == 0 ||
		len(x) != tlen*cin || len(w) != cout*k*cin || len(dy) != tlen*cout ||
		len(dx) != tlen*cin || len(dw) != cout*k*cin || len(db) != cout {
		return ErrShape
	}
	if tlen == 0 {
		clear(dw)
		clear(db)
		return nil
	}
	c2pl_conv1d_bwd(x, tlen, cin, w, cout, k, dy, dx, dw, db)
	return nil
}

// MaxPoolForward calcule p[s*cout+o] = max_{t in [segStart[s], segEnd[s])} y[t*cout+o] et
// argmax (premier t atteignant le maximum, -1 pour un segment vide, p = 0 alors).
// Exigences : 0 <= segStart[s] <= segEnd[s] <= tlen ; p et argmax de longueur nseg*cout.
func MaxPoolForward(y []float32, tlen, cout int, segStart, segEnd []int, p []float32, argmax []int) error {
	nseg := len(segStart)
	if tlen < 0 || cout <= 0 || len(segEnd) != nseg || len(y) != tlen*cout ||
		len(p) != nseg*cout || len(argmax) != nseg*cout {
		return ErrShape
	}
	for s := range nseg {
		if segStart[s] < 0 || segStart[s] > segEnd[s] || segEnd[s] > tlen {
			return ErrShape
		}
	}
	if nseg == 0 {
		return nil
	}
	c2pl_maxpool_fwd(y, tlen, cout, segStart, segEnd, nseg, p, argmax)
	return nil
}

// MaxPoolBackward remet dy (tlen*cout) à zéro puis dy[argmax[s*cout+o]*cout+o] += dp[s*cout+o]
// (argmax -1 ignoré). Exigence : argmax[i] dans [-1, tlen).
func MaxPoolBackward(argmax []int, nseg, cout int, dp []float32, tlen int, dy []float32) error {
	if nseg < 0 || cout <= 0 || tlen < 0 || len(argmax) != nseg*cout || len(dp) != nseg*cout || len(dy) != tlen*cout {
		return ErrShape
	}
	for _, a := range argmax {
		if a < -1 || a >= tlen {
			return ErrShape
		}
	}
	if nseg == 0 {
		clear(dy)
		return nil
	}
	c2pl_maxpool_bwd(argmax, nseg, cout, dp, tlen, dy)
	return nil
}

// DenseForward calcule y[o] = b[o] + Σ_i w[o*n+i]*x[i] avec n = len(x), m = len(y) ;
// len(w) = m*n, len(b) = m.
func DenseForward(x, w, b, y []float32) error {
	n, m := len(x), len(y)
	if n == 0 || m == 0 || len(w) != m*n || len(b) != m {
		return ErrShape
	}
	c2pl_dense_fwd(x, n, w, b, m, y)
	return nil
}

// DenseBackward remet dx (n), dw (m*n), db (m) à zéro puis les accumule à partir de dy (m).
func DenseBackward(x, w, dy, dx, dw, db []float32) error {
	n, m := len(x), len(dy)
	if n == 0 || m == 0 || len(w) != m*n || len(dx) != n || len(dw) != m*n || len(db) != m {
		return ErrShape
	}
	c2pl_dense_bwd(x, n, w, m, dy, dx, dw, db)
	return nil
}

// TanhForward calcule y[i] = tanh(x[i]) ; len(y) = len(x) > 0.
func TanhForward(x, y []float32) error {
	if len(x) == 0 || len(y) != len(x) {
		return ErrShape
	}
	c2pl_tanh_fwd(x, len(x), y)
	return nil
}

// TanhBackward calcule dx[i] = dy[i]*(1-y[i]*y[i]).
func TanhBackward(y, dy, dx []float32) error {
	if len(y) == 0 || len(dy) != len(y) || len(dx) != len(y) {
		return ErrShape
	}
	c2pl_tanh_bwd(y, len(y), dy, dx)
	return nil
}

// SignBits met le bit b du mot w à 1 si h[w*64+b] >= 0 ; len(h) = 64*len(words) > 0.
func SignBits(h []float32, words []uint64) error {
	if len(words) == 0 || len(h) != 64*len(words) {
		return ErrShape
	}
	c2pl_sign_bits(h, len(h), words)
	return nil
}

// LossSeparationHinge rend (1/n) Σ max(0, margin - label[i]*s[i])^2 et son gradient en s.
func LossSeparationHinge(s, label []float32, margin float32, grad []float32) (float32, error) {
	n := len(s)
	if n == 0 || len(label) != n || len(grad) != n {
		return 0, ErrShape
	}
	return c2pl_loss_sephinge(s, label, n, margin, 1/float32(n), grad), nil
}

// LossTriplet rend max(0, |ha-hp|^2 - |ha-hn|^2 + margin) et ses gradients (nuls si inactif).
func LossTriplet(ha, hp, hn []float32, margin float32, dha, dhp, dhn []float32) (float32, error) {
	d := len(ha)
	if d == 0 || len(hp) != d || len(hn) != d || len(dha) != d || len(dhp) != d || len(dhn) != d {
		return 0, ErrShape
	}
	return c2pl_loss_triplet(ha, hp, hn, d, margin, dha, dhp, dhn), nil
}

// LossBitBalance rend Σ_d mu_d^2 avec mu_d la moyenne de h[b*dim+d] sur le lot, et dh.
func LossBitBalance(h []float32, batch, dim int, dh []float32) (float32, error) {
	if batch <= 0 || dim <= 0 || len(h) != batch*dim || len(dh) != batch*dim {
		return 0, ErrShape
	}
	return c2pl_loss_bitbalance(h, batch, dim, 1/float32(batch), dh), nil
}

// AdamWStep applique un pas AdamW découplé en place sur w, avec moments m et v
// et gradient g (toutes de même longueur > 0) ; step >= 1 numérote le pas pour
// les corrections de biais, calculées ici en float64 puis arrondies.
func AdamWStep(w, m, v, g []float32, cfg AdamWConfig, step int) error {
	n := len(w)
	if n == 0 || len(m) != n || len(v) != n || len(g) != n || step < 1 {
		return ErrShape
	}
	bc1 := float32(1 / (1 - math.Pow(float64(cfg.Beta1), float64(step))))
	bc2 := float32(1 / (1 - math.Pow(float64(cfg.Beta2), float64(step))))
	c2pl_adamw_step(w, m, v, g, n, cfg.LearningRate, cfg.Beta1, cfg.Beta2, cfg.Epsilon, cfg.WeightDecay, bc1, bc2)
	return nil
}

// Sqrt32 et Reciprocal32 exposent les primitives scalaires sans division ni libm
// employées par le pas AdamW et la tangente hyperbolique.
func Sqrt32(x float32) float32       { return c2pl_sqrtf(x) }
func Reciprocal32(d float32) float32 { return c2pl_rcpf(d) }
