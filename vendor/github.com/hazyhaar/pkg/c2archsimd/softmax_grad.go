package c2archsimd

import "math"

// SoftmaxGradient calcule la perte d'entropie croisée softmax pondérée par classe,
// augmentée d'une pénalité L2, ainsi que ses gradients par rapport à la matrice de
// projection W (K x D), au vecteur de biais b (K) et aux logits intermédiaires.
//
// Les conventions de disposition sont en lignes majeures : X[i*D:(i+1)*D] est
// l'échantillon i, W[k*D:(k+1)*D] la classe k, Y[i] l'étiquette de l'échantillon i
// et probsScratch[i*K:(i+1)*K] la ligne de probabilités correspondante.
//
// L'orchestration (exponentielle, logarithme, perte, gradient du biais) est
// scalaire. Le produit scalaire et la rangée du gradient de W sont les noyaux
// _c2_softmax_grad_dot et _c2_softmax_grad_wrow, émis par sgoiter depuis
// c2simd/sources/c2archsimd/c2_softmax_grad.c : voie AVX2 sous
// goexperiment.simd sur amd64, repli scalaire déroulé par quatre ailleurs.
// L'accumulation du gradient reste en float64. Le calcul n'alloue rien sur le
// tas.
func SoftmaxGradient(
	N, D, K int,
	X []float32,
	W []float32,
	b []float32,
	Y []int32,
	classWeights []float32,
	lambda float32,
	outLoss *float64,
	outGradW []float32,
	outGradB []float32,
	probsScratch []float32,
) {
	if outLoss != nil {
		*outLoss = 0
	}
	if N <= 0 || K <= 0 {
		return
	}

	var loss float64

	// Passe avant : projection linéaire des logits, soustraction du maximum par
	// échantillon, softmax stable et entropie croisée pondérée.
	for i := 0; i < N; i++ {
		base := i * K
		xrow := X[i*D : i*D+D]

		z0 := _c2_softmax_grad_dot(W[:D], xrow, D)
		if b != nil {
			z0 += b[0]
		}
		probsScratch[base] = z0
		maxLogit := z0
		for k := 1; k < K; k++ {
			z := _c2_softmax_grad_dot(W[k*D:k*D+D], xrow, D)
			if b != nil {
				z += b[k]
			}
			probsScratch[base+k] = z
			if z > maxLogit {
				maxLogit = z
			}
		}

		var sum float64
		for k := 0; k < K; k++ {
			e := float32(math.Exp(float64(probsScratch[base+k] - maxLogit)))
			probsScratch[base+k] = e
			sum += float64(e)
		}
		if sum <= 0 {
			sum = 1
		}
		inv := float32(1.0 / sum)

		tgt := int(Y[i])
		cw := 1.0
		if classWeights != nil {
			cw = float64(classWeights[tgt])
		}
		var pTgt float32
		for k := 0; k < K; k++ {
			p := probsScratch[base+k] * inv
			probsScratch[base+k] = p
			if k == tgt {
				pTgt = p
			}
		}
		if pTgt < 1e-30 {
			pTgt = 1e-30
		}
		loss += cw * (-math.Log(float64(pTgt)))
	}
	loss /= float64(N)

	// Conversion en place des probabilités en coefficients dL/dz_{i,k}.
	invN := float32(1.0) / float32(N)
	for i := 0; i < N; i++ {
		base := i * K
		tgt := int(Y[i])
		invNcw := invN
		if classWeights != nil {
			invNcw *= classWeights[tgt]
		}
		for k := 0; k < K; k++ {
			d := probsScratch[base+k]
			if k == tgt {
				d -= 1
			}
			probsScratch[base+k] = invNcw * d
		}
	}

	// Gradient de W : accumulation float64 par classe et par dimension, avec
	// pénalité L2.
	lam := float64(lambda)
	for k := 0; k < K; k++ {
		_c2_softmax_grad_wrow(X, probsScratch, W[k*D:k*D+D], outGradW[k*D:k*D+D], N, D, K, k, lam)
	}

	// Gradient du biais : somme des coefficients dL/dz par classe.
	if outGradB != nil {
		for k := 0; k < K; k++ {
			var accd float64
			for i := 0; i < N; i++ {
				accd += float64(probsScratch[i*K+k])
			}
			outGradB[k] = float32(accd)
		}
	}

	// Pénalité L2 ajoutée à la perte.
	var reg float64
	for j := 0; j < K*D; j++ {
		w := float64(W[j])
		reg += w * w
	}
	loss += 0.5 * lam * reg

	if outLoss != nil {
		*outLoss = loss
	}
}
