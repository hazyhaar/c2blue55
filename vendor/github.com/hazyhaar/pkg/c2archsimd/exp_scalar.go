package c2archsimd

import "math"

// Constantes float32 exactes de l'approximation exponentielle. Les litteraux
// hexadecimaux garantissent une representation identique a celle de la source
// C c2simd/sources/c2archsimd/exp_f32.c, d'ou sgoiter emet la voie vectorielle
// ExpFloat32x8 (exp_f32_gen.go). ExpFloat32 reste ecrite en Go : sgoiter ne
// transpile ni fmaf ni floorf. Sa parite bit a bit avec la fonction C du meme
// nom est prouvee par TestExpFloat32VsCOracle.
const (
	c2ExpLog2E = float32(0x1.715476p+0)   // 1/log(2)
	c2ExpLn2Hi = float32(0x1.63p-1)       // ln2 tronque
	c2ExpLn2Lo = float32(-0x1.bd0106p-13) // ln2 - ln2_hi
	c2ExpHalf  = float32(0.5)

	c2ExpC6 = float32(0x1.6c16c2p-10) // 1/720
	c2ExpC5 = float32(0x1.111112p-07) // 1/120
	c2ExpC4 = float32(0x1.555556p-05) // 1/24
	c2ExpC3 = float32(0x1.555556p-03) // 1/6
	c2ExpC2 = float32(0x1p-01)        // 1/2
	c2ExpC1 = float32(0x1p+00)        // 1
	c2ExpC0 = float32(0x1p+00)        // 1

	c2ExpHi = float32(88.0)
	c2ExpLo = float32(-88.0)

	// c2ExpMinN est l'exposant biaise minimal d'une puissance normale 2^n.
	c2ExpMinN = int32(-126)
)

// fmaf32 realise un produit-scalaire fuse correctement arrondi en float32. Go
// n'expose pas de primitive float32 dediee : le calcul en float64 via math.FMA
// est exact pour deux operandes float32, puis arrondi une seule fois vers
// float32, ce qui reproduit la semantique de fmaf() du C.
func fmaf32(a, b, c float32) float32 {
	return float32(math.FMA(float64(a), float64(b), float64(c)))
}

// ExpFloat32 rend une approximation float32 de e^x par decomposition
// d'argument et polynome de degre 6 evalue par produits fuses. Le domaine des
// valeurs finies est borne a [-88, 88] ; NaN est propage tel quel, +Inf rend
// +Inf et -Inf rend 0. Sous 2^-126 le resultat sature a zero.
//
// La fonction n'alloue rien sur le tas.
func ExpFloat32(x float32) float32 {
	if x != x {
		return x
	}
	if math.IsInf(float64(x), 1) {
		return x
	}
	if math.IsInf(float64(x), -1) {
		return 0
	}
	if x > c2ExpHi {
		x = c2ExpHi
	}
	if x < c2ExpLo {
		x = c2ExpLo
	}

	z := float32(math.Floor(float64(fmaf32(x, c2ExpLog2E, c2ExpHalf))))
	n := int32(z)
	if n < c2ExpMinN {
		return 0
	}

	nf := float32(n)
	r := fmaf32(-nf, c2ExpLn2Hi, x)
	r = fmaf32(-nf, c2ExpLn2Lo, r)

	p := c2ExpC6
	p = fmaf32(p, r, c2ExpC5)
	p = fmaf32(p, r, c2ExpC4)
	p = fmaf32(p, r, c2ExpC3)
	p = fmaf32(p, r, c2ExpC2)
	p = fmaf32(p, r, c2ExpC1)
	p = fmaf32(p, r, c2ExpC0)

	scale := math.Float32frombits(uint32(n+127) << 23)
	return p * scale
}

// ExpFloat32Array applique l'approximation a min(len(in), len(out)) elements :
// blocs de huit voies par ExpFloat32x8 lorsque la voie AVX2 est compilee et
// presente, reste par ExpFloat32. Le balayage est C2_exp_f32_array, emis par
// sgoiter depuis exp_f32.c. Aucune allocation sur le tas.
func ExpFloat32Array(in, out []float32) {
	n := len(in)
	if len(out) < n {
		n = len(out)
	}
	C2_exp_f32_array(in, out, n)
}
