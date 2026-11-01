//go:build goexperiment.simd && amd64

package engine

import "simd/archsimd"

// posPosDot calcule le produit scalaire de deux vecteurs de position relative
// en AVX2 sur huit flottants par itération, avec accumulateur vectoriel et
// réduction horizontale finale. Le reliquat non multiple de huit est traité
// scalairement. Le repli scalaire s'applique si AVX2 n'est pas disponible.
func posPosDot(a, b []float32) float32 {
	if !archsimd.X86.AVX2() {
		return dotF32(a, b)
	}
	var acc archsimd.Float32x8 = archsimd.BroadcastFloat32x8(float32(0))
	i := 0
	for ; i+8 <= len(a); i += 8 {
		acc = archsimd.LoadFloat32x8(a[i:][:8]).MulAdd(archsimd.LoadFloat32x8(b[i:][:8]), acc)
	}
	var lanes [8]float32
	acc.Store(lanes[:])
	sum := (((lanes[0] + lanes[1]) + (lanes[2] + lanes[3])) + ((lanes[4] + lanes[5]) + (lanes[6] + lanes[7])))
	for ; i < len(a); i++ {
		sum += a[i] * b[i]
	}
	return sum
}
