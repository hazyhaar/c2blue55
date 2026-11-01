//go:build !goexperiment.simd || !amd64

package engine

// posPosDot est le repli scalaire utilisé lorsque la compilation n'active pas
// les instructions vectorielles archsimd.
func posPosDot(a, b []float32) float32 {
	return dotF32(a, b)
}
