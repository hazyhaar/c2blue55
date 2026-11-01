//go:build !(goexperiment.simd && amd64)

package tensor

func gemv4N5Q8K(sortie []float32, poids []byte, activation []byte, cols int) {
	GEMV4N5Q8KReference(sortie, poids, activation, cols)
}
