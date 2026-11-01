//go:build !(goexperiment.simd && amd64)

package tensor

func gemv4N4Q8K(y []float32, w4 []byte, q8k []byte, cols int) {
	GEMV4N4Q8KReference(y, w4, q8k, cols)
}
