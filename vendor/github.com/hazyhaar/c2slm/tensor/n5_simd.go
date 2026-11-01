//go:build goexperiment.simd && amd64

package tensor

import "github.com/hazyhaar/pkg/c2archsimd"

func gemv4N5Q8K(y []float32, w5 []byte, q8k []byte, cols int) {
	c2archsimd.C2_tensor_gemv4_n5_q8_k(w5, q8k, int32(cols), y)
}
