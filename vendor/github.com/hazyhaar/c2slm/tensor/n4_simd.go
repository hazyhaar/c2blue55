//go:build goexperiment.simd && amd64

package tensor

import "github.com/hazyhaar/pkg/c2archsimd"

func gemv4N4Q8K(y []float32, w4 []byte, q8k []byte, cols int) {
	c2archsimd.C2_tensor_gemv4_n4_q8_k(w4, q8k, int32(cols), y)
}
