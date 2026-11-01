// SPDX-License-Identifier: Apache-2.0 OR MIT

//go:build !amd64 || !goexperiment.simd || js || wasm

package c2archtsim

// HasAVX2 reports whether AVX2 hardware acceleration is active.
func HasAVX2() bool {
	return false
}

func C2archtsim_lut16_avx2(in []byte, t16 *C2archtsim_table16_t, out []byte) {
	C2archtsim_lut16(in, t16, out)
}

func C2archtsim_lut256_avx2(in []byte, t_lo *C2archtsim_table16_t, t_hi *C2archtsim_table16_t, out []byte) {
	for i := 0; i < 32; i++ {
		lo := t_lo.B[in[i]&15]
		hi := t_hi.B[(in[i]>>4)&15]
		out[i] = lo & hi
	}
}

func C2archtsim_hex_encode16_avx2(in []byte, out []byte) {
	C2archtsim_hex_encode16(in, out)
}

func C2archtsim_vint_lens32_avx2(in []byte, out []byte) {
	C2archtsim_vint_lens32(in, out)
}
