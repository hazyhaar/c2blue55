//go:build !amd64 || !goexperiment.simd || js || wasm

package c2archsimd

// HasAVX2 reports whether AVX2 hardware acceleration is active.
func HasAVX2() bool {
	return false
}

func C2archsimd_lut16_avx2(in []byte, t16 *C2archsimd_table16_t, out []byte) {
	C2archsimd_lut16(in, t16, out)
}

func C2archsimd_lut256_avx2(in []byte, t_lo *C2archsimd_table16_t, t_hi *C2archsimd_table16_t, out []byte) {
	for i := 0; i < 32; i++ {
		lo := t_lo.B[in[i]&15]
		hi := t_hi.B[(in[i]>>4)&15]
		out[i] = lo & hi
	}
}

func C2archsimd_hex_encode16_avx2(in []byte, out []byte) {
	C2archsimd_hex_encode16(in, out)
}

func C2archsimd_vint_lens32_avx2(in []byte, out []byte) {
	C2archsimd_vint_lens32(in, out)
}
