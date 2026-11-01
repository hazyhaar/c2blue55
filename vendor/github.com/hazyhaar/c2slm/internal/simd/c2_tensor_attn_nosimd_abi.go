//go:build !(goexperiment.simd && amd64)

package simd

// Repli scalaire des feuilles assembleur de l'attention : même signature
// (entiers en int32, ABI des feuilles gcc) sur le transpilé scalaire de la
// même source C (c2_tensor_attn_scalaire_nosimd_gen.go).

func C2_tensor_attn_qk(q []float32, kbase []float32, pos int32, stride int32, scale float32, scores []float32, hd int32) {
	C2_tensor_attn_qk_scalaire(q, kbase, int(pos), int(stride), scale, scores, int(hd))
}

func C2_tensor_attn_av(scores []float32, vbase []float32, pos int32, stride int32, out []float32, hd int32) {
	C2_tensor_attn_av_scalaire(scores, vbase, int(pos), int(stride), out, int(hd))
}
