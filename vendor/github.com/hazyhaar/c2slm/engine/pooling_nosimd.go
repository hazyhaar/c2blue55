//go:build !goexperiment.simd || !amd64

package engine

// PoolFirstToken copies the first token hidden vector (the [CLS] or [STATE]
// representation) of a [seqLen*hiddenDim] buffer into out.
func PoolFirstToken(hidden []float32, hiddenDim int, out []float32) {
	poolFirstTokenScalar(hidden, hiddenDim, out)
}

// PoolMean reduces the seqLen token vectors of a [seqLen*hiddenDim] buffer to
// their arithmetic mean. This build has no SIMD experiment, so the scalar
// reference is used directly.
func PoolMean(hidden []float32, seqLen, hiddenDim int, out []float32) {
	poolMeanScalar(hidden, seqLen, hiddenDim, out)
}

// PoolMeanWithAttentionMask reduces the token vectors selected by the boolean
// attention mask to their arithmetic mean, ignoring padding. This build has no
// SIMD experiment, so the scalar reference is used directly.
func PoolMeanWithAttentionMask(hidden []float32, mask []bool, seqLen, hiddenDim int, out []float32) {
	poolMeanWithAttentionMaskScalar(hidden, mask, seqLen, hiddenDim, out)
}

// L2Normalize writes out[i] = v[i] / sqrt(sum(v^2)+eps). This build has no SIMD
// experiment, so the scalar reference is used directly.
func L2Normalize(v []float32, out []float32, eps float32) {
	l2NormalizeScalar(v, out, eps)
}
