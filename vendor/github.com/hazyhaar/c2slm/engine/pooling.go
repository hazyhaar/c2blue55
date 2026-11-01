//go:build goexperiment.simd && amd64

package engine

import (
	"math"
	"simd/archsimd"
)

// PoolFirstToken copies the first token hidden vector (the [CLS] or [STATE]
// representation) of a [seqLen*hiddenDim] buffer into out. The extraction is a
// flat contiguous copy; out must be caller-owned and len(out) >= hiddenDim.
func PoolFirstToken(hidden []float32, hiddenDim int, out []float32) {
	poolFirstTokenScalar(hidden, hiddenDim, out)
}

// PoolMean reduces the seqLen token vectors of a [seqLen*hiddenDim] buffer to
// their arithmetic mean:
//
//	v[d] = (1/N) * sum_i hidden[i*hiddenDim + d]
//
// The accumulation is vectorized eight lanes at a time with Float32x8.Add and
// the result is scaled by the inverse sequence length. A scalar tail handles
// hidden dimensions that are not a multiple of eight.
func PoolMean(hidden []float32, seqLen, hiddenDim int, out []float32) {
	if archsimd.X86.AVX2() {
		poolMeanAVX2(hidden, seqLen, hiddenDim, out)
		return
	}
	poolMeanScalar(hidden, seqLen, hiddenDim, out)
}

// PoolMeanWithAttentionMask reduces the token vectors selected by the boolean
// attention mask to their arithmetic mean, ignoring padding ([PAD]):
//
//	v[d] = (1/C) * sum_{i: mask[i]} hidden[i*hiddenDim + d]
//
// with C the number of set mask entries. An empty or all-false mask zeroes out
// without dividing. The accumulation uses Float32x8.Add and a scalar tail.
func PoolMeanWithAttentionMask(hidden []float32, mask []bool, seqLen, hiddenDim int, out []float32) {
	if archsimd.X86.AVX2() {
		poolMeanWithAttentionMaskAVX2(hidden, mask, seqLen, hiddenDim, out)
		return
	}
	poolMeanWithAttentionMaskScalar(hidden, mask, seqLen, hiddenDim, out)
}

// L2Normalize writes out[i] = v[i] / sqrt(sum(v^2)+eps) using a fused
// multiply-add reduction for the squared norm and a lane-wise multiply by the
// inverse norm. The sum of squares stays in the FP32 domain exactly like the
// scalar reference; only its horizontal reduction is vectorized.
func L2Normalize(v []float32, out []float32, eps float32) {
	if archsimd.X86.AVX2() {
		l2NormalizeAVX2(v, out, eps)
		return
	}
	l2NormalizeScalar(v, out, eps)
}

// poolMeanAVX2 is the eight-lane kernel behind PoolMean.
func poolMeanAVX2(hidden []float32, seqLen, hiddenDim int, out []float32) {
	n := hiddenDim
	if n > len(out) {
		n = len(out)
	}
	if n <= 0 {
		return
	}
	if seqLen <= 0 {
		zeroFloat32(out[:n])
		return
	}

	inv := archsimd.BroadcastFloat32x8(1.0 / float32(seqLen))
	d := 0
	for ; d+8 <= n; d += 8 {
		acc := archsimd.BroadcastFloat32x8(0)
		for i := 0; i < seqLen; i++ {
			acc = acc.Add(archsimd.LoadFloat32x8(hidden[i*hiddenDim+d:]))
		}
		acc.Mul(inv).Store(out[d:])
	}

	invScalar := 1.0 / float32(seqLen)
	for ; d < n; d++ {
		var sum float32
		for i := 0; i < seqLen; i++ {
			sum += hidden[i*hiddenDim+d]
		}
		out[d] = sum * invScalar
	}
}

// poolMeanWithAttentionMaskAVX2 is the eight-lane kernel behind
// PoolMeanWithAttentionMask.
func poolMeanWithAttentionMaskAVX2(hidden []float32, mask []bool, seqLen, hiddenDim int, out []float32) {
	n := hiddenDim
	if n > len(out) {
		n = len(out)
	}
	if n <= 0 {
		return
	}
	limit := seqLen
	if limit > len(mask) {
		limit = len(mask)
	}

	count := 0
	for i := 0; i < limit; i++ {
		if mask[i] {
			count++
		}
	}
	if count == 0 {
		zeroFloat32(out[:n])
		return
	}

	inv := archsimd.BroadcastFloat32x8(1.0 / float32(count))
	d := 0
	for ; d+8 <= n; d += 8 {
		acc := archsimd.BroadcastFloat32x8(0)
		for i := 0; i < limit; i++ {
			if mask[i] {
				acc = acc.Add(archsimd.LoadFloat32x8(hidden[i*hiddenDim+d:]))
			}
		}
		acc.Mul(inv).Store(out[d:])
	}

	invScalar := 1.0 / float32(count)
	for ; d < n; d++ {
		var sum float32
		for i := 0; i < limit; i++ {
			if mask[i] {
				sum += hidden[i*hiddenDim+d]
			}
		}
		out[d] = sum * invScalar
	}
}

// l2NormalizeAVX2 is the eight-lane kernel behind L2Normalize.
func l2NormalizeAVX2(v, out []float32, eps float32) {
	n := len(v)
	if n > len(out) {
		n = len(out)
	}
	if n <= 0 {
		return
	}

	acc := archsimd.BroadcastFloat32x8(0)
	i := 0
	for ; i+8 <= n; i += 8 {
		x := archsimd.LoadFloat32x8(v[i:])
		acc = x.MulAdd(x, acc)
	}
	var lanes [8]float32
	acc.StoreArray(&lanes)
	sum := ((lanes[0] + lanes[1]) + (lanes[2] + lanes[3])) + ((lanes[4] + lanes[5]) + (lanes[6] + lanes[7]))
	for ; i < n; i++ {
		sum += v[i] * v[i]
	}

	norm := float32(math.Sqrt(float64(sum + eps)))
	inv := archsimd.BroadcastFloat32x8(1.0 / norm)
	i = 0
	for ; i+8 <= n; i += 8 {
		archsimd.LoadFloat32x8(v[i:]).Mul(inv).Store(out[i:])
	}
	invScalar := 1.0 / norm
	for ; i < n; i++ {
		out[i] = v[i] * invScalar
	}
}
