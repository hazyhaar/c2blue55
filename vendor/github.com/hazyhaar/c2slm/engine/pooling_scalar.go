package engine

import "math"

// poolFirstTokenScalar copies the first token vector (the [CLS] or [STATE]
// representation) of a [seqLen*hiddenDim] hidden-state buffer into out.
func poolFirstTokenScalar(hidden []float32, hiddenDim int, out []float32) {
	n := hiddenDim
	if n > len(out) {
		n = len(out)
	}
	if n > len(hidden) {
		n = len(hidden)
	}
	if n <= 0 {
		return
	}
	copy(out[:n], hidden[:n])
}

// poolMeanScalar computes the arithmetic mean of the seqLen token vectors
// laid out contiguously as [seqLen*hiddenDim].
func poolMeanScalar(hidden []float32, seqLen, hiddenDim int, out []float32) {
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
	zeroFloat32(out[:n])
	for i := 0; i < seqLen; i++ {
		base := i * hiddenDim
		for d := 0; d < n; d++ {
			out[d] += hidden[base+d]
		}
	}
	inv := 1.0 / float32(seqLen)
	for d := 0; d < n; d++ {
		out[d] *= inv
	}
}

// poolMeanWithAttentionMaskScalar computes the mean of the token vectors whose
// mask entry is true, ignoring padding. When no token is selected the output is
// zeroed without dividing.
func poolMeanWithAttentionMaskScalar(hidden []float32, mask []bool, seqLen, hiddenDim int, out []float32) {
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
	zeroFloat32(out[:n])
	for i := 0; i < limit; i++ {
		if !mask[i] {
			continue
		}
		base := i * hiddenDim
		for d := 0; d < n; d++ {
			out[d] += hidden[base+d]
		}
	}
	inv := 1.0 / float32(count)
	for d := 0; d < n; d++ {
		out[d] *= inv
	}
}

// l2NormalizeScalar writes out[i] = v[i] / sqrt(sum(v^2)+eps) without any heap
// allocation for caller-owned out.
func l2NormalizeScalar(v, out []float32, eps float32) {
	n := len(v)
	if n > len(out) {
		n = len(out)
	}
	if n <= 0 {
		return
	}
	var sum float32
	for i := 0; i < n; i++ {
		sum += v[i] * v[i]
	}
	inv := float32(1.0) / float32(math.Sqrt(float64(sum+eps)))
	for i := 0; i < n; i++ {
		out[i] = v[i] * inv
	}
}

// zeroFloat32 clears a caller-owned slice in place.
func zeroFloat32(s []float32) {
	for i := range s {
		s[i] = 0
	}
}
