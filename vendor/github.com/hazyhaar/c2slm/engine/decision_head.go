package engine

import "github.com/hazyhaar/c2slm/internal/simd"

// MaxK is the hard upper bound on the number of classes a DecisionHead can
// score in a single restricted projection. The generated micro-kernel keeps its
// logit workspace as a stack array [256]float32, so this bound is structural.
const MaxK = 256

// Indices used by the binary Noul primitive: class 0 is false, class 1 is true.
const (
	NoulFalseIndex = 0
	NoulTrueIndex  = 1
)

// DecisionHead is the closed typed decision head ("System One"). It projects a
// hidden state onto k candidate rows and reduces the resulting logits to a
// calibrated distribution over the choices. Both the projection and the softmax
// are delegated to the AVX2 micro-kernel C2_tensor_logit_gather_softmax (scalar
// fallback included), so DecideChoice, DecideNoul and DecideScore allocate
// nothing on the heap when the caller supplies a pre-sized scratch buffer.
//
// Weights is row-major [MaxK * HiddenDim]: row i occupies
// Weights[i*HiddenDim : (i+1)*HiddenDim]. A call with k candidates uses the
// first k rows only. Biases is optional; a nil or short slice disables it.
type DecisionHead struct {
	Weights     []float32
	Biases      []float32
	HiddenDim   int
	Temperature float32
}

// NewDecisionHead allocates a head with an empty projection of MaxK rows and no
// bias. The weights are zero, so a caller must populate them (or replace the
// slice) before the first decision.
func NewDecisionHead(hiddenDim int, temperature float32) *DecisionHead {
	if hiddenDim < 0 {
		hiddenDim = 0
	}
	return &DecisionHead{
		Weights:     make([]float32, MaxK*hiddenDim),
		HiddenDim:   hiddenDim,
		Temperature: temperature,
	}
}

// effectiveTemperature returns a usable positive temperature, defaulting to 1
// when the field is zero, negative or NaN, since the kernel divides by it.
func (h *DecisionHead) effectiveTemperature() float32 {
	t := h.Temperature
	if !(t > 0) {
		return 1
	}
	return t
}

// validChoice reports whether the head and the supplied buffers can service a
// k-way restricted projection of dimension h.HiddenDim without panicking.
func (h *DecisionHead) validChoice(hiddenState []float32, k int, scratch []float32) (dim int, ok bool) {
	if h == nil || k <= 0 || k > MaxK {
		return 0, false
	}
	dim = h.HiddenDim
	if dim <= 0 || len(hiddenState) < dim || len(h.Weights) < k*dim || len(scratch) < k {
		return 0, false
	}
	return dim, true
}

// DecideChoice scores k classes (k between 1 and MaxK) against hiddenState and
// returns the winning index, its label (empty when labels is too short), the
// winning probability as confidence, and the full probability vector. probs
// aliases the caller-owned scratch buffer and stays valid until scratch is
// reused; nothing is allocated on the heap.
func (h *DecisionHead) DecideChoice(hiddenState []float32, k int, labels []string, scratch []float32) (bestIdx int, bestLabel string, confidence float32, probs []float32) {
	dim, ok := h.validChoice(hiddenState, k, scratch)
	if !ok {
		return -1, "", 0, nil
	}

	probs = scratch[:k]
	var bias []float32
	if len(h.Biases) >= k {
		bias = h.Biases[:k]
	}
	simd.C2_tensor_logit_gather_softmax(hiddenState, h.Weights[:k*dim], bias, probs, k, dim, h.effectiveTemperature())

	bestIdx = 0
	confidence = probs[0]
	for i := 1; i < k; i++ {
		if probs[i] > confidence {
			bestIdx = i
			confidence = probs[i]
		}
	}
	if bestIdx < len(labels) {
		bestLabel = labels[bestIdx]
	}
	return bestIdx, bestLabel, confidence, probs
}

// DecideNoul reduces the two-way Noul primitive to a calibrated probability of
// true. It uses the first two weight rows and returns probs[NoulTrueIndex],
// which is the softmax probability of the "true" class. It returns 0 when the
// head is unusable. No heap allocation occurs.
func (h *DecisionHead) DecideNoul(hiddenState []float32, scratch []float32) float32 {
	dim, ok := h.validChoice(hiddenState, 2, scratch)
	if !ok {
		return 0
	}

	probs := scratch[:2]
	var bias []float32
	if len(h.Biases) >= 2 {
		bias = h.Biases[:2]
	}
	simd.C2_tensor_logit_gather_softmax(hiddenState, h.Weights[:2*dim], bias, probs, 2, dim, h.effectiveTemperature())
	return probs[NoulTrueIndex]
}

// DecideScore evaluates an ordered numeric scale. levels[i] is the value of
// class i, and the returned expected value is sum(levels[i] * probs[i]). probs
// aliases scratch exactly as in DecideChoice. It returns 0 and a nil vector when
// the head is unusable or levels is empty. No heap allocation occurs.
func (h *DecisionHead) DecideScore(hiddenState []float32, levels []float32, scratch []float32) (expected float32, probs []float32) {
	k := len(levels)
	if _, ok := h.validChoice(hiddenState, k, scratch); !ok {
		return 0, nil
	}

	_, _, _, probs = h.DecideChoice(hiddenState, k, nil, scratch)
	if probs == nil {
		return 0, nil
	}
	for i := 0; i < k; i++ {
		expected += levels[i] * probs[i]
	}
	return expected, probs
}
