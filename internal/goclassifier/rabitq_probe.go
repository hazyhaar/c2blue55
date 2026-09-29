package goclassifier

import (
	"errors"
	"math"
	"math/bits"
)

// RaBitQ probe: structured pseudo-random projection of an arbitrary feature
// vector into a fixed 512-dimensional space, 1-bit sign quantization, and a
// POPCNT-based anomaly far-side check between two conformal candidate classes.
//
// The projection is built from a normalized Fast Walsh-Hadamard Transform (FHT)
// preceded by a deterministic Rademacher (+1/-1) sign pattern. The transform
// matrix is orthonormal, so Euclidean distances and inner products of the input
// are preserved exactly (up to float32 rounding) without ever materializing a
// dense 512 x D matrix.

const (
	// MaxClasses defines the maximum supported number of output classes.
	MaxClasses = 1024

	// RabitqDim is the fixed projection and quantization width of the probe.
	RabitqDim = 512

	// RabitqWords is the number of 64-bit words holding RabitqDim sign bits.
	RabitqWords = RabitqDim / 64

	// RabitqSeed is the fixed 64-bit seed driving the deterministic sign pattern.
	RabitqSeed uint64 = 0x9E3779B97F4A7C15

	// rabitqInvSqrtDim is 1/sqrt(RabitqDim), the FHT orthonormalization factor.
	rabitqInvSqrtDim = float32(0.04419417382415922)

	// probeConfirmSlack is the absolute Hamming tolerance placed on a class's
	// own intra-class dispersion before the query is deemed corroborating.
	probeConfirmSlack = float32(0.02)

	// probeConfirmMargin is the minimum Hamming separation between the primary
	// class and the alternative class for a confirmation to be declared.
	probeConfirmMargin = float32(0.02)

	// probeAnomalySlack is the dispersion-relative slack beyond which a query is
	// considered off-distribution for that class.
	probeAnomalySlack = float32(0.10)
)

var (
	// ErrInvalidDimensions is returned when model dimensions are invalid or non-positive.
	ErrInvalidDimensions = errors.New("goclassifier: dimensions must be positive")

	// ErrNilProbe is returned when invoking methods on a nil RabitqProbe.
	ErrNilProbe = errors.New("goclassifier: nil rabitq probe")

	// ErrClassOutOfRange is returned when a class index is invalid.
	ErrClassOutOfRange = errors.New("goclassifier: class index out of range")

	// ErrRabitqDimension is returned when a raw vector exceeds RabitqDim.
	ErrRabitqDimension = errors.New("goclassifier: rabitq input dimension out of range")

	// ErrDegenerateProbe is returned when both candidate classes are identical.
	ErrDegenerateProbe = errors.New("goclassifier: rabitq probe requires distinct classes")
)

// rabitqSigns is the deterministic Rademacher pattern derived once from
// RabitqSeed by a splitmix64 generator. It is computed at package
// initialization, so the probe path never allocates and never re-derives it.
var rabitqSigns = func() [RabitqDim]float32 {
	var s [RabitqDim]float32
	z := RabitqSeed
	for i := range s {
		z += RabitqSeed
		v := z
		v = (v ^ (v >> 30)) * 0xBF58476D1CE4E5B9
		v = (v ^ (v >> 27)) * 0x94D049BB133111EB
		v ^= v >> 31
		if v&1 == 0 {
			s[i] = 1
		} else {
			s[i] = -1
		}
	}
	return s
}()

// RabitqCode is the compact 1-bit encoding of a centered 512-dimensional vector.
// Bits holds the 512 sign bits (bit j set when the centered component is
// non-negative), L1 holds the sum of absolute centered components, and L2 holds
// the Euclidean norm of the centered vector.
type RabitqCode struct {
	Bits [RabitqWords]uint64
	L1   float32
	L2   float32
}

// ProbeVerdict is the ternary outcome of the anomaly probe.
type ProbeVerdict uint8

const (
	// ProbeConfirm states that the query sits inside the primary class
	// dispersion and materially closer to it than to the alternative class.
	ProbeConfirm ProbeVerdict = iota

	// ProbeContradiction states that the query is not confirmed as primary,
	// either because it is closer to the alternative class or because the two
	// clusters are not separable at this distance.
	ProbeContradiction

	// ProbeAnomaly states that the query lies outside the dispersion of both
	// candidate classes and is therefore an off-distribution sample.
	ProbeAnomaly
)

// String renders a verdict with an explicit functional label.
func (v ProbeVerdict) String() string {
	switch v {
	case ProbeConfirm:
		return "confirm"
	case ProbeContradiction:
		return "contradiction"
	case ProbeAnomaly:
		return "anomaly"
	default:
		return "unknown"
	}
}

// ProbeStats carries the measured distances and the resulting verdict.
// D1 and D2 are the mean normalized Hamming distances to the primary and
// alternative class prototypes. Spread1 and Spread2 are the intra-class mean
// normalized Hamming dispersions. Margin is D2 - D1.
type ProbeStats struct {
	Verdict ProbeVerdict
	D1      float32
	D2      float32
	Spread1 float32
	Spread2 float32
	Margin  float32
}

// FHT512 applies an in-place, orthonormal Fast Walsh-Hadamard Transform to a
// 512-element buffer. The butterfly pass runs in O(RabitqDim log RabitqDim)
// additions, then the whole buffer is scaled by 1/sqrt(512) so that the
// transform matrix is orthogonal.
func FHT512(buf *[RabitqDim]float32) {
	for h := 1; h < RabitqDim; h <<= 1 {
		for i := 0; i < RabitqDim; i += h << 1 {
			for j := i; j < i+h; j++ {
				a := buf[j]
				b := buf[j+h]
				buf[j] = a + b
				buf[j+h] = a - b
			}
		}
	}
	for i := range buf {
		buf[i] *= rabitqInvSqrtDim
	}
}

// ProjectRabitq writes the structured pseudo-random projection of features into
// dst. Components beyond the first RabitqDim entries are ignored. The input is
// zero-padded to 512, multiplied by the deterministic Rademacher pattern, then
// transformed by FHT512. No dense projection matrix is allocated or stored.
func ProjectRabitq(dst *[RabitqDim]float32, features []float32) {
	n := len(features)
	if n > RabitqDim {
		n = RabitqDim
	}
	for i := 0; i < n; i++ {
		dst[i] = features[i] * rabitqSigns[i]
	}
	for i := n; i < RabitqDim; i++ {
		dst[i] = 0
	}
	FHT512(dst)
}

// QuantizeRabitq encodes a projected 512-dimensional vector into its 1-bit
// RaBitQ form. The vector is centered by its arithmetic mean; each centered
// component contributes a sign bit, and the L1 and L2 norms of the centered
// vector are recorded for the asymmetric distance estimator.
func QuantizeRabitq(v *[RabitqDim]float32) RabitqCode {
	var code RabitqCode

	var mean float32
	for i := 0; i < RabitqDim; i++ {
		mean += v[i]
	}
	mean /= RabitqDim

	var l1, l2 float32
	for w := 0; w < RabitqWords; w++ {
		var word uint64
		base := w * 64
		for b := 0; b < 64; b++ {
			c := v[base+b] - mean
			if c < 0 {
				l1 -= c
			} else {
				word |= uint64(1) << uint(b)
				l1 += c
			}
			l2 += c * c
		}
		code.Bits[w] = word
	}

	code.L1 = l1
	code.L2 = float32(math.Sqrt(float64(l2)))
	return code
}

// hamming512 returns the Hamming distance between two 512-bit codes using the
// hardware POPCNT instruction through math/bits.OnesCount64.
func hamming512(a, b *[RabitqWords]uint64) int {
	var d uint64
	for w := 0; w < RabitqWords; w++ {
		d += uint64(bits.OnesCount64(a[w] ^ b[w]))
	}
	return int(d)
}

// AsymmetricDistance estimates the squared Euclidean distance between a live
// projected query and a stored prototype code. The query retains its floating
// point norm while the angle is read from the POPCNT Hamming fraction:
// cos = 1 - 2*hamming/512.
func AsymmetricDistance(query *[RabitqDim]float32, code RabitqCode) float32 {
	q := QuantizeRabitq(query)
	return AsymmetricDistanceCodes(q, code)
}

// AsymmetricDistanceCodes is the code-to-code form of the asymmetric estimator.
// It consumes only the stored codes and norms and performs no allocation.
func AsymmetricDistanceCodes(q, code RabitqCode) float32 {
	h := float32(hamming512(&q.Bits, &code.Bits))
	cos := 1 - 2*h/RabitqDim
	return q.L2*q.L2 + code.L2*code.L2 - 2*q.L2*code.L2*cos
}

// classSpread returns the mean normalized Hamming distance of a class's
// prototypes to their majority-bit centroid. A class with fewer than two
// prototypes has zero dispersion.
func classSpread(protos []RabitqCode) float32 {
	n := len(protos)
	if n <= 1 {
		return 0
	}

	var centroid [RabitqWords]uint64
	for w := 0; w < RabitqWords; w++ {
		var ones int
		for i := range protos {
			ones += bits.OnesCount64(protos[i].Bits[w])
		}
		if ones*2 >= n*64 {
			centroid[w] = ^uint64(0)
		}
	}

	var sum int
	for i := range protos {
		sum += hamming512(&centroid, &protos[i].Bits)
	}
	return float32(sum) / (float32(n) * RabitqDim)
}

// meanHamming returns the mean normalized Hamming distance from a query code to
// a class's prototypes. An empty class is maximally distant by convention.
func meanHamming(q *RabitqCode, protos []RabitqCode) float32 {
	n := len(protos)
	if n == 0 {
		return 1
	}
	var sum int
	for i := range protos {
		sum += hamming512(&q.Bits, &protos[i].Bits)
	}
	return float32(sum) / (float32(n) * RabitqDim)
}

// RabitqProbe is a compact per-class index of quantized training prototypes.
type RabitqProbe struct {
	classes int
	protos  [][]RabitqCode
}

// NewRabitqProbe allocates an empty probe for the given number of classes.
func NewRabitqProbe(classes int) (*RabitqProbe, error) {
	if classes <= 0 || classes > MaxClasses {
		return nil, ErrInvalidDimensions
	}
	return &RabitqProbe{classes: classes, protos: make([][]RabitqCode, classes)}, nil
}

// Classes reports the configured class count.
func (p *RabitqProbe) Classes() int {
	if p == nil {
		return 0
	}
	return p.classes
}

// PrototypeCount reports the number of prototypes stored for a given class.
func (p *RabitqProbe) PrototypeCount(class int) int {
	if p == nil || class < 0 || class >= p.classes {
		return 0
	}
	return len(p.protos[class])
}

// AddPrototype projects, quantizes and files one training vector under class.
func (p *RabitqProbe) AddPrototype(class int, features []float32) error {
	if p == nil {
		return ErrNilProbe
	}
	if class < 0 || class >= p.classes {
		return ErrClassOutOfRange
	}
	if len(features) == 0 || len(features) > RabitqDim {
		return ErrRabitqDimension
	}
	var proj [RabitqDim]float32
	ProjectRabitq(&proj, features)
	p.protos[class] = append(p.protos[class], QuantizeRabitq(&proj))
	return nil
}

// Probe evaluates the contradictory indicator for a query vector against the
// two conformal candidate classes. The query is projected and quantized once;
// distances are then measured to the prototypes of both classes. The probe
// performs no heap allocation.
func (p *RabitqProbe) Probe(query []float32, primary, alternative int) (ProbeStats, error) {
	var st ProbeStats
	if p == nil {
		return st, ErrNilProbe
	}
	if primary < 0 || primary >= p.classes || alternative < 0 || alternative >= p.classes {
		return st, ErrClassOutOfRange
	}
	if primary == alternative {
		return st, ErrDegenerateProbe
	}
	if len(query) == 0 || len(query) > RabitqDim {
		return st, ErrRabitqDimension
	}

	var proj [RabitqDim]float32
	ProjectRabitq(&proj, query)
	qc := QuantizeRabitq(&proj)

	sp1 := classSpread(p.protos[primary])
	sp2 := classSpread(p.protos[alternative])
	d1 := meanHamming(&qc, p.protos[primary])
	d2 := meanHamming(&qc, p.protos[alternative])

	st.D1 = d1
	st.D2 = d2
	st.Spread1 = sp1
	st.Spread2 = sp2
	st.Margin = d2 - d1

	switch {
	case d1 > sp1+probeAnomalySlack && d2 > sp2+probeAnomalySlack:
		st.Verdict = ProbeAnomaly
	case d1 <= sp1+probeConfirmSlack && d2 > d1+probeConfirmMargin:
		st.Verdict = ProbeConfirm
	default:
		st.Verdict = ProbeContradiction
	}
	return st, nil
}
