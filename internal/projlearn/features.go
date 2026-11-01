package projlearn

import (
	"math"
	"math/bits"
)

// Example est un exemple d'entraînement ou d'évaluation : octets du nom
// (minuscules, <= 253), bornes des labels, traits structurels, étiquette.
type Example struct {
	Name   []byte
	Labels []int
	Struct [8]float32
	Label  float32
	Family string
}

// PCG64 est un générateur déterministe maison (PCG XSL RR 128/64).
type PCG64 struct {
	hi uint64
	lo uint64
}

// NewPCG64 construit le générateur à partir d'une graine.
func NewPCG64(seed uint64) *PCG64 {
	g := &PCG64{}
	g.step()
	lo, carry := bits.Add64(g.lo, seed, 0)
	g.lo = lo
	g.hi, _ = bits.Add64(g.hi, 0, carry)
	g.step()
	return g
}

func (g *PCG64) step() {
	hi, lo := bits.Mul64(g.lo, 4865540595714422341)
	_, crossA := bits.Mul64(g.hi, 4865540595714422341)
	_, crossB := bits.Mul64(g.lo, 2549297995355413924)
	newLo, crossCarry := bits.Add64(lo, 1, 0)
	g.lo = newLo
	g.hi = hi + crossA + crossB + crossCarry
}

// Uint64 rend le prochain nombre.
func (g *PCG64) Uint64() uint64 {
	g.step()
	return bits.RotateLeft64(g.hi^g.lo, -int(g.hi>>58))
}

// StructFeatures renseigne Struct depuis les traits d'une question DNS.
func StructFeatures(qtype uint16, labelCount, maxLabelLen uint8, subCardinality uint32, encoded bool, nameLen int) [8]float32 {
	clamp := func(x float64) float32 {
		if x < 0 {
			return 0
		}
		if x > 1 {
			return 1
		}
		return float32(x)
	}
	var flag float32
	if encoded {
		flag = 1
	}
	return [8]float32{clamp(float64(qtype) / 255), clamp(float64(labelCount) / 16),
		clamp(float64(maxLabelLen) / 64), clamp(math.Log2(float64(subCardinality)+1) / 16),
		flag, clamp(float64(nameLen) / 253), 0, 0}
}
