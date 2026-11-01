package tensor

import (
	"encoding/binary"
	"fmt"
	"math"
)

// N4Size returns the number of bytes occupied by four-row, 32-column records.
func N4Size(rows, cols int) int {
	return rows / 4 * (cols / 32) * 80
}

// QuantizeRowsN4 encodes the Q4_0 reference rounding rule in interleaved groups.
func QuantizeRowsN4(w []float32, rows, cols int, out []byte) error {
	if rows <= 0 || cols <= 0 || rows%4 != 0 || cols%256 != 0 || rows > int(^uint(0)>>1)/cols || len(w) != rows*cols || len(out) != N4Size(rows, cols) {
		return fmt.Errorf("N4: dimensions ou tailles incohérentes: %d x %d", rows, cols)
	}
	for groupe := 0; groupe < rows/4; groupe++ {
		for bloc := 0; bloc < cols/32; bloc++ {
			enregistrement := out[(groupe*cols/32+bloc)*80:]
			for ligne := 0; ligne < 4; ligne++ {
				poids := w[(groupe*4+ligne)*cols+bloc*32:]
				var maximum, signe float32
				for i := 0; i < 32; i++ {
					if valeur := float32(math.Abs(float64(poids[i]))); valeur > maximum {
						maximum, signe = valeur, poids[i]
					}
				}
				echelle := float32(0) // amax nul : échelle +0 (spec §2), jamais −0
				if maximum != 0 {
					echelle = signe / -8
				}
				binary.LittleEndian.PutUint32(enregistrement[ligne*4:], math.Float32bits(echelle))
				inverse := float32(0)
				if maximum != 0 {
					inverse = 1 / echelle
				}
				for i := 0; i < 16; i++ {
					bas := int(poids[i]*inverse + 8.5)
					haut := int(poids[i+16]*inverse + 8.5)
					if bas < 0 {
						bas = 0
					}
					if bas > 15 {
						bas = 15
					}
					if haut < 0 {
						haut = 0
					}
					if haut > 15 {
						haut = 15
					}
					enregistrement[16+ligne*16+i] = byte(bas | haut<<4)
				}
			}
		}
	}
	return nil
}

// DequantizeN4 reconstructs every row from the interleaved records.
func DequantizeN4(in []byte, rows, cols int, out []float32) {
	for groupe := 0; groupe < rows/4; groupe++ {
		for bloc := 0; bloc < cols/32; bloc++ {
			enregistrement := in[(groupe*cols/32+bloc)*80:]
			for ligne := 0; ligne < 4; ligne++ {
				echelle := math.Float32frombits(binary.LittleEndian.Uint32(enregistrement[ligne*4:]))
				poids := out[(groupe*4+ligne)*cols+bloc*32:]
				for i := 0; i < 16; i++ {
					valeur := enregistrement[16+ligne*16+i]
					poids[i] = echelle * float32(int(valeur&15)-8)
					poids[i+16] = echelle * float32(int(valeur>>4)-8)
				}
			}
		}
	}
}

// DequantizeQ8_K reconstructs activation values from their block scales.
func DequantizeQ8_K(q8k []byte, cols int) []float32 {
	activation := make([]float32, cols)
	for bloc := 0; bloc < cols/256; bloc++ {
		partie := q8k[bloc*BlockSizeQ8_K:]
		echelle := math.Float32frombits(binary.LittleEndian.Uint32(partie))
		for i := 0; i < 256; i++ {
			activation[bloc*256+i] = echelle * float32(int8(partie[4+i]))
		}
	}
	return activation
}

// GEMV4N4Q8K computes four scalar dot products in ascending block order.
// GEMV4N4Q8K calcule quatre lignes N4 contre une activation Q8_K : noyau
// transpilé c2archsimd sous goexperiment.simd, référence Go scalaire sinon.
func GEMV4N4Q8K(y []float32, w4 []byte, q8k []byte, cols int) {
	gemv4N4Q8K(y, w4, q8k, cols)
}

// gemv4N4Q8KReference est la référence scalaire du contrat §3 (spec/n4-format-v1.md).
func GEMV4N4Q8KReference(y []float32, w4 []byte, q8k []byte, cols int) {
	var cumul [4]float32
	for bloc := 0; bloc < cols/32; bloc++ {
		enregistrement := w4[bloc*80:]
		activation := q8k[(bloc/8)*BlockSizeQ8_K:]
		echelleActivation := math.Float32frombits(binary.LittleEndian.Uint32(activation))
		position := bloc % 8
		sommeActivation := int(int16(binary.LittleEndian.Uint16(activation[260+(position*2)*2:]))) + int(int16(binary.LittleEndian.Uint16(activation[260+(position*2+1)*2:])))
		for ligne := 0; ligne < 4; ligne++ {
			var somme int
			for i := 0; i < 32; i++ {
				quant := enregistrement[16+ligne*16+i%16]
				if i >= 16 {
					quant >>= 4
				} else {
					quant &= 15
				}
				somme += int(quant) * int(int8(activation[4+position*32+i]))
			}
			echelle := math.Float32frombits(binary.LittleEndian.Uint32(enregistrement[ligne*4:]))
			sd := echelle * echelleActivation
			cumul[ligne] += sd * float32(somme-8*sommeActivation)
		}
	}
	copy(y, cumul[:])
}

// GEMVN4Q8KRange computes complete quadruplets in the half-open range.
func GEMVN4Q8KRange(y []float32, w []byte, q8k []byte, startQuad, endQuad, cols int) {
	pas := cols / 32 * 80
	for groupe := startQuad; groupe < endQuad; groupe++ {
		GEMV4N4Q8K(y[4*groupe:4*groupe+4], w[groupe*pas:(groupe+1)*pas], q8k, cols)
	}
}
