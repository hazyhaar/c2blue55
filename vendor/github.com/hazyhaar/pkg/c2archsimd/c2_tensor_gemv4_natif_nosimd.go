//go:build !(goexperiment.simd && amd64)

package c2archsimd

import (
	"encoding/binary"
	"math"
)

// Replis scalaires des feuilles assembleur gemv4 N4 et N5 (format natif c2slm,
// /devhoros/c2slm/spec/n4-format-v1.md §3 et §7) : une feuille gcc n'a pas de
// repli émis ; ces deux fonctions suivent le contrat d'accumulation mot pour
// mot (S et A entiers, sd = scale × d en float32, acc += sd × float32(S − k×A),
// blocs croissants) et sont bit-exactes avec les feuilles.

func gemv4NatifScalaire(y []float32, w []byte, q8k []byte, cols int32, bits int) {
	taille := 80
	decalage := 8
	if bits == 5 {
		taille = 96
		decalage = 16
	}
	var cumul [4]float32
	for bloc := 0; bloc < int(cols)/32; bloc++ {
		enregistrement := w[bloc*taille:]
		activation := q8k[(bloc/8)*292:]
		echelleActivation := math.Float32frombits(binary.LittleEndian.Uint32(activation))
		position := bloc % 8
		sommeActivation := int(int16(binary.LittleEndian.Uint16(activation[260+(position*2)*2:]))) + int(int16(binary.LittleEndian.Uint16(activation[260+(position*2+1)*2:])))
		for ligne := 0; ligne < 4; ligne++ {
			var hauts uint32
			if bits == 5 {
				hauts = binary.LittleEndian.Uint32(enregistrement[80+ligne*4:])
			}
			var somme int
			for i := 0; i < 32; i++ {
				quant := int(enregistrement[16+ligne*16+i%16])
				if i >= 16 {
					quant >>= 4
				} else {
					quant &= 15
				}
				if bits == 5 {
					quant |= int((hauts>>uint(i))&1) << 4
				}
				somme += quant * int(int8(activation[4+position*32+i]))
			}
			echelle := math.Float32frombits(binary.LittleEndian.Uint32(enregistrement[ligne*4:]))
			sd := echelle * echelleActivation
			cumul[ligne] += sd * float32(somme-decalage*sommeActivation)
		}
	}
	copy(y, cumul[:])
}

// C2_tensor_gemv4_n4_q8_k est le repli scalaire de la feuille N4.
func C2_tensor_gemv4_n4_q8_k(w4 []byte, q8k []byte, cols int32, out4 []float32) {
	gemv4NatifScalaire(out4, w4, q8k, cols, 4)
}

// C2_tensor_gemv4_n5_q8_k est le repli scalaire de la feuille N5.
func C2_tensor_gemv4_n5_q8_k(w5 []byte, q8k []byte, cols int32, out4 []float32) {
	gemv4NatifScalaire(out4, w5, q8k, cols, 5)
}
