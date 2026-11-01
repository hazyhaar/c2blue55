package tensor

import (
	"encoding/binary"
	"fmt"
	"math"
)

// N5Size donne la taille des enregistrements de quatre lignes et 32 colonnes.
func N5Size(rows, cols int) int {
	return rows / 4 * (cols / 32) * 96
}

// QuantizeRowsN5 encode les poids suivant la règle Q5_0.
func QuantizeRowsN5(poids []float32, rows, cols int, sortie []byte) error {
	if rows <= 0 || cols <= 0 || rows%4 != 0 || cols%256 != 0 || rows > int(^uint(0)>>1)/cols || len(poids) != rows*cols || len(sortie) != N5Size(rows, cols) {
		return fmt.Errorf("N5: dimensions ou tailles incohérentes: %d x %d", rows, cols)
	}
	for groupe := 0; groupe < rows/4; groupe++ {
		for bloc := 0; bloc < cols/32; bloc++ {
			enregistrement := sortie[(groupe*cols/32+bloc)*96:]
			for ligne := 0; ligne < 4; ligne++ {
				valeurs := poids[(groupe*4+ligne)*cols+bloc*32:]
				var maximum, signe float32
				for i := 0; i < 32; i++ {
					if valeur := float32(math.Abs(float64(valeurs[i]))); valeur > maximum {
						maximum, signe = valeur, valeurs[i]
					}
				}
				echelle := float32(0)
				inverse := float32(0)
				if maximum != 0 {
					echelle = signe / -16
					inverse = 1 / echelle
				}
				binary.LittleEndian.PutUint32(enregistrement[ligne*4:], math.Float32bits(echelle))
				var bitsHauts uint32
				for i := 0; i < 32; i++ {
					quant := int(valeurs[i]*inverse + 16.5)
					if quant < 0 {
						quant = 0
					}
					if quant > 31 {
						quant = 31
					}
					if i < 16 {
						enregistrement[16+ligne*16+i] = byte(quant & 15)
					} else {
						enregistrement[16+ligne*16+i-16] |= byte((quant & 15) << 4)
					}
					bitsHauts |= uint32(quant>>4) << i
				}
				binary.LittleEndian.PutUint32(enregistrement[80+ligne*4:], bitsHauts)
			}
		}
	}
	return nil
}

// DequantizeN5 reconstruit les quatre lignes de chaque enregistrement.
func DequantizeN5(entree []byte, rows, cols int, sortie []float32) {
	for groupe := 0; groupe < rows/4; groupe++ {
		for bloc := 0; bloc < cols/32; bloc++ {
			enregistrement := entree[(groupe*cols/32+bloc)*96:]
			for ligne := 0; ligne < 4; ligne++ {
				echelle := math.Float32frombits(binary.LittleEndian.Uint32(enregistrement[ligne*4:]))
				bitsHauts := binary.LittleEndian.Uint32(enregistrement[80+ligne*4:])
				valeurs := sortie[(groupe*4+ligne)*cols+bloc*32:]
				for i := 0; i < 16; i++ {
					quant := enregistrement[16+ligne*16+i]
					valeurs[i] = echelle * float32(int(quant&15|byte((bitsHauts>>i&1)<<4))-16)
					valeurs[i+16] = echelle * float32(int(quant>>4|byte((bitsHauts>>(i+16)&1)<<4))-16)
				}
			}
		}
	}
}

// GEMV4N5Q8K calcule quatre produits scalaires dans l'ordre des blocs.
func GEMV4N5Q8K(sortie []float32, poids []byte, activation []byte, cols int) {
	gemv4N5Q8K(sortie, poids, activation, cols)
}

// GEMV4N5Q8KReference applique le contrat scalaire du produit N5 × Q8_K.
func GEMV4N5Q8KReference(sortie []float32, poids []byte, q8k []byte, cols int) {
	var cumul [4]float32
	for bloc := 0; bloc < cols/32; bloc++ {
		enregistrement := poids[bloc*96:]
		activation := q8k[(bloc/8)*BlockSizeQ8_K:]
		echelleActivation := math.Float32frombits(binary.LittleEndian.Uint32(activation))
		position := bloc % 8
		sommeActivation := int(int16(binary.LittleEndian.Uint16(activation[260+position*4:]))) + int(int16(binary.LittleEndian.Uint16(activation[262+position*4:])))
		for ligne := 0; ligne < 4; ligne++ {
			bitsHauts := binary.LittleEndian.Uint32(enregistrement[80+ligne*4:])
			var somme int
			for i := 0; i < 32; i++ {
				quant := enregistrement[16+ligne*16+i%16]
				if i >= 16 {
					quant >>= 4
				} else {
					quant &= 15
				}
				quant |= byte((bitsHauts >> i & 1) << 4)
				somme += int(quant) * int(int8(activation[4+position*32+i]))
			}
			echelle := math.Float32frombits(binary.LittleEndian.Uint32(enregistrement[ligne*4:]))
			sd := echelle * echelleActivation
			cumul[ligne] += sd * float32(somme-16*sommeActivation)
		}
	}
	copy(sortie, cumul[:])
}

// GEMVN5Q8KRange calcule les quadruplets de l'intervalle semi-ouvert.
func GEMVN5Q8KRange(sortie []float32, poids []byte, activation []byte, debut, fin, cols int) {
	pas := cols / 32 * 96
	for groupe := debut; groupe < fin; groupe++ {
		GEMV4N5Q8K(sortie[4*groupe:4*groupe+4], poids[groupe*pas:(groupe+1)*pas], activation, cols)
	}
}
