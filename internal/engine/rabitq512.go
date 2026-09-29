// Quantification 1-bit RaBitQ et évaluateur scalaire sans table pour vecteurs de
// dimension 512. Le fichier reprend la convention de horosvec (rabitq.go,
// rabitq_bitproduct.go) : le signe de la composante centrée occupe le bit (i%64)
// du mot i/64. Un vecteur de 512 dimensions tient donc dans huit mots de 64 bits,
// soit exactement les 64 premiers octets de Probe_event_t.Payload. Le centrage
// s'effectue sur l'origine : la signature imposée ne transporte pas de centroïde,
// donc la même origine zéro doit être retenue à l'encodage et à la requête.
package engine

import (
	"math"
	"math/bits"

	"code.hazyhaar.fr/goclassifier"
)

const (
	// rabitqDim512 est la dimension fixe traitée par ce noyau.
	rabitqDim512 = 512
	// rabitqWords512 est le nombre de mots de 64 bits d'un code de 512 bits.
	rabitqWords512 = rabitqDim512 / 64
	// rabitqBpBits512 est la largeur de quantification de la requête, en plans
	// de bits. La valeur cinq provient des mesures consignées dans
	// horosvec/rabitq_bitproduct.go : à quatre bits le rappel perd, à huit bits
	// l'évaluation devient plus lente que la table sans gagner en estimation.
	rabitqBpBits512 = 5
)

// QueryPlanes512 porte la requête centrée, quantifiée sur cinq bits et
// transposée en cinq plans de mots de 64 bits. La structure est à taille fixe :
// sa préparation ne réserve rien sur le tas et les tampons se réutilisent d'une
// requête à l'autre.
type QueryPlanes512 struct {
	Planes [rabitqBpBits512 * rabitqWords512]uint64
	VMin   float64
	Delta  float64
	SumQ   float64
}

// Encode512 encode le signe de chaque composante de vec, réputée centrée, dans
// un code de huit mots de 64 bits. La fonction rend la norme L2 au carré et la
// norme L1 de la composante centrée ; cette dernière est le facteur de
// correction asymétrique ⟨ō, o⟩ de RaBitQ. Le code est écrit en intégralité
// dans dstCode, les dimensions au-delà de 512 étant ignorées et les bits de
// remplissage laissés à zéro.
func Encode512(vec []float32, dstCode *[rabitqWords512]uint64) (sqNorm float64, l1Norm float64) {
	if dstCode == nil {
		return 0, 0
	}
	var code [rabitqWords512]uint64
	n := len(vec)
	if n > rabitqDim512 {
		n = rabitqDim512
	}
	for i := 0; i < n; i++ {
		c := float64(vec[i])
		sqNorm += c * c
		if c >= 0 {
			l1Norm += c
			code[i>>6] |= 1 << (uint(i) & 63)
		} else {
			l1Norm -= c
		}
	}
	*dstCode = code
	return sqNorm, l1Norm
}

// Quantize512 expose la quantification 1-bit RaBitQ d'un vecteur de dimension
// au plus 512 vers le bitcode de huit mots de 64 bits attendu par les entrées
// de codebook. La fonction rend la norme L2 au carré et la norme L1 du vecteur
// centré, facteurs de correction conservés par le format .c2book.
func Quantize512(vec []float32, dst *[codebookWords]uint64) (sqNorm float64, l1Norm float64) {
	return Encode512(vec, dst)
}

// QuantizeMeanCentered512 quantifie vec après soustraction de sa moyenne arithmétique,
// éliminant ainsi le biais du centrage à l'origine brut.
func QuantizeMeanCentered512(vec []float32, dst *[codebookWords]uint64) (sqNorm float64, l1Norm float64) {
	if dst == nil || len(vec) == 0 {
		return 0, 0
	}
	n := len(vec)
	if n > rabitqDim512 {
		n = rabitqDim512
	}
	var mean float64
	for i := 0; i < n; i++ {
		mean += float64(vec[i])
	}
	mean /= float64(n)

	var code [rabitqWords512]uint64
	for i := 0; i < n; i++ {
		c := float64(vec[i]) - mean
		sqNorm += c * c
		if c >= 0 {
			l1Norm += c
			code[i>>6] |= 1 << (uint(i) & 63)
		} else {
			l1Norm -= c
		}
	}
	*dst = code
	return sqNorm, l1Norm
}

// QuantizeFHT512 applique la projection orthonormée de Hadamard FHT512 et les motifs
// déterministes de Rademacher selon la convention canonique de goclassifier. QuantizeRabitq.
// Assure une cohérence métrique bit-à-bit parfaite entre c2blue55 et goclassifier.
func QuantizeFHT512(vec []float32, dst *[codebookWords]uint64) (sqNorm float64, l1Norm float64) {
	if dst == nil {
		return 0, 0
	}
	var proj [goclassifier.RabitqDim]float32
	goclassifier.ProjectRabitq(&proj, vec)
	code := goclassifier.QuantizeRabitq(&proj)
	for w := 0; w < codebookWords; w++ {
		dst[w] = code.Bits[w]
	}
	return float64(code.L2 * code.L2), float64(code.L1)
}

// prepareQueryPlanes quantifie la requête centrée sur 32 niveaux régulièrement
// espacés, puis transpose chaque bit de niveau en un plan de mots de 64 bits.
// La reconstruction exacte d'une composante est VMin + Delta·niveau ; la somme
// Σ q_i est précalculée dans SumQ. Un appel par requête, hors du chemin chaud.
func prepareQueryPlanes(queryCentered []float64, dst *QueryPlanes512) {
	if dst == nil {
		return
	}
	clear(dst.Planes[:])
	dst.VMin, dst.Delta, dst.SumQ = 0, 1, 0

	n := len(queryCentered)
	if n > rabitqDim512 {
		n = rabitqDim512
	}
	if n == 0 {
		return
	}

	vMin, vMax := queryCentered[0], queryCentered[0]
	var sumQ float64
	for i := 0; i < n; i++ {
		v := queryCentered[i]
		if v < vMin {
			vMin = v
		}
		if v > vMax {
			vMax = v
		}
		sumQ += v
	}

	levels := float64(int(1)<<rabitqBpBits512 - 1)
	delta := (vMax - vMin) / levels
	if delta == 0 {
		// Requête centrée constante : tous les niveaux valent zéro et le pas
		// devient arbitraire.
		delta = 1
	}
	dst.VMin, dst.Delta, dst.SumQ = vMin, delta, sumQ

	planes := &dst.Planes
	for i := 0; i < n; i++ {
		q := uint64(math.Round((queryCentered[i] - vMin) / delta))
		if q > uint64(levels) {
			q = uint64(levels)
		}
		w, bit := i>>6, uint(i)&63
		for k := 0; k < rabitqBpBits512; k++ {
			if (q>>uint(k))&1 == 1 {
				planes[k*rabitqWords512+w] |= 1 << bit
			}
		}
	}
}

// bitProductScalar rend Σ_k 2^k·popcount(code & plan_k), c'est-à-dire la somme
// pondérée des niveaux sélectionnés par le code, et le nombre de bits à un du
// code. Les cinq accumulateurs sont indépendants pour laisser le processeur
// enchaîner les comptages sans dépendance de données ; la boucle est déroulée
// par quatre mots, seul dégagement mesuré au sol (le déroulé complet n'apporte
// rien de plus).
func bitProductScalar(code *[rabitqWords512]uint64, qp *QueryPlanes512) (uint64, int) {
	p := &qp.Planes
	var a0, a1, a2, a3, a4, pc int
	for i := 0; i < rabitqWords512; i += 4 {
		c0, c1, c2, c3 := code[i], code[i+1], code[i+2], code[i+3]
		pc += bits.OnesCount64(c0) + bits.OnesCount64(c1) + bits.OnesCount64(c2) + bits.OnesCount64(c3)
		a0 += bits.OnesCount64(c0&p[i]) + bits.OnesCount64(c1&p[i+1]) + bits.OnesCount64(c2&p[i+2]) + bits.OnesCount64(c3&p[i+3])
		a1 += bits.OnesCount64(c0&p[rabitqWords512+i]) + bits.OnesCount64(c1&p[rabitqWords512+i+1]) + bits.OnesCount64(c2&p[rabitqWords512+i+2]) + bits.OnesCount64(c3&p[rabitqWords512+i+3])
		a2 += bits.OnesCount64(c0&p[2*rabitqWords512+i]) + bits.OnesCount64(c1&p[2*rabitqWords512+i+1]) + bits.OnesCount64(c2&p[2*rabitqWords512+i+2]) + bits.OnesCount64(c3&p[2*rabitqWords512+i+3])
		a3 += bits.OnesCount64(c0&p[3*rabitqWords512+i]) + bits.OnesCount64(c1&p[3*rabitqWords512+i+1]) + bits.OnesCount64(c2&p[3*rabitqWords512+i+2]) + bits.OnesCount64(c3&p[3*rabitqWords512+i+3])
		a4 += bits.OnesCount64(c0&p[4*rabitqWords512+i]) + bits.OnesCount64(c1&p[4*rabitqWords512+i+1]) + bits.OnesCount64(c2&p[4*rabitqWords512+i+2]) + bits.OnesCount64(c3&p[4*rabitqWords512+i+3])
	}
	acc := uint64(a0) + uint64(a1)<<1 + uint64(a2)<<2 + uint64(a3)<<3 + uint64(a4)<<4
	return acc, pc
}

// BitProductScalar évalue la distance carrée RaBitQ asymétrique entre la requête
// préparée et un code stocké, sans table de correspondance. La requête quantifiée
// reconstruit Σ b_i·q_i = VMin·popcount(code) + Delta·Σ2^k·popcount(code & plan_k),
// d'où Σ s_i·q_i = 2·Σ b_i·q_i − Σ q_i avec s_i = ±1 et b_i ∈ {0,1}. La distance
// reprend alors la formule de rabitqDistanceAsym :
//
//	dist² = querySqNorm + storedSqNorm − 2·storedSqNorm·signDot / storedL1Norm.
func BitProductScalar(qp *QueryPlanes512, querySqNorm float64, code *[rabitqWords512]uint64, storedSqNorm, storedL1Norm float64) float64 {
	if storedL1Norm == 0 {
		return storedSqNorm
	}
	if qp == nil || code == nil {
		return storedSqNorm
	}
	bp, pc := bitProductScalar(code, qp)
	sumSelected := qp.VMin*float64(pc) + qp.Delta*float64(bp)
	signDot := 2*sumSelected - qp.SumQ
	return querySqNorm + storedSqNorm - 2.0*storedSqNorm*signDot/storedL1Norm
}
