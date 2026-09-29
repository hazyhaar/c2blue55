// Extracteur de caractéristiques et projection 512D pour c2blue55.
//
// L'extracteur transforme un événement de 128 octets (Probe_event_t) ou sa
// seule charge utile de 96 octets en un vecteur flottant de 512 dimensions,
// écrit directement dans un tampon fourni par l'appelant. La projection
// combine quatre familles de mesures : n-grammes d'octets (unigrammes,
// bigrammes et trigrammes), entropie de Shannon locale sur fenêtres glissantes,
// distribution de classes de caractères, et métadonnées d'en-tête. Le vecteur
// est centré par soustraction d'un centroïde de référence déclaré à
// l'initialisation du paquet.
//
// Le chemin chaud n'alloue rien sur le tas : les histogrammes, les compteurs de
// classes et les accumulateurs résident dans des tableaux locaux, la sortie est
// écrite dans le slice de l'appelant, et aucune chaîne intermédiaire ni
// interface n'est construite.
package engine

import (
	"math"
	"math/bits"
)

// Dimensions et découpage du vecteur de projection. Les régions pavent
// exactement EmbeddingDim = 512 composantes.
const (
	// EmbeddingDim est la largeur fixe du vecteur de projection.
	EmbeddingDim = 512
	// FeaturePayloadBytes est la taille de la charge utile d'un événement.
	FeaturePayloadBytes = 96

	unigramBase = 0
	unigramDims = 256

	bigramBase = unigramBase + unigramDims
	bigramDims = 128

	trigramBase = bigramBase + bigramDims
	trigramDims = 64

	entropyBase = trigramBase + trigramDims
	entropyDims = 16

	classBase = entropyBase + entropyDims
	classDims = 12

	headerBase = classBase + classDims
	headerDims = 8

	aggregateBase = headerBase + headerDims
	aggregateDims = 28
)

// Assertion de compilation : les régions pavent exactement 512 dimensions.
var _ = [1]struct{}{}[EmbeddingDim-(aggregateBase+aggregateDims)]

// Indices des métadonnées d'en-tête.
const (
	hdrAction = iota
	hdrSubsystem
	hdrPIDFresh
	hdrPIDLow
	hdrFlagPopcount
	hdrSrcClass
	hdrSrcLow
	hdrPayloadUsed
	headerFeatureCount
)

// Indices des classes de caractères. Plusieurs classes se recouvrent : un
// octet hexadécimal minuscule alimente à la fois la classe hexadécimale, la
// classe des minuscules et, s'il s'agit d'une voyelle, la classe vocalique.
const (
	classVowel = iota
	classConsonant
	classUppercase
	classLowercase
	classDecimal
	classHexLetter
	classPunct
	classSpace
	classControl
	classHigh
	classPrintable
	classAlnum
	classFeatureCount
)

// Indices des agrégats statistiques et de la fusion d'en-tête.
const (
	aggEntropyMean = iota
	aggEntropyVar
	aggEntropyMin
	aggEntropyMax
	aggEntropyRange
	aggEntropyHostile
	aggDistinctRatio
	aggOccupancy
	aggBigramOccupancy
	aggTrigramOccupancy
	aggUnigramMax
	aggUsedRatio
	aggNulPos
	aggControlRatio
	aggPrintableRatio
	aggWhitespaceRatio
	aggUpperRatio
	aggLowerRatio
	aggDigitRatio
	aggHighRatio
	aggMaxRunRatio
	aggTransitionRatio
	aggMeanByte
	aggByteVar
	aggCollisionDensity
	aggBigramEntropy
	aggTrigramEntropy
	aggHeaderFusion
	aggregateFeatureCount
)

// entropyHostileBits est le seuil d'entropie locale, exprimé en bits par octet,
// au-delà duquel une fenêtre est comptée comme hostile.
const entropyHostileBits = 6.0

// Event est l'alias local de l'événement universel de 128 octets.
type Event = Probe_event_t

// FeatureExtractor projette un événement sur un vecteur de EmbeddingDim
// dimensions centré autour d'un centroïde. La structure est immuable après
// construction et chaque appel n'utilise que l'état local de sa pile, ce qui la
// rend sûre en concurrence sans verrou.
type FeatureExtractor struct {
	// Centroid est le vecteur de référence soustrait à chaque projection.
	Centroid [EmbeddingDim]float32
}

// NewFeatureExtractor construit un extracteur centré sur le centroïde de
// référence du paquet. Le centroïde est calculé une seule fois, à partir de
// constantes déclarées, et non sur des données observées.
func NewFeatureExtractor() FeatureExtractor {
	return FeatureExtractor{Centroid: referenceCentroid}
}

// referenceCentroid est le prior de centrage. Pour les canaux distributionnels,
// il vaut l'espérance sous une distribution d'octets uniforme : 1/256 pour les
// unigrammes, 1/128 pour les bigrammes, 1/64 pour les trigrammes, et 1 pour une
// entropie locale normalisée maximale. Les canaux d'en-tête et les agrégats
// sont centrés sur la référence neutre nulle.
var referenceCentroid = buildReferenceCentroid()

func buildReferenceCentroid() [EmbeddingDim]float32 {
	var c [EmbeddingDim]float32
	for i := 0; i < unigramDims; i++ {
		c[unigramBase+i] = 1.0 / float32(unigramDims)
	}
	for i := 0; i < bigramDims; i++ {
		c[bigramBase+i] = 1.0 / float32(bigramDims)
	}
	for i := 0; i < trigramDims; i++ {
		c[trigramBase+i] = 1.0 / float32(trigramDims)
	}
	for i := 0; i < entropyDims; i++ {
		c[entropyBase+i] = 1.0
	}
	c[classBase+classVowel] = 10.0 / 256.0
	c[classBase+classConsonant] = 42.0 / 256.0
	c[classBase+classUppercase] = 26.0 / 256.0
	c[classBase+classLowercase] = 26.0 / 256.0
	c[classBase+classDecimal] = 10.0 / 256.0
	c[classBase+classHexLetter] = 12.0 / 256.0
	c[classBase+classPunct] = 32.0 / 256.0
	c[classBase+classSpace] = 2.0 / 256.0
	c[classBase+classControl] = 33.0 / 256.0
	c[classBase+classHigh] = 128.0 / 256.0
	c[classBase+classPrintable] = 95.0 / 256.0
	c[classBase+classAlnum] = 62.0 / 256.0
	return c
}

// defaultExtractor est l'extracteur partagé des appels de paquet ExtractTo. Il
// est immuable après initialisation : le centroïde est une copie de la table de
// référence et aucun appel ne le mute, ce qui rend l'instance sûre en
// concurrence sans verrou.
var defaultExtractor = NewFeatureExtractor()

// ExtractTo projette un événement sur EmbeddingDim dimensions au moyen de
// l'extracteur partagé du paquet. C'est le point d'entrée de commodité pour les
// consommateurs qui n'ont pas à conserver leur propre extracteur ; il ne fait
// que déléguer à FeatureExtractor.ExtractTo et n'ajoute aucune allocation.
func ExtractTo(ev *Event, dst []float32) bool {
	return defaultExtractor.ExtractTo(ev, dst)
}

// ExtractTo écrit la projection de l'événement dans dst et retourne vrai en
// succès. Le tampon doit offrir au moins EmbeddingDim composantes ; une longueur
// insuffisante ou un événement nul est refusé sans écriture partielle. Une
// charge longue dont la page d'arène est recyclée, en cours d'écriture ou
// altérée est refusée : la projection d'un préfixe tronqué n'est jamais
// substituée à la charge réelle.
func (fe *FeatureExtractor) ExtractTo(ev *Event, dst []float32) bool {
	if ev == nil || len(dst) < EmbeddingDim {
		return false
	}
	if ev.Flags&FlagLongPayload == 0 {
		return fe.ExtractResolvedTo(ev, ev.Payload[:payloadUsed(ev.Payload[:])], dst)
	}
	var page [PageSize]byte
	payload, err := ResolvePayloadGlobal(ev, &page)
	if err != nil {
		return false
	}
	return fe.ExtractResolvedTo(ev, payload, dst)
}

// ExtractResolvedTo projette un événement dont la charge a déjà été résolue
// par l'appelant (ArenaPool.ResolvePayload). La cascade l'utilise pour ne
// résoudre la charge qu'une fois, et le rejeu forensique pour évaluer la
// charge scellée dans la preuve sans dépendre de l'état de l'arène.
func (fe *FeatureExtractor) ExtractResolvedTo(ev *Event, payload []byte, dst []float32) bool {
	if ev == nil || len(dst) < EmbeddingDim {
		return false
	}
	extractPayloadFeatures(payload, dst)
	fillEventHeader(ev, dst)
	fe.center(dst)
	return true
}

// ExtractPayloadTo projette la seule charge utile, sans en-tête. Les canaux
// d'en-tête restent à leur valeur neutre.
func (fe *FeatureExtractor) ExtractPayloadTo(payload []byte, dst []float32) bool {
	if len(dst) < EmbeddingDim {
		return false
	}
	extractPayloadFeatures(payload, dst)
	fe.center(dst)
	return true
}

// Extract retourne la projection par valeur, ce qui laisse le tampon sur la
// pile de l'appelant.
func (fe *FeatureExtractor) Extract(ev *Event) ([EmbeddingDim]float32, bool) {
	var out [EmbeddingDim]float32
	ok := fe.ExtractTo(ev, out[:])
	return out, ok
}

// center soustrait le centroïde de référence. Un extracteur nul est traité comme
// un centroïde nul, ce qui laisse la projection brute.
func (fe *FeatureExtractor) center(dst []float32) {
	if fe == nil {
		return
	}
	for i := 0; i < EmbeddingDim; i++ {
		dst[i] -= fe.Centroid[i]
	}
}

// extractPayloadFeatures remplit les régions distributionnelles et statistiques.
// Aucune allocation de tas : tous les états intermédiaires sont des tableaux
// locaux, et dst est remis à zéro sur ses 512 premières composantes.
func extractPayloadFeatures(data []byte, dst []float32) {
	clear(dst[:EmbeddingDim])

	used := payloadUsed(data)
	n := uint32(used)

	var hist [unigramDims]uint32
	var bigram [bigramDims]uint32
	var trigram [trigramDims]uint32
	var classes [classDims]uint32
	var window [256]uint32

	for i := 0; i < used; i++ {
		b := data[i]
		hist[b]++
		classifyByte(b, &classes)
	}
	for i := 0; i+1 < used; i++ {
		bigram[bigramBucket(data[i], data[i+1])]++
	}
	for i := 0; i+2 < used; i++ {
		trigram[trigramBucket(data[i], data[i+1], data[i+2])]++
	}

	if n > 0 {
		inv := 1.0 / float32(n)
		for i := 0; i < unigramDims; i++ {
			dst[unigramBase+i] = float32(hist[i]) * inv
		}
		for i := 0; i < classDims; i++ {
			dst[classBase+i] = float32(classes[i]) * inv
		}
	}
	if used >= 2 {
		inv := 1.0 / float32(used-1)
		for i := 0; i < bigramDims; i++ {
			dst[bigramBase+i] = float32(bigram[i]) * inv
		}
	}
	if used >= 3 {
		inv := 1.0 / float32(used-2)
		for i := 0; i < trigramDims; i++ {
			dst[trigramBase+i] = float32(trigram[i]) * inv
		}
	}

	var eSum, eSumSq float64
	eMin := 0.0
	eMax := 0.0
	hostile := 0
	if used > 0 {
		eMin = 8.0
		for w := 0; w < entropyDims; w++ {
			start := w * used / entropyDims
			end := (w + 1) * used / entropyDims
			if end > used {
				end = used
			}
			clear(window[:])
			total := uint32(0)
			for i := start; i < end; i++ {
				window[data[i]]++
				total++
			}
			bitsPerByte := 0.0
			if total > 1 {
				bitsPerByte = shannonBits(window[:], total)
			}
			dst[entropyBase+w] = float32(bitsPerByte / 8.0)
			eSum += bitsPerByte
			eSumSq += bitsPerByte * bitsPerByte
			if bitsPerByte < eMin {
				eMin = bitsPerByte
			}
			if bitsPerByte > eMax {
				eMax = bitsPerByte
			}
			if bitsPerByte >= entropyHostileBits {
				hostile++
			}
		}
	}
	eMean := eSum / float64(entropyDims)
	eVar := eSumSq/float64(entropyDims) - eMean*eMean
	if eVar < 0 {
		eVar = 0
	}

	distinct := 0
	maxHist := uint32(0)
	var sumHistSq uint64
	for i := 0; i < unigramDims; i++ {
		c := hist[i]
		if c > 0 {
			distinct++
			sumHistSq += uint64(c) * uint64(c)
		}
		if c > maxHist {
			maxHist = c
		}
	}
	nonzeroBigram := 0
	for i := 0; i < bigramDims; i++ {
		if bigram[i] > 0 {
			nonzeroBigram++
		}
	}
	nonzeroTrigram := 0
	for i := 0; i < trigramDims; i++ {
		if trigram[i] > 0 {
			nonzeroTrigram++
		}
	}

	var sumBytes uint64
	for i := 0; i < used; i++ {
		sumBytes += uint64(data[i])
	}
	meanByte := 0.0
	byteVar := 0.0
	if n > 0 {
		meanByte = float64(sumBytes) / float64(n)
		var sq float64
		for i := 0; i < used; i++ {
			d := float64(data[i]) - meanByte
			sq += d * d
		}
		byteVar = sq / float64(n)
	}

	maxRun := 0
	run := 0
	transitions := 0
	for i := 0; i < used; i++ {
		if i > 0 && data[i] == data[i-1] {
			run++
		} else {
			run = 1
			if i > 0 {
				transitions++
			}
		}
		if run > maxRun {
			maxRun = run
		}
	}

	invN := 0.0
	if n > 0 {
		invN = 1.0 / float64(n)
	}

	b := aggregateBase
	dst[b+aggEntropyMean] = float32(eMean / 8.0)
	dst[b+aggEntropyVar] = float32(eVar / 64.0)
	dst[b+aggEntropyMin] = float32(eMin / 8.0)
	dst[b+aggEntropyMax] = float32(eMax / 8.0)
	dst[b+aggEntropyRange] = float32((eMax - eMin) / 8.0)
	dst[b+aggEntropyHostile] = float32(hostile) / float32(entropyDims)
	dst[b+aggDistinctRatio] = float32(distinct) / 256.0
	dst[b+aggOccupancy] = float32(float64(distinct) * invN)
	dst[b+aggBigramOccupancy] = float32(nonzeroBigram) / float32(bigramDims)
	dst[b+aggTrigramOccupancy] = float32(nonzeroTrigram) / float32(trigramDims)
	dst[b+aggUnigramMax] = float32(float64(maxHist) * invN)
	dst[b+aggUsedRatio] = float32(used) / float32(FeaturePayloadBytes)
	dst[b+aggNulPos] = float32(used) / float32(FeaturePayloadBytes)
	dst[b+aggControlRatio] = float32(float64(classes[classControl]) * invN)
	dst[b+aggPrintableRatio] = float32(float64(classes[classPrintable]) * invN)
	dst[b+aggWhitespaceRatio] = float32(float64(classes[classSpace]) * invN)
	dst[b+aggUpperRatio] = float32(float64(classes[classUppercase]) * invN)
	dst[b+aggLowerRatio] = float32(float64(classes[classLowercase]) * invN)
	dst[b+aggDigitRatio] = float32(float64(classes[classDecimal]) * invN)
	dst[b+aggHighRatio] = float32(float64(classes[classHigh]) * invN)
	dst[b+aggMaxRunRatio] = float32(float64(maxRun) * invN)
	dst[b+aggTransitionRatio] = float32(float64(transitions) * invN)
	dst[b+aggMeanByte] = float32(meanByte / 255.0)
	dst[b+aggByteVar] = float32(byteVar / (255.0 * 255.0))
	dst[b+aggCollisionDensity] = float32(float64(sumHistSq) * invN * invN)
	bigramEntropy := 0.0
	if used >= 2 {
		bigramEntropy = shannonBits(bigram[:], uint32(used-1)) / 7.0
	}
	trigramEntropy := 0.0
	if used >= 3 {
		trigramEntropy = shannonBits(trigram[:], uint32(used-2)) / 6.0
	}
	dst[b+aggBigramEntropy] = float32(bigramEntropy)
	dst[b+aggTrigramEntropy] = float32(trigramEntropy)
	dst[headerBase+hdrPayloadUsed] = float32(used) / float32(FeaturePayloadBytes)
}

// fillEventHeader projette les métadonnées d'en-tête et la fusion action ×
// sous-système.
func fillEventHeader(ev *Event, dst []float32) {
	h := headerBase
	dst[h+hdrAction] = float32(ev.Action) / 65535.0
	dst[h+hdrSubsystem] = float32(ev.Subsystem) / 65535.0
	if ev.Pid != 0 {
		dst[h+hdrPIDFresh] = 1
	}
	dst[h+hdrPIDLow] = float32(ev.Pid&0xFF) / 255.0
	dst[h+hdrFlagPopcount] = float32(bits.OnesCount32(ev.Flags)) / 32.0
	srcClass := float32(ev.Src >> 32)
	if srcClass > 8 {
		srcClass = 8
	}
	dst[h+hdrSrcClass] = srcClass / 8.0
	dst[h+hdrSrcLow] = float32(uint32(ev.Src)) / 4294967295.0
	dst[aggregateBase+aggHeaderFusion] = (float32(ev.Action) / 65535.0) * (float32(ev.Subsystem) / 65535.0)
}

// payloadUsed retourne l'index du premier octet NUL, ou la longueur bornée à 96
// lorsqu'aucun terminateur n'est présent. Cette convention de troncature est
// celle déjà appliquée par l'évaluateur de règles.
func payloadUsed(data []byte) int {
	end := len(data)
	if end > FeaturePayloadBytes {
		end = FeaturePayloadBytes
	}
	for i := 0; i < end; i++ {
		if data[i] == 0 {
			return i
		}
	}
	return end
}

// bigramBucket projette un bigramme sur l'un des 128 seaux.
func bigramBucket(a, b byte) int {
	return int((uint32(a)<<1 ^ uint32(b)) & uint32(bigramDims-1))
}

// trigramBucket projette un trigramme sur l'un des 64 seaux.
func trigramBucket(a, b, c byte) int {
	h := uint32(a)*0x9E3779B1 ^ uint32(b)*0x85EBCA77 ^ uint32(c)*0xC2B2AE3D
	return int(h & uint32(trigramDims-1))
}

// shannonBits calcule l'entropie de Shannon d'une distribution de comptages, en
// bits par symbole. total est le nombre d'observations.
func shannonBits(counts []uint32, total uint32) float64 {
	if total <= 1 {
		return 0
	}
	inv := 1.0 / float64(total)
	h := 0.0
	for i := 0; i < len(counts); i++ {
		c := counts[i]
		if c == 0 {
			continue
		}
		p := float64(c) * inv
		h -= p * math.Log2(p)
	}
	if h < 0 {
		h = 0
	}
	return h
}

// classifyByte incrémente les classes de caractères auxquelles l'octet
// appartient. Les classes se recouvrent volontairement.
func classifyByte(b byte, classes *[classDims]uint32) {
	if isVowelLetter(b) {
		classes[classVowel]++
	} else if isASCIILetter(b) {
		classes[classConsonant]++
	}
	if b >= 'A' && b <= 'Z' {
		classes[classUppercase]++
	}
	if b >= 'a' && b <= 'z' {
		classes[classLowercase]++
	}
	if isASCIIDigit(b) {
		classes[classDecimal]++
	}
	if isHexLetter(b) {
		classes[classHexLetter]++
	}
	if isASCIIPunct(b) {
		classes[classPunct]++
	}
	if isASCIISpace(b) {
		classes[classSpace]++
	}
	if isASCIIControl(b) {
		classes[classControl]++
	}
	if b >= 0x80 {
		classes[classHigh]++
	}
	if isASCIIPrintable(b) {
		classes[classPrintable]++
	}
	if isASCIILetter(b) || isASCIIDigit(b) {
		classes[classAlnum]++
	}
}

func isASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isASCIIDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func isHexLetter(b byte) bool {
	return (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

func isVowelLetter(b byte) bool {
	switch b {
	case 'a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U':
		return true
	}
	return false
}

func isASCIIPunct(b byte) bool {
	return b >= 0x21 && b <= 0x7E && !isASCIILetter(b) && !isASCIIDigit(b)
}

func isASCIISpace(b byte) bool {
	return b == ' ' || b == '\t'
}

func isASCIIControl(b byte) bool {
	return b < 0x20 || b == 0x7F
}

func isASCIIPrintable(b byte) bool {
	return b >= 0x20 && b <= 0x7E
}
