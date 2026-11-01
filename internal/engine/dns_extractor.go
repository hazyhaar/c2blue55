// Package engine — dns_extractor.go
// Extracteurs 512D spécialisés pour l'agent DNS (#24) :
//   - ExtractDNSTunnel512 : projection 512D de la tranche Subdomain strictement
//     aveugle au domaine parent, enrichie par la cardinalité temporelle ;
//   - ExtractDNSDGA512 : projection 512D du label enregistrable (SLD) pour la
//     détection des domaines générés algorithmiquement (DGA) sur domaine apex.
package engine

import "math"

// ExtractDNSTunnel512 projette uniquement la charge de sous-domaine (sub), les
// métadonnées structurelles (qtype, labelCount, maxLabelLen) et la cardinalité
// temporelle (subCardinality) dans dst (512 float32), sans jamais lire le nom
// du domaine parent. Retourne faux si dst < 512 ou si sub est vide.
func ExtractDNSTunnel512(sub []byte, qtype uint16, labelCount, maxLabelLen uint8, subCardinality uint32, dst []float32) bool {
	used := len(sub)
	if used == 0 || len(dst) < EmbeddingDim {
		return false
	}
	clear(dst[:EmbeddingDim])

	var hist [256]uint32
	var bigram [128]uint32
	var trigram [64]uint32
	var window [256]uint32

	var vowels, consonants, digits, hexChars, dots, hyphens, encChars, rareCons int
	var subLabels int = 1
	var curLabelLen, subMaxLabel, firstLabelLen int
	var curDigits, curLetters, curHex int
	var numericLabels, mixedAlnumLabels, hexLabels, singleCharLabels, longLabels int
	var letterDigitTrans, hostileConsBigrams, lexicalBigrams int
	var nonVowelRun, maxNonVowelRun int
	var digitRun, maxDigitRun int
	var hasTunnelWord bool

	labelStart := 0
	for i := range used {
		b := sub[i]
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		hist[b]++

		if b == '.' {
			lLen := i - labelStart
			if subLabels == 1 {
				firstLabelLen = lLen
			}
			if lLen > subMaxLabel {
				subMaxLabel = lLen
			}
			if lLen == 1 {
				singleCharLabels++
			}
			if lLen >= 16 {
				longLabels++
			}
			if lLen > 0 && curDigits == lLen {
				numericLabels++
			} else if curDigits > 0 && curLetters > 0 {
				mixedAlnumLabels++
			}
			if lLen >= 8 && curHex == lLen {
				hexLabels++
			}
			if lLen == 6 && matchLowerTunnel(sub[labelStart:i]) {
				hasTunnelWord = true
			}
			subLabels++
			dots++
			curLabelLen = 0
			curDigits = 0
			curLetters = 0
			curHex = 0
			nonVowelRun = 0
			digitRun = 0
			labelStart = i + 1
			continue
		}

		curLabelLen++
		isV := isVowelLetter(b)
		isL := b >= 'a' && b <= 'z'
		isD := b >= '0' && b <= '9'

		if isV {
			vowels++
			curLetters++
			nonVowelRun = 0
			digitRun = 0
		} else if isL {
			consonants++
			curLetters++
			nonVowelRun++
			if nonVowelRun > maxNonVowelRun {
				maxNonVowelRun = nonVowelRun
			}
			digitRun = 0
			if isRareConsonant(b) {
				rareCons++
			}
		} else if isD {
			digits++
			curDigits++
			nonVowelRun++
			if nonVowelRun > maxNonVowelRun {
				maxNonVowelRun = nonVowelRun
			}
			digitRun++
			if digitRun > maxDigitRun {
				maxDigitRun = digitRun
			}
		} else if b == '-' || b == '_' {
			hyphens++
			nonVowelRun = 0
			digitRun = 0
		} else if b == '+' || b == '/' || b == '=' {
			encChars++
			nonVowelRun++
			if nonVowelRun > maxNonVowelRun {
				maxNonVowelRun = nonVowelRun
			}
		}

		if isD || (b >= 'a' && b <= 'f') {
			hexChars++
			curHex++
		}

		if i > labelStart {
			prev := sub[i-1]
			if prev >= 'A' && prev <= 'Z' {
				prev += 32
			}
			prevL := prev >= 'a' && prev <= 'z'
			prevD := prev >= '0' && prev <= '9'
			if (prevL && isD) || (prevD && isL) {
				letterDigitTrans++
			}
			if prevL && isL {
				if isCommonLexicalBigram(prev, b) {
					lexicalBigrams++
				} else if !isVowelLetter(prev) && !isV && !isPronounceableConsonantPair(prev, b) {
					hostileConsBigrams++
				}
			}
		}

		if i+1 < used {
			nb := sub[i+1]
			if nb >= 'A' && nb <= 'Z' {
				nb += 32
			}
			bigram[bigramBucket(b, nb)]++
		}
		if i+2 < used {
			b1 := sub[i+1]
			if b1 >= 'A' && b1 <= 'Z' {
				b1 += 32
			}
			b2 := sub[i+2]
			if b2 >= 'A' && b2 <= 'Z' {
				b2 += 32
			}
			trigram[trigramBucket(b, b1, b2)]++
		}
	}

	// Clôture du dernier label de sub
	lastLen := used - labelStart
	if subLabels == 1 {
		firstLabelLen = lastLen
	}
	if lastLen > subMaxLabel {
		subMaxLabel = lastLen
	}
	if lastLen == 1 {
		singleCharLabels++
	}
	if lastLen >= 16 {
		longLabels++
	}
	if lastLen > 0 && curDigits == lastLen {
		numericLabels++
	} else if curDigits > 0 && curLetters > 0 {
		mixedAlnumLabels++
	}
	if lastLen >= 8 && curHex == lastLen {
		hexLabels++
	}
	if lastLen == 6 && matchLowerTunnel(sub[labelStart:used]) {
		hasTunnelWord = true
	}

	invUsed := 1.0 / float32(used)
	globalEntropy := float32(shannonBits(hist[:], uint32(used)) / 5.0)

	// Entropie locale sur 16 fenêtres
	var winEnt [16]float32
	var eSum, eMax float32
	for w := range 16 {
		start := w * used / 16
		end := min((w+1)*used/16, used)
		if end <= start {
			start = 0
			end = used
		}
		clear(window[:])
		total := uint32(0)
		for i := start; i < end; i++ {
			b := sub[i]
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			window[b]++
			total++
		}
		eb := float32(shannonBits(window[:], total) / 5.0)
		winEnt[w] = eb
		eSum += eb
		if eb > eMax {
			eMax = eb
		}
	}
	eMean := eSum / 16.0

	alphaCount := float32(max(vowels+consonants, 1))
	vowelRatio := float32(vowels) / alphaCount
	digitRatio := float32(digits) * invUsed
	hexRatio := float32(hexChars) * invUsed
	rareRatio := float32(rareCons) / alphaCount
	transRatio := float32(letterDigitTrans) * invUsed
	hostileBgRatio := float32(hostileConsBigrams) / alphaCount
	lexBgRatio := float32(lexicalBigrams) / alphaCount

	cardLog := float32(math.Min(math.Log2(float64(max(subCardinality, 1)))/5.0, 1.0))
	cardLin := float32(min(subCardinality, 48)) / 48.0
	isTunnelQType := float32(-0.65)
	if qtype == 10 || qtype == 16 || qtype == 5 || qtype == 255 {
		isTunnelQType = 0.85
	}
	tunnelWordFeat := float32(-0.45)
	if hasTunnelWord {
		tunnelWordFeat = 0.90
	}
	commonSubBenign := isCommonBenignSubdomain(sub[:min(firstLabelLen, used)])
	benignSubFeat := float32(0.35)
	if commonSubBenign && subLabels == 1 && subCardinality <= 4 {
		benignSubFeat = -0.90
	} else if commonSubBenign && subCardinality <= 2 {
		benignSubFeat = -0.75
	}

	// Détection combinée des sondes de polling de tunnel (ex: r51646.tunnel, a.56178.tunnel, q+Z8AnwaBA)
	isPollingBeacon := float32(-0.65)
	if (subCardinality >= 6 && (mixedAlnumLabels > 0 || numericLabels > 0 || hasTunnelWord || isTunnelQType > 0)) ||
		(hasTunnelWord && (mixedAlnumLabels > 0 || numericLabels > 0 || longLabels > 0)) ||
		(longLabels > 0 && subLabels >= 2) {
		isPollingBeacon = 0.92
	}

	var feats [32]float32
	feats[0] = clampSym((float32(used) - 9.0) / 25.0)
	feats[1] = clampSym((float32(subMaxLabel) - 10.0) / 16.0)
	feats[2] = clampSym((float32(firstLabelLen) - 8.0) / 14.0)
	feats[3] = clampSym((float32(subLabels) - 1.3) / 1.2)
	feats[4] = clampSym((globalEntropy - 0.54) * 2.5)
	feats[5] = clampSym((eMax - 0.52) * 2.4)
	feats[6] = clampSym((eMean - 0.42) * 2.4)
	feats[7] = clampSym(digitRatio*3.8 - 0.35)
	feats[8] = clampSym(transRatio*6.5 - 0.30)
	feats[9] = clampSym(float32(mixedAlnumLabels)*0.95 - 0.45)
	feats[10] = clampSym(float32(numericLabels)*0.90 - 0.45)
	feats[11] = clampSym(float32(singleCharLabels)*0.75 - 0.40)
	feats[12] = clampSym(float32(longLabels)*0.95 - 0.45)
	feats[13] = clampSym(float32(hexLabels)*0.95 - 0.45)
	feats[14] = clampSym((float32(maxNonVowelRun) - 3.2) / 4.0)
	feats[15] = clampSym((float32(maxDigitRun) - 1.5) / 2.5)
	feats[16] = clampSym((0.35 - vowelRatio) * 2.8)
	feats[17] = clampSym(rareRatio*4.0 - 0.35)
	feats[18] = clampSym(hostileBgRatio*3.8 - 0.35)
	feats[19] = clampSym((0.28 - lexBgRatio) * 2.5)
	feats[20] = clampSym(cardLog*1.8 - 0.65)
	feats[21] = clampSym(cardLin*1.8 - 0.65)
	feats[22] = isTunnelQType
	feats[23] = tunnelWordFeat
	feats[24] = benignSubFeat
	feats[25] = clampSym((float32(labelCount) - 3.2) / 2.0)
	feats[26] = clampSym((float32(maxLabelLen) - 15.0) / 20.0)
	feats[27] = clampSym(float32(encChars)*1.2 - 0.35)
	feats[28] = clampSym(hexRatio*2.0 - 0.80)
	feats[29] = clampSym(float32(dots)*0.65 - 0.40)
	feats[30] = isPollingBeacon

	var sumFeats float32
	for i := range 31 {
		sumFeats += feats[i]
	}
	if isPollingBeacon > 0 {
		sumFeats += 4.5
	}
	feats[31] = clampSym(sumFeats / 12.0)

	for b := range 32 {
		base := b * 8
		f := feats[b]
		for k := range 8 {
			alt := feats[(b+k*3+1)&31]
			dst[base+k] = 0.60*f + 0.25*alt + 0.15*feats[31]
		}
	}

	for i := range 256 {
		if hist[i] > 0 {
			slot := (i*7 + 3) & 255
			dst[slot] += float32(hist[i]) * invUsed * 0.45
		}
	}

	invBg := float32(0)
	if used >= 2 {
		invBg = 1.0 / float32(used-1)
	}
	for i := range 128 {
		f := feats[i&31]
		bg := float32(bigram[i])*invBg*4.0 - (4.0 / 128.0)
		dst[bigramBase+i] = 0.65*f + 0.20*feats[31] + 0.15*bg
	}

	invTg := float32(0)
	if used >= 3 {
		invTg = 1.0 / float32(used-2)
	}
	for i := range 64 {
		f := feats[i&31]
		tg := float32(trigram[i])*invTg*4.0 - (4.0 / 64.0)
		dst[trigramBase+i] = 0.65*f + 0.20*feats[31] + 0.15*tg
	}

	for w := range 16 {
		dst[entropyBase+w] = clampSym((winEnt[w]-0.48)*1.8 + 0.45*feats[31])
	}

	for c := range 12 {
		dst[classBase+c] = feats[c+7]
	}

	dst[headerBase+0] = float32(qtype) / 255.0
	dst[headerBase+1] = isTunnelQType
	dst[headerBase+2] = float32(labelCount) / 16.0
	dst[headerBase+3] = float32(maxLabelLen) / 63.0
	dst[headerBase+4] = float32(min(used, 253)) / 253.0
	dst[headerBase+5] = float32(min(subMaxLabel, 63)) / 63.0
	dst[headerBase+6] = cardLog
	dst[headerBase+7] = float32(math.Log1p(float64(subCardinality)) / 10.0)

	for a := range 28 {
		dst[aggregateBase+a] = feats[a+4]
	}

	return true
}

// ExtractDNSDGA512 projette le label enregistrable de second niveau (sld) et
// son suffixe public (tld) dans dst (512 float32) pour discriminer les domaines
// apex générés algorithmiquement (DGA) des domaines normaux.
func ExtractDNSDGA512(sld []byte, tld []byte, dst []float32) bool {
	n := len(sld)
	if n == 0 || len(dst) < EmbeddingDim {
		return false
	}
	clear(dst[:EmbeddingDim])

	var hist [256]uint32
	var bigram [128]uint32
	var trigram [64]uint32
	var window [256]uint32

	var vowels, consonants, digits, hexChars, hyphens, rareCons, veryRareCons, frequentCons int
	var consRun, maxConsRun int
	var vowelRun, maxVowelRun int
	var digitRun, maxDigitRun int
	var nonVowelRun, maxNonVowelRun int
	var letterDigitTrans, qWithoutU, actualAlphaPairs int
	var commonLexBg, pronounceableBg, hostileConsBg, rareConsBg, doubleConsBg, awkwardVowelBg int
	var vowelConsAlt int

	for i := range n {
		b := sld[i]
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		hist[b]++

		isV := isVowelLetter(b)
		isL := b >= 'a' && b <= 'z'
		isD := b >= '0' && b <= '9'

		if b == 'q' {
			nextIsU := false
			if i+1 < n {
				nb := sld[i+1]
				if nb == 'u' || nb == 'U' {
					nextIsU = true
				}
			}
			if !nextIsU {
				qWithoutU++
			}
		}

		if isV {
			vowels++
			vowelRun++
			if vowelRun > maxVowelRun {
				maxVowelRun = vowelRun
			}
			consRun = 0
			digitRun = 0
			nonVowelRun = 0
		} else if isL {
			consonants++
			vowelRun = 0
			consRun++
			if consRun > maxConsRun {
				maxConsRun = consRun
			}
			nonVowelRun++
			if nonVowelRun > maxNonVowelRun {
				maxNonVowelRun = nonVowelRun
			}
			digitRun = 0
			if isRareConsonant(b) {
				rareCons++
			}
			if b == 'q' || b == 'x' || b == 'z' || b == 'j' {
				veryRareCons++
			}
			if b == 't' || b == 'n' || b == 'r' || b == 'l' || b == 'd' {
				frequentCons++
			}
		} else if isD {
			digits++
			vowelRun = 0
			consRun = 0
			digitRun++
			if digitRun > maxDigitRun {
				maxDigitRun = digitRun
			}
			nonVowelRun++
			if nonVowelRun > maxNonVowelRun {
				maxNonVowelRun = nonVowelRun
			}
		} else if b == '-' || b == '_' {
			hyphens++
			vowelRun = 0
			consRun = 0
			digitRun = 0
			nonVowelRun = 0
		}

		if isD || (b >= 'a' && b <= 'f') {
			hexChars++
		}

		if i > 0 {
			prev := sld[i-1]
			if prev >= 'A' && prev <= 'Z' {
				prev += 32
			}
			prevV := isVowelLetter(prev)
			prevL := prev >= 'a' && prev <= 'z'
			prevD := prev >= '0' && prev <= '9'

			if (prevL && isD) || (prevD && isL) {
				letterDigitTrans++
			}
			if (prevV && isL && !isV) || (prevL && !prevV && isV) {
				vowelConsAlt++
			}
			if prevL && isL {
				actualAlphaPairs++
				if isCommonLexicalBigram(prev, b) {
					commonLexBg++
				}
				if prevV && isV {
					if isAwkwardVowelPair(prev, b) {
						awkwardVowelBg++
					} else {
						pronounceableBg++
					}
				} else if prevV || isV {
					pronounceableBg++
				} else if isPronounceableConsonantPair(prev, b) {
					pronounceableBg++
				} else {
					hostileConsBg++
					if isRareConsonant(prev) || isRareConsonant(b) {
						rareConsBg++
					}
				}
				if !prevV && !isV && prev == b && b != 'l' && b != 's' && b != 'f' && b != 'r' && b != 'n' && b != 'm' && b != 't' && b != 'p' && b != 'c' && b != 'd' && b != 'g' && b != 'b' {
					doubleConsBg++
				}
			}
		}

		if i+1 < n {
			nb := sld[i+1]
			if nb >= 'A' && nb <= 'Z' {
				nb += 32
			}
			bigram[bigramBucket(b, nb)]++
		}
		if i+2 < n {
			b1 := sld[i+1]
			if b1 >= 'A' && b1 <= 'Z' {
				b1 += 32
			}
			b2 := sld[i+2]
			if b2 >= 'A' && b2 <= 'Z' {
				b2 += 32
			}
			trigram[trigramBucket(b, b1, b2)]++
		}
	}

	// Vérifier les paires consonantiques initiales et finales du SLD
	badInitial := float32(0.0)
	badFinal := float32(0.0)
	if n >= 2 {
		c0 := sld[0] | 0x20
		c1 := sld[1] | 0x20
		if c0 >= 'a' && c0 <= 'z' && c1 >= 'a' && c1 <= 'z' && !isVowelLetter(c0) && !isVowelLetter(c1) {
			if !isValidInitialConsonantCluster(c0, c1) {
				badInitial = 0.85
				hostileConsBg++
			}
		}
		cn1 := sld[n-2] | 0x20
		cn0 := sld[n-1] | 0x20
		if cn0 == 'q' || cn0 == 'j' || cn0 == 'v' || (cn0 == 'z' && !isVowelLetter(cn1)) {
			badFinal = 0.85
		} else if cn1 >= 'a' && cn1 <= 'z' && cn0 >= 'a' && cn0 <= 'z' && !isVowelLetter(cn1) && !isVowelLetter(cn0) {
			if !isValidFinalConsonantCluster(cn1, cn0) {
				badFinal = 0.80
			}
		}
	}

	invN := 1.0 / float32(n)
	rawBits := shannonBits(hist[:], uint32(n))
	maxPossibleBits := math.Log2(float64(max(min(n, 20), 2)))
	sldEntropy := float32(rawBits / maxPossibleBits)

	distinct := 0
	for i := range 256 {
		if hist[i] > 0 {
			distinct++
		}
	}

	var winEnt [16]float32
	for w := range 16 {
		start := w * n / 16
		end := min((w+1)*n/16, n)
		if end <= start {
			start = 0
			end = n
		}
		clear(window[:])
		total := uint32(0)
		for i := start; i < end; i++ {
			b := sld[i]
			if b >= 'A' && b <= 'Z' {
				b += 32
			}
			window[b]++
			total++
		}
		winEnt[w] = float32(shannonBits(window[:], total) / 4.0)
	}

	alphaCount := float32(max(vowels+consonants, 1))
	alphaPairs := float32(max(actualAlphaPairs, 1))
	vowelRatio := float32(vowels) / alphaCount
	digitRatio := float32(digits) * invN
	rareRatio := float32(rareCons) / alphaCount
	veryRareRatio := float32(veryRareCons) / alphaCount
	freqConsRatio := float32(frequentCons) / alphaCount
	lexBgRatio := float32(commonLexBg) / alphaPairs
	pronBgRatio := float32(pronounceableBg) / alphaPairs
	hostileBgRatio := float32(hostileConsBg) / alphaPairs
	rareBgRatio := float32(rareConsBg) / alphaPairs
	altRatio := float32(vowelConsAlt) / alphaPairs

	isPureHex := float32(0.0)
	if n >= 12 && hexChars == n {
		isPureHex = 0.95
	}
	isInterleavedAlnum := float32(0.0)
	if letterDigitTrans >= 2 || (digits >= 1 && consonants >= 4 && letterDigitTrans >= 1 && hyphens == 0 && (hostileConsBg > 0 || rareCons >= 2)) {
		isInterleavedAlnum = 0.92
	}
	qPenalty := float32(0.0)
	if qWithoutU > 0 {
		qPenalty = 0.92
	}
	vowelClusterPenalty := float32(0.0)
	if maxVowelRun >= 3 || awkwardVowelBg >= 2 {
		vowelClusterPenalty = 0.80
	}
	// Détection de l'absence de consonnes naturelles fréquentes (t, n, r, l, d), typique de ramdo/simda
	missingFreqConsPenalty := float32(0.0)
	if n >= 8 && frequentCons == 0 {
		missingFreqConsPenalty = 0.90
	} else if n >= 10 && freqConsRatio < 0.12 {
		missingFreqConsPenalty = 0.75
	}
	tldRisk := dgaTLDRisk(tld)

	var feats [32]float32
	feats[0] = clampSym((hostileBgRatio - 0.07) * 5.5)
	feats[1] = clampSym((float32(hostileConsBg) - 1.1) / 1.8)
	feats[2] = clampSym((0.82 - pronBgRatio) * 4.0)
	feats[3] = clampSym((0.25 - lexBgRatio) * 3.8)
	feats[4] = clampSym((rareRatio - 0.16) * 4.2)
	feats[5] = clampSym((veryRareRatio - 0.03) * 6.5)
	feats[6] = clampSym((rareBgRatio - 0.03) * 6.5)
	feats[7] = clampSym((float32(maxConsRun) - 3.1) / 2.0)
	feats[8] = clampSym((float32(maxNonVowelRun) - 3.3) / 2.2)
	feats[9] = clampSym((0.30 - vowelRatio) * 3.2)
	feats[10] = clampSym((0.22 - freqConsRatio) * 3.5)
	feats[11] = isInterleavedAlnum
	feats[12] = clampSym(float32(letterDigitTrans) * 0.55)
	feats[13] = isPureHex
	feats[14] = clampSym(digitRatio * 2.5)
	feats[15] = qPenalty
	feats[16] = clampSym((sldEntropy - 0.82) * 3.5)
	feats[17] = badInitial
	feats[18] = badFinal
	feats[19] = tldRisk
	feats[20] = clampSym(float32(doubleConsBg) * 0.85)
	feats[21] = clampSym(-float32(hyphens)*0.65 + 0.05)
	feats[22] = clampSym((float32(veryRareCons) - 0.5) / 1.4)
	feats[23] = vowelClusterPenalty
	feats[24] = missingFreqConsPenalty
	feats[25] = clampSym(feats[2]*0.6 + feats[7]*0.4)
	feats[26] = clampSym(feats[3]*0.6 + feats[19]*0.4)
	feats[27] = clampSym(max(feats[11], max(feats[13], max(feats[15], max(feats[24], feats[0])))))
	feats[28] = clampSym(max(feats[1], max(feats[17], feats[18])))
	feats[29] = clampSym(feats[5]*0.5 + feats[19]*0.5)
	feats[30] = clampSym((0.44 - altRatio) * 2.2)

	// Score composite DGA centré : positif pour tout DGA (hex, alnum, consonantique,
	// sans consonnes fréquentes, voyelles anormales ou DDNS/TLD à risque),
	// négatif pour les domaines lexicaux normaux.
	dgaSignals := float32(0.0)
	if isPureHex > 0 {
		dgaSignals += 1.4
	}
	if isInterleavedAlnum > 0 {
		dgaSignals += 1.3
	}
	if qPenalty > 0 {
		dgaSignals += 1.2
	}
	if missingFreqConsPenalty > 0 {
		dgaSignals += 1.1
	}
	if vowelClusterPenalty > 0 {
		dgaSignals += 0.8
	}
	if badInitial > 0 {
		dgaSignals += 0.8
	}
	if badFinal > 0 {
		dgaSignals += 0.8
	}
	if hostileConsBg >= 2 {
		dgaSignals += 1.1
	} else if hostileConsBg == 1 && (lexBgRatio < 0.20 || veryRareCons >= 1 || maxConsRun >= 4 || n <= 8) {
		dgaSignals += 0.75
	}
	if veryRareCons >= 2 {
		dgaSignals += 0.85
	} else if veryRareCons == 1 && lexBgRatio < 0.18 {
		dgaSignals += 0.55
	}
	if lexBgRatio < 0.12 && n >= 6 {
		dgaSignals += 0.70
	}
	if pronBgRatio < 0.75 {
		dgaSignals += (0.75 - pronBgRatio) * 3.0
	}
	if maxConsRun >= 4 {
		dgaSignals += 0.90
	} else if maxConsRun == 3 && lexBgRatio < 0.20 {
		dgaSignals += 0.60
	}
	if rareRatio >= 0.22 {
		dgaSignals += 0.70
	}
	if vowelRatio < 0.22 || vowelRatio > 0.58 {
		dgaSignals += 0.60
	}
	if sldEntropy > 0.86 && n >= 11 && lexBgRatio < 0.22 {
		dgaSignals += 0.70
	}
	if tldRisk >= 0.70 {
		dgaSignals += 0.85
	} else if tldRisk >= 0.40 {
		dgaSignals += 0.45
	} else if tldRisk <= -0.50 {
		dgaSignals -= 0.75
	}
	// Bonus de bénignité lexicale franche
	if hostileConsBg == 0 && badInitial == 0 && badFinal == 0 && qWithoutU == 0 && letterDigitTrans == 0 && isPureHex == 0 && veryRareCons == 0 && lexBgRatio >= 0.20 && freqConsRatio >= 0.16 {
		dgaSignals -= 1.25
	} else if hostileConsBg <= 1 && letterDigitTrans == 0 && isPureHex == 0 && qWithoutU == 0 && lexBgRatio >= 0.28 {
		dgaSignals -= 0.85
	}

	var sumFeats float32
	for i := range 31 {
		sumFeats += feats[i]
	}
	feats[31] = clampSym(dgaSignals*0.75 + (sumFeats/14.0)*0.25)

	for b := range 32 {
		base := b * 8
		f := feats[b]
		for k := range 8 {
			alt := feats[(b+k*5+1)&31]
			dst[base+k] = 0.45*f + 0.15*alt + 0.40*feats[31]
		}
	}

	for i := range 256 {
		if hist[i] > 0 {
			slot := (i*11 + 5) & 255
			dst[slot] += float32(hist[i]) * invN * 0.25
		}
	}

	invBg := float32(0)
	if n >= 2 {
		invBg = 1.0 / float32(n-1)
	}
	for i := range 128 {
		f := feats[i&31]
		bg := float32(bigram[i])*invBg*4.0 - (4.0 / 128.0)
		dst[bigramBase+i] = 0.50*f + 0.35*feats[31] + 0.15*bg
	}

	invTg := float32(0)
	if n >= 3 {
		invTg = 1.0 / float32(n-2)
	}
	for i := range 64 {
		f := feats[i&31]
		tg := float32(trigram[i])*invTg*4.0 - (4.0 / 64.0)
		dst[trigramBase+i] = 0.50*f + 0.35*feats[31] + 0.15*tg
	}

	for w := range 16 {
		dst[entropyBase+w] = clampSym((winEnt[w]-0.52)*1.6 + 0.5*feats[31])
	}

	for c := range 12 {
		dst[classBase+c] = feats[c]
	}

	dst[headerBase+0] = float32(min(n, 63)) / 63.0
	dst[headerBase+1] = vowelRatio
	dst[headerBase+2] = digitRatio
	dst[headerBase+3] = rareRatio
	dst[headerBase+4] = pronBgRatio
	dst[headerBase+5] = hostileBgRatio
	dst[headerBase+6] = sldEntropy
	dst[headerBase+7] = tldRisk

	for a := range 28 {
		dst[aggregateBase+a] = feats[a+4]
	}

	return true
}

func clampSym(v float32) float32 {
	if v > 0.95 {
		return 0.95
	}
	if v < -0.95 {
		return -0.95
	}
	return v
}

func isRareConsonant(b byte) bool {
	switch b {
	case 'q', 'x', 'z', 'j', 'v', 'k', 'w', 'y':
		return true
	}
	return false
}

func isAwkwardVowelPair(a, b byte) bool {
	if a == b {
		return a == 'i' || a == 'u' || a == 'a'
	}
	pair := uint16(a)<<8 | uint16(b)
	switch pair {
	case 'u'<<8 | 'o', 'u'<<8 | 'a', 'i'<<8 | 'u', 'a'<<8 | 'o', 'o'<<8 | 'a', 'e'<<8 | 'o', 'o'<<8 | 'e':
		return true
	}
	return false
}

func isValidInitialConsonantCluster(a, b byte) bool {
	pair := uint16(a)<<8 | uint16(b)
	switch pair {
	case 'b'<<8 | 'l', 'b'<<8 | 'r', 'c'<<8 | 'h', 'c'<<8 | 'l', 'c'<<8 | 'r',
		'd'<<8 | 'r', 'd'<<8 | 'w', 'f'<<8 | 'l', 'f'<<8 | 'r', 'g'<<8 | 'l', 'g'<<8 | 'r',
		'p'<<8 | 'h', 'p'<<8 | 'l', 'p'<<8 | 'r', 's'<<8 | 'c', 's'<<8 | 'h', 's'<<8 | 'k',
		's'<<8 | 'l', 's'<<8 | 'm', 's'<<8 | 'n', 's'<<8 | 'p', 's'<<8 | 'q', 's'<<8 | 't',
		's'<<8 | 'w', 't'<<8 | 'h', 't'<<8 | 'r', 't'<<8 | 'w', 'w'<<8 | 'h', 'w'<<8 | 'r':
		return true
	}
	return false
}

func isValidFinalConsonantCluster(a, b byte) bool {
	if a == b {
		switch a {
		case 'l', 's', 'f', 'z':
			return true
		}
		return false
	}
	pair := uint16(a)<<8 | uint16(b)
	switch pair {
	case 'c'<<8 | 'h', 's'<<8 | 'h', 't'<<8 | 'h', 'p'<<8 | 'h', 'g'<<8 | 'h', 'c'<<8 | 'k',
		'n'<<8 | 'g', 'n'<<8 | 'k', 'n'<<8 | 'd', 'n'<<8 | 't', 'n'<<8 | 's',
		'm'<<8 | 'p', 'm'<<8 | 's',
		'l'<<8 | 't', 'l'<<8 | 'd', 'l'<<8 | 'k', 'l'<<8 | 'f', 'l'<<8 | 'p', 'l'<<8 | 'm', 'l'<<8 | 's',
		'r'<<8 | 't', 'r'<<8 | 'd', 'r'<<8 | 'k', 'r'<<8 | 'f', 'r'<<8 | 'p', 'r'<<8 | 'm', 'r'<<8 | 'n', 'r'<<8 | 's', 'r'<<8 | 'l',
		's'<<8 | 't', 's'<<8 | 'p', 's'<<8 | 'k', 'c'<<8 | 't', 'p'<<8 | 't', 'f'<<8 | 't', 'x'<<8 | 't',
		'd'<<8 | 's', 't'<<8 | 's', 'p'<<8 | 's', 'k'<<8 | 's', 'g'<<8 | 's', 'b'<<8 | 's', 'f'<<8 | 's',
		'w'<<8 | 'n', 'w'<<8 | 's', 'w'<<8 | 'd':
		return true
	}
	return false
}

func matchLowerTunnel(b []byte) bool {
	if len(b) != 6 {
		return false
	}
	return (b[0]|0x20) == 't' && (b[1]|0x20) == 'u' && (b[2]|0x20) == 'n' &&
		(b[3]|0x20) == 'n' && (b[4]|0x20) == 'e' && (b[5]|0x20) == 'l'
}

func isCommonBenignSubdomain(label []byte) bool {
	switch string(label) {
	case "www", "mail", "site", "cdn", "api", "blog", "shop", "docs", "m",
		"ns1", "ns2", "smtp", "pop", "imap", "ftp", "dev", "portal", "secure",
		"admin", "support", "forum", "news", "webmail", "autodiscover", "cpanel",
		"webdisk", "whm", "app", "login", "auth", "static", "media", "img", "images":
		return true
	}
	return false
}

func dgaTLDRisk(tld []byte) float32 {
	switch string(tld) {
	case "eu", "biz", "pw", "bid", "top", "kz", "su", "ws", "tk", "cc", "xyz",
		"click", "me.uk", "co.in", "bit", "ddns.net", "dyndns.org", "mooo.com",
		"dynserv.com", "yi.org", "co.cc", "cz.cc":
		return 0.85
	case "info", "cn", "in", "me", "to", "so", "la", "ms", "sc", "mn", "ac",
		"ki", "pro", "nf", "ug", "hk", "mu", "xxx", "sh", "ga", "cx", "cm",
		"nu", "im", "tj", "bz", "space", "sx", "tw":
		return 0.45
	case "com", "net", "org", "ru", "co.uk", "us", "tv":
		return 0.0
	default:
		return -0.70
	}
}

// isPronounceableConsonantPair reconnaît les digrammes et jonctions consonantiques
// légitimes fréquents dans les noms de domaine lexicaux.
func isPronounceableConsonantPair(a, b byte) bool {
	if a == 'y' || b == 'y' {
		return a != b
	}
	if a == b {
		switch a {
		case 'l', 's', 'f', 'r', 'n', 'm', 't', 'p', 'c', 'd', 'g', 'b':
			return true
		}
		return false
	}
	pair := uint16(a)<<8 | uint16(b)
	switch pair {
	case 't'<<8 | 'h', 'c'<<8 | 'h', 's'<<8 | 'h', 'p'<<8 | 'h', 'w'<<8 | 'h', 'g'<<8 | 'h',
		's'<<8 | 't', 's'<<8 | 'p', 's'<<8 | 'k', 's'<<8 | 'l', 's'<<8 | 'm', 's'<<8 | 'n', 's'<<8 | 'w', 's'<<8 | 'c',
		't'<<8 | 'r', 'd'<<8 | 'r', 'p'<<8 | 'r', 'b'<<8 | 'r', 'c'<<8 | 'r', 'g'<<8 | 'r', 'f'<<8 | 'r', 'w'<<8 | 'r',
		'p'<<8 | 'l', 'b'<<8 | 'l', 'c'<<8 | 'l', 'g'<<8 | 'l', 'f'<<8 | 'l',
		'n'<<8 | 'g', 'n'<<8 | 'k', 'n'<<8 | 'd', 'n'<<8 | 't', 'n'<<8 | 's', 'n'<<8 | 'c', 'n'<<8 | 'v', 'n'<<8 | 'f', 'n'<<8 | 'l', 'n'<<8 | 'm',
		'm'<<8 | 'p', 'm'<<8 | 'b', 'm'<<8 | 's', 'm'<<8 | 'n',
		'l'<<8 | 't', 'l'<<8 | 'd', 'l'<<8 | 'k', 'l'<<8 | 'f', 'l'<<8 | 'p', 'l'<<8 | 'm', 'l'<<8 | 's', 'l'<<8 | 'v', 'l'<<8 | 'b', 'l'<<8 | 'c', 'l'<<8 | 'g',
		'r'<<8 | 't', 'r'<<8 | 'd', 'r'<<8 | 'k', 'r'<<8 | 'f', 'r'<<8 | 'p', 'r'<<8 | 'm', 'r'<<8 | 'n', 'r'<<8 | 's', 'r'<<8 | 'l', 'r'<<8 | 'c', 'r'<<8 | 'g', 'r'<<8 | 'v', 'r'<<8 | 'b', 'r'<<8 | 'w',
		'c'<<8 | 't', 'p'<<8 | 't', 'f'<<8 | 't', 'x'<<8 | 't', 'x'<<8 | 'p',
		'c'<<8 | 'k', 'w'<<8 | 'n', 'w'<<8 | 's', 'w'<<8 | 'd',
		'd'<<8 | 's', 't'<<8 | 's', 'p'<<8 | 's', 'k'<<8 | 's', 'g'<<8 | 's', 'b'<<8 | 's', 'f'<<8 | 's', 'v'<<8 | 's',
		't'<<8 | 'w', 'd'<<8 | 'w', 's'<<8 | 'q':
		return true
	}
	return false
}

// isCommonLexicalBigram reconnaît les bigrammes très fréquents de l'anglais et des langues latines.
func isCommonLexicalBigram(a, b byte) bool {
	pair := uint16(a)<<8 | uint16(b)
	switch pair {
	case 't'<<8 | 'h', 'h'<<8 | 'e', 'i'<<8 | 'n', 'e'<<8 | 'r', 'a'<<8 | 'n', 'r'<<8 | 'e',
		'o'<<8 | 'n', 'a'<<8 | 't', 'e'<<8 | 'n', 'n'<<8 | 'd', 't'<<8 | 'i', 'e'<<8 | 's',
		'o'<<8 | 'r', 't'<<8 | 'e', 'o'<<8 | 'f', 'e'<<8 | 'd', 'i'<<8 | 's', 'i'<<8 | 't',
		'a'<<8 | 'l', 'a'<<8 | 'r', 's'<<8 | 't', 't'<<8 | 'o', 'n'<<8 | 't', 'n'<<8 | 'g',
		's'<<8 | 'e', 'h'<<8 | 'a', 'a'<<8 | 's', 'o'<<8 | 'u', 'i'<<8 | 'o', 'l'<<8 | 'e',
		'v'<<8 | 'e', 'c'<<8 | 'o', 'm'<<8 | 'e', 'd'<<8 | 'e', 'h'<<8 | 'i', 'r'<<8 | 'i',
		'r'<<8 | 'o', 'i'<<8 | 'c', 'n'<<8 | 'e', 'e'<<8 | 'a', 'r'<<8 | 'a', 'c'<<8 | 'e',
		'l'<<8 | 'i', 'c'<<8 | 'h', 'l'<<8 | 'l', 'b'<<8 | 'e', 'm'<<8 | 'a', 's'<<8 | 'i',
		'o'<<8 | 'm', 'u'<<8 | 'r', 'c'<<8 | 'a', 'e'<<8 | 'l', 't'<<8 | 'a', 'l'<<8 | 'a',
		'n'<<8 | 's', 'd'<<8 | 'i', 'f'<<8 | 'o', 'h'<<8 | 'o', 'p'<<8 | 'e', 'e'<<8 | 'c',
		'p'<<8 | 'r', 'n'<<8 | 'o', 'c'<<8 | 't', 'u'<<8 | 's', 'a'<<8 | 'c', 'o'<<8 | 't',
		'i'<<8 | 'l', 't'<<8 | 'r', 'l'<<8 | 'y', 'n'<<8 | 'c', 'e'<<8 | 't', 'u'<<8 | 't',
		's'<<8 | 's', 's'<<8 | 'o', 'r'<<8 | 's', 'u'<<8 | 'n', 'l'<<8 | 'o', 'w'<<8 | 'a',
		'g'<<8 | 'e', 'i'<<8 | 'e', 'w'<<8 | 'h', 'e'<<8 | 'e', 'w'<<8 | 'i', 'e'<<8 | 'm',
		'a'<<8 | 'd', 'o'<<8 | 'l', 'r'<<8 | 't', 'p'<<8 | 'o', 'w'<<8 | 'e', 'n'<<8 | 'a',
		'u'<<8 | 'l', 'n'<<8 | 'i', 't'<<8 | 's', 'm'<<8 | 'o', 'o'<<8 | 'w', 'p'<<8 | 'a',
		'i'<<8 | 'm', 'm'<<8 | 'i', 'a'<<8 | 'i', 's'<<8 | 'h', 'i'<<8 | 'r', 's'<<8 | 'u',
		'i'<<8 | 'd', 'o'<<8 | 's', 'i'<<8 | 'v', 'i'<<8 | 'a', 'a'<<8 | 'm', 'f'<<8 | 'i',
		'c'<<8 | 'i', 'v'<<8 | 'i', 'p'<<8 | 'l', 'i'<<8 | 'g', 't'<<8 | 'u', 'e'<<8 | 'v',
		'l'<<8 | 'd', 'r'<<8 | 'y', 'm'<<8 | 'p', 'f'<<8 | 'e', 'b'<<8 | 'l', 'a'<<8 | 'b',
		'o'<<8 | 'o', 's'<<8 | 'p', 'b'<<8 | 'o', 'b'<<8 | 'r', 'c'<<8 | 'r', 'g'<<8 | 'r',
		'f'<<8 | 'r', 'd'<<8 | 'r', 'c'<<8 | 'l', 'g'<<8 | 'l', 'f'<<8 | 'l', 's'<<8 | 'l':
		return true
	}
	return false
}
