package engine

// dotF32 calcule le produit scalaire de deux vecteurs float32 de même longueur
// dans un ordre de sommation fixe, de la gauche vers la droite. Cet ordre rend
// chaque terme de contenu reproductible entre le noyau de référence et le noyau
// précalculé.
func dotF32(a, b []float32) float32 {
	var sum float32
	for i := range a {
		sum += a[i] * b[i]
	}
	return sum
}

// contentTerms relève les trois termes désentrelacés qui dépendent à la fois des
// vecteurs de contenu requête/clé et des plongements de position relative.
func contentTerms(qi, kj, posQi, posKj []float32) (cc, cp, pc float32) {
	cc = dotF32(qi, kj)
	cp = dotF32(qi, posKj)
	pc = dotF32(posQi, kj)
	return cc, cp, pc
}

// assembleScore combine les quatre termes d'attention désentrelacée dans un
// ordre d'addition figé, afin que la variante précalculée et la variante de
// référence produisent un résultat bit-à-bit identique.
func assembleScore(qi, kj, posQi, posKj []float32, pp, scale float32) float32 {
	cc, cp, pc := contentTerms(qi, kj, posQi, posKj)
	return (((cc + cp) + pc) + pp) * scale
}

// PrecomputePositionPositionTable remplit outPP[delta] avec le produit scalaire
// du vecteur de position relative de requête et du vecteur de position relative
// de clé pour delta dans [0, 2*kDist]. Chaque entrée ne dépend que de la
// distance scalaire delta = j - i + kDist, ce qui permet de sortir ce quatrième
// terme de la boucle chaude d'attention. Le tableau compte 2*kDist+1 flottants
// et reste résident en cache L1D.
func PrecomputePositionPositionTable(posQ, posK []float32, kDist, dHead int, outPP []float32) {
	for delta := 0; delta <= 2*kDist; delta++ {
		off := delta * dHead
		outPP[delta] = posPosDot(posQ[off:off+dHead], posK[off:off+dHead])
	}
}

// C2_deberta_disentangled_attn calcule la matrice de scores désentrelacée d'une
// tête unique sur une séquence de n positions. Les quatre termes sont
// content-content, content-to-position, position-to-content et le terme
// position-position recalculé pour chaque paire (i, j). q, k et scores sont
// respectivement de tailles n*dHead, n*dHead et n*n ; posQ et posK de taille
// (2*kDist+1)*dHead. Une distance hors bornes annule le score.
func C2_deberta_disentangled_attn(q, k, posQ, posK []float32, scores []float32, n, headDim, kDist int, scale float32) {
	for i := 0; i < n; i++ {
		qi := q[i*headDim : (i+1)*headDim]
		for j := 0; j < n; j++ {
			delta := j - i + kDist
			if delta < 0 || delta > 2*kDist {
				scores[i*n+j] = 0
				continue
			}
			kj := k[j*headDim : (j+1)*headDim]
			off := delta * headDim
			posQi := posQ[off : off+headDim]
			posKj := posK[off : off+headDim]
			pp := posPosDot(posQi, posKj)
			scores[i*n+j] = assembleScore(qi, kj, posQi, posKj, pp, scale)
		}
	}
}

// C2_deberta_disentangled_attn_fast est la variante optimisée du noyau
// d'attention désentrelacée. Le terme position-position provient du tableau
// outPP précalculé, ce qui supprime le produit scalaire 64-D par paire (i, j)
// au profit d'une simple addition. La signature et la sémantique sont
// identiques à C2_deberta_disentangled_attn.
func C2_deberta_disentangled_attn_fast(q, k, posQ, posK, outPP []float32, scores []float32, n, headDim, kDist int, scale float32) {
	for i := 0; i < n; i++ {
		qi := q[i*headDim : (i+1)*headDim]
		for j := 0; j < n; j++ {
			delta := j - i + kDist
			if delta < 0 || delta > 2*kDist {
				scores[i*n+j] = 0
				continue
			}
			kj := k[j*headDim : (j+1)*headDim]
			off := delta * headDim
			posQi := posQ[off : off+headDim]
			posKj := posK[off : off+headDim]
			scores[i*n+j] = assembleScore(qi, kj, posQi, posKj, outPP[delta], scale)
		}
	}
}
