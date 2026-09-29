// Pré-filtre syntaxique et filtre d'entropie pour fenêtres de code source. Le
// module répond à l'audit V8 WebAssembly : les bannières de commentaires
// (// ======) et les alignements de macros à plusieurs dizaines d'espaces
// produisent des fenêtres à entropie quasi nulle qui saturent l'espace 512D et
// entrent en collision de Hamming avec des bourrages NOP. La normalisation
// retire le bruit syntaxique sans allocation sur le tas, puis le prédicat
// d'élagage écarte les blocs triviaux avant extraction RaBitQ.
package engine

// DefaultMinEntropy est le seuil de Shannon par défaut, exprimé en bits par
// octet. Une fenêtre de code source ordinaire dépasse largement cette valeur ;
// un alignement d'espaces ou une bannière de séparateurs reste en dessous.
const DefaultMinEntropy = 1.5

// DefaultMinEntropyQ8 est le seuil de Shannon par défaut en virgule fixe Q8.8 (1.5 * 256 = 384).
const DefaultMinEntropyQ8 uint32 = 384

// boilerplateBytes énumère les octets dont la répétition à plus de 75 % suffit
// à qualifier un bourrage : zéro binaire, espace, opcode NOP x86 (0x90), et les
// séparateurs de bannière '=', '-' et '*'.
var boilerplateBytes = [...]byte{0x00, 0x20, 0x90, '=', '-', '*'}

// isCodeSpace reconnaît l'espace blanc au sens de \s pour les sources mixtes :
// espace, tabulation, retour chariot, saut de ligne, tabulation verticale et
// saut de page. La fonction isASCIISpace de feature_extractor.go ne couvre que
// l'espace et la tabulation et n'est donc pas réemployée ici.
func isCodeSpace(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', '\v', '\f':
		return true
	}
	return false
}

// hasHashCommentPrefix indique si le dièse rencontré à la position i ouvre un
// commentaire : il doit être en tête de fenêtre ou précédé d'un espace blanc.
// Cette contrainte évite d'amputer un fragment de chaîne non délimité ou un
// croisillon de mot de passe collé à son préfixe.
func hasHashCommentPrefix(src []byte, i int) bool {
	return i == 0 || isCodeSpace(src[i-1])
}

// NormalizeCodeWindow élimine les commentaires de fin de ligne (// et #) et les
// commentaires multi-lignes (/* ... */), préserve verbatim le contenu des
// chaînes littérales délimitées par ", ' ou `, puis effondre chaque séquence
// d'espaces blancs consécutifs en un unique octet 0x20. Le résultat est écrit
// dans dst, qui doit offrir une capacité au moins égale à len(src) ; la fonction
// retourne le nombre d'octets utiles écrits et ne réserve rien sur le tas.
//
// Les séquences blanches séparées par un commentaire retiré fusionnent en un
// seul espace. Une fenêtre entièrement blanche rend un unique espace, tandis
// qu'une fenêtre vide rend zéro octet.
func NormalizeCodeWindow(src []byte, dst []byte) int {
	if cap(dst) < len(src) {
		return 0
	}
	dst = dst[:cap(dst)]

	n := 0
	i := 0
	limit := len(src)

	for i < limit {
		c := src[i]

		// Chaîne littérale : recopie verbatim, échappements compris, sans
		// effondrement d'espace ni interprétation de commentaire.
		if c == '"' || c == '\'' || c == '`' {
			quote := c
			dst[n] = c
			n++
			i++
			for i < limit {
				ch := src[i]
				dst[n] = ch
				n++
				i++
				if ch == '\\' && quote != '`' && i < limit {
					dst[n] = src[i]
					n++
					i++
					continue
				}
				if ch == quote {
					break
				}
			}
			continue
		}

		// Commentaire de fin de ligne //.
		if c == '/' && i+1 < limit && src[i+1] == '/' {
			for i < limit && src[i] != '\n' {
				i++
			}
			continue
		}

		// Commentaire multi-lignes /* ... */ ; un bloc non fermé consomme la
		// fin de fenêtre.
		if c == '/' && i+1 < limit && src[i+1] == '*' {
			i += 2
			for i+1 < limit && !(src[i] == '*' && src[i+1] == '/') {
				i++
			}
			if i+1 < limit {
				i += 2
			} else {
				i = limit
			}
			continue
		}

		// Commentaire de fin de ligne # (shell, Python, Makefile).
		if c == '#' && hasHashCommentPrefix(src, i) {
			for i < limit && src[i] != '\n' {
				i++
			}
			continue
		}

		// Espace blanc : effondrement de la séquence en un seul 0x20, fusion
		// comprise avec un espace déjà émis avant un commentaire retiré.
		if isCodeSpace(c) {
			for i < limit && isCodeSpace(src[i]) {
				i++
			}
			if n == 0 || dst[n-1] != ' ' {
				dst[n] = ' '
				n++
			}
			continue
		}

		dst[n] = c
		n++
		i++
	}
	return n
}

// CalculateEntropyQ8 calcule l'entropie de Shannon en virgule fixe Q8.8 (0..2048).
// Il exploite directement l'algorithme entier C2bt_calc_entropy_8_8 et les tables L1D
// ARCHTIME du moteur (c_log2_c_table), sans allocation sur le tas et sans fonction mathématique flottante.
func CalculateEntropyQ8(data []byte) uint32 {
	if len(data) == 0 {
		return 0
	}
	return C2bt_calc_entropy_8_8(data, uint64(len(data)))
}

// CalculateShannonEntropy calcule l'entropie de Shannon H en bits par octet (0.0..8.0).
// La conversion depuis le format fixe Q8.8 s'effectue par division par 256.0.
func CalculateShannonEntropy(data []byte) float64 {
	return float64(CalculateEntropyQ8(data)) / 256.0
}

// IsBoilerplateOrLowEntropy retourne vrai lorsque le bloc doit être rejeté
// avant extraction : bloc vide, entropie de Shannon inférieure à minEntropy, ou
// répétition d'un unique octet de bourrage à plus de 75 % du bloc. Le seuil de
// répétition est strict : compter exactement trois quarts du bloc ne suffit pas
// à rejeter un contenu par ailleurs structuré.
func IsBoilerplateOrLowEntropy(data []byte, minEntropy float64) bool {
	if len(data) == 0 {
		return true
	}
	if minEntropy > 0 {
		minQ8 := uint32(minEntropy * 256.0)
		if CalculateEntropyQ8(data) < minQ8 {
			return true
		}
	}

	var freq [256]int
	for _, b := range data {
		freq[b]++
	}
	threeQuarters := len(data) * 3
	for _, b := range boilerplateBytes {
		if freq[b]*4 > threeQuarters {
			return true
		}
	}
	return false
}
