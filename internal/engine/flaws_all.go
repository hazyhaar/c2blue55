package engine

// FlawsAll agrège les catalogues d'anti-patterns de code vulnérable 01 à 05.
// Il fournit 75 signatures de motifs structurels de code vulnérable couvrant :
// - Catégorie 01 : Débordements arithmétiques silencieux, wrapping uint64, conversions rétrécissantes
// - Catégorie 02 : Désynchronisations de parseurs, wire types protobuf manquants, frontières TLV
// - Catégorie 03 : Concurrence non synchronisée, écritures concurrentes sur map Go, TOCTOU fichier
// - Catégorie 04 : Réentrance et cohérence d'état, appels externes avant écriture d'état, EIP-150 gas griefing
// - Catégorie 05 : Bornes mémoire et troncatures C/C++, débordement d'allocateur malloc, index négatif
func FlawsAll() []MotifDef {
	total := 15 * 5
	out := make([]MotifDef, 0, total)
	out = append(out, FlawsArithmetic()...)
	out = append(out, FlawsParser()...)
	out = append(out, FlawsConcurrency()...)
	out = append(out, FlawsReentrancy()...)
	out = append(out, FlawsMemory()...)
	return out
}

// BuildFlawsAllCodebook encode l'ensemble des 75 motifs d'anti-patterns et rend le codebook unifié.
func BuildFlawsAllCodebook() (*Codebook, error) {
	defs := FlawsAll()
	entries := make([]CodebookEntry, 0, len(defs))
	for i := range defs {
		entry, _, _, err := EncodeMotif(&defs[i])
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return NewCodebook(entries), nil
}

// SaveFlawsAllCodebook sérialise le catalogue d'anti-patterns unifié au format .c2book.
func SaveFlawsAllCodebook(path string) error {
	cb, err := BuildFlawsAllCodebook()
	if err != nil {
		return err
	}
	return SaveCodebook(path, cb.entries)
}
