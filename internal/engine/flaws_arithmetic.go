package engine

// Flaws arithmétiques : catalogue de quinze anti-patterns de calculs entiers
// non vérifiés, de débordements silencieux et de troncatures de largeur en Go
// et en Solidity. L'exemple emblématique provient de cbridge-node
// (CELER-VULN-02, server.go:353), où l'échelle décimale est calculée par une
// boucle de multiplication uint64 sans borne. Chaque définition porte une
// fenêtre canonique de 96 octets, le sous-système, l'action et la sévérité.
// L'encodage RaBitQ 512D réemploie FeatureExtractor.ExtractTo puis Encode512,
// sans nouvelle voie de calcul.
//
// Les quinze motifs (ThreatID 0x1001..0x100F) sont des signatures de code
// vulnérable construites pour la détection. Le vocabulaire de sous-systèmes,
// d'actions et de sévérités est déjà déclaré par la série motifs_croises_05.go
// et est réemployé tel quel, sans redéclaration.

// FlawsArithmetic rend le catalogue complet des quinze motifs d'arithmétique
// non vérifiée. L'ordre est stable et suit la numérotation des ThreatID.
func FlawsArithmetic() []MotifDef {
	return []MotifDef{
		{
			ThreatID:  0x1001,
			Name:      "cbridge-uint64-decimal-scale-overflow",
			Source:    "CELER-VULN-02; cbridge-node server.go:353",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("p := uint64(1); for i := uint64(0); i < delta; i++ { p = p * 10 }"),
		},
		{
			ThreatID:  0x1002,
			Name:      "unbounded-bitshift-overflow-64bit",
			Source:    "CWE-1339; décalage >= largeur du type",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("val := uint64(1) << shift; if shift >= 64 { wrap silencieux }"),
		},
		{
			ThreatID:  0x1003,
			Name:      "truncating-int64-to-uint32-cast",
			Source:    "CWE-197; conversion rétrécissante",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityMedium,
			Window:    mustMotifWindow("length := uint32(int64Length); buffer := make([]byte, length)"),
		},
		{
			ThreatID:  0x1004,
			Name:      "unchecked-addition-overflow-loop",
			Source:    "CWE-190; accumulation uint64 sans max",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("total += item.Amount; accumulation uint64 sans verification max"),
		},
		{
			ThreatID:  0x1005,
			Name:      "solidity-unchecked-block-arithmetic",
			Source:    "Solidity <0.8.0; bloc unchecked",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("unchecked { balance[account] += amount; totalSupply += amount; }"),
		},
		{
			ThreatID:  0x1006,
			Name:      "integer-multiplication-overflow-alloc",
			Source:    "CWE-190; taille d'allocation dérivée",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("allocSize := count * elementSize; ptr := malloc(allocSize)"),
		},
		{
			ThreatID:  0x1007,
			Name:      "underflow-subtraction-balance-check",
			Source:    "CWE-191; contrôle après soustraction",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("newBalance := currentBalance - withdrawAmount; if newBalance >= 0"),
		},
		{
			ThreatID:  0x1008,
			Name:      "negative-signed-index-conversion",
			Source:    "CWE-195; index signé converti en non signé",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityMedium,
			Window:    mustMotifWindow("index := int(userVal); slice := data[uint(index):]"),
		},
		{
			ThreatID:  0x1009,
			Name:      "time-duration-overflow-nanoseconds",
			Source:    "CWE-190; Durée en nanosecondes",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityMedium,
			Window:    mustMotifWindow("timeout := time.Duration(days * 24 * 3600 * 1e9)"),
		},
		{
			ThreatID:  0x100A,
			Name:      "bigint-setuint64-sign-overflow",
			Source:    "CWE-196; Int64() sur valeur > MaxInt64",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityMedium,
			Window:    mustMotifWindow("b := new(big.Int).SetUint64(u64Val); n := b.Int64()"),
		},
		{
			ThreatID:  0x100B,
			Name:      "exponentiation-overflow-math-pow",
			Source:    "CWE-190; math.Pow en flottant puis cast",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityMedium,
			Window:    mustMotifWindow("scale := math.Pow(10, float64(decimals)); result := int64(val * scale)"),
		},
		{
			ThreatID:  0x100C,
			Name:      "slice-bound-length-overflow",
			Source:    "CWE-190; offset + length non borné",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("if offset + length > len(buffer) { debordement si wrap }"),
		},
		{
			ThreatID:  0x100D,
			Name:      "round-trip-float64-uint64-precision",
			Source:    "CWE-681; perte des bits de poids faible",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityMedium,
			Window:    mustMotifWindow("f := float64(bigIntVal); parsed := uint64(f) perte bits faibles"),
		},
		{
			ThreatID:  0x100E,
			Name:      "division-by-zero-or-modulo-uncheck",
			Source:    "CWE-369; diviseur non vérifié",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("chunkCount := totalSize / chunkSize; remainder := totalSize % chunkSize"),
		},
		{
			ThreatID:  0x100F,
			Name:      "atomic-add-wrap-counter-overflow",
			Source:    "CWE-190; compteur uint32 saturant",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityLow,
			Window:    mustMotifWindow("seq := atomic.AddUint32(&counter, 1) saturation a 4G operations"),
		},
	}
}

// BuildFlawsArithmeticCodebook encode le catalogue complet et rend un codebook
// contigu, prêt pour la recherche par distance de Hamming.
func BuildFlawsArithmeticCodebook() (*Codebook, error) {
	defs := FlawsArithmetic()
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

// SaveFlawsArithmeticCodebook écrit le catalogue encodé au format .c2book.
func SaveFlawsArithmeticCodebook(path string) error {
	cb, err := BuildFlawsArithmeticCodebook()
	if err != nil {
		return err
	}
	return SaveCodebook(path, cb.entries)
}
