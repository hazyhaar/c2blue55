package engine

// Flaws Memory : catalogue de 15 anti-patterns de bornes mémoire et
// d'arithmétique de pointeurs observables dans les runtimes et interpréteurs
// C/C++ (Node.js src/, V8, runtime Go bas-niveau). Chaque définition porte une
// fenêtre canonique strictement inférieure à 96 octets, terminée par des NUL,
// le sous-système et la sévérité. L'encodage RaBitQ 512D réemploie
// FeatureExtractor.ExtractTo puis Encode512, sans nouvelle voie de calcul.
//
// Les quinze motifs (ThreatID 0x5001..0x500F) sont des signatures de code
// vulnérable construites pour la détection. Aucune charge réelle n'est
// revendiquée. Le vocabulaire de sous-systèmes, MotifDef, mustMotifWindow et
// EncodeMotif sont déjà déclarés par la série 05 et sont réemployés tels quels.

// FlawsMemory rend le catalogue complet des quinze motifs. L'ordre est stable,
// il suit la numérotation des identifiants de menace 0x5001 à 0x500F.
func FlawsMemory() []MotifDef {
	return []MotifDef{
		{
			ThreatID:  0x5001,
			Name:      "unchecked-offset-length-addition-wrap",
			Source:    "Arithmétique de bornes non vérifiée",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("if (offset + len > total_size) { // wrap arithmetique offset+len overflow }"),
		},
		{
			ThreatID:  0x5002,
			Name:      "memcpy-user-controlled-length-unbounded",
			Source:    "Copie sans borne de capacité",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("memcpy(dest, src, user_len); // ecriture hors bornes sans dest_cap"),
		},
		{
			ThreatID:  0x5003,
			Name:      "pointer-arithmetic-out-of-bounds",
			Source:    "Déréférencement hors bornes",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("char* ptr = base + index; *ptr = val; // depassement sans index < max"),
		},
		{
			ThreatID:  0x5004,
			Name:      "malloc-multiplication-overflow-uaf",
			Source:    "Débordement de calcul d'allocation",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("void* buf = malloc(count * size); // debordement taille petit buffer"),
		},
		{
			ThreatID:  0x5005,
			Name:      "off-by-one-null-terminator-overwrite",
			Source:    "Débordement d'un octet au terminateur",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("for (int i = 0; i <= max_len; i++) { buf[i] = input[i]; } buf[max_len] = 0;"),
		},
		{
			ThreatID:  0x5006,
			Name:      "v8-arraybuffer-backing-store-uaf",
			Source:    "V8 ArrayBuffer détaché",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("ArrayBuffer::GetBackingStore(); // acces apres detachement ArrayBuffer"),
		},
		{
			ThreatID:  0x5007,
			Name:      "snprintf-truncation-misinterpretation",
			Source:    "Troncature snprintf mal interprétée",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityMedium,
			Window:    mustMotifWindow("int n = snprintf(buf, len, \"%s\", s); buf[n] = 0; // n >= len OOB write"),
		},
		{
			ThreatID:  0x5008,
			Name:      "double-free-pointer-not-nulled",
			Source:    "Libération répétée sans remise à zéro",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("free(ptr); // pointeur non mis a NULL suivi d'un second free(ptr)"),
		},
		{
			ThreatID:  0x5009,
			Name:      "alloca-unbounded-stack-exhaustion",
			Source:    "Allocation de pile non bornée",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("char* stack_buf = (char*)alloca(user_size); // crash par stack overflow"),
		},
		{
			ThreatID:  0x500A,
			Name:      "use-after-scope-stack-pointer-escape",
			Source:    "Échappement de pointeur de pile",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("{ int temp = 42; res = &temp; } return res; // pointeur sur variable expiree"),
		},
		{
			ThreatID:  0x500B,
			Name:      "type-punning-strict-aliasing-violation",
			Source:    "Violation d'aliasing strict",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityMedium,
			Window:    mustMotifWindow("float* f = (float*)&uint32_val; // violation aliasing strict UB compilateur"),
		},
		{
			ThreatID:  0x500C,
			Name:      "format-string-user-input-printf",
			Source:    "Chaîne de format contrôlée par l'entrée",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("printf(user_input); // corruption de pile par specificateurs de format"),
		},
		{
			ThreatID:  0x500D,
			Name:      "uninitialized-struct-padding-leak",
			Source:    "Fuite par remplissage non initialisé",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityMedium,
			Window:    mustMotifWindow("struct Header h; h.id = 1; copy_to_user(dest, &h, sizeof(h)); // fuite padding"),
		},
		{
			ThreatID:  0x500E,
			Name:      "v8-turbofan-type-confusion-range",
			Source:    "V8 TurboFan Type::Range",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("Type::Range(min, max); // confusion de type elimination de verification"),
		},
		{
			ThreatID:  0x500F,
			Name:      "integer-truncation-size-t-to-int",
			Source:    "Troncation size_t vers int",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("int len = (int)size_t_val; if (len < max) memcpy(dst, src, len);"),
		},
	}
}

// BuildFlawsMemoryCodebook encode le catalogue complet et rend un codebook
// contigu, prêt pour la recherche par distance de Hamming.
func BuildFlawsMemoryCodebook() (*Codebook, error) {
	defs := FlawsMemory()
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

// SaveFlawsMemoryCodebook écrit le catalogue encodé au format .c2book.
func SaveFlawsMemoryCodebook(path string) error {
	cb, err := BuildFlawsMemoryCodebook()
	if err != nil {
		return err
	}
	return SaveCodebook(path, cb.entries)
}
