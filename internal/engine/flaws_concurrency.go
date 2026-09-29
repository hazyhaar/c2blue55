package engine

// Flaws concurrency : catalogue de signatures vectorisant quinze anti-patterns
// de concurrence mal synchronisée, d'accès concurrents non protégés à des
// structures partagées et de fenêtres de temps de vérification-utilisation
// (TOCTOU, time-of-check to time-of-use) caractéristiques des modules Go
// complexes, notamment les nœuds de consensus et les clients de chaînes.
//
// Chaque définition porte une fenêtre canonique de moins de 96 octets, le
// sous-système et la sévérité. L'encodage RaBitQ 512D réemploie la voie réelle
// du moteur, à savoir FeatureExtractor.ExtractTo puis Encode512 via EncodeMotif,
// sans nouvelle voie de calcul. Les constantes de vocabulaire, MotifDef,
// mustMotifWindow et EncodeMotif sont déjà déclarés par la série 05 et sont
// réemployés tels quels.
//
// Les quinze motifs (ThreatID 0x3001..0x300F) décrivent des signatures de code
// vulnérable construites pour la détection. Aucune charge réelle n'est
// revendiquée.

// FlawsConcurrency rend le catalogue complet des quinze anti-patterns de
// concurrence. L'ordre suit la séquence stable des identifiants de menace.
func FlawsConcurrency() []MotifDef {
	return []MotifDef{
		{
			ThreatID:  0x3001,
			Name:      "map-write-outside-mutex-lock",
			Source:    "Go runtime fatal error: concurrent map writes",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("m[key] = value; // fatal error: concurrent map writes sans mu.Lock()"),
		},
		{
			ThreatID:  0x3002,
			Name:      "toctou-os-stat-then-os-open",
			Source:    "TOCTOU: os.Stat suivi de os.OpenFile sous O_CREATE",
			Subsystem: motifSubFile,
			Action:    motifActRead,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("if _, err := os.Stat(path); err == nil { f, _ := os.OpenFile(path, O_CREATE, 0600) }"),
		},
		{
			ThreatID:  0x3003,
			Name:      "goroutine-closure-loop-variable-capture",
			Source:    "Go < 1.22: capture de la variable de boucle par la goroutine",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("for _, item := range items { go func() { process(item) }() }"),
		},
		{
			ThreatID:  0x3004,
			Name:      "double-check-locking-missing-memory-barrier",
			Source:    "Double-checked locking sans barrière mémoire explicite",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("if instance == nil { mu.Lock(); if instance == nil { instance = new() } mu.Unlock() }"),
		},
		{
			ThreatID:  0x3005,
			Name:      "mutex-unlock-premature-state-exposure",
			Source:    "Publication d'un état intermédiaire après déverrouillage",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("mu.Unlock(); ch <- state; // état intermédiaire exposé avant commit global"),
		},
		{
			ThreatID:  0x3006,
			Name:      "atomic-load-then-non-atomic-store",
			Source:    "Lecture atomique suivie d'écriture non atomique sans CAS",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("val := atomic.LoadUint64(&flag); if val == 0 { flag = 1 } // race sans CAS"),
		},
		{
			ThreatID:  0x3007,
			Name:      "sync-waitgroup-add-inside-goroutine",
			Source:    "sync.WaitGroup: Add appelé dans la goroutine, en course avec Wait",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("go func() { wg.Add(1); defer wg.Done(); work() }() // race avec wg.Wait()"),
		},
		{
			ThreatID:  0x3008,
			Name:      "channel-close-on-active-producer-race",
			Source:    "panic: send on closed channel sous producteur actif",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("close(ch); ch <- event; // panic: send on closed channel sous concurrence"),
		},
		{
			ThreatID:  0x3009,
			Name:      "slice-concurrent-append-data-race",
			Source:    "append concurrent sur tranche partagée: corruption du backing array",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("go func() { list = append(list, elem) }() // corruption de backing array"),
		},
		{
			ThreatID:  0x300A,
			Name:      "rwmutex-rlock-upgrade-deadlock",
			Source:    "sync.RWMutex: acquisition de Lock sous un RLock déjà tenu",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("rw.RLock(); if needUpdate { rw.Lock(); update() } // deadlock récursif"),
		},
		{
			ThreatID:  0x300B,
			Name:      "context-done-leak-in-select",
			Source:    "select sans case <-ctx.Done(): fuite de goroutine possible",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityMedium,
			Window:    mustMotifWindow("select { case ch <- val: default: } // fuite de goroutine sans case <-ctx.Done()"),
		},
		{
			ThreatID:  0x300C,
			Name:      "file-read-after-close-race",
			Source:    "os.File: Close concurrent de Read, descripteur fermé en vol",
			Subsystem: motifSubFile,
			Action:    motifActRead,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("go f.Close(); n, err := f.Read(buf); // descripteur fermé en vol"),
		},
		{
			ThreatID:  0x300D,
			Name:      "sync-pool-retained-pointer-after-put",
			Source:    "sync.Pool: réutilisation d'un objet après Put",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("pool.Put(buf); useBuffer(buf); // réutilisation d'objet libéré en pool"),
		},
		{
			ThreatID:  0x300E,
			Name:      "time-after-leak-in-hot-loop",
			Source:    "time.After dans une boucle chaude: fuite de minuteur par itération",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityMedium,
			Window:    mustMotifWindow("select { case <-ch: case <-time.After(time.Second): // fuite timer à chaque itération }"),
		},
		{
			ThreatID:  0x300F,
			Name:      "atomic-pointer-nil-dereference-race",
			Source:    "atomic.LoadPointer suivi d'un déréférencement sans contrôle de nil",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("ptr := atomic.LoadPointer(&p); (*Data)(ptr).Field // déréférencement sans check nil"),
		},
	}
}

// BuildFlawsConcurrencyCodebook encode le catalogue complet et rend un codebook
// contigu, prêt pour la recherche par distance de Hamming.
func BuildFlawsConcurrencyCodebook() (*Codebook, error) {
	defs := FlawsConcurrency()
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

// SaveFlawsConcurrencyCodebook écrit le catalogue encodé au format .c2book.
func SaveFlawsConcurrencyCodebook(path string) error {
	cb, err := BuildFlawsConcurrencyCodebook()
	if err != nil {
		return err
	}
	return SaveCodebook(path, cb.entries)
}
