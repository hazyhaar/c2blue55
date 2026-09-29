package engine

import (
	"math/bits"
	"path/filepath"
	"testing"
)

func TestFlawsConcurrencyCatalog(t *testing.T) {
	defs := FlawsConcurrency()
	if len(defs) != 15 {
		t.Fatalf("FlawsConcurrency: %d définitions, attendu 15", len(defs))
	}

	type attendu struct {
		subsystem uint16
		action    uint16
		severity  uint16
	}
	attenduParID := map[uint32]attendu{
		0x3001: {motifSubProc, motifActExec, SeverityCritical},
		0x3002: {motifSubFile, motifActRead, SeverityHigh},
		0x3003: {motifSubProc, motifActExec, SeverityHigh},
		0x3004: {motifSubProc, motifActExec, SeverityHigh},
		0x3005: {motifSubProc, motifActExec, SeverityCritical},
		0x3006: {motifSubProc, motifActExec, SeverityHigh},
		0x3007: {motifSubProc, motifActExec, SeverityHigh},
		0x3008: {motifSubProc, motifActExec, SeverityCritical},
		0x3009: {motifSubProc, motifActExec, SeverityHigh},
		0x300A: {motifSubProc, motifActExec, SeverityCritical},
		0x300B: {motifSubProc, motifActExec, SeverityMedium},
		0x300C: {motifSubFile, motifActRead, SeverityHigh},
		0x300D: {motifSubProc, motifActExec, SeverityHigh},
		0x300E: {motifSubProc, motifActExec, SeverityMedium},
		0x300F: {motifSubProc, motifActExec, SeverityHigh},
	}

	seen := make(map[uint32]string, len(defs))
	for i := range defs {
		d := &defs[i]
		if d.ThreatID == 0 {
			t.Fatalf("motif %d: identifiant nul", i)
		}
		if prev, ok := seen[d.ThreatID]; ok {
			t.Fatalf("motif %d: identifiant 0x%04X déjà porté par %s", i, d.ThreatID, prev)
		}
		seen[d.ThreatID] = d.Name

		want, ok := attenduParID[d.ThreatID]
		if !ok {
			t.Fatalf("motif 0x%04X: identifiant hors catalogue attendu", d.ThreatID)
		}
		if d.Subsystem != want.subsystem {
			t.Fatalf("motif 0x%04X: sous-système %d, attendu %d", d.ThreatID, d.Subsystem, want.subsystem)
		}
		if d.Action != want.action {
			t.Fatalf("motif 0x%04X: action %d, attendue %d", d.ThreatID, d.Action, want.action)
		}
		if d.Severity != want.severity {
			t.Fatalf("motif 0x%04X: sévérité %d, attendue %d", d.ThreatID, d.Severity, want.severity)
		}
		if d.Severity < SeverityLow || d.Severity > SeverityCritical {
			t.Fatalf("motif %s: sévérité %d hors bornes 1..4", d.Name, d.Severity)
		}
		if d.Name == "" || d.Source == "" {
			t.Fatalf("motif 0x%04X: nom ou source vide", d.ThreatID)
		}

		n := 0
		for n < FeaturePayloadBytes && d.Window[n] != 0 {
			n++
		}
		if n == 0 {
			t.Fatalf("motif %s: fenêtre vide", d.Name)
		}
		if n == FeaturePayloadBytes {
			t.Fatalf("motif %s: fenêtre non terminée sur 96 octets", d.Name)
		}
	}

	for id := range attenduParID {
		if _, ok := seen[id]; !ok {
			t.Fatalf("motif 0x%04X absent du catalogue", id)
		}
	}
}

func TestFlawsConcurrencyEncoding(t *testing.T) {
	cb, err := BuildFlawsConcurrencyCodebook()
	if err != nil {
		t.Fatalf("BuildFlawsConcurrencyCodebook: %v", err)
	}
	if cb.Len() != 15 {
		t.Fatalf("codebook: %d entrées, attendu 15", cb.Len())
	}
	entries := cb.entries

	for i := range entries {
		got, dist, found := cb.SearchNearest(&entries[i].Bitcode, 0)
		if !found || dist != 0 {
			t.Fatalf("entrée %d (0x%04X): recherche exacte trouvée=%v distance=%d", i, entries[i].ThreatID, found, dist)
		}
		if got.ThreatID != entries[i].ThreatID {
			t.Fatalf("entrée %d: ThreatID rendu 0x%04X, attendu 0x%04X (collision de bitcode)", i, got.ThreatID, entries[i].ThreatID)
		}
	}

	minDist := 1 << 30
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			d := 0
			for k := 0; k < codebookWords; k++ {
				d += bits.OnesCount64(entries[i].Bitcode[k] ^ entries[j].Bitcode[k])
			}
			if d == 0 {
				t.Fatalf("bitcodes identiques entre 0x%04X et 0x%04X", entries[i].ThreatID, entries[j].ThreatID)
			}
			if d < minDist {
				minDist = d
			}
		}
	}
	t.Logf("distance de Hamming minimale entre motifs : %d", minDist)
}

func TestFlawsConcurrencySaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flaws-concurrency.c2book")
	if err := SaveFlawsConcurrencyCodebook(path); err != nil {
		t.Fatalf("SaveFlawsConcurrencyCodebook: %v", err)
	}
	loaded, err := LoadCodebook(path)
	if err != nil {
		t.Fatalf("LoadCodebook: %v", err)
	}
	built, err := BuildFlawsConcurrencyCodebook()
	if err != nil {
		t.Fatalf("BuildFlawsConcurrencyCodebook: %v", err)
	}
	if loaded.Len() != built.Len() {
		t.Fatalf("taille relue %d, attendue %d", loaded.Len(), built.Len())
	}
	for i := range built.entries {
		if loaded.entries[i] != built.entries[i] {
			t.Fatalf("entrée %d divergente après aller-retour (0x%04X)", i, built.entries[i].ThreatID)
		}
	}
}
