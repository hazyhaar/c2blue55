package engine

import (
	"math/bits"
	"path/filepath"
	"testing"
)

func TestFlawsArithmeticCatalog(t *testing.T) {
	defs := FlawsArithmetic()
	if len(defs) != 15 {
		t.Fatalf("FlawsArithmetic: %d définitions, attendu 15", len(defs))
	}
	seen := make(map[uint32]string, len(defs))
	for i := range defs {
		d := &defs[i]
		if d.ThreatID < 0x1001 || d.ThreatID > 0x100F {
			t.Fatalf("motif %d: ThreatID 0x%04X hors plage 0x1001..0x100F", i, d.ThreatID)
		}
		if prev, ok := seen[d.ThreatID]; ok {
			t.Fatalf("motif %d: identifiant 0x%04X déjà porté par %s", i, d.ThreatID, prev)
		}
		seen[d.ThreatID] = d.Name

		if d.Subsystem != motifSubProc {
			t.Fatalf("motif %s: sous-système %d, attendu motifSubProc", d.Name, d.Subsystem)
		}
		if d.Action != motifActExec {
			t.Fatalf("motif %s: action %d, attendue motifActExec", d.Name, d.Action)
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
		if n >= FeaturePayloadBytes {
			t.Fatalf("motif %s: fenêtre non terminée par NUL sur %d octets", d.Name, FeaturePayloadBytes)
		}
	}
}

func TestFlawsArithmeticEncoding(t *testing.T) {
	cb, err := BuildFlawsArithmeticCodebook()
	if err != nil {
		t.Fatalf("BuildFlawsArithmeticCodebook: %v", err)
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

func TestFlawsArithmeticSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "flaws-arithmetic.c2book")
	if err := SaveFlawsArithmeticCodebook(path); err != nil {
		t.Fatalf("SaveFlawsArithmeticCodebook: %v", err)
	}
	loaded, err := LoadCodebook(path)
	if err != nil {
		t.Fatalf("LoadCodebook: %v", err)
	}
	built, err := BuildFlawsArithmeticCodebook()
	if err != nil {
		t.Fatalf("BuildFlawsArithmeticCodebook: %v", err)
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
