package engine

import (
	"path/filepath"
	"testing"
)

func TestMotifsCroisesAllCatalog(t *testing.T) {
	defs := MotifsCroisesAll()
	if len(defs) != 75 {
		t.Fatalf("MotifsCroisesAll: %d définitions, attendu 75", len(defs))
	}

	seen := make(map[uint32]string, len(defs))
	for i := range defs {
		d := &defs[i]
		if d.ThreatID == 0 {
			t.Fatalf("motif %d: identifiant nul", i)
		}
		if prev, ok := seen[d.ThreatID]; ok {
			t.Fatalf("motif %d: collision ThreatID 0x%04X entre %s et %s", i, d.ThreatID, d.Name, prev)
		}
		seen[d.ThreatID] = d.Name

		if d.Name == "" || d.Source == "" {
			t.Fatalf("motif 0x%04X: nom ou source vide", d.ThreatID)
		}
	}
}

func TestMotifsCroisesAllEncoding(t *testing.T) {
	cb, err := BuildMotifsCroisesAllCodebook()
	if err != nil {
		t.Fatalf("BuildMotifsCroisesAllCodebook: %v", err)
	}
	if cb.Len() != 75 {
		t.Fatalf("codebook: %d entrées, attendu 75", cb.Len())
	}

	// Exact match retrieval for all 75 entries
	for i := range cb.entries {
		entry := &cb.entries[i]
		got, dist, found := cb.SearchNearest(&entry.Bitcode, 0)
		if !found || dist != 0 {
			t.Fatalf("entrée %d (0x%04X): recherche exacte trouvée=%v distance=%d", i, entry.ThreatID, found, dist)
		}
		if got.ThreatID != entry.ThreatID {
			t.Fatalf("entrée %d: ThreatID rendu 0x%04X, attendu 0x%04X", i, got.ThreatID, entry.ThreatID)
		}
	}
}

func TestMotifsCroisesAllSaveLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "motifs-croises-all.c2book")
	if err := SaveMotifsCroisesAllCodebook(path); err != nil {
		t.Fatalf("SaveMotifsCroisesAllCodebook: %v", err)
	}
	loaded, err := LoadCodebook(path)
	if err != nil {
		t.Fatalf("LoadCodebook: %v", err)
	}
	if loaded.Len() != 75 {
		t.Fatalf("taille relue %d, attendue 75", loaded.Len())
	}
}
