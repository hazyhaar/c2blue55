package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFlawsAllCountAndUnicity(t *testing.T) {
	defs := FlawsAll()
	if len(defs) != 75 {
		t.Fatalf("attendu 75 motifs, obtenu %d", len(defs))
	}

	seenIDs := make(map[uint32]string)
	seenNames := make(map[string]uint32)

	for _, m := range defs {
		if prev, ok := seenIDs[m.ThreatID]; ok {
			t.Errorf("ThreatID dupliqué 0x%X pour '%s' (déjà utilisé par '%s')", m.ThreatID, m.Name, prev)
		}
		seenIDs[m.ThreatID] = m.Name

		if prevID, ok := seenNames[m.Name]; ok {
			t.Errorf("Nom de motif dupliqué '%s' pour 0x%X (déjà utilisé par 0x%X)", m.Name, m.ThreatID, prevID)
		}
		seenNames[m.Name] = m.ThreatID

		if len(m.Window) != 96 {
			t.Errorf("motif %s (0x%X) a une fenêtre de taille invalide: %d octets", m.Name, m.ThreatID, len(m.Window))
		}
	}
}

func TestBuildFlawsAllCodebook(t *testing.T) {
	cb, err := BuildFlawsAllCodebook()
	if err != nil {
		t.Fatalf("erreur encodage codebook complet: %v", err)
	}
	if cb.Len() != 75 {
		t.Fatalf("attendu 75 entrées dans le codebook, obtenu %d", cb.Len())
	}

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "patterns_code_flaws.c2book")

	if err := SaveFlawsAllCodebook(path); err != nil {
		t.Fatalf("erreur sauvegarde codebook: %v", err)
	}

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("fichier .c2book non trouvé: %v", err)
	}
	if fi.Size() == 0 {
		t.Fatalf("fichier .c2book vide")
	}

	loaded, err := LoadCodebook(path)
	if err != nil {
		t.Fatalf("erreur rechargement .c2book: %v", err)
	}
	if loaded.Len() != 75 {
		t.Fatalf("attendu 75 entrées rechargées, obtenu %d", loaded.Len())
	}
}
