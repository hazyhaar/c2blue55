package projlearn_test

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/projlearn"
)

func TestCheckpoint_RoundTrip(t *testing.T) {
	cfg := projlearn.DefaultConfig()
	params := projlearn.NewParams(cfg, 7)
	requireShapes(t, params, cfg)
	dir := t.TempDir()
	path := filepath.Join(dir, "model.c2pl")
	const step = 17
	if err := projlearn.SaveCheckpoint(path, params, cfg, step); err != nil {
		t.Fatalf("SaveCheckpoint: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("point de contrôle absent après SaveCheckpoint: %v", err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, attendu 0600", st.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("lecture du répertoire: %v", err)
	}
	for _, entry := range entries {
		if bytes.Contains([]byte(entry.Name()), []byte(".tmp")) {
			t.Fatalf("fichier temporaire résiduel: %s", entry.Name())
		}
	}
	loaded, loadedCfg, loadedStep, err := projlearn.LoadCheckpoint(path)
	if err != nil {
		t.Fatalf("LoadCheckpoint: %v", err)
	}
	if loaded == nil {
		t.Fatal("LoadCheckpoint a rendu des paramètres nil")
	}
	requireShapes(t, loaded, cfg)
	if loadedCfg != cfg {
		t.Fatalf("cfg rechargée %+v, attendu %+v", loadedCfg, cfg)
	}
	if loadedStep != step {
		t.Fatalf("step rechargé %d, attendu %d", loadedStep, step)
	}
	pairs := []struct {
		name string
		got  []float32
		want []float32
	}{
		{"Embed", loaded.Embed, params.Embed},
		{"ConvW", loaded.ConvW, params.ConvW},
		{"ConvB", loaded.ConvB, params.ConvB},
		{"Dense1W", loaded.Dense1W, params.Dense1W},
		{"Dense1B", loaded.Dense1B, params.Dense1B},
		{"Dense2W", loaded.Dense2W, params.Dense2W},
		{"Dense2B", loaded.Dense2B, params.Dense2B},
		{"ReadoutW", loaded.ReadoutW, params.ReadoutW},
		{"ReadoutB", loaded.ReadoutB, params.ReadoutB},
	}
	for _, pair := range pairs {
		if !slices.Equal(pair.got, pair.want) {
			t.Fatalf("%s non restitué", pair.name)
		}
	}
}

func savedPair(t *testing.T) (dir string, bodyA, bodyB []byte) {
	t.Helper()
	cfg := projlearn.DefaultConfig()
	first := projlearn.NewParams(cfg, 7)
	second := projlearn.NewParams(cfg, 8)
	requireShapes(t, first, cfg)
	requireShapes(t, second, cfg)
	dir = t.TempDir()
	pathA := filepath.Join(dir, "seed-a.c2pl")
	pathB := filepath.Join(dir, "seed-b.c2pl")
	if err := projlearn.SaveCheckpoint(pathA, first, cfg, 17); err != nil {
		t.Fatalf("SaveCheckpoint A: %v", err)
	}
	if err := projlearn.SaveCheckpoint(pathB, second, cfg, 17); err != nil {
		t.Fatalf("SaveCheckpoint B: %v", err)
	}
	var err error
	bodyA, err = os.ReadFile(pathA)
	if err != nil {
		t.Fatalf("lecture A: %v", err)
	}
	bodyB, err = os.ReadFile(pathB)
	if err != nil {
		t.Fatalf("lecture B: %v", err)
	}
	if len(bodyA) < 40 || len(bodyB) != len(bodyA) {
		t.Fatalf("points de contrôle inutilisables: %d et %d octets", len(bodyA), len(bodyB))
	}
	return dir, bodyA, bodyB
}

func bodyByte(t *testing.T, bodyA, bodyB []byte) int {
	t.Helper()
	if len(bodyA) < 33 {
		t.Fatalf("fichier trop court: %d", len(bodyA))
	}
	limit := len(bodyA) - 32
	for i := range limit {
		if bodyA[i] != bodyB[i] {
			return i
		}
	}
	t.Fatal("aucun octet de corps ne diffère entre deux graines")
	return -1
}

func expectIntegrityRefusal(t *testing.T, path string) {
	t.Helper()
	loaded, _, _, err := projlearn.LoadCheckpoint(path)
	if !errors.Is(err, projlearn.ErrCheckpointIntegrity) {
		t.Fatalf("erreur=%v, attendu ErrCheckpointIntegrity", err)
	}
	if loaded != nil {
		t.Fatal("paramètres partiels rendus")
	}
}

func TestCheckpoint_IntegrityRefusals(t *testing.T) {
	t.Run("fichier_absent", func(t *testing.T) {
		absentPath := filepath.Join(t.TempDir(), "absent.c2pl")
		loaded, _, _, err := projlearn.LoadCheckpoint(absentPath)
		if err == nil {
			t.Fatal("fichier absent: erreur attendue absente")
		}
		if errors.Is(err, projlearn.ErrCheckpointIntegrity) {
			t.Fatalf("fichier absent classé à tort comme intégrité: %v", err)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("fichier absent: %v n'enveloppe pas fs.ErrNotExist", err)
		}
		if loaded != nil {
			t.Fatal("fichier absent: paramètres rendus")
		}
	})
	t.Run("octet_du_corps_inversé", func(t *testing.T) {
		dir, bodyA, bodyB := savedPair(t)
		at := bodyByte(t, bodyA, bodyB)
		mutated := append([]byte(nil), bodyA...)
		mutated[at] ^= 0xFF
		path := filepath.Join(dir, "corps.c2pl")
		if err := os.WriteFile(path, mutated, 0o600); err != nil {
			t.Fatalf("écriture: %v", err)
		}
		expectIntegrityRefusal(t, path)
	})
	t.Run("magic_altéré", func(t *testing.T) {
		dir, bodyA, _ := savedPair(t)
		at := bytes.Index(bodyA, []byte("C2PL1"))
		if at < 0 {
			t.Fatal("magic C2PL1 absent du point de contrôle")
		}
		mutated := append([]byte(nil), bodyA...)
		mutated[at] ^= 0xFF
		path := filepath.Join(dir, "magic.c2pl")
		if err := os.WriteFile(path, mutated, 0o600); err != nil {
			t.Fatalf("écriture: %v", err)
		}
		expectIntegrityRefusal(t, path)
	})
	t.Run("fichier_tronqué", func(t *testing.T) {
		dir, bodyA, _ := savedPair(t)
		if len(bodyA) <= 7 {
			t.Fatalf("fichier trop court pour une troncature de 7 octets: %d", len(bodyA))
		}
		path := filepath.Join(dir, "tronque.c2pl")
		if err := os.WriteFile(path, bodyA[:len(bodyA)-7], 0o600); err != nil {
			t.Fatalf("écriture: %v", err)
		}
		expectIntegrityRefusal(t, path)
	})
}
