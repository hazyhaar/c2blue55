// Package main — floppy_builder_test.go
// Test d'intégration de forgerie des 3 disquettes et validation du chargement mmap.
package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

func resolveWittgensteinDataDir(t testing.TB) string {
	t.Helper()
	if env := os.Getenv("C2BLUE_DATA_DIR"); env != "" {
		return env
	}
	candidates := []string{
		"../../testdata/wittgenstein",
		"testdata/wittgenstein",
		"pkg/c2blue55/testdata/wittgenstein",
		"../../../pkg/c2blue55/testdata/wittgenstein",
	}
	for _, cand := range candidates {
		if _, err := os.Stat(filepath.Join(cand, "floppies", "floppy_lolbas.c2book")); err == nil {
			return cand
		}
	}
	return "../../testdata/wittgenstein"
}

// TestWittgenstein_Floppies_Rebuild éprouve la forgerie complète à partir des données brutes
// lorsqu'elles sont présentes, et consigne un SKIP explicite si elles manquent.
func TestWittgenstein_Floppies_Rebuild(t *testing.T) {
	dataDir := resolveWittgensteinDataDir(t)
	if _, err := os.Stat(filepath.Join(dataDir, "netrack_dns", "train.csv")); err != nil {
		t.Skip("sources d'apprentissage brutes absentes (netrack_dns/train.csv) : forgerie omise, disquettes pré-compilées testées dans TestWittgenstein_Floppies_BuildAndLoad")
	}
	if _, err := os.Stat(filepath.Join(dataDir, "lakera_agent_attacks.csv")); err != nil {
		t.Skip("sources d'apprentissage brutes absentes (lakera_agent_attacks.csv) : forgerie omise, disquettes pré-compilées testées dans TestWittgenstein_Floppies_BuildAndLoad")
	}
	tmpOut := t.TempDir()
	if err := BuildWittgensteinFloppies(dataDir, tmpOut); err != nil {
		t.Fatalf("BuildWittgensteinFloppies a échoué: %v", err)
	}
}

func TestWittgenstein_Floppies_BuildAndLoad(t *testing.T) {
	dataDir := resolveWittgensteinDataDir(t)
	outDir := filepath.Join(dataDir, "floppies")

	floppyTests := []struct {
		filename string
		family   uint16
	}{
		{"floppy_lolbas.c2book", engine.FloppyFamilyLOLBAS},
		{"floppy_dns_c2.c2book", engine.FloppyFamilyDNSC2},
		{"floppy_agent_mcp.c2book", engine.FloppyFamilyAgentMCP},
	}

	slot := engine.NewFloppySlot()

	for _, ft := range floppyTests {
		p := filepath.Join(outDir, ft.filename)
		// Une clé erronée doit faire refuser la disquette scellée.
		if bad, err := engine.LoadFloppyMmap(p, []byte("cle-erronee")); err == nil {
			bad.Close()
			t.Fatalf("LoadFloppyMmap(%s) a accepté une clé HMAC erronée", ft.filename)
		} else if !errors.Is(err, engine.ErrFloppySeal) {
			t.Fatalf("LoadFloppyMmap(%s) attendait ErrFloppySeal, a eu: %v", ft.filename, err)
		}
		// Une disquette scellée chargée sans clé doit être rejetée avec ErrFloppyUnsealed.
		if bad, err := engine.LoadFloppyMmap(p, nil); err == nil {
			bad.Close()
			t.Fatalf("LoadFloppyMmap(%s) a accepté un chargement sans clé d'une disquette scellée", ft.filename)
		} else if !errors.Is(err, engine.ErrFloppyUnsealed) {
			t.Fatalf("LoadFloppyMmap(%s) sans clé attendait ErrFloppyUnsealed, a eu: %v", ft.filename, err)
		}
		disk, err := engine.LoadFloppyMmap(p, engine.WittgensteinFloppyKey(ft.family))
		if err != nil {
			t.Fatalf("LoadFloppyMmap(%s) a échoué: %v", ft.filename, err)
		}
		if disk.Header.Flags&engine.FloppyFlagSealed == 0 {
			t.Errorf("%s n'est pas scellée", ft.filename)
		}
		t.Logf("%s : %d centroïdes, %d prototypes L1a, rayon de veto calibré %d bits", ft.filename, disk.Header.EntryCount, len(disk.Prototypes), disk.BlockRadius())
		// La sonde conforme L1a doit être embarquée, avec des prototypes des deux classes.
		var perClass [2]int
		for _, pr := range disk.Prototypes {
			perClass[pr.Class]++
		}
		if perClass[0] == 0 || perClass[1] == 0 || disk.Probe() == nil {
			t.Errorf("%s : prototypes L1a bénins=%d hostiles=%d, sonde=%v", ft.filename, perClass[0], perClass[1], disk.Probe() != nil)
		}
		if disk.Header.FamilyID != ft.family {
			t.Errorf("FamilyID pour %s = %d, attendu %d", ft.filename, disk.Header.FamilyID, ft.family)
		}
		if disk.Header.EntryCount == 0 {
			t.Errorf("EntryCount = 0 pour %s", ft.filename)
		}
		if len(disk.Keywords) == 0 {
			t.Errorf("Aucun mot-clé pour %s", ft.filename)
		}
		if len(disk.Head) == 0 {
			t.Errorf("Aucune classe DecisionHead pour %s", ft.filename)
		}

		// Commutation atomique O(1) sans blocage
		old := slot.Swap(disk)
		if old != nil {
			_ = old.Close()
		}

		cur := slot.Current()
		if cur == nil || cur.Header.FamilyID != ft.family {
			t.Errorf("FloppySlot n'a pas commuté vers la famille %d", ft.family)
		}

		// Test de prédiction INT8 sur le vecteur nul
		var dummyVec [engine.EmbeddingDim]float32
		cls, score, _ := cur.PredictINT8(dummyVec[:])
		if cls < 0 {
			t.Errorf("PredictINT8 a échoué pour %s: cls=%d, score=%d", ft.filename, cls, score)
		}
	}

	// La disquette LOLBAS ne contient que la partition d'apprentissage : aucun
	// reverse shell tenu à l'écart ne doit y avoir un centroïde identique.
	assertLOLBASHoldoutExcluded(t, dataDir, filepath.Join(outDir, "floppy_lolbas.c2book"))

	// Nettoyage final
	if cur := slot.Current(); cur != nil {
		_ = cur.Close()
	}
}

func assertLOLBASHoldoutExcluded(t *testing.T, dataDir, path string) {
	t.Helper()
	shells, err := engine.LoadReverseShellPayloads(filepath.Join(dataDir, "reverse_shells.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	nTrain := engine.ReverseShellTrainCount(len(shells))
	disk, err := engine.LoadFloppyMmap(path, engine.WittgensteinFloppyKey(engine.FloppyFamilyLOLBAS))
	if err != nil {
		t.Fatal(err)
	}
	defer disk.Close()
	if int(disk.Header.EntryCount) > nTrain {
		t.Fatalf("EntryCount LOLBAS = %d, supérieur à la partition d'apprentissage (%d)", disk.Header.EntryCount, nTrain)
	}
	trainCodes := map[[engine.EmbeddingDim / 64]uint64]bool{}
	fe := engine.NewFeatureExtractor()
	arena := engine.NewArenaPool()
	for _, p := range shells[:nTrain] {
		if v, ok := embedEvent(&fe, arena, 1, 1, []byte(p)); ok {
			var code [engine.EmbeddingDim / 64]uint64
			engine.QuantizeFHT512(v[:], &code)
			trainCodes[code] = true
		}
	}
	leaks := 0
	for _, p := range shells[nTrain:] {
		v, ok := embedEvent(&fe, arena, 1, 1, []byte(p))
		if !ok {
			continue
		}
		var code [engine.EmbeddingDim / 64]uint64
		engine.QuantizeFHT512(v[:], &code)
		if trainCodes[code] {
			continue // code identique à un shell d'apprentissage : pas une fuite de partition
		}
		for i := range disk.Entries {
			if disk.Entries[i].Bitcode == code {
				leaks++
				break
			}
		}
	}
	if leaks != 0 {
		t.Fatalf("%d reverse shells tenus à l'écart figurent comme centroïdes LOLBAS", leaks)
	}
	t.Logf("partition LOLBAS : %d centroïdes d'apprentissage, %d shells tenus à l'écart, 0 fuite, rayon de veto %d", disk.Header.EntryCount, len(shells)-nTrain, disk.BlockRadius())
}
