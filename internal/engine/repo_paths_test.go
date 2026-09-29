package engine

import (
	"os"
	"path/filepath"
	"testing"
)

// testRepoRoot rend la racine du dépôt git qui contient le paquet. Elle
// remonte depuis le répertoire courant de go test, qui est le dossier du
// paquet, jusqu'au premier « .git » : un dossier dans un clone, un fichier
// dans un worktree lié. Aucun chemin absolu n'est supposé, si bien qu'un
// worktree lit sa propre copie de l'arbre et non l'arbre principal.
func testRepoRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("répertoire courant du test illisible : %v", err)
	}
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("racine du dépôt introuvable : aucun .git au-dessus du dossier du paquet")
		}
		dir = parent
	}
}

// testModuleRoot remonte depuis le répertoire du test jusqu'au premier go.mod ou .git.
func testModuleRoot(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("répertoire courant du test illisible : %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "."
}

// testWittgensteinDataDir résout l'emplacement des données et disquettes d'évaluation.
// Il consulte en priorité C2BLUE_DATA_DIR, puis les répertoires testdata/wittgenstein
// relatifs, puis le chemin historique /devhoros/data/wittgenstein.
func testWittgensteinDataDir(t testing.TB) string {
	t.Helper()
	if env := os.Getenv("C2BLUE_DATA_DIR"); env != "" {
		return env
	}
	root := testModuleRoot(t)
	candidates := []string{
		filepath.Join(root, "testdata", "wittgenstein"),
		filepath.Join(root, "pkg", "c2blue55", "testdata", "wittgenstein"),
	}
	for _, cand := range candidates {
		if _, err := os.Stat(filepath.Join(cand, "floppies", "floppy_lolbas.c2book")); err == nil {
			return cand
		}
	}
	return filepath.Join(root, "testdata", "wittgenstein")
}

// testExternalDir rend l'emplacement d'une ressource externe ou repli sous la racine du dépôt.
func testExternalDir(t testing.TB, env, rel string) string {
	t.Helper()
	if v := os.Getenv(env); v != "" {
		return v
	}
	return filepath.Join(testRepoRoot(t), rel)
}
