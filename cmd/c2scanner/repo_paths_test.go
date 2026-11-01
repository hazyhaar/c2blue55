package main

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

// testExternalDir rend l'emplacement d'une ressource que l'arbre suivi ne
// contient pas (dépôt imbriqué ou zone ignorée par git) : la valeur de la
// variable d'environnement env si elle est posée, sinon rel sous la racine du
// dépôt. Elle ne vérifie pas l'existence : l'appelant garde sa propre règle
// d'absence.
func testExternalDir(t testing.TB, env, rel string) string {
	t.Helper()
	if v := os.Getenv(env); v != "" {
		return v
	}
	return filepath.Join(testRepoRoot(t), rel)
}

// testRequireExternal résout la ressource comme testExternalDir et exige sa
// présence. Une variable posée qui désigne un chemin absent fait échouer le
// test, car la configuration est alors fausse. Sans variable, une ressource
// absente saute le test en nommant la variable à poser : un worktree lié ou
// un clone neuf ne contient pas ce qui vit hors de l'arbre suivi.
func testRequireExternal(t testing.TB, env, rel string) string {
	t.Helper()
	if v := os.Getenv(env); v != "" {
		if _, err := os.Stat(v); err != nil {
			t.Fatalf("%s=%s inaccessible : %v", env, v, err)
		}
		return v
	}
	p := testExternalDir(t, env, rel)
	if _, err := os.Stat(p); err != nil {
		t.Skipf("ressource hors de l'arbre suivi absente : %s (%v) ; poser %s pour exécuter ce test depuis un worktree lié ou un clone", p, err, env)
	}
	return p
}
