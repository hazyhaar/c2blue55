package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAuditForgeEchoueSurFichierIllisible(t *testing.T) {
	repSource := t.TempDir()
	repSortie := t.TempDir()

	cheminValide := filepath.Join(repSource, "valide.bin")
	if err := os.WriteFile(cheminValide, []byte("charge-valide-123456"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	cheminCasse := filepath.Join(repSource, "casse.bin")
	if err := os.Symlink(filepath.Join(repSource, "absent.bin"), cheminCasse); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	cheminBook := filepath.Join(repSortie, "resultat-audit.c2book")
	sortieStd, sortieErr, codeSortie := forge(t, "-in", repSource, "-out", cheminBook)
	if codeSortie == 0 {
		t.Fatalf("c2forge a ignore silencieusement un fichier illisible (codeSortie=0)\nstdout=%s\nstderr=%s", sortieStd, sortieErr)
	}
	if _, errStat := os.Stat(cheminBook); !errors.Is(errStat, os.ErrNotExist) {
		t.Fatalf("le codebook %s ne devait pas etre cree apres erreur de lecture (errStat=%v)", cheminBook, errStat)
	}
}
