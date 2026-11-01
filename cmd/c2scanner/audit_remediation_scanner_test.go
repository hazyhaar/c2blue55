package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/engine"
)

func TestAuditScannerRefuseTroncatureSilencieuse16Mio(t *testing.T) {
	repTravail := t.TempDir()
	cheminBook := filepath.Join(repTravail, "audit.c2book")
	var bitsEntree [bitcodeWords]uint64
	bitsEntree[0] = 0xdeadbeefcafebabe
	if err := engine.SaveCodebook(cheminBook, []engine.CodebookEntry{
		{Bitcode: bitsEntree, ThreatID: 1, Subsystem: 1, Severity: 2},
	}); err != nil {
		t.Fatalf("SaveCodebook: %v", err)
	}

	repCible := filepath.Join(repTravail, "cible")
	if err := os.MkdirAll(repCible, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	cheminFichierGeant := filepath.Join(repCible, "depasse-16mio.bin")
	fichierGeant, err := os.OpenFile(cheminFichierGeant, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if err := fichierGeant.Truncate(maxFileBytes + 4096); err != nil {
		_ = fichierGeant.Close()
		t.Fatalf("Truncate: %v", err)
	}
	if err := fichierGeant.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var sortie bytes.Buffer
	_, errScan := runScan(scanConfig{
		bookPath:  cheminBook,
		target:    repCible,
		threshold: 0,
		stride:    32,
		cores:     1,
		out:       &sortie,
	})
	if errScan == nil {
		t.Fatalf("runScan a tronque silencieusement un fichier de %d octets (> maxFileBytes=%d) sans erreur",
			maxFileBytes+4096, maxFileBytes)
	}
}
