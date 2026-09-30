// Package engine — wittgenstein_corpus_test.go
package engine

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"
)

func TestWittgensteinFloppyKey_ResolutionAndEnforcement(t *testing.T) {
	// 1. Clé par défaut (mode démonstration)
	defaultKey := WittgensteinFloppyKey(FloppyFamilyLOLBAS)
	if len(defaultKey) == 0 {
		t.Fatalf("clé par défaut vide")
	}
	if !bytes.Equal(defaultKey, []byte(defaultWittgensteinFloppyKeys[FloppyFamilyLOLBAS])) {
		t.Fatalf("clé par défaut incorrecte: %s", string(defaultKey))
	}

	// 2. Surcharge via variable d'environnement
	const customKey = "secret-custom-key-production"
	t.Setenv("C2BLUE_HMAC_KEY_LOLBAS", customKey)
	resolved := WittgensteinFloppyKey(FloppyFamilyLOLBAS)
	if !bytes.Equal(resolved, []byte(customKey)) {
		t.Fatalf("clé personnalisée non résolue: attendu %s, obtenu %s", customKey, string(resolved))
	}

	// 3. Mode strict (C2BLUE_REQUIRE_SECURE_KEYS=1) avec variable absente
	t.Setenv("C2BLUE_HMAC_KEY_DNS", "")
	t.Setenv("C2BLUE_REQUIRE_SECURE_KEYS", "1")
	dnsKey := WittgensteinFloppyKey(FloppyFamilyDNSC2)
	if dnsKey != nil {
		t.Fatalf("mode strict devait refuser le repli sur la clé de démo, obtenu %s", string(dnsKey))
	}
}

func TestLoadFloppy_StrictModeRefusesUnsealed(t *testing.T) {
	tmpDir := t.TempDir()
	floppyPath := filepath.Join(tmpDir, "unsealed.c2book")

	// 1. Créer une disquette non scellée (sans clé HMAC)
	err := SaveFloppyFile(floppyPath, FloppyFamilyLOLBAS, nil, nil, nil, nil, 12, nil)
	if err != nil {
		t.Fatalf("échec création disquette non scellée: %v", err)
	}

	// 2. Sans mode strict : le chargement sans clé réussit avec contrôle CRC32C seul
	disk, err := LoadFloppyMmap(floppyPath, nil)
	if err != nil {
		t.Fatalf("échec chargement hors mode strict: %v", err)
	}
	disk.Close()

	// 3. En mode strict (C2BLUE_REQUIRE_SECURE_KEYS=1) : refus catégorique de la disquette non scellée
	t.Setenv("C2BLUE_REQUIRE_SECURE_KEYS", "1")
	_, err = LoadFloppyMmap(floppyPath, nil)
	if !errors.Is(err, ErrFloppyUnsealed) {
		t.Fatalf("attendu ErrFloppyUnsealed en mode strict pour disquette non scellée, obtenu: %v", err)
	}

	// 4. En mode strict (C2BLUE_PRODUCTION=1) : également refus catégorique
	t.Setenv("C2BLUE_REQUIRE_SECURE_KEYS", "")
	t.Setenv("C2BLUE_PRODUCTION", "1")
	_, err = LoadFloppyMmap(floppyPath, nil)
	if !errors.Is(err, ErrFloppyUnsealed) {
		t.Fatalf("attendu ErrFloppyUnsealed sous C2BLUE_PRODUCTION=1 pour disquette non scellée, obtenu: %v", err)
	}
}
