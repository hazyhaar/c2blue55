// Package engine — wittgenstein_corpus_test.go
package engine

import (
	"bytes"
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
