package engine_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

const (
	hostileRunID = "replay-tuns-20261027T150942Z"
	benignRunID  = "local-dns-20261027T113715Z"
	hostileViews = 598
	benignViews  = 69
)

func TestDeltaRecompile_ProofTriplet(t *testing.T) {
	corpusDir, labDir := wittgensteinRoots(t)
	trainPath := filepath.Join(corpusDir, "netrack_dns", "train.csv")
	if _, err := os.Stat(trainPath); err != nil {
		t.Fatalf("corpus netrack_dns introuvable: %v", err)
	}
	key := engine.WittgensteinFloppyKey(engine.FloppyFamilyDNSC2)
	if len(key) == 0 {
		t.Fatal("clé HMAC de la famille DNS absente")
	}

	forgeDir := t.TempDir()
	if err := engine.BuildDNSFloppiesColdSplit(corpusDir, forgeDir, key); err != nil {
		t.Fatalf("BuildDNSFloppiesColdSplit: %v", err)
	}
	basePath := filepath.Join(forgeDir, "floppy_dns_tunnel.c2book")
	baseDisk, err := engine.LoadFloppyMmap(basePath, key)
	if err != nil {
		t.Fatalf("LoadFloppyMmap(base): %v", err)
	}
	t.Cleanup(func() { _ = baseDisk.Close() })

	hostileRun := ingestLabRun(t, labDir, hostileRunID)
	benignRun := ingestLabRun(t, labDir, benignRunID)
	hostile := hostileRun.QueryViews()
	benign := benignRun.QueryViews()
	if len(hostile) != hostileViews {
		t.Fatalf("vues hostiles = %d, attendu %d", len(hostile), hostileViews)
	}
	if len(benign) != benignViews {
		t.Fatalf("vues bénignes = %d, attendu %d", len(benign), benignViews)
	}
	if hostileRun.Manifest.RunID != hostileRunID || hostileRun.Manifest.Family != "redhost-replay" {
		t.Fatalf("run hostile %q famille %q, attendu %s / redhost-replay", hostileRun.Manifest.RunID, hostileRun.Manifest.Family, hostileRunID)
	}

	missed := make([]engine.DNSQueryView, 0)
	for _, view := range hostile {
		verdict := engine.EvaluateDNSView(view, baseDisk, nil)
		if verdict.Action != engine.VerdictBlock {
			missed = append(missed, view)
		}
	}
	fromFN := len(missed) > 0
	recompileViews := missed
	if !fromFN {
		limit := min(len(hostile), 50)
		recompileViews = append([]engine.DNSQueryView(nil), hostile[:limit]...)
		t.Logf("motif déjà couvert: preuve construite sur les %d premières vues hostiles, FNBefore attendu 0", len(recompileViews))
	}
	t.Logf("FN avant=%d sur %d vues hostiles, EntryCount=%d", len(missed), len(hostile), baseDisk.Header.EntryCount)

	outDir := t.TempDir()
	outPath := filepath.Join(outDir, "floppy_dns_tunnel.c2book")
	report, err := engine.RecompileDNSTunnelDelta(basePath, outPath, recompileViews, key)
	if err != nil {
		t.Fatalf("RecompileDNSTunnelDelta: %v", err)
	}
	t.Logf("BaseSHA256=%s OutSHA256=%s CentroidsBefore=%d CentroidsAdded=%d MissedIn=%d MissedAfter=%d BenignFPBefore=%d BenignFPAfter=%d",
		report.BaseSHA256, report.OutSHA256, report.CentroidsBefore, report.CentroidsAdded, report.MissedIn, report.MissedAfter, report.BenignFPBefore, report.BenignFPAfter)

	baseSum := fileSHA256(t, basePath)
	outSum := fileSHA256(t, outPath)
	if report.BaseSHA256 != baseSum {
		t.Errorf("BaseSHA256 = %s, attendu %s", report.BaseSHA256, baseSum)
	}
	if report.OutSHA256 != outSum {
		t.Errorf("OutSHA256 = %s, attendu %s", report.OutSHA256, outSum)
	}
	if fromFN && report.CentroidsAdded < 1 {
		t.Errorf("CentroidsAdded = %d, attendu >= 1", report.CentroidsAdded)
	}
	if report.CentroidsBefore != int(baseDisk.Header.EntryCount) {
		t.Errorf("CentroidsBefore = %d, EntryCount = %d", report.CentroidsBefore, baseDisk.Header.EntryCount)
	}
	assertNoTempNames(t, outDir)

	newDisk, err := engine.LoadFloppyMmap(outPath, key)
	if err != nil {
		t.Fatalf("LoadFloppyMmap(recompilée): %v", err)
	}
	t.Cleanup(func() { _ = newDisk.Close() })

	proof, err := engine.ProvePattern(baseDisk, newDisk, hostileRunID, hostileRun.Manifest.Family, hostile, benign)
	if err != nil {
		t.Fatalf("ProvePattern: %v", err)
	}
	t.Logf("RunID=%s Family=%s FNBefore=%d FNAfter=%d FPBefore=%d FPAfter=%d Proven=%v",
		proof.RunID, proof.Family, proof.FNBefore, proof.FNAfter, proof.FPBefore, proof.FPAfter, proof.Proven)
	if proof.RunID != hostileRunID || proof.Family != hostileRun.Manifest.Family {
		t.Errorf("preuve %s/%s, attendu %s/%s", proof.RunID, proof.Family, hostileRunID, hostileRun.Manifest.Family)
	}
	if fromFN {
		if proof.FNBefore != len(missed) {
			t.Errorf("FNBefore = %d, attendu %d", proof.FNBefore, len(missed))
		}
	} else if proof.FNBefore != 0 || proof.Proven || !proof.AlreadyCovered {
		// Corrigé par l'architecte le 2026-10-27 (audit S-07) : sans évasion
		// initiale il n'y a pas de motif prouvé, seulement un motif déjà couvert.
		t.Errorf("motif déjà couvert: FNBefore=%d Proven=%v AlreadyCovered=%v, attendu 0, false, true", proof.FNBefore, proof.Proven, proof.AlreadyCovered)
	}
	if proof.FNAfter != 0 {
		t.Errorf("FNAfter = %d, attendu 0", proof.FNAfter)
	}
	if proof.FPAfter > proof.FPBefore {
		t.Errorf("FPAfter = %d > FPBefore = %d", proof.FPAfter, proof.FPBefore)
	}
	wantProven := proof.FNBefore > 0 && proof.FNAfter == 0 && proof.FPAfter <= proof.FPBefore
	if proof.Proven != wantProven {
		t.Errorf("Proven = %v, attendu %v", proof.Proven, wantProven)
	}
}

func TestDeltaRecompile_Refusals(t *testing.T) {
	_, labDir := wittgensteinRoots(t)
	key := engine.WittgensteinFloppyKey(engine.FloppyFamilyDNSC2)
	if len(key) == 0 {
		t.Fatal("clé HMAC de la famille DNS absente")
	}
	validBase := filepath.Join(t.TempDir(), "base.c2book")
	copyFile(t, sealedFloppyPath(t), validBase)
	baseDisk, err := engine.LoadFloppyMmap(validBase, key)
	if err != nil {
		t.Fatalf("base scellée illisible: %v", err)
	}
	_ = baseDisk.Close()

	hostileRun := ingestLabRun(t, labDir, hostileRunID)
	hostile := hostileRun.QueryViews()
	if len(hostile) == 0 {
		t.Fatal("aucune vue hostile pour le refus d'écriture")
	}
	oneView := hostile[:1]

	t.Run("corps altéré", func(t *testing.T) {
		altered := copyAlteredBody(t, validBase)
		_, loadErr := engine.LoadFloppyMmap(altered, key)
		if loadErr == nil {
			t.Fatal("LoadFloppyMmap accepte une disquette au corps altéré")
		}
		outDir := t.TempDir()
		outPath := filepath.Join(outDir, "sortie.c2book")
		_, err := engine.RecompileDNSTunnelDelta(altered, outPath, oneView, key)
		if err == nil {
			t.Fatal("recompilation d'une base altérée: erreur attendue absente")
		}
		if !errors.Is(err, loadErr) {
			t.Fatalf("recompilation: %v, attendu l'erreur de LoadFloppyMmap (%v)", err, loadErr)
		}
		assertAbsent(t, outPath)
		assertNoTempNames(t, outDir)
	})

	t.Run("vues manquées vides", func(t *testing.T) {
		for _, label := range []string{"nil", "tranche vide"} {
			t.Run(label, func(t *testing.T) {
				var missed []engine.DNSQueryView
				if label == "tranche vide" {
					missed = []engine.DNSQueryView{}
				}
				outDir := t.TempDir()
				outPath := filepath.Join(outDir, "sortie.c2book")
				_, err := engine.RecompileDNSTunnelDelta(validBase, outPath, missed, key)
				if !errors.Is(err, engine.ErrDeltaContract) {
					t.Fatalf("missed %s: %v, attendu ErrDeltaContract", label, err)
				}
				assertAbsent(t, outPath)
				assertNoTempNames(t, outDir)
			})
		}
	})

	t.Run("répertoire non inscriptible", func(t *testing.T) {
		parent := t.TempDir()
		sealed := filepath.Join(parent, "scelle")
		if err := os.Mkdir(sealed, 0o755); err != nil {
			t.Fatalf("création du répertoire scellé: %v", err)
		}
		if err := os.Chmod(sealed, 0o555); err != nil {
			t.Fatalf("scellement du répertoire: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(sealed, 0o755) })
		outPath := filepath.Join(sealed, "sortie.c2book")
		before := namesIn(t, parent)
		_, err := engine.RecompileDNSTunnelDelta(validBase, outPath, oneView, key)
		if err == nil {
			t.Fatal("répertoire non inscriptible: erreur attendue absente")
		}
		if errors.Is(err, engine.ErrDeltaContract) && !os.IsPermission(err) {
			t.Fatalf("répertoire non inscriptible: refus de contrat %v, attendu une erreur d'écriture", err)
		}
		assertAbsent(t, outPath)
		if got := namesIn(t, parent); !slices.Equal(got, before) {
			t.Fatalf("fichiers du parent = %v, attendu %v", got, before)
		}
		if got := namesIn(t, sealed); len(got) != 0 {
			t.Fatalf("temporaires dans le répertoire scellé: %v", got)
		}
	})
}

func wittgensteinRoots(t *testing.T) (corpusDir, labDir string) {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("répertoire du paquet illisible: %v", err)
	}
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("aucun .git au-dessus du répertoire du paquet")
		}
		dir = parent
	}
	candidates := []string{
		filepath.Join(dir, "wittgenstein"),
		filepath.Join(dir, "..", "wittgenstein"),
		filepath.Join(dir, "..", "..", "..", "wittgenstein"),
	}
	for _, cand := range candidates {
		lab := filepath.Join(cand, "redhost_lab")
		st, statErr := os.Stat(lab)
		if statErr == nil && st.IsDir() {
			return cand, lab
		}
	}
	t.Fatalf("wittgenstein/redhost_lab introuvable depuis la racine %s", dir)
	return "", ""
}

func ingestLabRun(t *testing.T, labDir, runID string) c2blue55.RedhostLabRun {
	t.Helper()
	run, err := c2blue55.IngestRedhostLabRun(
		filepath.Join(labDir, runID+".pcap"),
		filepath.Join(labDir, runID+".manifest.json"),
	)
	if err != nil {
		t.Fatalf("ingestion %s: %v", runID, err)
	}
	return run
}

func sealedFloppyPath(t *testing.T) string {
	t.Helper()
	corpusDir, _ := wittgensteinRoots(t)
	path := filepath.Join(corpusDir, "floppies", "floppy_dns_c2.c2book")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("disquette scellée introuvable: %v", err)
	}
	return path
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lecture %s: %v", path, err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	payload, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("lecture %s: %v", src, err)
	}
	if err := os.WriteFile(dst, payload, 0o600); err != nil {
		t.Fatalf("écriture %s: %v", dst, err)
	}
}

func copyAlteredBody(t *testing.T, src string) string {
	t.Helper()
	payload, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("lecture %s: %v", src, err)
	}
	if len(payload) <= engine.FloppyHeaderSize {
		t.Fatalf("disquette trop courte pour un corps: %d octets", len(payload))
	}
	payload[engine.FloppyHeaderSize] ^= 0xFF
	dst := filepath.Join(t.TempDir(), "base-alteree.c2book")
	if err := os.WriteFile(dst, payload, 0o600); err != nil {
		t.Fatalf("écriture de la copie altérée: %v", err)
	}
	return dst
}

func assertAbsent(t *testing.T, path string) {
	t.Helper()
	_, err := os.Stat(path)
	if err == nil {
		t.Fatalf("fichier créé: %s", path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %s: %v", path, err)
	}
}

func assertNoTempNames(t *testing.T, dir string) {
	t.Helper()
	for _, name := range namesIn(t, dir) {
		if strings.Contains(name, ".tmp") || strings.HasPrefix(name, ".") {
			t.Errorf("temporaire résiduel %s", filepath.Join(dir, name))
		}
	}
}

func namesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("lecture %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	return names
}
