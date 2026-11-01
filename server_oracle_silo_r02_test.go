package c2blue55

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/engine"
)

// TestDailyOracleSilo_GlobErrorPropagated fige la strate R-02 : une erreur de
// filepath.Glob dans la liste des tranches (storedDayFilesLocked) ne doit pas
// être tenue pour « aucune tranche ». Un répertoire de stockage contenant un
// crochet ouvrant rend le motif de Glob invalide (filepath.ErrBadPattern) ; la
// vérification de chaîne et le scellement doivent alors rendre cette erreur,
// enveloppée, au lieu d'un succès sur une liste vide.
func TestDailyOracleSilo_GlobErrorPropagated(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "silo[")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	cfg := DefaultSiloConfig(dir)
	cfg.MachineID = 0xCAFE12345678DEAD
	silo, err := NewDailyOracleSilo(cfg)
	if err != nil {
		t.Fatalf("NewDailyOracleSilo: %v", err)
	}

	if _, err := silo.VerifyOracleChain(); !errors.Is(err, filepath.ErrBadPattern) {
		t.Errorf("VerifyOracleChain : err = %v, attendu une erreur enveloppant filepath.ErrBadPattern", err)
	}

	snap := engine.ServerHealthSnapshot{
		TimestampSec:    1789732800,
		Subsystem:       engine.OracleSubAuth,
		Action:          engine.OracleActStateNominal,
		HealthScore:     990,
		Severity:        engine.SeverityLow,
		CorrelatedCount: 1,
	}
	if err := silo.IngestSnapshot(&snap); err != nil {
		t.Fatalf("IngestSnapshot: %v", err)
	}
	if err := silo.SealDay(1789732800 + 3600); !errors.Is(err, filepath.ErrBadPattern) {
		t.Errorf("SealDay : err = %v, attendu une erreur enveloppant filepath.ErrBadPattern", err)
	}
}
