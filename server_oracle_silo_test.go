package c2blue55

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

func TestDailyOracleSilo_RotationAndSeal(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "c2oracle_test_*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	cfg := SiloConfig{
		StorageDir:      tmpDir,
		MachineID:       0xCAFE12345678DEAD,
		NominalDist:     45,
		MaxRetainedDays: 7,
	}
	silo, err := NewDailyOracleSilo(cfg)
	if err != nil {
		t.Fatalf("NewDailyOracleSilo: %v", err)
	}

	// Événement du Jour J (ex: timestamp correspondant à 2026-09-18 12:00:00)
	tsDay1 := uint64(1789732800)
	snap1 := engine.ServerHealthSnapshot{
		TimestampSec:    tsDay1,
		Subsystem:       engine.OracleSubAuth,
		Action:          engine.OracleActStateNominal,
		HealthScore:     990,
		Severity:        engine.SeverityLow,
		CorrelatedCount: 1,
	}
	if err := silo.IngestSnapshot(&snap1); err != nil {
		t.Fatalf("IngestSnapshot day1: %v", err)
	}

	// Événement du Jour J+1 (ex: timestamp 24h plus tard : 2026-09-19 12:00:00)
	// Doit déclencher mécaniquement la rotation automatique de la tranche J
	tsDay2 := tsDay1 + 86400
	snap2 := engine.ServerHealthSnapshot{
		TimestampSec:    tsDay2,
		Subsystem:       engine.OracleSubKernel,
		Action:          engine.OracleActStateNominal,
		HealthScore:     980,
		Severity:        engine.SeverityLow,
		CorrelatedCount: 2,
	}
	if err := silo.IngestSnapshot(&snap2); err != nil {
		t.Fatalf("IngestSnapshot day2: %v", err)
	}

	// Vérifie les compteurs de rotation
	_, activeEntries, totalIngested, totalRotations := silo.Stats()
	if totalIngested != 2 {
		t.Fatalf("totalIngested = %d, attendu 2", totalIngested)
	}
	if totalRotations != 1 {
		t.Fatalf("totalRotations = %d, attendu 1", totalRotations)
	}
	if activeEntries != 1 {
		t.Fatalf("activeEntries = %d, attendu 1", activeEntries)
	}

	// Scellement explicite du Jour J+1
	if err := silo.SealDay(tsDay2 + 3600); err != nil {
		t.Fatalf("SealDay: %v", err)
	}

	// Vérifie que les deux fichiers .c2oracle existent et sont valides
	pattern := filepath.Join(tmpDir, "oracle_cafe12345678dead_*.c2oracle")
	files, _ := filepath.Glob(pattern)
	if len(files) != 2 {
		t.Fatalf("fichiers créés = %d, attendu 2", len(files))
	}

	// Reconstruit la baseline de l'oracle individuel
	oracle, err := silo.BuildServerBaseline(7)
	if err != nil {
		t.Fatalf("BuildServerBaseline: %v", err)
	}
	if oracle.Len() != 2 {
		t.Fatalf("oracle.Len() = %d, attendu 2", oracle.Len())
	}

	// Interroge l'oracle individuel avec le vecteur du Jour J
	var queryCode [8]uint64
	engine.VectorizeServerHealthLocality(&snap1, &queryCode)
	dist, isNominal, sub, _ := oracle.QueryState(&queryCode)
	if dist != 0 || !isNominal || sub != engine.OracleSubAuth {
		t.Fatalf("requête Day1: dist=%d, isNominal=%v, sub=%d", dist, isNominal, sub)
	}
	locNominal, locDist, locSub, _ := oracle.QueryStateLocality(&queryCode, engine.DefaultLocalityThresholds())
	if !locNominal || locDist != (engine.LocalityDistance{}) || locSub != engine.OracleSubAuth {
		t.Fatalf("requête de localité Day1: nominal=%v, ecart=%+v, sub=%d", locNominal, locDist, locSub)
	}
}

func TestLogStreamIngester_RealHostLogs(t *testing.T) {
	// Vérifie la présence d'un fichier de log réel sur l'hôte Linux
	realLogPath := "/var/log/dpkg.log"
	if _, err := os.Stat(realLogPath); os.IsNotExist(err) {
		t.Skip("Journal /var/log/dpkg.log non disponible sur cet environnement de test")
	}

	tmpDir, err := os.MkdirTemp("", "c2oracle_real_*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	silo, err := NewDailyOracleSilo(DefaultSiloConfig(tmpDir))
	if err != nil {
		t.Fatalf("NewDailyOracleSilo: %v", err)
	}

	ingester := NewLogStreamIngester(silo)
	count, err := ingester.IngestLogFile(realLogPath)
	if err != nil {
		t.Fatalf("IngestLogFile: %v", err)
	}
	if count == 0 {
		t.Fatalf("aucun log ingéré depuis %s", realLogPath)
	}

	t.Logf("Succès d'ingestion de traces réelles de l'hôte: %d événements ingérés", count)

	// Scelle la dernière tranche
	if err := silo.SealDay(uint64(time.Now().Unix())); err != nil {
		t.Fatalf("SealDay: %v", err)
	}

	// Assemble l'oracle individuel à partir des traces réelles de l'hôte
	oracle, err := silo.BuildServerBaseline(30)
	if err != nil {
		t.Fatalf("BuildServerBaseline: %v", err)
	}
	if oracle.Len() == 0 {
		t.Fatalf("oracle.Len() = 0 après ingestion de logs réels")
	}
	t.Logf("Oracle individuel du serveur initialisé avec %d états de référence réels", oracle.Len())
}
