package c2blue55

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

const p0MachineID = 0xCAFE12345678DEAD

func p0Silo(t *testing.T, dir string) *DailyOracleSilo {
	t.Helper()
	silo, err := NewDailyOracleSilo(SiloConfig{StorageDir: dir, MachineID: p0MachineID, NominalDist: 45, MaxRetainedDays: 7})
	if err != nil {
		t.Fatalf("NewDailyOracleSilo: %v", err)
	}
	return silo
}

func p0Snap(ts uint64, entity uint64, sev uint16, score uint16) engine.ServerHealthSnapshot {
	return engine.ServerHealthSnapshot{
		TimestampSec:    ts,
		Subsystem:       engine.OracleSubAuth,
		Action:          engine.OracleActStateNominal,
		HealthScore:     score,
		Severity:        sev,
		CorrelatedCount: 1,
		EntityID:        entity,
	}
}

func p0Ingest(t *testing.T, silo *DailyOracleSilo, snaps ...engine.ServerHealthSnapshot) {
	t.Helper()
	for i := range snaps {
		if err := silo.IngestSnapshot(&snaps[i]); err != nil {
			t.Fatalf("IngestSnapshot: %v", err)
		}
	}
}

func p0DayPath(dir string, ts uint64) string {
	return filepath.Join(dir, fmt.Sprintf("oracle_%016x_%d.c2oracle", uint64(p0MachineID), ts/86400))
}

func p0LoadDay(t *testing.T, dir string, ts uint64) (*engine.OracleDailyHeader, []engine.OracleVectorEntry) {
	t.Helper()
	f, err := os.Open(p0DayPath(dir, ts))
	if err != nil {
		t.Fatalf("ouverture de la tranche: %v", err)
	}
	defer f.Close()
	hdr, entries, err := engine.LoadOracleDay(f)
	if err != nil {
		t.Fatalf("LoadOracleDay: %v", err)
	}
	return hdr, entries
}

const (
	p0DayA = uint64(1789732800) // midi, jour 20714
	p0DayB = p0DayA + 86400
)

// Un flux dont les jours s'entrelacent (A, B, A) rescelle A : les entrées déjà scellées doivent survivre.
func TestSilo_OutOfOrderDaysKeepSealedEntries(t *testing.T) {
	dir := t.TempDir()
	silo := p0Silo(t, dir)
	p0Ingest(t, silo, p0Snap(p0DayA, 1, engine.SeverityLow, 990), p0Snap(p0DayB, 2, engine.SeverityLow, 990), p0Snap(p0DayA+60, 3, engine.SeverityLow, 990))
	if err := silo.SealDay(p0DayA + 3600); err != nil {
		t.Fatalf("SealDay: %v", err)
	}
	if _, entries := p0LoadDay(t, dir, p0DayA); len(entries) != 2 {
		t.Fatalf("tranche A: %d entrées, attendu 2 (entrée scellée détruite)", len(entries))
	}
}

// Un redémarrage du collecteur dans la même journée ne doit pas effacer la tranche déjà scellée.
func TestSilo_RestartSameDayMerges(t *testing.T) {
	dir := t.TempDir()
	first := p0Silo(t, dir)
	p0Ingest(t, first, p0Snap(p0DayA, 1, engine.SeverityLow, 990), p0Snap(p0DayA+10, 2, engine.SeverityLow, 990))
	if err := first.SealDay(p0DayA + 20); err != nil {
		t.Fatalf("SealDay 1: %v", err)
	}
	second := p0Silo(t, dir)
	p0Ingest(t, second, p0Snap(p0DayA+30, 3, engine.SeverityLow, 990))
	if err := second.SealDay(p0DayA + 40); err != nil {
		t.Fatalf("SealDay 2: %v", err)
	}
	hdr, entries := p0LoadDay(t, dir, p0DayA)
	if len(entries) != 3 {
		t.Fatalf("tranche fusionnée: %d entrées, attendu 3", len(entries))
	}
	if hdr.StartTsSec != p0DayA || hdr.EndTsSec != p0DayA+40 {
		t.Fatalf("bornes fusionnées: [%d, %d], attendu [%d, %d]", hdr.StartTsSec, hdr.EndTsSec, p0DayA, p0DayA+40)
	}
}

// Garde de non-régression de la fusion : réingérer le même journal ne duplique aucune entrée.
func TestSilo_ReingestIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	for range 2 {
		silo := p0Silo(t, dir)
		p0Ingest(t, silo, p0Snap(p0DayA, 1, engine.SeverityLow, 990), p0Snap(p0DayA+10, 2, engine.SeverityLow, 990))
		if err := silo.SealDay(p0DayA + 20); err != nil {
			t.Fatalf("SealDay: %v", err)
		}
	}
	if _, entries := p0LoadDay(t, dir, p0DayA); len(entries) != 2 {
		t.Fatalf("réingestion: %d entrées, attendu 2", len(entries))
	}
}

// Garde de non-régression : deux scellements successifs ne dupliquent rien.
func TestSilo_SealTwiceNoDuplication(t *testing.T) {
	dir := t.TempDir()
	silo := p0Silo(t, dir)
	p0Ingest(t, silo, p0Snap(p0DayA, 1, engine.SeverityLow, 990))
	for range 2 {
		if err := silo.SealDay(p0DayA + 20); err != nil {
			t.Fatalf("SealDay: %v", err)
		}
	}
	p0Ingest(t, silo, p0Snap(p0DayA+30, 2, engine.SeverityLow, 990))
	if err := silo.SealDay(p0DayA + 40); err != nil {
		t.Fatalf("SealDay: %v", err)
	}
	if _, entries := p0LoadDay(t, dir, p0DayA); len(entries) != 2 {
		t.Fatalf("double scellement: %d entrées, attendu 2", len(entries))
	}
}

// Une tranche existante illisible n'est jamais écrasée : le scellement échoue et le fichier reste intact.
func TestSilo_CorruptExistingDayIsNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := p0DayPath(dir, p0DayA)
	garbage := []byte("tranche corrompue, preuve a conserver")
	if err := os.WriteFile(path, garbage, 0o644); err != nil {
		t.Fatal(err)
	}
	silo := p0Silo(t, dir)
	p0Ingest(t, silo, p0Snap(p0DayA, 1, engine.SeverityLow, 990))
	if err := silo.SealDay(p0DayA + 20); err == nil {
		t.Fatal("scellement accepté par-dessus une tranche corrompue")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, garbage) {
		t.Fatal("tranche corrompue écrasée")
	}
}

// Les entrées de sévérité High/Critical n'entrent jamais dans la baseline.
func TestBuildServerBaseline_ExcludesHighSeverityEntries(t *testing.T) {
	dir := t.TempDir()
	silo := p0Silo(t, dir)
	nominal := p0Snap(p0DayA, 1, engine.SeverityLow, 990)
	attack := p0Snap(p0DayA+60, 666, engine.SeverityHigh, 400)
	critical := p0Snap(p0DayA+120, 667, engine.SeverityCritical, 200)
	p0Ingest(t, silo, nominal, attack, critical)
	if err := silo.SealDay(p0DayA + 3600); err != nil {
		t.Fatalf("SealDay: %v", err)
	}
	oracle, err := silo.BuildServerBaseline(7)
	if err != nil {
		t.Fatalf("BuildServerBaseline: %v", err)
	}
	if oracle.Len() != 1 {
		t.Fatalf("baseline: %d entrées, attendu 1 (anomalies admises)", oracle.Len())
	}
	var code [8]uint64
	engine.VectorizeServerHealthLocality(&attack, &code)
	if dist, nominalHit, _, _ := oracle.QueryState(&code); dist == 0 || nominalHit {
		t.Fatalf("l'attaque est reconnue comme nominale: dist=%d", dist)
	}
	if nominalHit, d, _, _ := oracle.QueryStateLocality(&code, engine.DefaultLocalityThresholds()); nominalHit {
		t.Fatalf("l'attaque est un voisin nominal: %+v", d)
	}
}

// En mode strict, une tranche marquée OracleFlagAnomalies est écartée en entier.
func TestBuildServerBaseline_StrictModeExcludesAnomalousDays(t *testing.T) {
	dir := t.TempDir()
	silo, err := NewDailyOracleSilo(SiloConfig{StorageDir: dir, MachineID: p0MachineID, BaselineExcludeAnomalousDays: true})
	if err != nil {
		t.Fatal(err)
	}
	p0Ingest(t, silo, p0Snap(p0DayA, 1, engine.SeverityLow, 990), p0Snap(p0DayA+60, 666, engine.SeverityHigh, 400), p0Snap(p0DayB, 2, engine.SeverityLow, 990))
	if err := silo.SealDay(p0DayB + 60); err != nil {
		t.Fatal(err)
	}
	oracle, err := silo.BuildServerBaseline(7)
	if err != nil {
		t.Fatal(err)
	}
	if oracle.Len() != 1 {
		t.Fatalf("baseline stricte: %d entrées, attendu 1 (jour B seul)", oracle.Len())
	}
}

// Les entrées dégradées (score < 700) ou marquées OracleFlagDegraded n'entrent
// jamais dans la baseline, même de sévérité basse ou moyenne.
func TestBuildServerBaseline_ExcludesDegradedEntries(t *testing.T) {
	dir := t.TempDir()
	silo := p0Silo(t, dir)
	p0Ingest(t, silo,
		p0Snap(p0DayA, 1, engine.SeverityLow, 990),
		p0Snap(p0DayA+60, 2, engine.SeverityLow, 699),
		p0Snap(p0DayA+120, 3, engine.SeverityMedium, 450),
		p0Snap(p0DayA+180, 4, engine.SeverityMedium, 700),
	)
	if err := silo.SealDay(p0DayA + 3600); err != nil {
		t.Fatalf("SealDay: %v", err)
	}
	oracle, err := silo.BuildServerBaseline(7)
	if err != nil {
		t.Fatalf("BuildServerBaseline: %v", err)
	}
	if oracle.Len() != 2 {
		t.Fatalf("baseline: %d entrées, attendu 2 (scores 990 et 700)", oracle.Len())
	}
}

// Le drapeau OracleFlagDegraded porté par une entrée suffit à l'écarter, quel que soit son score.
func TestBaselineAdmissible_DegradedFlagAlone(t *testing.T) {
	entries := []engine.OracleVectorEntry{
		{HealthScore: 990, Severity: engine.SeverityLow},
		{HealthScore: 990, Severity: engine.SeverityLow, Flags: engine.OracleFlagDegraded},
	}
	if kept := baselineAdmissible(entries); len(kept) != 1 || kept[0].Flags != 0 {
		t.Fatalf("admises: %+v", kept)
	}
}

const (
	lockHelperEnvDir   = "C2ORACLE_LOCK_HELPER_DIR"
	lockHelperEnvIndex = "C2ORACLE_LOCK_HELPER_INDEX"
	lockSealsPerWriter = 40
)

// lockSealEach scelle le même jour une entrée à la fois, pour multiplier les fenêtres de course.
func lockSealEach(t *testing.T, dir string, writer int) {
	silo := p0Silo(t, dir)
	for i := range lockSealsPerWriter {
		p0Ingest(t, silo, p0Snap(p0DayA+uint64(i), uint64(writer*1000+i+1), engine.SeverityLow, 990))
		if err := silo.SealDay(p0DayA + 3600); err != nil {
			t.Fatalf("écrivain %d, scellement %d: %v", writer, i, err)
		}
	}
}

// Plusieurs silos d'un même processus scellent le même jour : aucune entrée ne se perd.
func TestSilo_ConcurrentSealersInProcessLoseNothing(t *testing.T) {
	dir := t.TempDir()
	const writers = 6
	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() { lockSealEach(t, dir, w) })
	}
	wg.Wait()
	if _, entries := p0LoadDay(t, dir, p0DayA); len(entries) != writers*lockSealsPerWriter {
		t.Fatalf("tranche: %d entrées, attendu %d (écrasement concurrent)", len(entries), writers*lockSealsPerWriter)
	}
}

// Point d'entrée des processus enfants de TestSilo_ConcurrentSealersAcrossProcesses.
func TestSiloLockHelperProcess(t *testing.T) {
	dir := os.Getenv(lockHelperEnvDir)
	if dir == "" {
		t.Skip("processus auxiliaire uniquement")
	}
	w, err := strconv.Atoi(os.Getenv(lockHelperEnvIndex))
	if err != nil {
		t.Fatal(err)
	}
	lockSealEach(t, dir, w)
}

// Plusieurs processus distincts (démon et c2forge -oracle-ingest) scellent le même
// jour dans le même répertoire : le verrou flock les sérialise, aucune entrée ne se perd.
func TestSilo_ConcurrentSealersAcrossProcesses(t *testing.T) {
	dir := t.TempDir()
	const writers = 4
	cmds := make([]*exec.Cmd, writers)
	outs := make([]bytes.Buffer, writers)
	for w := range writers {
		cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSiloLockHelperProcess$", "-test.count=1")
		cmd.Env = append(os.Environ(), lockHelperEnvDir+"="+dir, lockHelperEnvIndex+"="+strconv.Itoa(w))
		cmd.Stdout, cmd.Stderr = &outs[w], &outs[w]
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds[w] = cmd
	}
	for w, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("processus %d: %v\n%s", w, err, outs[w].String())
		}
	}
	if _, entries := p0LoadDay(t, dir, p0DayA); len(entries) != writers*lockSealsPerWriter {
		t.Fatalf("tranche: %d entrées, attendu %d (écrasement inter-processus)", len(entries), writers*lockSealsPerWriter)
	}
}
