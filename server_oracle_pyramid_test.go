package c2blue55

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

func TestPyramidHorizonNames(t *testing.T) {
	for i, name := range []string{"4h", "12h", "24h", "7d", "30d", "120d", "365d"} {
		sc, ok := ParsePyramidHorizon(name)
		if !ok || sc != 1<<i {
			t.Fatalf("%s -> 0x%04x", name, sc)
		}
		if back, ok := PyramidHorizonName(sc); !ok || back != name {
			t.Fatalf("0x%04x -> %s", sc, back)
		}
	}
	for _, sc := range []uint16{0, engine.DeltaScale4h | engine.DeltaScale24h, 1 << 7} {
		if _, err := PyramidFileName(1, sc); !errors.Is(err, engine.ErrPyramidScale) {
			t.Fatalf("0x%04x: %v", sc, err)
		}
	}
	if _, ok := ParsePyramidHorizon("1y"); ok {
		t.Fatal("horizon inconnu admis")
	}
}

// La description se traduit fidèlement : créneaux, jours, champs fixés,
// entité hachée comme ParseLogLine, préréglage surchargé.
func TestCompileDeltaDescription(t *testing.T) {
	desc := `{"rules": [
	  {"id": 7, "label": "apt-weekend", "preset": "apt-maintenance", "radius": 2, "scales": ["7d"],
	   "not_before": "2026-09-27T00:00:00Z", "not_after": "2026-10-05T00:00:00Z",
	   "days": ["sat", "DIM"], "hours": "00:00-24:00"},
	  {"id": 8, "label": "sauvegarde", "not_before": "2026-09-27T00:00:00Z", "not_after": "2026-09-28T00:00:00Z",
	   "hours": "01:30-02:15", "radius": 3, "scales": ["24h", "30d"],
	   "state": {"subsystem": 5, "action": 6, "severity": 2, "health_score": 850, "correlated": 1,
	             "entity": "backup.log", "time": "01:45", "payload": "rsync"},
	   "match": ["subsystem", "action", "entity", "slot"]}
	]}`
	rules, err := CompileDeltaDescription(strings.NewReader(desc))
	if err != nil || len(rules) != 2 {
		t.Fatalf("%v", err)
	}
	a, b := rules[0], rules[1]
	if a.RuleID != 7 || a.MaxRadius != 2 || a.ScaleMask != engine.DeltaScale7d || a.DaysOfWeekMask != 1<<6|1<<0 ||
		a.TimeSlotMin != 0 || a.TimeSlotMax != engine.DeltaSlotsPerDay-1 ||
		a.NotBeforeSec != uint64(time.Date(2026, 9, 27, 0, 0, 0, 0, time.UTC).Unix()) {
		t.Fatalf("regle preset: %+v", a)
	}
	// 01:30 = créneau 4 (5400 s * 64 / 86400), 02:15 exclu = créneau 5.
	if b.TimeSlotMin != 4 || b.TimeSlotMax != 5 || b.ScaleMask != engine.DeltaScale24h|engine.DeltaScale30d || b.DaysOfWeekMask != engine.DeltaAllDays {
		t.Fatalf("regle state: %+v", b)
	}
	snap := engine.ServerHealthSnapshot{Subsystem: 5, Action: 6, Severity: 2, HealthScore: 850, CorrelatedCount: 1,
		EntityID: LogActorID("backup.log"), TimestampSec: 3600 + 45*60}
	copy(snap.RawPayload[:], "rsync")
	pattern, mask := engine.DeltaPatternFromSnapshot(&snap, engine.DeltaMatchSubsystem|engine.DeltaMatchAction|engine.DeltaMatchEntity|engine.DeltaMatchSlot)
	if b.Pattern != pattern || b.Mask != mask {
		t.Fatal("motif ou masque different de l'instantane decrit")
	}
	// Une ligne dpkg réelle de maintenance est bien celle que vise le préréglage.
	line, ok := ParseLogLine("2026-09-28 03:00:00 status half-installed libc6:amd64 2.40-1", "dpkg.log")
	if !ok {
		t.Fatal("ligne dpkg non analysee")
	}
	var bc [8]uint64
	engine.VectorizeServerHealthLocality(&line, &bc)
	for w := range 8 {
		if (bc[w]^a.Pattern[w])&a.Mask[w] != 0 {
			t.Fatalf("preset apt-maintenance ne vise pas la ligne dpkg (mot %d)", w)
		}
	}
	for name, bad := range map[string]string{
		"vide":            `{"rules": []}`,
		"sans etat":       `{"rules": [{"id":1,"label":"x","radius":2,"scales":["7d"],"not_before":"2026-09-27T00:00:00Z","not_after":"2026-10-05T00:00:00Z"}]}`,
		"preset et etat":  `{"rules": [{"id":1,"label":"x","preset":"apt-maintenance","state":{},"not_before":"2026-09-27T00:00:00Z","not_after":"2026-10-05T00:00:00Z"}]}`,
		"champ":           `{"rules": [{"id":1,"label":"x","preset":"apt-maintenance","match":["tout"],"not_before":"2026-09-27T00:00:00Z","not_after":"2026-10-05T00:00:00Z"}]}`,
		"slot sans heure": `{"rules": [{"id":1,"label":"x","radius":2,"scales":["7d"],"state":{"severity":1},"match":["slot"],"not_before":"2026-09-27T00:00:00Z","not_after":"2026-10-05T00:00:00Z"}]}`,
		"jour":            `{"rules": [{"id":1,"label":"x","preset":"apt-maintenance","days":["lundi"],"not_before":"2026-09-27T00:00:00Z","not_after":"2026-10-05T00:00:00Z"}]}`,
		"rayon large":     `{"rules": [{"id":1,"label":"x","preset":"apt-maintenance","radius":8,"not_before":"2026-09-27T00:00:00Z","not_after":"2026-10-05T00:00:00Z"}]}`,
		"libelle long":    `{"rules": [{"id":1,"label":"` + strings.Repeat("x", 33) + `","preset":"apt-maintenance","not_before":"2026-09-27T00:00:00Z","not_after":"2026-10-05T00:00:00Z"}]}`,
		"24h en debut":    `{"rules": [{"id":1,"label":"x","preset":"apt-maintenance","hours":"24:00-24:00","not_before":"2026-09-27T00:00:00Z","not_after":"2026-10-05T00:00:00Z"}]}`,
	} {
		if _, err := CompileDeltaDescription(strings.NewReader(bad)); err == nil {
			t.Fatalf("%s: description acceptee", name)
		}
	}
}

// LoadPyramids refuse un fichier dont l'en-tête contredit le nom, et ignore
// les noms hors convention.
func TestLoadPyramids_ScaleMustMatchName(t *testing.T) {
	dir := t.TempDir()
	silo, err := NewDailyOracleSilo(SiloConfig{StorageDir: dir, MachineID: 42})
	if err != nil {
		t.Fatal(err)
	}
	s := engine.ServerHealthSnapshot{Subsystem: 5, Action: 6, Severity: engine.SeverityLow, HealthScore: 980, TimestampSec: 20000*86400 + 9*3600}
	var e engine.OracleVectorEntry
	engine.VectorizeServerHealthLocality(&s, &e.Bitcode)
	e.RelativeSec, e.Subsystem, e.HealthScore, e.Severity = 9*3600, 5, 980, engine.SeverityLow
	pyr, err := engine.CondensePyramidHierarchy([]engine.CondenseDay{{EpochDay: 20000, Entries: []engine.OracleVectorEntry{e}}},
		engine.CondenseConfig{Scales: engine.DeltaScale24h}, 42)
	if err != nil {
		t.Fatal(err)
	}
	name7, _ := PyramidFileName(42, engine.DeltaScale7d)
	if err := writePyramidAtomic(filepath.Join(dir, name7), pyr[engine.DeltaScale24h], nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := silo.LoadPyramids(nil); !errors.Is(err, ErrPyramidFileScale) {
		t.Fatalf("en-tete 24h sous un nom 7d: %v", err)
	}
	if err := os.Rename(filepath.Join(dir, name7), filepath.Join(dir, "pyramid_000000000000002a_1y.c2pyramid")); err != nil {
		t.Fatal(err)
	}
	if _, scales, err := silo.LoadPyramids(nil); err != nil || scales != 0 {
		t.Fatalf("nom hors convention: 0x%04x %v", scales, err)
	}
}
