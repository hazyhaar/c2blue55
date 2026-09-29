package c2blue55

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

var chainKey = []byte("cle-hote-partagee-chainage-32-oc")

func keyedSilo(t *testing.T, dir string, key []byte) *DailyOracleSilo {
	t.Helper()
	silo, err := NewDailyOracleSilo(SiloConfig{StorageDir: dir, MachineID: p0MachineID, MaxRetainedDays: 7, HMACKey: key})
	if err != nil {
		t.Fatal(err)
	}
	return silo
}

func loadKeyed(t *testing.T, dir string, ts uint64, key []byte) *engine.OracleDailyHeader {
	t.Helper()
	hdr, _, err := loadOracleDayFile(p0DayPath(dir, ts), key)
	if err != nil {
		t.Fatalf("relecture du jour %d: %v", ts/86400, err)
	}
	return hdr
}

// Chaque tranche porte le sceau de la précédente ; un jour sans événement est
// sauté ; la chaîne se vérifie, y compris après redémarrage du silo.
func TestSilo_PrevDaySealChains(t *testing.T) {
	dir := t.TempDir()
	silo := keyedSilo(t, dir, chainKey)
	dayC := p0DayB + 2*86400 // le jour intermédiaire n'a aucun événement
	p0Ingest(t, silo, p0Snap(p0DayA, 1, engine.SeverityLow, 990), p0Snap(p0DayB, 2, engine.SeverityLow, 990))
	// Redémarrage : le silo suivant doit relire le sceau du jour B sur disque.
	if err := silo.SealDay(p0DayB + 60); err != nil {
		t.Fatal(err)
	}
	silo = keyedSilo(t, dir, chainKey)
	p0Ingest(t, silo, p0Snap(dayC, 3, engine.SeverityLow, 990))
	if err := silo.SealDay(dayC + 60); err != nil {
		t.Fatal(err)
	}
	a, b, c := loadKeyed(t, dir, p0DayA, chainKey), loadKeyed(t, dir, p0DayB, chainKey), loadKeyed(t, dir, dayC, chainKey)
	if a.PrevDaySeal != ([32]byte{}) || b.PrevDaySeal != a.Seal || c.PrevDaySeal != b.Seal {
		t.Fatal("chainage PrevDaySeal incorrect")
	}
	if a.Flags&engine.OracleFlagKeyed == 0 {
		t.Fatal("tranche non marquee OracleFlagKeyed")
	}
	if breaks, err := silo.VerifyOracleChain(); err != nil || len(breaks) != 0 {
		t.Fatalf("chaine intacte signalee rompue: %v %+v", err, breaks)
	}
}

// Remplacer une tranche par une autre, correctement scellée sous la clé
// (initié qui connaît la clé, ou tranche rejouée d'une autre date), rompt le
// lien du jour suivant ; une tranche scellée sans la clé est refusée.
func TestSilo_ChainDetectsReplacedDay(t *testing.T) {
	dir := t.TempDir()
	silo := keyedSilo(t, dir, chainKey)
	p0Ingest(t, silo, p0Snap(p0DayA, 1, engine.SeverityLow, 990), p0Snap(p0DayB, 2, engine.SeverityLow, 990))
	if err := silo.SealDay(p0DayB + 60); err != nil {
		t.Fatal(err)
	}
	// Tranche A réécrite sans l'événement, scellée sous la clé.
	forged := engine.OracleDailyHeader{EpochDay: uint32(p0DayA / 86400), StartTsSec: p0DayA, EndTsSec: p0DayA + 60,
		Flags: engine.OracleFlagSealed, MachineID: p0MachineID}
	var e engine.OracleVectorEntry
	e.HealthScore = 990
	if err := writeOracleDayAtomic(p0DayPath(dir, p0DayA), &forged, []engine.OracleVectorEntry{e}, chainKey); err != nil {
		t.Fatal(err)
	}
	breaks, err := keyedSilo(t, dir, chainKey).VerifyOracleChain()
	if err != nil || len(breaks) != 1 || breaks[0].EpochDay != uint32(p0DayB/86400) {
		t.Fatalf("remplacement non detecte: %v %+v", err, breaks)
	}
	// Tranche A réécrite par qui ignore la clé : sceau SHA-256, refusée.
	if err := writeOracleDayAtomic(p0DayPath(dir, p0DayA), &forged, []engine.OracleVectorEntry{e}, nil); err != nil {
		t.Fatal(err)
	}
	breaks, _ = keyedSilo(t, dir, chainKey).VerifyOracleChain()
	if len(breaks) == 0 || breaks[0].EpochDay != uint32(p0DayA/86400) {
		t.Fatalf("tranche non authentifiee non signalee: %+v", breaks)
	}
	o, err := keyedSilo(t, dir, chainKey).BuildServerBaseline(7)
	if err != nil || o.Len() != 1 {
		t.Fatalf("baseline: %v, %d entrees (attendu 1, la tranche forgee ecartee)", err, o.Len())
	}
}

// Sous clé, une tranche v3 du même jour est archivée, jamais fusionnée, et son
// en-tête non authentifié ne transmet ni bornes ni drapeaux ; sans clé, une
// tranche v3 est archivée comme une v2 et ses bornes sont reprises.
func TestSilo_V3DayArchivedUnderKey(t *testing.T) {
	for _, keyed := range []bool{false, true} {
		dir := t.TempDir()
		path := p0DayPath(dir, p0DayA)
		legacy := v3WriteDay(t, dir, p0DayA-600, engine.OracleVersionV3, engine.OracleFlagMaintenance,
			p0Snap(p0DayA-600, 1, engine.SeverityLow, 990))
		var key []byte
		if keyed {
			key = chainKey
		}
		silo := keyedSilo(t, dir, key)
		p0Ingest(t, silo, p0Snap(p0DayA, 2, engine.SeverityLow, 990))
		if err := silo.SealDay(p0DayA + 60); err != nil {
			t.Fatalf("cle=%v: %v", keyed, err)
		}
		if archived, err := os.ReadFile(path + ".v3"); err != nil || !bytes.Equal(archived, legacy) {
			t.Fatalf("cle=%v: archive v3 absente ou alteree: %v", keyed, err)
		}
		hdr, entries, err := loadOracleDayFile(path, key)
		if err != nil || hdr.Version != engine.OracleVersion || len(entries) != 1 {
			t.Fatalf("cle=%v: tranche v4 %v", keyed, err)
		}
		inherited := hdr.Flags&engine.OracleFlagMaintenance != 0 && hdr.StartTsSec == p0DayA-600
		if inherited == keyed {
			t.Fatalf("cle=%v: bornes et drapeaux repris=%v", keyed, inherited)
		}
	}
}

// Une clé trop courte est refusée dès la création du silo.
func TestSilo_RejectsShortKey(t *testing.T) {
	if _, err := NewDailyOracleSilo(SiloConfig{StorageDir: t.TempDir(), HMACKey: []byte("court")}); !errors.Is(err, engine.ErrSealKey) {
		t.Fatalf("cle courte: %v", err)
	}
}

// Rattrapage : un jour antérieur scellé après un jour postérieur repropage le
// chaînage, et la chaîne reste intacte ; une tranche postérieure non
// authentifiée n'est jamais réécrite.
func TestSilo_BackfillRelinksSuccessors(t *testing.T) {
	dir := t.TempDir()
	silo := keyedSilo(t, dir, chainKey)
	dayC := p0DayB + 86400
	p0Ingest(t, silo, p0Snap(p0DayB, 2, engine.SeverityLow, 990), p0Snap(dayC, 3, engine.SeverityLow, 990))
	if err := silo.SealDay(dayC + 60); err != nil {
		t.Fatal(err)
	}
	backfill := keyedSilo(t, dir, chainKey)
	p0Ingest(t, backfill, p0Snap(p0DayA, 1, engine.SeverityLow, 990))
	if err := backfill.SealDay(p0DayA + 60); err != nil {
		t.Fatal(err)
	}
	a, b, c := loadKeyed(t, dir, p0DayA, chainKey), loadKeyed(t, dir, p0DayB, chainKey), loadKeyed(t, dir, dayC, chainKey)
	if b.PrevDaySeal != a.Seal || c.PrevDaySeal != b.Seal {
		t.Fatal("chainage non repropage apres rattrapage")
	}
	if breaks, _ := backfill.VerifyOracleChain(); len(breaks) != 0 {
		t.Fatalf("chaine rompue apres rattrapage: %+v", breaks)
	}
	// Tranche C remplacée sans la clé : le rescellement de B ne l'écrase pas.
	forged := engine.OracleDailyHeader{EpochDay: uint32(dayC / 86400), StartTsSec: dayC, EndTsSec: dayC + 60, MachineID: p0MachineID}
	if err := writeOracleDayAtomic(p0DayPath(dir, dayC), &forged, make([]engine.OracleVectorEntry, 1), nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(p0DayPath(dir, dayC))
	p0Ingest(t, backfill, p0Snap(p0DayB+5, 4, engine.SeverityLow, 990))
	if err := backfill.SealDay(p0DayB + 90); err != nil {
		t.Fatal(err)
	}
	if after, _ := os.ReadFile(p0DayPath(dir, dayC)); !bytes.Equal(before, after) {
		t.Fatal("tranche posterieure non authentifiee reecrite")
	}
}
