package c2blue55

import (
	"bytes"
	"os"
	"testing"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

// v3WriteDay écrit dans dir la tranche d'un jour avec la version d'en-tête
// voulue, scellée comme l'aurait fait le binaire de cette version.
func v3WriteDay(t *testing.T, dir string, ts uint64, version, flags uint16, snaps ...engine.ServerHealthSnapshot) []byte {
	t.Helper()
	entries := make([]engine.OracleVectorEntry, len(snaps))
	for i := range snaps {
		if version == engine.OracleVersionLegacy {
			engine.VectorizeServerHealth(&snaps[i], &entries[i].Bitcode)
		} else {
			engine.VectorizeServerHealthLocality(&snaps[i], &entries[i].Bitcode)
		}
		entries[i].RelativeSec = uint32(snaps[i].TimestampSec % 86400)
		entries[i].Subsystem = snaps[i].Subsystem
		entries[i].HealthScore = snaps[i].HealthScore
		entries[i].Severity = snaps[i].Severity
		entries[i].CorrelatedCount = snaps[i].CorrelatedCount
	}
	hdr := engine.OracleDailyHeader{
		Magic: engine.OracleMagic, Version: version, VectorDim: engine.OracleVectorDim,
		EpochDay: uint32(ts / 86400), StartTsSec: ts, EndTsSec: ts + 3600,
		VectorCount: uint32(len(entries)), AverageScore: 990,
		Flags: engine.OracleFlagSealed | flags, MachineID: p0MachineID,
	}
	hdr.Seal = engine.ComputeOracleDaySeal(&hdr, entries)
	var out bytes.Buffer
	out.Write(engine.AppendOracleDailyHeader(nil, &hdr))
	var eb [engine.OracleEntrySize]byte
	for i := range entries {
		engine.EncodeOracleVectorEntry(&eb, &entries[i])
		out.Write(eb[:])
	}
	if err := os.WriteFile(p0DayPath(dir, ts), out.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// Le silo scelle en version 4 des bitcodes de VectorizeServerHealthLocality.
func TestSilo_SealsVersion4LocalityBitcodes(t *testing.T) {
	dir := t.TempDir()
	silo := p0Silo(t, dir)
	snap := p0Snap(p0DayA, 7, engine.SeverityLow, 990)
	copy(snap.RawPayload[:], "sshd[42]: Accepted publickey for cl-ment")
	p0Ingest(t, silo, snap)
	if err := silo.SealDay(p0DayA + 60); err != nil {
		t.Fatal(err)
	}
	hdr, entries := p0LoadDay(t, dir, p0DayA)
	if hdr.Version != engine.OracleVersion {
		t.Fatalf("version scellee: %d", hdr.Version)
	}
	var want, legacy [8]uint64
	engine.VectorizeServerHealthLocality(&snap, &want)
	engine.VectorizeServerHealth(&snap, &legacy)
	if len(entries) != 1 || entries[0].Bitcode != want {
		t.Fatalf("bitcode scelle %x, attendu %x", entries[0].Bitcode, want)
	}
	if want == legacy {
		t.Fatal("les deux encodages coincident : le test ne discrimine pas")
	}
}

// Une tranche v2 du même jour n'est ni écrasée ni fusionnée : elle est conservée
// sous <chemin>.v2, ses bornes et drapeaux passent à la tranche v3.
func TestSilo_LegacyDayArchivedNotMerged(t *testing.T) {
	dir := t.TempDir()
	path := p0DayPath(dir, p0DayA)
	legacy := v3WriteDay(t, dir, p0DayA-600, engine.OracleVersionLegacy, engine.OracleFlagMaintenance,
		p0Snap(p0DayA-600, 1, engine.SeverityLow, 990), p0Snap(p0DayA-300, 2, engine.SeverityLow, 990))

	silo := p0Silo(t, dir)
	fresh := p0Snap(p0DayA, 3, engine.SeverityLow, 990)
	p0Ingest(t, silo, fresh)
	if err := silo.SealDay(p0DayA + 60); err != nil {
		t.Fatalf("SealDay: %v", err)
	}
	archived, err := os.ReadFile(path + ".v2")
	if err != nil || !bytes.Equal(archived, legacy) {
		t.Fatalf("archive v2 absente ou alteree: %v", err)
	}
	hdr, entries := p0LoadDay(t, dir, p0DayA)
	if hdr.Version != engine.OracleVersion || len(entries) != 1 {
		t.Fatalf("tranche v3: version %d, %d entrees (attendu 1, aucune entree v2)", hdr.Version, len(entries))
	}
	if hdr.Flags&engine.OracleFlagMaintenance == 0 || hdr.StartTsSec != p0DayA-600 {
		t.Fatalf("drapeaux 0x%x ou debut %d non repris de la v2", hdr.Flags, hdr.StartTsSec)
	}

	// Un second scellement fusionne normalement avec la tranche v3, l'archive reste.
	p0Ingest(t, silo, p0Snap(p0DayA+120, 4, engine.SeverityLow, 990))
	if err := silo.SealDay(p0DayA + 180); err != nil {
		t.Fatal(err)
	}
	if _, entries = p0LoadDay(t, dir, p0DayA); len(entries) != 2 {
		t.Fatalf("fusion v3: %d entrees, attendu 2", len(entries))
	}
	if again, _ := os.ReadFile(path + ".v2"); !bytes.Equal(again, legacy) {
		t.Fatal("archive v2 modifiee par le second scellement")
	}
}

// Un fichier distinct déjà présent sous le nom d'archive fait échouer le
// scellement sans toucher ni à lui ni à la tranche v2.
func TestSilo_LegacyArchiveCollisionRefused(t *testing.T) {
	dir := t.TempDir()
	path := p0DayPath(dir, p0DayA)
	legacy := v3WriteDay(t, dir, p0DayA, engine.OracleVersionLegacy, 0, p0Snap(p0DayA, 1, engine.SeverityLow, 990))
	other := []byte("archive etrangere")
	if err := os.WriteFile(path+".v2", other, 0o644); err != nil {
		t.Fatal(err)
	}
	silo := p0Silo(t, dir)
	p0Ingest(t, silo, p0Snap(p0DayA+60, 2, engine.SeverityLow, 990))
	if err := silo.SealDay(p0DayA + 120); err == nil {
		t.Fatal("scellement accepte malgre une archive distincte")
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, legacy) {
		t.Fatal("tranche v2 alteree")
	}
	if got, _ := os.ReadFile(path + ".v2"); !bytes.Equal(got, other) {
		t.Fatal("archive etrangere ecrasee")
	}
}

// La baseline ne lit que les tranches v3 non saturées.
func TestBuildServerBaseline_SkipsLegacyAndSaturatedDays(t *testing.T) {
	dir := t.TempDir()
	dayC := p0DayB + 86400
	v3WriteDay(t, dir, p0DayB, engine.OracleVersionLegacy, 0,
		p0Snap(p0DayB, 10, engine.SeverityLow, 990), p0Snap(p0DayB+60, 11, engine.SeverityLow, 990))
	saturated := p0Snap(dayC, 20, engine.SeverityLow, 990)
	v3WriteDay(t, dir, dayC, engine.OracleVersion, engine.OracleFlagSaturated,
		saturated, p0Snap(dayC+60, 21, engine.SeverityLow, 990), p0Snap(dayC+120, 22, engine.SeverityLow, 990))

	silo := p0Silo(t, dir)
	kept := p0Snap(p0DayA, 30, engine.SeverityLow, 990)
	p0Ingest(t, silo, kept)
	if err := silo.SealDay(p0DayA + 60); err != nil {
		t.Fatal(err)
	}
	oracle, err := silo.BuildServerBaseline(7)
	if err != nil {
		t.Fatal(err)
	}
	if oracle.Len() != 1 {
		t.Fatalf("baseline: %d entrees, attendu 1 (jour A seul)", oracle.Len())
	}
	cfg := engine.DefaultLocalityThresholds()
	var code [8]uint64
	engine.VectorizeServerHealthLocality(&kept, &code)
	if nominal, _, _, _ := oracle.QueryStateLocality(&code, cfg); !nominal {
		t.Fatal("entree du jour A non reconnue")
	}
	engine.VectorizeServerHealthLocality(&saturated, &code)
	if nominal, _, _, _ := oracle.QueryStateLocality(&code, cfg); nominal {
		t.Fatal("entree d'une tranche saturee admise dans la baseline")
	}

	// Sans le drapeau de saturation, la même tranche v3 entre dans la baseline.
	v3WriteDay(t, dir, dayC, engine.OracleVersion, 0,
		saturated, p0Snap(dayC+60, 21, engine.SeverityLow, 990), p0Snap(dayC+120, 22, engine.SeverityLow, 990))
	if oracle, err = silo.BuildServerBaseline(7); err != nil || oracle.Len() != 4 {
		t.Fatalf("temoin non sature: %v, %d entrees, attendu 4", err, oracle.Len())
	}
}
