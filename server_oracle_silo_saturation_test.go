package c2blue55

import (
	"testing"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

// hasBitcode dit si une entrée porte le bitcode de snap.
func hasBitcode(entries []engine.OracleVectorEntry, snap *engine.ServerHealthSnapshot) bool {
	var want [8]uint64
	engine.VectorizeServerHealthLocality(snap, &want)
	for i := range entries {
		if entries[i].Bitcode == want {
			return true
		}
	}
	return false
}

// Une journée qui dépasse le plafond n'arrête pas le collecteur : l'entrée
// normale en trop passe par le réservoir, l'entrée Critical est gardée en
// évinçant une entrée normale, la rotation scelle la tranche pleine marquée
// échantillonnée, et l'en-tête compte tous les événements observés.
func TestSilo_IngestBeyondCapDoesNotBlockRotation(t *testing.T) {
	dir := t.TempDir()
	silo := p0Silo(t, dir)
	for i := range engine.OracleMaxVectorCount {
		snap := p0Snap(p0DayA+uint64(i%3600), uint64(i)+1, engine.SeverityLow, 950)
		if err := silo.IngestSnapshot(&snap); err != nil {
			t.Fatalf("entrée %d: %v", i, err)
		}
	}
	critical := p0Snap(p0DayA+11, 1<<41, engine.SeverityCritical, 200)
	p0Ingest(t, silo, p0Snap(p0DayA+10, 1<<40, engine.SeverityLow, 950), critical)
	if _, active, ingested, _ := silo.Stats(); active != engine.OracleMaxVectorCount || ingested != engine.OracleMaxVectorCount+2 {
		t.Fatalf("actives=%d ingérées=%d, attendu %d et %d", active, ingested, engine.OracleMaxVectorCount, engine.OracleMaxVectorCount+2)
	}
	if got := silo.Dropped(); got != 2 {
		t.Fatalf("Dropped=%d, attendu 2", got)
	}

	p0Ingest(t, silo, p0Snap(p0DayB, 7, engine.SeverityLow, 950))
	day, active, _, rotations := silo.Stats()
	if day != uint32(p0DayB/86400) || active != 1 || rotations != 1 {
		t.Fatalf("après rotation: jour=%d actives=%d rotations=%d", day, active, rotations)
	}
	hdr, entries := p0LoadDay(t, dir, p0DayA)
	if len(entries) != engine.OracleMaxVectorCount {
		t.Fatalf("%d entrées scellées, attendu %d", len(entries), engine.OracleMaxVectorCount)
	}
	if !hasBitcode(entries, &critical) {
		t.Fatal("l'entrée Critical a été écartée par la saturation")
	}
	want := engine.OracleFlagSealed | engine.OracleFlagSaturated | engine.OracleFlagSampled | engine.OracleFlagAnomalies | engine.OracleFlagDegraded
	if hdr.Flags&want != want {
		t.Fatalf("drapeaux=%#x, attendu au moins %#x", hdr.Flags, want)
	}
	if hdr.ObservedCount != engine.OracleMaxVectorCount+2 {
		t.Fatalf("ObservedCount=%d, attendu %d", hdr.ObservedCount, engine.OracleMaxVectorCount+2)
	}
	if err := silo.SealDay(p0DayB + 60); err != nil {
		t.Fatalf("scellement du jour suivant: %v", err)
	}
	if hdr, _ := p0LoadDay(t, dir, p0DayB); hdr.Flags&(engine.OracleFlagSaturated|engine.OracleFlagSampled) != 0 {
		t.Fatalf("saturation propagée au jour suivant: %#x", hdr.Flags)
	}
}

// Une tranche déjà scellée au plafond, relancée avec de nouvelles entrées,
// n'échoue pas : l'entrée High nouvelle est gardée, les entrées normales sont
// échantillonnées, le surplus est compté et la tranche marquée échantillonnée.
func TestSilo_SealMergeBeyondCapSamples(t *testing.T) {
	dir := t.TempDir()
	day := uint32(p0DayA / 86400)
	existing := make([]engine.OracleVectorEntry, engine.OracleMaxVectorCount)
	for i := range existing {
		existing[i].Bitcode[0] = uint64(i) + 1
		existing[i].HealthScore = 950
		existing[i].Severity = engine.SeverityLow
	}
	hdr := engine.OracleDailyHeader{EpochDay: day, StartTsSec: p0DayA, EndTsSec: p0DayA + 3600, Flags: engine.OracleFlagSealed, MachineID: p0MachineID}
	if err := writeOracleDayAtomic(p0DayPath(dir, p0DayA), &hdr, existing, nil); err != nil {
		t.Fatalf("tranche préexistante: %v", err)
	}

	silo := p0Silo(t, dir)
	high := p0Snap(p0DayA+11, 2, engine.SeverityHigh, 400)
	p0Ingest(t, silo,
		p0Snap(p0DayA+10, 1, engine.SeverityLow, 950),
		high,
		p0Snap(p0DayA+12, 3, engine.SeverityLow, 950))
	if err := silo.SealDay(p0DayA + 86399); err != nil {
		t.Fatalf("SealDay au-delà du plafond: %v", err)
	}
	if got := silo.Dropped(); got != 3 {
		t.Fatalf("Dropped=%d, attendu 3", got)
	}
	if _, active, _, _ := silo.Stats(); active != 0 {
		t.Fatalf("tranche non réinitialisée: %d entrées actives", active)
	}
	got, entries := p0LoadDay(t, dir, p0DayA)
	if len(entries) != engine.OracleMaxVectorCount {
		t.Fatalf("%d entrées, attendu %d", len(entries), engine.OracleMaxVectorCount)
	}
	if !hasBitcode(entries, &high) {
		t.Fatal("l'entrée High nouvelle a été écartée")
	}
	want := engine.OracleFlagSaturated | engine.OracleFlagSampled | engine.OracleFlagAnomalies | engine.OracleFlagDegraded
	if got.Flags&want != want {
		t.Fatalf("drapeaux=%#x, attendu au moins %#x", got.Flags, want)
	}
	if got.ObservedCount != engine.OracleMaxVectorCount+3 {
		t.Fatalf("ObservedCount=%d, attendu %d", got.ObservedCount, engine.OracleMaxVectorCount+3)
	}
}

// Le réservoir garde toutes les entrées High/Critical, un échantillon des
// autres réparti uniformément sur le flux, et il est déterministe.
func TestSampleOracleEntries_PriorityAndUniformity(t *testing.T) {
	const total, capacity, prioEvery = 100_000, 10_000, 97
	entries := make([]engine.OracleVectorEntry, total)
	nPrio := 0
	for i := range entries {
		entries[i].Bitcode[0] = uint64(i)
		entries[i].Severity = engine.SeverityLow
		if i%prioEvery == 0 {
			entries[i].Severity = engine.SeverityCritical
			nPrio++
		}
	}
	g1 := splitMix64{state: 42}
	out := sampleOracleEntries(entries, capacity, &g1)
	if len(out) != capacity {
		t.Fatalf("%d entrées gardées, attendu %d", len(out), capacity)
	}
	prio := 0
	var deciles [10]int
	for i := range out {
		if i > 0 && out[i].Bitcode[0] <= out[i-1].Bitcode[0] {
			t.Fatal("ordre d'origine non conservé")
		}
		if out[i].Severity == engine.SeverityCritical {
			prio++
			continue
		}
		deciles[out[i].Bitcode[0]*10/total]++
	}
	if prio != nPrio {
		t.Fatalf("%d entrées prioritaires gardées sur %d", prio, nPrio)
	}
	// Chaque décile du flux reçoit (capacity - nPrio) / 10 entrées normales ;
	// l'écart type binomial vaut environ 30, la borne en admet dix fois plus.
	expect := (capacity - nPrio) / 10
	for d, n := range deciles {
		if n < expect-300 || n > expect+300 {
			t.Fatalf("décile %d: %d entrées, attendu %d ± 300 (%v)", d, n, expect, deciles)
		}
	}
	g2 := splitMix64{state: 42}
	again := sampleOracleEntries(entries, capacity, &g2)
	for i := range out {
		if out[i] != again[i] {
			t.Fatal("échantillonnage non déterministe")
		}
	}
	// Prioritaires plus nombreuses que la capacité : elles seules sont gardées.
	g3 := splitMix64{state: 1}
	if few := sampleOracleEntries(entries, nPrio/2, &g3); len(few) != nPrio/2 {
		t.Fatalf("%d entrées, attendu %d", len(few), nPrio/2)
	} else {
		for i := range few {
			if few[i].Severity != engine.SeverityCritical {
				t.Fatal("entrée normale gardée alors que les prioritaires débordent")
			}
		}
	}
}

// Une tranche échantillonnée entre dans la baseline ; une tranche saturée
// sans échantillonnage (ancien comportement) en reste exclue.
func TestBuildServerBaseline_AdmitsSampledDays(t *testing.T) {
	dir := t.TempDir()
	s := p0Snap(p0DayA, 5, engine.SeverityLow, 990)
	var e engine.OracleVectorEntry
	engine.VectorizeServerHealthLocality(&s, &e.Bitcode)
	e.Subsystem, e.HealthScore, e.Severity = s.Subsystem, s.HealthScore, s.Severity
	hdr := engine.OracleDailyHeader{EpochDay: uint32(p0DayA / 86400), StartTsSec: p0DayA, EndTsSec: p0DayA + 60,
		Flags: engine.OracleFlagSealed | engine.OracleFlagSaturated | engine.OracleFlagSampled, MachineID: p0MachineID, ObservedCount: 10}
	if err := writeOracleDayAtomic(p0DayPath(dir, p0DayA), &hdr, []engine.OracleVectorEntry{e}, nil); err != nil {
		t.Fatal(err)
	}
	hdr2 := engine.OracleDailyHeader{EpochDay: uint32(p0DayB / 86400), StartTsSec: p0DayB, EndTsSec: p0DayB + 60,
		Flags: engine.OracleFlagSealed | engine.OracleFlagSaturated, MachineID: p0MachineID}
	e2 := e
	e2.Bitcode[6] ^= 1
	if err := writeOracleDayAtomic(p0DayPath(dir, p0DayB), &hdr2, []engine.OracleVectorEntry{e2}, nil); err != nil {
		t.Fatal(err)
	}
	o, err := p0Silo(t, dir).BuildServerBaseline(7)
	if err != nil {
		t.Fatal(err)
	}
	if o.Len() != 1 {
		t.Fatalf("baseline: %d entrées, attendu 1 (tranche échantillonnée seule)", o.Len())
	}
}

// TestSilo_EpochDayZeroCumulates vérifie que les événements du jour Unix 0
// (1970-01-01) sont cumulés sans réinitialisation à chaque ligne (défaut D1 résolu).
func TestSilo_EpochDayZeroCumulates(t *testing.T) {
	dir := t.TempDir()
	silo := p0Silo(t, dir)
	for i := range 5 {
		snap := p0Snap(uint64(i*60), uint64(i+1), engine.SeverityLow, 950)
		if err := silo.IngestSnapshot(&snap); err != nil {
			t.Fatalf("ingest %d: %v", i, err)
		}
	}
	day, active, ingested, _ := silo.Stats()
	if day != 0 || active != 5 || ingested != 5 {
		t.Fatalf("jour 0: day=%d active=%d ingested=%d, attendu day=0 active=5 ingested=5", day, active, ingested)
	}
}

