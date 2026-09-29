package engine

import (
	"bytes"
	"errors"
	"sync"
	"testing"
)

func TestServerOracleMemoryAlignmentAndSizes(t *testing.T) {
	if OracleHeaderSize != 128 || OracleHeaderSizeV3 != 80 {
		t.Fatalf("OracleHeaderSize = %d, OracleHeaderSizeV3 = %d, attendu 128 et 80", OracleHeaderSize, OracleHeaderSizeV3)
	}
	if OracleEntrySize != 80 {
		t.Fatalf("OracleEntrySize = %d, attendu 80", OracleEntrySize)
	}
}

func TestServerOracleRoundTripAndSeal(t *testing.T) {
	hdr := OracleDailyHeader{
		EpochDay:     20716,
		StartTsSec:   1789824000,
		EndTsSec:     1789910400,
		MachineID:    0xDEADBEEFCAFEBA11,
		AverageScore: 980,
		Flags:        OracleFlagSealed,
	}

	entries := make([]OracleVectorEntry, 5)
	for i := range entries {
		entries[i].Bitcode[0] = uint64(i * 1000)
		entries[i].Bitcode[7] = 0xAA55AA55AA55AA55
		entries[i].RelativeSec = uint32(i * 3600)
		entries[i].Subsystem = OracleSubKernel
		entries[i].HealthScore = 950
		entries[i].Severity = SeverityLow
		entries[i].CorrelatedCount = 1
	}

	var buf bytes.Buffer
	if err := SaveOracleDay(&buf, &hdr, entries); err != nil {
		t.Fatalf("SaveOracleDay: %v", err)
	}

	// 1. Rechargement et vérification nominale
	loadedHdr, loadedEntries, err := LoadOracleDay(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatalf("LoadOracleDay: %v", err)
	}
	if loadedHdr.VectorCount != 5 {
		t.Fatalf("VectorCount = %d, attendu 5", loadedHdr.VectorCount)
	}
	if loadedHdr.MachineID != 0xDEADBEEFCAFEBA11 {
		t.Fatalf("MachineID mismatch: got %x", loadedHdr.MachineID)
	}
	if len(loadedEntries) != 5 {
		t.Fatalf("len(loadedEntries) = %d, attendu 5", len(loadedEntries))
	}
	if loadedEntries[0].Bitcode[7] != 0xAA55AA55AA55AA55 {
		t.Fatalf("Bitcode[7] altéré")
	}

	// 2. Vérification du rejet sur corruption du sceau SHA-256
	corrupted := buf.Bytes()
	corrupted[OracleHeaderSize+10] ^= 0xFF // Altération d'un bit de payload
	_, _, errCorrupt := LoadOracleDay(bytes.NewReader(corrupted))
	if errCorrupt != ErrOracleSeal {
		t.Fatalf("attendu ErrOracleSeal sur altération, obtenu %v", errCorrupt)
	}
}

func TestVectorizeServerHealth_DeterministicAndSeparation(t *testing.T) {
	snapNominal := ServerHealthSnapshot{
		TimestampSec:    1789850000,
		Subsystem:       OracleSubService,
		Action:          OracleActStateNominal,
		HealthScore:     990,
		Severity:        SeverityLow,
		CorrelatedCount: 1,
		EntropyQ8:       512,
		EntityID:        1001,
		ContextFlags:    0,
	}

	var codeNominal1, codeNominal2 [8]uint64
	VectorizeServerHealth(&snapNominal, &codeNominal1)
	VectorizeServerHealth(&snapNominal, &codeNominal2)

	// Déterminisme bit-exact
	if codeNominal1 != codeNominal2 {
		t.Fatalf("VectorizeServerHealth non déterministe")
	}

	// État d'anomalie critique
	snapCritical := ServerHealthSnapshot{
		TimestampSec:    1789850000,
		Subsystem:       OracleSubKernel,
		Action:          OracleActAnomalyBurst,
		HealthScore:     300,
		Severity:        SeverityCritical,
		CorrelatedCount: 50,
		EntropyQ8:       1800,
		EntityID:        6666,
		ContextFlags:    0x10,
	}
	var codeCritical [8]uint64
	VectorizeServerHealth(&snapCritical, &codeCritical)

	// Distance de Hamming entre nominal et critique
	dist := HammingDistance512(&codeNominal1, &codeCritical)
	if dist < 120 {
		t.Fatalf("distance de Hamming insuffisante entre nominal et critique: %d bits", dist)
	}
}

func TestServerBaselineOracle_Query(t *testing.T) {
	oracle := NewServerBaselineOracle(0x1234, 45)

	var snapNominal ServerHealthSnapshot
	snapNominal.TimestampSec = 1789824000 + 3600
	snapNominal.Subsystem = OracleSubAuth
	snapNominal.Action = OracleActStateNominal
	snapNominal.HealthScore = 980
	snapNominal.Severity = SeverityLow
	snapNominal.EntityID = 100

	var nominalCode [8]uint64
	VectorizeServerHealth(&snapNominal, &nominalCode)

	entry := OracleVectorEntry{
		Bitcode:     nominalCode,
		RelativeSec: 3600,
		Subsystem:   OracleSubAuth,
		HealthScore: 980,
		Severity:    SeverityLow,
	}
	oracle.IngestDailyEntries([]OracleVectorEntry{entry})

	// Requête identique -> distance 0 et isNominal = true
	dist0, isNom0, sub0, sc0 := oracle.QueryState(&nominalCode)
	if dist0 != 0 || !isNom0 || sub0 != OracleSubAuth || sc0 != 980 {
		t.Fatalf("requête identique: dist=%d, isNom=%v, sub=%d, sc=%d", dist0, isNom0, sub0, sc0)
	}

	// Requête d'un état très distant (attaque / anomalie)
	var alienCode [8]uint64
	for i := range alienCode {
		alienCode[i] = nominalCode[i] ^ 0xFFFFFFFFFFFFFFFF // 512 bits inversés
	}
	distAlien, isNomAlien, _, _ := oracle.QueryState(&alienCode)
	if distAlien != 512 || isNomAlien {
		t.Fatalf("requête alien: dist=%d, isNom=%v", distAlien, isNomAlien)
	}
}

func BenchmarkVectorizeServerHealth(b *testing.B) {
	snap := ServerHealthSnapshot{
		TimestampSec:    1789850000,
		Subsystem:       OracleSubService,
		Action:          OracleActStateNominal,
		HealthScore:     990,
		Severity:        SeverityLow,
		CorrelatedCount: 1,
		EntropyQ8:       512,
		EntityID:        1001,
	}
	var out [8]uint64
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VectorizeServerHealth(&snap, &out)
	}
}

func BenchmarkServerBaselineOracleQuery(b *testing.B) {
	oracle := NewServerBaselineOracle(0x1234, 45)
	entries := make([]OracleVectorEntry, 1024)
	for i := range entries {
		entries[i].Bitcode[0] = uint64(i)
		entries[i].Subsystem = OracleSubKernel
		entries[i].HealthScore = 900
	}
	oracle.IngestDailyEntries(entries)

	var query [8]uint64
	query[0] = 512
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		oracle.QueryState(&query)
	}
}

// oracleDayWithVersion scelle une tranche en forçant la version d'en-tête,
// comme l'aurait écrite un binaire antérieur ou postérieur ; l'en-tête a la
// taille de sa version (80 octets avant la version 4, 128 ensuite).
func oracleDayWithVersion(version uint16, entries []OracleVectorEntry) []byte {
	hdr := OracleDailyHeader{
		Magic: OracleMagic, Version: version, VectorDim: OracleVectorDim,
		EpochDay: 20716, StartTsSec: 1789824000, EndTsSec: 1789910400,
		VectorCount: uint32(len(entries)), MachineID: 0xDEADBEEFCAFEBA11, Flags: OracleFlagSealed,
	}
	hdr.Seal = ComputeOracleDaySeal(&hdr, entries)
	out := AppendOracleDailyHeader(nil, &hdr)
	var eb [OracleEntrySize]byte
	for i := range entries {
		EncodeOracleVectorEntry(&eb, &entries[i])
		out = append(out, eb[:]...)
	}
	return out
}

// SaveOracleDay écrit la version 4 ; LoadOracleDay admet les versions 2 et 3
// (en-tête de 80 octets) et refuse les versions 1 et 5.
func TestOracleVersion4_WriteAndLegacyRead(t *testing.T) {
	if OracleVersion != 4 || OracleVersionV3 != 3 || OracleVersionLegacy != 2 {
		t.Fatalf("versions: %d / %d / %d", OracleVersion, OracleVersionV3, OracleVersionLegacy)
	}
	hdr := OracleDailyHeader{EpochDay: 20716, MachineID: 1}
	var buf bytes.Buffer
	if err := SaveOracleDay(&buf, &hdr, make([]OracleVectorEntry, 2)); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != OracleHeaderSize+2*OracleEntrySize {
		t.Fatalf("taille v4 %d", buf.Len())
	}
	got, _, err := LoadOracleDay(bytes.NewReader(buf.Bytes()))
	if err != nil || got.Version != 4 {
		t.Fatalf("relecture v4: %v, version %v", err, got)
	}
	entries := make([]OracleVectorEntry, 3)
	entries[1].Bitcode[4] = 0xABCDEF
	for _, tc := range []struct {
		version uint16
		want    error
	}{{1, ErrOracleVersion}, {2, nil}, {3, nil}, {4, nil}, {5, ErrOracleVersion}} {
		h, e, err := LoadOracleDay(bytes.NewReader(oracleDayWithVersion(tc.version, entries)))
		if !errors.Is(err, tc.want) {
			t.Fatalf("version %d: %v, attendu %v", tc.version, err, tc.want)
		}
		if err == nil && (h.Version != tc.version || len(e) != 3 || e[1].Bitcode[4] != 0xABCDEF) {
			t.Fatalf("version %d: relecture alteree", tc.version)
		}
	}
	// Le sceau couvre la version : relabelliser une v2 en v3, ou une v3 en v4, est détecté.
	v2 := oracleDayWithVersion(2, entries)
	v2[8] = 3
	if _, _, err := LoadOracleDay(bytes.NewReader(v2)); !errors.Is(err, ErrOracleSeal) {
		t.Fatalf("v2 relabellisee en v3: %v", err)
	}
	v3 := oracleDayWithVersion(3, entries)
	v3[8] = 4
	if _, _, err := LoadOracleDay(bytes.NewReader(v3)); err == nil {
		t.Fatal("v3 relabellisee en v4 acceptee")
	}
}

func localityEntry(s *ServerHealthSnapshot) OracleVectorEntry {
	var e OracleVectorEntry
	VectorizeServerHealthLocality(s, &e.Bitcode)
	e.Subsystem = s.Subsystem
	e.HealthScore = s.HealthScore
	e.Severity = s.Severity
	return e
}

func TestQueryStateLocality_Semantics(t *testing.T) {
	cfg := DefaultLocalityThresholds()
	o := NewServerBaselineOracle(1, 0)

	base := localityBase()
	if nominal, d, sub, score := o.QueryStateLocality(localityCode(&base), cfg); nominal || d != localityDistanceNone || sub != 0 || score != 0 {
		t.Fatalf("oracle vide: %v %+v %d %d", nominal, d, sub, score)
	}

	far := base
	far.HealthScore = 850 // environ 8 bits sur le mot 3
	near := base
	near.HealthScore = 960 // environ 1 bit
	o.IngestDailyEntries([]OracleVectorEntry{localityEntry(&far), localityEntry(&near)})

	if nominal, _, _, _ := o.QueryStateLocality(nil, cfg); nominal {
		t.Fatal("code nil nominal")
	}

	// La référence voisine la plus proche est retenue, pas la première.
	nominal, d, sub, score := o.QueryStateLocality(localityCode(&base), cfg)
	if !nominal || score != 960 || sub != OracleSubService || d.Categorical != 0 {
		t.Fatalf("voisin le plus proche: %v %+v %d %d", nominal, d, sub, score)
	}
	if want := LocalityDistanceOf(localityCode(&base), localityCode(&near)); d != want {
		t.Fatalf("ecart rendu %+v, attendu %+v", d, want)
	}

	// Une aggravation de sévérité n'est jamais nominale, même à métriques égales.
	worse := base
	worse.Severity = SeverityHigh
	nominal, d, _, _ = o.QueryStateLocality(localityCode(&worse), cfg)
	if nominal || d.SeverityRise != 2 {
		t.Fatalf("aggravation: %v %+v", nominal, d)
	}

	// Un autre sous-système n'est pas nominal ; l'écart catégoriel est rapporté.
	other := base
	other.Subsystem = OracleSubAuth
	nominal, d, _, _ = o.QueryStateLocality(localityCode(&other), cfg)
	if nominal || d.Categorical == 0 {
		t.Fatalf("autre sous-systeme: %v %+v", nominal, d)
	}

	// Une autre entité n'est pas nominale sous les seuils par défaut.
	alien := base
	alien.EntityID = 9999
	if nominal, _, _, _ = o.QueryStateLocality(localityCode(&alien), cfg); nominal {
		t.Fatal("entite etrangere nominale")
	}

	// Cohérence avec EvaluateLocalityMatch sur chaque référence.
	for _, q := range []ServerHealthSnapshot{base, worse, other, alien, far} {
		want := false
		for _, ref := range []ServerHealthSnapshot{far, near} {
			want = want || EvaluateLocalityMatch(localityCode(&q), localityCode(&ref), cfg)
		}
		if got, _, _, _ := o.QueryStateLocality(localityCode(&q), cfg); got != want {
			t.Fatalf("QueryStateLocality=%v, EvaluateLocalityMatch=%v pour %+v", got, want, q)
		}
	}
}

func TestQueryStateLocality_ZeroAlloc(t *testing.T) {
	o := NewServerBaselineOracle(1, 0)
	base := localityBase()
	entries := make([]OracleVectorEntry, 512)
	for i := range entries {
		s := base
		s.EntityID = uint64(i + 1)
		entries[i] = localityEntry(&s)
	}
	o.IngestDailyEntries(entries)
	code := localityCode(&base)
	cfg := DefaultLocalityThresholds()
	if n := testing.AllocsPerRun(200, func() { o.QueryStateLocality(code, cfg) }); n != 0 {
		t.Fatalf("QueryStateLocality: %v allocations", n)
	}
}

// Ingestion et interrogations concurrentes ; -race vérifie le verrou partagé.
func TestQueryStateLocality_ConcurrentWithIngest(t *testing.T) {
	o := NewServerBaselineOracle(1, 0)
	base := localityBase()
	code := localityCode(&base)
	cfg := DefaultLocalityThresholds()
	var wg sync.WaitGroup
	wg.Go(func() {
		for i := range 200 {
			s := base
			s.EntityID = uint64(i + 900) // couvre l'entité 1001 de localityBase
			o.IngestDailyEntries([]OracleVectorEntry{localityEntry(&s)})
		}
	})
	for range 4 {
		wg.Go(func() {
			for range 200 {
				o.QueryStateLocality(code, cfg)
			}
		})
	}
	wg.Wait()
	if nominal, _, _, _ := o.QueryStateLocality(code, cfg); !nominal {
		t.Fatal("entite 1001 ingeree mais non reconnue")
	}
}

func BenchmarkQueryStateLocality(b *testing.B) {
	o := NewServerBaselineOracle(1, 0)
	base := localityBase()
	entries := make([]OracleVectorEntry, 10000)
	for i := range entries {
		s := base
		s.EntityID = uint64(i + 5000)
		entries[i] = localityEntry(&s)
	}
	o.IngestDailyEntries(entries)
	code := localityCode(&base)
	cfg := DefaultLocalityThresholds()
	b.ReportAllocs()
	for b.Loop() {
		o.QueryStateLocality(code, cfg)
	}
}
