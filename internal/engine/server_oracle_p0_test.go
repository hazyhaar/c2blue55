package engine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"runtime"
	"sync"
	"testing"
)

// sealedOracleDay produit un binaire .c2oracle valide de n entrées.
func sealedOracleDay(t *testing.T, n int) []byte {
	t.Helper()
	hdr := OracleDailyHeader{
		EpochDay:     20716,
		StartTsSec:   1789824000,
		EndTsSec:     1789910400,
		MachineID:    0xDEADBEEFCAFEBA11,
		AverageScore: 980,
		Flags:        OracleFlagSealed,
	}
	entries := make([]OracleVectorEntry, n)
	for i := range entries {
		entries[i].Bitcode[0] = uint64(i + 1)
		entries[i].RelativeSec = uint32(i * 60)
		entries[i].Subsystem = OracleSubAuth
		entries[i].HealthScore = 990
		entries[i].Severity = SeverityLow
	}
	var buf bytes.Buffer
	if err := SaveOracleDay(&buf, &hdr, entries); err != nil {
		t.Fatalf("SaveOracleDay: %v", err)
	}
	return buf.Bytes()
}

// Toute métadonnée de l'en-tête altérée après scellement doit être rejetée.
func TestLoadOracleDay_SealCoversHeader(t *testing.T) {
	fields := []struct {
		name string
		off  int
	}{
		{"EpochDay", 12},
		{"StartTsSec", 16},
		{"EndTsSec", 24},
		{"AverageScore", 36},
		{"Flags", 38},
		{"MachineID", 40},
	}
	orig := sealedOracleDay(t, 3)
	for _, f := range fields {
		t.Run(f.name, func(t *testing.T) {
			tampered := bytes.Clone(orig)
			tampered[f.off] ^= 0x01
			_, _, err := LoadOracleDay(bytes.NewReader(tampered))
			if !errors.Is(err, ErrOracleSeal) {
				t.Fatalf("altération de %s acceptée: err=%v", f.name, err)
			}
		})
	}
}

// oracleAllocBytes mesure les octets alloués par un LoadOracleDay.
func oracleAllocBytes(data []byte) (uint64, error) {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, _, err := LoadOracleDay(bytes.NewReader(data))
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc, err
}

// Un en-tête qui annonce plus d'entrées que la borne est refusé avant toute allocation.
func TestLoadOracleDay_RejectsOversizedVectorCount(t *testing.T) {
	data := sealedOracleDay(t, 1)[:OracleHeaderSize]
	binary.LittleEndian.PutUint32(data[32:36], 1<<24+1)
	alloc, err := oracleAllocBytes(data)
	if err == nil {
		t.Fatal("en-tête surdimensionné accepté")
	}
	if alloc > 1<<20 {
		t.Fatalf("en-tête hostile: %d octets alloués avant rejet", alloc)
	}
}

// Un fichier tronqué qui annonce un grand nombre d'entrées (sous la borne)
// ne doit pas provoquer d'allocation proportionnelle à ce nombre annoncé.
func TestLoadOracleDay_TruncatedBodyDoesNotPreallocate(t *testing.T) {
	data := sealedOracleDay(t, 1)[:OracleHeaderSize]
	binary.LittleEndian.PutUint32(data[32:36], 1<<20) // 80 Mio annoncés, 0 fournis
	alloc, err := oracleAllocBytes(data)
	if err == nil {
		t.Fatal("fichier tronqué accepté")
	}
	if alloc > 8<<20 {
		t.Fatalf("fichier tronqué: %d octets alloués pour un corps vide", alloc)
	}
}

// Ingestion et interrogation concurrentes : le détecteur de course doit rester muet.
func TestServerBaselineOracle_ConcurrentIngestQuery(t *testing.T) {
	oracle := NewServerBaselineOracle(0x1234, 45)
	batch := make([]OracleVectorEntry, 64)
	for i := range batch {
		batch[i].Bitcode[0] = uint64(i)
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for range 200 {
				oracle.IngestDailyEntries(batch)
			}
		})
		wg.Go(func() {
			var q [8]uint64
			for range 200 {
				oracle.QueryState(&q)
				_ = oracle.Len()
			}
		})
	}
	wg.Wait()
	if got, want := oracle.Len(), 4*200*len(batch); got != want {
		t.Fatalf("Len = %d, attendu %d", got, want)
	}
}

// Le rejet d'un en-tête surdimensionné porte l'erreur contractuelle dédiée.
func TestLoadOracleDay_OversizedIsErrOracleTooLarge(t *testing.T) {
	data := sealedOracleDay(t, 1)[:OracleHeaderSize]
	binary.LittleEndian.PutUint32(data[32:36], OracleMaxVectorCount+1)
	if _, _, err := LoadOracleDay(bytes.NewReader(data)); !errors.Is(err, ErrOracleTooLarge) {
		t.Fatalf("err=%v, attendu ErrOracleTooLarge", err)
	}
}

// Le plafond couvre six entrées par seconde sur un jour et borne une tranche sous 41 Mio.
func TestOracleMaxVectorCount_DayScale(t *testing.T) {
	if OracleMaxVectorCount != 1<<19 {
		t.Fatalf("OracleMaxVectorCount = %d, attendu 1<<19", OracleMaxVectorCount)
	}
	if OracleMaxVectorCount < 6*86400 {
		t.Fatalf("plafond %d sous six entrées par seconde", OracleMaxVectorCount)
	}
	if size := OracleHeaderSize + OracleMaxVectorCount*OracleEntrySize; size > 41<<20 {
		t.Fatalf("tranche maximale de %d octets > 41 Mio", size)
	}
}

// Le seuil de dégradation exporté pilote l'encodeur historique comme le silo.
func TestDegradedHealthScore_DrivesLegacyEncoder(t *testing.T) {
	if DegradedHealthScore != 700 {
		t.Fatalf("DegradedHealthScore = %d, attendu 700", DegradedHealthScore)
	}
	at := ServerHealthSnapshot{TimestampSec: 1789850000, Subsystem: OracleSubService, Action: OracleActStateNominal, HealthScore: DegradedHealthScore, EntityID: 1}
	below := at
	below.HealthScore = DegradedHealthScore - 1
	var a, b [8]uint64
	VectorizeServerHealth(&at, &a)
	VectorizeServerHealth(&below, &b)
	if (a[0]^b[0])&0xF000F000F000F000 != 0xF000F000F000F000 {
		t.Fatalf("le motif de dégradation ne bascule pas au seuil: %#x / %#x", a[0], b[0])
	}
}

// SaveOracleDay refuse une entrée de plus que le plafond et accepte le plafond exact,
// qui se relit intégralement.
func TestSaveOracleDay_BoundaryAtMax(t *testing.T) {
	var buf bytes.Buffer
	over := make([]OracleVectorEntry, OracleMaxVectorCount+1)
	if err := SaveOracleDay(&buf, &OracleDailyHeader{}, over); !errors.Is(err, ErrOracleTooLarge) {
		t.Fatalf("max+1: err=%v, attendu ErrOracleTooLarge", err)
	}
	buf.Reset()
	if err := SaveOracleDay(&buf, &OracleDailyHeader{}, over[:OracleMaxVectorCount]); err != nil {
		t.Fatalf("max: %v", err)
	}
	hdr, entries, err := LoadOracleDay(bytes.NewReader(buf.Bytes()))
	if err != nil || hdr.VectorCount != OracleMaxVectorCount || len(entries) != OracleMaxVectorCount {
		t.Fatalf("relecture au plafond: err=%v", err)
	}
}
