package engine

import (
	"fmt"
	"math/rand/v2"
	"testing"
)

func localityBase() ServerHealthSnapshot {
	s := ServerHealthSnapshot{
		TimestampSec:    1789850000,
		Subsystem:       OracleSubService,
		Action:          OracleActStateNominal,
		HealthScore:     980,
		Severity:        SeverityLow,
		CorrelatedCount: 4,
		EntropyQ8:       1100,
		EntityID:        1001,
	}
	copy(s.RawPayload[:], "systemd[1]: Started session-42.scope - Session 42 of User cl-ment.")
	return s
}

func localityDist(enc func(*ServerHealthSnapshot, *[8]uint64), a, b *ServerHealthSnapshot) int {
	var ca, cb [8]uint64
	enc(a, &ca)
	enc(b, &cb)
	return HammingDistance512(&ca, &cb)
}

// Une petite variation scalaire donne une petite distance ; l'encodeur historique l'amplifie en avalanche.
func TestLocalityEncoder_SmallDeltaSmallDistance(t *testing.T) {
	base := localityBase()
	cases := []struct {
		name   string
		mutate func(*ServerHealthSnapshot)
		maxLoc int
	}{
		{"score -16", func(s *ServerHealthSnapshot) { s.HealthScore -= 16 }, 2},
		{"score -160", func(s *ServerHealthSnapshot) { s.HealthScore -= 160 }, 11},
		{"entropie +32 (0,125 bit)", func(s *ServerHealthSnapshot) { s.EntropyQ8 += 32 }, 1},
		{"heure +5 min", func(s *ServerHealthSnapshot) { s.TimestampSec += 300 }, 2},
		{"correlated 4->5", func(s *ServerHealthSnapshot) { s.CorrelatedCount = 5 }, 0},
		{"correlated 4->64", func(s *ServerHealthSnapshot) { s.CorrelatedCount = 64 }, 8},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := base
			c.mutate(&m)
			loc := localityDist(VectorizeServerHealthLocality, &base, &m)
			legacy := localityDist(VectorizeServerHealth, &base, &m)
			t.Logf("distance locale=%d, historique=%d", loc, legacy)
			if loc > c.maxLoc {
				t.Fatalf("distance locale %d > %d", loc, c.maxLoc)
			}
		})
	}
}

// Le code horaire est circulaire : 23:59 et 00:01 sont voisins.
func TestLocalityEncoder_TimeWrapsAround(t *testing.T) {
	a, b := localityBase(), localityBase()
	day := a.TimestampSec / 86400 * 86400
	a.TimestampSec = day + 86400 - 60
	b.TimestampSec = day + 86400 + 60
	if d := localityDist(VectorizeServerHealthLocality, &a, &b); d > 2 {
		t.Fatalf("minuit: distance %d", d)
	}
	b.TimestampSec = day + 86400 - 60 + 43200
	if d := localityDist(VectorizeServerHealthLocality, &a, &b); d != 64 {
		t.Fatalf("douze heures d'écart: distance %d, attendu 64", d)
	}
}

// Un changement de catégorie ou un basculement vers une attaque reste nettement séparé.
func TestLocalityEncoder_CategoricalAndAttackSeparation(t *testing.T) {
	base := localityBase()
	sub := base
	sub.Subsystem = OracleSubAuth
	if d := localityDist(VectorizeServerHealthLocality, &base, &sub); d < 16 {
		t.Fatalf("changement de sous-système: distance %d < 16", d)
	}
	attack := base
	attack.Subsystem, attack.Action = OracleSubAuth, OracleActAuthFailure
	attack.HealthScore, attack.Severity = 400, SeverityHigh
	attack.EntityID = 6666
	copy(attack.RawPayload[:], "sshd[991]: Failed password for invalid user admin from 203.0.113.9 port 4242\x00")
	d := localityDist(VectorizeServerHealthLocality, &base, &attack)
	t.Logf("nominal vs attaque: distance %d", d)
	if d < 120 {
		t.Fatalf("attaque trop proche du nominal: %d", d)
	}
}

func TestLocalityEncoder_ZeroAlloc(t *testing.T) {
	s := localityBase()
	var out [8]uint64
	if n := testing.AllocsPerRun(100, func() { VectorizeServerHealthLocality(&s, &out) }); n != 0 {
		t.Fatalf("%v allocations par appel", n)
	}
}

func BenchmarkVectorizeServerHealthLocality(b *testing.B) {
	s := localityBase()
	var out [8]uint64
	b.ReportAllocs()
	for b.Loop() {
		VectorizeServerHealthLocality(&s, &out)
	}
}

// Coût des mots 0 à 6 seuls : charge vide, SimHash court-circuité.
func BenchmarkVectorizeServerHealthLocalityNoPayload(b *testing.B) {
	s := localityBase()
	s.RawPayload = [FeaturePayloadBytes]byte{}
	var out [8]uint64
	b.ReportAllocs()
	for b.Loop() {
		VectorizeServerHealthLocality(&s, &out)
	}
}

func localityCode(s *ServerHealthSnapshot) *[8]uint64 {
	var c [8]uint64
	VectorizeServerHealthLocality(s, &c)
	return &c
}

// Une dérive progressive des métriques reste nominale à chaque pas, alors que sa
// distance totale dépasse l'ordre de grandeur d'un seul changement de catégorie.
func TestEvaluateLocalityMatch_ProgressiveDriftStaysNominal(t *testing.T) {
	cfg := DefaultLocalityThresholds()
	base := localityBase()
	ref := localityCode(&base)
	cur := base
	for step := range 10 {
		cur.HealthScore -= 16
		cur.EntropyQ8 += 12
		cur.TimestampSec += 180
		cur.CorrelatedCount++
		copy(cur.RawPayload[:], fmt.Sprintf("systemd[1]: Started session-%d.scope - Session %d of User cl-ment.", 42+step, 42+step))
		d := LocalityDistanceOf(localityCode(&cur), ref)
		t.Logf("pas %d: %+v", step, d)
		if !d.Within(cfg) {
			t.Fatalf("pas %d: dérive progressive rejetée: %+v", step, d)
		}
	}
}

// Une variation isolée de chaque métrique scalaire reste sous le seuil par défaut.
func TestEvaluateLocalityMatch_ScalarVariationsNominal(t *testing.T) {
	cfg := DefaultLocalityThresholds()
	base := localityBase()
	ref := localityCode(&base)
	for _, c := range []struct {
		name   string
		mutate func(*ServerHealthSnapshot)
	}{
		{"score -160", func(s *ServerHealthSnapshot) { s.HealthScore -= 160 }},
		{"entropie +0,5 bit", func(s *ServerHealthSnapshot) { s.EntropyQ8 += 128 }},
		{"heure +30 min", func(s *ServerHealthSnapshot) { s.TimestampSec += 1800 }},
		{"correlated 4->64", func(s *ServerHealthSnapshot) { s.CorrelatedCount = 64 }},
		{"sévérité en baisse", func(s *ServerHealthSnapshot) { s.Severity = 0 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := base
			c.mutate(&m)
			if !EvaluateLocalityMatch(localityCode(&m), ref, cfg) {
				t.Fatalf("variation rejetée: %+v", LocalityDistanceOf(localityCode(&m), ref))
			}
		})
	}
}

// Changement de sous-système ou d'action, aggravation de sévérité, attaque
// complète, entité étrangère ou dérive scalaire massive : tous rejetés.
func TestEvaluateLocalityMatch_Rejections(t *testing.T) {
	cfg := DefaultLocalityThresholds()
	base := localityBase()
	ref := localityCode(&base)
	for _, c := range []struct {
		name   string
		mutate func(*ServerHealthSnapshot)
	}{
		{"sous-système", func(s *ServerHealthSnapshot) { s.Subsystem = OracleSubAuth }},
		{"action", func(s *ServerHealthSnapshot) { s.Action = OracleActProcessSpawn }},
		{"sévérité Low->Medium seule", func(s *ServerHealthSnapshot) { s.Severity = SeverityMedium }},
		{"sévérité Low->High seule", func(s *ServerHealthSnapshot) { s.Severity = SeverityHigh }},
		{"entité étrangère", func(s *ServerHealthSnapshot) { s.EntityID = 6666 }},
		{"score 980->400", func(s *ServerHealthSnapshot) { s.HealthScore = 400 }},
		{"attaque complète", func(s *ServerHealthSnapshot) {
			s.Subsystem, s.Action = OracleSubAuth, OracleActAuthFailure
			s.HealthScore, s.Severity, s.EntityID = 400, SeverityHigh, 6666
			copy(s.RawPayload[:], "sshd[991]: Failed password for invalid user admin from 203.0.113.9 port 4242\x00")
		}},
		{"attaque déguisée, même catégorie", func(s *ServerHealthSnapshot) {
			s.HealthScore, s.Severity = 300, SeverityHigh
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			m := base
			c.mutate(&m)
			d := LocalityDistanceOf(localityCode(&m), ref)
			t.Logf("%+v, total=%d", d, localityDist(VectorizeServerHealthLocality, &base, &m))
			if d.Within(cfg) {
				t.Fatalf("écart accepté comme nominal: %+v", d)
			}
		})
	}
}

// Comparatif : le seuil unique de 45 bits sur la distance totale accepte un
// changement de sous-système et une aggravation de sévérité ; la distance
// partitionnée les refuse, et les deux acceptent une dérive scalaire modérée.
func TestEvaluateLocalityMatch_VersusSingleThreshold(t *testing.T) {
	const single = 45
	cfg := DefaultLocalityThresholds()
	base := localityBase()
	ref := localityCode(&base)

	sub := base
	sub.Subsystem = OracleSubStorage
	sev := base
	sev.Severity = SeverityHigh
	drift := base
	drift.HealthScore -= 160
	drift.TimestampSec += 1800
	copy(drift.RawPayload[:], "systemd[1]: Started session-57.scope - Session 57 of User cl-ment.")

	for _, c := range []struct {
		name    string
		s       *ServerHealthSnapshot
		nominal bool
	}{
		{"changement de sous-système", &sub, false},
		{"sévérité Low->High", &sev, false},
		{"dérive scalaire modérée", &drift, true},
	} {
		code := localityCode(c.s)
		total := HammingDistance512(code, ref)
		t.Logf("%s: total=%d %+v", c.name, total, LocalityDistanceOf(code, ref))
		if total > single {
			t.Fatalf("%s: total %d > %d, le comparatif ne montre plus le défaut du seuil unique", c.name, total, single)
		}
		if got := EvaluateLocalityMatch(code, ref, cfg); got != c.nominal {
			t.Fatalf("%s: nominal=%v, attendu %v", c.name, got, c.nominal)
		}
	}
}

func TestEvaluateLocalityMatch_NilNeverMatches(t *testing.T) {
	base := localityBase()
	c := localityCode(&base)
	if EvaluateLocalityMatch(nil, c, DefaultLocalityThresholds()) || EvaluateLocalityMatch(c, nil, DefaultLocalityThresholds()) {
		t.Fatal("code nil accepté")
	}
}

func TestEvaluateLocalityMatch_ZeroAlloc(t *testing.T) {
	base := localityBase()
	a, b := localityCode(&base), localityCode(&base)
	cfg := DefaultLocalityThresholds()
	if n := testing.AllocsPerRun(100, func() { _ = EvaluateLocalityMatch(a, b, cfg) }); n != 0 {
		t.Fatalf("%v allocations par appel", n)
	}
}

// Deux entités distinctes à charge identique ne sont jamais voisines sous les
// seuils par défaut ; une tolérance d'entité configurée au-delà de 16 bits est
// ramenée à MaxEntityToleranceBits, dont le taux de confusion reste sous 10⁻³.
func TestEvaluateLocalityMatch_ForeignEntityNeverMatches(t *testing.T) {
	const pairs = 200_000
	rng := rand.New(rand.NewPCG(1, 2))
	def := DefaultLocalityThresholds()
	loose := def
	loose.MaxEntity = 24
	a, b := localityBase(), localityBase()
	var ca, cb [8]uint64
	var capped int
	for range pairs {
		a.EntityID, b.EntityID = rng.Uint64(), rng.Uint64()
		if a.EntityID == b.EntityID {
			continue
		}
		VectorizeServerHealthLocality(&a, &ca)
		VectorizeServerHealthLocality(&b, &cb)
		d := LocalityDistanceOf(&ca, &cb)
		if d.Entity == 0 {
			t.Fatalf("entités %d et %d de même code", a.EntityID, b.EntityID)
		}
		if d.Within(def) {
			t.Fatalf("entité étrangère acceptée par défaut: %+v", d)
		}
		if d.Within(loose) {
			capped++
		}
		if d.Entity > MaxEntityToleranceBits && d.Within(loose) {
			t.Fatalf("tolérance d'entité non plafonnée: %+v", d)
		}
	}
	t.Logf("tolérance 24 plafonnée à %d bits: %d confusions sur %d", MaxEntityToleranceBits, capped, pairs)
	if capped*1000 > pairs {
		t.Fatalf("taux de confusion %d/%d > 10⁻³", capped, pairs)
	}
}

// Seule, l'heure admet 12 pas de 22,5 min (4 h 30, 24 bits) et refuse le treizième.
func TestEvaluateLocalityMatch_TimeAloneBudget(t *testing.T) {
	cfg := DefaultLocalityThresholds()
	const step = 86400 / localitySlotsPerDay
	base := localityBase()
	base.TimestampSec = base.TimestampSec / 86400 * 86400
	ref := localityCode(&base)
	for _, c := range []struct {
		slots   uint64
		nominal bool
	}{{12, true}, {13, false}} {
		m := base
		m.TimestampSec += c.slots * step
		d := LocalityDistanceOf(localityCode(&m), ref)
		if d.Scalar != int(2*c.slots) || d.Within(cfg) != c.nominal {
			t.Fatalf("%d pas: %+v, nominal attendu %v", c.slots, d, c.nominal)
		}
	}
}
