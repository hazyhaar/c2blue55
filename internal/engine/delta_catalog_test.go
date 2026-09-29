package engine

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"
)

const deltaMachine = 0xCAFE12345678DEAD

// deltaTs est le mardi 29 septembre 2026, 14:00:00 UTC.
var deltaTs = uint64(time.Date(2026, 9, 29, 14, 0, 0, 0, time.UTC).Unix())

func deltaSnap(sev uint16) ServerHealthSnapshot {
	s := localityBase()
	s.TimestampSec = deltaTs
	s.Severity = sev
	return s
}

// deltaRule rend une règle valide qui dispense le voisinage de s : catégorie,
// sévérité et corrélation, score et entité masqués, rayon 6.
func deltaRule(id uint32, s *ServerHealthSnapshot) DeltaRule {
	r := DeltaRule{
		Pattern:        *localityCode(s),
		NotBeforeSec:   deltaTs - 3600,
		NotAfterSec:    deltaTs + 3600,
		RuleID:         id,
		MaxRadius:      6,
		ScaleMask:      DeltaScale4h | DeltaScale24h,
		DaysOfWeekMask: DeltaAllDays,
		TimeSlotMin:    0,
		TimeSlotMax:    DeltaSlotsPerDay - 1,
	}
	for _, w := range []int{0, 1, 2, 3, 6} {
		r.Mask[w] = ^uint64(0)
	}
	copy(r.Label[:], "apt-upgrade-maintenance")
	return r
}

func deltaSave(t *testing.T, rules ...DeltaRule) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := SaveDeltaCatalog(&buf, deltaMachine, rules); err != nil {
		t.Fatalf("SaveDeltaCatalog: %v", err)
	}
	return buf.Bytes()
}

func deltaLoad(t *testing.T, data []byte) *DeltaCatalog {
	t.Helper()
	c, err := LoadDeltaCatalog(bytes.NewReader(data), deltaMachine)
	if err != nil {
		t.Fatalf("LoadDeltaCatalog: %v", err)
	}
	return c
}

// deltaRaw scelle des règles sans les valider, comme le ferait un outil tiers,
// pour éprouver les gardes du chargement indépendamment de SaveDeltaCatalog.
func deltaRaw(machine uint64, rules ...DeltaRule) []byte {
	hdr := DeltaHeader{Magic: DeltaMagic, Version: DeltaVersion, Dimension: DeltaDim, RuleCount: uint32(len(rules)), MachineID: machine}
	hdr.Seal = ComputeDeltaSeal(&hdr, rules)
	var out bytes.Buffer
	var hb [DeltaHeaderSize]byte
	EncodeDeltaHeader(&hb, &hdr)
	out.Write(hb[:])
	var rb [DeltaRuleSize]byte
	for i := range rules {
		EncodeDeltaRule(&rb, &rules[i])
		out.Write(rb[:])
	}
	return out.Bytes()
}

func TestDeltaCatalog_Sizes(t *testing.T) {
	if unsafe.Sizeof(DeltaHeader{}) != 64 || unsafe.Sizeof(DeltaRule{}) != 192 {
		t.Fatalf("tailles: en-tete %d, regle %d", unsafe.Sizeof(DeltaHeader{}), unsafe.Sizeof(DeltaRule{}))
	}
	s := deltaSnap(SeverityLow)
	data := deltaSave(t, deltaRule(1, &s), deltaRule(2, &s))
	if len(data) != DeltaHeaderSize+2*DeltaRuleSize {
		t.Fatalf("taille du fichier: %d", len(data))
	}
	if !bytes.Equal(data[:8], []byte("C2DELTA1")) {
		t.Fatalf("magie: %q", data[:8])
	}
}

func TestDeltaCatalog_RoundTrip(t *testing.T) {
	s := deltaSnap(SeverityMedium)
	want := []DeltaRule{deltaRule(7, &s), deltaRule(9, &s)}
	want[1].DaysOfWeekMask = 0x41
	want[1].TimeSlotMin, want[1].TimeSlotMax = 3, 40
	want[1].Reserved = [5]byte{1, 2, 3, 4, 5}
	c := deltaLoad(t, deltaSave(t, want...))
	if c.Len() != 2 {
		t.Fatalf("Len = %d", c.Len())
	}
	for i := range want {
		if c.rules[i] != want[i] {
			t.Fatalf("regle %d alteree:\n got %+v\nwant %+v", i, c.rules[i], want[i])
		}
	}
}

// Chaque octet du fichier est couvert : une altération donne ErrDeltaSeal ou
// une erreur de structure, jamais un chargement réussi.
func TestDeltaCatalog_SealCoversEveryByte(t *testing.T) {
	s := deltaSnap(SeverityLow)
	data := deltaSave(t, deltaRule(1, &s))
	for i := range data {
		if i >= 24 && i < 56 {
			continue // le sceau lui-même
		}
		bad := bytes.Clone(data)
		bad[i] ^= 0x01
		if _, err := LoadDeltaCatalog(bytes.NewReader(bad), deltaMachine); err == nil {
			t.Fatalf("octet %d altere accepte", i)
		}
	}
	bad := bytes.Clone(data)
	bad[30] ^= 0xFF
	if _, err := LoadDeltaCatalog(bytes.NewReader(bad), deltaMachine); !errors.Is(err, ErrDeltaSeal) {
		t.Fatalf("sceau altere: %v", err)
	}
	bad = bytes.Clone(data)
	bad[DeltaHeaderSize+100] ^= 0x10
	if _, err := LoadDeltaCatalog(bytes.NewReader(bad), deltaMachine); !errors.Is(err, ErrDeltaSeal) {
		t.Fatalf("regle alteree: %v", err)
	}
}

func TestDeltaCatalog_StructuralErrors(t *testing.T) {
	s := deltaSnap(SeverityLow)
	good := deltaSave(t, deltaRule(1, &s))
	mut := func(f func(b []byte)) []byte { b := bytes.Clone(good); f(b); return b }
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"vide", nil, ErrDeltaCorrupt},
		{"en-tete tronque", good[:40], ErrDeltaCorrupt},
		{"regle tronquee", good[:DeltaHeaderSize+100], ErrDeltaCorrupt},
		{"magie", mut(func(b []byte) { b[0] = 'X' }), ErrDeltaMagic},
		{"version", mut(func(b []byte) { b[8] = 2 }), ErrDeltaVersion},
		{"dimension", mut(func(b []byte) { b[11] = 0 }), ErrDeltaDim},
		{"trop de regles", mut(func(b []byte) { b[12], b[13], b[14] = 0x01, 0x00, 0x01 }), ErrDeltaTooLarge},
	}
	for _, tc := range cases {
		if _, err := LoadDeltaCatalog(bytes.NewReader(tc.data), deltaMachine); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, attendu %v", tc.name, err, tc.want)
		}
	}
	if _, err := LoadDeltaCatalog(bytes.NewReader(good), deltaMachine+1); !errors.Is(err, ErrDeltaMachine) {
		t.Fatalf("autre machine: %v", err)
	}
}

// Un en-tête annonçant beaucoup de règles sur un corps vide n'engage pas de mémoire.
func TestDeltaCatalog_TruncatedDoesNotPreallocate(t *testing.T) {
	hdr := DeltaHeader{Magic: DeltaMagic, Version: DeltaVersion, Dimension: DeltaDim, RuleCount: DeltaMaxRuleCount, MachineID: deltaMachine}
	var hb [DeltaHeaderSize]byte
	EncodeDeltaHeader(&hb, &hdr)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := LoadDeltaCatalog(bytes.NewReader(hb[:]), deltaMachine)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrDeltaCorrupt) {
		t.Fatalf("attendu ErrDeltaCorrupt: %v", err)
	}
	// Tampon de lecture (64 Kio) et préallocation bornée (256 règles, 48 Kio),
	// contre 12 Mio si le compte annoncé décidait de la capacité.
	if got := after.TotalAlloc - before.TotalAlloc; got > 256<<10 {
		t.Fatalf("%d octets alloues pour un corps vide", got)
	}
}

// Les gardes s'appliquent à l'écriture comme au chargement d'un fichier scellé
// par un tiers qui ne les a pas vérifiées.
func TestDeltaCatalog_Guards(t *testing.T) {
	low := deltaSnap(SeverityLow)
	high := deltaSnap(SeverityHigh)
	cases := []struct {
		name string
		edit func(r *DeltaRule)
		want error
	}{
		{"NotAfterSec nul", func(r *DeltaRule) { r.NotAfterSec = 0 }, ErrDeltaEternal},
		{"fenetre vide", func(r *DeltaRule) { r.NotAfterSec = r.NotBeforeSec }, ErrDeltaEternal},
		{"fenetre inversee", func(r *DeltaRule) { r.NotAfterSec = r.NotBeforeSec - 1 }, ErrDeltaEternal},
		{"eternelle depuis zero", func(r *DeltaRule) { r.NotBeforeSec, r.NotAfterSec = 0, 0 }, ErrDeltaEternal},
		{"RuleID nul", func(r *DeltaRule) { r.RuleID = 0 }, ErrDeltaRule},
		{"libelle vide", func(r *DeltaRule) { r.Label = [32]byte{} }, ErrDeltaRule},
		{"echelle vide", func(r *DeltaRule) { r.ScaleMask = 0 }, ErrDeltaRule},
		{"echelle au-dela de 365j", func(r *DeltaRule) { r.ScaleMask = 1 << 7 }, ErrDeltaRule},
		{"echelle connue plus bit inconnu", func(r *DeltaRule) { r.ScaleMask = DeltaScale24h | 1<<15 }, ErrDeltaRule},
		{"aucun jour", func(r *DeltaRule) { r.DaysOfWeekMask = 0 }, ErrDeltaRule},
		{"jour 7", func(r *DeltaRule) { r.DaysOfWeekMask = 0x80 }, ErrDeltaRule},
		{"creneaux inverses", func(r *DeltaRule) { r.TimeSlotMin, r.TimeSlotMax = 10, 9 }, ErrDeltaRule},
		{"creneau 64", func(r *DeltaRule) { r.TimeSlotMax = 64 }, ErrDeltaRule},
		{"masque vide", func(r *DeltaRule) { r.Mask = [8]uint64{}; r.MaxRadius = 0 }, ErrDeltaRule},
		{"rayon couvrant le masque", func(r *DeltaRule) { r.Mask = [8]uint64{2: localitySeverityMask}; r.MaxRadius = 32 }, ErrDeltaRule},
		{"severite partiellement masquee", func(r *DeltaRule) { r.Mask[2] = 0xFFFFFFFF00FFFFFF }, ErrDeltaSeverity},
		{"severite non masquee", func(r *DeltaRule) { r.Mask[2] = 0 }, ErrDeltaSeverity},
		{"severite hors thermometre", func(r *DeltaRule) { r.Pattern[2] = r.Pattern[2]&^localitySeverityMask | thermo64(20) }, ErrDeltaSeverity},
		{"severite trouee", func(r *DeltaRule) { r.Pattern[2] = r.Pattern[2]&^localitySeverityMask | 0xFF00 }, ErrDeltaSeverity},
		{"Low rayon 8", func(r *DeltaRule) { r.MaxRadius = 8 }, ErrDeltaSeverity},
	}
	for _, tc := range cases {
		r := deltaRule(1, &low)
		tc.edit(&r)
		if err := SaveDeltaCatalog(&bytes.Buffer{}, deltaMachine, []DeltaRule{r}); !errors.Is(err, tc.want) {
			t.Errorf("%s, ecriture: %v, attendu %v", tc.name, err, tc.want)
		}
		if _, err := LoadDeltaCatalog(bytes.NewReader(deltaRaw(deltaMachine, r)), deltaMachine); !errors.Is(err, tc.want) {
			t.Errorf("%s, chargement: %v, attendu %v", tc.name, err, tc.want)
		}
	}

	// Une seule règle invalide fait refuser le catalogue entier.
	bad := deltaRule(2, &low)
	bad.NotAfterSec = 0
	if _, err := LoadDeltaCatalog(bytes.NewReader(deltaRaw(deltaMachine, deltaRule(1, &low), bad)), deltaMachine); !errors.Is(err, ErrDeltaEternal) {
		t.Fatalf("catalogue mixte: %v", err)
	}
	if err := SaveDeltaCatalog(&bytes.Buffer{}, deltaMachine, []DeltaRule{deltaRule(3, &low), deltaRule(3, &low)}); !errors.Is(err, ErrDeltaRule) {
		t.Fatalf("RuleID en double: %v", err)
	}

	// Finding F_DS_01 : une règle qui vise High ne dépasse pas 7 bits, sans
	// quoi elle absorberait l'aggravation vers Critical ; une règle qui vise
	// Critical est plafonnée à DeltaCriticalMaxRadius.
	rh := deltaRule(4, &high)
	rh.MaxRadius = 7
	if err := ValidateDeltaRule(&rh); err != nil {
		t.Fatalf("regle High rayon 7 refusee: %v", err)
	}
	rh.MaxRadius = 8
	if err := ValidateDeltaRule(&rh); !errors.Is(err, ErrDeltaSeverity) {
		t.Fatalf("regle High rayon 8 admise: %v", err)
	}
	crit := deltaSnap(SeverityCritical)
	rc := deltaRule(5, &crit)
	rc.MaxRadius = DeltaCriticalMaxRadius
	if err := ValidateDeltaRule(&rc); err != nil {
		t.Fatalf("regle Critical rayon %d refusee: %v", DeltaCriticalMaxRadius, err)
	}
	for _, radius := range []uint16{DeltaCriticalMaxRadius + 1, 64, 300} {
		rc.MaxRadius = radius
		if err := ValidateDeltaRule(&rc); !errors.Is(err, ErrDeltaSeverity) {
			t.Fatalf("regle Critical rayon %d admise: %v", radius, err)
		}
		if _, err := LoadDeltaCatalog(bytes.NewReader(deltaRaw(deltaMachine, rc)), deltaMachine); !errors.Is(err, ErrDeltaSeverity) {
			t.Fatalf("regle Critical rayon %d chargee: %v", radius, err)
		}
	}
}

// Finding F_DS_01, garde de chargement : pour toute sévérité inférieure à
// Critical et tout rayon admis, l'état identique au motif mais d'un niveau plus
// grave n'est jamais dispensé.
func TestDeltaCatalog_NoRuleAbsorbsOneLevel(t *testing.T) {
	for _, target := range []uint16{0, SeverityLow, SeverityMedium, SeverityHigh} {
		s := deltaSnap(target)
		for radius := uint16(0); radius < 8; radius++ {
			r := deltaRule(1, &s)
			r.MaxRadius = radius
			c := deltaLoad(t, deltaSave(t, r))
			for obs := target + 1; obs <= SeverityCritical; obs++ {
				o := s
				o.Severity = obs
				if ok, id := c.EvaluateDelta(localityCode(&o), deltaTs, DeltaScale4h); ok {
					t.Fatalf("severite %d rayon %d: %d dispense par la regle %d", target, radius, obs, id)
				}
			}
		}
	}
}

// Finding F_DS_01, garde d'évaluation : une règle admise par erreur (catalogue
// construit sans ValidateDeltaRule) ne dispense pas davantage un état plus grave
// que son motif, même si la distance tient dans son rayon.
func TestDeltaCatalog_RuntimeSeverityGuard(t *testing.T) {
	high := deltaSnap(SeverityHigh)
	r := deltaRule(77, &high)
	r.MaxRadius = 64
	c := &DeltaCatalog{machineID: deltaMachine, rules: []DeltaRule{r}}
	if ok, id := c.EvaluateDelta(localityCode(&high), deltaTs, DeltaScale4h); !ok || id != 77 {
		t.Fatalf("motif High non dispense: %v %d", ok, id)
	}
	crit := high
	crit.Severity = SeverityCritical
	if ok, id := c.EvaluateDelta(localityCode(&crit), deltaTs, DeltaScale4h); ok {
		t.Fatalf("Critical dispense par la regle High %d", id)
	}
	// Une sévérité moindre reste dispensable dans le rayon.
	med := high
	med.Severity = SeverityMedium
	if ok, _ := c.EvaluateDelta(localityCode(&med), deltaTs, DeltaScale4h); !ok {
		t.Fatal("Medium refuse par la regle High de rayon 64")
	}

	// Un champ de sévérité observé troué est jugé au niveau de son bit le plus
	// haut : un bit isolé au rang 25 (niveau Critical) n'est pas dispensé par
	// une règle Low, alors qu'il n'est qu'à 1 bit du motif.
	low := deltaSnap(SeverityLow)
	lc := deltaLoad(t, deltaSave(t, deltaRule(3, &low)))
	forged := *localityCode(&low)
	forged[2] |= 1 << 25
	if ok, id := lc.EvaluateDelta(&forged, deltaTs, DeltaScale4h); ok {
		t.Fatalf("severite forgee dispensee par la regle %d", id)
	}
}

// Finding F_DS_10 : les sept échelles se désignent chacune, une règle ne
// s'applique qu'aux siennes, et une échelle inconnue ne dispense rien.
func TestDeltaCatalog_Scales(t *testing.T) {
	all := []uint16{DeltaScale4h, DeltaScale12h, DeltaScale24h, DeltaScale7d, DeltaScale30d, DeltaScale120d, DeltaScale365d}
	if len(all) != DeltaScaleCount {
		t.Fatalf("%d echelles, DeltaScaleCount = %d", len(all), DeltaScaleCount)
	}
	var union uint16
	for i, sc := range all {
		if sc != 1<<i || union&sc != 0 {
			t.Fatalf("echelle %d = 0x%04x", i, sc)
		}
		union |= sc
	}
	if union != DeltaScaleAll {
		t.Fatalf("union 0x%04x, DeltaScaleAll 0x%04x", union, DeltaScaleAll)
	}
	s := deltaSnap(SeverityLow)
	for i, sc := range all {
		r := deltaRule(uint32(i+1), &s)
		r.ScaleMask = sc
		c := deltaLoad(t, deltaSave(t, r))
		for _, q := range all {
			if ok, _ := c.EvaluateDelta(localityCode(&s), deltaTs, q); ok != (q == sc) {
				t.Fatalf("regle 0x%04x, echelle 0x%04x: %v", sc, q, ok)
			}
		}
	}
	r := deltaRule(9, &s)
	r.ScaleMask = DeltaScaleAll
	c := deltaLoad(t, deltaSave(t, r))
	if ok, _ := c.EvaluateDelta(localityCode(&s), deltaTs, 1<<7); ok {
		t.Fatal("echelle inconnue dispensee")
	}
}

// EvaluateStateWithDelta : nominal sans consulter le catalogue, dispensé par une
// règle, anomalie sans règle, et aucune dispense sans catalogue.
func TestEvaluateStateWithDelta(t *testing.T) {
	cfg := DefaultLocalityThresholds()
	ref := deltaSnap(SeverityLow)
	o := NewServerBaselineOracle(deltaMachine, 0)
	o.IngestDailyEntries([]OracleVectorEntry{{Bitcode: *localityCode(&ref), Subsystem: ref.Subsystem, HealthScore: ref.HealthScore, Severity: ref.Severity}})

	// Un score effondré de 980 à 500 : 30 bits de dérive scalaire, au-delà des 24 admis.
	drift := ref
	drift.HealthScore = 500
	r := deltaRule(21, &drift)
	c := deltaLoad(t, deltaSave(t, r))

	if v := EvaluateStateWithDelta(o, c, localityCode(&ref), deltaTs, DeltaScale4h, cfg); !v.Nominal || v.Dispensed || v.RuleID != 0 || v.Anomaly() {
		t.Fatalf("etat de reference: %+v", v)
	}
	if v := EvaluateStateWithDelta(o, c, localityCode(&drift), deltaTs, DeltaScale4h, cfg); v.Nominal || !v.Dispensed || v.RuleID != 21 || v.Anomaly() {
		t.Fatalf("derive dispensee: %+v", v)
	}
	if v := EvaluateStateWithDelta(o, c, localityCode(&drift), deltaTs, DeltaScale12h, cfg); v.Nominal || v.Dispensed || !v.Anomaly() {
		t.Fatalf("derive hors echelle de la regle: %+v", v)
	}
	if v := EvaluateStateWithDelta(o, nil, localityCode(&drift), deltaTs, DeltaScale4h, cfg); !v.Anomaly() || v.Distance.Scalar == 0 {
		t.Fatalf("derive sans catalogue: %+v", v)
	}
	if v := EvaluateStateWithDelta(nil, c, localityCode(&drift), deltaTs, DeltaScale4h, cfg); !v.Dispensed || v.Distance != localityDistanceNone {
		t.Fatalf("sans oracle: %+v", v)
	}
	if v := EvaluateStateWithDelta(o, c, nil, deltaTs, DeltaScale4h, cfg); !v.Anomaly() {
		t.Fatalf("observation nil: %+v", v)
	}
	// La dérive aggravée en High n'est dispensée ni par la baseline ni par la règle Low.
	worse := drift
	worse.Severity = SeverityHigh
	if v := EvaluateStateWithDelta(o, c, localityCode(&worse), deltaTs, DeltaScale4h, cfg); !v.Anomaly() {
		t.Fatalf("aggravation blanchie: %+v", v)
	}
	code := localityCode(&drift)
	if n := testing.AllocsPerRun(1000, func() { EvaluateStateWithDelta(o, c, code, deltaTs, DeltaScale4h, cfg) }); n != 0 {
		t.Fatalf("EvaluateStateWithDelta: %v allocations", n)
	}
}

// Finding F8 : pour toute règle admise qui vise Low ou Medium, un état observé
// identique au motif sauf pour sa sévérité portée à High ou Critical n'est
// jamais dispensé.
func TestDeltaCatalog_SeverityCannotReachHigh(t *testing.T) {
	for _, target := range []uint16{0, SeverityLow, SeverityMedium} {
		for radius := uint16(0); radius < 8; radius++ {
			s := deltaSnap(target)
			r := deltaRule(1, &s)
			r.MaxRadius = radius
			c := deltaLoad(t, deltaSave(t, r))
			if ok, _ := c.EvaluateDelta(localityCode(&s), deltaTs, DeltaScale4h); !ok {
				t.Fatalf("severite %d rayon %d: le motif lui-meme n'est pas dispense", target, radius)
			}
			for _, obs := range []uint16{SeverityHigh, SeverityCritical} {
				o := s
				o.Severity = obs
				if ok, id := c.EvaluateDelta(localityCode(&o), deltaTs, DeltaScale4h); ok {
					t.Fatalf("severite %d rayon %d: %d dispense par la regle %d", target, radius, obs, id)
				}
			}
		}
		s := deltaSnap(target)
		r := deltaRule(1, &s)
		r.MaxRadius = 8
		if err := ValidateDeltaRule(&r); !errors.Is(err, ErrDeltaSeverity) {
			t.Fatalf("severite %d rayon 8 admis: %v", target, err)
		}
	}
}

func TestDeltaCatalog_EvaluateRadiusBoundary(t *testing.T) {
	s := deltaSnap(SeverityLow)
	r := deltaRule(42, &s)
	c := deltaLoad(t, deltaSave(t, r))
	obs := *localityCode(&s)
	// Six bits masqués retournés sur le mot 3 (score) : exactement le rayon.
	obs[3] ^= 0x3F
	if ok, id := c.EvaluateDelta(&obs, deltaTs, DeltaScale24h); !ok || id != 42 {
		t.Fatalf("distance = rayon refusee: %v %d", ok, id)
	}
	obs[3] ^= 0x40
	if ok, _ := c.EvaluateDelta(&obs, deltaTs, DeltaScale24h); ok {
		t.Fatal("distance = rayon+1 acceptee")
	}
	// Les bits hors masque (mots 4, 5 et 7) ne comptent pas.
	obs = *localityCode(&s)
	obs[4], obs[5], obs[7] = ^obs[4], ^obs[5], ^obs[7]
	if ok, _ := c.EvaluateDelta(&obs, deltaTs, DeltaScale24h); !ok {
		t.Fatal("bits hors masque comptes")
	}
	// Une autre catégorie ou une autre entité est refusée.
	o := s
	o.Subsystem = OracleSubAuth
	if ok, _ := c.EvaluateDelta(localityCode(&o), deltaTs, DeltaScale24h); ok {
		t.Fatal("autre sous-systeme dispense")
	}
	o = s
	o.EntityID++
	if ok, _ := c.EvaluateDelta(localityCode(&o), deltaTs, DeltaScale24h); ok {
		t.Fatal("autre entite dispensee")
	}
}

func TestDeltaCatalog_EvaluateCalendar(t *testing.T) {
	s := deltaSnap(SeverityLow)
	code := localityCode(&s)
	wd := time.Unix(int64(deltaTs), 0).UTC().Weekday()
	if wd != time.Tuesday {
		t.Fatalf("jour de reference: %v", wd)
	}
	slot := uint8(deltaTs % 86400 * DeltaSlotsPerDay / 86400) // 14h00 -> 37

	base := deltaRule(5, &s)
	cases := []struct {
		name  string
		edit  func(r *DeltaRule)
		ts    uint64
		scale uint16
		want  bool
	}{
		{"nominal", func(*DeltaRule) {}, deltaTs, DeltaScale4h, true},
		{"borne NotBefore incluse", func(r *DeltaRule) { r.NotBeforeSec = deltaTs }, deltaTs, DeltaScale4h, true},
		{"borne NotAfter incluse", func(r *DeltaRule) { r.NotAfterSec = deltaTs }, deltaTs, DeltaScale4h, true},
		{"avant NotBefore", func(r *DeltaRule) { r.NotBeforeSec = deltaTs + 1 }, deltaTs, DeltaScale4h, false},
		{"apres NotAfter", func(r *DeltaRule) { r.NotAfterSec = deltaTs - 1 }, deltaTs, DeltaScale4h, false},
		{"mardi seul", func(r *DeltaRule) { r.DaysOfWeekMask = 1 << time.Tuesday }, deltaTs, DeltaScale4h, true},
		{"tous sauf mardi", func(r *DeltaRule) { r.DaysOfWeekMask = DeltaAllDays &^ (1 << time.Tuesday) }, deltaTs, DeltaScale4h, false},
		{"creneau exact", func(r *DeltaRule) { r.TimeSlotMin, r.TimeSlotMax = slot, slot }, deltaTs, DeltaScale4h, true},
		{"creneau suivant", func(r *DeltaRule) { r.TimeSlotMin, r.TimeSlotMax = slot+1, 63 }, deltaTs, DeltaScale4h, false},
		{"creneau precedent", func(r *DeltaRule) { r.TimeSlotMin, r.TimeSlotMax = 0, slot-1 }, deltaTs, DeltaScale4h, false},
		{"echelle 12h absente", func(*DeltaRule) {}, deltaTs, DeltaScale12h, false},
		{"echelle nulle", func(*DeltaRule) {}, deltaTs, 0, false},
	}
	for _, tc := range cases {
		r := base
		tc.edit(&r)
		c := deltaLoad(t, deltaSave(t, r))
		if ok, _ := c.EvaluateDelta(code, tc.ts, tc.scale); ok != tc.want {
			t.Errorf("%s: %v, attendu %v", tc.name, ok, tc.want)
		}
	}

	// Jour de la semaine sur sept jours consécutifs, contre time.Weekday.
	for d := range uint64(7) {
		ts := deltaTs + d*86400
		r := base
		r.NotAfterSec = ts + 1
		r.DaysOfWeekMask = 1 << time.Unix(int64(ts), 0).UTC().Weekday()
		c := deltaLoad(t, deltaSave(t, r))
		if ok, _ := c.EvaluateDelta(code, ts, DeltaScale4h); !ok {
			t.Fatalf("jour %d non reconnu", d)
		}
	}
}

// La première règle applicable dans l'ordre du catalogue l'emporte.
func TestDeltaCatalog_FirstMatchWins(t *testing.T) {
	s := deltaSnap(SeverityLow)
	expired := deltaRule(10, &s)
	expired.NotAfterSec = deltaTs - 1
	c := deltaLoad(t, deltaSave(t, expired, deltaRule(11, &s), deltaRule(12, &s)))
	if ok, id := c.EvaluateDelta(localityCode(&s), deltaTs, DeltaScale4h); !ok || id != 11 {
		t.Fatalf("regle retenue: %v %d, attendu 11", ok, id)
	}
	var nilCat *DeltaCatalog
	if ok, _ := nilCat.EvaluateDelta(localityCode(&s), deltaTs, DeltaScale4h); ok {
		t.Fatal("catalogue nil dispense")
	}
	if ok, _ := c.EvaluateDelta(nil, deltaTs, DeltaScale4h); ok {
		t.Fatal("observation nil dispensee")
	}
}

func TestDeltaCatalog_EvaluateZeroAlloc(t *testing.T) {
	s := deltaSnap(SeverityLow)
	rules := make([]DeltaRule, 64)
	for i := range rules {
		o := s
		o.EntityID = uint64(i + 1)
		rules[i] = deltaRule(uint32(i+1), &o)
	}
	c := deltaLoad(t, deltaSave(t, rules...))
	code := localityCode(&s)
	if n := testing.AllocsPerRun(1000, func() { c.EvaluateDelta(code, deltaTs, DeltaScale4h) }); n != 0 {
		t.Fatalf("EvaluateDelta: %v allocations", n)
	}
}

// Le catalogue immuable se lit concurremment ; -race vérifie l'absence de course.
func TestDeltaCatalog_ConcurrentEvaluate(t *testing.T) {
	s := deltaSnap(SeverityLow)
	c := deltaLoad(t, deltaSave(t, deltaRule(1, &s)))
	code := localityCode(&s)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				if ok, _ := c.EvaluateDelta(code, deltaTs, DeltaScale4h); !ok {
					t.Error("dispense perdue")
					return
				}
			}
		})
	}
	wg.Wait()
}

func BenchmarkEvaluateDelta(b *testing.B) {
	s := deltaSnap(SeverityLow)
	rules := make([]DeltaRule, 256)
	for i := range rules {
		o := s
		o.EntityID = uint64(i + 1000)
		rules[i] = deltaRule(uint32(i+1), &o)
	}
	var buf bytes.Buffer
	if err := SaveDeltaCatalog(&buf, deltaMachine, rules); err != nil {
		b.Fatal(err)
	}
	c, err := LoadDeltaCatalog(&buf, deltaMachine)
	if err != nil {
		b.Fatal(err)
	}
	code := localityCode(&s)
	b.ReportAllocs()
	for b.Loop() {
		c.EvaluateDelta(code, deltaTs, DeltaScale4h)
	}
}

// Finding N4 : EvaluateDelta n'accepte qu'une échelle à un seul bit. Une
// échelle composée dispensait avant le correctif dès qu'un de ses bits
// croisait ceux de la règle.
func TestDeltaCatalog_ComposedScaleRefused(t *testing.T) {
	s := deltaSnap(SeverityLow)
	c := deltaLoad(t, deltaSave(t, deltaRule(1, &s))) // règle 4 h | 24 h
	obs := localityCode(&s)
	if ok, id := c.EvaluateDelta(obs, deltaTs, DeltaScale4h); !ok || id != 1 {
		t.Fatalf("echelle simple couverte: %v %d", ok, id)
	}
	for _, sc := range []uint16{0, DeltaScale4h | DeltaScale12h, DeltaScale4h | DeltaScale24h, DeltaScaleAll, 1<<7 | DeltaScale4h} {
		if ok, _ := c.EvaluateDelta(obs, deltaTs, sc); ok {
			t.Fatalf("echelle composee 0x%04x dispensee", sc)
		}
	}
}

var deltaKey = []byte("cle-secrete-hote-c2blue55-phase5")

// deltaSealOracle recalcule le HMAC-SHA256 d'un fichier .c2delta sur ses octets
// bruts, sceau remis à zéro, sans passer par l'encodeur du paquet.
func deltaSealOracle(file, key []byte) []byte {
	raw := bytes.Clone(file)
	clear(raw[24:56])
	m := hmac.New(sha256.New, key)
	m.Write(raw)
	return m.Sum(nil)
}

// Finding F_DS_02 : le sceau HMAC couvre les mêmes octets que le SHA-256, un
// catalogue ne se charge que sous sa clé, et une clé vide garde le SHA-256.
func TestDeltaCatalog_HMAC(t *testing.T) {
	s := deltaSnap(SeverityLow)
	rules := []DeltaRule{deltaRule(1, &s), deltaRule(2, &s)}
	var keyed bytes.Buffer
	if err := SaveDeltaCatalogHMAC(&keyed, deltaMachine, rules, deltaKey); err != nil {
		t.Fatal(err)
	}
	file := keyed.Bytes()
	if !bytes.Equal(file[24:56], deltaSealOracle(file, deltaKey)) {
		t.Fatal("sceau HMAC different de l'oracle crypto/hmac")
	}
	var hdr DeltaHeader
	DecodeDeltaHeader((*[DeltaHeaderSize]byte)(file[:DeltaHeaderSize]), &hdr)
	if ComputeDeltaSealHMAC(&hdr, rules, deltaKey) != hdr.Seal {
		t.Fatal("ComputeDeltaSealHMAC ne rend pas le sceau ecrit")
	}
	if ComputeDeltaSealHMAC(&hdr, rules, nil) != ComputeDeltaSeal(&hdr, rules) {
		t.Fatal("cle vide differente du SHA-256")
	}
	if ComputeDeltaSealHMAC(&hdr, rules, deltaKey) == ComputeDeltaSeal(&hdr, rules) {
		t.Fatal("sceau HMAC egal au SHA-256")
	}
	c, err := LoadDeltaCatalogHMAC(bytes.NewReader(file), deltaMachine, deltaKey)
	if err != nil || c.Len() != 2 {
		t.Fatalf("chargement sous la cle: %v", err)
	}
	other := bytes.Repeat([]byte{'x'}, SealKeyMinLen)
	for name, key := range map[string][]byte{"sans cle": nil, "autre cle": other} {
		if _, err := LoadDeltaCatalogHMAC(bytes.NewReader(file), deltaMachine, key); !errors.Is(err, ErrDeltaSeal) {
			t.Fatalf("%s: %v, attendu ErrDeltaSeal", name, err)
		}
	}
	// Un attaquant local sans la clé élargit une règle et rescelle en SHA-256.
	forged := rules[0]
	forged.NotAfterSec += 30 * 86400
	if _, err := LoadDeltaCatalogHMAC(bytes.NewReader(deltaRaw(deltaMachine, forged, rules[1])), deltaMachine, deltaKey); !errors.Is(err, ErrDeltaSeal) {
		t.Fatalf("catalogue forge accepte sous cle: %v", err)
	}
	// Une clé vide reste compatible avec les catalogues SHA-256 existants.
	if _, err := LoadDeltaCatalogHMAC(bytes.NewReader(deltaSave(t, rules...)), deltaMachine, nil); err != nil {
		t.Fatalf("compatibilite SHA-256: %v", err)
	}
	short := []byte("court")
	if err := SaveDeltaCatalogHMAC(io.Discard, deltaMachine, rules, short); !errors.Is(err, ErrSealKey) {
		t.Fatalf("cle courte a l'ecriture: %v", err)
	}
	if _, err := LoadDeltaCatalogHMAC(bytes.NewReader(file), deltaMachine, short); !errors.Is(err, ErrSealKey) {
		t.Fatalf("cle courte au chargement: %v", err)
	}
}

// DeltaPatternFromSnapshot masque exactement les mots demandés, et toujours la sévérité.
func TestDeltaPatternFromSnapshot(t *testing.T) {
	s := deltaSnap(SeverityMedium)
	p, m := DeltaPatternFromSnapshot(&s, 0)
	if p != *localityCode(&s) || m != [8]uint64{2: localitySeverityMask} {
		t.Fatalf("sans champ: masque %x", m)
	}
	_, m = DeltaPatternFromSnapshot(&s, DeltaMatchAll)
	for w := range 8 {
		if m[w] != ^uint64(0) {
			t.Fatalf("tous champs: mot %d = %x", w, m[w])
		}
	}
	_, m = DeltaPatternFromSnapshot(&s, DeltaMatchAction|DeltaMatchEntity)
	if m != [8]uint64{1: ^uint64(0), 2: localitySeverityMask, 6: ^uint64(0)} {
		t.Fatalf("action et entite: %x", m)
	}
	r := deltaRule(1, &s)
	r.Pattern, r.Mask = DeltaPatternFromSnapshot(&s, DeltaMatchSubsystem|DeltaMatchScore)
	if err := ValidateDeltaRule(&r); err != nil {
		t.Fatalf("regle issue du motif: %v", err)
	}
}
