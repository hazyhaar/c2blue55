package engine

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"
	"unsafe"
)

const pyrMachine = deltaMachine

// pyrDay est le jour calendaire de deltaTs (mardi 29 septembre 2026).
var pyrDay = uint32(deltaTs / 86400)

var pyrScales = [DeltaScaleCount]uint16{DeltaScale4h, DeltaScale12h, DeltaScale24h, DeltaScale7d, DeltaScale30d, DeltaScale120d, DeltaScale365d}

// pyrEntry rend l'entrée de tranche d'un instantané.
func pyrEntry(s *ServerHealthSnapshot) OracleVectorEntry {
	return OracleVectorEntry{
		Bitcode:     *localityCode(s),
		RelativeSec: uint32(s.TimestampSec % 86400),
		Subsystem:   s.Subsystem,
		HealthScore: s.HealthScore,
		Severity:    s.Severity,
	}
}

// pyrProto rend un prototype valide centré sur l'état s, observé toute heure et tout jour.
func pyrProto(s *ServerHealthSnapshot, radius uint16) PyramidPrototype {
	return PyramidPrototype{
		Bitcode:         *localityCode(s),
		Radius:          radius,
		Subsystem:       s.Subsystem,
		AverageScore:    s.HealthScore,
		MinScore:        s.HealthScore,
		HitCount:        1,
		TemporalPattern: PyramidHoursMask | PyramidDaysMask,
	}
}

func pyrSave(t testing.TB, scale uint16, protos ...PyramidPrototype) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := SavePyramid(&buf, pyrMachine, scale, pyrDay-6, pyrDay, protos); err != nil {
		t.Fatalf("SavePyramid: %v", err)
	}
	return buf.Bytes()
}

func pyrLoad(t testing.TB, data []byte) *Pyramid {
	t.Helper()
	p, err := LoadPyramid(bytes.NewReader(data), pyrMachine)
	if err != nil {
		t.Fatalf("LoadPyramid: %v", err)
	}
	return p
}

// pyrRaw scelle une pyramide sans la valider, comme le ferait un outil tiers.
func pyrRaw(hdr PyramidHeader, protos ...PyramidPrototype) []byte {
	hdr.Magic, hdr.Version, hdr.PrototypeCount = PyramidMagic, PyramidVersion, uint32(len(protos))
	hdr.Seal = ComputePyramidSeal(&hdr, protos)
	var out bytes.Buffer
	var hb [PyramidHeaderSize]byte
	EncodePyramidHeader(&hb, &hdr)
	out.Write(hb[:])
	var pb [PyramidPrototypeSize]byte
	for i := range protos {
		EncodePyramidPrototype(&pb, &protos[i])
		out.Write(pb[:])
	}
	return out.Bytes()
}

// pyrEngine installe une pyramide par échelle demandée, chacune avec les mêmes prototypes.
func pyrEngine(t testing.TB, scales uint16, protos ...PyramidPrototype) *MultiScalePyramid {
	t.Helper()
	m := NewMultiScalePyramid(pyrMachine)
	for _, sc := range pyrScales {
		if scales&sc != 0 {
			if err := m.Install(pyrLoad(t, pyrSave(t, sc, protos...))); err != nil {
				t.Fatalf("Install 0x%04x: %v", sc, err)
			}
		}
	}
	return m
}

func TestPyramid_SizesAndLayout(t *testing.T) {
	if unsafe.Sizeof(PyramidHeader{}) != 64 || unsafe.Sizeof(PyramidPrototype{}) != 96 {
		t.Fatalf("tailles: en-tete %d, prototype %d", unsafe.Sizeof(PyramidHeader{}), unsafe.Sizeof(PyramidPrototype{}))
	}
	// Les décalages Go coïncident avec l'encodage disque.
	var h PyramidHeader
	var p PyramidPrototype
	for name, got := range map[string]uintptr{
		"Scale": unsafe.Offsetof(h.Scale), "PrototypeCount": unsafe.Offsetof(h.PrototypeCount),
		"EpochStart": unsafe.Offsetof(h.EpochStart), "EpochEnd": unsafe.Offsetof(h.EpochEnd),
		"MachineID": unsafe.Offsetof(h.MachineID), "Seal": unsafe.Offsetof(h.Seal),
	} {
		want := map[string]uintptr{"Scale": 10, "PrototypeCount": 12, "EpochStart": 16, "EpochEnd": 20, "MachineID": 24, "Seal": 32}[name]
		if got != want {
			t.Errorf("en-tete %s: decalage %d, attendu %d", name, got, want)
		}
	}
	for name, got := range map[string]uintptr{
		"Radius": unsafe.Offsetof(p.Radius), "Subsystem": unsafe.Offsetof(p.Subsystem),
		"AverageScore": unsafe.Offsetof(p.AverageScore), "MinScore": unsafe.Offsetof(p.MinScore),
		"HitCount": unsafe.Offsetof(p.HitCount), "TemporalPattern": unsafe.Offsetof(p.TemporalPattern),
		"Reserved": unsafe.Offsetof(p.Reserved),
	} {
		want := map[string]uintptr{"Radius": 64, "Subsystem": 66, "AverageScore": 68, "MinScore": 70, "HitCount": 72, "TemporalPattern": 76, "Reserved": 80}[name]
		if got != want {
			t.Errorf("prototype %s: decalage %d, attendu %d", name, got, want)
		}
	}
	s := deltaSnap(SeverityLow)
	data := pyrSave(t, DeltaScale7d, pyrProto(&s, 8), pyrProto(&s, 4))
	if len(data) != PyramidHeaderSize+2*PyramidPrototypeSize {
		t.Fatalf("taille du fichier: %d", len(data))
	}
	if !bytes.Equal(data[:8], []byte("C2PYRAM1")) {
		t.Fatalf("magie: %q", data[:8])
	}
}

func TestPyramid_RoundTrip(t *testing.T) {
	s := deltaSnap(SeverityMedium)
	want := []PyramidPrototype{pyrProto(&s, 16), pyrProto(&s, 0)}
	want[1].Reserved = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	want[1].TemporalPattern = 1<<5 | 1<<(PyramidDaysShift+6)
	want[1].HitCount = ^uint32(0)
	want[1].MinScore, want[1].AverageScore = DegradedHealthScore, 1000
	p := pyrLoad(t, pyrSave(t, DeltaScale365d, want...))
	hdr := p.Header()
	if hdr.Scale != DeltaScale365d || hdr.EpochStart != pyrDay-6 || hdr.EpochEnd != pyrDay || hdr.MachineID != pyrMachine || hdr.PrototypeCount != 2 {
		t.Fatalf("en-tete: %+v", hdr)
	}
	if !slices.Equal(p.protos, want) {
		t.Fatalf("prototypes alteres:\n got %+v\nwant %+v", p.protos, want)
	}
}

// Chaque octet du fichier est couvert : une altération donne ErrPyramidSeal ou
// une erreur de structure, jamais un chargement réussi.
func TestPyramid_SealCoversEveryByte(t *testing.T) {
	s := deltaSnap(SeverityLow)
	data := pyrSave(t, DeltaScale30d, pyrProto(&s, 8), pyrProto(&s, 2))
	for i := range data {
		if i >= 32 && i < 64 {
			continue // le sceau lui-même
		}
		for _, flip := range []byte{0x01, 0x80} {
			bad := bytes.Clone(data)
			bad[i] ^= flip
			if _, err := LoadPyramid(bytes.NewReader(bad), pyrMachine); err == nil {
				t.Fatalf("octet %d altere (0x%02x) accepte", i, flip)
			}
		}
	}
	for _, i := range []int{32, 50, 63} {
		bad := bytes.Clone(data)
		bad[i] ^= 0xFF
		if _, err := LoadPyramid(bytes.NewReader(bad), pyrMachine); !errors.Is(err, ErrPyramidSeal) {
			t.Fatalf("sceau altere a l'octet %d: %v", i, err)
		}
	}
	for _, i := range []int{PyramidHeaderSize + 3, PyramidHeaderSize + 90, len(data) - 1} {
		bad := bytes.Clone(data)
		bad[i] ^= 0x10
		if _, err := LoadPyramid(bytes.NewReader(bad), pyrMachine); !errors.Is(err, ErrPyramidSeal) {
			t.Fatalf("prototype altere a l'octet %d: %v", i, err)
		}
	}
}

func TestPyramid_StructuralErrors(t *testing.T) {
	s := deltaSnap(SeverityLow)
	good := pyrSave(t, DeltaScale24h, pyrProto(&s, 8))
	mut := func(f func(b []byte)) []byte { b := bytes.Clone(good); f(b); return b }
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"vide", nil, ErrPyramidCorrupt},
		{"en-tete tronque", good[:40], ErrPyramidCorrupt},
		{"prototype tronque", good[:PyramidHeaderSize+50], ErrPyramidCorrupt},
		{"magie", mut(func(b []byte) { b[0] = 'X' }), ErrPyramidMagic},
		{"version", mut(func(b []byte) { b[8] = 2 }), ErrPyramidVersion},
		{"trop de prototypes", mut(func(b []byte) { b[12], b[13], b[14] = 0x01, 0x00, 0x01 }), ErrPyramidTooLarge},
	}
	for _, tc := range cases {
		if _, err := LoadPyramid(bytes.NewReader(tc.data), pyrMachine); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, attendu %v", tc.name, err, tc.want)
		}
	}
	if _, err := LoadPyramid(bytes.NewReader(good), pyrMachine+1); !errors.Is(err, ErrPyramidMachine) {
		t.Fatalf("autre machine: %v", err)
	}
}

// Les gardes s'appliquent à l'écriture comme au chargement d'un fichier scellé
// par un tiers qui ne les a pas vérifiées.
func TestPyramid_Guards(t *testing.T) {
	low := deltaSnap(SeverityLow)
	high := deltaSnap(SeverityHigh)
	crit := deltaSnap(SeverityCritical)
	type edit struct {
		name  string
		hdr   func(h *PyramidHeader)
		proto func(p *PyramidPrototype)
		want  error
	}
	cases := []edit{
		{"echelle nulle", func(h *PyramidHeader) { h.Scale = 0 }, nil, ErrPyramidScale},
		{"deux echelles", func(h *PyramidHeader) { h.Scale = DeltaScale4h | DeltaScale7d }, nil, ErrPyramidScale},
		{"echelle inconnue", func(h *PyramidHeader) { h.Scale = 1 << 7 }, nil, ErrPyramidScale},
		{"horizon inverse", func(h *PyramidHeader) { h.EpochStart, h.EpochEnd = pyrDay, pyrDay-1 }, nil, ErrPyramidEpoch},
		{"rayon 17", nil, func(p *PyramidPrototype) { p.Radius = PyramidMaxRadius + 1 }, ErrPyramidPrototype},
		{"centroide High", nil, func(p *PyramidPrototype) { p.Bitcode = *localityCode(&high) }, ErrPyramidPrototype},
		{"centroide Critical", nil, func(p *PyramidPrototype) { p.Bitcode = *localityCode(&crit) }, ErrPyramidPrototype},
		{"severite trouee", nil, func(p *PyramidPrototype) { p.Bitcode[2] = p.Bitcode[2]&^localitySeverityMask | 0xFF00 }, ErrPyramidPrototype},
		{"score minimal degrade", nil, func(p *PyramidPrototype) { p.MinScore = DegradedHealthScore - 1 }, ErrPyramidPrototype},
		{"minimum au-dessus de la moyenne", nil, func(p *PyramidPrototype) { p.MinScore = p.AverageScore + 1 }, ErrPyramidPrototype},
		{"moyenne au-dessus de 1000", nil, func(p *PyramidPrototype) { p.AverageScore, p.MinScore = 1001, 1001 }, ErrPyramidPrototype},
		{"aucune observation", nil, func(p *PyramidPrototype) { p.HitCount = 0 }, ErrPyramidPrototype},
		{"aucune heure", nil, func(p *PyramidPrototype) { p.TemporalPattern = PyramidDaysMask }, ErrPyramidPrototype},
		{"aucun jour", nil, func(p *PyramidPrototype) { p.TemporalPattern = PyramidHoursMask }, ErrPyramidPrototype},
		{"bit 31", nil, func(p *PyramidPrototype) { p.TemporalPattern |= 1 << 31 }, ErrPyramidPrototype},
	}
	for _, tc := range cases {
		h := PyramidHeader{Scale: DeltaScale7d, EpochStart: pyrDay - 6, EpochEnd: pyrDay, MachineID: pyrMachine}
		p := pyrProto(&low, 8)
		if tc.hdr != nil {
			tc.hdr(&h)
		}
		if tc.proto != nil {
			tc.proto(&p)
		}
		if err := SavePyramid(&bytes.Buffer{}, pyrMachine, h.Scale, h.EpochStart, h.EpochEnd, []PyramidPrototype{p}); !errors.Is(err, tc.want) {
			t.Errorf("%s, ecriture: %v, attendu %v", tc.name, err, tc.want)
		}
		if _, err := LoadPyramid(bytes.NewReader(pyrRaw(h, p)), pyrMachine); !errors.Is(err, tc.want) {
			t.Errorf("%s, chargement: %v, attendu %v", tc.name, err, tc.want)
		}
	}
	// Un seul prototype invalide fait refuser la pyramide entière.
	bad := pyrProto(&low, 8)
	bad.HitCount = 0
	h := PyramidHeader{Scale: DeltaScale7d, EpochStart: pyrDay, EpochEnd: pyrDay, MachineID: pyrMachine}
	if _, err := LoadPyramid(bytes.NewReader(pyrRaw(h, pyrProto(&low, 8), bad)), pyrMachine); !errors.Is(err, ErrPyramidPrototype) {
		t.Fatalf("pyramide mixte: %v", err)
	}
}

// Un en-tête annonçant beaucoup de prototypes sur un corps vide n'engage pas de mémoire.
func TestPyramid_TruncatedDoesNotPreallocate(t *testing.T) {
	hdr := PyramidHeader{Magic: PyramidMagic, Version: PyramidVersion, Scale: DeltaScale7d, PrototypeCount: PyramidMaxPrototypes, MachineID: pyrMachine}
	var hb [PyramidHeaderSize]byte
	EncodePyramidHeader(&hb, &hdr)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := LoadPyramid(bytes.NewReader(hb[:]), pyrMachine)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrPyramidCorrupt) {
		t.Fatalf("attendu ErrPyramidCorrupt: %v", err)
	}
	// Tampon de lecture (64 Kio) et préallocation bornée (1024 prototypes, 96 Kio),
	// contre 6 Mio si le compte annoncé décidait de la capacité.
	if got := after.TotalAlloc - before.TotalAlloc; got > 256<<10 {
		t.Fatalf("%d octets alloues pour un corps vide", got)
	}
}

// pyrStream produit des tranches de sept jours : un service nominal dont le
// score, l'entropie et l'heure dérivent peu, une authentification nominale,
// et des états qui ne doivent jamais servir de référence.
func pyrStream() []CondenseDay {
	var days []CondenseDay
	for d := range uint32(7) {
		day := CondenseDay{EpochDay: pyrDay - 6 + d}
		base := uint64(day.EpochDay) * 86400
		for i := range 40 {
			s := localityBase()
			s.TimestampSec = base + 9*3600 + uint64(i)*60
			s.HealthScore = uint16(960 + i%5*5)
			s.EntropyQ8 = uint32(1100 + i%3*8)
			day.Entries = append(day.Entries, pyrEntry(&s))

			a := localityBase()
			a.Subsystem, a.EntityID = OracleSubAuth, 2002
			a.TimestampSec = base + 21*3600 + uint64(i)*30
			day.Entries = append(day.Entries, pyrEntry(&a))
		}
		for _, sev := range []uint16{SeverityHigh, SeverityCritical} {
			s := localityBase()
			s.TimestampSec, s.Severity = base+12*3600, sev
			day.Entries = append(day.Entries, pyrEntry(&s))
		}
		deg := localityBase()
		deg.TimestampSec, deg.HealthScore = base+13*3600, DegradedHealthScore-1
		day.Entries = append(day.Entries, pyrEntry(&deg))
		flagged := localityBase()
		flagged.TimestampSec = base + 14*3600
		e := pyrEntry(&flagged)
		e.Flags = OracleFlagAnomalies
		day.Entries = append(day.Entries, e)
		// Champ Severity Low mais bitcode High : le bitcode fait foi.
		forged := localityBase()
		forged.TimestampSec, forged.Severity = base+15*3600, SeverityHigh
		fe := pyrEntry(&forged)
		fe.Severity = SeverityLow
		day.Entries = append(day.Entries, fe)
		days = append(days, day)
	}
	return days
}

func TestCondensePrototypes_ReferenceOnly(t *testing.T) {
	days := pyrStream()
	protos, st := CondensePrototypes(days, CondenseConfig{Radius: 12})
	if st.Admitted != 7*80 || st.Excluded != 7*5 {
		t.Fatalf("admises %d, ecartees %d", st.Admitted, st.Excluded)
	}
	if st.EpochStart != pyrDay-6 || st.EpochEnd != pyrDay {
		t.Fatalf("horizon %d..%d", st.EpochStart, st.EpochEnd)
	}
	if len(protos) < 2 {
		t.Fatalf("%d prototypes, au moins un par sous-systeme attendu", len(protos))
	}
	var hits uint64
	subs := map[uint16]bool{}
	for i := range protos {
		p := &protos[i]
		if err := ValidatePyramidPrototype(p); err != nil {
			t.Fatalf("prototype %d invalide: %v", i, err)
		}
		if int(p.Radius) > 12 {
			t.Fatalf("prototype %d: rayon %d > 12", i, p.Radius)
		}
		if lvl, _ := deltaSeverityLevel(p.Bitcode[2]); lvl != SeverityLow {
			t.Fatalf("prototype %d: severite %d", i, lvl)
		}
		hits += uint64(p.HitCount)
		subs[p.Subsystem] = true
	}
	if hits != uint64(st.Admitted) || !subs[OracleSubService] || !subs[OracleSubAuth] || len(subs) != 2 {
		t.Fatalf("observations %d, sous-systemes %v", hits, subs)
	}
	// Chaque entrée admise tombe dans le rayon de son prototype : réévaluée à son
	// propre instant, elle est nominale à toutes les échelles.
	m := pyrEngine(t, DeltaScaleAll, protos...)
	for _, day := range days {
		for i := range day.Entries {
			e := &day.Entries[i]
			if _, ok := condenseAdmit(e); !ok {
				continue
			}
			ts := uint64(day.EpochDay)*86400 + uint64(e.RelativeSec)
			if rep := m.EvaluateInstantaneous(&e.Bitcode, ts, nil); rep.NominalMask != DeltaScaleAll {
				t.Fatalf("entree admise non nominale: %+v", rep)
			}
		}
	}
	// Les états écartés restent des anomalies.
	for _, day := range days {
		for i := range day.Entries {
			e := &day.Entries[i]
			if _, ok := condenseAdmit(e); ok {
				continue
			}
			ts := uint64(day.EpochDay)*86400 + uint64(e.RelativeSec)
			rep := m.EvaluateInstantaneous(&e.Bitcode, ts, nil)
			if e.Flags == 0 && e.HealthScore >= DegradedHealthScore && rep.NominalMask != 0 {
				t.Fatalf("etat grave devenu nominal: severite %d, %+v", e.Severity, rep)
			}
		}
	}
}

// Le motif temporel porte les heures et les jours effectivement observés.
func TestCondensePrototypes_TemporalPattern(t *testing.T) {
	protos, _ := CondensePrototypes(pyrStream(), CondenseConfig{})
	var svc, auth uint32
	for _, p := range protos {
		switch p.Subsystem {
		case OracleSubService:
			svc |= p.TemporalPattern
		case OracleSubAuth:
			auth |= p.TemporalPattern
		}
	}
	if svc&PyramidHoursMask != 1<<9 || auth&PyramidHoursMask != 1<<21 {
		t.Fatalf("heures: service 0x%06x, auth 0x%06x", svc&PyramidHoursMask, auth&PyramidHoursMask)
	}
	if svc&PyramidDaysMask != PyramidDaysMask || auth&PyramidDaysMask != PyramidDaysMask {
		t.Fatalf("jours: service 0x%08x, auth 0x%08x", svc, auth)
	}
}

// Même entrée, même résultat, quel que soit l'ordre de présentation des jours.
func TestCondensePrototypes_Deterministic(t *testing.T) {
	days := pyrStream()
	a, sa := CondensePrototypes(days, CondenseConfig{Radius: 10})
	b, sb := CondensePrototypes(days, CondenseConfig{Radius: 10})
	rev := slices.Clone(days)
	slices.Reverse(rev)
	c, sc := CondensePrototypes(rev, CondenseConfig{Radius: 10})
	if !slices.Equal(a, b) || !slices.Equal(a, c) || sa != sb || sa != sc {
		t.Fatalf("condensation non deterministe: %d/%d/%d prototypes", len(a), len(b), len(c))
	}
}

// Deux sévérités admises ne fusionnent jamais, même à 8 bits l'une de l'autre.
func TestCondensePrototypes_SeverityNeverMerges(t *testing.T) {
	low := deltaSnap(SeverityLow)
	med := deltaSnap(SeverityMedium)
	protos, st := CondensePrototypes([]CondenseDay{{EpochDay: pyrDay, Entries: []OracleVectorEntry{pyrEntry(&low), pyrEntry(&med), pyrEntry(&low)}}}, CondenseConfig{Radius: 16})
	if len(protos) != 2 || st.Clusters != 2 {
		t.Fatalf("%d prototypes pour deux severites", len(protos))
	}
	if protos[0].HitCount != 2 || protos[1].HitCount != 1 || protos[0].Radius != 0 {
		t.Fatalf("prototypes: %+v", protos)
	}
}

// Saturation : MaxPrototypes garde les groupes les plus fournis, MinHits écarte
// les groupes rares, et le compte des observations perdues est exact.
func TestCondensePrototypes_Saturation(t *testing.T) {
	var entries []OracleVectorEntry
	for ent := range 10 {
		s := deltaSnap(SeverityLow)
		s.EntityID = uint64(5000 + ent)
		for range ent + 1 {
			entries = append(entries, pyrEntry(&s))
		}
	}
	day := []CondenseDay{{EpochDay: pyrDay, Entries: entries}}
	protos, st := CondensePrototypes(day, CondenseConfig{MaxPrototypes: 3})
	if len(protos) != 3 || st.Clusters != 10 || st.DroppedClusters != 7 || st.DroppedHits != 1+2+3+4+5+6+7 {
		t.Fatalf("saturation: %d prototypes, %+v", len(protos), st)
	}
	for i, want := range []uint32{8, 9, 10} {
		if protos[i].HitCount != want {
			t.Fatalf("prototype %d: %d observations, attendu %d (ordre de creation)", i, protos[i].HitCount, want)
		}
	}
	protos, st = CondensePrototypes(day, CondenseConfig{MinHits: 9})
	if len(protos) != 2 || st.DroppedHits != 1+2+3+4+5+6+7+8 {
		t.Fatalf("MinHits: %d prototypes, %+v", len(protos), st)
	}
	if protos, st := CondensePrototypes(nil, CondenseConfig{}); len(protos) != 0 || st != (CondenseStats{}) {
		t.Fatalf("entree vide: %v %+v", protos, st)
	}
}

// Le rayon de chaque prototype borne la distance de tous ses membres, y compris
// quand le vote majoritaire s'éloigne du meneur au point de le dépasser.
func TestCondensePrototypes_RadiusBoundsMembers(t *testing.T) {
	ref := deltaSnap(SeverityLow)
	leader := pyrEntry(&ref)
	entries := []OracleVectorEntry{leader}
	// Six membres retournent les bits 0..3 du mot 7, quatre les bits 4..7 : tous
	// à 4 bits du meneur. Le vote (6 sur 11) retourne les bits 0..3, et les
	// quatre derniers membres sont alors à 8 bits du centroïde, au-delà du rayon 4.
	for range 6 {
		e := leader
		e.Bitcode[7] ^= 0x0F
		entries = append(entries, e)
	}
	for range 4 {
		e := leader
		e.Bitcode[7] ^= 0xF0
		entries = append(entries, e)
	}
	protos, st := CondensePrototypes([]CondenseDay{{EpochDay: pyrDay, Entries: entries}}, CondenseConfig{Radius: 4})
	if len(protos) != 1 || st.Clusters != 1 {
		t.Fatalf("%d prototypes", len(protos))
	}
	if protos[0].Bitcode != leader.Bitcode || protos[0].Radius != 4 || protos[0].HitCount != 11 {
		t.Fatalf("repli sur le meneur absent: rayon %d, centroide = meneur %v", protos[0].Radius, protos[0].Bitcode == leader.Bitcode)
	}
	// Sans débordement, le centroïde est le vote : avec sept membres 0..3 sur
	// douze et rayon 8, le centroïde retourne les bits 0..3.
	e := leader
	e.Bitcode[7] ^= 0x0F
	protos, _ = CondensePrototypes([]CondenseDay{{EpochDay: pyrDay, Entries: append(slices.Clone(entries), e)}}, CondenseConfig{Radius: 8})
	want := leader.Bitcode
	want[7] ^= 0x0F
	if len(protos) != 1 || protos[0].Bitcode != want || protos[0].Radius != 8 {
		t.Fatalf("centroide vote: rayon %d", protos[0].Radius)
	}
	for _, e := range entries {
		if d := HammingDistance512(&e.Bitcode, &protos[0].Bitcode); d > int(protos[0].Radius) {
			t.Fatalf("membre a %d bits, rayon %d", d, protos[0].Radius)
		}
	}
}

// Un état nominal l'est à chaque échelle installée ; une échelle absente ne
// rend aucun verdict.
func TestMultiScale_NominalAndLoaded(t *testing.T) {
	s := deltaSnap(SeverityLow)
	m := pyrEngine(t, DeltaScale4h|DeltaScale24h|DeltaScale365d, pyrProto(&s, 6))
	if m.Scales() != DeltaScale4h|DeltaScale24h|DeltaScale365d {
		t.Fatalf("echelles installees 0x%04x", m.Scales())
	}
	rep := m.EvaluateInstantaneous(localityCode(&s), deltaTs, nil)
	if rep.LoadedMask != m.Scales() || rep.NominalMask != m.Scales() || rep.AnomalyMask != 0 || rep.DispensedMask != 0 {
		t.Fatalf("rapport: %+v", rep)
	}
	for i, lv := range rep.Levels {
		if lv.Scale != pyrScales[i] {
			t.Fatalf("niveau %d: echelle 0x%04x", i, lv.Scale)
		}
		if lv.Loaded != (m.Scales()&lv.Scale != 0) || lv.Anomaly() {
			t.Fatalf("niveau %d: %+v", i, lv)
		}
		if lv.Loaded && (lv.DisparityBits != 0 || lv.PrototypeIndex != 0) {
			t.Fatalf("niveau %d: %+v", i, lv)
		}
		if !lv.Loaded && (lv.DisparityBits != 512 || lv.PrototypeIndex != -1) {
			t.Fatalf("niveau absent %d: %+v", i, lv)
		}
	}
	var nilEngine *MultiScalePyramid
	if rep := nilEngine.EvaluateInstantaneous(localityCode(&s), deltaTs, nil); rep.LoadedMask != 0 {
		t.Fatalf("moteur nil: %+v", rep)
	}
	if rep := m.EvaluateInstantaneous(nil, deltaTs, nil); rep.LoadedMask != 0 || rep.AnomalyMask != 0 {
		t.Fatalf("observation nil: %+v", rep)
	}
}

// Un écart au-delà du rayon est dispensé aux seules échelles de la règle, et
// reste une anomalie active aux autres.
func TestMultiScale_DeviationDispensedPerScale(t *testing.T) {
	s := deltaSnap(SeverityLow)
	m := pyrEngine(t, DeltaScaleAll, pyrProto(&s, 4))
	drift := s
	drift.HealthScore = 500
	obs := localityCode(&drift)
	d := HammingDistance512(obs, localityCode(&s))
	if d <= 4 {
		t.Fatalf("derive de %d bits seulement", d)
	}
	rep := m.EvaluateInstantaneous(obs, deltaTs, nil)
	if rep.AnomalyMask != DeltaScaleAll || rep.NominalMask != 0 {
		t.Fatalf("sans catalogue: %+v", rep)
	}
	for _, lv := range rep.Levels {
		if int(lv.DisparityBits) != d || lv.PrototypeIndex != 0 || lv.RuleID != 0 {
			t.Fatalf("niveau: %+v, distance %d attendue", lv, d)
		}
	}
	r := deltaRule(31, &drift)
	r.ScaleMask = DeltaScale4h | DeltaScale7d | DeltaScale365d
	c := deltaLoad(t, deltaSave(t, r))
	rep = m.EvaluateInstantaneous(obs, deltaTs, c)
	if rep.DispensedMask != r.ScaleMask || rep.AnomalyMask != DeltaScaleAll&^r.ScaleMask {
		t.Fatalf("avec catalogue: %+v", rep)
	}
	for _, lv := range rep.Levels {
		if lv.Dispensed != (r.ScaleMask&lv.Scale != 0) || (lv.Dispensed && lv.RuleID != 31) {
			t.Fatalf("niveau: %+v", lv)
		}
	}
	// Hors de la fenêtre de la règle, plus aucune dispense.
	if rep := m.EvaluateInstantaneous(obs, r.NotAfterSec+1, c); rep.DispensedMask != 0 || rep.AnomalyMask != DeltaScaleAll {
		t.Fatalf("regle expiree: %+v", rep)
	}
}

// Pyramide vide : toute observation est une anomalie, sauf dispense.
func TestMultiScale_EmptyPyramid(t *testing.T) {
	s := deltaSnap(SeverityLow)
	m := pyrEngine(t, DeltaScale7d)
	if m.Scales() != DeltaScale7d {
		t.Fatalf("echelles 0x%04x", m.Scales())
	}
	rep := m.EvaluateInstantaneous(localityCode(&s), deltaTs, nil)
	if rep.AnomalyMask != DeltaScale7d || rep.Levels[3].DisparityBits != 512 || rep.Levels[3].PrototypeIndex != -1 {
		t.Fatalf("pyramide vide: %+v", rep)
	}
	r := deltaRule(8, &s)
	r.ScaleMask = DeltaScale7d
	if rep := m.EvaluateInstantaneous(localityCode(&s), deltaTs, deltaLoad(t, deltaSave(t, r))); rep.DispensedMask != DeltaScale7d || rep.AnomalyMask != 0 {
		t.Fatalf("pyramide vide dispensee: %+v", rep)
	}
}

// Un prototype de rayon 16 n'absorbe aucune aggravation de sévérité, bien que
// Medium ne soit qu'à 8 bits de Low et High à 16 bits.
func TestMultiScale_SeverityGuard(t *testing.T) {
	low := deltaSnap(SeverityLow)
	m := pyrEngine(t, DeltaScaleAll, pyrProto(&low, PyramidMaxRadius))
	for _, sev := range []uint16{SeverityMedium, SeverityHigh, SeverityCritical} {
		o := low
		o.Severity = sev
		code := localityCode(&o)
		if d := HammingDistance512(code, localityCode(&low)); sev <= SeverityHigh && d > PyramidMaxRadius {
			t.Fatalf("severite %d a %d bits: le cas ne mord pas", sev, d)
		}
		if rep := m.EvaluateInstantaneous(code, deltaTs, nil); rep.NominalMask != 0 || rep.AnomalyMask != DeltaScaleAll {
			t.Fatalf("severite %d blanchie: %+v", sev, rep)
		}
	}
	// Une sévérité moindre que celle du prototype reste admise dans le rayon.
	med := deltaSnap(SeverityMedium)
	m = pyrEngine(t, DeltaScale24h, pyrProto(&med, PyramidMaxRadius))
	if rep := m.EvaluateInstantaneous(localityCode(&low), deltaTs, nil); rep.NominalMask != DeltaScale24h {
		t.Fatalf("Low refuse par un prototype Medium: %+v", rep)
	}
}

// Motif temporel : à 4 h et 12 h aucun filtre ; à 24 h l'heure et ses voisines,
// minuit voisinant 23 h ; à 7 j et au-delà, le jour de la semaine en plus.
func TestMultiScale_TemporalWrapAround(t *testing.T) {
	s := deltaSnap(SeverityLow)
	p := pyrProto(&s, 4)
	p.TemporalPattern = 1<<23 | 1<<(PyramidDaysShift+int(time.Sunday))
	m := pyrEngine(t, DeltaScaleAll, p)
	code := localityCode(&s)
	at := func(day time.Weekday, hour, minute int) uint64 {
		// Semaine du dimanche 27 septembre 2026.
		return uint64(time.Date(2026, 9, 27+int(day), hour, minute, 0, 0, time.UTC).Unix())
	}
	short := DeltaScale4h | DeltaScale12h
	cases := []struct {
		name string
		ts   uint64
		want uint16
	}{
		{"dimanche 23h30", at(time.Sunday, 23, 30), DeltaScaleAll},
		{"dimanche 22h10, voisine", at(time.Sunday, 22, 10), DeltaScaleAll},
		{"dimanche 00h20, minuit voisin de 23h", at(time.Sunday, 0, 20), DeltaScaleAll},
		{"dimanche 01h00, hors voisinage", at(time.Sunday, 1, 0), short},
		{"dimanche 21h59, hors voisinage", at(time.Sunday, 21, 59), short},
		{"lundi 00h20, jour absent", at(time.Monday, 0, 20), short | DeltaScale24h},
		{"samedi 23h30, jour absent", at(time.Saturday, 23, 30), short | DeltaScale24h},
		{"lundi 12h00", at(time.Monday, 12, 0), short},
	}
	for _, tc := range cases {
		if rep := m.EvaluateInstantaneous(code, tc.ts, nil); rep.NominalMask != tc.want || rep.AnomalyMask != DeltaScaleAll&^tc.want {
			t.Errorf("%s: nominal 0x%04x, attendu 0x%04x", tc.name, rep.NominalMask, tc.want)
		}
	}
}

// Un prototype qui contient l'état l'emporte sur un prototype plus proche qui
// ne le contient pas ; à défaut, le plus proche est rapporté.
func TestMultiScale_ContainingPrototypeWins(t *testing.T) {
	s := deltaSnap(SeverityLow)
	near := pyrProto(&s, 0)
	near.Bitcode[7] ^= 0x3 // à 2 bits, rayon 0 : ne contient pas s
	far := pyrProto(&s, 6)
	far.Bitcode[7] ^= 0x3F0 // à 6 bits, rayon 6 : contient s
	m := pyrEngine(t, DeltaScale4h, near, far)
	lv := m.EvaluateInstantaneous(localityCode(&s), deltaTs, nil).Levels[0]
	if !lv.Nominal || lv.PrototypeIndex != 1 || lv.DisparityBits != 6 {
		t.Fatalf("niveau: %+v", lv)
	}
	m = pyrEngine(t, DeltaScale4h, near)
	lv = m.EvaluateInstantaneous(localityCode(&s), deltaTs, nil).Levels[0]
	if lv.Nominal || lv.PrototypeIndex != 0 || lv.DisparityBits != 2 {
		t.Fatalf("niveau sans prototype contenant: %+v", lv)
	}
}

func TestMultiScale_InstallRemove(t *testing.T) {
	s := deltaSnap(SeverityLow)
	m := NewMultiScalePyramid(pyrMachine)
	other, err := LoadPyramid(bytes.NewReader(pyrRaw(PyramidHeader{Scale: DeltaScale7d, EpochStart: 1, EpochEnd: 2, MachineID: pyrMachine + 1}, pyrProto(&s, 4))), pyrMachine+1)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Install(other); !errors.Is(err, ErrPyramidMachine) {
		t.Fatalf("pyramide etrangere: %v", err)
	}
	if err := m.Install(nil); err == nil {
		t.Fatal("pyramide nil installee")
	}
	p := pyrLoad(t, pyrSave(t, DeltaScale30d, pyrProto(&s, 4)))
	if err := m.Install(p); err != nil || m.Scales() != DeltaScale30d {
		t.Fatalf("Install: %v, 0x%04x", err, m.Scales())
	}
	// Remplacement par une pyramide vide de la même échelle.
	if err := m.Install(pyrLoad(t, pyrSave(t, DeltaScale30d))); err != nil {
		t.Fatal(err)
	}
	if rep := m.EvaluateInstantaneous(localityCode(&s), deltaTs, nil); rep.AnomalyMask != DeltaScale30d {
		t.Fatalf("remplacement ignore: %+v", rep)
	}
	for _, bad := range []uint16{0, DeltaScale4h | DeltaScale12h, 1 << 7} {
		if err := m.Remove(bad); !errors.Is(err, ErrPyramidScale) {
			t.Fatalf("Remove 0x%04x: %v", bad, err)
		}
	}
	if err := m.Remove(DeltaScale30d); err != nil || m.Scales() != 0 {
		t.Fatalf("Remove: %v, 0x%04x", err, m.Scales())
	}
}

func TestMultiScale_EvaluateZeroAlloc(t *testing.T) {
	protos, _ := CondensePrototypes(pyrStream(), CondenseConfig{Radius: 8})
	m := pyrEngine(t, DeltaScaleAll, protos...)
	s := deltaSnap(SeverityLow)
	drift := s
	drift.HealthScore = 500
	r := deltaRule(4, &drift)
	r.ScaleMask = DeltaScale24h
	c := deltaLoad(t, deltaSave(t, r))
	for _, code := range []*[8]uint64{localityCode(&s), localityCode(&drift)} {
		if n := testing.AllocsPerRun(1000, func() { m.EvaluateInstantaneous(code, deltaTs, c) }); n != 0 {
			t.Fatalf("EvaluateInstantaneous: %v allocations", n)
		}
	}
}

// Évaluations concurrentes pendant des installations et retraits ; -race
// vérifie l'absence de course, et chaque rapport reste cohérent.
func TestMultiScale_ConcurrentInstallEvaluate(t *testing.T) {
	s := deltaSnap(SeverityLow)
	full := make([]*Pyramid, DeltaScaleCount)
	for i, sc := range pyrScales {
		full[i] = pyrLoad(t, pyrSave(t, sc, pyrProto(&s, 4)))
	}
	m := NewMultiScalePyramid(pyrMachine)
	code := localityCode(&s)
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Go(func() {
			for k := range 200 {
				i := (w + k) % DeltaScaleCount
				if k%3 == 2 {
					_ = m.Remove(pyrScales[i])
				} else if err := m.Install(full[i]); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	for range 8 {
		wg.Go(func() {
			for range 500 {
				rep := m.EvaluateInstantaneous(code, deltaTs, nil)
				if rep.NominalMask != rep.LoadedMask || rep.AnomalyMask != 0 || rep.NominalMask|rep.DispensedMask|rep.AnomalyMask != rep.LoadedMask {
					t.Errorf("rapport incoherent: %+v", rep)
					return
				}
			}
		})
	}
	wg.Wait()
}

func BenchmarkEvaluateInstantaneous(b *testing.B) {
	s := deltaSnap(SeverityLow)
	protos := make([]PyramidPrototype, 1024)
	for i := range protos {
		o := s
		o.EntityID = uint64(i + 7000)
		protos[i] = pyrProto(&o, 8)
	}
	m := pyrEngine(b, DeltaScaleAll, protos...)
	drift := s
	drift.HealthScore = 500
	c := deltaLoad2(b, deltaRule(1, &drift))
	code := localityCode(&drift)
	b.ReportAllocs()
	for b.Loop() {
		m.EvaluateInstantaneous(code, deltaTs, c)
	}
}

func deltaLoad2(b *testing.B, rules ...DeltaRule) *DeltaCatalog {
	var buf bytes.Buffer
	if err := SaveDeltaCatalog(&buf, deltaMachine, rules); err != nil {
		b.Fatal(err)
	}
	c, err := LoadDeltaCatalog(&buf, deltaMachine)
	if err != nil {
		b.Fatal(err)
	}
	return c
}

// Finding F_DS_02 : la pyramide se scelle en HMAC-SHA256, ne se charge que sous
// sa clé, et une pyramide forgée sans la clé est refusée.
func TestPyramid_HMAC(t *testing.T) {
	s := deltaSnap(SeverityLow)
	protos := []PyramidPrototype{pyrProto(&s, 4)}
	var keyed bytes.Buffer
	if err := SavePyramidHMAC(&keyed, pyrMachine, DeltaScale7d, pyrDay-6, pyrDay, protos, deltaKey); err != nil {
		t.Fatal(err)
	}
	file := keyed.Bytes()
	raw := bytes.Clone(file)
	clear(raw[32:64])
	m := hmac.New(sha256.New, deltaKey)
	m.Write(raw)
	if !bytes.Equal(file[32:64], m.Sum(nil)) {
		t.Fatal("sceau HMAC different de l'oracle crypto/hmac")
	}
	var hdr PyramidHeader
	DecodePyramidHeader((*[PyramidHeaderSize]byte)(file[:PyramidHeaderSize]), &hdr)
	if ComputePyramidSealHMAC(&hdr, protos, deltaKey) != hdr.Seal ||
		ComputePyramidSealHMAC(&hdr, protos, nil) != ComputePyramidSeal(&hdr, protos) {
		t.Fatal("ComputePyramidSealHMAC incoherent")
	}
	p, err := LoadPyramidHMAC(bytes.NewReader(file), pyrMachine, deltaKey)
	if err != nil || p.Len() != 1 {
		t.Fatalf("chargement sous la cle: %v", err)
	}
	for name, key := range map[string][]byte{"sans cle": nil, "autre cle": bytes.Repeat([]byte{'y'}, 32)} {
		if _, err := LoadPyramidHMAC(bytes.NewReader(file), pyrMachine, key); !errors.Is(err, ErrPyramidSeal) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Un attaquant élargit la norme (rayon 16) et rescelle en SHA-256.
	wide := protos[0]
	wide.Radius = PyramidMaxRadius
	forged := pyrRaw(PyramidHeader{Scale: DeltaScale7d, EpochStart: pyrDay - 6, EpochEnd: pyrDay, MachineID: pyrMachine}, wide)
	if _, err := LoadPyramidHMAC(bytes.NewReader(forged), pyrMachine, deltaKey); !errors.Is(err, ErrPyramidSeal) {
		t.Fatalf("pyramide forgee acceptee sous cle: %v", err)
	}
	if _, err := LoadPyramidHMAC(bytes.NewReader(forged), pyrMachine, nil); err != nil {
		t.Fatalf("compatibilite SHA-256: %v", err)
	}
	var again bytes.Buffer
	if err := p.SaveHMAC(&again, deltaKey); err != nil || !bytes.Equal(again.Bytes(), file) {
		t.Fatalf("SaveHMAC ne reproduit pas le fichier: %v", err)
	}
	if err := SavePyramidHMAC(io.Discard, pyrMachine, DeltaScale7d, pyrDay, pyrDay, protos, []byte("court")); !errors.Is(err, ErrSealKey) {
		t.Fatalf("cle courte: %v", err)
	}
}

// pyrDistinct rend n entrées d'entités toutes distinctes, chacune à plus de
// PyramidMaxRadius bits des autres (mot 6 mélangé), donc chacune son groupe.
func pyrDistinct(first, n int) []OracleVectorEntry {
	out := make([]OracleVectorEntry, 0, n)
	for i := range n {
		s := deltaSnap(SeverityLow)
		s.EntityID = uint64(100000 + first + i)
		out = append(out, pyrEntry(&s))
	}
	return out
}

// Finding N3 : les groupes vivants ne dépassent jamais le plafond, les groupes
// évincés sont les moins fournis, un groupe fréquent survit à un flot d'états
// uniques, et la condensation reste déterministe.
func TestCondensePrototypes_IntermediateBudget(t *testing.T) {
	heavy := deltaSnap(SeverityLow)
	heavy.EntityID = 7
	var entries []OracleVectorEntry
	for range 50 {
		entries = append(entries, pyrEntry(&heavy))
	}
	entries = append(entries, pyrDistinct(0, 100)...)
	for range 10 {
		entries = append(entries, pyrEntry(&heavy))
	}
	day := []CondenseDay{{EpochDay: pyrDay, Entries: entries}}
	const budget = 8
	protos, st := CondensePrototypes(day, CondenseConfig{MaxIntermediateClusters: budget})
	if st.PeakClusters != budget {
		t.Fatalf("pic de groupes vivants %d, plafond %d", st.PeakClusters, budget)
	}
	if st.Clusters != 101 || st.EvictedClusters == 0 || uint64(st.EvictedClusters) != st.EvictedHits {
		t.Fatalf("evictions: %+v", st)
	}
	if len(protos) > budget || len(protos) != st.Clusters-st.EvictedClusters-st.DroppedClusters {
		t.Fatalf("%d prototypes, %+v", len(protos), st)
	}
	var sum uint64
	for _, p := range protos {
		sum += uint64(p.HitCount)
	}
	if sum+st.EvictedHits+st.DroppedHits != uint64(st.Admitted) {
		t.Fatalf("observations: %d gardees + %d evincees + %d ecartees != %d admises", sum, st.EvictedHits, st.DroppedHits, st.Admitted)
	}
	if protos[0].HitCount != 60 || protos[0].Bitcode != *localityCode(&heavy) {
		t.Fatalf("groupe frequent perdu: %+v", protos[0])
	}
	// Les survivants uniques sont les derniers fondés : à égalité, le plus ancien part.
	last := pyrDistinct(99, 1)[0]
	if protos[len(protos)-1].Bitcode != last.Bitcode {
		t.Fatal("le dernier etat unique a ete evince avant un plus ancien")
	}
	for _, p := range protos {
		if err := ValidatePyramidPrototype(&p); err != nil {
			t.Fatal(err)
		}
	}
	again, st2 := CondensePrototypes(day, CondenseConfig{MaxIntermediateClusters: budget})
	if !slices.Equal(protos, again) || st != st2 {
		t.Fatal("condensation plafonnee non deterministe")
	}
	// Sous le plafond, rien n'est évincé et le résultat ne dépend pas du plafond.
	full, stFull := CondensePrototypes(day, CondenseConfig{MaxIntermediateClusters: 200})
	if stFull.EvictedClusters != 0 || stFull.PeakClusters != 101 || len(full) != 101 {
		t.Fatalf("sous le plafond: %+v", stFull)
	}
	dflt, _ := CondensePrototypes(day, CondenseConfig{})
	if !slices.Equal(full, dflt) {
		t.Fatal("plafond par defaut different d'un plafond non atteint")
	}
}

func TestCondensePrototypes_BudgetBounds(t *testing.T) {
	for in, want := range map[int]int{
		0: CondenseDefaultIntermediateClusters, -3: CondenseDefaultIntermediateClusters,
		1: 1, 4096: 4096, 16384: 16384, 16385: CondenseMaxIntermediateClusters, 1 << 30: CondenseMaxIntermediateClusters,
	} {
		if got := condenseBudget(in); got != want {
			t.Fatalf("condenseBudget(%d) = %d, attendu %d", in, got, want)
		}
	}
	if CondenseDefaultIntermediateClusters != 4096 || CondenseMaxIntermediateClusters != 16384 {
		t.Fatal("plafonds contractuels modifies")
	}
}

// La hiérarchie condense des horizons emboîtés ancrés sur le dernier jour :
// chaque échelle ne voit que les tranches de son horizon.
func TestCondensePyramidHierarchy(t *testing.T) {
	end := pyrDay
	// Un état unique par tranche, aux jours end, end-3, end-10, end-60, end-200, end-380.
	offsets := []uint32{380, 200, 60, 10, 3, 0}
	var days []CondenseDay
	for i, off := range offsets {
		days = append(days, CondenseDay{EpochDay: end - off, Entries: pyrDistinct(i, 1)})
	}
	slices.Reverse(days) // l'ordre fourni ne compte pas
	pyr, stats, err := CondensePyramidHierarchyStats(days, CondenseConfig{}, pyrMachine)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint16]struct {
		n     int
		start uint32
	}{
		DeltaScale24h: {1, end}, DeltaScale7d: {2, end - 3}, DeltaScale30d: {3, end - 10},
		DeltaScale120d: {4, end - 60}, DeltaScale365d: {5, end - 200},
	}
	if len(pyr) != len(want) {
		t.Fatalf("%d pyramides", len(pyr))
	}
	for sc, w := range want {
		p := pyr[sc]
		h := p.Header()
		if p.Len() != w.n || h.Scale != sc || h.EpochStart != w.start || h.EpochEnd != end || h.MachineID != pyrMachine {
			t.Fatalf("echelle 0x%04x: %d prototypes, en-tete %+v", sc, p.Len(), h)
		}
		if stats[sc].Admitted != w.n {
			t.Fatalf("echelle 0x%04x: stats %+v", sc, stats[sc])
		}
		var buf bytes.Buffer
		if err := p.SaveHMAC(&buf, deltaKey); err != nil {
			t.Fatal(err)
		}
		back, err := LoadPyramidHMAC(&buf, pyrMachine, deltaKey)
		if err != nil || back.Len() != w.n {
			t.Fatalf("aller-retour 0x%04x: %v", sc, err)
		}
		m := NewMultiScalePyramid(pyrMachine)
		if err := m.Install(back); err != nil {
			t.Fatal(err)
		}
	}
	// Échelles choisies, et refus des horizons infra-journaliers.
	sub, err := CondensePyramidHierarchy(days, CondenseConfig{Scales: DeltaScale7d | DeltaScale365d}, pyrMachine)
	if err != nil || len(sub) != 2 || sub[DeltaScale7d].Len() != 2 {
		t.Fatalf("echelles choisies: %v", err)
	}
	for _, sc := range []uint16{DeltaScale4h, DeltaScale12h, 1 << 7} {
		if _, err := CondensePyramidHierarchy(days, CondenseConfig{Scales: sc | DeltaScale24h}, pyrMachine); !errors.Is(err, ErrPyramidScale) {
			t.Fatalf("echelle 0x%04x: %v", sc, err)
		}
	}
	if _, err := CondensePyramidHierarchy(nil, CondenseConfig{}, pyrMachine); !errors.Is(err, ErrCondenseNoDays) {
		t.Fatalf("sans tranche: %v", err)
	}
	// Un historique plus court que l'horizon ne sous-déborde pas le jour de départ.
	early := []CondenseDay{{EpochDay: 3, Entries: pyrDistinct(0, 1)}}
	if p, err := CondensePyramidHierarchy(early, CondenseConfig{}, pyrMachine); err != nil || p[DeltaScale365d].Header().EpochStart != 3 {
		t.Fatalf("historique court: %v", err)
	}
}
