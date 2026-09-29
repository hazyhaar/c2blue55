package c2blue55

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

// Finding F_DS_05 : les K dernières tranches sont les K derniers jours
// numériques. En ordre lexicographique, « _9 » passe après « _10 » et « _99 »
// après « _100 ».
func TestBuildServerBaseline_NumericDayOrder(t *testing.T) {
	dir := t.TempDir()
	silo := p0Silo(t, dir)
	days := []uint64{9, 10, 99, 100}
	snaps := make(map[uint64]engine.ServerHealthSnapshot, len(days))
	for i, d := range days {
		s := p0Snap(d*86400+3600, uint64(100+i), engine.SeverityLow, 990)
		snaps[d] = s
		v3WriteDay(t, dir, d*86400, engine.OracleVersion, 0, s)
	}
	cfg := engine.DefaultLocalityThresholds()
	nominal := func(o *engine.ServerBaselineOracle, d uint64) bool {
		s := snaps[d]
		var code [8]uint64
		engine.VectorizeServerHealthLocality(&s, &code)
		ok, _, _, _ := o.QueryStateLocality(&code, cfg)
		return ok
	}
	for _, tc := range []struct {
		maxDays int
		kept    []uint64
	}{
		{1, []uint64{100}},
		{2, []uint64{99, 100}},
		{3, []uint64{10, 99, 100}},
		{0, days},
	} {
		o, err := silo.BuildServerBaseline(tc.maxDays)
		if err != nil {
			t.Fatal(err)
		}
		if o.Len() != len(tc.kept) {
			t.Fatalf("maxDays %d: %d entrees, attendu %d", tc.maxDays, o.Len(), len(tc.kept))
		}
		for _, d := range tc.kept {
			if !nominal(o, d) {
				t.Fatalf("maxDays %d: jour %d absent de la baseline", tc.maxDays, d)
			}
		}
	}
}

// Un jour n'a qu'un nom admis : un nom à zéro de tête, non décimal ou hors
// uint32 est écarté avant la sélection des K jours ; un nom canonique dont
// l'en-tête porte un autre jour occupe sa place parmi les K jours, comme une
// tranche illisible, mais n'apporte aucune entrée.
func TestBuildServerBaseline_NonCanonicalDayNamesSkipped(t *testing.T) {
	dir := t.TempDir()
	silo := p0Silo(t, dir)
	good := p0Snap(10*86400+60, 1, engine.SeverityLow, 990)
	v3WriteDay(t, dir, 10*86400, engine.OracleVersion, 0, good)
	stray := v3WriteDay(t, dir, 9*86400, engine.OracleVersion, 0, p0Snap(9*86400+60, 2, engine.SeverityLow, 990))
	if err := os.Remove(p0DayPath(dir, 9*86400)); err != nil {
		t.Fatal(err)
	}
	prefix := fmt.Sprintf("oracle_%016x_", uint64(p0MachineID))
	for _, name := range []string{"009", "+9", "0x9", "", "4294967296"} {
		if err := os.WriteFile(filepath.Join(dir, prefix+name+".c2oracle"), stray, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	o, err := silo.BuildServerBaseline(1)
	if err != nil {
		t.Fatal(err)
	}
	var code [8]uint64
	engine.VectorizeServerHealthLocality(&good, &code)
	if ok, _, _, _ := o.QueryStateLocality(&code, engine.DefaultLocalityThresholds()); o.Len() != 1 || !ok {
		t.Fatalf("baseline: %d entrees, jour 10 nominal %v", o.Len(), ok)
	}
	if err := os.WriteFile(filepath.Join(dir, prefix+"11.c2oracle"), stray, 0o644); err != nil {
		t.Fatal(err)
	}
	if o, _ = silo.BuildServerBaseline(0); o.Len() != 1 {
		t.Fatalf("tous les jours: %d entrees, attendu 1 (en-tete du jour 9 sous le nom 11)", o.Len())
	}
}

// linkRefused simule un système de fichiers sans liens durs le temps d'un test.
func linkRefused(t *testing.T, errno syscall.Errno) {
	t.Helper()
	prev := linkFile
	linkFile = func(oldname, newname string) error {
		return &os.LinkError{Op: "link", Old: oldname, New: newname, Err: errno}
	}
	t.Cleanup(func() { linkFile = prev })
}

// sealLegacy scelle un jour dont la tranche existante est en version 2.
func sealLegacy(t *testing.T, dir string) (path string, legacy []byte, err error) {
	t.Helper()
	path = p0DayPath(dir, p0DayA)
	legacy = v3WriteDay(t, dir, p0DayA-600, engine.OracleVersionLegacy, 0, p0Snap(p0DayA-600, 1, engine.SeverityLow, 990))
	silo := p0Silo(t, dir)
	p0Ingest(t, silo, p0Snap(p0DayA, 3, engine.SeverityLow, 990))
	return path, legacy, silo.SealDay(p0DayA + 60)
}

func noTempLeft(t *testing.T, dir string) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.Contains(e.Name(), ".tmp-") {
			t.Fatalf("fichier temporaire laisse: %s", e.Name())
		}
	}
}

// Finding F_DS_03 : sans lien dur possible, l'archive v2 devient une copie
// atomique et le scellement aboutit.
func TestArchiveLegacyDay_CopyFallback(t *testing.T) {
	for _, errno := range []syscall.Errno{syscall.EPERM, syscall.EXDEV, syscall.EMLINK, syscall.ENOTSUP} {
		t.Run(errno.Error(), func(t *testing.T) {
			linkRefused(t, errno)
			dir := t.TempDir()
			path, legacy, err := sealLegacy(t, dir)
			if err != nil {
				t.Fatalf("SealDay sans lien dur: %v", err)
			}
			archived, err := os.ReadFile(path + ".v2")
			if err != nil || !bytes.Equal(archived, legacy) {
				t.Fatalf("copie d'archive absente ou alteree: %v", err)
			}
			if hdr, entries := p0LoadDay(t, dir, p0DayA); hdr.Version != engine.OracleVersion || len(entries) != 1 {
				t.Fatalf("tranche v3: version %d, %d entrees", hdr.Version, len(entries))
			}
			noTempLeft(t, dir)
		})
	}
}

// Une copie d'archive identique laissée par un scellement interrompu est
// admise, qu'on retente le lien (EEXIST) ou la copie.
func TestArchiveLegacyDay_IdenticalCopyAdmitted(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		t.Run(fmt.Sprintf("lien_refuse=%v", refuse), func(t *testing.T) {
			if refuse {
				linkRefused(t, syscall.EPERM)
			}
			dir := t.TempDir()
			path := p0DayPath(dir, p0DayA)
			legacy := v3WriteDay(t, dir, p0DayA-600, engine.OracleVersionLegacy, 0, p0Snap(p0DayA-600, 1, engine.SeverityLow, 990))
			if err := os.WriteFile(path+".v2", legacy, 0o644); err != nil {
				t.Fatal(err)
			}
			silo := p0Silo(t, dir)
			p0Ingest(t, silo, p0Snap(p0DayA, 3, engine.SeverityLow, 990))
			if err := silo.SealDay(p0DayA + 60); err != nil {
				t.Fatalf("copie identique refusee: %v", err)
			}
		})
	}
}

// Une archive distincte déjà présente reste refusée sur le chemin de copie :
// ni elle ni la tranche v2 ne sont écrasées.
func TestArchiveLegacyDay_CopyFallbackRefusesForeignArchive(t *testing.T) {
	linkRefused(t, syscall.EPERM)
	dir := t.TempDir()
	path := p0DayPath(dir, p0DayA)
	legacy := v3WriteDay(t, dir, p0DayA, engine.OracleVersionLegacy, 0, p0Snap(p0DayA, 1, engine.SeverityLow, 990))
	// Même taille que la tranche, contenu différent.
	other := bytes.Repeat([]byte{0xA5}, len(legacy))
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
	noTempLeft(t, dir)
}
