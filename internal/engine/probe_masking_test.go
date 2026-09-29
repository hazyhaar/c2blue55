// Package engine — probe_masking_test.go
// La sonde conforme L1a embarquée peut conclure « bénin confirmé » et sortir
// de la cascade avant L1b. Sur netrack_dns/validate.csv, avant que cette
// confirmation soit subordonnée au voisinage des centroïdes d'attaque, 621
// domaines tuns.org et 41 domaines example.org hostiles étaient ainsi laissés
// passer alors que L1b seule les bloquait (mesure du 2026-09-29). Ce test
// compare, domaine par domaine, la cascade avec et sans sonde.
package engine

import (
	"encoding/csv"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInferenceCascade_ProbeNeverMasksL1bVeto(t *testing.T) {
	dataDir := testWittgensteinDataDir(t)
	f, err := os.Open(filepath.Join(dataDir, "netrack_dns", "validate.csv"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(f).ReadAll()
	f.Close()
	if err != nil {
		t.Fatal(err)
	}

	evaluate := func(withProbe bool) []CascadeVerdict {
		ce := NewCascadeEngine(NewCodebook(nil), NewGrayZoneDecider(DefaultGrayZoneConfig()))
		d, err := LoadFloppyMmap(filepath.Join(dataDir, "floppies", "floppy_dns_c2.c2book"), WittgensteinFloppyKey(FloppyFamilyDNSC2))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { d.Close() })
		if d.Probe() == nil {
			t.Fatal("la disquette DNS n'embarque pas de sonde L1a")
		}
		if !withProbe {
			d.probe = nil
		}
		ce.MountFloppy(FloppyFamilyDNSC2, d)
		pool := NewArenaPool()
		ce.arena = pool
		out := make([]CascadeVerdict, len(rows))
		for i, r := range rows {
			var ev Probe_event_t
			ev.Subsystem, ev.Action = 3, 3
			pool.StorePayload(&ev, []byte(strings.TrimSpace(r[1])))
			out[i] = ce.EvaluateEvent(&ev)
		}
		return out
	}
	with, without := evaluate(true), evaluate(false)

	masked := 0
	var benignQuarWith, benignQuarWithout, benign int
	for i, r := range rows {
		if strings.TrimSpace(r[0]) == "0" {
			benign++
			if with[i].Action == VerdictQuarantine {
				benignQuarWith++
			}
			if without[i].Action == VerdictQuarantine {
				benignQuarWithout++
			}
			continue
		}
		if without[i].Action == VerdictBlock && with[i].Action == VerdictPass {
			masked++
			if masked <= 5 {
				t.Logf("veto L1b masqué par L1a : %q", r[1])
			}
		}
	}
	t.Logf("quarantaine bénigne : %d/%d avec sonde, %d/%d sans sonde", benignQuarWith, benign, benignQuarWithout, benign)
	if masked != 0 {
		t.Fatalf("%d domaines C2 bloqués par L1b seule sont laissés passer par la confirmation L1a", masked)
	}
}
