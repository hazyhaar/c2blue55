// Package c2blue55 — subsystems_test.go
// Validation unitaire des invariants de la Phase 1 :
// Unification des sous-systèmes, routage multicanal réel et régulation grayzone.
package c2blue55

import (
	"testing"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

func TestSubsystems_ValuesAndNames(t *testing.T) {
	if SubProc != 1 || SubFile != 2 || SubNet != 3 || SubMCP != 4 || SubHarness != 5 || SubEntropy != 6 || SubGPU != 7 {
		t.Fatalf("Invariants de sous-systèmes corrompus")
	}
	if SubMem != SubMCP {
		t.Fatalf("SubMem doit être un alias exact de SubMCP (4)")
	}

	names := map[uint16]string{
		SubProc:    "Process",
		SubFile:    "Filesystem",
		SubNet:     "Network",
		SubMCP:     "MCP-Agent",
		SubHarness: "Harness",
		SubEntropy: "Entropy",
		SubGPU:     "GPU",
	}
	for sub, want := range names {
		if got := SubsystemName(sub); got != want {
			t.Errorf("SubsystemName(%d) = %q, attendu %q", sub, got, want)
		}
	}
}

func TestSubsystems_OracleMapping(t *testing.T) {
	cases := []struct {
		sub       uint16
		oracleSub uint16
	}{
		{SubProc, engine.OracleSubProc},
		{SubFile, engine.OracleSubStorage},
		{SubNet, engine.OracleSubNet},
		{SubMCP, engine.OracleSubAgent},
		{SubHarness, engine.OracleSubService},
		{SubEntropy, engine.OracleSubKernel},
		{SubGPU, engine.OracleSubKernel},
	}
	for _, c := range cases {
		mapped := SubsystemToOracle(c.sub)
		if mapped != c.oracleSub {
			t.Errorf("SubsystemToOracle(%d) = %d, attendu %d", c.sub, mapped, c.oracleSub)
		}
		back := OracleToSubsystem(c.oracleSub)
		if back == 0 {
			t.Errorf("OracleToSubsystem(%d) a retourné 0", c.oracleSub)
		}
	}
}

func TestContext_InjectObservation_MultiChannel(t *testing.T) {
	ctx := NewContext(Config{})
	if err := ctx.Start(); err != nil {
		t.Fatal(err)
	}
	defer ctx.Stop()

	// Injecter 1 événement par sous-système
	evProc := Event{Subsystem: SubProc, Pid: 101}
	evFile := Event{Subsystem: SubFile, Pid: 102}
	evNet := Event{Subsystem: SubNet, Pid: 103}
	evMCP := Event{Subsystem: SubMCP, Pid: 104}

	if rc := ctx.InjectObservation(&evProc); rc != 0 {
		t.Fatalf("InjectObservation(Proc) = %d", rc)
	}
	if rc := ctx.InjectObservation(&evFile); rc != 0 {
		t.Fatalf("InjectObservation(File) = %d", rc)
	}
	if rc := ctx.InjectObservation(&evNet); rc != 0 {
		t.Fatalf("InjectObservation(Net) = %d", rc)
	}
	if rc := ctx.InjectObservation(&evMCP); rc != 0 {
		t.Fatalf("InjectObservation(MCP) = %d", rc)
	}

	// Relever par lot et vérifier la diversité des canaux reçus
	out := make([]Event, 10)
	n := ctx.PollBatch(out, 10)
	if n != 4 {
		t.Fatalf("PollBatch a relevé %d événements, attendu 4", n)
	}

	seen := make(map[uint16]bool)
	for i := 0; i < n; i++ {
		seen[out[i].Subsystem] = true
	}
	if !seen[SubProc] || !seen[SubFile] || !seen[SubNet] || !seen[SubMCP] {
		t.Fatalf("PollBatch n'a pas drainé les 4 canaux distincts : %+v", seen)
	}
}

func TestRouter_RingMCP_And_DropsUnknown(t *testing.T) {
	rt := NewRouter()

	evMCP := Event{Subsystem: SubMCP, Src: 42}
	if !rt.Dispatch(&evMCP) {
		t.Fatal("Dispatch(SubMCP) refusé")
	}
	if rt.RingMCP().Len() != 1 {
		t.Fatalf("RingMCP().Len() = %d, attendu 1", rt.RingMCP().Len())
	}
	if rt.RingMem().Len() != 1 {
		t.Fatalf("RingMem().Len() (alias) = %d, attendu 1", rt.RingMem().Len())
	}

	// Événement non routé (ex. SubGPU = 7)
	evGPU := Event{Subsystem: SubGPU, Src: 99}
	if rt.Dispatch(&evGPU) {
		t.Fatal("Dispatch(SubGPU) accepté par un routeur à 4 anneaux")
	}
	if rt.DropsUnknown() != 1 {
		t.Fatalf("DropsUnknown = %d, attendu 1", rt.DropsUnknown())
	}
}

func TestGrayzone_AntiBypass_Anonymous(t *testing.T) {
	cfg := engine.DefaultGrayZoneConfig()
	cfg.SourceMaxBurst = 3
	cfg.SourceRefillPerSec = 1
	gz := engine.NewGrayZoneDecider(cfg)

	// Consommer le quota anonyme (sourceID == 0)
	ontoKey := engine.PackOntoKey(engine.SubjUserInteractive, engine.ActExecve, engine.TgtTmpExec, engine.CtxInteractiveTTY)
	res1 := gz.DecideWithSource(nil, nil, ontoKey, 0)
	res2 := gz.DecideWithSource(nil, nil, ontoKey, 0)
	res3 := gz.DecideWithSource(nil, nil, ontoKey, 0)
	res4 := gz.DecideWithSource(nil, nil, ontoKey, 0)

	_ = res1
	_ = res2
	_ = res3
	if res4.Verdict != engine.CascadeSourceThrottled {
		t.Fatalf("La source anonyme (0) n'a pas été bridée après épuisement du quota unitaire : verdict=%d (attendu CascadeSourceThrottled=%d)",
			res4.Verdict, engine.CascadeSourceThrottled)
	}
}
