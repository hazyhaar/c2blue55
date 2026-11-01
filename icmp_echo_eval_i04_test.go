package c2blue55

import (
	"path/filepath"
	"testing"
)

// Strate I-04 (évaluateur) : EvaluateICMPEchoPCAP distingue les feux de parité
// (REASON_IC01) des feux « réponse non sollicitée » (REASON_IC02) ; Fires
// reste la somme, AsymmetricFires et UnsolicitedFires détaillent.
func TestEvaluateICMPEchoPCAP_UnsolicitedCounted(t *testing.T) {
	dir := t.TempDir()
	client, server := [4]byte{10, 55, 0, 2}, [4]byte{10, 55, 0, 1}
	payload := make([]byte, 28)
	var frames [][]byte
	var ts []uint64
	base := uint64(1_793_300_000_000_000)
	// Requête seq 0 + réponse identique ; puis deux réponses orphelines seq 2 et 3 (même identifiant).
	frames = append(frames, i03Frame(client, server, 8, 23475, 0, payload), i03Frame(server, client, 0, 23475, 0, payload),
		i03Frame(server, client, 0, 23475, 2, make([]byte, 228)), i03Frame(server, client, 0, 23475, 3, make([]byte, 228)))
	ts = append(ts, base, base+200, base+500_000, base+600_000)
	path := filepath.Join(dir, "orphan.pcap")
	n05WritePCAP(t, path, frames, ts)
	rep, err := EvaluateICMPEchoPCAP(path)
	if err != nil {
		t.Fatal(err)
	}
	if rep.EchoRequests != 1 || rep.EchoReplies != 3 || rep.Fires != 2 || rep.AsymmetricFires != 0 || rep.UnsolicitedFires != 2 || rep.PacketsToFirstFire != 3 {
		t.Errorf("rapport = %+v, attendu EchoRequests=1 EchoReplies=3 Fires=2 AsymmetricFires=0 UnsolicitedFires=2 PacketsToFirstFire=3", rep)
	}
}
