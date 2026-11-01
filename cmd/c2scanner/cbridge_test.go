package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	c2blue55 "github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

func TestCbridgeActualHammingDistance(t *testing.T) {
	cb, err := engine.LoadCodebook(filepath.Join(testRequireExternal(t, "HOROS_DATA_DIR", "data"), "vuln_corpora", "patterns_code_flaws.c2book"))
	if err != nil {
		t.Fatalf("LoadCodebook: %v", err)
	}

	path := filepath.Join(testRequireExternal(t, "HOROS_AUDITS_DIR", "audits"), "cbridge-node", "server", "server.go")
	sourceBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	needle := "p := uint64(1)"
	idx := strings.Index(string(sourceBytes), needle)
	if idx < 0 {
		t.Fatalf("needle introuvable dans %s", path)
	}

	t.Logf("Trouvé needle '%s' à l'offset %d dans %s", needle, idx, path)

	var vec [engine.EmbeddingDim]float32
	var code [bitcodeWords]uint64
	var ev c2blue55.Event
	ev.Subsystem = c2blue55.SubFile
	ev.Action = c2blue55.ActRead

	bestDist := 512
	bestThreat := uint32(0)
	bestOffset := -1

	for off := idx - 48; off <= idx+48; off++ {
		if off < 0 || off+96 > len(sourceBytes) {
			continue
		}
		copy(ev.Payload[:], sourceBytes[off:off+96])

		if !engine.ExtractTo(&ev, vec[:]) {
			continue
		}
		engine.Quantize512(vec[:], &code)

		match, dist, found := cb.SearchNearest(&code, 512)
		if found && dist < bestDist {
			bestDist = dist
			bestThreat = match.ThreatID
			bestOffset = off
			t.Logf("Offset %d: best match ThreatID 0x%X, distance = %d/512 (%.1f%% similarité)",
				off, match.ThreatID, dist, 100.0*(1.0-float64(dist)/512.0))
		}
	}

	t.Logf("RÉSULTAT FINAL: Distance minimale = %d (ThreatID 0x%X) à l'offset %d", bestDist, bestThreat, bestOffset)
}

func TestPbBridgeActualHammingDistance(t *testing.T) {
	cb, err := engine.LoadCodebook(filepath.Join(testRequireExternal(t, "HOROS_DATA_DIR", "data"), "vuln_corpora", "patterns_code_flaws.c2book"))
	if err != nil {
		t.Fatalf("LoadCodebook: %v", err)
	}

	path := filepath.Join(testRequireExternal(t, "HOROS_AUDITS_DIR", "audits"), "sgn-v2-contracts", "contracts", "libraries", "PbBridge.sol")
	contractBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	needle := "buf.decKey()"
	idx := strings.Index(string(contractBytes), needle)
	if idx < 0 {
		t.Fatalf("needle introuvable dans %s", path)
	}

	t.Logf("Trouvé needle '%s' à l'offset %d dans %s", needle, idx, path)

	var vec [engine.EmbeddingDim]float32
	var code [bitcodeWords]uint64
	var ev c2blue55.Event
	ev.Subsystem = c2blue55.SubNet
	ev.Action = c2blue55.ActConnect

	bestDist := 512
	bestThreat := uint32(0)
	bestOffset := -1

	for off := idx - 48; off <= idx+48; off++ {
		if off < 0 || off+96 > len(contractBytes) {
			continue
		}
		copy(ev.Payload[:], contractBytes[off:off+96])

		if !engine.ExtractTo(&ev, vec[:]) {
			continue
		}
		engine.Quantize512(vec[:], &code)

		match, dist, found := cb.SearchNearest(&code, 512)
		if found && dist < bestDist {
			bestDist = dist
			bestThreat = match.ThreatID
			bestOffset = off
			t.Logf("Offset %d: best match ThreatID 0x%X, distance = %d/512 (%.1f%% similarité)",
				off, match.ThreatID, dist, 100.0*(1.0-float64(dist)/512.0))
		}
	}

	t.Logf("RÉSULTAT FINAL PbBridge: Distance minimale = %d (ThreatID 0x%X) à l'offset %d", bestDist, bestThreat, bestOffset)
}

