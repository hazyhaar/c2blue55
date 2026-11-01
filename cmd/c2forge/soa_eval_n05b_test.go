package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Strate N-05b : sous-commande `c2forge soa-eval -pcap <capture> -report <json>`
// qui appelle c2blue55.EvaluateSOANegativePCAP, écrit le rapport JSON et
// imprime une ligne de compteurs. Oracle sur la capture réelle de la campagne
// du 2026-10-29 (Run-A : 200 réponses négatives, 198 feux, premier feu au 6e
// paquet), retrouvée par remontée vers wittgenstein/redhost_lab/n04-20261029.

func n05bCapture(t *testing.T, name string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for range 6 {
		candidate := filepath.Join(dir, "wittgenstein", "redhost_lab", "n04-20261029", name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
		dir = filepath.Dir(dir)
	}
	t.Fatalf("capture %s introuvable en remontant depuis le répertoire de test", name)
	return ""
}

func TestSOAEval_RunAReportAndLine(t *testing.T) {
	pcap := n05bCapture(t, "n04-runA-stego-v2.pcap")
	report := filepath.Join(t.TempDir(), "runA.json")
	var out bytes.Buffer
	code, err := runSOAEval([]string{"-pcap", pcap, "-report", report}, &out)
	if err != nil || code != 0 {
		t.Fatalf("soa-eval : code=%d err=%v", code, err)
	}
	ligne := strings.TrimSpace(out.String())
	champs := strings.Fields(ligne)
	// <pcap> responses negativeWithSOA fires firedKeys packetsToFirstFire firstFireTsNs
	if len(champs) != 7 || champs[0] != pcap || champs[1] != "200" || champs[2] != "200" || champs[3] != "198" || champs[4] != "1" || champs[5] != "6" {
		t.Errorf("ligne = %q, attendu <pcap> 200 200 198 1 6 <ts>", ligne)
	}
	raw, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var rep struct {
		PCAP               string `json:"pcap"`
		SHA256             string `json:"sha256"`
		Responses          uint32 `json:"responses"`
		NegativeWithSOA    uint32 `json:"negative_with_soa"`
		Fires              uint32 `json:"fires"`
		FiredKeys          uint32 `json:"fired_keys"`
		PacketsToFirstFire uint32 `json:"packets_to_first_fire"`
		FirstFireTsNs      uint64 `json:"first_fire_ts_ns"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatalf("rapport JSON : %v", err)
	}
	if rep.PCAP != pcap || len(rep.SHA256) != 64 || rep.Responses != 200 || rep.NegativeWithSOA != 200 || rep.Fires != 198 || rep.FiredKeys != 1 || rep.PacketsToFirstFire != 6 || rep.FirstFireTsNs == 0 {
		t.Errorf("rapport = %+v", rep)
	}
}

func TestSOAEval_BenignRunNoFire(t *testing.T) {
	pcap := n05bCapture(t, "n04-benin-soa-v2.pcap")
	report := filepath.Join(t.TempDir(), "benin.json")
	var out bytes.Buffer
	code, err := runSOAEval([]string{"-pcap", pcap, "-report", report}, &out)
	if err != nil || code != 0 {
		t.Fatalf("soa-eval : code=%d err=%v", code, err)
	}
	champs := strings.Fields(out.String())
	if len(champs) != 7 || champs[1] != "100" || champs[2] != "100" || champs[3] != "0" || champs[4] != "0" || champs[5] != "0" {
		t.Errorf("ligne = %q, attendu <pcap> 100 100 0 0 0 0", strings.TrimSpace(out.String()))
	}
}

func TestSOAEval_Refusals(t *testing.T) {
	var out bytes.Buffer
	if code, err := runSOAEval([]string{"-pcap", "/nonexistent.pcap", "-report", filepath.Join(t.TempDir(), "r.json")}, &out); code == 0 || err == nil {
		t.Errorf("capture absente : code=%d err=%v, attendu code != 0", code, err)
	}
	if code, err := runSOAEval([]string{"-pcap", "x.pcap"}, &out); code != 2 || err == nil {
		t.Errorf("sans -report : code=%d err=%v, attendu 2", code, err)
	}
	if code, err := runSOAEval([]string{"-pcap", "x.pcap", "-report", "r.json", "extra"}, &out); code != 2 || err == nil {
		t.Errorf("argument surnuméraire : code=%d err=%v, attendu 2", code, err)
	}
}
