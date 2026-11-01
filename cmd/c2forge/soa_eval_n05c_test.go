package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSOAEval_ReportWrittenAtomicallyMode0600(t *testing.T) {
	pcap := n05bCapture(t, "n04-benin-soa-v2.pcap")
	dir := t.TempDir()
	report := filepath.Join(dir, "rapport.json")
	var out bytes.Buffer
	if code, err := runSOAEval([]string{"-pcap", pcap, "-report", report}, &out); err != nil || code != 0 {
		t.Fatalf("soa-eval : code=%d err=%v", code, err)
	}
	info, err := os.Stat(report)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode du rapport = %o, attendu 600", info.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != "rapport.json" {
			t.Errorf("fichier résiduel dans le répertoire du rapport : %s", e.Name())
		}
	}
	if !strings.Contains(out.String(), " 100 100 0 0 0 0") {
		t.Errorf("ligne = %q", strings.TrimSpace(out.String()))
	}
	// Répertoire de rapport absent : erreur rendue, aucun fichier créé.
	if code, err := runSOAEval([]string{"-pcap", pcap, "-report", filepath.Join(dir, "absent", "r.json")}, &out); code == 0 || err == nil {
		t.Errorf("répertoire absent : code=%d err=%v", code, err)
	}
}
