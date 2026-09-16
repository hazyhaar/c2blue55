package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hazyhaar/c2slm"
)

func TestRegisterDefenseTools(t *testing.T) {
	reg := c2slm.NewToolRegistry()
	d, err := RegisterDefenseTools(reg, "")
	if err != nil {
		t.Fatalf("RegisterDefenseTools: %v", err)
	}
	if d == nil {
		t.Fatal("DefenseTools nil")
	}
	if reg.Len() != 3 {
		t.Fatalf("Len = %d, attendu 3", reg.Len())
	}
	names := map[string]bool{}
	for _, def := range reg.Definitions() {
		names[def.Name] = true
		if len(def.Parameters) == 0 {
			t.Errorf("outil %s sans schéma de paramètres", def.Name)
		}
	}
	for _, want := range []string{"inspect_socket", "inspect_proc", "ban_ip"} {
		if !names[want] {
			t.Errorf("outil %s non enregistré", want)
		}
	}
	block := reg.SystemToolsBlock()
	if !strings.Contains(block, "# Tools") || !strings.Contains(block, "inspect_socket") {
		t.Errorf("bloc outils incomplet:\n%s", block)
	}
}

func TestInspectProcSelf(t *testing.T) {
	d := NewDefenseTools("")
	args, _ := json.Marshal(map[string]int{"pid": os.Getpid()})
	raw, err := d.InspectProc(args)
	if err != nil {
		t.Fatalf("InspectProc: %v", err)
	}
	var res inspectProcResult
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if res.PID != os.Getpid() {
		t.Fatalf("PID = %d", res.PID)
	}
	if res.Comm == "" && res.Cmdline == "" {
		t.Fatalf("comm et cmdline vides: %+v", res)
	}
	if res.ExeSHA256 == "" && res.ExeHashNote == "" {
		t.Fatalf("aucune empreinte ni note: %+v", res)
	}
	if res.ExeSHA256 != "" && len(res.ExeSHA256) != 64 {
		t.Fatalf("empreinte SHA-256 de longueur %d", len(res.ExeSHA256))
	}
}

func TestInspectProcErrors(t *testing.T) {
	d := NewDefenseTools("")
	if _, err := d.InspectProc(json.RawMessage(`{"pid":0}`)); err == nil {
		t.Fatal("pid 0 devait être refusé")
	}
	// Un PID très improbable : processus absent.
	if _, err := d.InspectProc(json.RawMessage(`{"pid":2147483647}`)); err == nil {
		t.Fatal("un processus inexistant devait produire une erreur")
	}
	if _, err := d.InspectProc(json.RawMessage(`{`)); err == nil {
		t.Fatal("arguments malformés devaient être refusés")
	}
}

func TestInspectSocketSelf(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()
	port := conn.LocalAddr().(*net.UDPAddr).Port

	d := NewDefenseTools("")
	args, _ := json.Marshal(map[string]int{"port": port})
	raw, err := d.InspectSocket(args)
	if err != nil {
		t.Fatalf("InspectSocket: %v", err)
	}
	var res inspectSocketResult
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if res.Port != port {
		t.Fatalf("port = %d", res.Port)
	}
	if len(res.Matches) == 0 {
		t.Fatalf("aucun socket trouvé pour le port %d: %+v", port, res)
	}
	found := false
	for _, m := range res.Matches {
		for _, pid := range m.PIDs {
			if pid == os.Getpid() {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("le processus courant n'a pas été associé au socket: %+v", res.Matches)
	}
}

func TestInspectSocketValidation(t *testing.T) {
	d := NewDefenseTools("")
	if _, err := d.InspectSocket(json.RawMessage(`{"port":0}`)); err == nil {
		t.Fatal("port 0 devait être refusé")
	}
	if _, err := d.InspectSocket(json.RawMessage(`{"port":70000}`)); err == nil {
		t.Fatal("port hors bornes devait être refusé")
	}
}

func TestParseProcNetAddr(t *testing.T) {
	ip, port, err := parseProcNetAddr("0100007F:0035")
	if err != nil || ip != "127.0.0.1" || port != 53 {
		t.Fatalf("v4 = %q:%d err=%v", ip, port, err)
	}
	ip, port, err = parseProcNetAddr("00000000000000000000000001000000:0035")
	if err != nil || ip != "::1" || port != 53 {
		t.Fatalf("v6 = %q:%d err=%v", ip, port, err)
	}
	if _, _, err := parseProcNetAddr("garbage"); err == nil {
		t.Fatal("adresse malformée acceptée")
	}
}

func TestBanIPJournalChain(t *testing.T) {
	dir := t.TempDir()
	journal := filepath.Join(dir, "blocks.jsonl")
	d := NewDefenseTools(journal)

	first, err := d.BanIP(json.RawMessage(`{"ip":"10.0.0.1","duration_seconds":60}`))
	if err != nil {
		t.Fatalf("premier ban: %v", err)
	}
	var r1 banIPResult
	if err := json.Unmarshal([]byte(first), &r1); err != nil {
		t.Fatalf("JSON 1: %v", err)
	}
	if !r1.Banned || r1.Applied {
		t.Fatalf("état inattendu: %+v", r1)
	}
	if !strings.Contains(r1.NFTRule, "10.0.0.1") || !strings.Contains(r1.NFTRule, "timeout 60s") {
		t.Fatalf("règle nftables = %q", r1.NFTRule)
	}
	if len(r1.EntryHash) != 64 {
		t.Fatalf("empreinte invalide: %q", r1.EntryHash)
	}

	second, err := d.BanIP(json.RawMessage(`{"ip":"10.0.0.2","duration_seconds":120}`))
	if err != nil {
		t.Fatalf("second ban: %v", err)
	}
	var r2 banIPResult
	if err := json.Unmarshal([]byte(second), &r2); err != nil {
		t.Fatalf("JSON 2: %v", err)
	}
	if r2.PrevHash != r1.EntryHash {
		t.Fatalf("chaîne rompue: prev=%q attendu=%q", r2.PrevHash, r1.EntryHash)
	}
	if r2.EntryHash == r1.EntryHash {
		t.Fatal("deux entrées partagent la même empreinte")
	}

	// Le journal doit contenir deux lignes JSON valides et chaînées.
	data, err := os.ReadFile(journal)
	if err != nil {
		t.Fatalf("lecture journal: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lignes dans le journal, attendu 2", len(lines))
	}
	var e1, e2 banJournalEntry
	json.Unmarshal([]byte(lines[0]), &e1)
	json.Unmarshal([]byte(lines[1]), &e2)
	if e2.PrevHash != e1.Hash || e1.PrevHash != "" {
		t.Fatalf("chaîne journal incorrecte: e1.prev=%q e2.prev=%q e1.hash=%q", e1.PrevHash, e2.PrevHash, e1.Hash)
	}
}

func TestBanIPChainRecovery(t *testing.T) {
	dir := t.TempDir()
	journal := filepath.Join(dir, "blocks.jsonl")

	d1 := NewDefenseTools(journal)
	out, err := d1.BanIP(json.RawMessage(`{"ip":"192.168.1.5","duration_seconds":30}`))
	if err != nil {
		t.Fatalf("ban initial: %v", err)
	}
	var r1 banIPResult
	json.Unmarshal([]byte(out), &r1)

	// Une nouvelle instance doit reprendre le dernier maillon du journal.
	d2 := NewDefenseTools(journal)
	out2, err := d2.BanIP(json.RawMessage(`{"ip":"192.168.1.6","duration_seconds":30}`))
	if err != nil {
		t.Fatalf("ban repris: %v", err)
	}
	var r2 banIPResult
	json.Unmarshal([]byte(out2), &r2)
	if r2.PrevHash != r1.EntryHash {
		t.Fatalf("reprise de chaîne: prev=%q attendu=%q", r2.PrevHash, r1.EntryHash)
	}
}

func TestBanIPValidation(t *testing.T) {
	d := NewDefenseTools("")
	cases := []string{
		`{"ip":"not-an-ip","duration_seconds":10}`,
		`{"ip":"10.0.0.1","duration_seconds":0}`,
		`{"duration_seconds":10}`,
		`{`,
	}
	for _, c := range cases {
		if _, err := d.BanIP(json.RawMessage(c)); err == nil {
			t.Errorf("entrée %s devait être refusée", c)
		}
	}

	// La variante camelCase est tolérée.
	if _, err := d.BanIP(json.RawMessage(`{"ip":"10.0.0.9","durationSeconds":5}`)); err != nil {
		t.Errorf("durationSeconds camelCase refusé: %v", err)
	}
}
