package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55"
)

const b64Dense = `H4sICAAAAAAAAA+1Uy2rDMBD8F4m9xLIkW7Z8yKEldA9tD33YQ2QjIVmyZUluQv69K+m2hBJaQqEH3oVd7c7uzM5qJ0nS5Jw5Z5xL0iYkZcY5yTnlnHHOGWecS84F51xwLjjnnHPOS6+8Cq+CG+GNcCq8Cq+CG+GNcCq8Cq+CG+GNcCq8Cq+CG+GNcCq8Cq+CG+GNcCq8Cq+CG+GNcCq8Cq+CG+GNcCq8Cq+CG+GNcCq8Cq+CG+GNcCq8Cq+CG+GNcCq8Cq+CG+GNcCq8Cq+CG+GNcCq8=`

func TestWittgensteinEndToEnd(t *testing.T) {
	c2blue55.RegisterToolGrammar("read_file", []byte(`{"path":"/workspace/src/main.go"}`), 0x0001, 64)

	healthy := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path": "/etc/hosts"}}}`)
	fwd, veto, inc := FilterLine(healthy)
	if !fwd || veto != nil || inc != nil {
		t.Fatalf("épreuve saine: forward=%v veto=%s incident=%v", fwd, veto, inc)
	}

	hostileB64 := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"` + b64Dense + `"}}}`)
	fwd, veto, inc = FilterLine(hostileB64)
	if fwd {
		t.Fatal("épreuve Base64: forward=true, want false")
	}
	if len(veto) == 0 {
		t.Fatal("épreuve Base64: veto vide")
	}
	if !bytes.Contains(veto, []byte(`"code":-32003`)) || !bytes.Contains(veto, []byte("C2BLUE_VETO")) {
		t.Fatalf("épreuve Base64: veto=%s", veto)
	}
	assertVetoRPC(t, veto, 2, "read_file")
	if inc != nil {
		t.Fatal("grammar divergence must not fabricate a forensic dossier")
	}

	elfArgs := []byte(`{"path":"\u007fELF\u0002\u0001\u0001\u0000"}`)
	elfLine := make([]byte, 0, 160)
	elfLine = append(elfLine, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_file","arguments":`...)
	elfLine = append(elfLine, elfArgs...)
	elfLine = append(elfLine, `}}`...)
	fwd, veto, inc = FilterLine(elfLine)
	if fwd || len(veto) == 0 || !bytes.Contains(veto, []byte(`"code":-32003`)) {
		t.Fatalf("épreuve ELF: forward=%v veto=%s", fwd, veto)
	}
	assertVetoRPC(t, veto, 3, "read_file")
	if inc != nil {
		t.Fatal("unexpected dossier")
	}

	notif := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"` + b64Dense + `"}}}`)
	fwd, veto, inc = FilterLine(notif)
	if fwd {
		t.Fatal("notification: forward=true, want false")
	}
	if veto != nil {
		t.Fatalf("notification: veto=%s, want nil", veto)
	}
	if inc != nil {
		t.Fatal("unexpected dossier")
	}

	assertRelayPipes(t, healthy, hostileB64)
}

func assertVetoRPC(t *testing.T, raw []byte, wantID int, wantTool string) {
	t.Helper()
	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Data    struct {
				Tool  string `json:"tool"`
				DjsQ8 uint32 `json:"djs_q8"`
			} `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("veto json: %v (%s)", err, raw)
	}
	if resp.JSONRPC != "2.0" {
		t.Fatalf("jsonrpc=%q", resp.JSONRPC)
	}
	if resp.Error.Code != -32003 {
		t.Fatalf("code=%d", resp.Error.Code)
	}
	if !bytes.Contains([]byte(resp.Error.Message), []byte("C2BLUE_VETO")) {
		t.Fatalf("message=%q", resp.Error.Message)
	}
	if resp.Error.Data.Tool != wantTool {
		t.Fatalf("tool=%q want %q", resp.Error.Data.Tool, wantTool)
	}
	var id int
	if err := json.Unmarshal(resp.ID, &id); err != nil || id != wantID {
		t.Fatalf("id=%s want %d (%v)", resp.ID, wantID, err)
	}
}

func assertRelayPipes(t *testing.T, healthy, hostile []byte) {
	t.Helper()
	guardIn, clientW := io.Pipe()
	clientR, guardOut := io.Pipe()
	backendR, backIn := io.Pipe()
	backOut, backendW := io.Pipe()

	errCh := make(chan error, 1)
	go func() {
		errCh <- RunRelay(guardIn, guardOut, backIn, backOut)
	}()

	backendGot := make(chan []byte, 1)
	go func() {
		sc := bufio.NewScanner(backendR)
		if sc.Scan() {
			line := append([]byte(nil), sc.Bytes()...)
			backendGot <- line
			_, _ = backendW.Write(line)
			_, _ = backendW.Write(nl)
		}
		// Model normal child shutdown: output EOF follows consumed input EOF.
		for sc.Scan() {
		}
		_ = backendW.Close()
	}()

	clientGot := make(chan []byte, 2)
	go func() {
		sc := bufio.NewScanner(clientR)
		for sc.Scan() {
			clientGot <- append([]byte(nil), sc.Bytes()...)
		}
	}()

	if _, err := clientW.Write(append(append([]byte(nil), healthy...), '\n')); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-backendGot:
		if !bytes.Equal(got, healthy) {
			t.Fatalf("backend=%s want %s", got, healthy)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout forward sain")
	}
	select {
	case got := <-clientGot:
		if !bytes.Equal(got, healthy) {
			t.Fatalf("echo=%s", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout echo backend")
	}

	if _, err := clientW.Write(append(append([]byte(nil), hostile...), '\n')); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-clientGot:
		if !bytes.Contains(got, []byte(`-32003`)) || !bytes.Contains(got, []byte("C2BLUE_VETO")) {
			t.Fatalf("veto fil=%s", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout veto fil")
	}

	_ = clientW.Close()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("RunRelay: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunRelay n'est pas revenu")
	}
}
