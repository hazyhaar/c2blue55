package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55"
)

func TestGuardExecutableDefaultCatalog(t *testing.T) {
	if mode := os.Getenv("C2BLUE_GUARD_TEST_CHILD"); mode != "" {
		if mode == "full" {
			for i := 0; i < 32; i++ {
				if err := c2blue55.RegisterToolGrammar(fmt.Sprintf("full_%d", i), []byte("sample"), 1, 64); err != nil {
					panic(err)
				}
			}
		}
		os.Args = []string{"guard", "-cmd", "/bin/cat"}
		if mode == "stall" {
			os.Args = []string{"guard", "-cmd", "/bin/sh", "--", "-c", "sleep 30"}
		}
		flag.CommandLine = flag.NewFlagSet("guard", flag.ExitOnError)
		main()
		os.Exit(0)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGuardExecutableDefaultCatalog$")
	child.Env = append(os.Environ(), "C2BLUE_GUARD_TEST_CHILD=1")
	child.Stdin = bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unregistered","arguments":{}}}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}` + "\n")
	var stderr bytes.Buffer
	child.Stderr = &stderr
	output, err := child.Output()
	if err != nil {
		t.Fatalf("executable: %v %s", err, stderr.String())
	}
	if !bytes.Contains(output, []byte("C2BLUE_VETO")) || !bytes.Contains(output, []byte(`"path":"/etc/hosts"`)) {
		t.Fatalf("catalog/recovery: %s", output)
	}
	if !bytes.Contains(output, []byte(`"code":-32601`)) {
		t.Fatalf("unknown tool refusal is not explicit: %s", output)
	}
	full := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGuardExecutableDefaultCatalog$")
	full.Env = append(os.Environ(), "C2BLUE_GUARD_TEST_CHILD=full")
	failed, err := full.CombinedOutput()
	if err == nil || !bytes.Contains(failed, []byte("catalogue:")) {
		t.Fatalf("catalogue failure: %v %s", err, failed)
	}
	stall := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGuardExecutableDefaultCatalog$")
	stall.Env = append(os.Environ(), "C2BLUE_GUARD_TEST_CHILD=stall")
	failed, err = stall.CombinedOutput()
	if err == nil || !bytes.Contains(failed, []byte("backend output did not close")) {
		t.Fatalf("stalled child shutdown: %v %s", err, failed)
	}
}

func TestStrictJSONThenNominal(t *testing.T) {
	if err := loadDefaultCatalog(); err != nil {
		t.Fatal(err)
	}
	bad := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools\/call","params":{"name":"read_file","arguments":{"path":"` + b64Dense + `"}}}`,
		`{"jsonrpc":"2.0","id":1,"metho\u0064":"tools/call","params":{"na\u006de":"unknown","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call","params":{"name":"read_file","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"a","pa\u0074h":"b"}}}`,
		`{"jsonrpc":"2.0","id":1,"Method":"tools/call","params":{"name":"read_file","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unknown","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{},}}`,
		`{"jsonrpc":"2.0","id":{},"method":"ping"}`,
		`{"jsonrpc":"2.0","method":"ping"} {}`,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"read_file","arguments":{"path":"\q"}}}`,
	}
	good := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools\/call","params":{"name":"read_file","arguments":{"path":"/etc/hosts"}}}`)
	for _, line := range bad {
		fwd, veto, dossier := FilterLine([]byte(line))
		if fwd || !json.Valid(veto) || dossier != nil {
			t.Fatalf("accepted/invalid veto: %s -> %v %s", line, fwd, veto)
		}
		if fwd, veto, _ := FilterLine(good); !fwd || veto != nil {
			t.Fatalf("nominal recovery failed: %s", veto)
		}
	}
}

func TestFragmentedBackendSerializesWholeLines(t *testing.T) {
	reader, writer := io.Pipe()
	var output bytes.Buffer
	var mu sync.Mutex
	done := make(chan error, 1)
	go func() { done <- copyLocked(&mu, &output, reader) }()
	_, _ = writer.Write([]byte(`{"jsonrpc":"2.0","id":9,`))
	mu.Lock()
	output.WriteString("{\"veto\":true}\n")
	mu.Unlock()
	_, _ = writer.Write([]byte("\"result\":{}}\n"))
	_ = writer.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, line := range bytes.Split(bytes.TrimSpace(output.Bytes()), []byte{'\n'}) {
		if !json.Valid(line) {
			t.Fatalf("interleaved line: %s", line)
		}
	}
}

func TestBackendExitUnblocksInput(t *testing.T) {
	in, writer := io.Pipe()
	defer writer.Close()
	done := make(chan error, 1)
	go func() { done <- RunRelay(in, io.Discard, io.Discard, bytes.NewReader(nil)) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unexpected EOF must be visible")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked on input after child exit")
	}
}
