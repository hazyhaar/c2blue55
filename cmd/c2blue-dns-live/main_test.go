package main_test

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestCommandHelpExposesLiveServiceConfiguration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "run", ".", "-help")
	command.Env = append(os.Environ(), "GOEXPERIMENT=simd")
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("go run . -help a dépassé 30 s: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("go run . -help: %v\n%s", err, output)
	}
	text := string(output)
	for _, required := range []string{"-udp-listen", "-http-listen", "-evidence-dir", "C2BLUE_DASHBOARD_TOKEN"} {
		if !strings.Contains(text, required) {
			t.Errorf("aide de c2blue-dns-live: %q absent\n%s", required, text)
		}
	}
}
