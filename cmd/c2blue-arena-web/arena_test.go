package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55"
)

func TestRealMetricsDashboard(t *testing.T) {
	t.Setenv("C2BLUE_DASHBOARD_TOKEN", "private-test-token")
	cpu := readCPUPercent()
	if cpu < 0 || cpu > 100 {
		t.Fatalf("readCPUPercent()=%v hors [0,100]", cpu)
	}
	cpu2 := readCPUPercent()
	if cpu2 < 0 || cpu2 > 100 {
		t.Fatalf("readCPUPercent() second=%v hors [0,100]", cpu2)
	}

	tot, used, pct := readMemInfo()
	if tot <= 0 || used < 0 || pct < 0 {
		t.Fatalf("readMemInfo() total=%v used=%v pct=%v", tot, used, pct)
	}

	ch := c2blue55.NewChannel()
	procs := scanRealProcesses(ch)
	if len(procs) < 1 {
		t.Fatal("scanRealProcesses: aucun processus vivant")
	}
	if procs[0].PID == 0 && procs[0].Comm == "" {
		t.Fatal("scanRealProcesses: entrée vide")
	}

	a := newArena()
	t.Cleanup(a.close)
	srv := httptest.NewServer(a.handler())
	t.Cleanup(srv.Close)
	client := srv.Client()

	homeReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/", nil)
	homeReq.SetBasicAuth("observer", "private-test-token")
	home, err := client.Do(homeReq)
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	homeBody, err := io.ReadAll(home.Body)
	_ = home.Body.Close()
	if err != nil {
		t.Fatalf("GET / body: %v", err)
	}
	if home.StatusCode != http.StatusOK {
		t.Fatalf("GET / status=%d", home.StatusCode)
	}
	if !bytes.Contains(homeBody, []byte("CPU")) {
		t.Fatal("GET /: métrique CPU absente")
	}
	if !bytes.Contains(homeBody, []byte("RAM")) {
		t.Fatal("GET /: métrique RAM absente")
	}
	if !bytes.Contains(homeBody, []byte("SPSC")) {
		t.Fatal("GET /: métrique SPSC absente")
	}
	if bytes.Contains(bytes.ToLower(homeBody), []byte("alpine")) {
		t.Fatal("GET /: Alpine.js interdit")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/events", nil)
	req.SetBasicAuth("observer", "private-test-token")
	if err != nil {
		t.Fatalf("GET /events request: %v", err)
	}
	evRes, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /events: %v", err)
	}
	t.Cleanup(func() { _ = evRes.Body.Close() })
	if evRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /events status=%d", evRes.StatusCode)
	}
	ct := evRes.Header.Get("Content-Type")
	if ct != "text/event-stream" {
		t.Fatalf("GET /events Content-Type=%q", ct)
	}
	frame, err := readSSEData(evRes.Body)
	if err != nil {
		t.Fatalf("GET /events frame: %v", err)
	}
	var tel telemetryPayload
	if err := json.Unmarshal(frame, &tel); err != nil {
		t.Fatalf("GET /events json: %v (%s)", err, frame)
	}
	if tel.Host.MemTotalMB <= 0 {
		t.Fatalf("host.mem_total_mb=%v", tel.Host.MemTotalMB)
	}
	if tel.Host.CPUPct < 0 || tel.Host.CPUPct > 100 {
		t.Fatalf("host.cpu_pct=%v", tel.Host.CPUPct)
	}
	if tel.Host.Goroutines < 1 {
		t.Fatalf("host.goroutines=%d", tel.Host.Goroutines)
	}
}

func readSSEData(r io.Reader) ([]byte, error) {
	br := bufio.NewReader(r)
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("data:")))
		if len(payload) == 0 || bytes.Equal(payload, []byte("{}")) {
			continue
		}
		if !json.Valid(payload) {
			return nil, errInvalidSSE(string(payload))
		}
		return payload, nil
	}
}

type sseError string

func (e sseError) Error() string { return string(e) }

func errInvalidSSE(s string) error {
	return sseError("sse json invalide: " + strings.TrimSpace(s))
}
