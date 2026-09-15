package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55"
)

func TestObservationIdentityAndPrivacy(t *testing.T) {
	stat, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	birth, ok := processStartTime(stat)
	if !ok || birth == 0 {
		t.Fatalf("birth: %d %v", birth, ok)
	}
	if _, ok := processStartTime([]byte("invalid")); ok {
		t.Fatal("invalid stat accepted")
	}
	if got, ok := processStartTime(stat); !ok || got != birth {
		t.Fatal("nominal stat recovery")
	}
	ch := c2blue55.NewChannel()
	for pass := 0; pass < 2; pass++ {
		procs := scanRealProcesses(ch)
		if len(procs) == 0 {
			t.Fatal("no live observations")
		}
		for _, proc := range procs {
			if proc.StartTime == 0 || proc.Cmdline != "[arguments withheld]" {
				t.Fatalf("identity/privacy: %+v", proc)
			}
		}
		if scanOccupancy != 0 {
			t.Fatal("drained occupancy not zero")
		}
		var ev c2blue55.Event
		if ch.Read(&ev) != 0 {
			t.Fatal("channel is not drained")
		}
		if len(copyIncidents()) != 0 {
			t.Fatal("periodic observations fabricated correlation")
		}
	}
}

func TestObservationRateUsesElapsedTime(t *testing.T) {
	previous := time.Now().Add(-2 * time.Second)
	a := &arena{ch: c2blue55.NewChannel(), t0: time.Now(), lastCollect: previous}
	a.collect()
	if a.total == 0 || a.eps <= 0 {
		t.Fatal("no real observations")
	}
	measuredSeconds := float64(a.total) / a.eps
	if math.Abs(measuredSeconds-a.lastCollect.Sub(previous).Seconds()) > 1e-9 {
		t.Fatalf("rate used a nominal scan frequency instead of elapsed time: %f seconds", measuredSeconds)
	}
}

func TestAuthenticationSnapshotAndSubscriberBound(t *testing.T) {
	t.Setenv("C2BLUE_DASHBOARD_TOKEN", "private")
	a := newArena()
	defer a.close()
	h := a.handler()
	denied := httptest.NewRecorder()
	h.ServeHTTP(denied, httptest.NewRequest("GET", "/events", nil))
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", denied.Code)
	}
	good := httptest.NewRequest("GET", "/", nil)
	good.SetBasicAuth("observer", "private")
	accepted := httptest.NewRecorder()
	h.ServeHTTP(accepted, good)
	if accepted.Code != http.StatusOK {
		t.Fatal("authentication recovery")
	}
	for i := 0; i < cap(a.clients); i++ {
		a.clients <- struct{}{}
	}
	req := httptest.NewRequest("GET", "/events", nil)
	req.SetBasicAuth("observer", "private")
	full := httptest.NewRecorder()
	h.ServeHTTP(full, req)
	if full.Code != http.StatusServiceUnavailable {
		t.Fatal("unbounded subscribers")
	}
	for len(a.clients) > 0 {
		<-a.clients
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	recovered := httptest.NewRecorder()
	h.ServeHTTP(recovered, req.WithContext(ctx))
	if recovered.Code != http.StatusOK || !bytes.HasPrefix(recovered.Body.Bytes(), []byte("data: ")) {
		t.Fatal("subscriber recovery did not deliver snapshot")
	}
	// Freeze collection, not the HTTP readers: both see the same encoded sample.
	scanMu.Lock()
	first, second := a.sseFrame(), a.sseFrame()
	if !bytes.Equal(first, second) {
		t.Fatal("clients resampled telemetry")
	}
	scanMu.Unlock()
	var tel telemetryPayload
	if err := json.Unmarshal(bytes.TrimSpace(bytes.TrimPrefix(first, []byte("data: "))), &tel); err != nil {
		t.Fatal(err)
	}
	if tel.C2Blue.RingOccupancy != 0 || tel.C2Blue.EventsPerSec <= 0 {
		t.Fatalf("metrics: %+v", tel.C2Blue)
	}
}
