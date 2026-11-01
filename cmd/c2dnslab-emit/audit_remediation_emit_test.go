package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAuditIRLCampaignRespecteMaxQPS(t *testing.T) {
	connServeur, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket serveur: %v", err)
	}
	t.Cleanup(func() { _ = connServeur.Close() })

	connClient, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket client: %v", err)
	}
	t.Cleanup(func() { _ = connClient.Close() })

	adrLocale := connServeur.LocalAddr().String()
	debut := time.Now()
	recu, err := ExecuteIRLCampaign(connClient, adrLocale, 42, 5, 40, t.TempDir())
	dureeMesuree := time.Since(debut)
	if err != nil {
		t.Fatalf("ExecuteIRLCampaign: %v", err)
	}
	if recu.SentPackets != 40 {
		t.Fatalf("SentPackets = %d, attendu 40", recu.SentPackets)
	}
	// 40 paquets à maxQPS = 5 -> au moins 39 intervalles de 200 ms = 7,8 s (plancher 7 s).
	if dureeMesuree < 7*time.Second {
		t.Fatalf("ExecuteIRLCampaign n'a pas cadencé l'émission selon maxQPS=5: 40 paquets émis en %v (attendu >= 7s)", dureeMesuree)
	}
}

func TestAuditControlHTTPAuthentificationBearer(t *testing.T) {
	t.Setenv("DNSLAB_EMIT_CONTROL_TOKEN", "jeton-secret-audit")

	r := &runner{runsDir: t.TempDir()}
	_ = injectLaunch(r, func(ctx context.Context, _ string, _ ...string) (int, error) {
		return 0, nil
	})
	controlMux := lookupControl(r)
	if controlMux == nil {
		t.Fatal("serveur de controle absent sur (*runner)")
	}

	serveur := httptest.NewServer(controlMux)
	t.Cleanup(serveur.Close)

	campagne := iodineCampaign("audit-auth-bearer", time.Second)
	corpsJSON, err := json.Marshal(campagne)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	// 1. POST /v1/campaign sans en-tête Authorization -> 401 Unauthorized.
	reqSansJeton, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serveur.URL+"/v1/campaign", bytes.NewReader(corpsJSON))
	if err != nil {
		t.Fatalf("NewRequest sans jeton: %v", err)
	}
	reqSansJeton.Header.Set("Content-Type", "application/json")
	repSansJeton, err := serveur.Client().Do(reqSansJeton)
	if err != nil {
		t.Fatalf("POST sans jeton: %v", err)
	}
	_ = repSansJeton.Body.Close()
	if repSansJeton.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /v1/campaign sans en-tete Authorization: statut=%d, attendu %d", repSansJeton.StatusCode, http.StatusUnauthorized)
	}

	// 2. POST /v1/campaign avec mauvais jeton Bearer -> 401 Unauthorized.
	reqMauvaisJeton, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serveur.URL+"/v1/campaign", bytes.NewReader(corpsJSON))
	if err != nil {
		t.Fatalf("NewRequest mauvais jeton: %v", err)
	}
	reqMauvaisJeton.Header.Set("Content-Type", "application/json")
	reqMauvaisJeton.Header.Set("Authorization", "Bearer mauvais-jeton")
	repMauvaisJeton, err := serveur.Client().Do(reqMauvaisJeton)
	if err != nil {
		t.Fatalf("POST mauvais jeton: %v", err)
	}
	_ = repMauvaisJeton.Body.Close()
	if repMauvaisJeton.StatusCode != http.StatusUnauthorized {
		t.Errorf("POST /v1/campaign avec Bearer invalide: statut=%d, attendu %d", repMauvaisJeton.StatusCode, http.StatusUnauthorized)
	}
}
