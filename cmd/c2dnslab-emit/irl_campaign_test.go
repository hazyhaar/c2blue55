package main

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

func TestExecuteIRLCampaign(t *testing.T) {
	outDir := t.TempDir()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer conn.Close()

	// 1. Garde anti-spam OVH F-21 : refus immédiat sur IP externe, QPS > 5 ou maxPackets > 200 (SH-S18b-01).
	if _, err := ExecuteIRLCampaign(conn, "8.8.8.8:53", 42, 5, 40, outDir); !errors.Is(err, dnslab.ErrLiveRateContract) {
		t.Fatalf("attendu ErrLiveRateContract sur 8.8.8.8:53, obtenu %v", err)
	}
	if _, err := ExecuteIRLCampaign(conn, "127.0.0.1:5353", 42, 10, 40, outDir); !errors.Is(err, dnslab.ErrLiveRateContract) {
		t.Fatalf("attendu ErrLiveRateContract sur maxQPS=10 (>5), obtenu %v", err)
	}
	if _, err := ExecuteIRLCampaign(conn, "127.0.0.1:5353", 42, 5, 500, outDir); !errors.Is(err, dnslab.ErrLiveRateContract) {
		t.Fatalf("attendu ErrLiveRateContract sur maxPackets=500 (>200), obtenu %v", err)
	}

	// 2. Exécution bornée vers un écouteur loopback 127.0.0.1:<port>.
	sink, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket sink: %v", err)
	}
	defer sink.Close()

	receipt, err := ExecuteIRLCampaign(conn, sink.LocalAddr().String(), 0x7788, 5, 40, outDir)
	if err != nil {
		t.Fatalf("ExecuteIRLCampaign: %v", err)
	}
	if receipt.SentPackets != 40 || receipt.BenignCount+receipt.HostileCount != 40 {
		t.Fatalf("receipt inattendu: %+v", receipt)
	}
	raw, err := os.ReadFile(receipt.GroundTruthPath)
	if err != nil {
		t.Fatalf("ReadFile GroundTruthPath: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 40 {
		t.Fatalf("attendu 40 lignes dans ground_truth.jsonl, obtenu %d", len(lines))
	}
}
