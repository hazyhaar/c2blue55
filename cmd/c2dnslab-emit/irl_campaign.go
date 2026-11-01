package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

// IRLCampaignReceipt résume l'exécution bornée d'une campagne diluée IRL et le chemin de sa vérité terrain.
type IRLCampaignReceipt struct {
	RunID           string `json:"run_id"`
	SentPackets     int    `json:"sent_packets"`
	GroundTruthPath string `json:"ground_truth_path"`
	BenignCount     int    `json:"benign_count"`
	HostileCount    int    `json:"hostile_count"`
}

// ExecuteIRLCampaign vérifie la garde anti-spam OVH (F-21), émet un flux dilué IRL borné sur conn
// et écrit atomiquement le journal de vérité terrain <run_id>.ground_truth.jsonl.
func ExecuteIRLCampaign(conn net.PacketConn, targetAddr string, seed uint64, maxQPS, maxPackets int, outDir string) (IRLCampaignReceipt, error) {
	host, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		host = targetAddr
	}
	if err := dnslab.ValidateLiveRateGuard(host, maxQPS, maxPackets); err != nil {
		return IRLCampaignReceipt{}, err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return IRLCampaignReceipt{}, err
	}

	exchanges, truth, err := dnslab.BuildIRLDilutedStream(seed, 0.85, maxPackets)
	if err != nil {
		return IRLCampaignReceipt{}, err
	}

	runID := fmt.Sprintf("irl-%016x", seed)
	var receipt IRLCampaignReceipt
	receipt.RunID = runID

	var qBuf [512]byte
	var emitInterval time.Duration
	if maxQPS > 0 {
		emitInterval = time.Second / time.Duration(maxQPS)
	}
	for i, ex := range exchanges {
		if i > 0 && emitInterval > 0 {
			time.Sleep(emitInterval)
		}
		qname := ex.Subdomain + "." + ex.DomainApex
		qLen, err := dnslab.BuildQuery(uint16(0x1000+i), []byte(qname), ex.QType, qBuf[:])
		if err != nil {
			return IRLCampaignReceipt{}, err
		}
		if _, err := conn.WriteTo(qBuf[:qLen], udpAddr); err != nil {
			return IRLCampaignReceipt{}, err
		}
		receipt.SentPackets++
		if ex.Family == "BENIGN" {
			receipt.BenignCount++
		} else {
			receipt.HostileCount++
		}
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, gt := range truth {
		if err := enc.Encode(gt); err != nil {
			return IRLCampaignReceipt{}, err
		}
	}

	gtPath := filepath.Join(outDir, runID+".ground_truth.jsonl")
	tmpPath := gtPath + ".tmp"
	if err := os.WriteFile(tmpPath, buf.Bytes(), 0o644); err != nil {
		return IRLCampaignReceipt{}, err
	}
	if err := os.Rename(tmpPath, gtPath); err != nil {
		return IRLCampaignReceipt{}, err
	}
	receipt.GroundTruthPath = gtPath
	return receipt, nil
}
