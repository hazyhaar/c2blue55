package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/hazyhaar/c2blue55"
)

func runICMPEval(args []string, output io.Writer) (code int, err error) {
	options := flag.NewFlagSet("icmp-eval", flag.ContinueOnError)
	options.SetOutput(os.Stderr)
	cheminCapture := options.String("pcap", "", "Capture PCAP à évaluer")
	cheminRapport := options.String("report", "", "Chemin du rapport JSON")
	if err := options.Parse(args); err != nil {
		return 2, err
	}
	if options.NArg() != 0 || *cheminCapture == "" || *cheminRapport == "" {
		return 2, fmt.Errorf("icmp-eval exige -pcap et -report, sans argument supplémentaire")
	}

	mesures, err := c2blue55.EvaluateICMPEchoPCAP(*cheminCapture)
	if err != nil {
		return 1, err
	}
	capture, err := os.Open(*cheminCapture)
	if err != nil {
		return 1, err
	}
	hachage := sha256.New()
	_, err = io.Copy(hachage, capture)
	errFermeture := capture.Close()
	if err != nil {
		return 1, err
	}
	if errFermeture != nil {
		return 1, errFermeture
	}

	rapport, err := json.MarshalIndent(struct {
		PCAP               string `json:"pcap"`
		SHA256             string `json:"sha256"`
		IPv4Packets        uint32 `json:"ipv4_packets"`
		EchoRequests       uint32 `json:"echo_requests"`
		EchoReplies        uint32 `json:"echo_replies"`
		Fires              uint32 `json:"fires"`
		AsymmetricFires    uint32 `json:"asymmetric_fires"`
		UnsolicitedFires   uint32 `json:"unsolicited_fires"`
		PacketsToFirstFire uint32 `json:"packets_to_first_fire"`
		FirstFireTsNs      uint64 `json:"first_fire_ts_ns"`
	}{
		PCAP:               *cheminCapture,
		SHA256:             hex.EncodeToString(hachage.Sum(nil)),
		IPv4Packets:        mesures.IPv4Packets,
		EchoRequests:       mesures.EchoRequests,
		EchoReplies:        mesures.EchoReplies,
		Fires:              mesures.Fires,
		AsymmetricFires:    mesures.AsymmetricFires,
		UnsolicitedFires:   mesures.UnsolicitedFires,
		PacketsToFirstFire: mesures.PacketsToFirstFire,
		FirstFireTsNs:      mesures.FirstFireTsNs,
	}, "", "  ")
	if err != nil {
		return 1, err
	}
	temporaire, err := os.CreateTemp(filepath.Dir(*cheminRapport), ".icmp-eval-*")
	if err != nil {
		return 1, err
	}
	defer os.Remove(temporaire.Name())
	if _, err := temporaire.Write(append(rapport, '\n')); err != nil {
		temporaire.Close()
		return 1, err
	}
	if err := temporaire.Sync(); err != nil {
		temporaire.Close()
		return 1, err
	}
	if err := temporaire.Close(); err != nil {
		return 1, err
	}
	if err := os.Chmod(temporaire.Name(), 0o600); err != nil {
		return 1, err
	}
	if err := os.Rename(temporaire.Name(), *cheminRapport); err != nil {
		return 1, err
	}
	if _, err := fmt.Fprintf(output, "%s %d %d %d %d %d %d\n", *cheminCapture,
		mesures.IPv4Packets, mesures.EchoRequests, mesures.EchoReplies, mesures.Fires,
		mesures.PacketsToFirstFire, mesures.FirstFireTsNs); err != nil {
		return 1, err
	}
	return 0, nil
}
