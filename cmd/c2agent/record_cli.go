package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

func loadValidatedOOSProof(proofPath string) (engine.OOSPatternProof, bool) {
	if proofPath == "" {
		return engine.OOSPatternProof{}, false
	}
	proofBytes, err := os.ReadFile(proofPath)
	if err != nil {
		return engine.OOSPatternProof{}, false
	}
	var proof engine.OOSPatternProof
	if err := json.Unmarshal(proofBytes, &proof); err != nil {
		return engine.OOSPatternProof{}, false
	}
	if !proof.AllPass || len(proof.Families) < 4 {
		return engine.OOSPatternProof{}, false
	}
	for _, fam := range []string{"P1", "P2", "P3", "P4"} {
		metrics, ok := proof.Families[fam]
		if !ok || metrics.Recall < 0.90 || metrics.FalsePositives > 0 || metrics.AUC < 0.90 || metrics.LODO_AUC < 0.90 {
			return engine.OOSPatternProof{}, false
		}
	}
	return proof, true
}

// RunAgentRecordCLI rejoue ou capture un flux PCAP DNS en mode RecordSession (--record-dir)
// et exporte optionnellement les règles comportementales BlueTeam (--export-blueteam).
func RunAgentRecordCLI(args []string) int {
	fs := flag.NewFlagSet("c2agent-record", flag.ContinueOnError)
	pcapPath := fs.String("pcap", "", "Chemin du fichier PCAP DNS source")
	recordDir := fs.String("record-dir", "", "Répertoire de sortie pour <run_id>.pcap et <run_id>.episodes.jsonl")
	runID := fs.String("run-id", "c2agent-run", "Identifiant de la session d'enregistrement")
	exportBT := fs.String("export-blueteam", "", "Répertoire d'export des règles Sigma et Suricata")
	oosProofPath := fs.String("oos-proof", "", "Chemin du fichier JSON de preuve OOS validée")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *pcapPath == "" || *recordDir == "" {
		return 2
	}

	var validatedProof engine.OOSPatternProof
	if *exportBT != "" {
		var ok bool
		validatedProof, ok = loadValidatedOOSProof(*oosProofPath)
		if !ok {
			return 1
		}
	}

	pipe := c2blue55.NewDefaultPipeline()
	defer pipe.Close()

	rs, err := c2blue55.NewRecordSession(*recordDir, *runID, pipe)
	if err != nil {
		return 1
	}

	pcapBytes, err := os.ReadFile(*pcapPath)
	if err != nil || len(pcapBytes) < 24 {
		_ = rs.Close()
		return 1
	}

	linkType := binary.LittleEndian.Uint32(pcapBytes[20:24])
	pos := 24
	recorded := 0
	for pos+16 <= len(pcapBytes) {
		tsSec := int64(binary.LittleEndian.Uint32(pcapBytes[pos : pos+4]))
		tsSub := int64(binary.LittleEndian.Uint32(pcapBytes[pos+4 : pos+8]))
		inclLen := int(binary.LittleEndian.Uint32(pcapBytes[pos+8 : pos+12]))
		pos += 16
		if inclLen <= 0 || pos+inclLen > len(pcapBytes) {
			break
		}
		pkt := pcapBytes[pos : pos+inclLen]
		pos += inclLen

		ipOff := 0
		if linkType == 1 {
			if len(pkt) < 14 {
				continue
			}
			ipOff = 14
		}
		if len(pkt) < ipOff+28 {
			continue
		}
		ip := pkt[ipOff:]
		ihl := int(ip[0]&0x0f) * 4
		if ihl < 20 || len(ip) < ihl+8 || ip[9] != 17 {
			continue
		}
		var srcIP, dstIP [16]byte
		srcIP[10], srcIP[11] = 0xff, 0xff
		dstIP[10], dstIP[11] = 0xff, 0xff
		copy(srcIP[12:16], ip[12:16])
		copy(dstIP[12:16], ip[16:20])

		dnsPayload := ip[ihl+8:]
		tsNs := tsSec*1_000_000_000 + tsSub*1_000
		if _, err := rs.RecordDNSMessage(dnsPayload, tsNs, srcIP, dstIP); err == nil {
			recorded++
		}
	}

	if err := rs.Close(); err != nil || recorded == 0 {
		return 1
	}

	if *exportBT != "" {
		bundle, err := engine.ExportBlueTeamArtifacts(validatedProof, engine.DefaultPhysicalBounds())
		if err != nil {
			return 1
		}
		if err := os.MkdirAll(*exportBT, 0o755); err != nil {
			return 1
		}
		if err := os.WriteFile(filepath.Join(*exportBT, "sigma_rules.yml"), []byte(bundle.SigmaRulesYAML), 0o644); err != nil {
			return 1
		}
		if err := os.WriteFile(filepath.Join(*exportBT, "suricata.rules"), []byte(bundle.SuricataRules), 0o644); err != nil {
			return 1
		}
	}
	return 0
}
