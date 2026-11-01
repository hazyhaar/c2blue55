package c2blue55

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

// Full17MotifsBenchmarkReport regroupe le catalogue des 17 motifs DNS, les manifestes SHA-256
// des runs A et B, le découpage en 6 salves live OVH et le rapport de matrice de confusion 18x18 + ablation N vs N+1.
type Full17MotifsBenchmarkReport struct {
	Catalog            []dnslab.PatternSpec        `json:"catalog"`
	LiveSalveCount     int                         `json:"live_salve_count"`
	ManifestA          IRLRunArtifactManifest      `json:"manifest_a"`
	ManifestB          IRLRunArtifactManifest      `json:"manifest_b"`
	ManifestJSONPath   string                      `json:"manifest_json_path"`
	OOSProof           engine.OOSPatternProof      `json:"oos_proof"`
	Confusion18x18RunA engine.Confusion18x18Report `json:"confusion_18x18_run_a"`
	Confusion18x18RunB engine.Confusion18x18Report `json:"confusion_18x18_run_b"`
	BlueTeam           engine.BlueTeamBundle       `json:"blueteam"`
}

func execute17MotifsDilutedRun(outDir, runID, apexSuffix string, seed uint64) (
	IRLRunArtifactManifest,
	*engine.EpisodeRunCorpus,
	engine.Confusion18x18Report,
	int,
	error,
) {
	exchanges, truth, err := dnslab.BuildIRLDilutedStream17Motifs(seed, 0.80, 480)
	if err != nil {
		return IRLRunArtifactManifest{}, nil, engine.Confusion18x18Report{}, 0, err
	}
	salves, err := dnslab.SplitLiveSalves(exchanges, 160, dnslab.MaxLiveQPS)
	if err != nil {
		return IRLRunArtifactManifest{}, nil, engine.Confusion18x18Report{}, 0, err
	}

	pipe := NewDefaultPipeline()
	defer pipe.Close()

	rs, err := NewRecordSession(outDir, runID, pipe)
	if err != nil {
		return IRLRunArtifactManifest{}, nil, engine.Confusion18x18Report{}, 0, err
	}

	clientIP := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 55, 0, 2}
	serverIP := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 55, 0, 1}

	pts := make([]engine.Motif17EvalPoint, len(exchanges))
	frames := make([]blindWireExchange, len(exchanges))
	totalFrames := 0

	for i, ex := range exchanges {
		apex := ex.DomainApex + "-" + apexSuffix
		truth[i].DomainApex = apex

		// Varier le TxID avec la graine pour garantir que les PCAP de Run-A et Run-B ont des SHA-256 distincts.
		reqWire := make([]byte, len(ex.RequestWire))
		copy(reqWire, ex.RequestWire)
		respWire := make([]byte, len(ex.ResponseWire))
		copy(respWire, ex.ResponseWire)
		txid := uint16((seed & 0xFFFF) ^ uint64(0x6000+i))
		if len(reqWire) >= 2 {
			binary.BigEndian.PutUint16(reqWire[0:2], txid)
		}
		if len(respWire) >= 2 {
			binary.BigEndian.PutUint16(respWire[0:2], txid)
		}

		if _, err := rs.RecordDNSMessage(reqWire, ex.TimestampNs, clientIP, serverIP); err != nil {
			_ = rs.Close()
			return IRLRunArtifactManifest{}, nil, engine.Confusion18x18Report{}, 0, err
		}
		totalFrames++

		if _, err := rs.RecordDNSMessage(respWire, ex.TimestampNs+2_000_000, serverIP, clientIP); err != nil {
			_ = rs.Close()
			return IRLRunArtifactManifest{}, nil, engine.Confusion18x18Report{}, 0, err
		}
		totalFrames++

		frames[i] = blindWireExchange{
			ReqWire:     reqWire,
			RespWire:    respWire,
			TimestampNs: ex.TimestampNs,
			ClientIP:    clientIP,
		}

		pts[i] = engine.Motif17EvalPoint{
			TimestampNs:  ex.TimestampNs,
			ClientIP:     clientIP,
			TrueClass:    truth[i].MotifFamily,
			DomainApex:   apex,
			Subdomain:    ex.Subdomain,
			QType:        ex.QType,
			RequestWire:  reqWire,
			ResponseWire: respWire,
		}
	}

	if err := rs.Close(); err != nil {
		return IRLRunArtifactManifest{}, nil, engine.Confusion18x18Report{}, 0, err
	}

	vectors, states, err := extractBlindWireFeatures(frames, apexSuffix, true)
	if err != nil {
		return IRLRunArtifactManifest{}, nil, engine.Confusion18x18Report{}, 0, err
	}
	corpus := &engine.EpisodeRunCorpus{
		RunID:   runID,
		Samples: make([]engine.EpisodeVectorSample, len(exchanges)),
	}
	for i := range exchanges {
		corpus.Samples[i] = engine.EpisodeVectorSample{
			Family:     truth[i].MotifFamily,
			DomainApex: states[i].Apex,
			Features:   vectors[i],
		}
	}

	confRep, err := engine.EvaluateConfusion18x18AndAblation(pts)
	if err != nil {
		return IRLRunArtifactManifest{}, nil, engine.Confusion18x18Report{}, 0, err
	}

	var gtBuf bytes.Buffer
	enc := json.NewEncoder(&gtBuf)
	for _, gt := range truth {
		if err := enc.Encode(gt); err != nil {
			return IRLRunArtifactManifest{}, nil, engine.Confusion18x18Report{}, 0, err
		}
	}
	gtPath := filepath.Join(outDir, runID+".ground_truth.jsonl")
	if err := os.WriteFile(gtPath, gtBuf.Bytes(), 0o644); err != nil {
		return IRLRunArtifactManifest{}, nil, engine.Confusion18x18Report{}, 0, err
	}

	pcapSHA, err := fileSHA256Hex(rs.PCAPPath())
	if err != nil {
		return IRLRunArtifactManifest{}, nil, engine.Confusion18x18Report{}, 0, err
	}
	epSHA, err := fileSHA256Hex(rs.JSONLPath())
	if err != nil {
		return IRLRunArtifactManifest{}, nil, engine.Confusion18x18Report{}, 0, err
	}
	gtSHA, err := fileSHA256Hex(gtPath)
	if err != nil {
		return IRLRunArtifactManifest{}, nil, engine.Confusion18x18Report{}, 0, err
	}

	return IRLRunArtifactManifest{
		RunID:             runID,
		PCAPPath:          rs.PCAPPath(),
		PCAPSHA256:        pcapSHA,
		EpisodesPath:      rs.JSONLPath(),
		EpisodesSHA256:    epSHA,
		GroundTruthPath:   gtPath,
		GroundTruthSHA256: gtSHA,
		TotalFrames:       totalFrames,
	}, corpus, confRep, len(salves), nil
}

// RunIRL17MotifsFullSuite exécute de bout en bout l'homologation IRL des 17 motifs DNS (M-01..M-04 + P1..P13)
// sur deux runs disjoints Run-A et Run-B, valide la matrice de confusion 18x18 et l'ablation N vs N+1,
// et scelle le manifeste SHA-256 croisé.
func RunIRL17MotifsFullSuite(outDir string, seedA, seedB uint64) (Full17MotifsBenchmarkReport, error) {
	if seedA == seedB {
		return Full17MotifsBenchmarkReport{}, dnslab.ErrSameRunLeak
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return Full17MotifsBenchmarkReport{}, err
	}

	runAID := fmt.Sprintf("irl17-run-a-%08x", seedA)
	runBID := fmt.Sprintf("irl17-run-b-%08x", seedB)

	manA, corpusA, confA, salvesA, err := execute17MotifsDilutedRun(outDir, runAID, "a", seedA)
	if err != nil {
		return Full17MotifsBenchmarkReport{}, err
	}
	manB, corpusB, confB, _, err := execute17MotifsDilutedRun(outDir, runBID, "b", seedB)
	if err != nil {
		return Full17MotifsBenchmarkReport{}, err
	}

	proof, err := engine.ProvePatternOutOfSample(corpusA, corpusB)
	if err != nil {
		return Full17MotifsBenchmarkReport{}, err
	}
	bt, err := engine.ExportBlueTeamArtifacts(proof, engine.DefaultPhysicalBounds())
	if err != nil {
		return Full17MotifsBenchmarkReport{}, err
	}

	manifestPath := filepath.Join(outDir, "manifest_17motifs.json")
	rep := Full17MotifsBenchmarkReport{
		Catalog:            dnslab.PatternCatalog17(),
		LiveSalveCount:     salvesA,
		ManifestA:          manA,
		ManifestB:          manB,
		ManifestJSONPath:   manifestPath,
		OOSProof:           proof,
		Confusion18x18RunA: confA,
		Confusion18x18RunB: confB,
		BlueTeam:           bt,
	}

	rawManifest, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return Full17MotifsBenchmarkReport{}, err
	}
	if err := os.WriteFile(manifestPath, rawManifest, 0o644); err != nil {
		return Full17MotifsBenchmarkReport{}, err
	}
	return rep, nil
}
