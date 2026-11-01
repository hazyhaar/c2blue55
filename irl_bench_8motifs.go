package c2blue55

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

// Full8MotifsBenchmarkReport regroupe le catalogue des 8 motifs, les manifestes SHA-256 croisés
// des runs A et B, le découpage en salves live OVH et le rapport de matrice de confusion 9x9 + ablation N vs N+1.
type Full8MotifsBenchmarkReport struct {
	Catalog              []dnslab.PatternSpec      `json:"catalog"`
	LiveSalveCount       int                       `json:"live_salve_count"`
	ManifestA            IRLRunArtifactManifest    `json:"manifest_a"`
	ManifestB            IRLRunArtifactManifest    `json:"manifest_b"`
	ManifestJSONPath     string                    `json:"manifest_json_path"`
	OOSProof             engine.OOSPatternProof    `json:"oos_proof"`
	ConfusionAndAblation engine.Confusion9x9Report `json:"confusion_and_ablation"`
	BlueTeam             engine.BlueTeamBundle     `json:"blueteam"`
}

func rdataEntropyBits(b []byte) float32 {
	if len(b) == 0 {
		return 0
	}
	var hist [256]int
	for _, c := range b {
		hist[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range hist {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return float32(h)
}

func execute8MotifsDilutedRun(outDir, runID, apexSuffix string, seed uint64) (
	IRLRunArtifactManifest,
	*engine.EpisodeRunCorpus,
	[]engine.Motif8EvalPoint,
	int,
	error,
) {
	exchanges, truth, err := dnslab.BuildIRLDilutedStream8Motifs(seed, 0.85, 320)
	if err != nil {
		return IRLRunArtifactManifest{}, nil, nil, 0, err
	}
	salves, err := dnslab.SplitLiveSalves(exchanges, 160, 5)
	if err != nil {
		return IRLRunArtifactManifest{}, nil, nil, 0, err
	}

	pipe := NewDefaultPipeline()
	defer pipe.Close()

	rs, err := NewRecordSession(outDir, runID, pipe)
	if err != nil {
		return IRLRunArtifactManifest{}, nil, nil, 0, err
	}

	clientIP := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 55, 0, 2}
	serverIP := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 55, 0, 1}

	var qBuf, rBuf [512]byte
	frames := make([]blindWireExchange, len(exchanges))
	totalFrames := 0

	for i, ex := range exchanges {
		apex := ex.DomainApex + "-" + apexSuffix
		truth[i].DomainApex = apex
		qname := ex.Subdomain + "." + apex
		txid := uint16(0x4000 + i)

		qLen, err := dnslab.BuildQuery(txid, []byte(qname), ex.QType, qBuf[:])
		if err != nil {
			_ = rs.Close()
			return IRLRunArtifactManifest{}, nil, nil, 0, err
		}
		rLen, _, err := dnslab.BuildLabResponse8Motifs(qBuf[:qLen], seed+uint64(i), rBuf[:])
		if err != nil {
			_ = rs.Close()
			return IRLRunArtifactManifest{}, nil, nil, 0, err
		}

		if _, err := rs.RecordDNSMessage(qBuf[:qLen], ex.TimestampNs, clientIP, serverIP); err != nil {
			_ = rs.Close()
			return IRLRunArtifactManifest{}, nil, nil, 0, err
		}
		totalFrames++

		if _, err := rs.RecordDNSMessage(rBuf[:rLen], ex.TimestampNs+2_000_000, serverIP, clientIP); err != nil {
			_ = rs.Close()
			return IRLRunArtifactManifest{}, nil, nil, 0, err
		}
		totalFrames++

		reqCopy := make([]byte, qLen)
		copy(reqCopy, qBuf[:qLen])
		respCopy := make([]byte, rLen)
		copy(respCopy, rBuf[:rLen])
		frames[i] = blindWireExchange{
			ReqWire:     reqCopy,
			RespWire:    respCopy,
			TimestampNs: ex.TimestampNs,
			ClientIP:    clientIP,
		}
	}

	if err := rs.Close(); err != nil {
		return IRLRunArtifactManifest{}, nil, nil, 0, err
	}

	vectors, states, err := extractBlindWireFeatures(frames, apexSuffix, false)
	if err != nil {
		return IRLRunArtifactManifest{}, nil, nil, 0, err
	}

	corpus := &engine.EpisodeRunCorpus{
		RunID:   runID,
		Samples: make([]engine.EpisodeVectorSample, len(exchanges)),
	}
	evalPts := make([]engine.Motif8EvalPoint, len(exchanges))
	for i, ex := range exchanges {
		st := states[i]
		evalPts[i] = engine.Motif8EvalPoint{
			PacketIndex: i,
			TimestampNs: frames[i].TimestampNs,
			TrueClass:   ex.Family,
			DomainApex:  st.Apex,
			Subdomain:   st.Subdomain,
			QType:       st.QType,
			RCode:       st.RCode,
			RDataLen:    st.RDataLen,
			RDataEnt:    st.RDataEnt,
		}
		corpus.Samples[i] = engine.EpisodeVectorSample{
			Family:     ex.Family,
			DomainApex: st.Apex,
			Features:   vectors[i],
		}
	}

	var gtBuf bytes.Buffer
	enc := json.NewEncoder(&gtBuf)
	for _, gt := range truth {
		if err := enc.Encode(gt); err != nil {
			return IRLRunArtifactManifest{}, nil, nil, 0, err
		}
	}
	gtPath := filepath.Join(outDir, runID+".ground_truth.jsonl")
	if err := os.WriteFile(gtPath, gtBuf.Bytes(), 0o644); err != nil {
		return IRLRunArtifactManifest{}, nil, nil, 0, err
	}

	pcapSHA, err := fileSHA256Hex(rs.PCAPPath())
	if err != nil {
		return IRLRunArtifactManifest{}, nil, nil, 0, err
	}
	epSHA, err := fileSHA256Hex(rs.JSONLPath())
	if err != nil {
		return IRLRunArtifactManifest{}, nil, nil, 0, err
	}
	gtSHA, err := fileSHA256Hex(gtPath)
	if err != nil {
		return IRLRunArtifactManifest{}, nil, nil, 0, err
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
	}, corpus, evalPts, len(salves), nil
}

// RunIRL8MotifsFullSuite exécute l'homologation complète des 8 motifs (4 connus M-01..M-04 + 4 nouveaux P1..P4)
// dilués à 85% dans du bruit bénin IRL, valide la matrice de confusion 9x9 et le test d'ablation N vs N+1,
// et scelle le manifeste SHA-256 croisé.
func RunIRL8MotifsFullSuite(outDir string, seedA, seedB uint64) (Full8MotifsBenchmarkReport, error) {
	if seedA == seedB {
		return Full8MotifsBenchmarkReport{}, dnslab.ErrSameRunLeak
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return Full8MotifsBenchmarkReport{}, err
	}

	runAID := fmt.Sprintf("irl8-run-a-%08x", seedA)
	runBID := fmt.Sprintf("irl8-run-b-%08x", seedB)

	manA, corpusA, _, salvesA, err := execute8MotifsDilutedRun(outDir, runAID, "a", seedA)
	if err != nil {
		return Full8MotifsBenchmarkReport{}, err
	}
	manB, corpusB, evalB, _, err := execute8MotifsDilutedRun(outDir, runBID, "b", seedB)
	if err != nil {
		return Full8MotifsBenchmarkReport{}, err
	}

	ablationRep, err := engine.EvaluateConfusion9x9AndAblation(evalB)
	if err != nil {
		return Full8MotifsBenchmarkReport{}, err
	}

	proof, err := engine.ProvePatternOutOfSample(corpusA, corpusB)
	if err != nil {
		return Full8MotifsBenchmarkReport{}, err
	}
	bt, err := engine.ExportBlueTeamArtifacts(proof, engine.DefaultPhysicalBounds())
	if err != nil {
		return Full8MotifsBenchmarkReport{}, err
	}

	manifestPath := filepath.Join(outDir, "manifest_8motifs.json")
	rep := Full8MotifsBenchmarkReport{
		Catalog:              dnslab.PatternCatalog(),
		LiveSalveCount:       salvesA,
		ManifestA:            manA,
		ManifestB:            manB,
		ManifestJSONPath:     manifestPath,
		OOSProof:             proof,
		ConfusionAndAblation: ablationRep,
		BlueTeam:             bt,
	}

	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return Full8MotifsBenchmarkReport{}, err
	}
	if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
		return Full8MotifsBenchmarkReport{}, err
	}
	return rep, nil
}
