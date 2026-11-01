package c2blue55

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

// IRLRunArtifactManifest scelle les empreintes SHA-256 croisées du PCAP, du journal d'épisodes
// et de la vérité terrain d'un run dilué IRL.
type IRLRunArtifactManifest struct {
	RunID             string `json:"run_id"`
	PCAPPath          string `json:"pcap_path"`
	PCAPSHA256        string `json:"pcap_sha256"`
	EpisodesPath      string `json:"episodes_path"`
	EpisodesSHA256    string `json:"episodes_sha256"`
	GroundTruthPath   string `json:"ground_truth_path"`
	GroundTruthSHA256 string `json:"ground_truth_sha256"`
	TotalFrames       int    `json:"total_frames"`
}

// IRLBenchSummary regroupe tous les artefacts et preuves du banc de thésaurisation IRL de bout en bout.
type IRLBenchSummary struct {
	ManifestA            IRLRunArtifactManifest            `json:"manifest_a"`
	ManifestB            IRLRunArtifactManifest            `json:"manifest_b"`
	ManifestJSONPath     string                            `json:"manifest_json_path"`
	OOSProof             engine.OOSPatternProof            `json:"oos_proof"`
	TTDByFamily          map[string]engine.FamilyTTDReport `json:"ttd_by_family"`
	BlueTeam             engine.BlueTeamBundle             `json:"blueteam"`
	BenignFalsePositives int                               `json:"benign_false_positives"`
}

func fileSHA256Hex(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

type blindWireExchange struct {
	ReqWire     []byte
	RespWire    []byte
	TimestampNs int64
	ClientIP    [16]byte
}

type blindExchangeState struct {
	Subdomain string
	Apex      string
	QType     uint16
	RCode     uint8
	RDataLen  int
	RDataEnt  float32
	Snap      engine.DNSEpisodeSnapshot
	P3        engine.EpisodeP3Features
	P4        engine.ClientP4Features
}

func splitQNameByApexLabels(qname string, apexLabels int) (string, string) {
	if apexLabels < 2 {
		apexLabels = 2
	}
	dotsNeeded := apexLabels
	dotsFound := 0
	for idx := len(qname) - 1; idx >= 0; idx-- {
		if qname[idx] == '.' {
			dotsFound++
			if dotsFound == dotsNeeded {
				return qname[:idx], qname[idx+1:]
			}
		}
	}
	return "", qname
}

func isStrictLowerHexASCII(label string) bool {
	if len(label) == 0 {
		return false
	}
	for idx := 0; idx < len(label); idx++ {
		ch := label[idx]
		if !((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')) {
			return false
		}
	}
	return true
}

func hasConsonantRunASCII(label string, minRun int) bool {
	run := 0
	for idx := 0; idx < len(label); idx++ {
		ch := label[idx]
		if ch >= 'A' && ch <= 'Z' {
			ch += 'a' - 'A'
		}
		if ch >= 'a' && ch <= 'z' && ch != 'a' && ch != 'e' && ch != 'i' && ch != 'o' && ch != 'u' && ch != 'y' {
			run++
			if run >= minRun {
				return true
			}
		} else {
			run = 0
		}
	}
	return false
}

func isWireShardCandidate(sub string, qtype uint16, rcode uint8, rdataLen int) bool {
	if engine.IsRFCUnderscoreSubdomain(sub) || rcode != 0 || rdataLen >= 180 {
		return false
	}
	if qtype != 1 && qtype != 16 && qtype != 28 {
		return false
	}
	if len(sub) < 14 || len(sub) > 20 {
		return false
	}
	if strings.ContainsAny(sub, ".-_") || hasConsonantRunASCII(sub, 5) {
		return false
	}
	return labelEntropyNorm([]byte(sub)) >= 0.55
}

func extractBlindWireFeatures(frames []blindWireExchange, apexSuffix string, appendSuffix bool) ([][8]float32, []blindExchangeState, error) {
	apexLabels := 2
	if !appendSuffix && apexSuffix != "" {
		apexLabels += strings.Count(apexSuffix, ".")
	}

	var epStore engine.DNSEpisodeStore
	var rollup engine.DNSClientRollup

	lastTsByApex := make(map[string]int64)
	intervalsByApex := make(map[string][]int64)
	qtypesByApex := make(map[string][]uint16)
	queriesByApex := make(map[string]int)
	finalSnapByApex := make(map[string]engine.DNSEpisodeSnapshot)
	finalP3ByApex := make(map[string]engine.EpisodeP3Features)
	var finalClientP4 engine.ClientP4Features

	states := make([]blindExchangeState, len(frames))
	shardEligible := make([]bool, len(frames))

	for i, fr := range frames {
		var msgQ, msgR DNSMessage
		if err := ParseDNSMessage(fr.ReqWire, &msgQ); err != nil {
			return nil, nil, err
		}
		if err := ParseDNSMessage(fr.RespWire, &msgR); err != nil {
			return nil, nil, err
		}

		qname := string(msgQ.QName[:msgQ.QNameLen])
		sub, apex := splitQNameByApexLabels(qname, apexLabels)
		if appendSuffix && apexSuffix != "" {
			apex = apex + "-" + apexSuffix
		}

		var rdata []byte
		if msgR.AnswerCount > 0 {
			rdata = msgR.Answers[0].RData[:msgR.Answers[0].RDataLen]
		}
		rdataEnt := rdataEntropyBits(rdata)

		_, _ = epStore.ObserveExchange(engine.DNSExchangeObs{
			TimestampNs: fr.TimestampNs,
			SrcIP:       fr.ClientIP,
			TxID:        msgQ.ID,
			IsResponse:  false,
			QType:       msgQ.QType,
			ParentApex:  []byte(apex),
			Subdomain:   []byte(sub),
			HasNonLDH:   msgQ.HasNonLDH,
		}, nil)
		snap, _ := epStore.ObserveExchange(engine.DNSExchangeObs{
			TimestampNs: fr.TimestampNs + 2_000_000,
			SrcIP:       fr.ClientIP,
			TxID:        msgR.ID,
			IsResponse:  true,
			RCode:       msgR.RCode,
			QType:       msgQ.QType,
			ParentApex:  []byte(apex),
			Subdomain:   []byte(sub),
			AnswerRData: rdata,
			AnswerCount: msgR.AnswerCount,
			HasNonLDH:   msgQ.HasNonLDH,
		}, nil)
		finalSnapByApex[apex] = snap

		var p3Feat engine.EpisodeP3Features
		if !engine.IsRFCUnderscoreSubdomain(sub) && msgR.RCode == 0 {
			queriesByApex[apex]++
			if prevTs, ok := lastTsByApex[apex]; ok {
				intervalsByApex[apex] = append(intervalsByApex[apex], fr.TimestampNs-prevTs)
			}
			lastTsByApex[apex] = fr.TimestampNs
			qtypesByApex[apex] = append(qtypesByApex[apex], msgQ.QType)
			p3Feat = engine.ComputeEpisodeP3TimingFeatures(intervalsByApex[apex], qtypesByApex[apex], 50_000_000)
			finalP3ByApex[apex] = p3Feat
		}

		var p4Feat engine.ClientP4Features
		if isWireShardCandidate(sub, msgQ.QType, msgR.RCode, len(rdata)) {
			shardEligible[i] = true
			p4Feat = rollup.ObserveParentApex(fr.ClientIP, fnv64Msg([]byte(apex)), labelEntropyNorm([]byte(sub)), fr.TimestampNs)
			finalClientP4 = p4Feat
		}

		states[i] = blindExchangeState{
			Subdomain: sub,
			Apex:      apex,
			QType:     msgQ.QType,
			RCode:     msgR.RCode,
			RDataLen:  len(rdata),
			RDataEnt:  rdataEnt,
			Snap:      snap,
			P3:        p3Feat,
			P4:        p4Feat,
		}
	}

	vectors := make([][8]float32, len(frames))
	for i, st := range states {
		epSnap := finalSnapByApex[st.Apex]
		epP3 := finalP3ByApex[st.Apex]

		downlinkNorm := min(epSnap.DownlinkRatio/25.0, float32(2.0))
		rdataSizeNorm := min(float32(st.RDataLen)/220.0, float32(1.5))
		rdataCarrier := (st.RDataEnt / 8.0) * rdataSizeNorm

		firstLbl := st.Subdomain
		if dotIdx := strings.IndexByte(firstLbl, '.'); dotIdx >= 0 {
			firstLbl = firstLbl[:dotIdx]
		}
		var denseHexScore float32
		if len(firstLbl) >= 20 && len(firstLbl) <= 36 && isStrictLowerHexASCII(firstLbl) {
			denseHexScore = epSnap.Base32HexScore
		}
		firstLblNorm := min(float32(len(firstLbl))/36.0, float32(1.2))

		var markovScore, p3Composite float32
		if !engine.IsRFCUnderscoreSubdomain(st.Subdomain) && st.RCode == 0 {
			markovScore = epP3.MarkovEntropy
			if epP3.CompositeP3Score > 0 {
				p3Composite = epP3.CompositeP3Score
			}
		}

		var shardParentsNorm, shardComposite float32
		if shardEligible[i] && queriesByApex[st.Apex] <= 3 {
			subEnt := labelEntropyNorm([]byte(st.Subdomain))
			shardParentsNorm = min(float32(finalClientP4.DistinctHighEntParents)/12.0, float32(1.2)) * subEnt
			if finalClientP4.CompositeP4Score > 0 {
				shardComposite = finalClientP4.CompositeP4Score
			}
		}

		vectors[i] = [8]float32{
			downlinkNorm,
			rdataCarrier,
			denseHexScore,
			firstLblNorm,
			markovScore,
			p3Composite,
			shardParentsNorm,
			shardComposite,
		}
	}

	return vectors, states, nil
}

func executeAndRecordDilutedRun(outDir, runID, apexSuffix string, seed uint64) (
	IRLRunArtifactManifest,
	*engine.EpisodeRunCorpus,
	[]engine.StreamEvalPoint,
	error,
) {
	exchanges, truth, err := dnslab.BuildIRLDilutedStream(seed, 0.85, 160)
	if err != nil {
		return IRLRunArtifactManifest{}, nil, nil, err
	}

	pipe := NewDefaultPipeline()
	defer pipe.Close()

	rs, err := NewRecordSession(outDir, runID, pipe)
	if err != nil {
		return IRLRunArtifactManifest{}, nil, nil, err
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
		txid := uint16(0x2000 + i)

		qLen, err := dnslab.BuildQuery(txid, []byte(qname), ex.QType, qBuf[:])
		if err != nil {
			_ = rs.Close()
			return IRLRunArtifactManifest{}, nil, nil, err
		}
		rLen, _, err := dnslab.BuildLabResponseP1P4(qBuf[:qLen], seed+uint64(i), rBuf[:])
		if err != nil {
			_ = rs.Close()
			return IRLRunArtifactManifest{}, nil, nil, err
		}

		if _, err := rs.RecordDNSMessage(qBuf[:qLen], ex.TimestampNs, clientIP, serverIP); err != nil {
			_ = rs.Close()
			return IRLRunArtifactManifest{}, nil, nil, err
		}
		totalFrames++

		if _, err := rs.RecordDNSMessage(rBuf[:rLen], ex.TimestampNs+2_000_000, serverIP, clientIP); err != nil {
			_ = rs.Close()
			return IRLRunArtifactManifest{}, nil, nil, err
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
		return IRLRunArtifactManifest{}, nil, nil, err
	}

	vectors, states, err := extractBlindWireFeatures(frames, apexSuffix, false)
	if err != nil {
		return IRLRunArtifactManifest{}, nil, nil, err
	}

	corpus := &engine.EpisodeRunCorpus{
		RunID:   runID,
		Samples: make([]engine.EpisodeVectorSample, len(exchanges)),
	}
	streamPts := make([]engine.StreamEvalPoint, len(exchanges))
	for i, ex := range exchanges {
		st := states[i]
		streamPts[i] = engine.StreamEvalPoint{
			PacketIndex: i,
			TimestampNs: frames[i].TimestampNs,
			TrueFamily:  ex.Family,
			Subdomain:   st.Subdomain,
			Snap:        st.Snap,
			P3:          st.P3,
			P4:          st.P4,
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
			return IRLRunArtifactManifest{}, nil, nil, err
		}
	}
	gtPath := filepath.Join(outDir, runID+".ground_truth.jsonl")
	if err := os.WriteFile(gtPath, gtBuf.Bytes(), 0o644); err != nil {
		return IRLRunArtifactManifest{}, nil, nil, err
	}

	pcapSHA, err := fileSHA256Hex(rs.PCAPPath())
	if err != nil {
		return IRLRunArtifactManifest{}, nil, nil, err
	}
	epSHA, err := fileSHA256Hex(rs.JSONLPath())
	if err != nil {
		return IRLRunArtifactManifest{}, nil, nil, err
	}
	gtSHA, err := fileSHA256Hex(gtPath)
	if err != nil {
		return IRLRunArtifactManifest{}, nil, nil, err
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
	}, corpus, streamPts, nil
}

// RunIRLDilutedBench exécute de bout en bout les campagnes diluées Run-A et Run-B,
// enregistre les PCAP et JSONL synchronisés, valide la preuve OOS et le TTD,
// et scelle le manifest.json SHA-256 croisé ainsi que les règles BlueTeam.
func RunIRLDilutedBench(outDir string, seedA, seedB uint64) (IRLBenchSummary, error) {
	if seedA == seedB {
		return IRLBenchSummary{}, dnslab.ErrSameRunLeak
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return IRLBenchSummary{}, err
	}

	runAID := fmt.Sprintf("irl-run-a-%08x", seedA)
	runBID := fmt.Sprintf("irl-run-b-%08x", seedB)

	manA, corpusA, _, err := executeAndRecordDilutedRun(outDir, runAID, "a", seedA)
	if err != nil {
		return IRLBenchSummary{}, err
	}
	manB, corpusB, streamB, err := executeAndRecordDilutedRun(outDir, runBID, "b", seedB)
	if err != nil {
		return IRLBenchSummary{}, err
	}

	proof, err := engine.ProvePatternOutOfSample(corpusA, corpusB)
	if err != nil {
		return IRLBenchSummary{}, err
	}
	ttd, err := engine.ComputeStreamTTD(streamB)
	if err != nil {
		return IRLBenchSummary{}, err
	}
	bt, err := engine.ExportBlueTeamArtifacts(proof, engine.DefaultPhysicalBounds())
	if err != nil {
		return IRLBenchSummary{}, err
	}

	if err := os.WriteFile(filepath.Join(outDir, "sigma_dns_p1_p4.yml"), []byte(bt.SigmaRulesYAML), 0o644); err != nil {
		return IRLBenchSummary{}, err
	}
	if err := os.WriteFile(filepath.Join(outDir, "suricata_dns_p1_p4.rules"), []byte(bt.SuricataRules), 0o644); err != nil {
		return IRLBenchSummary{}, err
	}

	benignFP := 0
	for _, rep := range ttd {
		if rep.BenignFalsePositives > benignFP {
			benignFP = rep.BenignFalsePositives
		}
	}

	manifestPath := filepath.Join(outDir, "manifest.json")
	summary := IRLBenchSummary{
		ManifestA:            manA,
		ManifestB:            manB,
		ManifestJSONPath:     manifestPath,
		OOSProof:             proof,
		TTDByFamily:          ttd,
		BlueTeam:             bt,
		BenignFalsePositives: benignFP,
	}

	rawManifest, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return IRLBenchSummary{}, err
	}
	if err := os.WriteFile(manifestPath, rawManifest, 0o644); err != nil {
		return IRLBenchSummary{}, err
	}
	return summary, nil
}
