package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/engine"
)

func TestRunAgentRecordCLI(t *testing.T) {
	dir := t.TempDir()

	// 1. Scénario hostile SH-S18c-01 : absence de --record-dir ou de --pcap.
	if rc := RunAgentRecordCLI([]string{}); rc == 0 {
		t.Fatalf("attendu rc != 0 sans arguments")
	}
	if rc := RunAgentRecordCLI([]string{"--record-dir", dir}); rc == 0 {
		t.Fatalf("attendu rc != 0 sans --pcap")
	}

	// 2. Création d'un PCAP source contenant un échange DNS valide.
	qwire := append(buildCLIDNSName("p1dl01.irl-p1-01.org"), 0, 16, 0, 1)
	hdrQ := make([]byte, 12)
	binary.BigEndian.PutUint16(hdrQ[0:], 0x5151)
	binary.BigEndian.PutUint16(hdrQ[2:], 0x0100)
	binary.BigEndian.PutUint16(hdrQ[4:], 1)
	query := append(hdrQ, qwire...)

	pcap := make([]byte, 24)
	binary.LittleEndian.PutUint32(pcap[0:], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(pcap[4:], 2)
	binary.LittleEndian.PutUint16(pcap[6:], 4)
	binary.LittleEndian.PutUint32(pcap[16:], 65535)
	binary.LittleEndian.PutUint32(pcap[20:], 1)

	pkt := buildCLIEthUDPFrame(51000, 53, query)
	rec := make([]byte, 16)
	binary.LittleEndian.PutUint32(rec[0:], 1785000000)
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(pkt)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(pkt)))
	pcap = append(pcap, rec...)
	pcap = append(pcap, pkt...)

	srcPcap := filepath.Join(dir, "input.pcap")
	if err := os.WriteFile(srcPcap, pcap, 0o600); err != nil {
		t.Fatal(err)
	}

	// 3. Sans --oos-proof, --export-blueteam doit échouer et ne générer aucune règle factice.
	recDirSansPreuve := filepath.Join(dir, "recorded-sans-preuve")
	btDirSansPreuve := filepath.Join(dir, "blueteam-sans-preuve")
	if rcSansPreuve := RunAgentRecordCLI([]string{
		"--pcap", srcPcap,
		"--record-dir", recDirSansPreuve,
		"--run-id", "rec-sans-preuve",
		"--export-blueteam", btDirSansPreuve,
	}); rcSansPreuve == 0 {
		t.Errorf("RunAgentRecordCLI --export-blueteam sans --oos-proof a reussi (rc=0) alors qu'il doit echouer")
	}
	for _, regleInterdite := range []string{
		filepath.Join(btDirSansPreuve, "sigma_rules.yml"),
		filepath.Join(btDirSansPreuve, "suricata.rules"),
	} {
		if _, errStat := os.Stat(regleInterdite); !errors.Is(errStat, os.ErrNotExist) {
			t.Errorf("regle factice ecrite sans preuve OOS (%s): errStat=%v", regleInterdite, errStat)
		}
	}

	// 4. Avec une preuve OOS réelle calculée par ProvePatternOutOfSample, l'export BlueTeam réussit.
	corpusA := &engine.EpisodeRunCorpus{RunID: "cli-oos-run-a"}
	corpusB := &engine.EpisodeRunCorpus{RunID: "cli-oos-run-b"}
	corpusA.Samples = append(corpusA.Samples, engine.EpisodeVectorSample{
		Family: "BENIGN", DomainApex: "benin-a.example", Features: [8]float32{0, 0, 0, 0, 0, 0, 0, 0},
	})
	corpusB.Samples = append(corpusB.Samples, engine.EpisodeVectorSample{
		Family: "BENIGN", DomainApex: "benin-b.example", Features: [8]float32{0.05, 0.05, 0, 0, 0, 0, 0, 0},
	})
	for indiceFamille, nomFamille := range []string{"P1", "P2", "P3", "P4"} {
		var vecteurFamille [8]float32
		vecteurFamille[indiceFamille] = 10.0
		corpusA.Samples = append(corpusA.Samples, engine.EpisodeVectorSample{
			Family:     nomFamille,
			DomainApex: "a-" + strings.ToLower(nomFamille) + ".example",
			Features:   vecteurFamille,
		})
		corpusB.Samples = append(corpusB.Samples, engine.EpisodeVectorSample{
			Family:     nomFamille,
			DomainApex: "b-" + strings.ToLower(nomFamille) + ".example",
			Features:   vecteurFamille,
		})
	}
	preuveReelle, errPreuve := engine.ProvePatternOutOfSample(corpusA, corpusB)
	if errPreuve != nil || !preuveReelle.AllPass {
		t.Fatalf("ProvePatternOutOfSample: err=%v AllPass=%v", errPreuve, preuveReelle.AllPass)
	}
	octetsPreuve, errJSON := json.Marshal(preuveReelle)
	if errJSON != nil {
		t.Fatalf("json.Marshal(preuveReelle): %v", errJSON)
	}
	oosProofPath := filepath.Join(dir, "oos_proof.json")
	if errWrite := os.WriteFile(oosProofPath, octetsPreuve, 0o600); errWrite != nil {
		t.Fatalf("WriteFile(oos_proof.json): %v", errWrite)
	}

	recDir := filepath.Join(dir, "recorded")
	btDir := filepath.Join(dir, "blueteam")
	rc := RunAgentRecordCLI([]string{
		"--pcap", srcPcap,
		"--record-dir", recDir,
		"--run-id", "rec-01",
		"--export-blueteam", btDir,
		"--oos-proof", oosProofPath,
	})
	if rc != 0 {
		t.Fatalf("RunAgentRecordCLI avec --oos-proof valide: rc=%d attendu 0", rc)
	}

	for _, p := range []string{
		filepath.Join(recDir, "rec-01.pcap"),
		filepath.Join(recDir, "rec-01.episodes.jsonl"),
		filepath.Join(btDir, "sigma_rules.yml"),
		filepath.Join(btDir, "suricata.rules"),
	} {
		st, err := os.Stat(p)
		if err != nil || st.Size() == 0 {
			t.Fatalf("artefact %s absent ou vide: err=%v", p, err)
		}
	}
}
