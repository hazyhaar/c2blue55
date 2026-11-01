package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

func runDNSDelta(args []string, output io.Writer) (code int, err error) {
	flags := flag.NewFlagSet("dns-delta", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	basePath := flags.String("base", "", "Disquette DNS de base")
	labDir := flags.String("lab", "", "Répertoire des captures du laboratoire")
	runID := flags.String("run", "", "Identifiant du run hostile")
	benignID := flags.String("benign", "", "Identifiant du run bénin")
	outPath := flags.String("out", "", "Disquette différentielle en sortie")
	proofPath := flags.String("proof", "", "Chemin de la preuve JSON")
	if err = flags.Parse(args); err != nil {
		return 2, err
	}
	if flags.NArg() != 0 || *basePath == "" || *labDir == "" || *runID == "" || *benignID == "" || *outPath == "" || *proofPath == "" {
		return 2, fmt.Errorf("dns-delta exige -base, -lab, -run, -benign, -out et -proof, sans argument supplémentaire")
	}
	hostileRun, err := c2blue55.IngestRedhostLabRun(filepath.Join(*labDir, *runID+".pcap"), filepath.Join(*labDir, *runID+".manifest.json"))
	if err != nil {
		return 2, fmt.Errorf("run hostile: %w", err)
	}
	benignRun, err := c2blue55.IngestRedhostLabRun(filepath.Join(*labDir, *benignID+".pcap"), filepath.Join(*labDir, *benignID+".manifest.json"))
	if err != nil {
		return 2, fmt.Errorf("run bénin: %w", err)
	}
	key := engine.WittgensteinFloppyKey(engine.FloppyFamilyDNSC2)
	baseDisk, err := engine.LoadFloppyMmap(*basePath, key)
	if err != nil {
		return 2, fmt.Errorf("disquette de base: %w", err)
	}
	defer func() {
		err = errors.Join(err, baseDisk.Close())
		if err != nil {
			code = 2
		}
	}()
	hostile := hostileRun.QueryViews()
	missed := make([]engine.DNSQueryView, 0, len(hostile))
	for _, view := range hostile {
		if engine.EvaluateDNSView(view, baseDisk, nil).Action != engine.VerdictBlock {
			missed = append(missed, view)
		}
	}
	if len(missed) == 0 {
		if _, err = fmt.Fprintln(output, "aucune vue manquee : motif deja couvert"); err != nil {
			return 2, err
		}
		return 3, nil
	}
	delta, err := engine.RecompileDNSTunnelDelta(*basePath, *outPath, missed, key)
	if err != nil {
		return 2, err
	}
	newDisk, err := engine.LoadFloppyMmap(*outPath, key)
	if err != nil {
		return 2, fmt.Errorf("disquette différentielle: %w", err)
	}
	defer func() {
		err = errors.Join(err, newDisk.Close())
		if err != nil {
			code = 2
		}
	}()
	family := hostileRun.Manifest.Family
	if family == "" {
		family = hostileRun.Manifest.Label
	}
	proof, err := engine.ProvePattern(baseDisk, newDisk, *runID, family, hostile, benignRun.QueryViews())
	if err != nil {
		return 2, err
	}
	delta.BenignFPBefore = proof.FPBefore
	delta.BenignFPAfter = proof.FPAfter
	if err = writeDNSDeltaProof(*proofPath, delta, proof); err != nil {
		return 2, err
	}
	if _, err = fmt.Fprintf(output, "FNBefore=%d FNAfter=%d FPAfter=%d\n", proof.FNBefore, proof.FNAfter, proof.FPAfter); err != nil {
		return 2, err
	}
	if !proof.Proven {
		return 4, nil
	}
	return 0, nil
}

func writeDNSDeltaProof(path string, delta engine.DeltaReport, proof engine.PatternProof) (err error) {
	payload, err := json.MarshalIndent(struct {
		Delta engine.DeltaReport  `json:"delta"`
		Proof engine.PatternProof `json:"proof"`
	}{delta, proof}, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	stagingPath := file.Name()
	defer os.Remove(stagingPath)
	defer func() {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
	}()
	if err = file.Chmod(0o600); err != nil {
		return err
	}
	if _, err = file.Write(payload); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	closeErr := file.Close()
	file = nil
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(stagingPath, path); err != nil {
		return err
	}
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	return errors.Join(syncErr, directory.Close())
}
