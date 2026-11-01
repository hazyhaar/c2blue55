package engine

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// ErrDeltaContract signale une recompilation différentielle refusée (base
// illisible, aucune vue manquée, sortie non écrite).
var ErrDeltaContract = errors.New("engine: recompilation differentielle hors contrat")

// DeltaReport décrit une recompilation différentielle sur fichier (strate S-07).
type DeltaReport struct {
	BaseSHA256      string
	OutSHA256       string
	CentroidsBefore int
	CentroidsAdded  int
	MissedIn        int
	MissedAfter     int
	BenignFPBefore  int
	BenignFPAfter   int
}

// PatternProof est le triplet opposable d'un motif prouvé.
type PatternProof struct {
	RunID          string
	Family         string
	FNBefore       int
	FNAfter        int
	FPBefore       int
	FPAfter        int
	Proven         bool
	AlreadyCovered bool
}

// RecompileDNSTunnelDelta recompile la disquette de base avec les centroïdes
// découverts sur les vues manquées, vers outPath (atomique, HMAC).
func RecompileDNSTunnelDelta(basePath, outPath string, missed []DNSQueryView, hmacKey []byte) (report DeltaReport, err error) {
	if len(missed) == 0 {
		return report, ErrDeltaContract
	}
	base, err := LoadFloppyMmap(basePath, hmacKey)
	if err != nil {
		return report, fmt.Errorf("base: %w", err)
	}
	baseClosed := false
	defer func() {
		if !baseClosed {
			err = errors.Join(err, base.Close())
		}
	}()

	baseHash, err := deltaFileSHA256(basePath)
	if err != nil {
		return report, err
	}
	candidates, err := DiscoverRedhostPatterns(missed, base, nil)
	if err != nil {
		return report, err
	}
	entries := make([]CodebookEntry, 0, len(base.Entries)+len(candidates))
	entries = append(entries, base.Entries...)
	seen := make(map[[codebookWords]uint64]struct{}, len(base.Entries)+len(candidates))
	for _, entry := range base.Entries {
		seen[entry.Bitcode] = struct{}{}
	}
	for _, candidate := range candidates {
		if _, exists := seen[candidate.Bitcode]; exists {
			continue
		}
		seen[candidate.Bitcode] = struct{}{}
		entries = append(entries, candidate)
	}

	// SaveFloppyFile publie déjà atomiquement son chemin ; ce chemin est ici
	// une préparation privée, que seul le dernier renommage rend visible.
	staging, err := os.CreateTemp(filepath.Dir(outPath), "."+filepath.Base(outPath)+".tmp-*")
	if err != nil {
		return report, err
	}
	stagingPath := staging.Name()
	defer func() {
		removeErr := os.Remove(stagingPath)
		if err != nil {
			err = errors.Join(err, removeErr)
		} else if removeErr != nil && !errors.Is(removeErr, fs.ErrNotExist) {
			err = removeErr
		}
	}()
	if err = staging.Close(); err != nil {
		return report, err
	}
	if err = SaveFloppyFile(stagingPath, base.Header.FamilyID, base.Keywords, entries, base.Head, base.Prototypes, base.Header.BlockRadius, hmacKey); err != nil {
		return report, err
	}
	updated, err := LoadFloppyMmap(stagingPath, hmacKey)
	if err != nil {
		return report, err
	}
	remaining := 0
	for _, view := range missed {
		if EvaluateDNSView(view, updated, nil).Action != VerdictBlock {
			remaining++
		}
	}
	if err = updated.Close(); err != nil {
		return report, err
	}
	outHash, err := deltaFileSHA256(stagingPath)
	if err != nil {
		return report, err
	}
	closeErr := base.Close()
	baseClosed = true
	if closeErr != nil {
		return report, closeErr
	}
	if err = os.Rename(stagingPath, outPath); err != nil {
		return report, err
	}
	// Les vues bénignes ne sont pas fournies à cette fonction : seuls
	// ProvePattern et son corpus bénin peuvent mesurer les faux positifs.
	return DeltaReport{
		BaseSHA256: baseHash, OutSHA256: outHash,
		CentroidsBefore: int(base.Header.EntryCount), CentroidsAdded: len(entries) - len(base.Entries),
		MissedIn: len(missed), MissedAfter: remaining,
	}, nil
}

// ProvePattern mesure l'évasion sur N, la correction sur N+1 et les FP du bénin
// pour les vues hostiles d'un run (runID, family).
func ProvePattern(baseDisk, newDisk *FloppyDisk, runID, family string, hostile, benign []DNSQueryView) (PatternProof, error) {
	if baseDisk == nil || newDisk == nil {
		return PatternProof{}, ErrDeltaContract
	}
	proof := PatternProof{RunID: runID, Family: family}
	for _, view := range hostile {
		if EvaluateDNSView(view, baseDisk, nil).Action != VerdictBlock {
			proof.FNBefore++
		}
		if EvaluateDNSView(view, newDisk, nil).Action != VerdictBlock {
			proof.FNAfter++
		}
	}
	for _, view := range benign {
		if EvaluateDNSView(view, baseDisk, nil).Action == VerdictBlock {
			proof.FPBefore++
		}
		if EvaluateDNSView(view, newDisk, nil).Action == VerdictBlock {
			proof.FPAfter++
		}
	}
	proof.Proven = proof.FNBefore > 0 && proof.FNAfter == 0 && proof.FPAfter <= proof.FPBefore
	proof.AlreadyCovered = proof.FNBefore == 0 && proof.FNAfter == 0
	return proof, nil
}

func deltaFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, file)
	closeErr := file.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}
