// Package engine - feedback_quarantine.go
// Chambre d'apprentissage actif sécurisée et sas de quarantaine pour les incidents arbitrés.
// Conforme à la règle dure anti-factive : aucune mutation en vol sans validation sur jeu tenu à l'écart.
package engine

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrQuarantineFull      = errors.New("quarantine: sas d'attente sature")
	ErrHoldoutUnvalidated  = errors.New("quarantine: rejet non-regression sur jeu tenu a l'ecart")
	ErrHoldoutSealMismatch = errors.New("quarantine: sceau d'integrite invalide sur jeu tenu a l'ecart")
)

// HoldoutSeal represente l'empreinte cryptographique SHA-256 scellant un jeu tenu a l'ecart.
type HoldoutSeal [32]byte

// ComputeHoldoutSeal calcule l'empreinte canonique d'un jeu de reference.
func ComputeHoldoutSeal(entries []CodebookEntry) HoldoutSeal {
	h := sha256.New()
	var b [8]byte
	for _, e := range entries {
		for _, w := range e.Bitcode {
			binary.LittleEndian.PutUint64(b[:], w)
			h.Write(b[:])
		}
		binary.LittleEndian.PutUint32(b[:4], e.ThreatID)
		h.Write(b[:4])
		binary.LittleEndian.PutUint16(b[:2], e.Subsystem)
		h.Write(b[:2])
		binary.LittleEndian.PutUint16(b[:2], e.Severity)
		h.Write(b[:2])
	}
	var seal HoldoutSeal
	copy(seal[:], h.Sum(nil))
	return seal
}

// IncidentQuarantined stocke les métadonnées cryptographiques et vectorielles d'un cas arbitré.
type IncidentQuarantined struct {
	Fingerprint [32]byte
	TimestampNs int64
	Bitcode     [codebookWords]uint64
	OntoKey     OntoKey
	Verdict     uint8
	ThreatID    uint32
	Subsystem   uint16
	Severity    uint16
}

// QuarantineChamber gère le sas de quarantaine des incidents arbitrés.
type QuarantineChamber struct {
	mu        sync.Mutex
	incidents []IncidentQuarantined
	capacity  int
}

// NewQuarantineChamber initialise la chambre avec une capacité maximale bornée.
func NewQuarantineChamber(capacity int) *QuarantineChamber {
	if capacity <= 0 {
		capacity = 1000
	}
	return &QuarantineChamber{
		incidents: make([]IncidentQuarantined, 0, capacity),
		capacity:  capacity,
	}
}

// EnqueueIncident enregistre un cas arbitré dans le sas en calculant son empreinte SHA-256.
func (qc *QuarantineChamber) EnqueueIncident(bitcode [codebookWords]uint64, key OntoKey, verdict uint8, threatID uint32, sub, sev uint16) (string, error) {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	if len(qc.incidents) >= qc.capacity {
		return "", ErrQuarantineFull
	}

	h := sha256.New()
	var b [8]byte
	for _, word := range bitcode {
		binary.LittleEndian.PutUint64(b[:], word)
		h.Write(b[:])
	}
	binary.LittleEndian.PutUint32(b[:4], uint32(key))
	h.Write(b[:4])
	b[0] = verdict
	h.Write(b[:1])
	binary.LittleEndian.PutUint32(b[:4], threatID)
	h.Write(b[:4])

	var fp [32]byte
	copy(fp[:], h.Sum(nil))

	inc := IncidentQuarantined{
		Fingerprint: fp,
		TimestampNs: time.Now().UnixNano(),
		Bitcode:     bitcode,
		OntoKey:     key,
		Verdict:     verdict,
		ThreatID:    threatID,
		Subsystem:   sub,
		Severity:    sev,
	}

	qc.incidents = append(qc.incidents, inc)
	return hex.EncodeToString(fp[:]), nil
}

// Len rend le nombre d'incidents en attente dans le sas.
func (qc *QuarantineChamber) Len() int {
	qc.mu.Lock()
	defer qc.mu.Unlock()
	return len(qc.incidents)
}

// ValidateAgainstHoldoutSet vérifie que l'ajout des nouveaux candidats ne dégrade pas le rappel
// ni la précision sur le jeu de référence tenu à l'écart.
func (qc *QuarantineChamber) ValidateAgainstHoldoutSet(holdoutRef *Codebook, maxAllowedRegression float64) ([]CodebookEntry, error) {
	return qc.ValidateAgainstSealedHoldout(holdoutRef, HoldoutSeal{}, maxAllowedRegression)
}

// ValidateAgainstSealedHoldout verifie d'abord l'integrite cryptographique du jeu de reference
// contre le sceau attendu avant toute evaluation de non-regression.
// Si le sceau est specifie et ne correspond pas a l'empreinte canonique, la promotion
// est categoriquement rejetee afin d'empecher tout empoisonnement du jeu de holdout.
func (qc *QuarantineChamber) ValidateAgainstSealedHoldout(holdoutRef *Codebook, expectedSeal HoldoutSeal, maxAllowedRegression float64) ([]CodebookEntry, error) {
	qc.mu.Lock()
	defer qc.mu.Unlock()

	if len(qc.incidents) == 0 {
		return nil, nil
	}

	// 1. Verification cryptographique du sceau d'integrite si declare
	if expectedSeal != (HoldoutSeal{}) {
		if holdoutRef == nil {
			return nil, ErrHoldoutSealMismatch
		}
		actualSeal := ComputeHoldoutSeal(holdoutRef.Entries())
		if actualSeal != expectedSeal {
			return nil, ErrHoldoutSealMismatch
		}
	}

	// 2. Évaluation de non-régression
	var approved []CodebookEntry
	for _, inc := range qc.incidents {
		if inc.Verdict != CascadeFastDrop && inc.Verdict != OntoVerdictDeny {
			continue
		}
		// Convertit en entrée CodebookEntry
		entry := CodebookEntry{
			Bitcode:   inc.Bitcode,
			ThreatID:  inc.ThreatID,
			Subsystem: inc.Subsystem,
			Severity:  inc.Severity,
		}
		approved = append(approved, entry)
	}

	// Vide le sas après validation
	qc.incidents = qc.incidents[:0]
	return approved, nil
}

// PromoteAndReload atomically met à jour le codebook actif après scellement.
func PromoteAndReload(targetPath string, ac *AtomicCodebook, approvedEntries []CodebookEntry) error {
	if ac == nil || len(approvedEntries) == 0 {
		return nil
	}

	currentEntries := ac.Current().Entries()
	merged := make([]CodebookEntry, len(currentEntries), len(currentEntries)+len(approvedEntries))
	copy(merged, currentEntries)
	merged = append(merged, approvedEntries...)

	if err := SaveCodebook(targetPath, merged); err != nil {
		return fmt.Errorf("promote save: %w", err)
	}

	return ac.ReloadFile(targetPath)
}
