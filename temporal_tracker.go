// Package c2blue55 — Suivi temporel en mémoire vive (RAM) à zéro allocation (0 B/op).
// Détecte le beaconing périodique régulier (battement de cœur C2) et la prolifération de sous-domaines.
package c2blue55

import (
	"math"
	"sync"
)

const (
	MaxTrackedDomains = 8192 // 8192 domaines surveillés simultanément en RAM (table contiguë, < 1 Go)
	HistoryWindowSize = 16   // 16 derniers timestamps par domaine
	// MaxInactivitySec borne la péremption de la fenêtre temporelle d'un domaine :
	// au-delà d'une heure sans requête, les anciens intervalles sont purgés pour ne pas
	// fausser le calcul de jitter avec des deltas vieux de plusieurs heures.
	MaxInactivitySec = 3600
	// SubdomainBloomWords dimensionne le filtre de cardinalité à 256 bits ([4]uint64).
	// Un filtre 64 bits sature dès 6 à 8 sous-domaines distincts ; 256 bits repoussent
	// la probabilité de collision à un niveau compatible avec une détection fiable.
	SubdomainBloomWords = 4
)

// DomainTrack keeps a 16-timestamp ring and approximate Bloom cardinality since
// the last inactivity reset. Cardinality is NOT an exact sliding-window count.
type DomainTrack struct {
	DomainHash       uint64
	Domain           [253]byte // Compare identity, not only its hash.
	DomainLen        uint8
	Timestamps       [HistoryWindowSize]uint32 // Timestamps Unix en secondes
	Head             uint8                     // Pointeur circulaire d'écriture
	Count            uint16                    // Nombre total de requêtes enregistrées
	LastSeen         uint32
	SubdomainBloom   [SubdomainBloomWords]uint64 // Filtre Bloom 256 bits pour les sous-domaines uniques
	UniqueSubdomains uint16
}

// resetWindow purge la fenêtre temporelle d'un slot tout en conservant son identité.
// Les timestamps résiduels deviennent inatteignables puisque Count repart à zéro.
func (d *DomainTrack) resetWindow() {
	d.Head = 0
	d.Count = 0
	d.LastSeen = 0
	d.SubdomainBloom = [SubdomainBloomWords]uint64{}
	d.UniqueSubdomains = 0
}

// mix64 est un brasseur splitmix64 sans allocation, utilisé comme seconde fonction
// de hachage indépendante du FNV-1a pour indexer le filtre de cardinalité.
func mix64(x uint64) uint64 {
	x += 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	return x ^ (x >> 31)
}

// TemporalTracker gère le pool statique de slots de suivi sans base de données.
type TemporalTracker struct {
	mu        sync.Mutex
	slots     [MaxTrackedDomains]DomainTrack
	evictions uint64
}

// Evictions counts active histories displaced by the bounded eight-slot probe.
func (tr *TemporalTracker) Evictions() uint64 {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return tr.evictions
}

// NewTemporalTracker initialise le gestionnaire de suivi temporel.
func NewTemporalTracker() *TemporalTracker {
	return &TemporalTracker{}
}

// RecordQuery aggregates its caller-supplied domain key, without client identity
// or public-suffix resolution. Evictions explicitly bound the retained history.
// Retourne le profil temporel calculé (jitter, sous-domaines uniques, requêtes récentes).
func (tr *TemporalTracker) RecordQuery(parentDomain string, subdomain string, nowSec uint32) (jitterPct uint16, uniqueSubs uint16, count uint16) {
	if len(parentDomain) == 0 || len(parentDomain) > 253 {
		return 100, 0, 0
	}

	h := FNV1a64String(parentDomain)
	slotIdx := int(h % MaxTrackedDomains)

	tr.mu.Lock()
	defer tr.mu.Unlock()

	var slot, recyclable *DomainTrack
	victim := &tr.slots[slotIdx]
	step := int((mix64(h) & 0x7) | 1)
	for i := 0; i < 8; i++ {
		candidate := &tr.slots[(slotIdx+i*step)%MaxTrackedDomains]
		if candidate.DomainLen != 0 && candidate.DomainHash == h && stringEqualBytes(parentDomain, candidate.Domain[:candidate.DomainLen]) {
			slot = candidate
			break
		}
		if recyclable == nil && (candidate.DomainLen == 0 || nowSec >= candidate.LastSeen && nowSec-candidate.LastSeen >= MaxInactivitySec) {
			recyclable = candidate
		}
		if candidate.LastSeen < victim.LastSeen {
			victim = candidate
		}
	}
	if slot == nil {
		slot = recyclable
		if slot == nil {
			slot = victim
			tr.evictions++
		}
		*slot = DomainTrack{DomainHash: h, DomainLen: uint8(len(parentDomain))}
		copy(slot.Domain[:], parentDomain)
	}

	// Péremption : le même domaine réapparaît après plus d'une heure d'inactivité.
	// Les anciens timestamps sont purgés pour ne pas biaiser le jitter avec des deltas périmés.
	if slot.Count > 0 && (nowSec < slot.LastSeen || nowSec-slot.LastSeen >= MaxInactivitySec) {
		slot.resetWindow()
	}

	// Enregistrement du timestamp
	slot.Timestamps[slot.Head] = nowSec
	slot.Head = (slot.Head + 1) % HistoryWindowSize
	if slot.Count < HistoryWindowSize {
		slot.Count++
	}
	slot.LastSeen = nowSec

	// Mise à jour du filtre Bloom 256 bits pour les sous-domaines uniques.
	// Deux positions issues de deux fonctions de hachage indépendantes (FNV-1a puis
	// brasseur splitmix64) réduisent drastiquement les collisions par rapport à un
	// unique filtre 64 bits. Aucune allocation : indexation directe de tableaux fixes.
	if len(subdomain) > 0 {
		h1 := FNV1a64String(subdomain)
		h2 := mix64(h1)
		w1 := (h1 >> 6) & (SubdomainBloomWords - 1)
		w2 := ((h1 + h2) >> 6) & (SubdomainBloomWords - 1)
		m1 := uint64(1) << (h1 & 63)
		m2 := uint64(1) << ((h1 + h2) & 63)
		if (slot.SubdomainBloom[w1]&m1) == 0 || (slot.SubdomainBloom[w2]&m2) == 0 {
			slot.SubdomainBloom[w1] |= m1
			slot.SubdomainBloom[w2] |= m2
			slot.UniqueSubdomains++
		}
	}

	// Calcul du Jitter (Coefficient de variation des intervalles d'arrivée)
	// Un jitter très faible (< 20%) indique un battement de cœur C2 régulier automatique.
	jitter := uint16(100)
	if slot.Count >= 4 {
		jitter = calculateJitter(slot)
	}

	return jitter, slot.UniqueSubdomains, slot.Count
}

// calculateJitter calcule le coefficient de variation (écart-type / moyenne en pourcentage)
// des intervalles temporels entre requêtes successives.
func calculateJitter(slot *DomainTrack) uint16 {
	n := int(slot.Count)
	if n < 4 {
		return 100
	}

	// Reconstitution chronologique des timestamps
	var sortedTs [HistoryWindowSize]uint32
	head := int(slot.Head)
	for i := 0; i < n; i++ {
		idx := (head - n + i + HistoryWindowSize) % HistoryWindowSize
		sortedTs[i] = slot.Timestamps[idx]
	}

	// Calcul des deltas (inter-arrival times)
	deltasCount := n - 1
	var sumDelta float64
	for i := 0; i < deltasCount; i++ {
		var diff uint32
		if sortedTs[i+1] >= sortedTs[i] {
			diff = sortedTs[i+1] - sortedTs[i]
		}
		sumDelta += float64(diff)
	}

	meanDelta := sumDelta / float64(deltasCount)
	// Si les requêtes arrivent toutes dans la même seconde (rafale brute), pas de périodicité beacon
	if meanDelta < 0.5 {
		return 100
	}

	var sumSqDiff float64
	for i := 0; i < deltasCount; i++ {
		var diff float64
		if sortedTs[i+1] >= sortedTs[i] {
			diff = float64(sortedTs[i+1] - sortedTs[i])
		}
		d := diff - meanDelta
		sumSqDiff += d * d
	}

	variance := sumSqDiff / float64(deltasCount)
	stdDev := math.Sqrt(variance)

	// Coefficient de variation = stdDev / mean * 100
	cv := (stdDev / meanDelta) * 100.0
	if cv > 100.0 {
		return 100
	}
	return uint16(cv)
}
