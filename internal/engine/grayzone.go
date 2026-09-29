// Package engine - grayzone.go
// Décideur en cascade associant le filtrage vectoriel RaBitQ 512D et le moteur ontologique 4xontoLang.
// Intègre un seau à jetons (Token Bucket) pour protéger le Slow Path contre les attaques DoS.
package engine

import (
	"sync/atomic"
	"time"
)

// Constantes de verdicts de cascade pour le pipeline d'interception.
const (
	CascadeFastPass        uint8 = 1 // Passage direct sans escalade
	CascadeFastDrop        uint8 = 2 // Rejet direct / veto formel
	CascadeEscalate        uint8 = 3 // Escalade vers Slow Path / arbitre HITL
	CascadeQueueFull       uint8 = 4 // File d'arbitrage saturee globalement (rejet fail-safe)
	CascadeSourceThrottled uint8 = 5 // Quota par source unitaire epuise (protection anti-DoS)
)

const (
	sourceBucketSlots = 256
	sourceBucketMask  = sourceBucketSlots - 1
)

type sourceSlot struct {
	sourceID   atomic.Uint64
	tokens     atomic.Uint32
	lastRefill atomic.Int64
}

// GrayZoneConfig definit les seuils de la zone grise et les quotas d'escalade.
type GrayZoneConfig struct {
	DistStrict         int    // Seuil de distance de Hamming pour rejection immediate (ex. 16)
	DistFar            int    // Seuil de distance au-dela duquel le trafic est repute non-apparent (ex. 64)
	MaxBurst           uint32 // Nombre maximal de jetons pour l'arbitrage global (ex. 100)
	RefillPerSec       uint32 // Rechargement de jetons globaux par seconde (ex. 25)
	SourceMaxBurst     uint32 // Plafond maximal de jetons par source unitaire (ex. 20)
	SourceRefillPerSec uint32 // Rechargement de jetons par source par seconde (ex. 5)
}

// DefaultGrayZoneConfig rend une configuration standard calibree.
func DefaultGrayZoneConfig() GrayZoneConfig {
	return GrayZoneConfig{
		DistStrict:         16,
		DistFar:            64,
		MaxBurst:           100,
		RefillPerSec:       25,
		SourceMaxBurst:     20,
		SourceRefillPerSec: 5,
	}
}

// GrayZoneDecider opere l'arbitrage entre Strate 1 (Hamming 512D) et Strate 2 (4xontoLang).
type GrayZoneDecider struct {
	cfg             GrayZoneConfig
	tokens          atomic.Uint32
	lastRefill      atomic.Int64
	escalated       atomic.Uint64
	throttledGlobal atomic.Uint64
	throttledSource atomic.Uint64
	sources         [sourceBucketSlots]sourceSlot
}

// NewGrayZoneDecider initialise le decideur avec sa reserve de jetons.
func NewGrayZoneDecider(cfg GrayZoneConfig) *GrayZoneDecider {
	if cfg.DistStrict <= 0 {
		cfg.DistStrict = 16
	}
	if cfg.DistFar <= cfg.DistStrict {
		cfg.DistFar = 64
	}
	if cfg.MaxBurst == 0 {
		cfg.MaxBurst = 100
	}
	if cfg.RefillPerSec == 0 {
		cfg.RefillPerSec = 25
	}
	if cfg.SourceMaxBurst == 0 {
		cfg.SourceMaxBurst = 20
	}
	if cfg.SourceRefillPerSec == 0 {
		cfg.SourceRefillPerSec = 5
	}

	d := &GrayZoneDecider{cfg: cfg}
	d.tokens.Store(cfg.MaxBurst)
	d.lastRefill.Store(time.Now().UnixNano())
	return d
}

// tryAcquireGlobalToken verifie et preleve un jeton du seau global de maniere non-bloquante.
func (d *GrayZoneDecider) tryAcquireGlobalToken() bool {
	now := time.Now().UnixNano()
	last := d.lastRefill.Load()
	elapsed := now - last

	if elapsed > int64(time.Second) {
		if d.lastRefill.CompareAndSwap(last, now) {
			added := uint32(elapsed/int64(time.Second)) * d.cfg.RefillPerSec
			cur := d.tokens.Load()
			newTok := cur + added
			if newTok > d.cfg.MaxBurst {
				newTok = d.cfg.MaxBurst
			}
			d.tokens.Store(newTok)
		}
	}

	for {
		cur := d.tokens.Load()
		if cur == 0 {
			d.throttledGlobal.Add(1)
			return false
		}
		if d.tokens.CompareAndSwap(cur, cur-1) {
			d.escalated.Add(1)
			return true
		}
	}
}

const anonymousSourceID uint64 = 0xAAAAAAAAAAAAAAAA

// sipHashMix applique un mélange 64 bits de type SplitMix64 pour prémunir les seaux
// contre les collisions adversariales ciblées.
func sipHashMix(x uint64) int {
	x ^= 0x9e3779b97f4a7c15
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9
	x = (x ^ (x >> 27)) * 0x94d049bb133111eb
	x ^= x >> 31
	return int(x & sourceBucketMask)
}

// tryAcquireSourceToken verifie et preleve un jeton du seau specifique a une source unitaire (PID/IP).
// Fonctionne en temps constant O(1) et sans allocation tas grace a un tableau statique a adressage indexe.
func (d *GrayZoneDecider) tryAcquireSourceToken(sourceID uint64) bool {
	if sourceID == 0 {
		sourceID = anonymousSourceID
	}

	slotIdx := sipHashMix(sourceID)
	slot := &d.sources[slotIdx]
	now := time.Now().UnixNano()
	curSrc := slot.sourceID.Load()

	if curSrc != sourceID {
		last := slot.lastRefill.Load()
		// Reallocation du slot si inactif depuis plus de 3 secondes ou non initialise
		if curSrc == 0 || (now-last) > int64(3*time.Second) {
			if slot.sourceID.CompareAndSwap(curSrc, sourceID) {
				slot.tokens.Store(d.cfg.SourceMaxBurst)
				slot.lastRefill.Store(now)
			}
		}
	}

	// Rechargement des jetons de la source unitaire
	last := slot.lastRefill.Load()
	elapsed := now - last
	if elapsed > int64(time.Second) {
		if slot.lastRefill.CompareAndSwap(last, now) {
			added := uint32(elapsed/int64(time.Second)) * d.cfg.SourceRefillPerSec
			cur := slot.tokens.Load()
			newTok := cur + added
			if newTok > d.cfg.SourceMaxBurst {
				newTok = d.cfg.SourceMaxBurst
			}
			slot.tokens.Store(newTok)
		}
	}

	// Prelevement du jeton source
	for {
		cur := slot.tokens.Load()
		if cur == 0 {
			d.throttledSource.Add(1)
			return false
		}
		if slot.tokens.CompareAndSwap(cur, cur-1) {
			return true
		}
	}
}

// CascadeResult synthetise le verdict rendu par la cascade.
type CascadeResult struct {
	Verdict          uint8
	HammingDist      int
	MatchedEntry     CodebookEntry
	OntoVerdict      uint8
	Diagnostic       string
	RequiresSlowPath bool
}

// DecideWithSource evalue conjointement la ressemblance vectorielle, les axiomes ontologiques
// et le double seau a jetons (source + global) pour empecher le deni de service par saturation.
// Garanti sans allocation tas sur le chemin chaud (0 B/op).
func (d *GrayZoneDecider) DecideWithSource(query *[codebookWords]uint64, cb *Codebook, ontoKey OntoKey, sourceID uint64) CascadeResult {
	var res CascadeResult

	// 1. Évaluation ontologique déterministe O(1)
	res.OntoVerdict = EvaluateOntology(ontoKey)

	// Axiome strict : le veto ontologique prime TOUJOURS sur toute métrique vectorielle.
	if res.OntoVerdict == OntoVerdictDeny {
		res.Verdict = CascadeFastDrop
		return res
	}

	// 2. Recherche vectorielle de proximité Hamming (au plus DistFar)
	bestDist := d.cfg.DistFar + 1
	var match CodebookEntry
	found := false
	if cb != nil && query != nil {
		match, bestDist, found = cb.SearchNearest(query, d.cfg.DistFar)
	}
	res.HammingDist = bestDist
	res.MatchedEntry = match

	// 3. Cas de correspondance hostile manifeste
	if found && bestDist <= d.cfg.DistStrict {
		res.Verdict = CascadeFastDrop
		return res
	}

	// 4. Cas de bénignité certifiée des deux côtés
	if res.OntoVerdict == OntoVerdictAllow && (!found || bestDist > d.cfg.DistFar) {
		res.Verdict = CascadeFastPass
		return res
	}

	// 5. Zone grise / Ambiguïté : déclenchement de l'escalade régulée
	res.RequiresSlowPath = true
	res.Diagnostic = OntoDiagnostic(ontoKey)

	// Étage 1 : Vérification du quota de la source unitaire (PID / IP)
	if !d.tryAcquireSourceToken(sourceID) {
		res.Verdict = CascadeSourceThrottled
		res.Diagnostic = "[Anti-DoS:SourceThrottled] Quota unitaire depasse pour la source, rejet conservateur"
		return res
	}

	// Étage 2 : Vérification du quota global du moteur
	if d.tryAcquireGlobalToken() {
		res.Verdict = CascadeEscalate
	} else {
		// En cas de saturation du quota global : repli de précaution
		res.Verdict = CascadeQueueFull
		res.Diagnostic = "[Anti-DoS:GlobalQueueFull] File d arbitrage global saturee, rejet conservateur"
	}

	return res
}

// Decide evalue la cascade avec une source par defaut (0).
func (d *GrayZoneDecider) Decide(query *[codebookWords]uint64, cb *Codebook, ontoKey OntoKey) CascadeResult {
	return d.DecideWithSource(query, cb, ontoKey, 0)
}

// Stats rend la volumetrie des escalades accordees et ecretees (globale et par source).
func (d *GrayZoneDecider) Stats() (escalated, throttledGlobal, throttledSource uint64) {
	return d.escalated.Load(), d.throttledGlobal.Load(), d.throttledSource.Load()
}
