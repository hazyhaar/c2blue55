// Package c2blue55 — Moteur d'évaluation et de filtrage DNS haute cadence (Zero-DB, 0 B/op).
// Combine filtrage déterministe SIMD, réputation compacte et triage vers l'arbitre SLM.
package c2blue55

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

var (
	ErrPipelineClosed = errors.New("c2blue55: pipeline ferme")
	ErrSLMQueueFull   = errors.New("c2blue55: file arbitrage pleine; incident non depose")
	ErrSLMAbandoned   = errors.New("c2blue55: incidents non arbitres a la fermeture; consulter SLMAbandoned")
	ErrAuditQueueFull = errors.New("c2blue55: file audit pleine; preuve non conservee")
)

// Verdicts du pipeline
const (
	DecisionFastPass       uint8 = 1 // No heuristic escalation, not a benignness certificate.
	DecisionFastDrop       uint8 = 2 // Local deny-policy recommendation, not network enforcement.
	DecisionEscalateSLM    uint8 = 3 // Suspect; ArbitrationQueued reports actual queue acceptance.
	DecisionBlockedBySLM   uint8 = 4 // Model recommendation, not proof of an attack.
	DecisionWhitelistedSLM uint8 = 5 // Model recommendation, not proof of innocence.
)

// PipelineConfig configure le moteur de filtrage.
type PipelineConfig struct {
	LogPath            string // Fichier JSONL d'audit (ex: "c2_events.jsonl")
	EntropyThresholdQ8 uint32 // Seuil d'entropie Shannon Q8.8 (défaut: 1024 = 4.0 bits/byte)
	BeaconJitterMax    uint16 // Jitter max pour suspecter un beacon (défaut: 20%)
	UniqueSubThreshold uint16 // Seuil de sous-domaines uniques suspects (défaut: 5)
}

// Pipeline représente l'instance d'évaluation complète d'un nœud agent.
type Pipeline struct {
	cfg     PipelineConfig
	rep     *AtomicReputation
	tracker *TemporalTracker
	logFile *os.File
	logMu   sync.Mutex

	// File d'attente bornée pour l'arbitrage SLM asynchrone
	slmQueue          chan SLMIncident
	lifeMu            sync.RWMutex
	closed            bool
	workerStarted     bool
	workerCancel      context.CancelFunc
	workerWG          sync.WaitGroup
	closeOnce         sync.Once
	closeErr          error
	auditQueue        chan auditRecord
	auditWG           sync.WaitGroup
	auditClosed       bool
	auditErr          error
	slmRejected       atomic.Uint64
	slmAbandoned      atomic.Uint64
	arbitrationErrors atomic.Uint64
	auditRejected     atomic.Uint64
	auditErrors       atomic.Uint64
}

// PipelineStats distinguishes accepted work, loss and failed evidence writes.
type PipelineStats struct {
	SLMRejected, SLMAbandoned, ArbitrationErrors, AuditRejected, AuditErrors, TrackerEvictions uint64
}

func (p *Pipeline) Stats() PipelineStats {
	return PipelineStats{p.slmRejected.Load(), p.slmAbandoned.Load(), p.arbitrationErrors.Load(), p.auditRejected.Load(), p.auditErrors.Load(), p.tracker.Evictions()}
}

func (p *Pipeline) AuditError() error {
	p.logMu.Lock()
	defer p.logMu.Unlock()
	return p.auditErr
}

type auditRecord struct {
	Time       time.Time `json:"time"`
	Domain     string    `json:"domain"`
	Action     string    `json:"action"`
	Reason     string    `json:"reason"`
	Confidence float64   `json:"confidence"`
}

// SLMIncident représente le dossier médico-légal transmis à l'arbitre SLM.
type SLMIncident struct {
	Timestamp          uint64  `json:"timestamp"`
	FQDN               string  `json:"fqdn"`
	ParentDomain       string  `json:"parent_domain"`
	Subdomain          string  `json:"subdomain"`
	QType              uint16  `json:"qtype"`
	EntropyQ8          uint32  `json:"entropy_q8"`
	EntropyBits        float64 `json:"entropy_bits"`
	PayloadClass       uint16  `json:"payload_class"`
	JitterPct          uint16  `json:"jitter_pct"`
	UniqueSubdomains   uint16  `json:"unique_subdomains"`
	QueryCount         uint16  `json:"query_count"`
	SuspectedIndicator string  `json:"suspected_indicator"`
	HumanSummary       string  `json:"human_summary,omitempty"`
	RecommendedAction  string  `json:"recommended_action,omitempty"`
}

// EvaluationResult contient le verdict immédiat rendu par la sonde.
type EvaluationResult struct {
	Decision          uint8
	MatchedDomain     string
	MatchedCategory   uint8
	EntropyQ8         uint32
	PayloadClass      uint16
	JitterPct         uint16
	UniqueSubdomains  uint16
	Incident          *SLMIncident
	ArbitrationQueued bool
}

// NewPipeline initialise le pipeline avec sa table de réputation compacte et son tracker.
func NewPipeline(cfg PipelineConfig, repTable *ReputationTable) (*Pipeline, error) {
	if repTable == nil {
		var err error
		repTable, err = GetDefaultReputationTable()
		if err != nil {
			return nil, err
		}
	}

	if cfg.EntropyThresholdQ8 == 0 {
		cfg.EntropyThresholdQ8 = 1024 // 4.0 bits/byte
	}
	if cfg.BeaconJitterMax == 0 {
		cfg.BeaconJitterMax = 20 // 20%
	}
	if cfg.UniqueSubThreshold == 0 {
		cfg.UniqueSubThreshold = 5
	}

	var f *os.File
	if cfg.LogPath != "" {
		var err error
		f, err = os.OpenFile(cfg.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, err
		}
	}

	p := &Pipeline{
		cfg:      cfg,
		rep:      NewAtomicReputation(repTable),
		tracker:  NewTemporalTracker(),
		logFile:  f,
		slmQueue: make(chan SLMIncident, 64), // File bornée à 64 alertes max
	}
	if f != nil {
		p.auditQueue = make(chan auditRecord, 64)
		p.auditWG.Add(1)
		go func() {
			defer p.auditWG.Done()
			encoder := json.NewEncoder(f)
			for entry := range p.auditQueue {
				if err := encoder.Encode(entry); err != nil {
					p.auditErrors.Add(1)
					p.logMu.Lock()
					p.auditErr = err
					p.logMu.Unlock()
				}
			}
		}()
	}
	return p, nil
}

// Reputation retourne le conteneur atomique de réputation du pipeline.
func (p *Pipeline) Reputation() *AtomicReputation {
	return p.rep
}

// EvaluatePacket analyse un paquet DNS brut, extrait ses métriques et rend un verdict déterministe.
// The ordinary and reputation decision paths allocate no heap memory. Audit
// serialization runs separately and allocates; escalation owns copied strings.
// Tracking aggregates the last two labels across clients: no public suffix list,
// client attribution or CNAME response analysis is provided by this API.
func (p *Pipeline) EvaluatePacket(rawPacket []byte, nowSec uint32) (EvaluationResult, error) {
	p.lifeMu.RLock()
	defer p.lifeMu.RUnlock()
	var ev DNSEvent
	var res EvaluationResult
	if p.closed {
		return res, ErrPipelineClosed
	}

	if err := ParseDNSQuery(rawPacket, &ev); err != nil {
		return res, err
	}

	fqdn := ev.FQDN()
	if len(fqdn) == 0 {
		res.Decision = DecisionFastPass
		return res, nil
	}

	parent := ev.Parent()
	sub := ev.Sub()

	// 1. Échelon 1 : Vérification de la Table de Réputation Compacte (O(log N), < 1 µs)
	if match, ok := p.rep.Match(fqdn); ok {
		res.MatchedDomain = match.MatchedDomain
		res.MatchedCategory = match.Classification

		if match.Classification == RepClassBlockC2 {
			res.Decision = DecisionFastDrop
			return res, p.logEvent(match.MatchedDomain, "DROP_REPUTATION_POLICY", match.MatchedDomain, 0)
		}
	}

	// 2. Échelon 2 : Métrologie de l'Entropie de Shannon AVX2 en virgule fixe Q8.8.
	// Elle est mesurée avant la reconnaissance protocolaire afin que l'exemption
	// protocolaire exige une charge réellement courte et de faible entropie : un
	// sélecteur DKIM/DMARC/ACME légitime, jamais un tunnel déguisé sous son préfixe.
	var profile engine.C2bt_entropy_profile_t
	if ev.SubdomainLen > 0 {
		engine.C2bt_profile_payload(ev.Subdomain[:ev.SubdomainLen], uint64(ev.SubdomainLen), &profile)
	} else {
		engine.C2bt_profile_payload(ev.Name[:ev.NameLen], uint64(ev.NameLen), &profile)
	}
	res.EntropyQ8 = profile.Entropy_q8
	res.PayloadClass = profile.Payload_class

	// 3. Échelon 3 : Reconnaissance bornée des protocoles cryptographiques normalisés.
	// L'exemption protocolaire n'est accordée que sur un enregistrement TXT explicite,
	// un label réservé complet, une charge courte (<= 45 octets) et de faible entropie
	// (< 4.0 bits/octet), portée par un domaine parent déjà certifié bénin (éditeur
	// DNSAML ou Tranco). Un préfixe débordant, même sous parent certifié, est traité
	// comme une charge utile suspecte : il n'est jamais blanchi et escalade vers le SLM.
	protocolLabelPresent := hasProtocolPrefixLabel(sub)
	protocolBounded := len(sub) <= MaxProtocolPrefixLen && res.EntropyQ8 < MinTunnelEntropyQ8
	protocolOverBound := protocolLabelPresent && !protocolBounded

	// 4. Échelon 4 : Suivi Temporel en RAM (Beaconing Jitter & Prolifération)
	jitter, uniqueSubs, count := p.tracker.RecordQuery(parent, sub, nowSec)
	res.JitterPct = jitter
	res.UniqueSubdomains = uniqueSubs

	// 5. Échelon 5 : Détection des Cas Limites (Grey Zone)
	// Conditions d'escalade :
	// - Charge utile Hex/Base64 dense de longueur significative (>= 15 caractères)
	// - OU Entropie anormale (> seuil Q8.8) ET longueur significative (>= 15 caractères)
	// - OU Beaconing temporel régulier (Jitter < 20% sur au moins 4 requêtes)
	// - OU Prolifération de sous-domaines uniques (>= 5 sous-domaines distincts)
	// - OU Requête TXT/NULL de grande taille (> 45 octets)
	// - OU Profondeur multi-labels anormale (évasion par dictionnaire de labels courts)
	// - OU Sécheresse de voyelles (charge utile encodée pauvre en voyelles, sans seuil Shannon)
	// - OU Type exotique volumineux (TypeNULL/TypeCNAME, vecteurs de tunnelisation)
	isHexOrB64Dense := (res.PayloadClass == 2 || res.PayloadClass == 3) && (ev.SubdomainLen >= 15 || ev.NameLen >= 25)
	isHighEntropy := res.EntropyQ8 >= p.cfg.EntropyThresholdQ8 && (ev.SubdomainLen >= 15 || ev.NameLen >= 25)
	isBeaconing := jitter <= p.cfg.BeaconJitterMax && count >= 4
	isSubdomainFlood := uniqueSubs >= p.cfg.UniqueSubThreshold
	isTunnelRecord := (ev.QType == TypeTXT || ev.QType == TypeNULL) && ev.NameLen >= 40
	isDeepMultilabel := ev.LabelCount >= 5 || ev.SubdomainLen >= 35
	isConsonantDrought := hasConsonantDrought(ev.Subdomain[:ev.SubdomainLen])
	isExoticTunnel := (ev.QType == TypeNULL && ev.NameLen >= 25) || (ev.QType == TypeCNAME && ev.NameLen >= 45)
	// Reputation is context, not an exemption from volume or protocol controls.
	if ev.QType == TypeTXT && protocolLabelPresent && protocolBounded && p.parentCertified(parent) &&
		!isBeaconing && !isSubdomainFlood && !isTunnelRecord && !isDeepMultilabel && !isConsonantDrought {
		res.Decision = DecisionFastPass
		return res, nil
	}

	if isHexOrB64Dense || isHighEntropy || isBeaconing || isSubdomainFlood || isTunnelRecord || isDeepMultilabel || protocolOverBound || isConsonantDrought || isExoticTunnel {
		indicator := "HIGH_ENTROPY"
		switch {
		case isConsonantDrought:
			indicator = "CONSONANT_DROUGHT_PAYLOAD"
		case isExoticTunnel && ev.QType == TypeCNAME:
			indicator = "CNAME_QUESTION_LONG" // No response RDATA was inspected.
		case isExoticTunnel && ev.QType == TypeNULL:
			indicator = "DNS_TUNNEL_RECORD_TYPE"
		case protocolOverBound && res.EntropyQ8 >= MinTunnelEntropyQ8:
			indicator = "HEX_BASE64_PAYLOAD_DENSE"
		case protocolOverBound:
			indicator = "DNS_TUNNEL_RECORD_TYPE"
		case isHexOrB64Dense:
			indicator = "HEX_BASE64_PAYLOAD_DENSE"
		case isBeaconing:
			indicator = "BEACONING_JITTER_LOW"
		case isSubdomainFlood:
			indicator = "SUBDOMAIN_EXFIL_FLOOD"
		case isTunnelRecord:
			indicator = "DNS_TUNNEL_RECORD_TYPE"
		case isDeepMultilabel:
			indicator = "DEEP_MULTILABEL_SUBDOMAIN"
		}

		inc := SLMIncident{
			Timestamp:          uint64(nowSec),
			FQDN:               string(ev.Name[:ev.NameLen]),
			ParentDomain:       string(ev.ParentDomain[:ev.ParentDomainLen]),
			Subdomain:          string(ev.Subdomain[:ev.SubdomainLen]),
			QType:              ev.QType,
			EntropyQ8:          res.EntropyQ8,
			EntropyBits:        float64(res.EntropyQ8) / 256.0,
			PayloadClass:       res.PayloadClass,
			JitterPct:          jitter,
			UniqueSubdomains:   uniqueSubs,
			QueryCount:         count,
			SuspectedIndicator: indicator,
		}
		res.Decision = DecisionEscalateSLM
		res.Incident = &inc

		// Dépose dans la file bornée non-bloquante pour l'arbitre SLM
		select {
		case p.slmQueue <- inc:
			res.ArbitrationQueued = true
		default:
			p.slmRejected.Add(1)
			return res, ErrSLMQueueFull
		}
		return res, nil
	}

	// 6. Trafic ordinaire non suspect
	res.Decision = DecisionFastPass
	return res, nil
}

// SLMQueue retourne le canal de lecture des cas limites pour le worker d'inférence.
func (p *Pipeline) SLMQueue() <-chan SLMIncident {
	return p.slmQueue
}

// ApplyDeterministicVeto validates vocabulary and applies heuristic bounds.
// A local vendor policy cannot override suspicious metrics. Confidence is zero
// for deterministic heuristics; it is not an estimated statistical probability.
// Le dossier d'incident est enrichi de la fiche médico-légale HITL (résumé et action
// recommandée) calibrée sur le verdict final effectivement retenu.
func (p *Pipeline) ApplyDeterministicVeto(incident *SLMIncident, proposedVerdict string) (finalVerdict string, confidence float64, overrideReason string) {
	p.lifeMu.RLock()
	defer p.lifeMu.RUnlock()
	if p.closed {
		return "INSUFFICIENT_EVIDENCE", 0, "PIPELINE_CLOSED"
	}
	finalVerdict, confidence, overrideReason = p.applyVetoRules(incident, proposedVerdict)
	if incident != nil {
		incident.HumanSummary = BuildHumanSummary(incident)
		incident.RecommendedAction = RecommendedActionForVerdict(finalVerdict)
	}
	return finalVerdict, confidence, overrideReason
}

// applyVetoRules applique les règles de veto déterministes et retourne le verdict final.
func (p *Pipeline) applyVetoRules(incident *SLMIncident, proposedVerdict string) (finalVerdict string, confidence float64, overrideReason string) {
	if incident == nil || !validSLMVerdict(proposedVerdict) {
		return "INSUFFICIENT_EVIDENCE", 0, "INVALID_ARBITRATION_VERDICT"
	}
	if math.IsNaN(incident.EntropyBits) || math.IsInf(incident.EntropyBits, 0) || incident.EntropyBits < 0 || incident.EntropyBits > 8 {
		return "INSUFFICIENT_EVIDENCE", 0, "INVALID_INCIDENT_METRICS"
	}

	// Règle 2 : Veto sur les protocoles cryptographiques légitimes.
	// Le veto n'opère que sur un label réservé complet, un enregistrement TXT explicite,
	// une charge courte (<= 45 octets) et de faible entropie (< 4.0 bits/octet). Il faut
	// en outre que le domaine parent soit certifié bénin OU que le volume observé reste
	// faible sans prolifération de sous-domaines. Un sélecteur débordant ou à haute
	// entropie, même sous un parent certifié, ne saurait blanchir un tunnel : le préfixe
	// protocolaire ne fait plus écran et l'escalade se poursuit.
	entropyQ8 := uint32(incident.EntropyBits * 256.0)
	if incident.QType == TypeTXT && isLegitimateProtocolPrefix(incident.Subdomain, entropyQ8) {
		if incident.QueryCount <= 3 && incident.UniqueSubdomains <= 2 {
			return "BENIGN_CRYPTO_KEY", 0, "HEURISTIC_PROTOCOL_SHAPE_NOT_CERTIFICATION"
		}
	}

	// Règle 3 : Veto sur échantillon insuffisant
	if incident.QueryCount < 3 && incident.EntropyBits < 4.2 {
		return "INSUFFICIENT_EVIDENCE", 0.0, "VETO_DETERMINISTE: Echantillon temporel insuffisant (< 3 requetes)"
	}

	// Si le modèle a conclu à une attaque et que le veto ne s'oppose pas
	if proposedVerdict == "DNS_TUNNEL_CONFIRMED" {
		return "DNS_TUNNEL_CONFIRMED", 0, "MODEL_PROPOSAL_NOT_PROOF"
	}

	return proposedVerdict, 0, "MODEL_PROPOSAL_NOT_PROOF"
}

func validSLMVerdict(verdict string) bool {
	switch verdict {
	case "BENIGN_AV_TELEMETRY", "BENIGN_DKIM_KEY", "BENIGN_CRYPTO_KEY", "DNS_TUNNEL_CONFIRMED", "INSUFFICIENT_EVIDENCE":
		return true
	}
	return false
}

// RecommendedActionForVerdict traduit un verdict d'arbitrage en action analyste
// déterministe pour la fiche médico-légale HITL.
func RecommendedActionForVerdict(verdict string) string {
	switch verdict {
	case "DNS_TUNNEL_CONFIRMED":
		return "BLOCK_IMMEDIATE"
	case "BENIGN_AV_TELEMETRY", "BENIGN_CRYPTO_KEY":
		return "ALLOW_VENDOR"
	case "INSUFFICIENT_EVIDENCE":
		return "MONITOR_ONLY"
	default:
		return "MONITOR_ONLY"
	}
}

// BuildHumanSummary compose une synthèse médico-légale déterministe et actionnable
// pour un analyste humain : indicateur suspect, FQDN, volume de requêtes, cardinalité
// des sous-domaines uniques et entropie mesurée.
func BuildHumanSummary(inc *SLMIncident) string {
	if inc == nil {
		return ""
	}
	return fmt.Sprintf(
		"Incident DNS suspect [%s]: FQDN=%s, requetes=%d, sous-domaines uniques=%d, entropie=%.2f bits/octet.",
		inc.SuspectedIndicator, inc.FQDN, inc.QueryCount, inc.UniqueSubdomains, inc.EntropyBits,
	)
}

// hasConsonantDrought détecte une anomalie linguistique sévère : un sous-domaine
// comportant au moins 15 lettres mais moins de 10% de voyelles (a,e,i,o,u,y).
// Zéro allocation tas (0 B/op).
func hasConsonantDrought(sub []byte) bool {
	var alphaLen, vowelCount int
	for i := 0; i < len(sub); i++ {
		c := sub[i]
		// Traitement insensible à la casse
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		if c >= 'a' && c <= 'z' {
			alphaLen++
			if c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u' || c == 'y' {
				vowelCount++
			}
		}
	}
	return alphaLen >= 15 && (vowelCount*10) < alphaLen
}

// parentCertified is the historical name of a LOCAL allow-policy lookup, not
// certification. Known shared hosting roots never confer a protocol exemption.
// Zéro allocation tas (0 B/op).
func (p *Pipeline) parentCertified(parent string) bool {
	if len(parent) == 0 || isSharedHostingDomain(parent) {
		return false
	}
	match, ok := p.rep.Match(parent)
	if !ok {
		return false
	}
	return match.Classification == RepClassAllowVendor || match.Classification == RepClassAllowTranco
}

// MaxProtocolPrefixLen borne la longueur maximale d'un sous-domaine protocolaire légitime.
// Un sélecteur DKIM/DMARC/ACME réel reste court ; au-delà de 45 octets, la charge utile
// dépasse le cadre d'un sélecteur et relève du tunnel ou de l'exfiltration.
const MaxProtocolPrefixLen = 45

// MinTunnelEntropyQ8 est le seuil d'entropie Q8.8 (4.0 bits/octet) au-delà duquel un
// préfixe protocolaire ne peut plus être blanchi : l'entropie d'un sélecteur est faible,
// celle d'une charge utile chiffrée ou encodée est élevée.
const MinTunnelEntropyQ8 uint32 = 1024

// isLegitimateProtocolPrefix détecte un préfixe réservé ET borne la charge à celle d'un
// sélecteur court et de faible entropie. Le préfixe n'est reconnu que comme label DNS
// complet (frontière de point stricte) : "_domainkeyevil" n'est pas "_domainkey".
// Zéro allocation tas.
func isLegitimateProtocolPrefix(sub string, entropyQ8 uint32) bool {
	if len(sub) == 0 || len(sub) > MaxProtocolPrefixLen || entropyQ8 >= MinTunnelEntropyQ8 {
		return false
	}
	return hasProtocolPrefixLabel(sub)
}

// hasProtocolPrefixLabel détecte syntaxiquement les préfixes réservés des protocoles de
// sécurité légitimes, sans considération de longueur ni d'entropie. Zéro allocation tas.
func hasProtocolPrefixLabel(sub string) bool {
	if len(sub) == 0 {
		return false
	}
	s := strings.ToLower(sub)
	return hasReservedLabel(s, "_domainkey") ||
		hasReservedLabel(s, "_dmarc") ||
		hasReservedLabel(s, "_acme-challenge")
}

// hasReservedLabel vérifie que label forme un label DNS complet dans s, c'est-à-dire
// délimité à gauche et à droite par un point ou par les bornes de la chaîne. La
// comparaison s'effectue strictement sur les frontières : aucun sous-mot partiel
// (ex. "_domainkeyevil" ou "_dmarc-evil") n'est accepté. Aucune allocation tas.
func hasReservedLabel(s, label string) bool {
	n := len(label)
	if n == 0 || len(s) < n {
		return false
	}
	for start := 0; start+n <= len(s); {
		idx := strings.Index(s[start:], label)
		if idx < 0 {
			return false
		}
		pos := start + idx
		leftBoundary := pos == 0 || s[pos-1] == '.'
		end := pos + n
		rightBoundary := end == len(s) || s[end] == '.'
		if leftBoundary && rightBoundary {
			return true
		}
		start = pos + 1
	}
	return false
}

// logEvent enqueues immutable strings for the JSONL writer without allocation.
// A retained error remains observable even after later writes recover.
func (p *Pipeline) logEvent(domain, action, reason string, conf float64) error {
	p.logMu.Lock()
	defer p.logMu.Unlock()
	if p.auditQueue == nil {
		return nil
	}
	if p.auditClosed {
		return ErrPipelineClosed
	}
	select {
	case p.auditQueue <- auditRecord{time.Now().UTC(), domain, action, reason, conf}:
		return p.auditErr
	default:
		p.auditRejected.Add(1)
		p.auditErr = ErrAuditQueueFull
		return ErrAuditQueueFull
	}
}

// Close rejects new packets, cancels inference, drains accepted incidents to
// callbacks (cancelled work becomes INSUFFICIENT_EVIDENCE), then flushes audit.
// Arbitrate must honor context; callbacks must return and must not call Close.
// Without a worker, queued incidents are counted as abandoned, never certified.
func (p *Pipeline) Close() error {
	p.closeOnce.Do(func() {
		p.lifeMu.Lock()
		p.closed = true
		if p.workerCancel != nil {
			p.workerCancel()
		}
		close(p.slmQueue)
		p.lifeMu.Unlock()
		p.workerWG.Wait()
		for range p.slmQueue {
			p.slmAbandoned.Add(1)
		}
		if p.slmAbandoned.Load() != 0 {
			p.closeErr = ErrSLMAbandoned
		}
		p.logMu.Lock()
		p.auditClosed = true
		if p.auditQueue != nil {
			close(p.auditQueue)
		}
		p.logMu.Unlock()
		p.auditWG.Wait()
		if p.logFile != nil {
			p.closeErr = errors.Join(p.closeErr, p.AuditError(), p.logFile.Sync(), p.logFile.Close())
		}
	})
	return p.closeErr
}

// SLMArbitrationResponse représente la décision structurée de l'arbitre IA.
type SLMArbitrationResponse struct {
	Verdict    string  `json:"verdict"` // "BENIGN_AV_TELEMETRY" | "BENIGN_DKIM_KEY" | "DNS_TUNNEL_CONFIRMED" | "INSUFFICIENT_EVIDENCE"
	Confidence float64 `json:"confidence"`
	Thought    string  `json:"thought"`

	HumanSummary      string `json:"human_summary,omitempty"`
	RecommendedAction string `json:"recommended_action,omitempty"`
}

// SLMArbitrator must honor cancellation. Close cannot forcibly interrupt an
// implementation that ignores ctx, or a callback that does not return.
type SLMArbitrator interface {
	Arbitrate(ctx context.Context, incident *SLMIncident) (SLMArbitrationResponse, error)
}

// StartArbitratorWorker starts at most one worker for the pipeline lifetime.
// Cancellation turns subsequent queued work into unavailable outcomes until Close
// ends the drain. Do not consume SLMQueue concurrently with this worker.
func (p *Pipeline) StartArbitratorWorker(ctx context.Context, arb SLMArbitrator, onVerdict func(incident SLMIncident, finalVerdict string, confidence float64, reason string)) {
	p.lifeMu.Lock()
	defer p.lifeMu.Unlock()
	if p.closed || p.workerStarted || arb == nil {
		return
	}
	ctx, p.workerCancel = context.WithCancel(ctx)
	p.workerStarted = true
	p.workerWG.Add(1)
	go func() {
		defer p.workerWG.Done()
		defer p.workerCancel()
		for inc := range p.slmQueue {
			var resp SLMArbitrationResponse
			err := ctx.Err()
			if err == nil {
				resp, err = arb.Arbitrate(ctx, &inc)
			}
			if err == nil {
				err = ctx.Err()
			}
			if err == nil && (!validSLMVerdict(resp.Verdict) || math.IsNaN(resp.Confidence) || math.IsInf(resp.Confidence, 0) || resp.Confidence < 0 || resp.Confidence > 1) {
				err = errors.New("invalid arbitration response")
			}
			finalVerdict, conf, reason := "INSUFFICIENT_EVIDENCE", 0.0, ""
			if err != nil {
				p.arbitrationErrors.Add(1)
				reason = "ARBITRATION_UNAVAILABLE: " + err.Error()
				inc.HumanSummary = BuildHumanSummary(&inc)
				inc.RecommendedAction = RecommendedActionForVerdict(finalVerdict)
			} else {
				finalVerdict, conf, reason = p.ApplyDeterministicVeto(&inc, resp.Verdict)
				if reason == "MODEL_PROPOSAL_NOT_PROOF" && finalVerdict == resp.Verdict {
					conf = resp.Confidence
				}
			}
			p.logEvent(inc.FQDN, finalVerdict, reason, conf)
			if onVerdict != nil {
				onVerdict(inc, finalVerdict, conf, reason)
			}
		}
	}()
}

// EvaluateChannelEvent consomme un événement réseau standard issu d'un anneau de capture.
func (p *Pipeline) EvaluateChannelEvent(ev *Event, nowSec uint32) (EvaluationResult, error) {
	return p.EvaluatePacket(ev.Payload[:], nowSec)
}
