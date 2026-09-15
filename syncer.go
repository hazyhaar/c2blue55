// Package c2blue55 — Synchroniseur périodique de réputation en mémoire vive (Zero-DB).
// Assure l'actualisation atomique des listes publiques (DNSAML, Tranco, ThreatFox) sans verrous.
package c2blue55

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// ReputationSource définit un référentiel distant ou local à synchroniser.
type ReputationSource struct {
	Name           string // Nom du référentiel (ex: "ThreatFox-C2", "Tranco-Top10k")
	URI            string // URL HTTP/HTTPS ou chemin de fichier local (ex: "file:///..." ou "https://...")
	Classification uint8  // RepClassAllowVendor, RepClassAllowTranco, RepClassBlockC2
	MatchKind      uint8  // MatchExact ou MatchSubtree
}

// SyncerConfig configure le synchroniseur de réputation.
type SyncerConfig struct {
	Sources       []ReputationSource
	SyncInterval  time.Duration // Fréquence de resynchronisation (défaut: 24h)
	HTTPTimeout   time.Duration // Timeout de requête HTTP (défaut: 15s)
	OnSyncSuccess func(numEntries int)
	OnSyncError   func(err error)
}

// ReputationSyncer orchestre le téléchargement, la compilation et l'échange atomique de la table de réputation.
type ReputationSyncer struct {
	cfg          SyncerConfig
	rep          *AtomicReputation
	httpClient   *http.Client
	syncMu       sync.Mutex
	provenanceMu sync.Mutex
	provenance   []SourceProvenance
}

// SourceProvenance attests bytes read, not the truth/authenticity of their claims.
// It is in-memory evidence; durable storage is the caller's responsibility.
type SourceProvenance struct {
	Name, URI string
	FetchedAt time.Time
	SHA256    string
	Entries   int
	Error     string
}

func (s *ReputationSyncer) Provenance() []SourceProvenance {
	s.provenanceMu.Lock()
	defer s.provenanceMu.Unlock()
	return append([]SourceProvenance(nil), s.provenance...)
}

// entryKey identifie une entrée lors de la fusion dédupliquée de résilience.
type entryKey struct {
	domain string
	class  uint8
	kind   uint8
}

// NewReputationSyncer initialise le synchroniseur avec sa configuration.
func NewReputationSyncer(cfg SyncerConfig, rep *AtomicReputation) *ReputationSyncer {
	cfg.Sources = append([]ReputationSource(nil), cfg.Sources...)
	if cfg.SyncInterval <= 0 {
		cfg.SyncInterval = 24 * time.Hour
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = 15 * time.Second
	}

	return &ReputationSyncer{
		cfg: cfg,
		rep: rep,
		httpClient: &http.Client{
			Timeout: cfg.HTTPTimeout,
		},
	}
}

// SyncOnce exécute une passe de synchronisation complète et échange atomiquement la table si succès.
// En cas d'erreur de réseau sur une source, conserve les entrées existantes et n'interrompt pas le service.
func (s *ReputationSyncer) SyncOnce(ctx context.Context) (int, error) {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.rep == nil || len(s.cfg.Sources) == 0 {
		err := errors.New("syncer: aucune source configuree ou reputation absente")
		if s.cfg.OnSyncError != nil {
			s.cfg.OnSyncError(err)
		}
		return 0, err
	}
	// Legacy local policy is not certified intelligence.
	allEntries := make([]BuildEntry, len(DefaultBuildEntries))
	copy(allEntries, DefaultBuildEntries)

	var lastErr error
	sourcesFailed := 0
	provenance := make([]SourceProvenance, 0, len(s.cfg.Sources))

	for _, src := range s.cfg.Sources {
		entries, receipt, err := s.fetchSource(ctx, src)
		provenance = append(provenance, receipt)
		if err != nil {
			lastErr = errors.Join(lastErr, fmt.Errorf("syncer: echec source %s (%s): %w", src.Name, src.URI, err))
			sourcesFailed++
			if s.cfg.OnSyncError != nil {
				s.cfg.OnSyncError(lastErr)
			}
			continue
		}
		allEntries = append(allEntries, entries...)
	}
	s.provenanceMu.Lock()
	s.provenance = provenance
	s.provenanceMu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}

	// Résilience mémoire : si une source quelconque a échoué lors de cette passe, les
	// entrées actuellement actives sont réintégrées à l'instantané compilé. Un incident
	// transitoire (fichier absent, timeout réseau) ne doit jamais effacer de la mémoire
	// vive les IOCs dynamiques déjà appris. La fusion est dédupliquée par (domaine,
	// classification, mode) pour ne pas gonfler la table avec des doublons.
	if sourcesFailed > 0 {
		if active := s.rep.Load(); active != nil {
			key := func(e BuildEntry) entryKey {
				return entryKey{domain: cleanDomain(e.Domain), class: e.Classification, kind: e.MatchKind}
			}
			seen := make(map[entryKey]struct{}, len(allEntries))
			for _, e := range allEntries {
				seen[key(e)] = struct{}{}
			}
			for _, e := range active.Entries() {
				k := key(e)
				if _, ok := seen[k]; ok {
					continue
				}
				seen[k] = struct{}{}
				allEntries = append(allEntries, e)
			}
		}
	}

	if len(allEntries) == 0 {
		return 0, fmt.Errorf("syncer: aucune entree valide a compiler")
	}

	// 2. Compilation de l'instantané compact binaire
	if err := s.rep.ReloadFromEntries(allEntries); err != nil {
		return 0, fmt.Errorf("syncer: echec compilation instantane: %w", err)
	}

	count := s.rep.Load().numEntries
	if lastErr == nil && s.cfg.OnSyncSuccess != nil {
		s.cfg.OnSyncSuccess(count)
	}

	return count, lastErr
}

// StartPeriodic démarre la goroutine de synchronisation périodique (ex: toutes les 24h).
func (s *ReputationSyncer) StartPeriodic(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(s.cfg.SyncInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_, _ = s.SyncOnce(ctx)
			}
		}
	}()
}

// fetchSource récupère les données d'une source locale ou distante.
func (s *ReputationSyncer) fetchSource(ctx context.Context, src ReputationSource) (entries []BuildEntry, receipt SourceProvenance, err error) {
	receipt = SourceProvenance{Name: src.Name, URI: src.URI, FetchedAt: time.Now().UTC()}
	defer func() {
		if err != nil {
			receipt.Error = err.Error()
		}
	}()
	var reader io.ReadCloser

	if strings.HasPrefix(src.URI, "http://") || strings.HasPrefix(src.URI, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URI, nil)
		if err != nil {
			return nil, receipt, err
		}
		req.Header.Set("User-Agent", "c2blue55-agent/1.0 (purego; security-research)")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return nil, receipt, err
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, receipt, fmt.Errorf("http status %d", resp.StatusCode)
		}
		reader = resp.Body
	} else {
		// Fichier local sur disque
		filePath := strings.TrimPrefix(src.URI, "file://")
		f, err := os.Open(filePath)
		if err != nil {
			return nil, receipt, err
		}
		reader = f
	}
	defer func() { err = errors.Join(err, reader.Close()) }()
	const maxSourceBytes = 16 << 20
	limited := &io.LimitedReader{R: reader, N: maxSourceBytes + 1}
	digest := sha256.New()
	entries, err = ParseDomainList(io.TeeReader(limited, digest), src.Classification, src.MatchKind)
	if err == nil && limited.N == 0 {
		err = errors.New("syncer: source exceeds 16 MiB")
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return nil, receipt, err
	}
	receipt.SHA256 = fmt.Sprintf("%x", digest.Sum(nil))
	receipt.Entries = len(entries)
	return entries, receipt, nil
}
