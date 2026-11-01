package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

// shipper met en file les lignes de journal (bornée à 10000) et les expédie par
// lots signés Ed25519 vers POST <logpit>/v1/append (pkg/logpit de REDTEAM :
// Class consenti, Origin, Body = lignes JSONL, KeyID, PrevHash chaîné).
type shipper struct {
	queue        []dnslab.JournalLine
	mu           sync.Mutex
	endpoint     string
	origin       string
	private      ed25519.PrivateKey
	interval     time.Duration
	client       *http.Client
	prevHash     string
	shipped      *atomic.Uint64
	dropped      *atomic.Uint64
	done         chan struct{}
	cancel       context.CancelFunc
	pendingLines int
}

func (s *shipper) enqueue(line dnslab.JournalLine) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.queue)+s.pendingLines >= 10000 {
		s.dropped.Add(1)
		log.Print("dnslab: file logpit pleine, ligne abandonnée")
		return
	}
	s.queue = append(s.queue, line)
}

type signedBatch struct {
	ID       string    `json:"id"`
	PrevHash string    `json:"prev_hash"`
	Hash     string    `json:"hash"`
	TS       time.Time `json:"ts"`
	Class    string    `json:"class"`
	Origin   string    `json:"origin"`
	Body     []byte    `json:"body"`
	KeyID    string    `json:"key_id"`
	Sig      []byte    `json:"sig"`
}

type canonicalBatch struct {
	ID       string `json:"id"`
	PrevHash string `json:"prev_hash"`
	TS       string `json:"ts"`
	Class    string `json:"class"`
	Origin   string `json:"origin"`
	Body     string `json:"body_hex"`
	KeyID    string `json:"key_id"`
}

func (s *shipper) start(parent context.Context) error {
	ctx, cancel := context.WithCancel(parent)
	s.cancel = cancel
	s.done = make(chan struct{})
	go s.run(ctx)
	return nil
}

func (s *shipper) refreshTip(ctx context.Context) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint+"/v1/tip", nil)
	if err != nil {
		return err
	}
	reply, err := s.client.Do(request)
	if err != nil {
		return err
	}
	defer reply.Body.Close()
	if reply.StatusCode != http.StatusOK {
		return fmt.Errorf("logpit tip: HTTP %d", reply.StatusCode)
	}
	var tip struct {
		Hash string `json:"hash"`
	}
	if err := json.NewDecoder(io.LimitReader(reply.Body, 4096)).Decode(&tip); err != nil {
		return err
	}
	if tip.Hash == "" {
		return errors.New("logpit: hash de tête absent")
	}
	s.prevHash = tip.Hash
	return nil
}

func (s *shipper) stop() {
	s.cancel()
	<-s.done
}

func (s *shipper) run(ctx context.Context) {
	defer func() {
		s.mu.Lock()
		remaining := len(s.queue) + s.pendingLines
		s.mu.Unlock()
		if remaining != 0 {
			s.dropped.Add(uint64(remaining))
			log.Printf("logpit: %d lignes abandonnées à l'arrêt", remaining)
		}
		close(s.done)
	}()
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	var body []byte
	attempts := 0
	lines := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if body == nil {
			s.mu.Lock()
			if len(s.queue) != 0 {
				lines = len(s.queue)
				s.pendingLines = lines
				body = make([]byte, 0, lines*256)
				for i := range s.queue {
					var err error
					body, err = dnslab.EncodeJournalLine(&s.queue[i], body)
					if err != nil {
						log.Printf("logpit: encodage: %v", err)
						s.dropped.Add(uint64(lines))
						s.pendingLines = 0
						body = nil
						break
					}
				}
				s.queue = s.queue[:0]
			}
			s.mu.Unlock()
		}
		if body == nil {
			continue
		}
		if s.prevHash == "" {
			if err := s.refreshTip(ctx); err != nil {
				attempts++
				log.Printf("logpit: amorçage de la tête (tentative %d/3): %v", attempts, err)
				if attempts == 3 {
					s.dropped.Add(uint64(lines))
					body, attempts, lines = nil, 0, 0
					s.mu.Lock()
					s.pendingLines = 0
					s.mu.Unlock()
				}
				continue
			}
		}
		pending, err := s.signBatch(body)
		if err != nil {
			log.Printf("logpit: signature: %v", err)
			s.dropped.Add(uint64(lines))
			s.mu.Lock()
			s.pendingLines = 0
			s.mu.Unlock()
			body, attempts, lines = nil, 0, 0
			continue
		}
		hash, err := s.appendBatch(ctx, pending)
		if err != nil {
			s.prevHash = "" // La tête peut avoir avancé, même après un refus ou une réponse perdue.
			attempts++
			log.Printf("logpit: lot refusé (tentative %d/3): %v", attempts, err)
			if attempts < 3 {
				continue
			}
			s.dropped.Add(uint64(lines))
		} else {
			s.prevHash = hash
			s.shipped.Add(uint64(lines))
		}
		body, attempts, lines = nil, 0, 0
		s.mu.Lock()
		s.pendingLines = 0
		s.mu.Unlock()
	}
}

func (s *shipper) signBatch(body []byte) (signedBatch, error) {
	instant := time.Now().UTC()
	pub := s.private.Public().(ed25519.PublicKey)
	// The timestamp and a monotonic process-local counter make the identifier unique.
	sequence := s.shipped.Load() + s.dropped.Load()
	id := fmt.Sprintf("dnslab-%d-%d", instant.UnixNano(), sequence)
	entry := signedBatch{ID: id, PrevHash: s.prevHash, TS: instant, Class: "consenti", Origin: s.origin, Body: body, KeyID: hex.EncodeToString(pub[:8])}
	canonical, err := json.Marshal(canonicalBatch{ID: entry.ID, PrevHash: entry.PrevHash, TS: instant.Format(time.RFC3339Nano), Class: entry.Class, Origin: entry.Origin, Body: hex.EncodeToString(body), KeyID: entry.KeyID})
	if err != nil {
		return signedBatch{}, err
	}
	digest := sha256.Sum256(canonical)
	entry.Hash = hex.EncodeToString(digest[:])
	entry.Sig = ed25519.Sign(s.private, canonical)
	return entry, nil
}

func (s *shipper) appendBatch(ctx context.Context, entry signedBatch) (string, error) {
	encoded, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/v1/append", bytes.NewReader(encoded))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/json")
	reply, err := s.client.Do(request)
	if err != nil {
		return "", err
	}
	defer reply.Body.Close()
	if reply.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("HTTP %d", reply.StatusCode)
	}
	var receipt struct {
		ID   string `json:"id"`
		Hash string `json:"hash"`
	}
	decodeErr := json.NewDecoder(io.LimitReader(reply.Body, 4096)).Decode(&receipt)
	if decodeErr != nil || receipt.ID != entry.ID || receipt.Hash != entry.Hash {
		if decodeErr != nil {
			log.Printf("logpit: reçu HTTP 201 illisible: %v", decodeErr)
		} else {
			log.Print("logpit: reçu HTTP 201 non conforme")
		}
		if err := s.refreshTip(ctx); err != nil {
			log.Printf("logpit: tête indisponible après HTTP 201: %v", err)
			return "", nil // L'entrée existe ; le prochain lot réamorcera la tête.
		}
		return s.prevHash, nil
	}
	return receipt.Hash, nil
}
