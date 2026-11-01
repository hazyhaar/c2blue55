package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

var errCampaignBusy = errors.New("c2dnslab-emit: une campagne court deja")

// runner maintient le verrou durant l'exécution et la publication du manifeste.
type runner struct {
	runsDir   string
	busy      bool
	mu        sync.Mutex
	launch    func(context.Context, string, ...string) (int, error)
	logpit    string
	origin    string
	private   ed25519.PrivateKey
	client    *http.Client
	host      string
	campaigns uint64
	shipped   uint64
	dropped   uint64
	errors    uint64
	ctx       context.Context
}

func (r *runner) reserve() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.busy {
		return false
	}
	r.busy = true
	return true
}

func (r *runner) run(ctx context.Context, c dnslab.Campaign) (dnslab.CampaignReport, error) {
	if !r.reserve() {
		return dnslab.CampaignReport{}, errCampaignBusy
	}
	return r.execute(ctx, c)
}

func (r *runner) execute(ctx context.Context, c dnslab.Campaign) (dnslab.CampaignReport, error) {
	defer func() {
		r.mu.Lock()
		r.busy = false
		r.mu.Unlock()
	}()
	if err := c.Validate(); err != nil {
		return dnslab.CampaignReport{}, err
	}
	var report dnslab.CampaignReport
	var runErr error
	if c.Tool == "replay" {
		conn, err := net.ListenPacket("udp", "")
		if err != nil {
			runErr = err
			report = dnslab.CampaignReport{RunID: c.RunID, Tool: c.Tool, Start: time.Now(), End: time.Now(), Errors: 1, ExitCode: -1}
		} else {
			address := c.ServerAddr()
			report, runErr = dnslab.RunReplay(ctx, conn, address, &c, time.Now)
			if err := conn.Close(); err != nil && runErr == nil {
				runErr = err
				report.Errors++
			}
		}
	} else {
		launcher := r.launch
		var diagnostic string
		if launcher == nil {
			launcher = func(ctx context.Context, name string, args ...string) (int, error) {
				return launchToolCaptured(ctx, &diagnostic, name, args...)
			}
		}
		report, runErr = dnslab.RunTool(ctx, &c, launcher)
		report.Diagnostic = diagnostic
	}
	host := r.host
	if host == "" {
		host, _ = os.Hostname()
	}
	if host == "" {
		host = "redbo"
	}
	path, manifestErr := dnslab.WriteRunManifest(r.runsDir, &c, report, host)
	if manifestErr == nil && r.logpit != "" {
		var payload []byte
		payload, manifestErr = os.ReadFile(path)
		if manifestErr == nil {
			shipping, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			manifestErr = r.ship(shipping, payload, c.RunID)
			cancel()
		}
	}
	r.mu.Lock()
	r.campaigns++
	r.dropped += uint64(report.Dropped)
	r.errors += uint64(report.Errors)
	if manifestErr != nil {
		r.errors++
	}
	r.mu.Unlock()
	if runErr != nil {
		return report, runErr
	}
	return report, manifestErr
}

// limitedOutput conserve 4096 octets au plus, sans bloquer le fils.
type limitedOutput struct {
	content []byte
	tail    bool
}

func (w *limitedOutput) Write(chunk []byte) (int, error) {
	if w.tail {
		if len(chunk) >= 4096 {
			w.content = append(w.content[:0], chunk[len(chunk)-4096:]...)
		} else if len(w.content)+len(chunk) > 4096 {
			overflow := len(w.content) + len(chunk) - 4096
			copy(w.content, w.content[overflow:])
			w.content = append(w.content[:len(w.content)-overflow], chunk...)
		} else {
			w.content = append(w.content, chunk...)
		}
		return len(chunk), nil
	}
	if len(w.content) < 4096 {
		remaining := min(len(chunk), 4096-len(w.content))
		w.content = append(w.content, chunk[:remaining]...)
	}
	return len(chunk), nil
}

func launchToolCaptured(ctx context.Context, diagnostic *string, name string, args ...string) (int, error) {
	process := exec.Command(name, args...)
	process.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	standard := &limitedOutput{}
	standardError := &limitedOutput{tail: true}
	process.Stdout = standard
	process.Stderr = standardError
	if err := process.Start(); err != nil {
		return -1, err
	}
	defer func() {
		if diagnostic != nil {
			start := max(len(standardError.content)-512, 0)
			*diagnostic = string(standardError.content[start:])
		}
	}()
	finished := make(chan error, 1)
	go func() { finished <- process.Wait() }()
	select {
	case err := <-finished:
		if err == nil {
			return 0, nil
		}
		if exit, ok := errors.AsType[*exec.ExitError](err); ok {
			return exit.ExitCode(), nil
		}
		return -1, err
	case <-ctx.Done():
		_ = syscall.Kill(-process.Process.Pid, syscall.SIGTERM)
		select {
		case err := <-finished:
			if err == nil {
				return 0, nil
			}
			if exit, ok := errors.AsType[*exec.ExitError](err); ok {
				return exit.ExitCode(), nil
			}
			return -1, err
		case <-time.After(5 * time.Second):
			_ = syscall.Kill(-process.Process.Pid, syscall.SIGKILL)
			err := <-finished
			if exit, ok := errors.AsType[*exec.ExitError](err); ok {
				return exit.ExitCode(), nil
			}
			if err != nil {
				return -1, err
			}
			return 0, nil
		}
	}
}

type signedEntry struct {
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

func (r *runner) ship(ctx context.Context, body []byte, runID string) error {
	if len(r.private) != ed25519.PrivateKeySize {
		return errors.New("logpit: graine absente")
	}
	client := r.client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	endpoint := strings.TrimRight(r.logpit, "/")
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/tip", nil)
	if err != nil {
		return err
	}
	reply, err := client.Do(request)
	if err != nil {
		return err
	}
	var tip struct {
		Hash string `json:"hash"`
	}
	if reply.StatusCode == http.StatusOK {
		err = json.NewDecoder(io.LimitReader(reply.Body, 4096)).Decode(&tip)
	} else {
		err = fmt.Errorf("logpit tip: HTTP %d", reply.StatusCode)
	}
	closeErr := reply.Body.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if tip.Hash == "" {
		return errors.New("logpit: tête absente")
	}
	instant := time.Now().UTC()
	public := r.private.Public().(ed25519.PublicKey)
	origin := r.origin
	if origin == "" {
		origin = "c2dnslab-emit"
	}
	entry := signedEntry{ID: fmt.Sprintf("c2dnslab-emit-%s-%d", runID, instant.UnixNano()), PrevHash: tip.Hash, TS: instant, Class: "consenti", Origin: origin, Body: body, KeyID: hex.EncodeToString(public[:8])}
	canonical, err := json.Marshal(struct {
		ID       string `json:"id"`
		PrevHash string `json:"prev_hash"`
		TS       string `json:"ts"`
		Class    string `json:"class"`
		Origin   string `json:"origin"`
		Body     string `json:"body_hex"`
		KeyID    string `json:"key_id"`
	}{entry.ID, entry.PrevHash, instant.Format(time.RFC3339Nano), entry.Class, entry.Origin, hex.EncodeToString(body), entry.KeyID})
	if err != nil {
		return err
	}
	digest := sha256.Sum256(canonical)
	entry.Hash = hex.EncodeToString(digest[:])
	entry.Sig = ed25519.Sign(r.private, canonical)
	encoded, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v1/append", bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	reply, err = client.Do(request)
	if err != nil {
		return err
	}
	var receipt struct {
		ID   string `json:"id"`
		Hash string `json:"hash"`
	}
	if reply.StatusCode == http.StatusCreated {
		if decodeErr := json.NewDecoder(io.LimitReader(reply.Body, 4096)).Decode(&receipt); decodeErr == nil && (receipt.ID != entry.ID || receipt.Hash != entry.Hash) {
			log.Printf("logpit append: reçu divergent id=%q hash=%q, attendu id=%q hash=%q", receipt.ID, receipt.Hash, entry.ID, entry.Hash)
		}
	} else {
		_, _ = io.Copy(io.Discard, io.LimitReader(reply.Body, 4096))
	}
	if closeErr := reply.Body.Close(); closeErr != nil {
		log.Printf("logpit append: fermeture du corps: %v", closeErr)
	}
	if reply.StatusCode != http.StatusCreated {
		return fmt.Errorf("logpit append: HTTP %d", reply.StatusCode)
	}
	// HTTP 201 confirme définitivement l'entrée, même si la fermeture échoue.
	r.mu.Lock()
	r.shipped++
	r.mu.Unlock()
	return nil
}

func (r *runner) ControlHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		r.mu.Lock()
		status := struct {
			Campaigns uint64 `json:"campagnes"`
			Shipped   uint64 `json:"envoyees"`
			Dropped   uint64 `json:"abandonnees"`
			Errors    uint64 `json:"erreurs"`
		}{r.campaigns, r.shipped, r.dropped, r.errors}
		r.mu.Unlock()
		encodedStatus, encodeErr := json.Marshal(status)
		if encodeErr != nil {
			http.Error(w, encodeErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, writeErr := w.Write(append(encodedStatus, '\n')); writeErr != nil {
			log.Printf("healthz write: %v", writeErr)
		}
	})
	mux.HandleFunc("/v1/campaign", func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		var campaign dnslab.Campaign
		decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&campaign); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF {
			http.Error(w, "JSON supplémentaire", http.StatusBadRequest)
			return
		}
		if err := campaign.Validate(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !r.reserve() {
			http.Error(w, errCampaignBusy.Error(), http.StatusConflict)
			return
		}
		encodedReply, encodeErr := json.Marshal(struct {
			RunID string `json:"run_id"`
		}{campaign.RunID})
		if encodeErr != nil {
			r.mu.Lock()
			r.busy = false
			r.mu.Unlock()
			http.Error(w, encodeErr.Error(), http.StatusInternalServerError)
			return
		}
		parent := r.ctx
		if parent == nil {
			parent = context.Background()
		}
		go func() {
			if _, err := r.execute(parent, campaign); err != nil {
				log.Printf("campagne %s: %v", campaign.RunID, err)
			}
		}()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		if _, writeErr := w.Write(append(encodedReply, '\n')); writeErr != nil {
			log.Printf("campaign reply write: %v", writeErr)
		}
	})
	mux.HandleFunc("/v1/runs", func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		// Laisse à une campagne tout juste terminée le temps de publier son manifeste.
		deadline := time.Now().Add(100 * time.Millisecond)
		for {
			r.mu.Lock()
			active := r.busy
			r.mu.Unlock()
			if !active || time.Now().After(deadline) {
				break
			}
			select {
			case <-request.Context().Done():
				return
			case <-time.After(5 * time.Millisecond):
			}
		}
		paths, err := filepath.Glob(filepath.Join(r.runsDir, "*.manifest.json"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		manifests := make([]c2blue55.RedhostLabManifest, 0, len(paths))
		for _, path := range paths {
			manifest, err := c2blue55.LoadRedhostLabManifest(path)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			manifests = append(manifests, manifest)
		}
		encodedManifests, encodeErr := json.Marshal(manifests)
		if encodeErr != nil {
			http.Error(w, encodeErr.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if _, writeErr := w.Write(append(encodedManifests, '\n')); writeErr != nil {
			log.Printf("runs write: %v", writeErr)
		}
	})
	return http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		expectedToken := os.Getenv("DNSLAB_EMIT_CONTROL_TOKEN")
		if expectedToken != "" {
			const bearerPrefix = "Bearer "
			authHeader := request.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, bearerPrefix) {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			providedToken := strings.TrimPrefix(authHeader, bearerPrefix)
			if len(providedToken) != len(expectedToken) || subtle.ConstantTimeCompare([]byte(providedToken), []byte(expectedToken)) != 1 {
				w.Header().Set("WWW-Authenticate", "Bearer")
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		mux.ServeHTTP(w, request)
	})
}
