package dnslive

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const registrationBodyDeadline = 5 * time.Second

type registrationRequest struct {
	RunID      string `json:"run_id"`
	Kind       string `json:"kind"`
	SourceIP   string `json:"source_ip"`
	SourcePort uint16 `json:"source_port"`
}

func (serviceLive *ServiceLive) routes() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/healthz":
			serviceLive.handleHealth(writer, request)
		case request.URL.Path == "/":
			serviceLive.handleDashboard(writer, request)
		case request.URL.Path == "/dashboard/api/runs":
			serviceLive.handleDashboardRuns(writer, request)
		case request.URL.Path == "/dashboard/api/events":
			serviceLive.handleDashboardEvents(writer, request)
		case request.URL.Path == "/dashboard/api/reasons":
			serviceLive.handleDashboardReasons(writer, request)
		case request.URL.Path == "/api/v1/registrations":
			serviceLive.handleRegistrations(writer, request)
		case strings.HasPrefix(request.URL.Path, "/api/v1/registrations/"):
			serviceLive.handleFinish(writer, request)
		case request.URL.Path == "/api/v1/runs":
			serviceLive.handleRuns(writer, request)
		case request.URL.Path == "/api/v1/events":
			serviceLive.handleEvents(writer, request)
		case request.URL.Path == "/api/v1/reasons":
			serviceLive.handleReasons(writer, request)
		case strings.HasPrefix(request.URL.Path, "/api/v1/evidence/"):
			serviceLive.handleEvidence(writer, request)
		default:
			writeJSONError(serviceLive, writer, http.StatusNotFound, "ressource inconnue")
		}
	})
}

func tokenMatches(provided, expected string) bool {
	providedDigest := sha256.Sum256([]byte(provided))
	expectedDigest := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(providedDigest[:], expectedDigest[:]) == 1
}

func (serviceLive *ServiceLive) bearerAuthorized(request *http.Request) bool {
	token, found := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
	return found && tokenMatches(token, serviceLive.cfg.DashboardToken)
}

func (serviceLive *ServiceLive) basicAuthorized(request *http.Request) bool {
	_, password, found := request.BasicAuth()
	return found && tokenMatches(password, serviceLive.cfg.DashboardToken)
}

func requireBearer(serviceLive *ServiceLive, writer http.ResponseWriter, request *http.Request) bool {
	if serviceLive.bearerAuthorized(request) {
		return true
	}
	writer.Header().Set("WWW-Authenticate", `Bearer realm="c2blue-dns-live"`)
	writeJSONError(serviceLive, writer, http.StatusUnauthorized, "authentification Bearer requise")
	return false
}

// requireBasicDashboard protège les routes de données du tableau : le tableau
// authentifié en Basic ne peut pas porter un jeton Bearer, ces routes sont
// donc servies sous la même authentification Basic que la page elle-même.
func requireBasicDashboard(serviceLive *ServiceLive, writer http.ResponseWriter, request *http.Request) bool {
	if serviceLive.basicAuthorized(request) {
		return true
	}
	writer.Header().Set("WWW-Authenticate", `Basic realm="c2blue-dns-live", charset="UTF-8"`)
	writeJSONError(serviceLive, writer, http.StatusUnauthorized, "authentification Basic requise")
	return false
}

func methodAllowed(serviceLive *ServiceLive, writer http.ResponseWriter, request *http.Request, method string) bool {
	if request.Method == method {
		return true
	}
	writer.Header().Set("Allow", method)
	writeJSONError(serviceLive, writer, http.StatusMethodNotAllowed, "méthode non autorisée")
	return false
}

func (serviceLive *ServiceLive) handleHealth(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(serviceLive, writer, request, http.MethodGet) {
		return
	}
	writeJSON(serviceLive, writer, http.StatusOK, struct {
		Status string `json:"status"`
	}{Status: "ok"})
}

func (serviceLive *ServiceLive) handleDashboard(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(serviceLive, writer, request, http.MethodGet) {
		return
	}
	if !serviceLive.basicAuthorized(request) {
		writer.Header().Set("WWW-Authenticate", `Basic realm="c2blue-dns-live", charset="UTF-8"`)
		writeJSONError(serviceLive, writer, http.StatusUnauthorized, "authentification Basic requise")
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	writer.WriteHeader(http.StatusOK)
	page := dashboardHTML
	if serviceLive.cfg.Language == "en" {
		page = dashboardHTMLEnglish
	}
	if _, err := io.WriteString(writer, page); err != nil {
		serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: écrire le tableau de bord: %w", err))
	}
}

func (serviceLive *ServiceLive) handleRegistrations(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(serviceLive, writer, request, http.MethodPost) {
		return
	}
	if !requireBearer(serviceLive, writer, request) {
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 64<<10)
	controller := http.NewResponseController(writer)
	if err := controller.SetReadDeadline(time.Now().Add(registrationBodyDeadline)); err != nil {
		serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: poser l'échéance du corps d'enregistrement: %w", err))
	}
	bodyTimedOut := false
	defer func() {
		if err := request.Body.Close(); err != nil && !bodyTimedOut {
			serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: fermer le corps d'enregistrement: %w", err))
		}
	}()
	body, err := readRegistrationBody(request.Body)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			bodyTimedOut = true
			serviceLive.abandonSlowBody(writer, "corps d'enregistrement non terminé avant l'échéance")
			return
		}
		writeJSONError(serviceLive, writer, http.StatusBadRequest, "corps JSON borné à 64 Kio requis")
		return
	}
	if err := controller.SetReadDeadline(time.Time{}); err != nil {
		serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: lever l'échéance du corps d'enregistrement: %w", err))
	}
	if len(body) > 64<<10 {
		writeJSONError(serviceLive, writer, http.StatusBadRequest, "corps JSON borné à 64 Kio requis")
		return
	}
	if err := validateSingleJSONValue(json.NewDecoder(bytes.NewReader(body))); err != nil {
		writeJSONError(serviceLive, writer, http.StatusBadRequest, "JSON unique sans clé dupliquée requis")
		return
	}
	registration, err := decodeRegistration(bytes.NewReader(body))
	if err != nil {
		writeJSONError(serviceLive, writer, http.StatusBadRequest, "contrat JSON d'enregistrement non respecté")
		return
	}
	sourceKey, err := normalizeRegistration(registration)
	if err != nil {
		writeJSONError(serviceLive, writer, http.StatusBadRequest, "identité d'enregistrement invalide")
		return
	}

	serviceLive.mu.Lock()
	if serviceLive.closing {
		serviceLive.mu.Unlock()
		writeJSONError(serviceLive, writer, http.StatusServiceUnavailable, "service en arrêt")
		return
	}
	if serviceLive.runs[registration.RunID] != nil {
		serviceLive.mu.Unlock()
		writeJSONError(serviceLive, writer, http.StatusConflict, "run_id déjà utilisé")
		return
	}
	if previous := serviceLive.sources[sourceKey]; previous != nil {
		if previous.registered {
			serviceLive.mu.Unlock()
			writeJSONError(serviceLive, writer, http.StatusConflict, "couple IP:port déjà enregistré")
			return
		}
		if err := serviceLive.finishSourceLocked(request.Context(), previous); err != nil {
			serviceLive.asynchronousErr = errors.Join(serviceLive.asynchronousErr, err)
			serviceLive.mu.Unlock()
			writeJSONError(serviceLive, writer, http.StatusInternalServerError, "clôture de la source inconnue impossible")
			return
		}
	}
	serviceLive.runOrdinal++
	source, err := serviceLive.newSourceLocked(sourceKey, registration.RunID, registration.Kind, serviceLive.runOrdinal)
	if err != nil {
		serviceLive.journalErr = errors.Join(serviceLive.journalErr, err)
		serviceLive.mu.Unlock()
		writeJSONError(serviceLive, writer, http.StatusInternalServerError, "création du run impossible")
		return
	}
	publicRun := liveRun{
		RunID:      registration.RunID,
		Kind:       registration.Kind,
		SourceIP:   sourceKey.Addr().String(),
		SourcePort: sourceKey.Port(),
	}
	serviceLive.sources[sourceKey] = source
	serviceLive.runs[registration.RunID] = &liveRunHistory{public: publicRun, source: source, ordinal: serviceLive.runOrdinal}
	serviceLive.mu.Unlock()
	writeJSON(serviceLive, writer, http.StatusCreated, publicRun)
}

func validateSingleJSONValue(decoder *json.Decoder) error {
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	_, err := decoder.Token()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("dnslive: seconde valeur JSON")
	}
	return err
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("dnslive: clé JSON non textuelle")
			}
			if _, duplicate := keys[key]; duplicate {
				return errors.New("dnslive: clé JSON dupliquée")
			}
			keys[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("dnslive: délimiteur JSON inattendu")
	}
}

func (serviceLive *ServiceLive) handleFinish(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(serviceLive, writer, request, http.MethodPost) {
		return
	}
	if !requireBearer(serviceLive, writer, request) {
		return
	}
	remainder := strings.TrimPrefix(request.URL.Path, "/api/v1/registrations/")
	runID, found := strings.CutSuffix(remainder, "/finish")
	if !found || !validRunID(runID) {
		writeJSONError(serviceLive, writer, http.StatusNotFound, "run inconnu")
		return
	}
	serviceLive.mu.Lock()
	history := serviceLive.runs[runID]
	if history == nil {
		serviceLive.mu.Unlock()
		writeJSONError(serviceLive, writer, http.StatusNotFound, "run inconnu")
		return
	}
	if err := serviceLive.finishSourceLocked(request.Context(), history.source); err != nil {
		serviceLive.journalErr = errors.Join(serviceLive.journalErr, err)
		serviceLive.mu.Unlock()
		writeJSONError(serviceLive, writer, http.StatusInternalServerError, "finalisation de la preuve impossible")
		return
	}
	publicRun := history.public
	serviceLive.mu.Unlock()
	writeJSON(serviceLive, writer, http.StatusOK, publicRun)
}

func validRunID(runID string) bool {
	if len(runID) == 0 || len(runID) > 128 {
		return false
	}
	for _, character := range runID {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func validKind(kind string) bool {
	if len(kind) == 0 || len(kind) > 128 || strings.TrimSpace(kind) != kind {
		return false
	}
	for _, character := range kind {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func (serviceLive *ServiceLive) handleRuns(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(serviceLive, writer, request, http.MethodGet) || !requireBearer(serviceLive, writer, request) {
		return
	}
	serviceLive.serveRuns(writer)
}

func (serviceLive *ServiceLive) handleDashboardRuns(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(serviceLive, writer, request, http.MethodGet) || !requireBasicDashboard(serviceLive, writer, request) {
		return
	}
	serviceLive.serveRuns(writer)
}

// serveRuns porte la charge utile commune aux routes Bearer /api/v1/runs et
// Basic /dashboard/api/runs : mêmes historiques, même tri par ordinal.
func (serviceLive *ServiceLive) serveRuns(writer http.ResponseWriter) {
	serviceLive.mu.Lock()
	histories := make([]*liveRunHistory, 0, len(serviceLive.runs))
	for _, history := range serviceLive.runs {
		histories = append(histories, history)
	}
	sort.Slice(histories, func(first, second int) bool {
		return histories[first].ordinal < histories[second].ordinal
	})
	runs := make([]liveRun, 0, len(histories))
	for _, history := range histories {
		runs = append(runs, history.public)
	}
	serviceLive.mu.Unlock()
	writeJSON(serviceLive, writer, http.StatusOK, runs)
}

func (serviceLive *ServiceLive) handleEvents(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(serviceLive, writer, request, http.MethodGet) || !requireBearer(serviceLive, writer, request) {
		return
	}
	serviceLive.serveEvents(writer, request)
}

func (serviceLive *ServiceLive) handleDashboardEvents(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(serviceLive, writer, request, http.MethodGet) || !requireBasicDashboard(serviceLive, writer, request) {
		return
	}
	serviceLive.serveEvents(writer, request)
}

// serveEvents porte la charge utile commune aux routes Bearer /api/v1/events
// et Basic /dashboard/api/events : même borne after, même filtre run_id, même
// fenêtre mémoire et même en-tête X-Events-Evicted.
func (serviceLive *ServiceLive) serveEvents(writer http.ResponseWriter, request *http.Request) {
	after := uint64(0)
	if text := request.URL.Query().Get("after"); text != "" {
		parsed, err := strconv.ParseUint(text, 10, 64)
		if err != nil {
			writeJSONError(serviceLive, writer, http.StatusBadRequest, "after doit être un entier non signé")
			return
		}
		after = parsed
	}
	runID := request.URL.Query().Get("run_id")
	serviceLive.mu.Lock()
	events := make([]liveEvent, 0, len(serviceLive.events))
	for _, event := range serviceLive.events {
		if event.Sequence > after && (runID == "" || event.RunID == runID) {
			events = append(events, event)
		}
	}
	eventsEvicted := serviceLive.eventsEvicted
	serviceLive.mu.Unlock()
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("X-Events-Evicted", strconv.FormatUint(eventsEvicted, 10))
	writer.WriteHeader(http.StatusOK)
	if err := writeEntirely(writer, []byte{'['}); err != nil {
		serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: écrire la réponse d'événements: %w", err))
		return
	}
	for index, event := range events {
		if index > 0 {
			if err := writeEntirely(writer, []byte{','}); err != nil {
				serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: écrire la réponse d'événements: %w", err))
				return
			}
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: encoder l'événement %d: %w", event.Sequence, err))
			return
		}
		if err := writeEntirely(writer, encoded); err != nil {
			serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: écrire la réponse d'événements: %w", err))
			return
		}
	}
	if err := writeEntirely(writer, []byte("]\n")); err != nil {
		serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: écrire la réponse d'événements: %w", err))
	}
}

func (serviceLive *ServiceLive) handleReasons(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(serviceLive, writer, request, http.MethodGet) || !requireBearer(serviceLive, writer, request) {
		return
	}
	serviceLive.serveReasons(writer)
}

func (serviceLive *ServiceLive) handleDashboardReasons(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(serviceLive, writer, request, http.MethodGet) || !requireBasicDashboard(serviceLive, writer, request) {
		return
	}
	serviceLive.serveReasons(writer)
}

// serveReasons porte la charge utile commune aux routes Bearer /api/v1/reasons
// et Basic /dashboard/api/reasons : mêmes guides, dans la langue configurée.
func (serviceLive *ServiceLive) serveReasons(writer http.ResponseWriter) {
	writeJSON(serviceLive, writer, http.StatusOK, reasonGuidesForLanguage(serviceLive.cfg.Language))
}

func (serviceLive *ServiceLive) handleEvidence(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(serviceLive, writer, request, http.MethodGet) || !requireBearer(serviceLive, writer, request) {
		return
	}
	runID := strings.TrimPrefix(request.URL.Path, "/api/v1/evidence/")
	if !validRunID(runID) {
		writeJSONError(serviceLive, writer, http.StatusNotFound, "preuve inconnue")
		return
	}
	serviceLive.mu.Lock()
	history := serviceLive.runs[runID]
	if history == nil || !history.source.finished {
		serviceLive.mu.Unlock()
		writeJSONError(serviceLive, writer, http.StatusNotFound, "preuve non finalisée")
		return
	}
	manifest, err := history.source.evidence.manifest()
	serviceLive.mu.Unlock()
	if err != nil {
		writeJSONError(serviceLive, writer, http.StatusInternalServerError, "manifeste indisponible")
		return
	}
	writeJSON(serviceLive, writer, http.StatusOK, manifest)
}

func writeJSON(serviceLive *ServiceLive, writer http.ResponseWriter, status int, payload any) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		writeJSONError(serviceLive, writer, http.StatusInternalServerError, "encodage JSON impossible")
		return
	}
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	encoded = append(encoded, '\n')
	if err := writeEntirely(writer, encoded); err != nil {
		serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: écrire la réponse HTTP: %w", err))
	}
}

func writeJSONError(serviceLive *ServiceLive, writer http.ResponseWriter, status int, message string) {
	encoded, err := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: message})
	if err != nil {
		serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: encoder une erreur HTTP: %w", err))
		return
	}
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	if err := writeEntirely(writer, append(encoded, '\n')); err != nil {
		serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: écrire une erreur HTTP: %w", err))
	}
}

func decodeRegistration(requestBody io.Reader) (registrationRequest, error) {
	var registration registrationRequest
	decoder := json.NewDecoder(requestBody)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registration); err != nil {
		return registrationRequest{}, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return registrationRequest{}, errors.New("dnslive: valeur JSON supplémentaire")
	}
	return registration, nil
}

func normalizeRegistration(registration registrationRequest) (netip.AddrPort, error) {
	if !validRunID(registration.RunID) || !validKind(registration.Kind) || registration.SourcePort == 0 {
		return netip.AddrPort{}, errors.New("dnslive: identité ou port d'enregistrement invalide")
	}
	sourceIP, err := netip.ParseAddr(registration.SourceIP)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("dnslive: IP d'enregistrement invalide: %w", err)
	}
	return netip.AddrPortFrom(sourceIP.Unmap(), registration.SourcePort), nil
}

func readRegistrationBody(body io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(body, (64<<10)+1))
}

// abandonSlowBody ferme une requête dont le corps n'a pas été terminé avant
// l'échéance : réponse 408 puis clôture RST de la connexion, sans goroutine
// ni connexion retenue indéfiniment. À défaut de détournement, la réponse
// 408 passe par le rédacteur standard.
func (serviceLive *ServiceLive) abandonSlowBody(writer http.ResponseWriter, message string) {
	controller := http.NewResponseController(writer)
	conn, buffered, err := controller.Hijack()
	if err != nil {
		writeJSONError(serviceLive, writer, http.StatusRequestTimeout, message)
		return
	}
	var abandonErr error
	payload, marshalErr := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: message})
	if marshalErr == nil {
		payload = append(payload, '\n')
		head := fmt.Sprintf("HTTP/1.1 408 Request Timeout\r\nContent-Type: application/json; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(payload))
		abandonErr = errors.Join(writeEntirely(buffered, append([]byte(head), payload...)), buffered.Flush())
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		if lingerErr := tcp.SetLinger(0); lingerErr != nil {
			abandonErr = errors.Join(abandonErr, fmt.Errorf("dnslive: poser SO_LINGER 0: %w", lingerErr))
		}
	}
	if closeErr := conn.Close(); closeErr != nil {
		abandonErr = errors.Join(abandonErr, fmt.Errorf("dnslive: fermer la connexion lente: %w", closeErr))
	}
	if abandonErr != nil {
		serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: abandonner le corps lent: %w", abandonErr))
	}
}
