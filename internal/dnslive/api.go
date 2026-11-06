package dnslive

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

type registrationRequest struct {
	RunID      string `json:"run_id"`
	Kind       string `json:"kind"`
	SourceIP   string `json:"source_ip"`
	SourcePort uint16 `json:"source_port"`
}

func (service *Service) routes() http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/healthz":
			service.handleHealth(writer, request)
		case request.URL.Path == "/":
			service.handleDashboard(writer, request)
		case request.URL.Path == "/api/v1/registrations":
			service.handleRegistrations(writer, request)
		case strings.HasPrefix(request.URL.Path, "/api/v1/registrations/"):
			service.handleFinish(writer, request)
		case request.URL.Path == "/api/v1/runs":
			service.handleRuns(writer, request)
		case request.URL.Path == "/api/v1/events":
			service.handleEvents(writer, request)
		case request.URL.Path == "/api/v1/reasons":
			service.handleReasons(writer, request)
		case strings.HasPrefix(request.URL.Path, "/api/v1/evidence/"):
			service.handleEvidence(writer, request)
		default:
			writeJSONError(service, writer, http.StatusNotFound, "ressource inconnue")
		}
	})
}

func tokenMatches(provided, expected string) bool {
	providedDigest := sha256.Sum256([]byte(provided))
	expectedDigest := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(providedDigest[:], expectedDigest[:]) == 1
}

func (service *Service) bearerAuthorized(request *http.Request) bool {
	authorization := request.Header.Get("Authorization")
	if token, found := strings.CutPrefix(authorization, "Bearer "); found && tokenMatches(token, service.cfg.DashboardToken) {
		return true
	}
	_, password, found := request.BasicAuth()
	return found && tokenMatches(password, service.cfg.DashboardToken)
}

func (service *Service) basicAuthorized(request *http.Request) bool {
	_, password, found := request.BasicAuth()
	return found && tokenMatches(password, service.cfg.DashboardToken)
}

func requireBearer(service *Service, writer http.ResponseWriter, request *http.Request) bool {
	if service.bearerAuthorized(request) {
		return true
	}
	writer.Header().Set("WWW-Authenticate", `Bearer realm="c2blue-dns-live"`)
	writeJSONError(service, writer, http.StatusUnauthorized, "authentification Bearer requise")
	return false
}

func methodAllowed(service *Service, writer http.ResponseWriter, request *http.Request, method string) bool {
	if request.Method == method {
		return true
	}
	writer.Header().Set("Allow", method)
	writeJSONError(service, writer, http.StatusMethodNotAllowed, "méthode non autorisée")
	return false
}

func (service *Service) handleHealth(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(service, writer, request, http.MethodGet) {
		return
	}
	writeJSON(service, writer, http.StatusOK, struct {
		Status string `json:"status"`
	}{Status: "ok"})
}

func (service *Service) handleDashboard(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(service, writer, request, http.MethodGet) {
		return
	}
	if !service.basicAuthorized(request) {
		writer.Header().Set("WWW-Authenticate", `Basic realm="c2blue-dns-live", charset="UTF-8"`)
		writeJSONError(service, writer, http.StatusUnauthorized, "authentification Basic requise")
		return
	}
	writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	writer.WriteHeader(http.StatusOK)
	page := dashboardHTML
	if service.cfg.Language == "en" {
		page = dashboardHTMLEnglish
	}
	if _, err := io.WriteString(writer, page); err != nil {
		service.recordAsynchronousError(fmt.Errorf("dnslive: écrire le tableau de bord: %w", err))
	}
}

func (service *Service) handleRegistrations(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(service, writer, request, http.MethodPost) {
		return
	}
	if !requireBearer(service, writer, request) {
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 64<<10)
	defer func() {
		if err := request.Body.Close(); err != nil {
			service.recordAsynchronousError(fmt.Errorf("dnslive: fermer le corps d'enregistrement: %w", err))
		}
	}()
	body, err := readRegistrationBody(request.Body)
	if err != nil || len(body) > 64<<10 {
		writeJSONError(service, writer, http.StatusBadRequest, "corps JSON borné à 64 Kio requis")
		return
	}
	if err := validateSingleJSONValue(json.NewDecoder(bytes.NewReader(body))); err != nil {
		writeJSONError(service, writer, http.StatusBadRequest, "JSON unique sans clé dupliquée requis")
		return
	}
	registration, err := decodeRegistration(bytes.NewReader(body))
	if err != nil {
		writeJSONError(service, writer, http.StatusBadRequest, "contrat JSON d'enregistrement non respecté")
		return
	}
	sourceKey, err := normalizeRegistration(registration)
	if err != nil {
		writeJSONError(service, writer, http.StatusBadRequest, "identité d'enregistrement invalide")
		return
	}

	service.mu.Lock()
	if service.closing {
		service.mu.Unlock()
		writeJSONError(service, writer, http.StatusServiceUnavailable, "service en arrêt")
		return
	}
	if service.runs[registration.RunID] != nil {
		service.mu.Unlock()
		writeJSONError(service, writer, http.StatusConflict, "run_id déjà utilisé")
		return
	}
	if previous := service.sources[sourceKey]; previous != nil {
		if previous.registered {
			service.mu.Unlock()
			writeJSONError(service, writer, http.StatusConflict, "couple IP:port déjà enregistré")
			return
		}
		if err := service.finishSourceLocked(request.Context(), previous); err != nil {
			service.journalErr = errors.Join(service.journalErr, err)
			service.mu.Unlock()
			writeJSONError(service, writer, http.StatusInternalServerError, "clôture de la source inconnue impossible")
			return
		}
	}
	service.runOrdinal++
	source, err := service.newSourceLocked(sourceKey, registration.RunID, registration.Kind, service.runOrdinal)
	if err != nil {
		service.journalErr = errors.Join(service.journalErr, err)
		service.mu.Unlock()
		writeJSONError(service, writer, http.StatusInternalServerError, "création du run impossible")
		return
	}
	publicRun := liveRun{
		RunID:      registration.RunID,
		Kind:       registration.Kind,
		SourceIP:   sourceKey.Addr().String(),
		SourcePort: sourceKey.Port(),
	}
	service.sources[sourceKey] = source
	service.runs[registration.RunID] = &liveRunHistory{public: publicRun, source: source, ordinal: service.runOrdinal}
	service.mu.Unlock()
	writeJSON(service, writer, http.StatusCreated, publicRun)
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

func (service *Service) handleFinish(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(service, writer, request, http.MethodPost) {
		return
	}
	if !requireBearer(service, writer, request) {
		return
	}
	remainder := strings.TrimPrefix(request.URL.Path, "/api/v1/registrations/")
	runID, found := strings.CutSuffix(remainder, "/finish")
	if !found || !validRunID(runID) {
		writeJSONError(service, writer, http.StatusNotFound, "run inconnu")
		return
	}
	service.mu.Lock()
	history := service.runs[runID]
	if history == nil {
		service.mu.Unlock()
		writeJSONError(service, writer, http.StatusNotFound, "run inconnu")
		return
	}
	if err := service.finishSourceLocked(request.Context(), history.source); err != nil {
		service.journalErr = errors.Join(service.journalErr, err)
		service.mu.Unlock()
		writeJSONError(service, writer, http.StatusInternalServerError, "finalisation de la preuve impossible")
		return
	}
	publicRun := history.public
	service.mu.Unlock()
	writeJSON(service, writer, http.StatusOK, publicRun)
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

func (service *Service) handleRuns(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(service, writer, request, http.MethodGet) || !requireBearer(service, writer, request) {
		return
	}
	service.mu.Lock()
	histories := make([]*liveRunHistory, 0, len(service.runs))
	for _, history := range service.runs {
		histories = append(histories, history)
	}
	sort.Slice(histories, func(first, second int) bool {
		return histories[first].ordinal < histories[second].ordinal
	})
	runs := make([]liveRun, 0, len(histories))
	for _, history := range histories {
		runs = append(runs, history.public)
	}
	service.mu.Unlock()
	writeJSON(service, writer, http.StatusOK, runs)
}

func (service *Service) handleEvents(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(service, writer, request, http.MethodGet) || !requireBearer(service, writer, request) {
		return
	}
	after := uint64(0)
	if text := request.URL.Query().Get("after"); text != "" {
		parsed, err := strconv.ParseUint(text, 10, 64)
		if err != nil {
			writeJSONError(service, writer, http.StatusBadRequest, "after doit être un entier non signé")
			return
		}
		after = parsed
	}
	runID := request.URL.Query().Get("run_id")
	service.mu.Lock()
	events := make([]liveEvent, 0)
	for _, event := range service.events {
		if event.Sequence > after && (runID == "" || event.RunID == runID) {
			events = append(events, event)
		}
	}
	eventsEvicted := service.eventsEvicted
	service.mu.Unlock()
	writer.Header().Set("X-Events-Evicted", strconv.FormatUint(eventsEvicted, 10))
	writeJSON(service, writer, http.StatusOK, events)
}

func (service *Service) handleReasons(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(service, writer, request, http.MethodGet) || !requireBearer(service, writer, request) {
		return
	}
	writeJSON(service, writer, http.StatusOK, reasonGuidesForLanguage(service.cfg.Language))
}

func (service *Service) handleEvidence(writer http.ResponseWriter, request *http.Request) {
	if !methodAllowed(service, writer, request, http.MethodGet) || !requireBearer(service, writer, request) {
		return
	}
	runID := strings.TrimPrefix(request.URL.Path, "/api/v1/evidence/")
	if !validRunID(runID) {
		writeJSONError(service, writer, http.StatusNotFound, "preuve inconnue")
		return
	}
	service.mu.Lock()
	history := service.runs[runID]
	if history == nil || !history.source.finished {
		service.mu.Unlock()
		writeJSONError(service, writer, http.StatusNotFound, "preuve non finalisée")
		return
	}
	manifest, err := history.source.evidence.manifest()
	service.mu.Unlock()
	if err != nil {
		writeJSONError(service, writer, http.StatusInternalServerError, "manifeste indisponible")
		return
	}
	writeJSON(service, writer, http.StatusOK, manifest)
}

func writeJSON(service *Service, writer http.ResponseWriter, status int, payload any) {
	encoded, err := json.Marshal(payload)
	if err != nil {
		writeJSONError(service, writer, http.StatusInternalServerError, "encodage JSON impossible")
		return
	}
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	encoded = append(encoded, '\n')
	if err := writeEntirely(writer, encoded); err != nil {
		service.recordAsynchronousError(fmt.Errorf("dnslive: écrire la réponse HTTP: %w", err))
	}
}

func writeJSONError(service *Service, writer http.ResponseWriter, status int, message string) {
	encoded, err := json.Marshal(struct {
		Error string `json:"error"`
	}{Error: message})
	if err != nil {
		service.recordAsynchronousError(fmt.Errorf("dnslive: encoder une erreur HTTP: %w", err))
		return
	}
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	if err := writeEntirely(writer, append(encoded, '\n')); err != nil {
		service.recordAsynchronousError(fmt.Errorf("dnslive: écrire une erreur HTTP: %w", err))
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
