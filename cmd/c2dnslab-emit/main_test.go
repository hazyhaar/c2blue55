package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

func emitSourceDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(file)
}

func busyMessage(t *testing.T) (string, bool) {
	t.Helper()
	entries, err := os.ReadDir(emitSourceDir())
	if err != nil {
		t.Fatalf("lecture du repertoire source: %v", err)
	}
	fileSet := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		parsed, parseErr := parser.ParseFile(fileSet, filepath.Join(emitSourceDir(), entry.Name()), nil, 0)
		if parseErr != nil {
			continue
		}
		for _, decl := range parsed.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range value.Names {
					if ident.Name != "errCampaignBusy" || i >= len(value.Values) {
						continue
					}
					message, ok := callString(value.Values[i])
					if ok {
						return message, true
					}
				}
			}
		}
	}
	return "", false
}

func callString(expr ast.Expr) (string, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) < 1 {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "New" && sel.Sel.Name != "Errorf") {
		return "", false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	text, err := strconv.Unquote(lit.Value)
	if err != nil || strings.Contains(text, "%") {
		return "", false
	}
	return text, true
}

func checkBusyError(t *testing.T, candidateErr error) error {
	t.Helper()
	message, ok := busyMessage(t)
	if !ok {
		return errors.New("sentinelle errCampaignBusy introuvable")
	}
	if candidateErr == nil {
		return errors.New("erreur nil au lieu de errCampaignBusy")
	}
	for current := candidateErr; current != nil; current = errors.Unwrap(current) {
		if current.Error() == message {
			return nil
		}
	}
	if strings.Contains(candidateErr.Error(), message) {
		return nil
	}
	return candidateErr
}

func injectLaunch(r *runner, launch func(context.Context, string, ...string) (int, error)) bool {
	target := reflect.ValueOf(r).Elem().FieldByName("launch")
	if !target.IsValid() || !target.CanAddr() || target.Type() != reflect.TypeOf(launch) {
		return false
	}
	reflect.NewAt(target.Type(), unsafe.Pointer(target.UnsafeAddr())).Elem().Set(reflect.ValueOf(launch))
	return true
}

func lookupControl(r *runner) http.Handler {
	method := reflect.ValueOf(r).MethodByName("ControlHandler")
	if !method.IsValid() {
		method = reflect.ValueOf(r).MethodByName("Handler")
	}
	if !method.IsValid() || method.Type().NumIn() != 0 || method.Type().NumOut() != 1 {
		return nil
	}
	out := method.Call(nil)
	controlMux, ok := out[0].Interface().(http.Handler)
	if !ok {
		return nil
	}
	return controlMux
}

func iodineCampaign(runID string, duration time.Duration) dnslab.Campaign {
	return dnslab.Campaign{
		RunID:    runID,
		Family:   "redhost-iodine",
		Tool:     "iodine",
		Server:   "10.55.0.1",
		Zone:     "lab.pound2pound.fr",
		Duration: duration,
		MaxQPS:   10,
	}
}

func TestRunner_OneCampaignAtATime(t *testing.T) {
	dir := t.TempDir()
	r := &runner{runsDir: dir}
	started := make(chan struct{})
	var startedOnce sync.Once
	injected := injectLaunch(r, func(ctx context.Context, name string, args ...string) (int, error) {
		startedOnce.Do(func() { close(started) })
		<-ctx.Done()
		return 0, nil
	})
	first := iodineCampaign("s05-runner-1", 2*time.Second)
	second := iodineCampaign("s05-runner-2", 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		_, runErr := r.run(ctx, first)
		errCh <- runErr
	}()

	select {
	case <-started:
	case runErr := <-errCh:
		_, secondErr := r.run(context.Background(), second)
		if busyCheckErr := checkBusyError(t, secondErr); busyCheckErr != nil {
			_, present := busyMessage(t)
			t.Fatalf("second appel err=%v (%v), attendu errors.Is(err, errCampaignBusy) ; lanceur injecté=%v, sentinelle présente=%v, première campagne=%v", secondErr, busyCheckErr, injected, present, runErr)
		}
	case <-time.After(400 * time.Millisecond):
		t.Fatal("la première campagne n'a ni appelé le lanceur ni rendu : l'occupation n'est pas observable")
	}

	_, secondErr := r.run(context.Background(), second)
	if busyCheckErr := checkBusyError(t, secondErr); busyCheckErr != nil {
		_, present := busyMessage(t)
		t.Fatalf("second appel err=%v (%v), attendu errors.Is(err, errCampaignBusy) sans écriture de manifeste ; sentinelle présente=%v", secondErr, busyCheckErr, present)
	}
	secondPath := filepath.Join(dir, second.RunID+".manifest.json")
	if _, statErr := os.Stat(secondPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("manifeste du second run accessible (%v) : le refus doit être sans effet", statErr)
	}
	select {
	case runErr := <-errCh:
		if runErr != nil {
			t.Fatalf("première campagne: %v", runErr)
		}
	case <-ctx.Done():
		t.Fatal("première campagne non terminée")
	}
	firstPath := filepath.Join(dir, first.RunID+".manifest.json")
	if _, statErr := os.Stat(firstPath); statErr != nil {
		t.Fatalf("manifeste du premier run absent de runsDir: %v", statErr)
	}
	third := iodineCampaign("s05-runner-3", 2*time.Second)
	thirdCtx, thirdCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer thirdCancel()
	_, thirdErr := r.run(thirdCtx, third)
	if thirdErr != nil {
		t.Fatalf("nouvel appel après la fin: %v, attendu accepté", thirdErr)
	}
}

func readReply(t *testing.T, resp *http.Response) []byte {
	t.Helper()
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("lecture de la réponse: %v", err)
	}
	return payload
}

func postCampaign(t *testing.T, client *http.Client, endpoint string, campaign dnslab.Campaign) (*http.Response, []byte) {
	t.Helper()
	payload, err := json.Marshal(campaign)
	if err != nil {
		t.Fatalf("encodage de la campagne: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, endpoint+"/v1/campaign", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("requête: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/campaign: %v", err)
	}
	return resp, readReply(t, resp)
}

func getPath(t *testing.T, client *http.Client, endpoint, path string) (*http.Response, []byte) {
	t.Helper()
	resp, err := client.Get(endpoint + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp, readReply(t, resp)
}

func hasNumericCounter(payload []byte) bool {
	var counters map[string]json.RawMessage
	if err := json.Unmarshal(payload, &counters); err != nil || len(counters) == 0 {
		return false
	}
	for _, field := range counters {
		var number json.Number
		dec := json.NewDecoder(bytes.NewReader(field))
		dec.UseNumber()
		if err := dec.Decode(&number); err != nil {
			continue
		}
		if _, err := number.Float64(); err == nil {
			return true
		}
	}
	return false
}

func TestControlHTTP_CampaignValidationAndStatus(t *testing.T) {
	dir := t.TempDir()
	r := &runner{runsDir: dir}
	started := make(chan struct{})
	finished := make(chan struct{})
	var startedOnce sync.Once
	var finishedOnce sync.Once
	injected := injectLaunch(r, func(ctx context.Context, name string, args ...string) (int, error) {
		startedOnce.Do(func() { close(started) })
		<-ctx.Done()
		finishedOnce.Do(func() { close(finished) })
		return 0, nil
	})
	controlMux := lookupControl(r)
	if controlMux == nil {
		t.Fatal("serveur de contrôle absent : (*runner).ControlHandler() ou (*runner).Handler() http.Handler est requis pour que POST /v1/campaign rende 400 ou 202, qu'un second POST rende 409, et que GET /healthz ainsi que GET /v1/runs répondent")
	}
	if !injected {
		t.Fatal("runner.launch absent : le lanceur factice ne peut pas être injecté, un processus iodine réel ne doit pas être lancé")
	}
	server := httptest.NewServer(controlMux)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 4 * time.Second

	refused := iodineCampaign("s05-http-refus", time.Second)
	refused.Server = "8.8.8.8"
	resp, _ := postCampaign(t, client, server.URL, refused)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("POST Server=8.8.8.8: statut %d, attendu 400", resp.StatusCode)
	}

	accepted := iodineCampaign("s05-http-ok", time.Second)
	resp, payload := postCampaign(t, client, server.URL, accepted)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("POST campagne valide: statut %d corps %s, attendu 202", resp.StatusCode, payload)
	}
	var acceptedBody struct {
		RunID string `json:"run_id"`
	}
	if err := json.Unmarshal(payload, &acceptedBody); err != nil || acceptedBody.RunID != accepted.RunID {
		t.Fatalf("corps 202=%s, attendu JSON {run_id:%s}", payload, accepted.RunID)
	}

	overlap := iodineCampaign("s05-http-overlap", time.Second)
	resp, _ = postCampaign(t, client, server.URL, overlap)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("second POST pendant l'exécution: statut %d, attendu 409", resp.StatusCode)
	}
	overlapPath := filepath.Join(dir, overlap.RunID+".manifest.json")
	if _, statErr := os.Stat(overlapPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("manifeste du second POST présent (%v) : 409 doit être sans effet", statErr)
	}

	resp, payload = getPath(t, client, server.URL, "/healthz")
	if resp.StatusCode != http.StatusOK || !hasNumericCounter(payload) {
		t.Fatalf("GET /healthz: statut %d corps %s, attendu 200 et des compteurs numériques", resp.StatusCode, payload)
	}

	select {
	case <-finished:
	case <-time.After(4 * time.Second):
		t.Fatal("campagne non terminée : GET /v1/runs ne peut pas lister le manifeste")
	}
	resp, payload = getPath(t, client, server.URL, "/v1/runs")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/runs: statut %d corps %s, attendu 200", resp.StatusCode, payload)
	}
	var listed []map[string]any
	if err := json.Unmarshal(payload, &listed); err != nil {
		t.Fatalf("GET /v1/runs corps %s, attendu un tableau JSON de manifestes", payload)
	}
	found := false
	for _, entry := range listed {
		if id, ok := entry["run_id"].(string); ok && id == accepted.RunID {
			found = true
		}
	}
	if !found {
		t.Fatalf("GET /v1/runs ne liste pas %s : %s", accepted.RunID, payload)
	}
	select {
	case <-started:
	default:
		t.Fatal("le lanceur factice n'a pas été appelé pour la campagne acceptée")
	}
}
