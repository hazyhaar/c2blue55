package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"

	c2 "github.com/hazyhaar/c2blue55"
)

// benchHealthScope attache la santé à la seule supervision de cette campagne.
type benchHealthScope struct{}

type benchHealthController struct {
	mu       sync.Mutex
	ready    bool
	revoked  bool
	err      error
	owner    context.Context
	address  string
	server   *http.Server
	listener net.Listener
	done     chan struct{}
	stopped  chan struct{}
	stop     chan struct{}
	stopOnce sync.Once
}

func benchValidateHealthAddress(address string) error {
	parsed, err := netip.ParseAddrPort(address)
	if err != nil || !parsed.Addr().IsLoopback() {
		return fmt.Errorf("healthz exige une adresse IP explicite de boucle locale: %q", address)
	}
	return nil
}

func newBenchHealth(ctx context.Context, address string) (*benchHealthController, error) {
	if ctx == nil {
		return nil, fmt.Errorf("contexte de santé absent")
	}
	if err := benchValidateHealthAddress(address); err != nil {
		return nil, err
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	health := &benchHealthController{
		owner: ctx, address: listener.Addr().String(), listener: listener,
		done: make(chan struct{}), stopped: make(chan struct{}), stop: make(chan struct{}),
	}
	health.server = &http.Server{
		Handler:           http.HandlerFunc(health.serveHTTP),
		ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 2 * time.Second,
		WriteTimeout: 2 * time.Second, IdleTimeout: 2 * time.Second,
		MaxHeaderBytes: 8192,
	}
	go func() {
		defer close(health.done)
		err := health.server.Serve(health.listener)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			health.remember(err)
		}
		health.NotReady()
	}()
	go health.run()
	return health, nil
}

func (health *benchHealthController) Addr() string { return health.address }

func (health *benchHealthController) Done() <-chan struct{} { return health.done }

func (health *benchHealthController) NotReady() {
	health.mu.Lock()
	defer health.mu.Unlock()
	health.ready, health.revoked = false, true
}

func (health *benchHealthController) prepare() error {
	health.mu.Lock()
	defer health.mu.Unlock()
	if health.revoked || health.owner.Err() != nil {
		return fmt.Errorf("préparation de santé révoquée")
	}
	health.ready = true
	return nil
}

func (health *benchHealthController) remember(err error) {
	if err == nil {
		return
	}
	health.mu.Lock()
	defer health.mu.Unlock()
	health.err = errors.Join(health.err, err)
	health.ready, health.revoked = false, true
}

func (health *benchHealthController) run() {
	defer close(health.stopped)
	select {
	case <-health.owner.Done():
	case <-health.stop:
	case <-health.done:
	}
	health.NotReady()
	cleanup, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := health.server.Shutdown(cleanup); err != nil {
		health.remember(err)
		health.remember(health.server.Close())
	}
}

func (health *benchHealthController) Close(ctx context.Context) error {
	health.NotReady()
	health.stopOnce.Do(func() { close(health.stop) })
	if ctx == nil {
		return fmt.Errorf("contexte de clôture HTTP absent")
	}
	var closeErr error
	for _, finished := range []<-chan struct{}{health.stopped, health.done} {
		select {
		case <-finished:
		case <-ctx.Done():
			closeErr = ctx.Err()
		}
		if closeErr != nil {
			break
		}
	}
	health.mu.Lock()
	defer health.mu.Unlock()
	return errors.Join(health.err, closeErr)
}

func (health *benchHealthController) serveHTTP(destination http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(destination, request.Body, 1024)
	defer func() { health.remember(request.Body.Close()) }()
	status := http.StatusOK
	var body string
	switch {
	case request.URL.Path != "/healthz":
		status = http.StatusNotFound
	case request.Method != http.MethodGet:
		status = http.StatusMethodNotAllowed
		destination.Header().Set("Allow", http.MethodGet)
	default:
		health.mu.Lock()
		ready := health.ready && !health.revoked && health.owner.Err() == nil
		health.mu.Unlock()
		if !ready {
			status = http.StatusServiceUnavailable
		}
		destination.Header().Set("Content-Type", "application/json")
		body = "{\"emitter\":\"generator\",\"generator\":\"cmd/c2agent/bench_health.go:newBenchHealth\",\"ready\":" + strconv.FormatBool(ready) + "}\n"
	}
	if body == "" {
		body = http.StatusText(status) + "\n"
		destination.Header().Set("Content-Type", "text/plain; charset=utf-8")
	}
	destination.Header().Set("Cache-Control", "no-store")
	destination.WriteHeader(status)
	n, err := io.WriteString(destination, body)
	if n != len(body) && err == nil {
		err = io.ErrShortWrite
	}
	health.remember(err)
}

type benchHealthSource struct {
	source  io.Reader
	health  *benchHealthController
	lastErr error
}

func (source *benchHealthSource) Read(destination []byte) (int, error) {
	n, err := source.source.Read(destination)
	if err != nil {
		source.lastErr = err
		source.health.NotReady()
	}
	return n, err
}

// benchHealthReader conserve l'unique tampon de 24 octets, même si la préparation
// échoue. Son propriétaire peut alors copier les octets reçus dans la pièce d'échec.
type benchHealthReader struct {
	header *bufio.Reader
	source *benchHealthSource
	stream io.Reader
	health *benchHealthController
}

func newBenchHealthReader(source io.Reader, health *benchHealthController) *benchHealthReader {
	monitored := &benchHealthSource{source: source, health: health}
	header := bufio.NewReaderSize(io.LimitReader(monitored, 24), 24)
	return &benchHealthReader{
		header: header, source: monitored, stream: io.MultiReader(header, monitored), health: health,
	}
}

func (reader *benchHealthReader) Read(destination []byte) (int, error) {
	n, err := reader.stream.Read(destination)
	if err != nil {
		reader.health.NotReady()
	}
	return n, err
}

func benchReadyCaptureReader(source io.Reader, health *benchHealthController) (io.Reader, error) {
	if source == nil || health == nil {
		return nil, fmt.Errorf("source de capture et contrôleur de santé requis")
	}
	reader, reused := source.(*benchHealthReader)
	if !reused {
		reader = newBenchHealthReader(source, health)
	} else if reader.health != health {
		return nil, fmt.Errorf("lecteur de préparation détenu par une autre campagne")
	}
	header, err := reader.header.Peek(24)
	if reader.source.lastErr != nil && reader.source.lastErr != io.EOF {
		err = errors.Join(err, reader.source.lastErr)
	}
	if err == nil {
		_, err = c2.ReadBenchPCAP(bytes.NewReader(header), func(c2.BenchPacket) error { return nil })
	}
	if err == nil {
		err = health.prepare()
	}
	if err != nil {
		health.NotReady()
		return nil, err
	}
	return reader, nil
}

func benchCaptureCommand(interfaceName, filter string) *exec.Cmd {
	command := exec.Command("tcpdump", "-n", "-s", "0", "-U", "-i", interfaceName, "-w", "-", filter)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = 2 * time.Second
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "LANG=C", "LC_ALL=C"}
	return command
}
