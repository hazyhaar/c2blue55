// c2dnslab-emit est le démon d'émission étiquetée du laboratoire DNS.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func isLoopbackControlAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	parsedIP := net.ParseIP(host)
	return parsedIP != nil && parsedIP.IsLoopback()
}

func main() {
	control := flag.String("control", "127.0.0.1:8754", "adresse du contrôle HTTP")
	runsDir := flag.String("runs-dir", "/var/lib/dnslab-emit/runs", "répertoire des manifestes")
	logpit := flag.String("logpit", "", "adresse HTTP logpit")
	origin := flag.String("origin", "c2dnslab-emit", "origine signée")
	flag.Parse()
	if !isLoopbackControlAddr(*control) && os.Getenv("DNSLAB_EMIT_CONTROL_TOKEN") == "" {
		log.Fatal("DNSLAB_EMIT_CONTROL_TOKEN est obligatoire lorsque -control n'écoute pas sur loopback")
	}
	r := &runner{runsDir: *runsDir, logpit: *logpit, origin: *origin}
	if *logpit != "" {
		seed, err := hex.DecodeString(os.Getenv("DNSLAB_EMIT_ORIGIN_SEED"))
		if err != nil || len(seed) != ed25519.SeedSize {
			log.Fatal("DNSLAB_EMIT_ORIGIN_SEED doit contenir 32 octets hexadécimaux")
		}
		r.private = ed25519.NewKeyFromSeed(seed)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	r.ctx = ctx
	server := &http.Server{Addr: *control, Handler: r.ControlHandler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			log.Printf("arrêt du contrôle: %v", err)
		}
	}()
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(fmt.Errorf("contrôle HTTP: %w", err))
	}
}
