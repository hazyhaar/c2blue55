package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/hazyhaar/c2blue55/internal/dnslive"
)

func main() {
	udpListen := flag.String("udp-listen", "127.0.0.1:5353", "adresse UDP DNS du laboratoire")
	httpListen := flag.String("http-listen", "127.0.0.1:8080", "adresse HTTP du tableau de bord")
	evidenceDir := flag.String("evidence-dir", "c2blue-dns-live-evidence", "répertoire des preuves JSONL et PCAP reconstitués")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: c2blue-dns-live [options]\n\nLe secret du tableau de bord est lu exclusivement dans C2BLUE_DASHBOARD_TOKEN.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if err := runService(*udpListen, *httpListen, *evidenceDir); err != nil {
		log.Fatal(err)
	}
}

func runService(udpListen, httpListen, evidenceDir string) error {
	token := os.Getenv("C2BLUE_DASHBOARD_TOKEN")
	if token == "" {
		return fmt.Errorf("C2BLUE_DASHBOARD_TOKEN est requis")
	}
	service, err := dnslive.New(dnslive.Config{
		UDPListen:      udpListen,
		HTTPListen:     httpListen,
		EvidenceDir:    evidenceDir,
		DashboardToken: token,
		Language:       os.Getenv("C2BLUE_LANG"),
	})
	if err != nil {
		return err
	}
	if err := service.Start(); err != nil {
		return err
	}
	log.Printf("DNS UDP sur %s ; tableau de bord sur http://%s", service.UDPAddr(), service.HTTPAddr())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return service.Close(shutdownCtx)
}
