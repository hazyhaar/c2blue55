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
	language := flag.String("lang", "", "langue du tableau de bord : fr ou en (l'emporte sur C2BLUE_LANG)")
	flag.Usage = func() {
		_, _ = fmt.Fprintf(flag.CommandLine.Output(), "Usage: c2blue-dns-live [options]\n\nLe secret du tableau de bord est lu exclusivement dans C2BLUE_DASHBOARD_TOKEN.\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := runService(ctx, *udpListen, *httpListen, *evidenceDir, *language)
	stop()
	if err != nil {
		log.Fatal(err)
	}
}

// runService arbitre la configuration, démarre le service DNS live puis
// l'arrête à l'annulation du contexte reçu : seul main connaît les signaux,
// runService reste testable avec un simple contexte à délai.
func runService(ctx context.Context, udpListen, httpListen, evidenceDir, language string) error {
	token := os.Getenv("C2BLUE_DASHBOARD_TOKEN")
	if token == "" {
		return fmt.Errorf("C2BLUE_DASHBOARD_TOKEN est requis")
	}
	languageArbitree, err := resolveLanguage(language)
	if err != nil {
		return err
	}
	serviceLive, err := dnslive.New(dnslive.Config{
		UDPListen:      udpListen,
		HTTPListen:     httpListen,
		EvidenceDir:    evidenceDir,
		DashboardToken: token,
		Language:       languageArbitree,
	})
	if err != nil {
		return err
	}
	if err := serviceLive.Start(); err != nil {
		return err
	}
	log.Printf("DNS UDP sur %s ; tableau de bord sur http://%s", serviceLive.UDPAddr(), serviceLive.HTTPAddr())
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), delaiFermetureService())
	defer cancel()
	return serviceLive.Close(shutdownCtx)
}

// delaiFermetureService borne la fermeture du service après la fin du contexte.
func delaiFermetureService() time.Duration {
	return 10 * time.Second
}

// resolveLanguage arbitre entre le drapeau -lang et C2BLUE_LANG : le drapeau
// non vide l'emporte, une valeur hors fr/en est refusée au démarrage.
func resolveLanguage(flagValue string) (string, error) {
	language := os.Getenv("C2BLUE_LANG")
	if flagValue != "" {
		language = flagValue
	}
	switch language {
	case "", "fr", "en":
		return language, nil
	default:
		return "", fmt.Errorf("langue %q non reconnue : -lang et C2BLUE_LANG acceptent uniquement fr ou en", language)
	}
}
