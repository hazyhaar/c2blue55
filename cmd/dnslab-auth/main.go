// dnslab-auth est le serveur DNS de laboratoire faisant autorité seule sur la
// zone de laboratoire (strate S-04) : écoute UDP sur le maillage, réponses
// fixes, journal typé, limitation de débit, expédition signée vers logpit.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

// serveDNS est la boucle unique du serveur : ReadFrom sur un tampon de 4096
// octets, BuildResponse, limitation, journal (avant toute réponse), WriteTo.
// Une erreur de journal arrête la boucle et est rendue ; l'annulation du
// contexte ferme la connexion et rend nil.
func serveDNS(ctx context.Context, conn net.PacketConn, zone *dnslab.Zone, limiter *dnslab.RateLimiter, journal *dnslab.JournalWriter, ship func(dnslab.JournalLine)) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)
	var packet [4096]byte
	var answer [512]byte
	for {
		packetLen, addr, err := conn.ReadFrom(packet[:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) && ctx.Err() != nil {
				return nil
			}
			return err
		}
		length, decision, parseErr := dnslab.BuildResponse(packet[:packetLen], zone, answer[:])
		instant := time.Now()
		// Deux allocations par datagramme, inhérentes au type JournalLine ; le chemin BuildResponse reste sans allocation.
		line := dnslab.JournalLine{TS: uint64(instant.UnixMicro()), QName: string(decision.QName[:decision.QNameLen]), QType: decision.QType, QClass: decision.QClass, Verdict: decision.Verdict.String(), RCode: decision.RCode, ResponseLen: uint16(length)}
		var source [16]byte
		if udp, ok := addr.(*net.UDPAddr); ok {
			line.Source, line.SourcePort = udp.IP.String(), uint16(udp.Port)
			copy(source[:], udp.IP.To16())
		} else {
			line.Source = addr.String()
		}
		if parseErr != nil {
			line.ParseError = parseErr.Error()
		}
		if limiter != nil {
			line.RateLimited = !limiter.Allow(source, instant.UnixMicro())
		}
		if err := journal.Append(&line); err != nil {
			return err
		}
		if ship != nil {
			ship(line)
		}
		if length > 0 && !line.RateLimited {
			if _, err := conn.WriteTo(answer[:length], addr); err != nil {
				if errors.Is(err, net.ErrClosed) && ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
	}
}

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() (runErr error) {
	listen := flag.String("listen", "10.55.0.1:53", "adresse UDP du laboratoire")
	apex := flag.String("zone", "lab.pound2pound.fr", "zone servie")
	ip := flag.String("answer-a", "10.55.0.1", "réponse A fixe")
	text := flag.String("answer-txt", "canary-lab-pound2pound", "réponse TXT fixe")
	ttl := flag.Uint("ttl", 0, "durée de vie")
	rate := flag.Uint("rrl", 50, "réponses par seconde")
	burst := flag.Uint("rrl-burst", 100, "rafale")
	dir := flag.String("journal-dir", "/var/lib/dnslab/journal", "répertoire du journal")
	health := flag.String("healthz", "127.0.0.1:8753", "adresse HTTP de santé")
	logpit := flag.String("logpit", "", "URL de logpit")
	origin := flag.String("origin", "dnslab-auth", "origine signée")
	keyPath := flag.String("origin-key", "", "fichier de graine Ed25519 hex")
	every := flag.Duration("ship-every", 5*time.Second, "intervalle d'expédition")
	modeNegatif := flag.String("negative", "none", "mode de réponse négative (none|soa|soa-stego)")
	graineNegative := flag.Uint64("negative-seed", 0, "graine 64 bits pour le mode soa-stego")
	modeAAAA := flag.String("aaaa", "none", "mode de réponse AAAA (none|static|iid-stego)")
	reponseAAAA := flag.String("aaaa-answer", "2001:db8:55::1", "réponse AAAA fixe ou préfixe 64 bits")
	graineAAAA := flag.Uint64("aaaa-seed", 0, "graine 64 bits pour le mode iid-stego")
	flag.Parse()
	parsed := net.ParseIP(*ip).To4()
	adresseAAAA := net.ParseIP(*reponseAAAA)
	if adresseAAAA != nil {
		adresseAAAA = adresseAAAA.To16()
	}
	if parsed == nil || adresseAAAA == nil || uint64(*ttl) > uint64(^uint32(0)) || uint64(*rate) > uint64(^uint32(0)) || uint64(*burst) > uint64(^uint32(0)) || *every <= 0 {
		return errors.New("dnslab: drapeaux invalides")
	}
	var answerA [4]byte
	copy(answerA[:], parsed)
	zone, err := dnslab.NewZone(*apex, answerA, *text, uint32(*ttl))
	if err != nil {
		return err
	}
	switch *modeNegatif {
	case "none":
		zone.Negative = dnslab.NegativeNone
	case "soa":
		zone.Negative = dnslab.NegativeSOA
	case "soa-stego":
		zone.Negative = dnslab.NegativeSOAStego
	default:
		return errors.New("dnslab: mode négatif inconnu")
	}
	zone.NegativeSeed = *graineNegative
	switch *modeAAAA {
	case "none":
		zone.AAAA = dnslab.AAAANone
	case "static":
		zone.AAAA = dnslab.AAAAStatic
	case "iid-stego":
		zone.AAAA = dnslab.AAAAIIDStego
	default:
		return errors.New("dnslab: mode AAAA inconnu")
	}
	copy(zone.AnswerAAAA[:], adresseAAAA)
	zone.AAAASeed = *graineAAAA
	limiter, err := dnslab.NewRateLimiter(uint32(*rate), uint32(*burst), 1024)
	if err != nil {
		return err
	}
	seedHex := os.Getenv("DNSLAB_ORIGIN_SEED")
	if *keyPath != "" {
		stat, err := os.Stat(*keyPath)
		if err != nil {
			return err
		}
		if stat.Mode().Perm() != 0o600 {
			return errors.New("dnslab: la graine doit avoir le mode 0600")
		}
		file, err := os.Open(*keyPath)
		if err != nil {
			return err
		}
		payload, readErr := io.ReadAll(io.LimitReader(file, 67))
		closeErr := file.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		seedHex = strings.TrimSpace(string(payload))
	}
	var private ed25519.PrivateKey
	if seedHex != "" {
		seed, err := hex.DecodeString(seedHex)
		if err != nil || len(seed) != ed25519.SeedSize {
			return errors.New("dnslab: graine Ed25519 invalide")
		}
		private = ed25519.NewKeyFromSeed(seed)
	}
	if *logpit != "" && len(private) == 0 {
		return errors.New("dnslab: -logpit requiert une graine Ed25519")
	}
	journal, err := dnslab.OpenJournal(*dir, time.Now)
	if err != nil {
		return err
	}
	defer func() {
		runErr = errors.Join(runErr, journal.Close())
	}()
	conn, err := net.ListenPacket("udp", *listen)
	if err != nil {
		return err
	}
	defer conn.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var questions, responses, refused, limited, journaled, shipped, dropped atomic.Uint64
	var sender *shipper
	if *logpit != "" {
		sender = &shipper{queue: make([]dnslab.JournalLine, 0, 10000), endpoint: strings.TrimRight(*logpit, "/"), origin: *origin, private: private, interval: *every, shipped: &shipped, dropped: &dropped, client: &http.Client{Timeout: 10 * time.Second}}
		if err := sender.start(ctx); err != nil {
			return err
		}
		defer sender.stop()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]uint64{"questions": questions.Load(), "reponses": responses.Load(), "refus": refused.Load(), "limitees": limited.Load(), "journal": journaled.Load(), "expedies": shipped.Load(), "abandonnes": dropped.Load()}); err != nil {
			log.Print(err)
		}
	})
	healthConn, err := net.Listen("tcp", *health)
	if err != nil {
		return err
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := server.Serve(healthConn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Print(err)
			stop()
		}
	}()
	defer server.Close()
	err = serveDNS(ctx, conn, &zone, limiter, journal, func(line dnslab.JournalLine) {
		questions.Add(1)
		journaled.Add(1)
		if line.RCode == 5 {
			refused.Add(1)
		}
		if line.RateLimited {
			limited.Add(1)
		} else if line.ResponseLen > 0 {
			responses.Add(1)
		}
		if sender != nil {
			sender.enqueue(line)
		}
	})
	return err
}
