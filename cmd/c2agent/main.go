// Command c2agent observes DNS datagrams explicitly sent to its UDP socket.
// It neither resolves DNS nor captures or blocks host traffic.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/hazyhaar/c2blue55"
)

func resolveDefaultModelPath() string {
	if p := os.Getenv("C2BLUE_MODEL_PATH"); p != "" {
		return p
	}
	candidates := []string{
		"models/qwen2.5-0.5b-instruct-q4_k_m.gguf",
		"../models/qwen2.5-0.5b-instruct-q4_k_m.gguf",
		"../../models/qwen2.5-0.5b-instruct-q4_k_m.gguf",
		"/data/models/qwen2.5-0.5b-gguf/qwen2.5-0.5b-instruct-q4_k_m.gguf",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return "models/qwen2.5-0.5b-instruct-q4_k_m.gguf"
}

func aiguillerCommande(args []string) (pris bool, code int) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return false, 0
	}
	switch args[0] {
	case "ingest":
		return true, RunAgentCLI(args[1:])
	case "record":
		return true, RunAgentRecordCLI(args[1:])
	case "observe", "replay":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return true, RunBenchCLI(ctx, args[0], args[1:], os.Stdout, os.Stderr)
	default:
		fmt.Fprintln(os.Stderr, "c2agent: sous-commande inconnue")
		return true, 2
	}
}

func main() {
	if pris, code := aiguillerCommande(os.Args[1:]); pris {
		os.Exit(code)
	}
	listenAddr := flag.String("listen", "127.0.0.1:5353", "Adresse d'écoute UDP DNS passive")
	logPath := flag.String("log", "c2_events.jsonl", "Chemin du journal d'audit JSONL append-only")
	syncHours := flag.Int("sync-hours", 24, "Fréquence de resynchronisation des référentiels (heures)")
	verbose := flag.Bool("v", false, "Mode verbeux (affiche chaque décision en direct)")
	sourcesPath := flag.String("sources", "", "Fichier JSON explicite de sources de reputation (tableau ReputationSource)")
	flag.Parse()
	sources, err := loadSources(*sourcesPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	fmt.Println("================================================================================")
	fmt.Println(" c2agent — Agent Souverain de Détection DNS C2 (Pur Go 1.27 / Zero-DB)")
	fmt.Println(" Tournoi IA Wittgenstein — Hackers-Arise / Master OTW")
	fmt.Println("================================================================================")

	// 1. Initialisation du Pipeline déterministe
	pipeCfg := c2blue55.PipelineConfig{
		LogPath:            *logPath,
		EntropyThresholdQ8: 1024, // 4.0 bits/byte
		BeaconJitterMax:    20,   // Jitter <= 20%
		UniqueSubThreshold: 5,    // >= 5 sous-domaines uniques
	}

	pipeline, err := c2blue55.NewPipeline(pipeCfg, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: impossible d'initialiser le pipeline: %v\n", err)
		os.Exit(1)
	}
	defer pipeline.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 2. Initialisation du Synchroniseur de réputation en mémoire vive
	syncerCfg := c2blue55.SyncerConfig{
		Sources:      sources,
		SyncInterval: time.Duration(*syncHours) * time.Hour,
		HTTPTimeout:  15 * time.Second,
		OnSyncSuccess: func(n int) {
			fmt.Printf("[SYNC] Référentiels mis à jour atomiquement en RAM (%d entrées actives)\n", n)
		},
		OnSyncError: func(err error) {
			fmt.Fprintf(os.Stderr, "[SYNC WARN] Échec de rafraîchissement d'une source: %v\n", err)
		},
	}
	syncer := c2blue55.NewReputationSyncer(syncerCfg, pipeline.Reputation())
	if len(sources) > 0 {
		syncer.StartPeriodic(ctx)
	} else {
		fmt.Println("[SYNC] Aucune source configuree; seeds locaux uniquement, sans actualisation distante")
	}

	// 3. Initialisation de l'arbitre à encodeur pur Go (CGO=0, passe unique).
	arbitrator, err := NewPureGoEncoderArbitrator(pipeline)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: impossible d'initialiser l'arbitre encodeur: %v\n", err)
		os.Exit(1)
	}
	defer arbitrator.Close()
	fmt.Println("[ENCODEUR] Arbitre d'encodage pur Go actif (micro-noyau logit softmax, sans poids autoregressif)")

	pipeline.StartArbitratorWorker(ctx, arbitrator, func(inc c2blue55.SLMIncident, finalVerdict string, conf float64, reason string) {
		fmt.Printf("[ARBITRAGE SLM] FQDN=%s | Verdict=%s | Confiance=%.2f | Motif=%s\n",
			inc.FQDN, finalVerdict, conf, reason)
	})

	// 4. Écoute UDP réseau passive
	udpAddr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: adresse UDP invalide %s: %v\n", *listenAddr, err)
		os.Exit(1)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: écoute UDP impossible sur %s: %v\n", *listenAddr, err)
		os.Exit(1)
	}
	defer conn.Close()

	fmt.Printf("[c2agent] Écoute active sur %s (Journal: %s)\n", *listenAddr, *logPath)
	fmt.Println("[c2agent] Observation UDP passive uniquement: aucune capture generale, resolution, transmission ou protection active; aucun blocage reseau")

	// Compteur d'écoute : chaque datagramme reçu est classé dans une issue exactement.
	compteurs := &compteursEcoute{}

	// Capture des signaux d'arrêt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n[c2agent] Signal d'arrêt reçu. Arrêt propre du moteur...")
		cancel()
		_ = conn.Close()
	}()

	// Buffer de réception de paquet UDP fixe (pile / 0 B/op)
	var packetBuf [2048]byte

	for {
		n, _, err := conn.ReadFromUDP(packetBuf[:])
		if err != nil {
			select {
			case <-ctx.Done():
				if err := compteurs.ecrireBilan(os.Stdout); err != nil {
					_, _ = fmt.Fprintf(os.Stderr, "c2agent: bilan non écrit: %v\n", err)
				}
				return
			default:
				continue
			}
		}

		nowSec := uint32(time.Now().Unix())
		traiterDatagramme(pipeline, packetBuf[:n], nowSec, compteurs, os.Stdout, *verbose)
	}
}

// compteursEcoute agrège les issues d'écoute de c2agent : chaque datagramme reçu
// incrémente exactement une des quatre issues (passes, refus, escalades,
// erreursAnalyse) ; escaladesRejetees trace la part des escalades que la file
// d'arbitrage bornée a refusées ; journalSignale garantit que l'échec d'écriture
// du journal d'audit n'est signalé qu'une seule fois, au premier refus concerné.
type compteursEcoute struct {
	passes            atomic.Uint64
	refus             atomic.Uint64
	escalades         atomic.Uint64
	erreursAnalyse    atomic.Uint64
	escaladesRejetees atomic.Uint64
	journalSignale    atomic.Bool
}

// traiterDatagramme évalue un datagramme DNS reçu et classe son issue dans les
// compteurs d'écoute. Une escalade rejetée pour file pleine est comptée dans
// escalades puis dans escaladesRejetees et est affichée sans être confondue
// avec un paquet corrompu ; un refus par réputation dont l'écriture du journal
// d'audit a échoué reste compté dans refus et n'est signalé par la ligne
// [JOURNAL D'AUDIT EN ERREUR] qu'une seule fois, au premier échec, sans être
// confondu avec une erreur d'analyse ; une décision inconnue rendue sans erreur
// est comptée dans erreursAnalyse ; toute autre erreur d'analyse est comptée
// seule et n'est affichée qu'en mode verbeux (D-C2B-L1-03 : une inondation ne
// remplit pas la sortie).
func traiterDatagramme(pipeline *c2blue55.Pipeline, paquet []byte, nowSec uint32, compteurs *compteursEcoute, sortie io.Writer, verbeux bool) {
	res, err := pipeline.EvaluatePacket(paquet, nowSec)
	if err != nil {
		if errors.Is(err, c2blue55.ErrSLMQueueFull) {
			compteurs.escalades.Add(1)
			compteurs.escaladesRejetees.Add(1)
			if res.Incident != nil {
				_, _ = fmt.Fprintf(sortie, "[ESCALADE REJETEE: FILE PLEINE] %s\n", res.Incident.FQDN)
			} else {
				_, _ = fmt.Fprintln(sortie, "[ESCALADE REJETEE: FILE PLEINE]")
			}
			return
		}
		if res.Decision == c2blue55.DecisionFastDrop {
			compteurs.refus.Add(1)
			_, _ = fmt.Fprintf(sortie, "[OBSERVATION: REFUS RECOMMANDE, NON APPLIQUE] %s (correspondance reputation)\n", res.MatchedDomain)
			if compteurs.journalSignale.CompareAndSwap(false, true) {
				if _, errSignal := fmt.Fprintf(sortie, "[JOURNAL D'AUDIT EN ERREUR] %v\n", err); errSignal != nil {
					compteurs.journalSignale.Store(false)
				}
			}
			return
		}
		compteurs.erreursAnalyse.Add(1)
		if verbeux {
			_, _ = fmt.Fprintf(sortie, "[ERREUR ANALYSE] %v\n", err)
		}
		return
	}

	switch res.Decision {
	case c2blue55.DecisionFastPass:
		compteurs.passes.Add(1)
		if verbeux && res.MatchedDomain != "" {
			_, _ = fmt.Fprintf(sortie, "[PASS] %s (Raison: %d)\n", res.MatchedDomain, res.MatchedCategory)
		}
	case c2blue55.DecisionFastDrop:
		compteurs.refus.Add(1)
		_, _ = fmt.Fprintf(sortie, "[OBSERVATION: REFUS RECOMMANDE, NON APPLIQUE] %s (correspondance reputation)\n", res.MatchedDomain)
	case c2blue55.DecisionEscalateSLM:
		compteurs.escalades.Add(1)
		if res.Incident != nil {
			_, _ = fmt.Fprintf(sortie, "[GREY ZONE ESCALADE] %s (Entropie: %.2f bits, Jitter: %d%%, Indicateur: %s)\n",
				res.Incident.FQDN, res.Incident.EntropyBits, res.Incident.JitterPct, res.Incident.SuspectedIndicator)
		}
	default:
		compteurs.erreursAnalyse.Add(1)
	}
}

// ecrireBilan écrit sur sortie la ligne unique de bilan des issues d'écoute et
// rend l'erreur d'écriture éventuelle.
func (c *compteursEcoute) ecrireBilan(sortie io.Writer) error {
	_, err := fmt.Fprintf(sortie, "[c2agent] bilan: passes=%d refus=%d escalades=%d erreurs_analyse=%d escalades_rejetees=%d\n",
		c.passes.Load(), c.refus.Load(), c.escalades.Load(), c.erreursAnalyse.Load(), c.escaladesRejetees.Load())
	return err
}

// localExpertArbitrator arbitre déterministe local par défaut lorsqu'aucun poids GGUF n'est chargé.
type localExpertArbitrator struct{}

func (a *localExpertArbitrator) Arbitrate(ctx context.Context, incident *c2blue55.SLMIncident) (c2blue55.SLMArbitrationResponse, error) {
	if err := ctx.Err(); err != nil {
		return c2blue55.SLMArbitrationResponse{}, err
	}
	// Analyse médico-légale locale :
	// Si forte entropie avec prolifération de sous-domaines ou beaconing avéré
	if incident.EntropyBits >= 4.1 && incident.UniqueSubdomains >= 5 {
		return localHITLResponse(incident, "DNS_TUNNEL_CONFIRMED", 0.96,
			"Sous-domaines multiples à forte entropie Shannon caractéristiques d'exfiltration par blocs"), nil
	}
	if incident.JitterPct <= 15 && incident.QueryCount >= 5 {
		return localHITLResponse(incident, "DNS_TUNNEL_CONFIRMED", 0.92,
			"Périodicité rigide d'intervalles (jitter < 15%) révélant une balise C2 automatisée"), nil
	}

	return localHITLResponse(incident, "INSUFFICIENT_EVIDENCE", 0.50,
		"Indicateurs ambigus ou volume insuffisant pour conclure"), nil
}

func loadSources(path string) ([]c2blue55.ReputationSource, error) {
	if path == "" {
		return nil, nil
	}
	rawJSON, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sources []c2blue55.ReputationSource
	decoder := json.NewDecoder(bytes.NewReader(rawJSON))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sources); err != nil {
		return nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("source configuration must contain one JSON array")
	}
	for _, source := range sources {
		u, err := url.Parse(source.URI)
		if err != nil || source.Name == "" || u.User != nil ||
			!((u.Scheme == "https" && u.Host != "") || (u.Scheme == "file" && u.Host == "" && len(u.Path) > 0 && u.Path[0] == '/')) {
			return nil, fmt.Errorf("invalid reputation source %q: require named HTTPS or absolute file URI", source.Name)
		}
		if source.Classification != c2blue55.RepClassBlockC2 && source.Classification != c2blue55.RepClassAllowVendor && source.Classification != c2blue55.RepClassAllowTranco {
			return nil, fmt.Errorf("invalid source classification")
		}
		if source.MatchKind != c2blue55.MatchExact && source.MatchKind != c2blue55.MatchSubtree {
			return nil, fmt.Errorf("invalid source match kind")
		}
	}
	return sources, nil
}

// localHITLResponse assemble une réponse d'arbitrage locale enrichie de la fiche
// médico-légale HITL déterministe (résumé et action recommandée).
func localHITLResponse(inc *c2blue55.SLMIncident, verdict string, confidence float64, thought string) c2blue55.SLMArbitrationResponse {
	return c2blue55.SLMArbitrationResponse{
		Verdict:           verdict,
		Confidence:        confidence,
		Thought:           thought,
		HumanSummary:      c2blue55.BuildHumanSummary(inc),
		RecommendedAction: c2blue55.RecommendedActionForVerdict(verdict),
	}
}

// RunAgentCLI exécute le mode hors-ligne d'ingestion PCAP DNS complète (--pcap, --manifest, --audit-out).
func RunAgentCLI(args []string) int {
	fs := flag.NewFlagSet("c2agent-cli", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	pcapPath := fs.String("pcap", "", "Chemin du fichier PCAP DNS à ingérer")
	manifestPath := fs.String("manifest", "", "Chemin optionnel du manifeste de campagne JSON")
	auditOut := fs.String("audit-out", "", "Chemin de sortie du journal d'audit JSONL")
	if err := fs.Parse(args); err != nil || *pcapPath == "" {
		return 2
	}
	if *manifestPath != "" {
		if _, err := os.Stat(*manifestPath); err != nil {
			return 2
		}
	}

	pipe, err := c2blue55.NewPipeline(c2blue55.PipelineConfig{LogPath: *auditOut}, nil)
	if err != nil {
		return 1
	}
	defer pipe.Close()

	var escalated, passed int
	stats, err := c2blue55.ReadPCAPDNSMessages(*pcapPath, func(meta c2blue55.PCAPMessageMeta, msg *c2blue55.DNSMessage) error {
		qname := string(msg.QName[:msg.QNameLen])
		if qname == "" {
			passed++
			return nil
		}
		parent := string(msg.ParentDomain[:msg.ParentDomainLen])
		sub := string(msg.Subdomain[:msg.SubdomainLen])
		var rdata []byte
		if msg.AnswerCount > 0 {
			rdata = msg.Answers[0].RData[:msg.Answers[0].RDataLen]
		}
		if len(rdata) > 200 || len(sub) >= 32 {
			escalated++
		} else {
			passed++
		}
		_ = parent
		return nil
	})
	if err != nil || stats.TotalPackets == 0 {
		return 1
	}

	if *auditOut != "" {
		rec := map[string]any{
			"pcap":            *pcapPath,
			"total_packets":   stats.TotalPackets,
			"decoded_queries": stats.DecodedQueries,
			"decoded_replies": stats.DecodedReplies,
			"malformed_count": stats.MalformedCount,
			"passed":          passed,
			"escalated":       escalated,
		}
		b, err := json.Marshal(rec)
		if err != nil {
			return 1
		}
		f, err := os.OpenFile(*auditOut, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return 1
		}
		_, werr := f.Write(append(b, '\n'))
		cerr := f.Close()
		if werr != nil || cerr != nil {
			return 1
		}
	}
	return 0
}
