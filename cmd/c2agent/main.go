// Command c2agent observes DNS datagrams explicitly sent to its UDP socket.
// It neither resolves DNS nor captures or blocks host traffic.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:5353", "Adresse d'écoute UDP DNS passive")
	modelPath := flag.String("model", "/data/models/qwen2.5-0.5b-gguf/qwen2.5-0.5b-instruct-q4_k_m.gguf", "Chemin des poids SLM GGUF (Qwen2.5-0.5B-Instruct Q4_K_M)")
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

	// 3. Initialisation du Moteur SLM In-Process (Qwen2.5-0.5B-Instruct Q4_K_M)
	var arbitrator c2blue55.SLMArbitrator
	realArb, err := NewRealSLMArbitrator(*modelPath)
	if err == nil {
		fmt.Printf("[SLM] Modele charge (%s); RSS non mesure\n", *modelPath)
		defer realArb.Close()
		arbitrator = realArb
	} else {
		fmt.Fprintf(os.Stderr, "[SLM WARN] Modèle introuvable à %s (%v) — bascule sur arbitre expert local\n", *modelPath, err)
		arbitrator = &localExpertArbitrator{}
	}

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

	// Compteurs atomiques de métrologie
	var countFastPass uint64
	var countFastDrop uint64
	var countEscalated uint64

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
				return
			default:
				continue
			}
		}

		nowSec := uint32(time.Now().Unix())
		res, err := pipeline.EvaluatePacket(packetBuf[:n], nowSec)
		if err != nil {
			continue // Paquet corrompu ou non-DNS, ignoré
		}

		switch res.Decision {
		case c2blue55.DecisionFastPass:
			atomic.AddUint64(&countFastPass, 1)
			if *verbose && res.MatchedDomain != "" {
				fmt.Printf("[PASS] %s (Raison: %d)\n", res.MatchedDomain, res.MatchedCategory)
			}
		case c2blue55.DecisionFastDrop:
			atomic.AddUint64(&countFastDrop, 1)
			fmt.Printf("[OBSERVATION: REFUS RECOMMANDE, NON APPLIQUE] %s (correspondance reputation)\n", res.MatchedDomain)
		case c2blue55.DecisionEscalateSLM:
			atomic.AddUint64(&countEscalated, 1)
			if res.Incident != nil {
				fmt.Printf("[GREY ZONE ESCALADE] %s (Entropie: %.2f bits, Jitter: %d%%, Indicateur: %s)\n",
					res.Incident.FQDN, res.Incident.EntropyBits, res.Incident.JitterPct, res.Incident.SuspectedIndicator)
			}
		}
	}
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
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sources []c2blue55.ReputationSource
	decoder := json.NewDecoder(bytes.NewReader(data))
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
