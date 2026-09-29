// Package main — floppy_builder.go
// Forgerie des trois disquettes de vecteurs canoniques du tournoi Wittgenstein
// à partir des données d'exécution réelles exclusives (/devhoros/data/wittgenstein/).
// Règle 4 (Anti-factive) : calcul empirique strict des poids et centroïdes réels (0 formule synthétique).
package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

func clampInt8(v float32) int8 {
	if v > 127.0 {
		return 127
	}
	if v < -127.0 {
		return -127
	}
	return int8(v)
}

// computeEmpiricalHead dérive les poids INT8 et les seuils QHat pour (0=Bénin, 1=Hostile)
// par différence empirique des centroïdes réels.
func computeEmpiricalHead(benignVectors, harmfulVectors [][engine.EmbeddingDim]float32) []engine.DecisionClass {
	var meanBenign [engine.EmbeddingDim]float32
	var meanHarmful [engine.EmbeddingDim]float32

	if len(benignVectors) > 0 {
		for _, vec := range benignVectors {
			for d := 0; d < engine.EmbeddingDim; d++ {
				meanBenign[d] += vec[d]
			}
		}
		invB := 1.0 / float32(len(benignVectors))
		for d := 0; d < engine.EmbeddingDim; d++ {
			meanBenign[d] *= invB
		}
	}

	if len(harmfulVectors) > 0 {
		for _, vec := range harmfulVectors {
			for d := 0; d < engine.EmbeddingDim; d++ {
				meanHarmful[d] += vec[d]
			}
		}
		invH := 1.0 / float32(len(harmfulVectors))
		for d := 0; d < engine.EmbeddingDim; d++ {
			meanHarmful[d] *= invH
		}
	}

	head := make([]engine.DecisionClass, 2)

	// Classe 0 (Bénin) : orientée vers meanBenign - meanHarmful
	for d := 0; d < engine.EmbeddingDim; d++ {
		diff := (meanBenign[d] - meanHarmful[d]) * 127.0
		head[0].Weights[d] = clampInt8(diff)
	}
	head[0].Bias = 0
	head[0].QHat = 0.05

	// Classe 1 (Hostile) : orientée vers meanHarmful - meanBenign
	for d := 0; d < engine.EmbeddingDim; d++ {
		diff := (meanHarmful[d] - meanBenign[d]) * 127.0
		head[1].Weights[d] = clampInt8(diff)
	}
	head[1].Bias = 0
	head[1].QHat = 0.05

	// Calibration empirique de QHat sur les échantillons d'apprentissage
	if len(harmfulVectors) > 0 {
		var sumScore float32
		for _, vec := range harmfulVectors {
			var dot int32
			for d := 0; d < engine.EmbeddingDim; d++ {
				f := vec[d]
				var q int32
				if f > 1.0 {
					q = 127
				} else if f < -1.0 {
					q = -127
				} else {
					q = int32(f * 127.0)
				}
				dot += q * int32(head[1].Weights[d])
			}
			normScore := float32(dot) / (127.0 * float32(engine.EmbeddingDim))
			sumScore += normScore
		}
		avgHarmfulScore := sumScore / float32(len(harmfulVectors))
		if avgHarmfulScore > 0.02 {
			head[1].QHat = avgHarmfulScore * 0.4
		}
	}

	if len(benignVectors) > 0 {
		var sumScore float32
		for _, vec := range benignVectors {
			var dot int32
			for d := 0; d < engine.EmbeddingDim; d++ {
				f := vec[d]
				var q int32
				if f > 1.0 {
					q = 127
				} else if f < -1.0 {
					q = -127
				} else {
					q = int32(f * 127.0)
				}
				dot += q * int32(head[0].Weights[d])
			}
			normScore := float32(dot) / (127.0 * float32(engine.EmbeddingDim))
			sumScore += normScore
		}
		avgBenignScore := sumScore / float32(len(benignVectors))
		if avgBenignScore > 0.02 {
			head[0].QHat = avgBenignScore * 0.4
		}
	}

	return head
}

// benignBlockRateMax est la part maximale de vecteurs bénins d'apprentissage
// admise dans le rayon de veto L1b d'une disquette (calibration du rayon).
const benignBlockRateMax = 0.01

// maxFloppyPrototypes borne le nombre de prototypes d'étalonnage L1a par
// classe : la sonde conforme mesure une distance moyenne à chaque prototype,
// son coût croît donc linéairement avec ce nombre.
const maxFloppyPrototypes = 32

// selectPrototypes retient au plus maxFloppyPrototypes vecteurs réels d'une
// classe, régulièrement espacés dans l'ordre du corpus d'apprentissage, pour
// couvrir toute l'étendue de la classe plutôt que son début.
func selectPrototypes(class uint16, vecs [][engine.EmbeddingDim]float32) []engine.FloppyPrototype {
	n := len(vecs)
	k := n
	if k > maxFloppyPrototypes {
		k = maxFloppyPrototypes
	}
	out := make([]engine.FloppyPrototype, 0, k)
	for i := 0; i < k; i++ {
		out = append(out, engine.FloppyPrototype{Class: class, Vector: vecs[i*n/k]})
	}
	return out
}

// embedEvent projette une charge réelle comme la cascade la verra en
// exploitation : dépôt dans l'arène (ce qui pose FlagLongPayload au-delà de
// 96 octets) puis extraction des traits depuis l'événement.
func embedEvent(fe *engine.FeatureExtractor, arena *engine.ArenaPool, subsystem, action uint16, payload []byte) ([engine.EmbeddingDim]float32, bool) {
	var ev engine.Probe_event_t
	ev.Subsystem = subsystem
	ev.Action = action
	arena.StorePayload(&ev, payload)
	var dst [engine.EmbeddingDim]float32
	ok := fe.ExtractTo(&ev, dst[:])
	return dst, ok
}

// dnsFamily rend le domaine enregistré (deux derniers labels) d'un nom DNS.
func dnsFamily(domain string) string {
	labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
	if len(labels) < 2 {
		return domain
	}
	return labels[len(labels)-2] + "." + labels[len(labels)-1]
}

// BuildWittgensteinFloppies lit les traces réelles et forge les 3 fichiers .c2book étendus.
//
// Disquette LOLBAS : seuls les ReverseShellTrainPercent premiers pour cent de
// reverse_shells.jsonl deviennent des centroïdes ; le reste est tenu à l'écart
// pour le banc. Le corpus bénin est celui des commandes d'administration
// (engine.BenignAdminCommands), partition d'apprentissage seulement.
// Disquette DNS : les domaines hostiles d'apprentissage sont échantillonnés à
// parts égales par famille (domaine enregistré), et non par ordre du fichier.
func BuildWittgensteinFloppies(dataDir, outDir string) error {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}

	fe := engine.NewFeatureExtractor()
	arena := engine.DefaultArenaPool()

	// =========================================================================
	// 1. Disquette LOLBAS (Living Off The Land, PrivEsc, Reverse Shells)
	// =========================================================================
	// Mots-clés réflexes : idiomes hostiles par eux-mêmes (ouverture d'un shell
	// sur socket, décodage et exécution en mémoire, téléchargement ou
	// destruction de clichés par un binaire système). Les noms d'outils seuls
	// (powershell, certutil, vssadmin, bitsadmin) ne suffisent pas : leur usage
	// d'administration courant serait bloqué.
	lolbasKeywords := []string{
		"bash -i", "/bin/sh -i", "/bin/bash -i", "/dev/tcp/", "/dev/udp/",
		"nc -e", "ncat -e", "socat exec", "mkfifo /tmp/",
		"FromBase64String", "Invoke-Expression", "iex(", "iex (", "|iex", "| iex",
		"-EncodedCommand", "powershell -enc", "powershell.exe -enc", "powershell -e ",
		"Net.Sockets.TCPClient", "DownloadString(",
		"certutil -urlcache", "certutil -decode", "vssadmin delete shadows", "bitsadmin /transfer",
	}

	var lolbasHarmfulVecs [][engine.EmbeddingDim]float32
	var lolbasBenignVecs [][engine.EmbeddingDim]float32
	var lolbasEntries []engine.CodebookEntry

	// Échantillons hostiles réels : partition d'apprentissage de reverse_shells.jsonl
	shells, err := engine.LoadReverseShellPayloads(filepath.Join(dataDir, "reverse_shells.jsonl"))
	if err != nil {
		return fmt.Errorf("impossible de lire reverse_shells.jsonl: %w", err)
	}
	nTrain := engine.ReverseShellTrainCount(len(shells))
	threatID := uint32(1001)
	for _, payload := range shells[:nTrain] {
		dst, ok := embedEvent(&fe, arena, 1, 1, []byte(payload)) // SubProc, ActExec
		if !ok {
			continue
		}
		var bitcode [engine.EmbeddingDim / 64]uint64
		engine.QuantizeFHT512(dst[:], &bitcode)
		lolbasEntries = append(lolbasEntries, engine.CodebookEntry{
			Bitcode:   bitcode,
			ThreatID:  threatID,
			Subsystem: 1,
			Severity:  engine.SeverityCritical,
		})
		threatID++
		lolbasHarmfulVecs = append(lolbasHarmfulVecs, dst)
	}

	// Échantillons bénins : partition d'apprentissage des commandes d'administration
	for i, cmd := range engine.BenignAdminCommands() {
		if !engine.IsBenignTrainIndex(i) {
			continue
		}
		if dst, ok := embedEvent(&fe, arena, 1, 1, []byte(cmd)); ok {
			lolbasBenignVecs = append(lolbasBenignVecs, dst)
		}
	}

	lolbasHead := computeEmpiricalHead(lolbasBenignVecs, lolbasHarmfulVecs)
	lolbasProtos := append(selectPrototypes(0, lolbasBenignVecs), selectPrototypes(1, lolbasHarmfulVecs)...)
	lolbasOut := filepath.Join(outDir, "floppy_lolbas.c2book")
	if err := engine.SaveFloppyFile(lolbasOut, engine.FloppyFamilyLOLBAS, lolbasKeywords, lolbasEntries, lolbasHead, lolbasProtos, engine.CalibrateBlockRadius(lolbasEntries, lolbasBenignVecs, benignBlockRateMax), engine.WittgensteinFloppyKey(engine.FloppyFamilyLOLBAS)); err != nil {
		return fmt.Errorf("échec de sauvegarde floppy_lolbas: %w", err)
	}

	// =========================================================================
	// 2. Disquette DNS / C2 (Netrack DNS Beaconing & Exfiltration)
	// =========================================================================
	dnsPath := filepath.Join(dataDir, "netrack_dns", "train.csv")
	dnsKeywords := []string{
		".hidemyself.org", ".onion", ".b33con", "cdn-update.", "tunnel-dns",
	}

	var dnsHarmfulVecs [][engine.EmbeddingDim]float32
	var dnsBenignVecs [][engine.EmbeddingDim]float32
	var dnsEntries []engine.CodebookEntry

	// Tout le bénin d'apprentissage (3 000 domaines) sert à la tête, aux
	// prototypes et au calibrage du rayon de veto.
	const dnsHarmfulPerFamily = 500
	const dnsBenignMax = 1 << 30
	f, err := os.Open(dnsPath)
	if err != nil {
		return fmt.Errorf("impossible d'ouvrir netrack_dns/train.csv: %w", err)
	}
	perFamily := map[string]int{}
	reader := csv.NewReader(f)
	threatID = uint32(2001)
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(row) < 2 {
			continue
		}
		label := strings.TrimSpace(row[0])
		domain := strings.TrimSpace(row[1])
		if len(domain) == 0 {
			continue
		}
		switch label {
		case "1":
			fam := dnsFamily(domain)
			if perFamily[fam] >= dnsHarmfulPerFamily {
				continue
			}
			dst, ok := embedEvent(&fe, arena, 3, 3, []byte(domain)) // SubNet, ActConnect
			if !ok {
				continue
			}
			perFamily[fam]++
			var bitcode [engine.EmbeddingDim / 64]uint64
			engine.QuantizeFHT512(dst[:], &bitcode)
			dnsEntries = append(dnsEntries, engine.CodebookEntry{
				Bitcode:   bitcode,
				ThreatID:  threatID,
				Subsystem: 3,
				Severity:  engine.SeverityHigh,
			})
			threatID++
			dnsHarmfulVecs = append(dnsHarmfulVecs, dst)
		case "0":
			if len(dnsBenignVecs) >= dnsBenignMax {
				continue
			}
			if dst, ok := embedEvent(&fe, arena, 3, 3, []byte(domain)); ok {
				dnsBenignVecs = append(dnsBenignVecs, dst)
			}
		}
	}
	f.Close()

	dnsHead := computeEmpiricalHead(dnsBenignVecs, dnsHarmfulVecs)
	dnsProtos := append(selectPrototypes(0, dnsBenignVecs), selectPrototypes(1, dnsHarmfulVecs)...)
	dnsOut := filepath.Join(outDir, "floppy_dns_c2.c2book")
	if err := engine.SaveFloppyFile(dnsOut, engine.FloppyFamilyDNSC2, dnsKeywords, dnsEntries, dnsHead, dnsProtos, engine.CalibrateBlockRadius(dnsEntries, dnsBenignVecs, benignBlockRateMax), engine.WittgensteinFloppyKey(engine.FloppyFamilyDNSC2)); err != nil {
		return fmt.Errorf("échec de sauvegarde floppy_dns_c2: %w", err)
	}

	// =========================================================================
	// 3. Disquette Agent IA / MCP (Lakera Prompt Injection & Tool Usurpation)
	// =========================================================================
	mcpPath := filepath.Join(dataDir, "lakera_agent_attacks.csv")
	mcpKeywords := []string{
		"IGNORE PREVIOUS INSTRUCTIONS", "SYSTEM:", "DEBUG=TRUE",
		"tool_call:", "admin_override", "disregard protocol",
		"unrestrained response", "rm -rf",
	}

	var mcpHarmfulVecs [][engine.EmbeddingDim]float32
	var mcpBenignVecs [][engine.EmbeddingDim]float32
	var mcpEntries []engine.CodebookEntry

	if f, err := os.Open(mcpPath); err == nil {
		defer f.Close()
		reader := csv.NewReader(f)
		threatID := uint32(3001)
		count := 0
		_, _ = reader.Read() // skip header
		for {
			row, err := reader.Read()
			if err == io.EOF || count >= 1000 {
				break
			}
			if err != nil || len(row) < 4 {
				continue
			}
			attackText := row[3]
			if len(attackText) == 0 {
				continue
			}

			var ev engine.Probe_event_t
			ev.Subsystem = 4 // SubMCP
			ev.Action = 4    // ActToolCall
			arena.StorePayload(&ev, []byte(attackText))

			var dst [engine.EmbeddingDim]float32
			if fe.ExtractTo(&ev, dst[:]) {
				var bitcode [engine.EmbeddingDim / 64]uint64
				engine.QuantizeFHT512(dst[:], &bitcode)
				mcpEntries = append(mcpEntries, engine.CodebookEntry{
					Bitcode:   bitcode,
					ThreatID:  threatID,
					Subsystem: 4,
					Severity:  engine.SeverityCritical,
				})
				threatID++
				mcpHarmfulVecs = append(mcpHarmfulVecs, dst)
				count++
			}
		}
	} else {
		return fmt.Errorf("impossible d'ouvrir lakera_agent_attacks.csv: %w", err)
	}

	// Échantillons MCP bénins réels (prompt_injection_train.csv label 0 et jbb_benign.csv)
	pInjPath := filepath.Join(dataDir, "prompt_injection_train.csv")
	if f, err := os.Open(pInjPath); err == nil {
		defer f.Close()
		reader := csv.NewReader(f)
		_, _ = reader.Read()
		count := 0
		for {
			row, err := reader.Read()
			if err == io.EOF || count >= 500 {
				break
			}
			if err != nil || len(row) < 2 {
				continue
			}
			if strings.TrimSpace(row[1]) == "0" && len(row[0]) > 0 {
				var ev engine.Probe_event_t
				ev.Subsystem = 4
				ev.Action = 4
				arena.StorePayload(&ev, []byte(row[0]))
				var dst [engine.EmbeddingDim]float32
				if fe.ExtractTo(&ev, dst[:]) {
					mcpBenignVecs = append(mcpBenignVecs, dst)
					count++
				}
			}
		}
	}

	jbbPath := filepath.Join(dataDir, "jbb_benign.csv")
	if f, err := os.Open(jbbPath); err == nil {
		defer f.Close()
		reader := csv.NewReader(f)
		_, _ = reader.Read()
		count := 0
		for {
			row, err := reader.Read()
			if err == io.EOF || count >= 300 {
				break
			}
			if err != nil || len(row) < 2 {
				continue
			}
			text := row[1]
			if len(text) > 0 {
				var ev engine.Probe_event_t
				ev.Subsystem = 4
				ev.Action = 4
				arena.StorePayload(&ev, []byte(text))
				var dst [engine.EmbeddingDim]float32
				if fe.ExtractTo(&ev, dst[:]) {
					mcpBenignVecs = append(mcpBenignVecs, dst)
					count++
				}
			}
		}
	}

	mcpHead := computeEmpiricalHead(mcpBenignVecs, mcpHarmfulVecs)
	mcpProtos := append(selectPrototypes(0, mcpBenignVecs), selectPrototypes(1, mcpHarmfulVecs)...)
	mcpOut := filepath.Join(outDir, "floppy_agent_mcp.c2book")
	if err := engine.SaveFloppyFile(mcpOut, engine.FloppyFamilyAgentMCP, mcpKeywords, mcpEntries, mcpHead, mcpProtos, engine.CalibrateBlockRadius(mcpEntries, mcpBenignVecs, benignBlockRateMax), engine.WittgensteinFloppyKey(engine.FloppyFamilyAgentMCP)); err != nil {
		return fmt.Errorf("échec de sauvegarde floppy_agent_mcp: %w", err)
	}

	return nil
}
