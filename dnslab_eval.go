package c2blue55

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/hazyhaar/c2blue55/internal/engine"
)

// ErrLabRunContract signale un run de laboratoire incomplet (manifeste sans
// capture, capture illisible) : aucun run n'est ignoré silencieusement.
var ErrLabRunContract = errors.New("c2blue55: run de laboratoire hors contrat")

// LabFamilyRun est un run ingéré du laboratoire (strate S-06).
type LabFamilyRun struct {
	Manifest     RedhostLabManifest
	RunID        string
	Family       string
	Views        []engine.DNSQueryView
	LabeledViews []LabeledDNSQueryView
	Hostile      bool
}

// LabFamilyMetrics rapporte l'homologation d'une famille tenue à l'écart.
type LabFamilyMetrics struct {
	Family             string
	Runs               int
	Questions          int
	InsuffisantPourAUC bool
	Metrics            engine.ColdSplitMetrics
}

// LoadLabRuns parcourt <labDir>/*.manifest.json et ingère <run_id>.pcap par
// IngestRedhostLabRun ; Hostile vaut vrai pour les familles redhost-*.
func LoadLabRuns(labDir string) ([]LabFamilyRun, error) {
	entries, err := os.ReadDir(labDir)
	if err != nil {
		return nil, fmt.Errorf("%w: lecture de %s: %w", ErrLabRunContract, labDir, err)
	}
	manifests := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".manifest.json") {
			manifests = append(manifests, filepath.Join(labDir, entry.Name()))
		}
	}
	slices.Sort(manifests)
	if len(manifests) == 0 {
		return nil, fmt.Errorf("%w: aucun manifeste sous %s", ErrLabRunContract, labDir)
	}
	runs := make([]LabFamilyRun, 0, len(manifests))
	for _, manifestPath := range manifests {
		stem := strings.TrimSuffix(filepath.Base(manifestPath), ".manifest.json")
		capturePath := filepath.Join(labDir, stem+".pcap")
		run, ingestErr := IngestRedhostLabRun(capturePath, manifestPath)
		if ingestErr != nil {
			return nil, fmt.Errorf("%w: run %s: %w", ErrLabRunContract, stem, ingestErr)
		}
		family := run.Manifest.Family
		if family == "" {
			family = run.Manifest.Label
		}
		runs = append(runs, LabFamilyRun{
			Manifest:     run.Manifest,
			RunID:        stem,
			Family:       family,
			Views:        run.QueryViews(),
			LabeledViews: run.Views,
			Hostile:      strings.HasPrefix(family, "redhost-"),
		})
	}
	return runs, nil
}

// LoadLabRunsTolerant parcourt <labDir>/*.manifest.json et ingère <run_id>.pcap
// par IngestRedhostLabRunTolerant (qualification hors LDH + NonLDHBurstGuard).
func LoadLabRunsTolerant(labDir string) ([]LabFamilyRun, error) {
	entries, err := os.ReadDir(labDir)
	if err != nil {
		return nil, fmt.Errorf("%w: lecture de %s: %w", ErrLabRunContract, labDir, err)
	}
	manifests := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".manifest.json") {
			manifests = append(manifests, filepath.Join(labDir, entry.Name()))
		}
	}
	slices.Sort(manifests)
	if len(manifests) == 0 {
		return nil, fmt.Errorf("%w: aucun manifeste sous %s", ErrLabRunContract, labDir)
	}
	runs := make([]LabFamilyRun, 0, len(manifests))
	for _, manifestPath := range manifests {
		stem := strings.TrimSuffix(filepath.Base(manifestPath), ".manifest.json")
		capturePath := filepath.Join(labDir, stem+".pcap")
		run, ingestErr := IngestRedhostLabRunTolerant(capturePath, manifestPath)
		if ingestErr != nil {
			return nil, fmt.Errorf("%w: run %s: %w", ErrLabRunContract, stem, ingestErr)
		}
		family := run.Manifest.Family
		if family == "" {
			family = run.Manifest.Label
		}
		runs = append(runs, LabFamilyRun{
			Manifest:     run.Manifest,
			RunID:        stem,
			Family:       family,
			Views:        run.QueryViews(),
			LabeledViews: run.Views,
			Hostile:      strings.HasPrefix(family, "redhost-"),
		})
	}
	return runs, nil
}

// EvaluateDNSLabFamiliesTolerant homologue chaque famille hostile tenue à l'écart
// en mode tolérant (lot V1) : les vues hors LDH condamnées par NonLDHBurstGuard
// sont bloquées en L0, tandis que les instances DNS-SD RFC 6763 et noms UTF-8
// locaux non condamnés en salve ne subissent pas d'évaluation sous-domaine LDH.
func EvaluateDNSLabFamiliesTolerant(corpusDir, labDir, outDir string, hmacKey []byte) ([]LabFamilyMetrics, error) {
	runs, err := LoadLabRunsTolerant(labDir)
	if err != nil {
		return nil, err
	}
	families := make([]string, 0)
	seen := make(map[string]bool)
	benignLabeled := make([]LabeledDNSQueryView, 0)
	for _, run := range runs {
		if !run.Hostile {
			benignLabeled = append(benignLabeled, run.LabeledViews...)
		} else if !seen[run.Family] {
			seen[run.Family] = true
			families = append(families, run.Family)
		}
	}
	slices.Sort(families)
	metrics := make([]LabFamilyMetrics, 0, len(families))
	for _, family := range families {
		row, evaluateErr := evaluateLabFamilyTolerant(corpusDir, outDir, family, runs, benignLabeled, hmacKey)
		if evaluateErr != nil {
			return nil, fmt.Errorf("famille %s: %w", family, evaluateErr)
		}
		metrics = append(metrics, row)
	}
	return metrics, nil
}

func evaluateLabFamilyTolerant(corpusDir, outDir, family string, runs []LabFamilyRun, benignLabeled []LabeledDNSQueryView, hmacKey []byte) (row LabFamilyMetrics, err error) {
	row.Family = family
	if family == "" {
		return row, fmt.Errorf("%w: famille vide", ErrLabRunContract)
	}
	for _, caractere := range family {
		if !(caractere >= 'a' && caractere <= 'z' || caractere >= '0' && caractere <= '9' || caractere == '-') {
			return row, fmt.Errorf("%w: famille invalide %q", ErrLabRunContract, family)
		}
	}
	repertoire := filepath.Join(outDir, family)
	if err = engine.BuildDNSFloppiesColdSplit(corpusDir, repertoire, hmacKey); err != nil {
		return row, err
	}
	tunnelPath := filepath.Join(repertoire, "floppy_dns_tunnel.c2book")
	tunnel, err := engine.LoadFloppyMmap(tunnelPath, hmacKey)
	if err != nil {
		return row, err
	}
	defer func() { err = errors.Join(err, tunnel.Close()) }()
	dga, err := engine.LoadFloppyMmap(filepath.Join(repertoire, "floppy_dns_dga.c2book"), hmacKey)
	if err != nil {
		return row, err
	}
	defer func() { err = errors.Join(err, dga.Close()) }()

	otherViews := make([]engine.DNSQueryView, 0)
	for _, run := range runs {
		if run.Hostile && run.Family != family {
			for _, vueEtiquetee := range run.LabeledViews {
				if vueEtiquetee.Grammar.Classe == QNameGrammarLDH {
					otherViews = append(otherViews, vueEtiquetee.View)
				}
			}
		}
	}
	if len(otherViews) > 0 {
		candidates, discoverErr := engine.DiscoverRedhostPatterns(otherViews, tunnel, dga)
		if discoverErr != nil {
			return row, discoverErr
		}
		entries := make([]engine.CodebookEntry, 0, len(tunnel.Entries)+len(candidates))
		entries = append(entries, tunnel.Entries...)
		entries = append(entries, candidates...)
		if err = engine.SaveFloppyFile(tunnelPath, engine.FloppyFamilyDNSTunnel, nil, entries, tunnel.Head, nil, 12, hmacKey); err != nil {
			return row, err
		}
		updated, loadErr := engine.LoadFloppyMmap(tunnelPath, hmacKey)
		if loadErr != nil {
			return row, loadErr
		}
		closeErr := tunnel.Close()
		tunnel = updated
		if closeErr != nil {
			return row, closeErr
		}
	}

	scores := make([]float64, 0, len(benignLabeled))
	labels := make([]bool, 0, len(benignLabeled))
	evaluerVue := func(vueEtiquetee LabeledDNSQueryView, hostile bool) {
		var verdict engine.CascadeVerdict
		score := -2.0
		switch {
		case vueEtiquetee.NonLDHBurstBlock:
			verdict = engine.CascadeVerdict{
				Stage:        engine.StageL0,
				Action:       engine.VerdictBlock,
				Flags:        0x0002,
				ConfidenceQ8: 256,
			}
			score = 10.0
		case vueEtiquetee.Grammar.Classe == QNameGrammarDNSSDInstance || vueEtiquetee.Grammar.Classe == QNameGrammarUTF8Local:
			vueApex := vueEtiquetee.View
			vueApex.Subdomain = nil
			vueApex.FQDN = nil
			verdict = engine.EvaluateDNSView(vueApex, nil, dga)
			if verdict.Stage == engine.StageL0 && verdict.Action == engine.VerdictBlock {
				score = 10.0
			}
		default:
			verdict = engine.EvaluateDNSView(vueEtiquetee.View, tunnel, dga)
			if verdict.Stage == engine.StageL0 && verdict.Action == engine.VerdictBlock {
				score = 10.0
			} else if len(vueEtiquetee.View.Subdomain) > 0 && vueEtiquetee.Grammar.Classe == QNameGrammarLDH {
				var features [engine.EmbeddingDim]float32
				engine.TunnelFeatures(vueEtiquetee.View, &features)
				score = engine.ThreatScore(&features, tunnel)
			}
		}
		engine.AccumulateVerdict(&row.Metrics, verdict, hostile)
		scores = append(scores, score)
		labels = append(labels, hostile)
	}
	for _, run := range runs {
		if run.Hostile && run.Family == family {
			row.Runs++
			row.Questions += len(run.LabeledViews)
			for _, vueEtiquetee := range run.LabeledViews {
				evaluerVue(vueEtiquetee, true)
			}
		}
	}
	for _, vueEtiquetee := range benignLabeled {
		evaluerVue(vueEtiquetee, false)
	}
	engine.FinalizeMetrics(&row.Metrics, row.Questions, len(benignLabeled), scores, labels)
	row.InsuffisantPourAUC = row.Questions < 50
	if row.InsuffisantPourAUC {
		row.Metrics.AUC = 0
	}
	return row, nil
}

// EvaluateDNSLabFamilies tient chaque famille hostile du laboratoire à l'écart
// à tour de rôle, forge les disquettes sur le reste et mesure les comptes bruts.
func EvaluateDNSLabFamilies(dataDir, labDir, outDir string, hmacKey []byte) ([]LabFamilyMetrics, error) {
	runs, err := LoadLabRuns(labDir)
	if err != nil {
		return nil, err
	}
	families := make([]string, 0)
	seen := make(map[string]bool)
	benignViews := make([]engine.DNSQueryView, 0)
	for _, run := range runs {
		if !run.Hostile {
			benignViews = append(benignViews, run.Views...)
		} else if !seen[run.Family] {
			seen[run.Family] = true
			families = append(families, run.Family)
		}
	}
	slices.Sort(families)
	metrics := make([]LabFamilyMetrics, 0, len(families))
	for _, family := range families {
		row, evaluateErr := evaluateLabFamily(dataDir, outDir, family, runs, benignViews, hmacKey)
		if evaluateErr != nil {
			return nil, fmt.Errorf("famille %s: %w", family, evaluateErr)
		}
		metrics = append(metrics, row)
	}
	return metrics, nil
}

func evaluateLabFamily(dataDir, outDir, family string, runs []LabFamilyRun, benignViews []engine.DNSQueryView, hmacKey []byte) (row LabFamilyMetrics, err error) {
	row.Family = family
	if family == "" {
		return row, fmt.Errorf("%w: famille vide", ErrLabRunContract)
	}
	for _, c := range family {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return row, fmt.Errorf("%w: famille invalide %q", ErrLabRunContract, family)
		}
	}
	dir := filepath.Join(outDir, family)
	if err = engine.BuildDNSFloppiesColdSplit(dataDir, dir, hmacKey); err != nil {
		return row, err
	}
	tunnelPath := filepath.Join(dir, "floppy_dns_tunnel.c2book")
	tunnel, err := engine.LoadFloppyMmap(tunnelPath, hmacKey)
	if err != nil {
		return row, err
	}
	defer func() { err = errors.Join(err, tunnel.Close()) }()
	dga, err := engine.LoadFloppyMmap(filepath.Join(dir, "floppy_dns_dga.c2book"), hmacKey)
	if err != nil {
		return row, err
	}
	defer func() { err = errors.Join(err, dga.Close()) }()

	otherViews := make([]engine.DNSQueryView, 0)
	for _, run := range runs {
		if run.Hostile && run.Family != family {
			otherViews = append(otherViews, run.Views...)
		}
	}
	if len(otherViews) > 0 {
		candidates, discoverErr := engine.DiscoverRedhostPatterns(otherViews, tunnel, dga)
		if discoverErr != nil {
			return row, discoverErr
		}
		entries := make([]engine.CodebookEntry, 0, len(tunnel.Entries)+len(candidates))
		entries = append(entries, tunnel.Entries...)
		entries = append(entries, candidates...)
		if err = engine.SaveFloppyFile(tunnelPath, engine.FloppyFamilyDNSTunnel, nil, entries, tunnel.Head, nil, 12, hmacKey); err != nil {
			return row, err
		}
		// La projection initiale reste ouverte jusqu'à ce que la nouvelle soit chargée.
		updated, loadErr := engine.LoadFloppyMmap(tunnelPath, hmacKey)
		if loadErr != nil {
			return row, loadErr
		}
		closeErr := tunnel.Close()
		tunnel = updated
		if closeErr != nil {
			return row, closeErr
		}
	}

	scores := make([]float64, 0, len(benignViews))
	labels := make([]bool, 0, len(benignViews))
	evaluate := func(view engine.DNSQueryView, hostile bool) {
		verdict := engine.EvaluateDNSView(view, tunnel, dga)
		engine.AccumulateVerdict(&row.Metrics, verdict, hostile)
		score := -2.0
		if verdict.Stage == engine.StageL0 && verdict.Action == engine.VerdictBlock {
			score = 10
		} else if len(view.Subdomain) > 0 {
			var features [engine.EmbeddingDim]float32
			engine.TunnelFeatures(view, &features)
			score = engine.ThreatScore(&features, tunnel)
		}
		scores = append(scores, score)
		labels = append(labels, hostile)
	}
	for _, run := range runs {
		if run.Hostile && run.Family == family {
			row.Runs++
			row.Questions += len(run.Views)
			for _, view := range run.Views {
				evaluate(view, true)
			}
		}
	}
	for _, view := range benignViews {
		evaluate(view, false)
	}
	engine.FinalizeMetrics(&row.Metrics, row.Questions, len(benignViews), scores, labels)
	row.InsuffisantPourAUC = row.Questions < 50
	if row.InsuffisantPourAUC {
		row.Metrics.AUC = 0
	}
	return row, nil
}

// WriteLabReport écrit le rapport JSON atomique et son tableau Markdown.
func WriteLabReport(path string, metrics []LabFamilyMetrics) error {
	payload, err := json.MarshalIndent(metrics, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	dir := filepath.Dir(path)
	mode, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if mode.Mode().Perm()&0o222 == 0 {
		return fmt.Errorf("répertoire non inscriptible: %s", dir)
	}
	realDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	realDir, err = filepath.Abs(realDir)
	if err != nil {
		return err
	}
	mdPath := path + ".md"
	var markdown strings.Builder
	fmt.Fprintf(&markdown, "filepath: %s\n\n# Homologation DNS du laboratoire\n\n", filepath.Join(realDir, filepath.Base(mdPath)))
	markdown.WriteString("| Family | Runs | Questions | TP | FP | TN | FN | QuarantineHostile | QuarantineBenign | AUC | InsuffisantPourAUC | MajorityClassRate | L0Blocks | L1aPasses | L1bBlocks |\n")
	markdown.WriteString("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |\n")
	for _, row := range metrics {
		fmt.Fprintf(&markdown, "| %s | %d | %d | %d | %d | %d | %d | %d | %d | %s | %t | %s | %d | %d | %d |\n",
			strings.ReplaceAll(row.Family, "|", `\|`), row.Runs, row.Questions, row.Metrics.TP, row.Metrics.FP,
			row.Metrics.TN, row.Metrics.FN, row.Metrics.QuarantineHostile,
			row.Metrics.QuarantineBenign, strconv.FormatFloat(row.Metrics.AUC, 'g', -1, 64),
			row.InsuffisantPourAUC, strconv.FormatFloat(row.Metrics.MajorityClassRate, 'g', -1, 64),
			row.Metrics.L0Blocks, row.Metrics.L1aPasses, row.Metrics.L1bBlocks)
	}
	if err := writeLabAtomic(mdPath, []byte(markdown.String())); err != nil {
		return err
	}
	return writeLabAtomic(path, payload)
}

func writeLabAtomic(path string, payload []byte) (err error) {
	file, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	defer func() {
		if file != nil {
			err = errors.Join(err, file.Close())
		}
	}()
	if err = file.Chmod(0o600); err != nil {
		return err
	}
	if _, err = file.Write(payload); err != nil {
		return err
	}
	if err = file.Sync(); err != nil {
		return err
	}
	closeErr := file.Close()
	file = nil
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(tempPath, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	err = dir.Sync()
	return errors.Join(err, dir.Close())
}
