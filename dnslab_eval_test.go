package c2blue55_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

const labAUCMinQuestions = 50

func TestLabRuns_LoadRealRuns(t *testing.T) {
	labDir := redhostLabDir(t)
	names := labManifestNames(t, labDir)
	if len(names) < 5 {
		t.Fatalf("manifestes=%d, attendu au moins 5", len(names))
	}
	requireKnownLabManifests(t, names)

	runs, err := c2blue55.LoadLabRuns(labDir)
	if err != nil {
		t.Fatalf("LoadLabRuns: %v", err)
	}
	if len(runs) != len(names) {
		t.Fatalf("runs=%d, manifestes=%d", len(runs), len(names))
	}
	seenPinned := 0
	for index, name := range names {
		stem := strings.TrimSuffix(name, ".manifest.json")
		run := runs[index]
		if run.RunID != stem {
			t.Errorf("runs[%d].RunID=%q, attendu %q (tri RunID croissant)", index, run.RunID, stem)
		}
		manifestPath := filepath.Join(labDir, name)
		loaded, loadErr := c2blue55.LoadRedhostLabManifest(manifestPath)
		if loadErr != nil {
			t.Fatalf("LoadRedhostLabManifest %s: %v", name, loadErr)
		}
		assertLabManifestFull(t, run.Manifest, loaded)
		if run.Manifest.RunID != stem {
			t.Errorf("Manifest.RunID=%q, attendu %q", run.Manifest.RunID, stem)
		}
		wantFamily := loaded.Family
		if wantFamily == "" {
			wantFamily = loaded.Label
		}
		if run.Family != wantFamily {
			t.Errorf("run %s Family=%q, attendu %q", stem, run.Family, wantFamily)
		}
		wantHostile := strings.HasPrefix(run.Family, "redhost-")
		if run.Hostile != wantHostile {
			t.Errorf("run %s Hostile=%t, attendu %t (famille %q)", stem, run.Hostile, wantHostile, run.Family)
		}
		ingested, ingestErr := c2blue55.IngestRedhostLabRun(filepath.Join(labDir, stem+".pcap"), manifestPath)
		if ingestErr != nil {
			t.Fatalf("IngestRedhostLabRun %s: %v", stem, ingestErr)
		}
		accepted := int(ingested.Stats.Accepted)
		if len(run.Views) != accepted {
			t.Errorf("run %s len(Views)=%d, IngestRedhostLabRun.Stats.Accepted=%d", stem, len(run.Views), accepted)
		}
		if pinned, ok := pinnedLabQuestions(stem); ok {
			seenPinned++
			if len(run.Views) != pinned {
				t.Errorf("run %s len(Views)=%d, vérité terrain %d", stem, len(run.Views), pinned)
			}
		}
		for viewIndex := range run.Views {
			fqdn := string(run.Views[viewIndex].FQDN)
			if !labFQDNAllowed(fqdn) {
				t.Errorf("run %s Views[%d].FQDN=%q, attendu suffixe pound2pound.fr ou hazyhaar.fr", stem, viewIndex, fqdn)
			}
		}
	}
	if seenPinned != 5 {
		t.Errorf("runs épinglés vus=%d, attendu 5", seenPinned)
	}
}

func TestLabRuns_MissingCaptureRefused(t *testing.T) {
	labDir := redhostLabDir(t)
	names := labManifestNames(t, labDir)
	if len(names) < 5 {
		t.Fatalf("manifestes=%d, attendu au moins 5", len(names))
	}
	omitted := strings.TrimSuffix(names[0], ".manifest.json")

	t.Run("capture absente", func(t *testing.T) {
		dir := t.TempDir()
		for _, name := range names {
			copyNamedFile(t, filepath.Join(labDir, name), filepath.Join(dir, name))
			stem := strings.TrimSuffix(name, ".manifest.json")
			if stem == omitted {
				continue
			}
			copyNamedFile(t, filepath.Join(labDir, stem+".pcap"), filepath.Join(dir, stem+".pcap"))
		}
		runs, err := c2blue55.LoadLabRuns(dir)
		if !errors.Is(err, c2blue55.ErrLabRunContract) {
			t.Fatalf("erreur=%v, attendu ErrLabRunContract", err)
		}
		if !strings.Contains(err.Error(), omitted) {
			t.Fatalf("erreur=%v ne nomme pas le run %s", err, omitted)
		}
		if runs != nil {
			t.Fatalf("tranche=%#v, attendu nil", runs)
		}
	})

	t.Run("manifeste hors contrat", func(t *testing.T) {
		dir := t.TempDir()
		name := names[0]
		stem := strings.TrimSuffix(name, ".manifest.json")
		payload, err := os.ReadFile(filepath.Join(labDir, name))
		if err != nil {
			t.Fatalf("lecture du manifeste: %v", err)
		}
		fields := manifestMap(t, payload)
		fields["champ_inconnu"] = "hors-contrat"
		encoded, err := json.Marshal(fields)
		if err != nil {
			t.Fatalf("encodage du manifeste altéré: %v", err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), encoded, 0o644); err != nil {
			t.Fatalf("écriture du manifeste altéré: %v", err)
		}
		copyNamedFile(t, filepath.Join(labDir, stem+".pcap"), filepath.Join(dir, stem+".pcap"))
		runs, err := c2blue55.LoadLabRuns(dir)
		if !errors.Is(err, c2blue55.ErrLabRunContract) {
			t.Fatalf("erreur=%v, attendu ErrLabRunContract", err)
		}
		if runs != nil {
			t.Fatalf("tranche=%#v, attendu nil", runs)
		}
	})
}

func TestLabFamilies_RealRunsHeldOut(t *testing.T) {
	corpusDir, labDir := wittgensteinDirs(t)
	rollup := hostileFamilyRollup(t, labDir)
	assertTerrainPins(t, rollup)
	hmacKey := engine.WittgensteinFloppyKey(engine.FloppyFamilyDNSC2)
	if len(hmacKey) == 0 {
		t.Fatal("clé HMAC de laboratoire vide")
	}

	outDir := t.TempDir()
	metrics, err := c2blue55.EvaluateDNSLabFamilies(corpusDir, labDir, outDir, hmacKey)
	if err != nil {
		t.Fatalf("EvaluateDNSLabFamilies: %v", err)
	}
	for _, row := range metrics {
		logLabFamily(t, row)
	}
	if len(metrics) != len(rollup) {
		t.Fatalf("familles rendues=%d, familles hostiles présentes=%d", len(metrics), len(rollup))
	}
	benignFloor := -1
	for index, roll := range rollup {
		row := metrics[index]
		if row.Family != roll.family {
			t.Errorf("metrics[%d].Family=%q, attendu %q (tri Family croissant)", index, row.Family, roll.family)
		}
		if row.Runs != roll.runs {
			t.Errorf("%s Runs=%d, attendu %d", roll.family, row.Runs, roll.runs)
		}
		if row.Questions != roll.questions {
			t.Errorf("%s Questions=%d, attendu %d", roll.family, row.Questions, roll.questions)
		}
		wantInsufficient := roll.questions < labAUCMinQuestions
		if row.InsuffisantPourAUC != wantInsufficient {
			t.Errorf("%s InsuffisantPourAUC=%t, attendu %t (seuil %d questions)", roll.family, row.InsuffisantPourAUC, wantInsufficient, labAUCMinQuestions)
		}
		cold := row.Metrics
		hostileSide := hostileAccounted(cold)
		if hostileSide != roll.questions {
			t.Errorf("%s TP+FN+QuarantineHostile=%d, attendu %d", roll.family, hostileSide, roll.questions)
		}
		benignSide := benignAccounted(cold)
		if benignSide < 69 {
			t.Errorf("%s TN+FP+QuarantineBenign=%d, attendu au moins 69", roll.family, benignSide)
		}
		if benignFloor < 0 {
			benignFloor = benignSide
		} else if benignSide != benignFloor {
			t.Errorf("%s bénin compté=%d, attendu %d (même ensemble bénin pour chaque famille tenue à l'écart)", roll.family, benignSide, benignFloor)
		}
		accounted := sixAccounted(cold)
		if cold.Total != accounted {
			t.Errorf("%s Total=%d, somme des six compteurs=%d", roll.family, cold.Total, accounted)
		}
		if cold.L0Blocks != 0 {
			t.Errorf("%s L0Blocks=%d, attendu 0", roll.family, cold.L0Blocks)
		}
		if wantInsufficient {
			if cold.AUC != 0 {
				t.Errorf("%s AUC=%g, attendu 0 (famille insuffisante, sans AUC)", roll.family, cold.AUC)
			}
		} else {
			if cold.AUC < 0 || cold.AUC > 1 || cold.AUC != cold.AUC {
				t.Errorf("%s AUC=%g, attendu dans [0, 1]", roll.family, cold.AUC)
			}
			if cold.MajorityClassRate < 0.5 || cold.MajorityClassRate > 1 || cold.MajorityClassRate != cold.MajorityClassRate {
				t.Errorf("%s MajorityClassRate=%g, attendu dans [0.5, 1]", roll.family, cold.MajorityClassRate)
			}
		}
		assertFamilyFloppies(t, outDir, roll.family, hmacKey)
	}

	secondDir := t.TempDir()
	second, secondErr := c2blue55.EvaluateDNSLabFamilies(corpusDir, labDir, secondDir, hmacKey)
	if secondErr != nil {
		t.Fatalf("second EvaluateDNSLabFamilies: %v", secondErr)
	}
	if len(second) != len(metrics) {
		t.Fatalf("second appel: familles=%d, attendu %d", len(second), len(metrics))
	}
	for index := range metrics {
		assertLabFamilyEqual(t, second[index], metrics[index])
	}
}

func TestWriteLabReport_AtomicAndMarkdown(t *testing.T) {
	metrics := sampleLabMetrics()

	t.Run("json et markdown", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "homologation.json")
		if err := c2blue55.WriteLabReport(path, metrics); err != nil {
			t.Fatalf("WriteLabReport: %v", err)
		}
		st, err := os.Stat(path)
		if err != nil {
			t.Fatalf("rapport JSON non écrit: %v", err)
		}
		if !st.Mode().IsRegular() {
			t.Fatalf("rapport JSON mode=%v, attendu fichier régulier", st.Mode())
		}
		if st.Mode().Perm() != 0o600 {
			t.Errorf("mode=%o, attendu 0600", st.Mode().Perm())
		}
		got := readLabReportJSON(t, path)
		if len(got) != len(metrics) {
			t.Fatalf("entrées JSON=%d, attendu %d", len(got), len(metrics))
		}
		for index := range metrics {
			assertLabFamilyEqual(t, got[index], metrics[index])
		}
		mdPath := path + ".md"
		assertLabMarkdown(t, mdPath, metrics)
		assertNoResidualFiles(t, dir, []string{filepath.Base(path), filepath.Base(mdPath)})
	})

	t.Run("répertoire non inscriptible", func(t *testing.T) {
		sealed := filepath.Join(t.TempDir(), "scelle")
		if err := os.Mkdir(sealed, 0o755); err != nil {
			t.Fatalf("création du répertoire scellé: %v", err)
		}
		if err := os.Chmod(sealed, 0o555); err != nil {
			t.Fatalf("scellement du répertoire: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(sealed, 0o755) })
		err := c2blue55.WriteLabReport(filepath.Join(sealed, "homologation.json"), metrics)
		if err == nil {
			t.Fatal("répertoire non inscriptible: erreur attendue absente")
		}
	})
}

func wittgensteinDirs(t *testing.T) (corpusDir, labDir string) {
	t.Helper()
	labDir = redhostLabDir(t)
	corpusDir = filepath.Dir(labDir)
	return corpusDir, labDir
}

func labManifestNames(t *testing.T, labDir string) []string {
	t.Helper()
	entries, err := os.ReadDir(labDir)
	if err != nil {
		t.Fatalf("lecture de %s: %v", labDir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".manifest.json") {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

func requireKnownLabManifests(t *testing.T, names []string) {
	t.Helper()
	known := []string{
		"iodine-20261027T151046Z.manifest.json",
		"local-dns-20261027T113715Z.manifest.json",
		"replay-20261027T150838Z.manifest.json",
		"replay-tuns-20261027T150656Z.manifest.json",
		"replay-tuns-20261027T150942Z.manifest.json",
	}
	for _, name := range known {
		if !slices.Contains(names, name) {
			t.Fatalf("manifeste connu absent: %s", name)
		}
	}
}

func pinnedLabQuestions(runID string) (int, bool) {
	switch runID {
	case "replay-20261027T150838Z":
		return 598, true
	case "replay-tuns-20261027T150656Z":
		return 132, true
	case "replay-tuns-20261027T150942Z":
		return 598, true
	case "iodine-20261027T151046Z":
		return 5, true
	case "local-dns-20261027T113715Z":
		return 69, true
	default:
		return 0, false
	}
}

func labFQDNAllowed(fqdn string) bool {
	return strings.HasSuffix(fqdn, "pound2pound.fr") || strings.HasSuffix(fqdn, "hazyhaar.fr")
}

func copyNamedFile(t *testing.T, src, dst string) {
	t.Helper()
	payload, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("lecture %s: %v", src, err)
	}
	if err := os.WriteFile(dst, payload, 0o644); err != nil {
		t.Fatalf("écriture %s: %v", dst, err)
	}
}

func assertLabManifestFull(t *testing.T, got, want c2blue55.RedhostLabManifest) {
	t.Helper()
	assertManifestEqual(t, got, want)
	if got.Family != want.Family || got.Tool != want.Tool || got.Emitter != want.Emitter || got.Server != want.Server {
		t.Errorf("champs de laboratoire got Family=%q Tool=%q Emitter=%q Server=%q, attendu Family=%q Tool=%q Emitter=%q Server=%q", got.Family, got.Tool, got.Emitter, got.Server, want.Family, want.Tool, want.Emitter, want.Server)
	}
}

type familyRollup struct {
	family    string
	runs      int
	questions int
}

func hostileFamilyRollup(t *testing.T, labDir string) []familyRollup {
	t.Helper()
	names := labManifestNames(t, labDir)
	byFamily := make(map[string]familyRollup)
	order := make([]string, 0)
	for _, name := range names {
		manifestPath := filepath.Join(labDir, name)
		loaded, err := c2blue55.LoadRedhostLabManifest(manifestPath)
		if err != nil {
			t.Fatalf("LoadRedhostLabManifest %s: %v", name, err)
		}
		family := loaded.Family
		if family == "" {
			family = loaded.Label
		}
		if !strings.HasPrefix(family, "redhost-") {
			continue
		}
		stem := strings.TrimSuffix(name, ".manifest.json")
		ingested, ingestErr := c2blue55.IngestRedhostLabRun(filepath.Join(labDir, stem+".pcap"), manifestPath)
		if ingestErr != nil {
			t.Fatalf("IngestRedhostLabRun %s: %v", stem, ingestErr)
		}
		roll := byFamily[family]
		if roll.runs == 0 {
			order = append(order, family)
		}
		roll.family = family
		roll.runs++
		roll.questions += int(ingested.Stats.Accepted)
		byFamily[family] = roll
	}
	slices.Sort(order)
	out := make([]familyRollup, 0, len(order))
	for _, family := range order {
		out = append(out, byFamily[family])
	}
	return out
}

func assertTerrainPins(t *testing.T, rollup []familyRollup) {
	t.Helper()
	foundReplay := false
	foundIodine := false
	for _, roll := range rollup {
		switch roll.family {
		case "redhost-replay":
			foundReplay = true
			if roll.runs != 3 || roll.questions != 1328 {
				t.Fatalf("vérité terrain redhost-replay: runs=%d questions=%d, attendu 3 et 1328", roll.runs, roll.questions)
			}
		case "redhost-iodine":
			foundIodine = true
			if roll.runs != 1 || roll.questions != 5 {
				t.Fatalf("vérité terrain redhost-iodine: runs=%d questions=%d, attendu 1 et 5", roll.runs, roll.questions)
			}
		}
	}
	if !foundReplay || !foundIodine {
		t.Fatalf("familles hostiles incomplètes: redhost-replay=%t redhost-iodine=%t", foundReplay, foundIodine)
	}
}

func hostileAccounted(cold engine.ColdSplitMetrics) int {
	return cold.TP + cold.FN + cold.QuarantineHostile
}

func benignAccounted(cold engine.ColdSplitMetrics) int {
	return cold.TN + cold.FP + cold.QuarantineBenign
}

func sixAccounted(cold engine.ColdSplitMetrics) int {
	return cold.TP + cold.FP + cold.TN + cold.FN + cold.QuarantineHostile + cold.QuarantineBenign
}

func logLabFamily(t *testing.T, row c2blue55.LabFamilyMetrics) {
	t.Helper()
	cold := row.Metrics
	t.Logf("famille=%s runs=%d questions=%d insuffisant=%t total=%d TP=%d FP=%d TN=%d FN=%d quarantaine_hostile=%d quarantaine_benin=%d L0=%d L1a=%d L1b=%d majorite=%g AUC=%g",
		row.Family, row.Runs, row.Questions, row.InsuffisantPourAUC,
		cold.Total, cold.TP, cold.FP, cold.TN, cold.FN, cold.QuarantineHostile, cold.QuarantineBenign,
		cold.L0Blocks, cold.L1aPasses, cold.L1bBlocks, cold.MajorityClassRate, cold.AUC)
}

func assertFamilyFloppies(t *testing.T, outDir, family string, hmacKey []byte) {
	t.Helper()
	for _, name := range []string{"floppy_dns_tunnel.c2book", "floppy_dns_dga.c2book"} {
		diskPath := filepath.Join(outDir, family, name)
		disk, err := engine.LoadFloppyMmap(diskPath, hmacKey)
		if err != nil {
			t.Errorf("LoadFloppyMmap %s: %v", diskPath, err)
			continue
		}
		if closeErr := disk.Close(); closeErr != nil {
			t.Errorf("fermeture %s: %v", diskPath, closeErr)
		}
	}
}

func assertColdSplitEqual(t *testing.T, got, want engine.ColdSplitMetrics) {
	t.Helper()
	if got.Total != want.Total || got.MajorityClassRate != want.MajorityClassRate || got.TP != want.TP || got.FP != want.FP || got.TN != want.TN || got.FN != want.FN || got.QuarantineHostile != want.QuarantineHostile || got.QuarantineBenign != want.QuarantineBenign || got.L0Blocks != want.L0Blocks || got.L1aPasses != want.L1aPasses || got.L1bBlocks != want.L1bBlocks || got.AUC != want.AUC {
		t.Errorf("ColdSplitMetrics=%+v, attendu %+v", got, want)
	}
}

func assertLabFamilyEqual(t *testing.T, got, want c2blue55.LabFamilyMetrics) {
	t.Helper()
	if got.Family != want.Family || got.Runs != want.Runs || got.Questions != want.Questions || got.InsuffisantPourAUC != want.InsuffisantPourAUC {
		t.Errorf("LabFamilyMetrics=%+v, attendu %+v", got, want)
	}
	assertColdSplitEqual(t, got.Metrics, want.Metrics)
}

func sampleLabMetrics() []c2blue55.LabFamilyMetrics {
	return []c2blue55.LabFamilyMetrics{
		{
			Family:             "redhost-iodine",
			Runs:               1,
			Questions:          5,
			InsuffisantPourAUC: true,
			Metrics: engine.ColdSplitMetrics{
				Total:             21,
				MajorityClassRate: 0.75,
				TP:                1,
				FP:                2,
				TN:                3,
				FN:                4,
				QuarantineHostile: 5,
				QuarantineBenign:  6,
				L0Blocks:          7,
				L1aPasses:         8,
				L1bBlocks:         9,
				AUC:               0.25,
			},
		},
		{
			Family:             "redhost-replay",
			Runs:               3,
			Questions:          1328,
			InsuffisantPourAUC: false,
			Metrics: engine.ColdSplitMetrics{
				Total:             75,
				MajorityClassRate: 0.5,
				TP:                10,
				FP:                11,
				TN:                12,
				FN:                13,
				QuarantineHostile: 14,
				QuarantineBenign:  15,
				L0Blocks:          16,
				L1aPasses:         17,
				L1bBlocks:         18,
				AUC:               0.5,
			},
		},
	}
}

func readLabReportJSON(t *testing.T, path string) []c2blue55.LabFamilyMetrics {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lecture du rapport JSON: %v", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	var got []c2blue55.LabFamilyMetrics
	if err := decoder.Decode(&got); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("JSON: contenu après le tableau: %v", err)
	}
	return got
}

func assertLabMarkdown(t *testing.T, mdPath string, metrics []c2blue55.LabFamilyMetrics) {
	t.Helper()
	payload, err := os.ReadFile(mdPath)
	if err != nil {
		t.Fatalf("rapport Markdown non écrit: %v", err)
	}
	realMD, err := filepath.EvalSymlinks(mdPath)
	if err != nil {
		t.Fatalf("chemin réel du markdown: %v", err)
	}
	text := string(payload)
	line, rest, found := strings.Cut(text, "\n")
	if !found {
		t.Fatal("markdown: fin de ligne absente après l'en-tête filepath")
	}
	wantHeader := "filepath: " + realMD
	if line != wantHeader {
		t.Errorf("première ligne=%q, attendu %q", line, wantHeader)
	}
	if !strings.HasPrefix(rest, "\n") {
		t.Error("ligne vide absente après l'en-tête filepath")
	}
	header, rows := markdownTable(strings.Split(text, "\n"))
	if header == nil {
		t.Fatal("tableau Markdown absent")
	}
	col := make(map[string]int, len(header))
	for index, cell := range header {
		col[cell] = index
	}
	for _, name := range []string{"Family", "Questions", "TP", "FP", "TN", "FN", "AUC"} {
		if _, ok := col[name]; !ok {
			t.Errorf("colonne %s absente: %v", name, header)
		}
	}
	if len(rows) != len(metrics) {
		t.Fatalf("lignes de tableau=%d, attendu %d", len(rows), len(metrics))
	}
	for index, row := range metrics {
		cells := rows[index]
		family, ok := cellAt(cells, col, "Family")
		if !ok || family != row.Family {
			t.Errorf("ligne %d Family=%q, attendu %q", index, family, row.Family)
		}
		if n, err := cellInt(cells, col, "Questions"); err != nil || n != row.Questions {
			t.Errorf("ligne %d Questions=%d (%v), attendu %d", index, n, err, row.Questions)
		}
		if n, err := cellInt(cells, col, "TP"); err != nil || n != row.Metrics.TP {
			t.Errorf("ligne %d TP=%d (%v), attendu %d", index, n, err, row.Metrics.TP)
		}
		if n, err := cellInt(cells, col, "FP"); err != nil || n != row.Metrics.FP {
			t.Errorf("ligne %d FP=%d (%v), attendu %d", index, n, err, row.Metrics.FP)
		}
		if n, err := cellInt(cells, col, "TN"); err != nil || n != row.Metrics.TN {
			t.Errorf("ligne %d TN=%d (%v), attendu %d", index, n, err, row.Metrics.TN)
		}
		if n, err := cellInt(cells, col, "FN"); err != nil || n != row.Metrics.FN {
			t.Errorf("ligne %d FN=%d (%v), attendu %d", index, n, err, row.Metrics.FN)
		}
		if auc, err := cellFloat(cells, col, "AUC"); err != nil || auc != row.Metrics.AUC {
			t.Errorf("ligne %d AUC=%g (%v), attendu %g", index, auc, err, row.Metrics.AUC)
		}
	}
}

func markdownTable(lines []string) (header []string, rows [][]string) {
	headerAt := -1
	for index, line := range lines {
		cells := splitMarkdownRow(line)
		if cells == nil || separatorRow(cells) {
			continue
		}
		if containsCell(cells, "Family") && containsCell(cells, "Questions") && containsCell(cells, "AUC") {
			headerAt = index
			header = cells
			break
		}
	}
	if headerAt < 0 {
		return nil, nil
	}
	for _, line := range lines[headerAt+1:] {
		cells := splitMarkdownRow(line)
		if cells == nil {
			break
		}
		if separatorRow(cells) {
			continue
		}
		rows = append(rows, cells)
	}
	return header, rows
}

func splitMarkdownRow(line string) []string {
	line = strings.TrimSpace(line)
	if !strings.Contains(line, "|") {
		return nil
	}
	parts := strings.Split(line, "|")
	cells := make([]string, 0, len(parts))
	for _, part := range parts {
		cells = append(cells, strings.TrimSpace(part))
	}
	if len(cells) > 0 && cells[0] == "" {
		cells = cells[1:]
	}
	if len(cells) > 0 && cells[len(cells)-1] == "" {
		cells = cells[:len(cells)-1]
	}
	if len(cells) == 0 {
		return nil
	}
	return cells
}

func separatorRow(cells []string) bool {
	if len(cells) == 0 {
		return false
	}
	for _, cell := range cells {
		if !strings.Contains(cell, "-") {
			return false
		}
		if strings.Trim(cell, " :-") != "" {
			return false
		}
	}
	return true
}

func containsCell(cells []string, name string) bool {
	return slices.Contains(cells, name)
}

func cellAt(cells []string, col map[string]int, name string) (string, bool) {
	index, ok := col[name]
	if !ok || index < 0 || index >= len(cells) {
		return "", false
	}
	return cells[index], true
}

func cellInt(cells []string, col map[string]int, name string) (int, error) {
	cell, ok := cellAt(cells, col, name)
	if !ok {
		return 0, errors.New("colonne introuvable")
	}
	return strconv.Atoi(cell)
}

func cellFloat(cells []string, col map[string]int, name string) (float64, error) {
	cell, ok := cellAt(cells, col, name)
	if !ok {
		return 0, errors.New("colonne introuvable")
	}
	return strconv.ParseFloat(cell, 64)
}

func assertNoResidualFiles(t *testing.T, dir string, want []string) {
	t.Helper()
	listed, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("lecture de %s: %v", dir, err)
	}
	names := make([]string, 0, len(listed))
	for _, entry := range listed {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	wantSorted := append([]string(nil), want...)
	slices.Sort(wantSorted)
	if !slices.Equal(names, wantSorted) {
		t.Errorf("fichiers=%v, attendu %v", names, wantSorted)
	}
}
