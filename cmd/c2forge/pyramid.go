package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55"
	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

// parseHMACKey lit la clé d'authentification des fichiers .c2oracle, .c2delta
// et .c2pyramid : « hex:<chiffres> » pour une clé hexadécimale, « file:<chemin> »
// pour une clé lue dans un fichier (fins de ligne finales retirées), toute autre
// valeur étant prise comme phrase secrète textuelle. Une valeur vide rend une
// clé vide, donc le sceau SHA-256. Une clé passée en clair sur la ligne de
// commande est visible des autres utilisateurs par la liste des processus :
// « file: » l'évite.
func parseHMACKey(spec string) ([]byte, error) {
	switch {
	case spec == "":
		return nil, nil
	case strings.HasPrefix(spec, "hex:"):
		k, err := hex.DecodeString(strings.TrimPrefix(spec, "hex:"))
		if err != nil {
			return nil, fmt.Errorf("-hmac-key hex: %w", err)
		}
		if len(k) == 0 {
			return nil, fmt.Errorf("-hmac-key hex: specification vide")
		}
		return k, nil
	case strings.HasPrefix(spec, "file:"):
		k, err := os.ReadFile(strings.TrimPrefix(spec, "file:"))
		if err != nil {
			return nil, fmt.Errorf("-hmac-key file: %w", err)
		}
		k = bytes.TrimRight(k, "\r\n")
		if len(k) == 0 {
			return nil, fmt.Errorf("-hmac-key file: fichier de cle vide")
		}
		return k, nil
	default:
		return []byte(spec), nil
	}
}

// sealKind nomme le sceau que produit ou exige une clé.
func sealKind(key []byte) string {
	if len(key) == 0 {
		return "SHA-256"
	}
	return "HMAC-SHA256"
}

// parseScales lit une liste d'horizons séparés par des virgules ; vide rend 0.
func parseScales(list string) (uint16, error) {
	var mask uint16
	for name := range strings.SplitSeq(list, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		bit, ok := c2blue55.ParsePyramidHorizon(name)
		if !ok {
			return 0, fmt.Errorf("horizon %q inconnu", name)
		}
		mask |= bit
	}
	return mask, nil
}

// openSilo ouvre le silo de outDir, dont les tranches sont scellées et
// vérifiées sous key (SHA-256 si key est vide).
func openSilo(outDir string, key []byte) (*c2blue55.DailyOracleSilo, error) {
	cfg := c2blue55.DefaultSiloConfig(outDir)
	cfg.HMACKey = key
	return c2blue55.NewDailyOracleSilo(cfg)
}

// runOracleIngest ingère un journal réel et scelle ses tranches sous key.
func runOracleIngest(w io.Writer, logPath, outDir string, key []byte) error {
	silo, err := openSilo(outDir, key)
	if err != nil {
		return fmt.Errorf("initialisation silo: %w", err)
	}
	n, err := c2blue55.NewLogStreamIngester(silo).IngestLogFile(logPath)
	if err != nil {
		return fmt.Errorf("ingestion log: %w", err)
	}
	if err := silo.SealDay(uint64(time.Now().Unix())); err != nil {
		return fmt.Errorf("scellement: %w", err)
	}
	fmt.Fprintf(w, "c2forge: %d evenements reels ingeres et scelles en tranches .c2oracle dans %s (sceau %s)\n", n, outDir, sealKind(key))
	return nil
}

// runOracleBaseline compile la baseline des tranches authentifiées sous key.
func runOracleBaseline(w io.Writer, outDir string, key []byte) error {
	silo, err := openSilo(outDir, key)
	if err != nil {
		return err
	}
	oracle, err := silo.BuildServerBaseline(30)
	if err != nil {
		return fmt.Errorf("baseline oracle: %w", err)
	}
	fmt.Fprintf(w, "c2forge — Oracle individuel operationnel : %d etats de sante de reference scelles (sceau %s)\n", oracle.Len(), sealKind(key))
	return nil
}

// runOracleVerifyChain vérifie le chaînage des sceaux et échoue sur tout maillon rompu.
func runOracleVerifyChain(w io.Writer, outDir string, key []byte) error {
	silo, err := openSilo(outDir, key)
	if err != nil {
		return err
	}
	breaks, err := silo.VerifyOracleChain()
	if err != nil {
		return err
	}
	for _, b := range breaks {
		fmt.Fprintf(w, "  jour %d : %s\n", b.EpochDay, b.Reason)
	}
	if len(breaks) > 0 {
		return fmt.Errorf("chaine des tranches rompue en %d point(s)", len(breaks))
	}
	fmt.Fprintf(w, "c2forge: chaine des tranches .c2oracle intacte (machine %016x, sceau %s)\n", silo.MachineID(), sealKind(key))
	return nil
}

// runOracleCondense condense les tranches du silo en pyramides multi-échelles.
func runOracleCondense(w io.Writer, outDir string, cfg engine.CondenseConfig, key []byte) error {
	silo, err := openSilo(outDir, key)
	if err != nil {
		return err
	}
	files, err := silo.CondensePyramids(cfg, key)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "c2forge — condensation hierarchique de %s (machine %016x, sceau %s)\n", outDir, silo.MachineID(), sealKind(key))
	for _, f := range files {
		name, _ := c2blue55.PyramidHorizonName(f.Scale)
		st := f.Stats
		fmt.Fprintf(w, "  %-5s : %5d prototypes | jours %d..%d | admises %d, ecartees %d | groupes %d (pic %d, evinces %d, %d obs.) | %s\n",
			name, f.Len, f.Header.EpochStart, f.Header.EpochEnd, st.Admitted, st.Excluded,
			st.Clusters, st.PeakClusters, st.EvictedClusters, st.EvictedHits, f.Path)
	}
	return nil
}

// runDeltaCompile compile une description JSON en catalogue .c2delta.
func runDeltaCompile(w io.Writer, descPath, catalogPath, outDir string, key []byte) error {
	if catalogPath == "" {
		return fmt.Errorf("-delta-compile exige -delta-catalog (fichier produit)")
	}
	f, err := os.Open(descPath)
	if err != nil {
		return err
	}
	rules, err := c2blue55.CompileDeltaDescription(f)
	_ = f.Close()
	if err != nil {
		return err
	}
	machine := c2blue55.DefaultSiloConfig(outDir).MachineID
	tmp, err := os.CreateTemp(filepath.Dir(catalogPath), filepath.Base(catalogPath)+".tmp-*")
	if err != nil {
		return err
	}
	werr := engine.SaveDeltaCatalogHMAC(tmp, machine, rules, key)
	if werr == nil {
		werr = tmp.Sync()
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = os.Rename(tmp.Name(), catalogPath)
	}
	if werr != nil {
		_ = os.Remove(tmp.Name())
		return werr
	}
	fmt.Fprintf(w, "c2forge: %d regles de dispense compilees dans %s (machine %016x, sceau %s)\n", len(rules), catalogPath, machine, sealKind(key))
	for i := range rules {
		r := &rules[i]
		fmt.Fprintf(w, "  regle %d %-32s : %s .. %s | echelles 0x%02x | jours 0x%02x | creneaux %d..%d | rayon %d\n",
			r.RuleID, strings.TrimRight(string(r.Label[:]), "\x00"),
			time.Unix(int64(r.NotBeforeSec), 0).UTC().Format(time.RFC3339), time.Unix(int64(r.NotAfterSec), 0).UTC().Format(time.RFC3339),
			r.ScaleMask, r.DaysOfWeekMask, r.TimeSlotMin, r.TimeSlotMax, r.MaxRadius)
	}
	return nil
}

// evalCounts compte les verdicts d'une échelle.
type evalCounts struct{ nominal, dispensed, anomaly int }

func (c *evalCounts) add(nominal, dispensed bool) {
	switch {
	case nominal:
		c.nominal++
	case dispensed:
		c.dispensed++
	default:
		c.anomaly++
	}
}

// runOracleEval évalue chaque ligne d'une trace contre la baseline du silo
// (échelle 30 j) et contre les pyramides multi-échelles, avec le catalogue de
// dispenses s'il est fourni. Seules les lignes qui ne sont pas nominales
// partout sont détaillées, sauf si verbose.
func runOracleEval(w io.Writer, tracePath, outDir, catalogPath string, key []byte, verbose bool) error {
	silo, err := openSilo(outDir, key)
	if err != nil {
		return err
	}
	machine := silo.MachineID()
	oracle, err := silo.BuildServerBaseline(30)
	if err != nil {
		return err
	}
	pyr, scales, err := silo.LoadPyramids(key)
	if err != nil {
		return err
	}
	var catalog *engine.DeltaCatalog
	catalogDesc := "absent"
	if catalogPath != "" {
		f, err := os.Open(catalogPath)
		if err != nil {
			return err
		}
		catalog, err = engine.LoadDeltaCatalogHMAC(f, machine, key)
		_ = f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", catalogPath, err)
		}
		catalogDesc = fmt.Sprintf("%d regles, %s", catalog.Len(), sealKind(key))
	}
	trace, err := os.Open(tracePath)
	if err != nil {
		return err
	}
	defer trace.Close()

	var loaded []string
	for i := range engine.DeltaScaleCount {
		if scales&(1<<i) != 0 {
			name, _ := c2blue55.PyramidHorizonName(1 << i)
			loaded = append(loaded, name)
		}
	}
	fmt.Fprintf(w, "c2forge — evaluation multi-echelle de %s (machine %016x)\n", tracePath, machine)
	fmt.Fprintf(w, "baseline : %d etats de reference | pyramides : %s | catalogue : %s\n",
		oracle.Len(), strings.Join(loaded, " "), catalogDesc)

	thresholds := engine.DefaultLocalityThresholds()
	source := filepath.Base(tracePath)
	var (
		events   int
		base     evalCounts
		perScale [engine.DeltaScaleCount]evalCounts
	)
	lines := bufio.NewScanner(trace)
	lines.Buffer(make([]byte, 64*1024), 1024*1024)
	for lines.Scan() {
		snap, ok := c2blue55.ParseLogLine(lines.Text(), source)
		if !ok {
			continue
		}
		events++
		var bc [8]uint64
		engine.VectorizeServerHealthLocality(&snap, &bc)
		v := engine.EvaluateStateWithDelta(oracle, catalog, &bc, snap.TimestampSec, engine.DeltaScale30d, thresholds)
		base.add(v.Nominal, v.Dispensed)
		rep := pyr.EvaluateInstantaneous(&bc, snap.TimestampSec, catalog)
		for i := range rep.Levels {
			if lv := rep.Levels[i]; lv.Loaded {
				perScale[i].add(lv.Nominal, lv.Dispensed)
			}
		}
		if !verbose && v.Nominal && rep.NominalMask == rep.LoadedMask {
			continue
		}
		fmt.Fprintf(w, "%s sub=%d act=%d sev=%d score=%d | base:%s |%s\n",
			time.Unix(int64(snap.TimestampSec), 0).UTC().Format(time.RFC3339),
			snap.Subsystem, snap.Action, snap.Severity, snap.HealthScore, baseVerdict(v), scaleVerdicts(&rep))
	}
	if err := lines.Err(); err != nil {
		return err
	}
	fmt.Fprintf(w, "synthese : %d evenements | base 30d : nominal %d, dispense %d, anomalie %d\n",
		events, base.nominal, base.dispensed, base.anomaly)
	for i, c := range perScale {
		if scales&(1<<i) == 0 {
			continue
		}
		name, _ := c2blue55.PyramidHorizonName(1 << i)
		fmt.Fprintf(w, "  %-5s : nominal %d, dispense %d, anomalie %d\n", name, c.nominal, c.dispensed, c.anomaly)
	}
	return nil
}

// baseVerdict rend le verdict de la baseline : NOMINAL, DISPENSE#<règle> ou
// ANOMALIE, avec l'écart par groupe de mots à la référence retenue.
func baseVerdict(v engine.StateDeltaVerdict) string {
	d := fmt.Sprintf("(cat %d, sev %+d, scal %d, ent %d, cont %d, surprise %.1f bits)",
		v.Distance.Categorical, v.Distance.SeverityRise, v.Distance.Scalar, v.Distance.Entity, v.Distance.Content, v.ContentSurprise)
	switch {
	case v.Nominal:
		return "NOMINAL" + d
	case v.Dispensed:
		return fmt.Sprintf("DISPENSE#%d%s", v.RuleID, d)
	default:
		return "ANOMALIE" + d
	}
}

// scaleVerdicts rend, pour chaque échelle chargée, N (nominal), D#<règle>
// (dispensé) ou A (anomalie), suivi de la distance au prototype admissible le
// plus proche et de son rang.
func scaleVerdicts(rep *engine.MultiScaleDisparityReport) string {
	var b strings.Builder
	for _, lv := range rep.Levels {
		if !lv.Loaded {
			continue
		}
		name, _ := c2blue55.PyramidHorizonName(lv.Scale)
		verdict := "A"
		switch {
		case lv.Nominal:
			verdict = "N"
		case lv.Dispensed:
			verdict = fmt.Sprintf("D#%d", lv.RuleID)
		}
		fmt.Fprintf(&b, " %s:%s(d=%d,p=%d)", name, verdict, lv.DisparityBits, lv.PrototypeIndex)
	}
	return b.String()
}
