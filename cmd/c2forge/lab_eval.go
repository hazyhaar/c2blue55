package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

func runLabEval(args []string, output io.Writer) (int, error) {
	flags := flag.NewFlagSet("lab-eval", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	sourceDir := flags.String("data", "", "Répertoire des données Wittgenstein")
	labDir := flags.String("lab", "", "Répertoire des captures du laboratoire")
	outDir := flags.String("out", "", "Répertoire des disquettes d'évaluation")
	reportPath := flags.String("report", "", "Chemin du rapport JSON")
	tolerant := flags.Bool("tolerant", false, "Ingère les QNAME hors LDH via ParseDNSQueryTolerant et NonLDHBurstGuard")
	if err := flags.Parse(args); err != nil {
		return 2, err
	}
	if flags.NArg() != 0 || *sourceDir == "" || *labDir == "" || *outDir == "" || *reportPath == "" {
		return 2, fmt.Errorf("lab-eval exige -data, -lab, -out et -report, sans argument supplémentaire")
	}
	evaluateur := c2blue55.EvaluateDNSLabFamilies
	if *tolerant {
		evaluateur = c2blue55.EvaluateDNSLabFamiliesTolerant
	}
	metrics, err := evaluateur(*sourceDir, *labDir, *outDir, engine.WittgensteinFloppyKey(engine.FloppyFamilyDNSC2))
	if err != nil {
		return 2, err
	}
	if err := c2blue55.WriteLabReport(*reportPath, metrics); err != nil {
		return 2, err
	}
	for _, row := range metrics {
		counts := row.Metrics
		if _, err := fmt.Fprintf(output, "%s %d %d %d %d %d %d %d %d %d %d %d %g %g %t\n",
			row.Family, row.Runs, row.Questions, counts.TP, counts.FP, counts.TN, counts.FN,
			counts.QuarantineHostile, counts.QuarantineBenign, counts.L0Blocks,
			counts.L1aPasses, counts.L1bBlocks, counts.MajorityClassRate, counts.AUC,
			row.InsuffisantPourAUC); err != nil {
			return 2, err
		}
	}
	return 0, nil
}
