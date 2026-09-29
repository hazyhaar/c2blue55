// Command c2forge indexe hors-ligne un répertoire de codes sources ou
// d'exploits réels en un codebook RaBitQ 512D (.c2book). Chaque fichier est
// découpé en fenêtres glissantes d'au plus 96 octets, la taille maximale de la
// charge utile d'un événement c2blue55. Chaque fenêtre est projetée en un
// vecteur de 512 dimensions par l'extracteur du moteur, quantifiée sur un bit
// par dimension, puis sérialisée avec ses métadonnées de menace.
//
// Le binaire ne se connecte à aucune sonde et n'applique aucune interdiction :
// il ne fait que vectoriser des octets fournis sur son disque.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

// Sous-systèmes conventionnels portés par les entrées produites. La valeur est
// fournie par le drapeau -subsystem et recopiée telle quelle dans chaque
// entrée ; la table documentaire reste 1 proc, 2 fichier, 3 réseau, 4 web.
const (
	actExec uint16 = 1
)

// forger détient l'état réutilisable d'un travailleur : l'extracteur de
// caractéristiques, un tampon de lecture réutilisé d'un fichier à l'autre et
// un vecteur de projection. Aucun de ces tampons n'est partagé entre
// travailleurs.
type forger struct {
	fe  engine.FeatureExtractor
	buf []byte
	vec [engine.EmbeddingDim]float32
}

func newForger() *forger {
	return &forger{fe: engine.NewFeatureExtractor()}
}

// readFile lit un fichier en blocs de 64 Kio dans un tampon conservé par le
// travailleur. La croissance du tampon est amortie sur l'ensemble du parcours
// et aucune copie intermédiaire du contenu n'est construite.
func (g *forger) readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := g.buf[:0]
	var block [64 << 10]byte
	for {
		n, rerr := f.Read(block[:])
		if n > 0 {
			buf = append(buf, block[:n]...)
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}
	g.buf = buf
	return buf, nil
}

// forge lit un fichier et rend les entrées de codebook produites, la
// volumétrie lue et un indicateur de succès. Un fichier vide ne produit aucune
// fenêtre ; un fichier plus court que la fenêtre produit une fenêtre unique
// bornée à sa longueur réelle.
func (g *forger) forge(path string, window, stride int, threatID uint32, subsystem uint16) (out []engine.CodebookEntry, read int, ok bool) {
	data, err := g.readFile(path)
	if err != nil {
		return nil, 0, false
	}
	n := len(data)
	if n == 0 {
		return nil, 0, true
	}
	if n < window {
		out = g.appendWindow(out, data, threatID, subsystem)
		return out, n, true
	}
	for off := 0; off+window <= n; off += stride {
		out = g.appendWindow(out, data[off:off+window], threatID, subsystem)
	}
	return out, n, true
}

// appendWindow projette une fenêtre en vecteur 512D, la quantifie en 1-bit
// RaBitQ et ajoute l'entrée correspondante. Les tampons de travail sont des
// champs du travailleur, donc la fonction n'alloue rien d'autre que la
// croissance de la tranche de sortie.
func (g *forger) appendWindow(out []engine.CodebookEntry, win []byte, threatID uint32, subsystem uint16) []engine.CodebookEntry {
	var ev engine.Event
	ev.Subsystem = subsystem
	ev.Action = actExec
	copy(ev.Payload[:], win)
	if !g.fe.ExtractTo(&ev, g.vec[:]) {
		return out
	}
	var e engine.CodebookEntry
	engine.Quantize512(g.vec[:], &e.Bitcode)
	e.ThreatID = threatID
	e.Subsystem = subsystem
	e.Severity = engine.SeverityLow
	return append(out, e)
}

// fnv1a32 calcule l'empreinte FNV-1a 32 bits d'une chaîne sans allouer.
func fnv1a32(s string) uint32 {
	const (
		offset = uint32(2166136261)
		prime  = uint32(16777619)
	)
	h := offset
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime
	}
	return h
}

// collectFiles parcourt le répertoire et rend les chemins absolus des fichiers
// réguliers ainsi que leur chemin relatif, dans un ordre trié et donc
// déterministe.
func collectFiles(root string) (abs []string, rel []string, err error) {
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		r, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		abs = append(abs, path)
		rel = append(rel, r)
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Sort(pathPairs{abs: abs, rel: rel})
	return abs, rel, nil
}

// pathPairs permet de trier deux tranches parallèles selon le chemin relatif.
type pathPairs struct {
	abs []string
	rel []string
}

func (p pathPairs) Len() int           { return len(p.rel) }
func (p pathPairs) Less(i, j int) bool { return p.rel[i] < p.rel[j] }
func (p pathPairs) Swap(i, j int) {
	p.abs[i], p.abs[j] = p.abs[j], p.abs[i]
	p.rel[i], p.rel[j] = p.rel[j], p.rel[i]
}

func main() {
	inDir := flag.String("in", "", "Répertoire source à ingérer (obligatoire)")
	outFile := flag.String("out", "gallery.c2book", "Chemin du fichier .c2book en sortie")
	window := flag.Int("window", engine.FeaturePayloadBytes, "Taille de la fenêtre en octets (1..96)")
	stride := flag.Int("stride", 32, "Pas d'avancement de la fenêtre en octets")
	threatID := flag.Uint("threat-id", 0, "Identifiant de menace fixe (0 = calcul FNV1a du chemin relatif)")
	subsystem := flag.Uint("subsystem", 1, "Sous-système par défaut (1=Proc, 2=File, 3=Net, 4=Web)")
	workers := flag.Int("workers", runtime.NumCPU(), "Nombre de goroutines de calcul")
	crossStacks := flag.Bool("cross-stacks", false, "Compile le catalogue unifie des 75 motifs croises (Stacks 01 a 05)")
	flaws := flag.Bool("flaws", false, "Compile le catalogue unifie des 75 anti-patterns de code vulnerable (Flaws 01 a 05)")
	thematicAll := flag.Bool("thematic-all", false, "Compile l'ensemble des 5 disquettes thematiques de vulnerabilites dans -out-dir")
	thematicCVE := flag.Bool("thematic-cve", false, "Compile la disquette thematique CVE (2021-2026)")
	thematicKernel := flag.Bool("thematic-kernel", false, "Compile la disquette thematique noyau Linux")
	thematicDPO := flag.Bool("thematic-dpo", false, "Compile la disquette thematique code vulnerable DPO")
	thematicFileless := flag.Bool("thematic-fileless", false, "Compile la disquette thematique evasion memoire")
	thematicFIM := flag.Bool("thematic-fim", false, "Compile la disquette thematique invariance FIM")
	oracleIngest := flag.String("oracle-ingest", "", "Ingere un fichier de journal reel du serveur pour generer des tranches .c2oracle")
	oracleBaseline := flag.Bool("oracle-baseline", false, "Compile et valide la baseline d'oracle individuel du serveur a partir de -out-dir")
	outDir := flag.String("out-dir", engine.DefaultVulnCorporaOutputDir, "Repertoire cible pour les disquettes produites")
	oracleCondense := flag.Bool("oracle-condense", false, "Condense les tranches .c2oracle de -out-dir en pyramides multi-echelles pyramid_<machine>_<horizon>.c2pyramid")
	oracleEval := flag.String("oracle-eval", "", "Evalue un fichier de trace contre la baseline et les pyramides de -out-dir, avec le catalogue -delta-catalog")
	evalVerbose := flag.Bool("eval-verbose", false, "Avec -oracle-eval, detaille aussi les evenements nominaux a toutes les echelles")
	deltaCompile := flag.String("delta-compile", "", "Compile une description JSON de regles de dispense en catalogue .c2delta ecrit dans -delta-catalog")
	deltaCatalog := flag.String("delta-catalog", "", "Catalogue .c2delta : produit par -delta-compile, lu par -oracle-eval")
	hmacKey := flag.String("hmac-key", "", "Cle d'authentification HMAC-SHA256 des .c2oracle, .c2delta et .c2pyramid : hex:<chiffres>, file:<chemin> ou phrase secrete (vide = SHA-256)")
	oracleVerifyChain := flag.Bool("oracle-verify-chain", false, "Verifie le chainage des sceaux (PrevDaySeal) des tranches .c2oracle de -out-dir sous -hmac-key")
	condenseScales := flag.String("condense-scales", "", "Horizons de -oracle-condense, separes par des virgules (defaut 24h,7d,30d,120d,365d)")
	condenseMinHits := flag.Uint("condense-min-hits", 1, "Observations minimales d'un prototype de -oracle-condense")
	condenseMaxClusters := flag.Int("condense-max-clusters", engine.CondenseDefaultIntermediateClusters, "Plafond des groupes intermediaires de -oracle-condense (maximum 16384)")
	wittgensteinFloppies := flag.Bool("wittgenstein-floppies", false, "Compile les 3 disquettes canoniques du tournoi Wittgenstein dans -out-dir")
	wittgensteinData := flag.String("wittgenstein-data", "data/wittgenstein", "Repertoire source des donnees reelles Wittgenstein")
	flag.Parse()

	if *oracleCondense || *oracleEval != "" || *deltaCompile != "" || *oracleIngest != "" || *oracleBaseline || *oracleVerifyChain {
		key, err := parseHMACKey(*hmacKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "c2forge: %v\n", err)
			os.Exit(2)
		}
		switch {
		case *deltaCompile != "":
			err = runDeltaCompile(os.Stdout, *deltaCompile, *deltaCatalog, *outDir, key)
		case *oracleCondense:
			var scales uint16
			if scales, err = parseScales(*condenseScales); err == nil {
				err = runOracleCondense(os.Stdout, *outDir, engine.CondenseConfig{
					MinHits:                 uint32(*condenseMinHits),
					MaxIntermediateClusters: *condenseMaxClusters,
					Scales:                  scales,
				}, key)
			}
		case *oracleEval != "":
			err = runOracleEval(os.Stdout, *oracleEval, *outDir, *deltaCatalog, key, *evalVerbose)
		case *oracleIngest != "":
			err = runOracleIngest(os.Stdout, *oracleIngest, *outDir, key)
		case *oracleVerifyChain:
			err = runOracleVerifyChain(os.Stdout, *outDir, key)
		default:
			err = runOracleBaseline(os.Stdout, *outDir, key)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "c2forge: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if *wittgensteinFloppies {
		if err := BuildWittgensteinFloppies(*wittgensteinData, *outDir); err != nil {
			fmt.Fprintf(os.Stderr, "c2forge: erreur forgerie disquettes wittgenstein: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("c2forge: les 3 disquettes canoniques ont été forgées avec succès dans %s\n", *outDir)
		return
	}

	if *thematicAll {
		results, err := engine.BuildThematicAllCodebooks(*outDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "c2forge: erreur compilation disquettes thematiques: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("c2forge — compilation des 5 disquettes thematiques achevee :")
		for _, r := range results {
			fmt.Printf("  • %-36s : %4d entrees | %7s | %s\n", r.Name, r.EntryCount, humanBytes(r.SizeBytes), r.Path)
		}
		return
	}

	if *thematicCVE {
		cb, err := engine.BuildThematicCVECorpus()
		if err != nil {
			fmt.Fprintf(os.Stderr, "c2forge: erreur CVE: %v\n", err)
			os.Exit(1)
		}
		if err := engine.SaveCodebook(*outFile, cb.Entries()); err != nil {
			fmt.Fprintf(os.Stderr, "c2forge: sauvegarde CVE: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("c2forge: %d entrees CVE compilees dans %s\n", cb.Len(), *outFile)
		return
	}

	if *thematicKernel {
		cb, err := engine.BuildThematicKernelCorpus("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "c2forge: erreur kernel: %v\n", err)
			os.Exit(1)
		}
		if err := engine.SaveCodebook(*outFile, cb.Entries()); err != nil {
			fmt.Fprintf(os.Stderr, "c2forge: sauvegarde kernel: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("c2forge: %d entrees kernel compilees dans %s\n", cb.Len(), *outFile)
		return
	}

	if *thematicDPO {
		cb, err := engine.BuildThematicDPOCorpus("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "c2forge: erreur DPO: %v\n", err)
			os.Exit(1)
		}
		if err := engine.SaveCodebook(*outFile, cb.Entries()); err != nil {
			fmt.Fprintf(os.Stderr, "c2forge: sauvegarde DPO: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("c2forge: %d entrees DPO compilees dans %s\n", cb.Len(), *outFile)
		return
	}

	if *thematicFileless {
		cb, err := engine.BuildThematicFilelessCorpus("")
		if err != nil {
			fmt.Fprintf(os.Stderr, "c2forge: erreur fileless: %v\n", err)
			os.Exit(1)
		}
		if err := engine.SaveCodebook(*outFile, cb.Entries()); err != nil {
			fmt.Fprintf(os.Stderr, "c2forge: sauvegarde fileless: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("c2forge: %d entrees fileless compilees dans %s\n", cb.Len(), *outFile)
		return
	}

	if *thematicFIM {
		cb, err := engine.BuildThematicFIMCorpus()
		if err != nil {
			fmt.Fprintf(os.Stderr, "c2forge: erreur FIM: %v\n", err)
			os.Exit(1)
		}
		if err := engine.SaveCodebook(*outFile, cb.Entries()); err != nil {
			fmt.Fprintf(os.Stderr, "c2forge: sauvegarde FIM: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("c2forge: %d entrees FIM compilees dans %s\n", cb.Len(), *outFile)
		return
	}

	if *crossStacks {
		if err := engine.SaveMotifsCroisesAllCodebook(*outFile); err != nil {
			fmt.Fprintf(os.Stderr, "c2forge: erreur lors de la compilation des motifs croises: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "c2forge: 75 motifs croises compiles dans %s\n", *outFile)
		return
	}

	if *flaws {
		if err := engine.SaveFlawsAllCodebook(*outFile); err != nil {
			fmt.Fprintf(os.Stderr, "c2forge: erreur lors de la compilation des failles de code: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "c2forge: 75 anti-patterns de failles de code compiles dans %s\n", *outFile)
		return
	}

	if *inDir == "" {
		fmt.Fprintln(os.Stderr, "c2forge: le drapeau -in est obligatoire (ou -thematic-all, -thematic-*, -cross-stacks, -flaws, -oracle-*, -delta-compile)")
		flag.Usage()
		os.Exit(2)
	}
	if *window < 1 || *window > engine.FeaturePayloadBytes {
		fmt.Fprintf(os.Stderr, "c2forge: -window doit tenir dans 1..%d\n", engine.FeaturePayloadBytes)
		os.Exit(2)
	}
	if *stride < 1 {
		fmt.Fprintln(os.Stderr, "c2forge: -stride doit être au moins 1")
		os.Exit(2)
	}
	if *workers < 1 {
		*workers = 1
	}

	root, err := filepath.Abs(*inDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "c2forge: chemin source invalide: %v\n", err)
		os.Exit(1)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		fmt.Fprintf(os.Stderr, "c2forge: %s n'est pas un répertoire lisible\n", root)
		os.Exit(1)
	}

	abs, rel, err := collectFiles(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "c2forge: parcours impossible: %v\n", err)
		os.Exit(1)
	}

	sub := uint16(*subsystem)
	base := uint32(*threatID)

	results := make([][]engine.CodebookEntry, len(abs))
	var (
		next     int64
		filesOK  int64
		filesErr int64
		bytesOK  int64
	)
	work := *workers
	if work > len(abs) {
		work = len(abs)
	}

	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < work; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g := newForger()
			for {
				i := int(atomic.AddInt64(&next, 1)) - 1
				if i >= len(abs) {
					return
				}
				id := base
				if id == 0 {
					id = fnv1a32(rel[i])
				}
				entries, read, ok := g.forge(abs[i], *window, *stride, id, sub)
				if !ok {
					atomic.AddInt64(&filesErr, 1)
					continue
				}
				results[i] = entries
				atomic.AddInt64(&filesOK, 1)
				atomic.AddInt64(&bytesOK, int64(read))
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	total := 0
	for _, r := range results {
		total += len(r)
	}
	entries := make([]engine.CodebookEntry, 0, total)
	for _, r := range results {
		entries = append(entries, r...)
	}

	if err := engine.SaveCodebook(*outFile, entries); err != nil {
		fmt.Fprintf(os.Stderr, "c2forge: écriture de %s impossible: %v\n", *outFile, err)
		os.Exit(1)
	}

	var written int64
	if st, err := os.Stat(*outFile); err == nil {
		written = st.Size()
	}
	secs := elapsed.Seconds()
	if secs <= 0 {
		secs = 1e-9
	}
	windowsPerSec := float64(total) / secs
	mbPerSec := float64(bytesOK) / (1 << 20) / secs

	fmt.Println("c2forge — indexation RaBitQ 512D hors-ligne")
	fmt.Printf("source              : %s\n", root)
	fmt.Printf("fichiers analysés   : %d\n", filesOK)
	if filesErr > 0 {
		fmt.Printf("fichiers illisibles : %d\n", filesErr)
	}
	fmt.Printf("fenêtres vectorisées: %d (fenêtre %d octets, pas %d)\n", total, *window, *stride)
	fmt.Printf("débit               : %.0f fenêtres/s | %.2f Mo/s\n", windowsPerSec, mbPerSec)
	fmt.Printf("fichier produit     : %s (%d entrées, %s)\n", *outFile, len(entries), humanBytes(written))
	fmt.Printf("durée               : %s\n", elapsed.Round(time.Millisecond))
}

// humanBytes rend une taille lisible en unités binaires.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d o", n)
	}
	value := float64(n)
	units := []string{"Kio", "Mio", "Gio", "Tio"}
	i := -1
	for value >= unit && i < len(units)-1 {
		value /= unit
		i++
	}
	return fmt.Sprintf("%.2f %s", value, units[i])
}
