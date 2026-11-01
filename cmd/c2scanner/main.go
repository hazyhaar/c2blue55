// Command c2scanner est l'auditeur souverain hors-ligne de c2blue55 : il charge
// un codebook RaBitQ 512D précalculé (.c2book), parcourt une arborescence de
// code ou de journaux, découpe chaque fichier en fenêtres de 96 octets,
// alimente un tampon annulaire SPSC (c2blue55.Channel, 1024 slots), projette
// chaque fenêtre sur un vecteur de 512 dimensions, le quantifie sur un bit et
// cherche le plus proche voisin du codebook par distance de Hamming. Une
// distance inférieure ou égale au seuil déclenche une alerte chemin/ligne/
// identifiant de menace.
//
// Le binaire n'applique aucune interception : il observe et rapporte.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

// windowBytes est la largeur d'une fenêtre d'inspection. Elle coïncide avec la
// charge utile d'un Probe_event_t afin qu'aucun octet utile ne soit tronqué par
// l'extracteur de caractéristiques.
const windowBytes = engine.FeaturePayloadBytes

// bitcodeWords est le nombre de mots de 64 bits d'un bitcode de 512 bits.
const bitcodeWords = engine.EmbeddingDim / 64

// maxCodebookBytes borne la taille du fichier .c2book chargé en mémoire. Une
// entrée sérialisée occupe 72 octets ; la borne de 14 Mio autorise environ
// 200 000 signatures tout en maintenant l'empreinte résidente sous la contrainte de 16 Mio.
const maxCodebookBytes = 14 << 20

// maxFileBytes borne la taille maximale lue d'un fichier régulier pour se
// prémunir contre les saturations mémoire ou les fichiers atypiques géants.
const maxFileBytes = 16 << 20

// streamBufferSize est la dimension fixe du tampon de lecture circulaire par
// travailleur. Sa largeur (64 Kio + windowBytes) permet de glisser en continu
// sans aucune réallocation sur le tas.
const streamBufferSize = (64 << 10) + windowBytes

// alert est l'enregistrement émis lorsqu'une fenêtre tombe sous le seuil. Les
// étiquettes JSON sont stables pour les pipelines SIEM et CI.
type alert struct {
	Path      string `json:"path"`
	Line      uint64 `json:"line"`
	ThreatID  uint32 `json:"threat_id"`
	Distance  int    `json:"distance"`
	Severity  uint16 `json:"severity"`
	Subsystem uint16 `json:"subsystem"`
}

// scanConfig regroupe les paramètres d'un scan, ce qui rend la fonction runScan
// directement testable sans passer par la ligne de commande.
type scanConfig struct {
	bookPath   string
	target     string
	threshold  int
	stride     int
	minEntropy float64
	normalize  bool
	jsonOut    bool
	cores      int
	out        io.Writer
}

// scanMetrics consigne les compteurs agrégés du scan.
type scanMetrics struct {
	files    uint64
	windows  uint64
	bytes    uint64
	alerts   uint64
	dropped  uint64
	elapsed  time.Duration
	entries  int
	rateMB   float64
	rateWin  float64
	coreUsed int
}

// fileRegistry associe un index de fichier, transporté par le champ Ts_ns de
// l'événement, à son chemin réel. L'enregistrement précède toute écriture dans
// le canal, si bien qu'une alerte ne peut référencer un chemin absent.
type fileRegistry struct {
	mu    sync.RWMutex
	paths []string
}

func (r *fileRegistry) add(path string) uint64 {
	r.mu.Lock()
	idx := uint64(len(r.paths))
	r.paths = append(r.paths, path)
	r.mu.Unlock()
	return idx
}

func (r *fileRegistry) get(idx uint64) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if idx < uint64(len(r.paths)) {
		return r.paths[idx]
	}
	return ""
}

// alertSink sérialise les alertes. Pour garantir un déterminisme strict et une
// reproductibilité bit-à-bit indépendante de l'ordonnancement concurrent des
// travailleurs, les alertes sont accumulées puis triées de façon stable par
// chemin, ligne, identifiant de menace et distance avant émission.
type alertSink struct {
	mu     sync.Mutex
	w      *bufio.Writer
	json   bool
	alerts []alert
}

func (s *alertSink) emit(a alert) {
	s.mu.Lock()
	s.alerts = append(s.alerts, a)
	s.mu.Unlock()
}

func (s *alertSink) flushSorted() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sort.Slice(s.alerts, func(i, j int) bool {
		if s.alerts[i].Path != s.alerts[j].Path {
			return s.alerts[i].Path < s.alerts[j].Path
		}
		if s.alerts[i].Line != s.alerts[j].Line {
			return s.alerts[i].Line < s.alerts[j].Line
		}
		if s.alerts[i].ThreatID != s.alerts[j].ThreatID {
			return s.alerts[i].ThreatID < s.alerts[j].ThreatID
		}
		return s.alerts[i].Distance < s.alerts[j].Distance
	})
	if s.w == nil {
		return nil
	}
	for _, a := range s.alerts {
		if s.json {
			line, err := json.Marshal(a)
			if err != nil {
				return fmt.Errorf("encodage JSON alerte: %w", err)
			}
			if _, err := s.w.Write(line); err != nil {
				return fmt.Errorf("écriture alerte JSON: %w", err)
			}
			if err := s.w.WriteByte('\n'); err != nil {
				return fmt.Errorf("écriture saut de ligne JSON: %w", err)
			}
		} else {
			if _, err := fmt.Fprintf(s.w, "ALERT %s:%d threat=%d distance=%d severity=%d subsystem=%d\n",
				a.Path, a.Line, a.ThreatID, a.Distance, a.Severity, a.Subsystem); err != nil {
				return fmt.Errorf("écriture alerte texte: %w", err)
			}
		}
	}
	if err := s.w.Flush(); err != nil {
		return fmt.Errorf("vidage alertes: %w", err)
	}
	return nil
}

func main() {
	bookPath := flag.String("book", "", "Fichier .c2book à charger (obligatoire en mode scan)")
	target := flag.String("target", "", "Répertoire de codebase ou de journaux à auditer (obligatoire)")
	threshold := flag.Int("threshold", 50, "Distance de Hamming maximale déclenchant une alerte (0..512)")
	stride := flag.Int("stride", 32, "Pas d'avancement de la fenêtre en octets (1..96, défaut 32, 0 ou 96 = blocs contigus)")
	normalize := flag.Bool("normalize", false, "Active le pré-filtre syntaxique NormalizeCodeWindow (élagage des commentaires et espaces). Avertissement : peut masquer des charges utiles dissimulées dans les commentaires.")
	jsonOut := flag.Bool("json", false, "Sortie d'alertes JSON ligne par ligne (SIEM/CI)")
	cores := flag.Int("cores", 2, "Nombre de cœurs CPU alloués")
	minEntropy := flag.Float64("min-entropy", 0.0, "Seuil minimal d'entropie de Shannon pour élaguer bannières et boilerplate (0 = désactivé)")
	buildBook := flag.String("build-book", "", "Enrôle la cible dans un .c2book puis quitte (chemin de sortie)")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "c2scanner: -target est obligatoire")
		flag.Usage()
		os.Exit(2)
	}
	if *buildBook == "" && *bookPath == "" {
		fmt.Fprintln(os.Stderr, "c2scanner: -book est obligatoire en mode scan")
		flag.Usage()
		os.Exit(2)
	}

	if *buildBook != "" {
		n, err := runBuild(*target, *buildBook)
		if err != nil {
			fmt.Fprintln(os.Stderr, "c2scanner: "+err.Error())
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "c2scanner: %d entrées enrôlées dans %s\n", n, *buildBook)
		return
	}

	cfg := scanConfig{
		bookPath:   *bookPath,
		target:     *target,
		threshold:  *threshold,
		stride:     *stride,
		minEntropy: *minEntropy,
		normalize:  *normalize,
		jsonOut:    *jsonOut,
		cores:      *cores,
		out:        os.Stdout,
	}
	metrics, err := runScan(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "c2scanner: "+err.Error())
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr,
		"c2scanner: files=%d windows=%d bytes=%d elapsed=%.3fs throughput=%.2fMiB/s windows_rate=%.0f/s alerts=%d threshold=%d entries=%d dropped=%d cores=%d\n",
		metrics.files, metrics.windows, metrics.bytes, metrics.elapsed.Seconds(),
		metrics.rateMB, metrics.rateWin, metrics.alerts, *threshold, metrics.entries,
		metrics.dropped, metrics.coreUsed)
}

// resolveCores borne le nombre de cœurs demandés à l'intervalle utile.
func resolveCores(cores int) int {
	if cores < 1 {
		cores = 1
	}
	if maxc := runtime.NumCPU(); cores > maxc {
		cores = maxc
	}
	return cores
}

// runScan charge le codebook, lance les travailleurs SPSC puis parcourt la
// cible. La sortie d'alertes est sérialisée par un unique alertSink.
func runScan(cfg scanConfig) (scanMetrics, error) {
	var m scanMetrics

	threshold := min(max(cfg.threshold, 0), engine.EmbeddingDim)

	if info, serr := os.Stat(cfg.bookPath); serr == nil && info.Size() > maxCodebookBytes {
		return m, fmt.Errorf("codebook trop volumineux: %d octets (maximum %d)", info.Size(), maxCodebookBytes)
	}
	book, err := engine.LoadCodebook(cfg.bookPath)
	if err != nil {
		return m, fmt.Errorf("chargement du codebook: %w", err)
	}
	m.entries = book.Len()

	root, err := os.Stat(cfg.target)
	if err != nil {
		return m, fmt.Errorf("cible inaccessible: %w", err)
	}
	if !root.IsDir() {
		return m, fmt.Errorf("la cible doit être un répertoire: %s", cfg.target)
	}

	cores := resolveCores(cfg.cores)
	m.coreUsed = cores
	prev := runtime.GOMAXPROCS(cores)
	defer runtime.GOMAXPROCS(prev)

	var sink *bufio.Writer
	if cfg.out != nil {
		sink = bufio.NewWriterSize(cfg.out, 1<<16)
	}
	emitter := &alertSink{w: sink, json: cfg.jsonOut}
	registry := &fileRegistry{}

	var (
		bytesCnt   atomic.Uint64
		windowsCnt atomic.Uint64
		filesCnt   atomic.Uint64
		alertsCnt  atomic.Uint64
	)

	paths := make(chan string, 256)
	workers := make([]*worker, cores)
	for i := range workers {
		w := &worker{
			book:       book,
			threshold:  threshold,
			stride:     cfg.stride,
			minEntropy: cfg.minEntropy,
			normalize:  cfg.normalize,
			reg:        registry,
			sink:       emitter,
			ch:         c2blue55.NewChannel(),
		}
		w.bytes = &bytesCnt
		w.windows = &windowsCnt
		w.files = &filesCnt
		w.alerts = &alertsCnt
		workers[i] = w
	}

	var consumers sync.WaitGroup
	for _, w := range workers {
		consumers.Add(1)
		go func(w *worker) {
			defer consumers.Done()
			w.consume()
		}(w)
	}

	var producers sync.WaitGroup
	for _, w := range workers {
		producers.Add(1)
		go func(w *worker) {
			defer producers.Done()
			w.produce(paths)
		}(w)
	}

	absBook, _ := filepath.Abs(cfg.bookPath)
	start := time.Now()
	walkErr := filepath.WalkDir(cfg.target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if abs, aerr := filepath.Abs(path); aerr == nil && abs == absBook {
			return nil
		}
		paths <- path
		return nil
	})
	close(paths)
	producers.Wait()
	consumers.Wait()
	m.elapsed = time.Since(start)

	m.bytes = bytesCnt.Load()
	m.windows = windowsCnt.Load()
	m.files = filesCnt.Load()
	m.alerts = alertsCnt.Load()
	var workerErr error
	for _, w := range workers {
		m.dropped += w.ch.Drops()
		if wErr := w.firstError(); wErr != nil && workerErr == nil {
			workerErr = wErr
		}
	}
	if m.elapsed > 0 {
		m.rateMB = float64(m.bytes) / (1 << 20) / m.elapsed.Seconds()
		m.rateWin = float64(m.windows) / m.elapsed.Seconds()
	}
	flushErr := emitter.flushSorted()
	if walkErr != nil {
		return m, fmt.Errorf("parcours de la cible: %w", walkErr)
	}
	if workerErr != nil {
		return m, workerErr
	}
	if flushErr != nil {
		return m, flushErr
	}
	return m, nil
}

// worker détient un tampon annulaire SPSC et les paramètres d'inspection. Un
// travailleur compte exactement un producteur et un consommateur.
type worker struct {
	book       *engine.Codebook
	threshold  int
	stride     int
	minEntropy float64
	normalize  bool
	reg        *fileRegistry
	sink       *alertSink
	ch         *c2blue55.Channel
	streamBuf  [streamBufferSize]byte
	normBuf    [windowBytes]byte

	bytes   *atomic.Uint64
	windows *atomic.Uint64
	files   *atomic.Uint64
	alerts  *atomic.Uint64

	errMu   sync.Mutex
	scanErr error
	done    atomic.Bool
}

func (w *worker) recordError(err error) {
	if err == nil {
		return
	}
	w.errMu.Lock()
	if w.scanErr == nil {
		w.scanErr = err
	}
	w.errMu.Unlock()
}

func (w *worker) firstError() error {
	w.errMu.Lock()
	defer w.errMu.Unlock()
	return w.scanErr
}

// produce lit séquentiellement les fichiers affectés par la file partagée et
// écrit chaque fenêtre dans son canal. Un rejet pour saturation est réessayé :
// un audit ne sacrifie aucune fenêtre au débit.
func (w *worker) produce(paths <-chan string) {
	var ev c2blue55.Event
	for path := range paths {
		w.scanFile(path, &ev)
	}
	w.done.Store(true)
}

// scanFile découpe un fichier en fenêtres de windowBytes avançant par pas de stride.
// La lecture s'effectue en continu sur un tampon fixe streamBuf sans allocation
// sur le tas et reste strictement bornée par maxFileBytes. Le numéro de ligne
// au début de chaque fenêtre est transporté par le champ Tid.
func (w *worker) scanFile(path string, ev *c2blue55.Event) {
	f, err := os.Open(path)
	if err != nil {
		w.recordError(fmt.Errorf("ouverture %s: %w", path, err))
		return
	}
	defer f.Close()

	st, statErr := f.Stat()
	if statErr != nil {
		w.recordError(fmt.Errorf("stat %s: %w", path, statErr))
		return
	}
	if st.Size() > maxFileBytes {
		w.recordError(fmt.Errorf("fichier %s hors borne (%d octets > maximum %d octets)", path, st.Size(), maxFileBytes))
		return
	}

	idx := w.reg.add(path)
	w.files.Add(1)

	stride := w.stride
	if stride <= 0 || stride > windowBytes {
		stride = windowBytes
	}

	buf := w.streamBuf[:]
	validLen := 0
	totalRead := uint64(0)
	eofReached := false
	line := uint32(1)
	lastLineProcessed := 0

	for {
		for !eofReached && validLen < len(buf) {
			if totalRead >= maxFileBytes {
				var extraByte [1]byte
				extraN, extraErr := f.Read(extraByte[:])
				if extraN > 0 {
					w.bytes.Add(totalRead)
					w.recordError(fmt.Errorf("fichier %s dépasse la limite de %d octets", path, maxFileBytes))
					return
				}
				if extraErr != nil && extraErr != io.EOF {
					w.bytes.Add(totalRead)
					w.recordError(fmt.Errorf("lecture %s: %w", path, extraErr))
					return
				}
				eofReached = true
				break
			}
			toRead := len(buf) - validLen
			if remain := maxFileBytes - totalRead; uint64(toRead) > remain {
				toRead = int(remain)
			}
			n, rerr := f.Read(buf[validLen : validLen+toRead])
			if n > 0 {
				validLen += n
				totalRead += uint64(n)
			}
			if rerr == io.EOF {
				eofReached = true
				break
			}
			if rerr != nil {
				w.bytes.Add(totalRead)
				w.recordError(fmt.Errorf("lecture %s: %w", path, rerr))
				return
			}
		}

		if validLen == 0 {
			w.bytes.Add(totalRead)
			return
		}

		cursor := 0
		for {
			if cursor+windowBytes <= validLen {
				for i := lastLineProcessed; i < cursor; i++ {
					if buf[i] == '\n' {
						line++
					}
				}
				lastLineProcessed = cursor

				*ev = c2blue55.Event{
					Ts_ns:     idx,
					Tid:       line,
					Subsystem: c2blue55.SubFile,
					Action:    c2blue55.ActRead,
				}
				copy(ev.Payload[:], buf[cursor:cursor+windowBytes])
				w.windows.Add(1)
				w.write(ev)

				if cursor+windowBytes == validLen && eofReached {
					w.bytes.Add(totalRead)
					return
				}

				cursor += stride
				continue
			}

			if !eofReached {
				for i := lastLineProcessed; i < cursor; i++ {
					if buf[i] == '\n' {
						line++
					}
				}
				rem := validLen - cursor
				if rem > 0 {
					copy(buf[0:rem], buf[cursor:validLen])
				}
				validLen = rem
				lastLineProcessed = 0
				break
			}

			if cursor < validLen {
				for i := lastLineProcessed; i < cursor; i++ {
					if buf[i] == '\n' {
						line++
					}
				}
				winLen := validLen - cursor
				*ev = c2blue55.Event{
					Ts_ns:     idx,
					Tid:       line,
					Subsystem: c2blue55.SubFile,
					Action:    c2blue55.ActRead,
				}
				copy(ev.Payload[:winLen], buf[cursor:validLen])
				for i := winLen; i < windowBytes; i++ {
					ev.Payload[i] = 0
				}
				w.windows.Add(1)
				w.write(ev)
			}

			w.bytes.Add(totalRead)
			return
		}
	}
}

// write insère une fenêtre en réessayant tant que le canal est saturé.
func (w *worker) write(ev *c2blue55.Event) {
	for {
		switch w.ch.Write(ev) {
		case 0, -1:
			return
		default:
			runtime.Gosched()
		}
	}
}

// consume vide le canal et inspecte chaque fenêtre. Le vidage final garantit
// qu'aucune écriture antérieure au drapeau de fin n'est perdue.
func (w *worker) consume() {
	var ev c2blue55.Event
	var vec [engine.EmbeddingDim]float32
	var code [bitcodeWords]uint64
	for {
		if w.ch.Read(&ev) == 1 {
			w.inspect(&ev, &vec, &code)
			continue
		}
		if !w.done.Load() {
			runtime.Gosched()
			continue
		}
		if w.ch.Read(&ev) == 1 {
			w.inspect(&ev, &vec, &code)
			continue
		}
		return
	}
}

// inspect projette la fenêtre, la quantifie et cherche le plus proche voisin.
// Si normalize est activé, un pré-filtre syntaxique élague les commentaires et
// compacte les espaces sans allocation.
// Sur correspondance, une alerte est émise avec le chemin résolu et la ligne de
// début de fenêtre.
func (w *worker) inspect(ev *c2blue55.Event, vec *[engine.EmbeddingDim]float32, code *[bitcodeWords]uint64) {
	payload := ev.Payload[:]
	if w.normalize {
		n := engine.NormalizeCodeWindow(payload, w.normBuf[:])
		for i := n; i < windowBytes; i++ {
			w.normBuf[i] = 0
		}
		payload = w.normBuf[:]
	}
	if w.minEntropy > 0 && engine.IsBoilerplateOrLowEntropy(payload, w.minEntropy) {
		return
	}
	if w.normalize {
		copy(ev.Payload[:], payload)
	}
	if !engine.ExtractTo(ev, vec[:]) {
		return
	}
	engine.Quantize512(vec[:], code)
	match, dist, found := w.book.SearchNearest(code, w.threshold)
	if !found {
		return
	}
	w.alerts.Add(1)
	w.sink.emit(alert{
		Path:      w.reg.get(ev.Ts_ns),
		Line:      uint64(ev.Tid),
		ThreatID:  match.ThreatID,
		Distance:  dist,
		Severity:  match.Severity,
		Subsystem: match.Subsystem,
	})
}

// runBuild parcourt la cible et enrôle chaque fenêtre comme entrée de codebook.
// L'enrôlement emploie exactement la chaîne d'inspection du scan, ce qui
// garantit qu'une cible réenrôlée se retrouve à distance nulle.
func runBuild(target, outPath string) (int, error) {
	root, err := os.Stat(target)
	if err != nil {
		return 0, fmt.Errorf("cible inaccessible: %w", err)
	}
	if !root.IsDir() {
		return 0, fmt.Errorf("la cible doit être un répertoire: %s", target)
	}

	var entries []engine.CodebookEntry
	var ev c2blue55.Event
	var vec [engine.EmbeddingDim]float32
	var code [bitcodeWords]uint64

	walkErr := filepath.WalkDir(target, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		f, oerr := os.Open(path)
		if oerr != nil {
			return nil
		}
		br := bufio.NewReaderSize(f, 1<<16)
		var buf [windowBytes]byte
		for {
			n, rerr := io.ReadFull(br, buf[:])
			if n == 0 && rerr != nil {
				break
			}
			for i := n; i < windowBytes; i++ {
				buf[i] = 0
			}
			ev = c2blue55.Event{Subsystem: c2blue55.SubFile, Action: c2blue55.ActRead}
			copy(ev.Payload[:], buf[:])
			if engine.ExtractTo(&ev, vec[:]) {
				engine.Quantize512(vec[:], &code)
				entries = append(entries, engine.CodebookEntry{
					Bitcode:   code,
					ThreatID:  uint32(len(entries) + 1),
					Subsystem: c2blue55.SubFile,
					Severity:  engine.SeverityMedium,
				})
			}
			if rerr != nil {
				break
			}
		}
		f.Close()
		return nil
	})
	if walkErr != nil {
		return 0, fmt.Errorf("parcours de la cible: %w", walkErr)
	}
	if err := engine.SaveCodebook(outPath, entries); err != nil {
		return 0, fmt.Errorf("écriture du codebook: %w", err)
	}
	return len(entries), nil
}
