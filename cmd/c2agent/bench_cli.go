package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	c2 "github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/pkg/ecritureatomique"
	"golang.org/x/sys/unix"
)

type benchCLIOptions struct {
	mode          string
	interfaceName string
	pcapPath      string
	outRoot       string
	filter        string
	healthAddress string
	duration      time.Duration
	maxBytes      int64
	dnsPorts      []uint16
}

type benchCaptureCounters struct {
	Captured *uint64 `json:"captured"`
	Received *uint64 `json:"received_by_filter"`
	Dropped  *uint64 `json:"dropped_by_kernel"`
}

type benchCampaignManifest struct {
	Emitter          string               `json:"emitter"`
	Generator        string               `json:"generator"`
	Mode             string               `json:"mode"`
	Host             string               `json:"host"`
	Arguments        []string             `json:"arguments"`
	CaptureArguments []string             `json:"capture_arguments"`
	HealthAddress    string               `json:"health_address,omitempty"`
	StartedAt        string               `json:"started_at"`
	FinishedAt       string               `json:"finished_at"`
	Executable       string               `json:"executable"`
	ExecutableSHA256 string               `json:"executable_sha256"`
	Build            *debug.BuildInfo     `json:"build"`
	MaxBytes         int64                `json:"max_bytes"`
	DNSPorts         []uint16             `json:"dns_ports"`
	CopiedBytes      int64                `json:"copied_bytes"`
	PCAPStats        c2.BenchPCAPStats    `json:"pcap_stats"`
	Observations     uint64               `json:"observations"`
	States           map[string]uint64    `json:"states"`
	CaptureCounters  benchCaptureCounters `json:"capture_counters"`
	CaptureExitCode  *int                 `json:"capture_exit_code"`
	StopReason       string               `json:"stop_reason"`
	PieceSHA256      map[string]string    `json:"piece_sha256"`
	Errors           []string             `json:"errors"`
	Complete         bool                 `json:"complete"`

	// Ce fichier n'a d'autorité qu'avec un code de sortie 0 et des empreintes concordantes.
	AdmissionRequiresExitCodeZero bool `json:"admission_requires_exit_code_zero"`
}

// RunBenchCLI capture avec tcpdump ou rejoue un fichier local par le même moteur.
// Chaque exécution possède son répertoire et conserve ses pièces en cas d'échec.
func RunBenchCLI(ctx context.Context, mode string, args []string, stdout, stderr io.Writer) int {
	if ctx == nil || stdout == nil || stderr == nil {
		return 2
	}
	options, err := benchParseOptions(mode, args)
	if err != nil {
		return benchCLIError(stderr, err, 2)
	}
	if err := ctx.Err(); err != nil {
		return benchCLIError(stderr, err, 1)
	}
	prefix := "replay-"
	if mode == "observe" {
		prefix = "capture-"
	}
	directory, err := os.MkdirTemp(options.outRoot, prefix)
	if err != nil {
		return benchCLIError(stderr, err, 1)
	}
	manifest := benchCampaignManifest{
		Emitter: "generator", Generator: "cmd/c2agent/bench_cli.go:RunBenchCLI",
		Mode: mode, Arguments: append([]string{mode}, args...),
		StartedAt: time.Now().UTC().Format(time.RFC3339Nano),
		MaxBytes:  options.maxBytes, DNSPorts: options.dnsPorts,
		States:      map[string]uint64{"observed": 0, "non_target": 0, "unsupported": 0, "malformed": 0},
		PieceSHA256: make(map[string]string, 3), Errors: make([]string, 0),

		AdmissionRequiresExitCodeZero: true,
	}
	remember := func(operationErr error) {
		if operationErr != nil {
			manifest.Errors = append(manifest.Errors, operationErr.Error())
		}
	}
	remember(os.Chmod(directory, 0o700))
	_, err = fmt.Fprintln(stdout, directory)
	remember(err)
	manifest.Host, err = os.Hostname()
	remember(err)
	manifest.Executable, err = os.Executable()
	remember(err)
	if err == nil {
		manifest.ExecutableSHA256, err = benchHashFile(manifest.Executable)
		remember(err)
	}
	if build, available := debug.ReadBuildInfo(); available {
		manifest.Build = build
	}
	remember(benchRunCampaign(ctx, options, directory, &manifest))
	for _, piece := range []string{"capture.pcap", "observations.jsonl", "capture.stderr"} {
		digest, hashErr := benchHashFile(filepath.Join(directory, piece))
		remember(hashErr)
		if hashErr == nil {
			manifest.PieceSHA256[piece] = digest
		}
	}
	manifest.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if len(manifest.Errors) != 0 {
		_, err = fmt.Fprintln(stderr, strings.Join(manifest.Errors, "\n"))
		remember(err)
	}
	manifest.Complete = len(manifest.Errors) == 0
	// Une annulation arrête l'opération, mais ne doit pas effacer son dossier
	// d'échec. La publication dispose de son propre contexte de clôture borné.
	publication, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	content, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return benchCLIError(stderr, err, 1)
	}
	manifestPath := filepath.Join(directory, "manifest.json")
	if err := ecritureatomique.Ecrire(publication, manifestPath, append(content, '\n')); err != nil {
		cancel()
		remember(err)
		manifest.Complete = false
		// Ecrire peut rendre une erreur après renommage. Une seule publication
		// du manifeste d'échec est tentée par le même écrivain, jamais un autre.
		failureContent, encodeErr := json.MarshalIndent(manifest, "", "  ")
		if encodeErr != nil {
			return benchCLIError(stderr, errors.Join(err, encodeErr, benchRemoveFailedManifest(manifestPath)), 1)
		}
		failurePublication, failureCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer failureCancel()
		failureErr := ecritureatomique.Ecrire(failurePublication, manifestPath, append(failureContent, '\n'))
		if failureErr != nil {
			failureErr = errors.Join(failureErr, benchRemoveFailedManifest(manifestPath))
		}
		return benchCLIError(stderr, errors.Join(err, failureErr), 1)
	}
	if !manifest.Complete {
		return 1
	}
	return 0
}

// Le chemin appartient au répertoire nouvellement réservé par cette exécution.
// Si le retrait échoue, le code 1 reste l'autorité même si un fichier subsiste.
func benchRemoveFailedManifest(manifestPath string) error {
	if err := os.Remove(manifestPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("retirer le manifeste après échec de publication: %w", err)
	}
	return nil
}

func benchCLIError(destination io.Writer, operationErr error, code int) int {
	if _, err := fmt.Fprintln(destination, operationErr); err != nil {
		return 1
	}
	return code
}

func benchParseOptions(mode string, args []string) (benchCLIOptions, error) {
	options := benchCLIOptions{mode: mode}
	if mode != "observe" && mode != "replay" {
		return options, fmt.Errorf("mode de banc inconnu: %q", mode)
	}
	flags := flag.NewFlagSet("c2agent "+mode, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&options.outRoot, "out-root", "", "Racine existante des pièces")
	flags.Int64Var(&options.maxBytes, "max-bytes", 268435456, "Borne stricte des octets PCAP")
	portsText := flags.String("dns-ports", "53,5335", "Ports DNS explicitement observés")
	if mode == "observe" {
		flags.StringVar(&options.interfaceName, "interface", "", "Interface de capture")
		flags.DurationVar(&options.duration, "duration", 0, "Durée obligatoire, de 1s à 1h")
		flags.StringVar(&options.filter, "filter", "", "Filtre BPF explicite")
		flags.StringVar(&options.healthAddress, "healthz", "", "Adresse HTTP de santé, en boucle locale uniquement")
	} else {
		flags.StringVar(&options.pcapPath, "pcap", "", "Fichier PCAP local")
	}
	if err := flags.Parse(args); err != nil {
		return options, err
	}
	if flags.NArg() != 0 || options.outRoot == "" || options.maxBytes < 24 || options.maxBytes > 1<<30 {
		return options, fmt.Errorf("arguments surnuméraires, racine absente ou max-bytes hors [24, 1073741824]")
	}
	if mode == "observe" && (options.interfaceName == "" || options.duration < time.Second || options.duration > time.Hour) {
		return options, fmt.Errorf("interface requise et durée obligatoire dans [1s, 1h]")
	}
	if mode == "replay" && options.pcapPath == "" {
		return options, fmt.Errorf("fichier --pcap requis")
	}
	if options.healthAddress != "" {
		if err := benchValidateHealthAddress(options.healthAddress); err != nil {
			return options, err
		}
	}
	portStrings := strings.Split(*portsText, ",")
	options.dnsPorts = make([]uint16, 0, len(portStrings))
	filterPorts := make([]string, 0, len(portStrings))
	for _, text := range portStrings {
		port, err := strconv.ParseUint(text, 10, 16)
		if err != nil || port == 0 {
			return options, fmt.Errorf("port DNS invalide: %q", text)
		}
		options.dnsPorts = append(options.dnsPorts, uint16(port))
		filterPorts = append(filterPorts, "port "+strconv.FormatUint(port, 10))
	}
	if mode == "observe" && options.filter == "" {
		options.filter = "((udp or tcp) and (" + strings.Join(filterPorts, " or ") + ")) or icmp"
	}
	root, err := filepath.Abs(options.outRoot)
	if err != nil {
		return options, err
	}
	stat, err := os.Stat(root)
	if err != nil {
		return options, err
	}
	if !stat.IsDir() {
		return options, fmt.Errorf("out-root n'est pas un répertoire existant")
	}
	options.outRoot = root
	return options, nil
}

func benchCreatePiece(directory, name string) (*os.File, error) {
	piece, err := os.OpenFile(filepath.Join(directory, name), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := piece.Chmod(0o600); err != nil {
		return nil, errors.Join(err, piece.Close())
	}
	return piece, nil
}

func benchRunCampaign(ctx context.Context, options benchCLIOptions, directory string, manifest *benchCampaignManifest) (operationErr error) {
	pieces := make([]*os.File, 0, 3)
	defer func() {
		for _, piece := range pieces {
			operationErr = errors.Join(operationErr, piece.Sync(), piece.Close())
		}
	}()
	for _, name := range []string{"capture.pcap", "observations.jsonl", "capture.stderr"} {
		piece, err := benchCreatePiece(directory, name)
		if err != nil {
			return err
		}
		pieces = append(pieces, piece)
	}
	observer, err := c2.NewBenchObserver(options.dnsPorts)
	if err != nil {
		return err
	}
	defer func() { operationErr = errors.Join(operationErr, observer.Close()) }()
	encoder := json.NewEncoder(pieces[1])
	visit := func(packet c2.BenchPacket) error {
		observation, err := observer.ObservePacket(packet)
		if err != nil {
			return err
		}
		if err := encoder.Encode(observation); err != nil {
			return err
		}
		manifest.Observations++
		manifest.States[observation.Status]++
		return nil
	}
	if options.mode == "observe" {
		operationErr = benchObserveLive(ctx, options, pieces[0], pieces[2], manifest, visit)
		return operationErr
	}
	source, err := os.OpenFile(options.pcapPath, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { operationErr = errors.Join(operationErr, source.Close()) }()
	stat, err := source.Stat()
	if err != nil {
		return err
	}
	if !stat.Mode().IsRegular() {
		return fmt.Errorf("le rejeu exige un fichier local régulier")
	}
	return benchReadCapture(&benchContextReader{ctx: ctx, source: source}, options.maxBytes, pieces[0], manifest, visit)
}

type benchContextReader struct {
	ctx    context.Context
	source io.Reader
}

func (reader *benchContextReader) Read(destination []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.source.Read(destination)
}

func benchReadCapture(source io.Reader, maxBytes int64, capture io.Writer, manifest *benchCampaignManifest, visit func(c2.BenchPacket) error) error {
	scoped, hasHealth := source.(*benchHealthReader)
	if hasHealth {
		defer scoped.health.NotReady()
	}
	limited := &io.LimitedReader{R: source, N: maxBytes}
	pieceWriter := &benchPieceWriter{destination: capture}
	copied := io.TeeReader(limited, pieceWriter)
	stats, parseErr := c2.ReadBenchPCAP(copied, visit)
	manifest.PCAPStats = stats
	if hasHealth && parseErr != nil {
		scoped.health.NotReady()
	}
	// Une erreur de format ne supprime pas les octets suivants de la pièce.
	// La vidange reste soumise à la même limite et au même lecteur d'annulation.
	_, drainErr := io.Copy(io.Discard, copied)
	manifest.CopiedBytes = pieceWriter.written
	var limitErr error
	if limited.N == 0 {
		limitErr = fmt.Errorf("limite de taille atteinte: %d octets, y compris si EOF exact", maxBytes)
	}
	return errors.Join(parseErr, drainErr, limitErr)
}

type benchPieceWriter struct {
	destination io.Writer
	written     int64
}

func (writer *benchPieceWriter) Write(content []byte) (int, error) {
	n, err := writer.destination.Write(content)
	writer.written += int64(n)
	if n != len(content) && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

type benchCaptureExit struct {
	err        error
	exitCode   *int
	stopReason string
}

func benchObserveLive(ctx context.Context, options benchCLIOptions, capture, captureStderr *os.File, manifest *benchCampaignManifest, visit func(c2.BenchPacket) error) (operationErr error) {
	var health *benchHealthController
	if options.healthAddress != "" {
		var err error
		health, err = newBenchHealth(ctx, options.healthAddress)
		if err != nil {
			return err
		}
		manifest.HealthAddress = health.Addr()
		ctx = context.WithValue(ctx, benchHealthScope{}, health)
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			operationErr = errors.Join(operationErr, health.Close(cleanup))
		}()
	}
	command := benchCaptureCommand(options.interfaceName, options.filter)
	manifest.CaptureArguments = append([]string(nil), command.Args...)
	command.Stderr = captureStderr
	pipeReader, pipeWriter, err := os.Pipe()
	if err != nil {
		return err
	}
	command.Stdout = pipeWriter
	if err := command.Start(); err != nil {
		return errors.Join(err, pipeReader.Close(), pipeWriter.Close())
	}
	writerCloseErr := pipeWriter.Close()
	readDone := make(chan struct{})
	finished := make(chan benchCaptureExit, 1)
	go func() { finished <- benchWaitCapture(ctx, command, options.duration, readDone, pipeReader) }()
	// Le superviseur traite l'annulation et ferme le tube après un délai borné.
	// Le lecteur poursuit entre-temps la vidange et l'observation des trames.
	var source io.Reader = pipeReader
	var preparationErr error
	if health != nil {
		scoped := newBenchHealthReader(pipeReader, health)
		_, preparationErr = benchReadyCaptureReader(scoped, health)
		// Le même tampon est rendu à la copie, même après un refus d'en-tête.
		source = scoped
	}
	readErr := errors.Join(preparationErr, benchReadCapture(source, options.maxBytes, capture, manifest, visit))
	close(readDone)
	termination := <-finished
	manifest.CaptureExitCode = termination.exitCode
	manifest.StopReason = termination.stopReason
	if _, err := captureStderr.Seek(0, io.SeekStart); err != nil {
		return errors.Join(writerCloseErr, readErr, termination.err, err)
	}
	counters, counterErr := benchReadCounters(captureStderr)
	manifest.CaptureCounters = counters
	var incompleteErr error
	if counters.Captured == nil || counters.Received == nil || counters.Dropped == nil {
		incompleteErr = fmt.Errorf("statistiques finales tcpdump inconnues")
	} else if *counters.Dropped != 0 {
		incompleteErr = fmt.Errorf("pertes noyau tcpdump: %d", *counters.Dropped)
	}
	return errors.Join(writerCloseErr, readErr, termination.err, counterErr, incompleteErr)
}

func benchSignalGroup(command *exec.Cmd, signal syscall.Signal) error {
	err := syscall.Kill(-command.Process.Pid, signal)
	if errors.Is(err, syscall.ESRCH) {
		return nil // Le statut de Wait reste l'autorité sur la fin du processus.
	}
	return err
}

func benchWaitCapture(ctx context.Context, command *exec.Cmd, duration time.Duration, readDone <-chan struct{}, pipeReader *os.File) benchCaptureExit {
	termination := benchCaptureExit{}
	observed := make(chan error, 1)
	go func() {
		var status unix.Siginfo
		for {
			err := unix.Waitid(unix.P_PID, command.Process.Pid, &status, unix.WEXITED|unix.WNOWAIT, nil)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			observed <- err
			return
		}
	}()
	timer := time.NewTimer(duration)
	defer timer.Stop()
	var observationErr error
	observationComplete := false
	select {
	case observationErr = <-observed:
		observationComplete = true
		termination.stopReason = "process_exit"
		termination.err = fmt.Errorf("tcpdump terminé avant la durée demandée")
	case <-ctx.Done():
		termination.stopReason = "context_cancelled"
		termination.err = ctx.Err()
	case <-timer.C:
		termination.stopReason = "duration"
	case <-readDone:
		termination.stopReason = "reader_end"
		termination.err = fmt.Errorf("flux de capture arrêté avant la durée demandée")
	}
	if health, present := ctx.Value(benchHealthScope{}).(*benchHealthController); present {
		health.NotReady()
	}
	if !observationComplete {
		termination.err = errors.Join(termination.err, benchSignalGroup(command, syscall.SIGINT))
		for _, stage := range []struct {
			delay  time.Duration
			signal syscall.Signal
		}{{2 * time.Second, syscall.SIGQUIT}, {500 * time.Millisecond, syscall.SIGKILL}, {2 * time.Second, syscall.SIGKILL}} {
			deadline := time.NewTimer(stage.delay)
			select {
			case observationErr = <-observed:
				observationComplete = true
			case <-deadline.C:
				termination.err = errors.Join(termination.err, fmt.Errorf("délai d'arrêt tcpdump dépassé; signal %s", stage.signal), benchSignalGroup(command, stage.signal))
			}
			deadline.Stop()
			if observationComplete {
				break
			}
		}
	}
	// WNOWAIT ne récolte pas le chef : son PID reste réservé jusqu'au nettoyage
	// de son groupe, même si readDone est déjà fermé et que le chef est terminé.
	// Une erreur de waitid laisse l'identité incertaine et interdit de la signaler.
	if observationErr == nil {
		termination.err = errors.Join(termination.err, benchSignalGroup(command, syscall.SIGKILL))
	}
	drain := time.NewTimer(2 * time.Second)
	defer drain.Stop()
	select {
	case <-readDone:
	case <-drain.C:
		termination.err = errors.Join(termination.err, fmt.Errorf("délai de vidange tcpdump dépassé"))
		if observationErr == nil {
			termination.err = errors.Join(termination.err, benchSignalGroup(command, syscall.SIGKILL))
		}
	}
	termination.err = errors.Join(termination.err, pipeReader.Close())
	if !observationComplete {
		select {
		case observationErr = <-observed:
			observationComplete = true
		default:
		}
	}
	if observationErr != nil {
		termination.err = errors.Join(termination.err, fmt.Errorf("observer la fin du chef sans récolte: %w", observationErr))
		return termination
	}
	if !observationComplete {
		termination.err = errors.Join(termination.err, fmt.Errorf("fin du chef non observée après SIGKILL; récolte non engagée"))
		return termination
	}
	// Tous les signaux et la clôture du tube précèdent Cmd.Wait. Aucun signal
	// numérique n'est envoyé après le début de la récolte définitive du chef.
	waited := make(chan error, 1)
	go func() { waited <- command.Wait() }()
	reap := time.NewTimer(2 * time.Second)
	defer reap.Stop()
	select {
	case waitErr := <-waited:
		termination.err = errors.Join(termination.err, waitErr)
		if command.ProcessState != nil {
			exitCode := command.ProcessState.ExitCode()
			termination.exitCode = &exitCode
		} else {
			termination.err = errors.Join(termination.err, fmt.Errorf("statut du chef inconnu après récolte"))
		}
	case <-reap.C:
		termination.err = errors.Join(termination.err, fmt.Errorf("délai de récolte du chef dépassé"))
	}
	return termination
}

func benchReadCounters(source *os.File) (benchCaptureCounters, error) {
	var counters benchCaptureCounters
	stat, err := source.Stat()
	if err != nil {
		return counters, err
	}
	if stat.Size() == int64(^uint64(0)>>1) {
		return counters, fmt.Errorf("journal tcpdump trop grand")
	}
	scanner := bufio.NewScanner(io.LimitReader(source, stat.Size()+1))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 || (fields[1] != "packet" && fields[1] != "packets") {
			continue
		}
		var destination **uint64
		switch strings.Join(fields[2:], " ") {
		case "captured":
			destination = &counters.Captured
		case "received by filter":
			destination = &counters.Received
		case "dropped by kernel":
			destination = &counters.Dropped
		default:
			continue
		}
		quantity, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			return counters, fmt.Errorf("compteur tcpdump invalide: %w", err)
		}
		*destination = &quantity
	}
	return counters, scanner.Err()
}

func benchHashFile(path string) (digest string, operationErr error) {
	piece, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { operationErr = errors.Join(operationErr, piece.Close()) }()
	stat, err := piece.Stat()
	if err != nil {
		return "", err
	}
	if !stat.Mode().IsRegular() || stat.Size() == int64(^uint64(0)>>1) {
		return "", fmt.Errorf("empreinte exigeant un fichier régulier de taille bornée: %s", path)
	}
	hash := sha256.New()
	n, err := io.Copy(hash, io.LimitReader(piece, stat.Size()+1))
	if err != nil {
		return "", err
	}
	if n != stat.Size() {
		return "", fmt.Errorf("fichier modifié pendant le calcul d'empreinte: %s", path)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
