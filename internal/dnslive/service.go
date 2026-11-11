package dnslive

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/dnslab"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

const (
	unregisteredSessionCap    = 32
	unregisteredIdleExpiry    = 60 * time.Second
	unregisteredSweepInterval = 10 * time.Second
)

var errUnregisteredCapped = errors.New("dnslive: plafond des sources non enregistrées atteint")

// Le struct Service est gelé : le compteur des datagrammes de sources non
// enregistrées jetés au-delà du plafond vit hors instance, indexé par
// l'adresse du service, et disparaît à la clôture.
var (
	unregisteredDropMu      sync.Mutex
	unregisteredDropCounter = make(map[*ServiceLive]*uint64)
)

// Le struct Service étant gelé, le signal d'arrêt du balayage vit lui aussi
// hors instance, indexé par l'adresse du service : l'entrée est posée au
// démarrage et retirée à la clôture.
var (
	sweeperStopMu      sync.Mutex
	sweeperStopSignals = make(map[*ServiceLive]chan struct{})
)

func (serviceLive *ServiceLive) armSweeperStop() chan struct{} {
	sweeperStopMu.Lock()
	defer sweeperStopMu.Unlock()
	stop := make(chan struct{})
	sweeperStopSignals[serviceLive] = stop
	return stop
}

func (serviceLive *ServiceLive) fireSweeperStop() {
	sweeperStopMu.Lock()
	stop, found := sweeperStopSignals[serviceLive]
	delete(sweeperStopSignals, serviceLive)
	sweeperStopMu.Unlock()
	if found {
		close(stop)
	}
}

func (serviceLive *ServiceLive) countUnregisteredDropLocked() {
	unregisteredDropMu.Lock()
	defer unregisteredDropMu.Unlock()
	counter, found := unregisteredDropCounter[serviceLive]
	if !found {
		counter = new(uint64)
		unregisteredDropCounter[serviceLive] = counter
	}
	*counter++
}

func (serviceLive *ServiceLive) forgetUnregisteredDropCounter() {
	unregisteredDropMu.Lock()
	delete(unregisteredDropCounter, serviceLive)
	unregisteredDropMu.Unlock()
}

// New valide la configuration et assemble un service sans ouvrir de socket.
func New(cfg Config) (*ServiceLive, error) {
	if strings.TrimSpace(cfg.UDPListen) == "" || strings.TrimSpace(cfg.HTTPListen) == "" ||
		strings.TrimSpace(cfg.EvidenceDir) == "" || strings.TrimSpace(cfg.DashboardToken) == "" {
		return nil, ErrLiveConfig
	}
	serviceLive := &ServiceLive{
		cfg:     cfg,
		events:  make([]liveEvent, 0, liveEventMemoryLimit),
		sources: make(map[netip.AddrPort]*liveSource),
		runs:    make(map[string]*liveRunHistory),
	}
	serviceLive.httpServer = &http.Server{
		Handler:           serviceLive.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	return serviceLive, nil
}

// Start ouvre les écoutes UDP et HTTP puis lance leurs deux boucles propres.
func (serviceLive *ServiceLive) Start() error {
	serviceLive.mu.Lock()
	defer serviceLive.mu.Unlock()
	if serviceLive.started {
		return ErrLiveStarted
	}
	if serviceLive.closing {
		return ErrLiveNotStart
	}
	if err := os.MkdirAll(serviceLive.cfg.EvidenceDir, 0o700); err != nil {
		return fmt.Errorf("dnslive: créer le répertoire de preuves: %w", err)
	}
	udpAddress, err := net.ResolveUDPAddr("udp", serviceLive.cfg.UDPListen)
	if err != nil {
		return fmt.Errorf("dnslive: résoudre l'écoute UDP: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		return fmt.Errorf("dnslive: écouter en UDP: %w", err)
	}
	httpListener, err := net.Listen("tcp", serviceLive.cfg.HTTPListen)
	if err != nil {
		return errors.Join(fmt.Errorf("dnslive: écouter en HTTP: %w", err), udpConn.Close())
	}
	serviceLive.udpConn = udpConn
	serviceLive.httpListener = httpListener
	serviceLive.started = true
	sweeperStop := serviceLive.armSweeperStop()
	serviceLive.workerWG.Go(func() { serviceLive.sweepUnregistered(sweeperStop) })
	serviceLive.workerWG.Go(serviceLive.serveUDP)
	serviceLive.workerWG.Go(serviceLive.serveHTTP)
	return nil
}

// sweepUnregistered balaye périodiquement, toutes les unregisteredSweepInterval,
// les sources non enregistrées afin de finaliser celles inactives au-delà de
// unregisteredIdleExpiry, indépendamment de l'arrivée de nouveaux datagrammes.
// Le balayage démarre avec le service et retourne dès le signal d'arrêt posé
// par Close : aucune goroutine n'est retenue après la clôture.
func (serviceLive *ServiceLive) sweepUnregistered(stop <-chan struct{}) {
	ticker := time.NewTicker(unregisteredSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			serviceLive.mu.Lock()
			if serviceLive.closing {
				serviceLive.mu.Unlock()
				return
			}
			serviceLive.expireUnregisteredLocked(now)
			serviceLive.mu.Unlock()
		case <-stop:
			return
		}
	}
}

// UDPAddr rend l'adresse UDP effective, y compris le port alloué avec :0.
func (serviceLive *ServiceLive) UDPAddr() string {
	serviceLive.mu.Lock()
	defer serviceLive.mu.Unlock()
	if serviceLive.udpConn == nil {
		return ""
	}
	return serviceLive.udpConn.LocalAddr().String()
}

// HTTPAddr rend l'adresse HTTP effective, y compris le port alloué avec :0.
func (serviceLive *ServiceLive) HTTPAddr() string {
	serviceLive.mu.Lock()
	defer serviceLive.mu.Unlock()
	if serviceLive.httpListener == nil {
		return ""
	}
	return serviceLive.httpListener.Addr().String()
}

func (serviceLive *ServiceLive) serveHTTP() {
	err := serviceLive.httpServer.Serve(serviceLive.httpListener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: serveur HTTP: %w", err))
	}
}

func (serviceLive *ServiceLive) serveUDP() {
	storage := make([]byte, 65535)
	for {
		read, sourceAddress, err := serviceLive.udpConn.ReadFromUDP(storage)
		if err != nil {
			serviceLive.mu.Lock()
			closing := serviceLive.closing
			serviceLive.mu.Unlock()
			if closing || errors.Is(err, net.ErrClosed) {
				return
			}
			serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: lecture UDP: %w", err))
			return
		}
		serviceLive.handleDatagram(storage[:read], sourceAddress)
	}
}

func (serviceLive *ServiceLive) recordAsynchronousError(err error) {
	serviceLive.mu.Lock()
	defer serviceLive.mu.Unlock()
	if serviceLive.closing && errors.Is(err, net.ErrClosed) {
		return
	}
	serviceLive.asynchronousErr = errors.Join(serviceLive.asynchronousErr, err)
}

func udpNetipAddress(address *net.UDPAddr) (netip.AddrPort, error) {
	ipAddress, ok := netip.AddrFromSlice(address.IP)
	if !ok {
		return netip.AddrPort{}, errors.New("dnslive: adresse UDP non convertible")
	}
	ipAddress = ipAddress.Unmap()
	if ipAddress.Is6() && address.Zone != "" {
		ipAddress = ipAddress.WithZone(address.Zone)
	}
	return netip.AddrPortFrom(ipAddress, uint16(address.Port)), nil
}

func addressAs16(address netip.Addr) [16]byte {
	return address.Unmap().As16()
}

func (serviceLive *ServiceLive) newSourceLocked(sourceAddress netip.AddrPort, runID, kind string, ordinal uint64) (*liveSource, error) {
	pipeline, err := c2blue55.NewPipeline(c2blue55.PipelineConfig{}, nil)
	if err != nil {
		return nil, fmt.Errorf("dnslive: créer le pipeline du run: %w", err)
	}
	zone, err := dnslab.NewZone("lab.pound2pound.fr", [4]byte{192, 0, 2, 55}, "c2blue-live", 60)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("dnslive: créer la zone de laboratoire: %w", err), pipeline.Close())
	}
	zone.NegativeSeed = 0x323032362d503230
	zone.AAAASeed = 0x323032362d503231
	switch kind {
	case "P20":
		zone.Negative = dnslab.NegativeSOAStego
	case "P21":
		zone.AAAA = dnslab.AAAAIIDStego
		zone.AnswerAAAA = [16]byte{0x20, 0x01, 0x0d, 0xb8}
	}
	stem := sourceEvidenceStem(runID, sourceAddress)
	if runID == "" {
		stem += "-" + strconv.FormatUint(ordinal, 10)
	}
	evidence, err := openEvidenceSession(serviceLive.cfg.EvidenceDir, runID, stem)
	if err != nil {
		return nil, errors.Join(err, pipeline.Close())
	}
	return &liveSource{
		key:        sourceAddress,
		runID:      runID,
		kind:       kind,
		registered: runID != "",
		pipeline:   pipeline,
		zone:       &zone,
		evidence:   evidence,
	}, nil
}

func (serviceLive *ServiceLive) sourceForDatagramLocked(sourceAddress netip.AddrPort, arrival time.Time) (*liveSource, error) {
	serviceLive.expireUnregisteredLocked(arrival)
	if source := serviceLive.sources[sourceAddress]; source != nil {
		source.evidence.lastActivityNS = arrival.UnixNano()
		return source, nil
	}
	if serviceLive.countUnregisteredLocked() >= unregisteredSessionCap {
		serviceLive.countUnregisteredDropLocked()
		return nil, errUnregisteredCapped
	}
	serviceLive.runOrdinal++
	source, err := serviceLive.newSourceLocked(sourceAddress, "", unregisteredKind, serviceLive.runOrdinal)
	if err != nil {
		return nil, err
	}
	serviceLive.sources[sourceAddress] = source
	return source, nil
}

func (serviceLive *ServiceLive) countUnregisteredLocked() int {
	nombreSourcesNonEnregistrees := 0
	for _, source := range serviceLive.sources {
		if !source.registered {
			nombreSourcesNonEnregistrees++
		}
	}
	return nombreSourcesNonEnregistrees
}

// expireUnregisteredLocked finalise la preuve des sessions de sources non
// enregistrées inactives depuis plus de unregisteredIdleExpiry. Les échecs
// propres à ces sources ne touchent jamais l'erreur globale de journal.
func (serviceLive *ServiceLive) expireUnregisteredLocked(arrival time.Time) {
	for key, source := range serviceLive.sources {
		if source.registered || source.finished {
			continue
		}
		if arrival.Sub(time.Unix(0, source.evidence.lastActivityNS)) < unregisteredIdleExpiry {
			continue
		}
		if err := errors.Join(source.pipeline.Close(), source.evidence.finish(context.Background())); err != nil {
			serviceLive.asynchronousErr = errors.Join(serviceLive.asynchronousErr,
				fmt.Errorf("dnslive: expirer la session d'une source non enregistrée: %w", err))
		}
		source.finished = true
		delete(serviceLive.sources, key)
	}
}

func (serviceLive *ServiceLive) handleDatagram(wirePacket []byte, sourceAddress *net.UDPAddr) {
	sourceKey, err := udpNetipAddress(sourceAddress)
	if err != nil {
		serviceLive.recordAsynchronousError(err)
		return
	}
	localKey, err := udpNetipAddress(serviceLive.udpConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		serviceLive.recordAsynchronousError(err)
		return
	}
	queryPacket := append([]byte(nil), wirePacket...)
	queryTime := time.Now().UnixNano()

	serviceLive.mu.Lock()
	if serviceLive.closing {
		serviceLive.mu.Unlock()
		return
	}
	if serviceLive.journalErr != nil {
		serviceLive.mu.Unlock()
		return
	}
	source, err := serviceLive.sourceForDatagramLocked(sourceKey, time.Unix(0, queryTime))
	if err != nil {
		if !errors.Is(err, errUnregisteredCapped) {
			serviceLive.asynchronousErr = errors.Join(serviceLive.asynchronousErr, err)
		}
		serviceLive.mu.Unlock()
		return
	}
	verdict, className, reasonCode, evaluationErr := source.pipeline.EvaluateDNSMessageWithReason(
		queryPacket,
		queryTime,
		addressAs16(sourceKey.Addr()),
		addressAs16(localKey.Addr()),
	)
	queryEvent := serviceLive.buildEventLocked(source, queryPacket, queryTime, queryDirection, sourceKey, localKey, verdict.Decision, className, reasonCode, evaluationErr)
	if err := serviceLive.journalEventLocked(source, queryEvent, queryPacket); err != nil {
		serviceLive.mu.Unlock()
		return
	}
	if evaluationErr != nil {
		serviceLive.mu.Unlock()
		return
	}

	responseStorage := make([]byte, 4096)
	var responseLength int
	if source.kind == "P20" || source.kind == "P21" {
		responseLength, _, err = dnslab.BuildResponse(queryPacket, source.zone, responseStorage)
	} else {
		responseLength, err = dnslab.BuildLabResponse17Motifs(queryPacket, source.kind, responseStorage)
	}
	if err != nil || responseLength <= 0 {
		if err == nil {
			err = errors.New("dnslive: répondeur sans réponse pour une question valide")
		}
		serviceLive.asynchronousErr = errors.Join(serviceLive.asynchronousErr, fmt.Errorf("dnslive: construire la réponse: %w", err))
		serviceLive.mu.Unlock()
		return
	}
	responsePacket := append([]byte(nil), responseStorage[:responseLength]...)
	responseTime := time.Now().UnixNano()
	responseVerdict, responseClass, responseReason, responseEvaluationErr := source.pipeline.EvaluateDNSMessageWithReason(
		responsePacket,
		responseTime,
		addressAs16(localKey.Addr()),
		addressAs16(sourceKey.Addr()),
	)
	switch source.kind {
	case "P20":
		if fired, _ := source.soaNegative.ObserveResponse(responseTime, addressAs16(sourceKey.Addr()), responsePacket); fired {
			responseClass = "P20"
			responseReason = engine.ReasonP20SOANegDownlink
			responseVerdict.Decision = c2blue55.DecisionEscalateSLM
		}
	case "P21":
		if fired, _ := source.aaaaIID.ObserveResponse(responseTime, addressAs16(sourceKey.Addr()), responsePacket); fired {
			responseClass = "P21"
			responseReason = engine.ReasonP21AAAAIIDDownlink
			responseVerdict.Decision = c2blue55.DecisionEscalateSLM
		}
	}
	responseEvent := serviceLive.buildEventLocked(source, responsePacket, responseTime, responseDirection, localKey, sourceKey, responseVerdict.Decision, responseClass, responseReason, responseEvaluationErr)
	if err := serviceLive.journalEventLocked(source, responseEvent, responsePacket); err != nil {
		serviceLive.mu.Unlock()
		return
	}
	if err := source.evidence.flush(); err != nil {
		_ = serviceLive.noteJournalFailureLocked(source, fmt.Errorf("dnslive: journal obligatoire: %w", err))
		serviceLive.mu.Unlock()
		return
	}
	serviceLive.mu.Unlock()

	written, err := serviceLive.udpConn.WriteToUDP(responsePacket, sourceAddress)
	if err != nil {
		serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: écriture UDP: %w", err))
		return
	}
	if written != len(responsePacket) {
		serviceLive.recordAsynchronousError(fmt.Errorf("dnslive: écriture UDP courte: %w", io.ErrShortWrite))
	}
}

func (serviceLive *ServiceLive) buildEventLocked(source *liveSource, wirePacket []byte, timestampNS int64, direction string, sourceAddress, destinationAddress netip.AddrPort, decision uint8, className, reasonCode string, evaluationErr error) liveEvent {
	digest := sha256.Sum256(wirePacket)
	event := liveEvent{
		Sequence:     serviceLive.sequence + 1,
		RunID:        source.runID,
		Kind:         source.kind,
		TimestampNS:  timestampNS,
		Direction:    direction,
		SrcIP:        sourceAddress.Addr().String(),
		SrcPort:      sourceAddress.Port(),
		DstIP:        destinationAddress.Addr().String(),
		DstPort:      destinationAddress.Port(),
		Decision:     decision,
		Class:        className,
		ReasonCode:   reasonCode,
		PacketSHA256: hex.EncodeToString(digest[:]),
		PacketBase64: base64.StdEncoding.EncodeToString(wirePacket),
	}
	if len(wirePacket) >= 2 {
		event.TxID = uint16(wirePacket[0])<<8 | uint16(wirePacket[1])
	}
	if evaluationErr != nil {
		event.ParseError = evaluationErr.Error()
		return event
	}
	var message c2blue55.DNSMessage
	if err := c2blue55.ParseDNSMessage(wirePacket, &message); err != nil {
		event.Class = "PARSE_ERR"
		event.ReasonCode = c2blue55.ReasonDNSParseError
		event.Decision = c2blue55.DecisionEscalateSLM
		event.ParseError = err.Error()
		return event
	}
	event.QName = string(message.QName[:message.QNameLen])
	event.QType = message.QType
	event.SubdomainLen = int(message.SubdomainLen)
	event.LabelCount = int(message.LabelCount)
	event.MaxLabelLen = int(message.MaxLabelLen)
	event.AnswerCount = int(message.AnswerCount)
	for index := 0; index < int(message.AnswerCount); index++ {
		event.RDataBytes += int(message.Answers[index].RDataLen)
	}
	return event
}

func (serviceLive *ServiceLive) journalEventLocked(source *liveSource, event liveEvent, wirePacket []byte) error {
	line, err := source.evidence.append(event, wirePacket)
	if err == nil && serviceLive.cfg.EventWriter != nil {
		err = writeEntirely(serviceLive.cfg.EventWriter, line)
	}
	if err != nil {
		return serviceLive.noteJournalFailureLocked(source, fmt.Errorf("dnslive: journal obligatoire: %w", err))
	}
	serviceLive.sequence = event.Sequence
	if len(serviceLive.events) == liveEventMemoryLimit {
		copy(serviceLive.events, serviceLive.events[1:])
		clear(serviceLive.events[len(serviceLive.events)-1:])
		serviceLive.events = serviceLive.events[:len(serviceLive.events)-1]
		serviceLive.eventsEvicted++
	}
	serviceLive.events = append(serviceLive.events, event)
	return nil
}

// noteJournalFailureLocked positionne l'erreur globale de journal pour un
// run enregistré uniquement. Un échec propre à une source non enregistrée
// est rapporté hors journal : il ne doit pas supprimer les réponses des
// runs enregistrés. L'appelant détient service.mu.
func (serviceLive *ServiceLive) noteJournalFailureLocked(source *liveSource, err error) error {
	if source.registered {
		serviceLive.journalErr = errors.Join(serviceLive.journalErr, err)
		return serviceLive.journalErr
	}
	serviceLive.asynchronousErr = errors.Join(serviceLive.asynchronousErr, err)
	return err
}

// Close arrête les écoutes, attend les boucles, synchronise puis ferme toutes
// les preuves et tous les pipelines. Toute panne de journal y est rapportée.
func (serviceLive *ServiceLive) Close(ctx context.Context) error {
	serviceLive.closeOnce.Do(func() {
		serviceLive.mu.Lock()
		serviceLive.closing = true
		if !serviceLive.started {
			serviceLive.closeErr = ErrLiveNotStart
			serviceLive.mu.Unlock()
			serviceLive.forgetUnregisteredDropCounter()
			return
		}
		udpConn := serviceLive.udpConn
		httpServer := serviceLive.httpServer
		serviceLive.mu.Unlock()
		serviceLive.fireSweeperStop()

		var lifecycleErr error
		if err := udpConn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			lifecycleErr = errors.Join(lifecycleErr, fmt.Errorf("dnslive: fermer UDP: %w", err))
		}
		if err := httpServer.Shutdown(ctx); err != nil {
			lifecycleErr = errors.Join(lifecycleErr, fmt.Errorf("dnslive: arrêt HTTP: %w", err))
			if closeErr := httpServer.Close(); closeErr != nil && !errors.Is(closeErr, http.ErrServerClosed) {
				lifecycleErr = errors.Join(lifecycleErr, fmt.Errorf("dnslive: forcer l'arrêt HTTP: %w", closeErr))
			}
		}
		serviceLive.workerWG.Wait()
		serviceLive.forgetUnregisteredDropCounter()

		serviceLive.mu.Lock()
		defer serviceLive.mu.Unlock()
		uniqueSources := make(map[*liveSource]struct{}, len(serviceLive.sources)+len(serviceLive.runs))
		for _, source := range serviceLive.sources {
			uniqueSources[source] = struct{}{}
		}
		for _, history := range serviceLive.runs {
			uniqueSources[history.source] = struct{}{}
		}
		for source := range uniqueSources {
			if !source.finished {
				lifecycleErr = errors.Join(lifecycleErr, source.pipeline.Close(), source.evidence.finish(ctx))
				source.finished = true
			}
		}
		serviceLive.closeErr = errors.Join(serviceLive.journalErr, serviceLive.asynchronousErr, lifecycleErr)
	})
	return serviceLive.closeErr
}

// finishSourceLocked clôt un run et détache son couple IP:port. L'appelant
// détient service.mu ; les paquets ultérieurs deviennent explicitement inconnus.
func (serviceLive *ServiceLive) finishSourceLocked(ctx context.Context, source *liveSource) error {
	if source.finished {
		return nil
	}
	err := errors.Join(source.pipeline.Close(), source.evidence.finish(ctx))
	if err != nil {
		return err
	}
	source.finished = true
	delete(serviceLive.sources, source.key)
	if source.registered {
		serviceLive.runs[source.runID].public.Finished = true
	}
	return nil
}
