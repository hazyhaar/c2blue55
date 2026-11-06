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
	"time"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/dnslab"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

// New valide la configuration et assemble un service sans ouvrir de socket.
func New(cfg Config) (*Service, error) {
	if strings.TrimSpace(cfg.UDPListen) == "" || strings.TrimSpace(cfg.HTTPListen) == "" ||
		strings.TrimSpace(cfg.EvidenceDir) == "" || strings.TrimSpace(cfg.DashboardToken) == "" {
		return nil, ErrLiveConfig
	}
	service := &Service{
		cfg:     cfg,
		events:  make([]liveEvent, 0, liveEventMemoryLimit),
		sources: make(map[netip.AddrPort]*liveSource),
		runs:    make(map[string]*liveRunHistory),
	}
	service.httpServer = &http.Server{
		Handler:           service.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	return service, nil
}

// Start ouvre les écoutes UDP et HTTP puis lance leurs deux boucles propres.
func (service *Service) Start() error {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.started {
		return ErrLiveStarted
	}
	if service.closing {
		return ErrLiveNotStart
	}
	if err := os.MkdirAll(service.cfg.EvidenceDir, 0o700); err != nil {
		return fmt.Errorf("dnslive: créer le répertoire de preuves: %w", err)
	}
	udpAddress, err := net.ResolveUDPAddr("udp", service.cfg.UDPListen)
	if err != nil {
		return fmt.Errorf("dnslive: résoudre l'écoute UDP: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddress)
	if err != nil {
		return fmt.Errorf("dnslive: écouter en UDP: %w", err)
	}
	httpListener, err := net.Listen("tcp", service.cfg.HTTPListen)
	if err != nil {
		return errors.Join(fmt.Errorf("dnslive: écouter en HTTP: %w", err), udpConn.Close())
	}
	service.udpConn = udpConn
	service.httpListener = httpListener
	service.started = true
	service.workerWG.Go(service.serveUDP)
	service.workerWG.Go(service.serveHTTP)
	return nil
}

// UDPAddr rend l'adresse UDP effective, y compris le port alloué avec :0.
func (service *Service) UDPAddr() string {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.udpConn == nil {
		return ""
	}
	return service.udpConn.LocalAddr().String()
}

// HTTPAddr rend l'adresse HTTP effective, y compris le port alloué avec :0.
func (service *Service) HTTPAddr() string {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.httpListener == nil {
		return ""
	}
	return service.httpListener.Addr().String()
}

func (service *Service) serveHTTP() {
	err := service.httpServer.Serve(service.httpListener)
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		service.recordAsynchronousError(fmt.Errorf("dnslive: serveur HTTP: %w", err))
	}
}

func (service *Service) serveUDP() {
	storage := make([]byte, 65535)
	for {
		read, sourceAddress, err := service.udpConn.ReadFromUDP(storage)
		if err != nil {
			service.mu.Lock()
			closing := service.closing
			service.mu.Unlock()
			if closing || errors.Is(err, net.ErrClosed) {
				return
			}
			service.recordAsynchronousError(fmt.Errorf("dnslive: lecture UDP: %w", err))
			return
		}
		service.handleDatagram(storage[:read], sourceAddress)
	}
}

func (service *Service) recordAsynchronousError(err error) {
	service.mu.Lock()
	defer service.mu.Unlock()
	if service.closing && errors.Is(err, net.ErrClosed) {
		return
	}
	service.asynchronousErr = errors.Join(service.asynchronousErr, err)
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

func (service *Service) newSourceLocked(sourceAddress netip.AddrPort, runID, kind string, ordinal uint64) (*liveSource, error) {
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
	evidence, err := openEvidenceSession(service.cfg.EvidenceDir, runID, stem)
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

func (service *Service) sourceForDatagramLocked(sourceAddress netip.AddrPort) (*liveSource, error) {
	if source := service.sources[sourceAddress]; source != nil {
		return source, nil
	}
	service.runOrdinal++
	source, err := service.newSourceLocked(sourceAddress, "", unregisteredKind, service.runOrdinal)
	if err != nil {
		return nil, err
	}
	service.sources[sourceAddress] = source
	return source, nil
}

func (service *Service) handleDatagram(wirePacket []byte, sourceAddress *net.UDPAddr) {
	sourceKey, err := udpNetipAddress(sourceAddress)
	if err != nil {
		service.recordAsynchronousError(err)
		return
	}
	localKey, err := udpNetipAddress(service.udpConn.LocalAddr().(*net.UDPAddr))
	if err != nil {
		service.recordAsynchronousError(err)
		return
	}
	queryPacket := append([]byte(nil), wirePacket...)
	queryTime := time.Now().UnixNano()

	service.mu.Lock()
	if service.closing {
		service.mu.Unlock()
		return
	}
	if service.journalErr != nil {
		service.mu.Unlock()
		return
	}
	source, err := service.sourceForDatagramLocked(sourceKey)
	if err != nil {
		service.journalErr = errors.Join(service.journalErr, err)
		service.mu.Unlock()
		return
	}
	verdict, className, reasonCode, evaluationErr := source.pipeline.EvaluateDNSMessageWithReason(
		queryPacket,
		queryTime,
		addressAs16(sourceKey.Addr()),
		addressAs16(localKey.Addr()),
	)
	queryEvent := service.buildEventLocked(source, queryPacket, queryTime, queryDirection, sourceKey, localKey, verdict.Decision, className, reasonCode, evaluationErr)
	if err := service.journalEventLocked(source, queryEvent, queryPacket); err != nil {
		service.mu.Unlock()
		return
	}
	if evaluationErr != nil {
		service.mu.Unlock()
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
		service.asynchronousErr = errors.Join(service.asynchronousErr, fmt.Errorf("dnslive: construire la réponse: %w", err))
		service.mu.Unlock()
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
	responseEvent := service.buildEventLocked(source, responsePacket, responseTime, responseDirection, localKey, sourceKey, responseVerdict.Decision, responseClass, responseReason, responseEvaluationErr)
	if err := service.journalEventLocked(source, responseEvent, responsePacket); err != nil {
		service.mu.Unlock()
		return
	}
	service.mu.Unlock()

	written, err := service.udpConn.WriteToUDP(responsePacket, sourceAddress)
	if err != nil {
		service.recordAsynchronousError(fmt.Errorf("dnslive: écriture UDP: %w", err))
		return
	}
	if written != len(responsePacket) {
		service.recordAsynchronousError(fmt.Errorf("dnslive: écriture UDP courte: %w", io.ErrShortWrite))
	}
}

func (service *Service) buildEventLocked(source *liveSource, wirePacket []byte, timestampNS int64, direction string, sourceAddress, destinationAddress netip.AddrPort, decision uint8, className, reasonCode string, evaluationErr error) liveEvent {
	digest := sha256.Sum256(wirePacket)
	event := liveEvent{
		Sequence:     service.sequence + 1,
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

func (service *Service) journalEventLocked(source *liveSource, event liveEvent, wirePacket []byte) error {
	line, err := source.evidence.append(event, wirePacket)
	if err == nil && service.cfg.EventWriter != nil {
		err = writeEntirely(service.cfg.EventWriter, line)
	}
	if err != nil {
		service.journalErr = errors.Join(service.journalErr, fmt.Errorf("dnslive: journal obligatoire: %w", err))
		return service.journalErr
	}
	service.sequence = event.Sequence
	if len(service.events) == liveEventMemoryLimit {
		copy(service.events, service.events[1:])
		clear(service.events[len(service.events)-1:])
		service.events = service.events[:len(service.events)-1]
		service.eventsEvicted++
	}
	service.events = append(service.events, event)
	return nil
}

// Close arrête les écoutes, attend les boucles, synchronise puis ferme toutes
// les preuves et tous les pipelines. Toute panne de journal y est rapportée.
func (service *Service) Close(ctx context.Context) error {
	service.closeOnce.Do(func() {
		service.mu.Lock()
		if !service.started {
			service.closeErr = ErrLiveNotStart
			service.mu.Unlock()
			return
		}
		service.closing = true
		udpConn := service.udpConn
		httpServer := service.httpServer
		service.mu.Unlock()

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
		service.workerWG.Wait()

		service.mu.Lock()
		defer service.mu.Unlock()
		uniqueSources := make(map[*liveSource]struct{}, len(service.sources)+len(service.runs))
		for _, source := range service.sources {
			uniqueSources[source] = struct{}{}
		}
		for _, history := range service.runs {
			uniqueSources[history.source] = struct{}{}
		}
		for source := range uniqueSources {
			if !source.finished {
				lifecycleErr = errors.Join(lifecycleErr, source.pipeline.Close(), source.evidence.finish(ctx))
				source.finished = true
			}
		}
		service.closeErr = errors.Join(service.journalErr, service.asynchronousErr, lifecycleErr)
	})
	return service.closeErr
}

// finishSourceLocked clôt un run et détache son couple IP:port. L'appelant
// détient service.mu ; les paquets ultérieurs deviennent explicitement inconnus.
func (service *Service) finishSourceLocked(ctx context.Context, source *liveSource) error {
	if source.finished {
		return nil
	}
	err := errors.Join(source.pipeline.Close(), source.evidence.finish(ctx))
	if err != nil {
		return err
	}
	source.finished = true
	delete(service.sources, source.key)
	if source.registered {
		service.runs[source.runID].public.Finished = true
	}
	return nil
}
