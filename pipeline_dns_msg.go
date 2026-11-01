package c2blue55

import (
	"math"
	"sync"

	"github.com/hazyhaar/c2blue55/internal/engine"
)

const (
	pipeMsgThrP4 = 0.40

	// ReasonDNSParseError signale un échec fail-closed du décodage filaire DNS.
	ReasonDNSParseError = "REASON_DNS_PARSE_ERROR"
)

type pipeMsgState struct {
	mu       sync.Mutex
	episodes engine.DNSEpisodeStore
	rollup   engine.DNSClientRollup
	stream18 engine.StreamingDNS18State
}

func fnv64Msg(b []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

func labelEntropyNorm(b []byte) float32 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]uint16
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		pr := float64(c) / n
		h -= pr * math.Log2(pr)
	}
	norm := float32(h / 5.0)
	if norm > 1 {
		norm = 1
	}
	return norm
}

// EvaluateDNSMessageWithReason décode et évalue un message DNS (QR=0/1) sur les 18 classes en 0 B/op.
// Le client est la source d'une requête, ou la destination renseignée d'une réponse.
// Les états DNS sont détenus par ce pipeline et sérialisés par son verrou local,
// sous le verrou du cycle de vie. Les agrégats internes des détecteurs sont conservés.
func (p *Pipeline) EvaluateDNSMessageWithReason(wirePacket []byte, nowNs int64, srcIP, dstIP [16]byte) (EvaluationResult, string, string, error) {
	var verdict EvaluationResult

	p.lifeMu.RLock()
	defer p.lifeMu.RUnlock()
	if p.closed {
		return verdict, "BENIGN", engine.ReasonNone, ErrPipelineClosed
	}

	var msg DNSMessage
	if err := ParseDNSMessage(wirePacket, &msg); err != nil {
		verdict.Decision = DecisionEscalateSLM
		return verdict, "PARSE_ERR", ReasonDNSParseError, err
	}

	sub := msg.Subdomain[:msg.SubdomainLen]
	parent := msg.ParentDomain[:msg.ParentDomainLen]

	clientIP := srcIP
	if msg.IsResponse && dstIP != ([16]byte{}) {
		clientIP = dstIP
	}

	st := &p.dnsMessages
	st.mu.Lock()
	defer st.mu.Unlock()

	var rdata []byte
	if msg.AnswerCount > 0 {
		rdata = msg.Answers[0].RData[:msg.Answers[0].RDataLen]
	}

	obs := engine.DNSExchangeObs{
		TimestampNs: nowNs,
		SrcIP:       clientIP,
		TxID:        msg.ID,
		IsResponse:  msg.IsResponse,
		RCode:       msg.RCode,
		QType:       msg.QType,
		ParentApex:  parent,
		Subdomain:   sub,
		AnswerRData: rdata,
		AnswerCount: msg.AnswerCount,
		HasNonLDH:   msg.HasNonLDH,
	}

	snap, _ := st.episodes.ObserveExchange(obs, nil)
	cls, reason, consumed := st.stream18.ObserveAndClassify18(
		wirePacket, nowNs, clientIP, sub, parent, msg.QType, snap, engine.EpisodeP3Features{},
	)

	var p4 engine.ClientP4Features
	if !consumed {
		subEntropy := labelEntropyNorm(sub)
		apexHash := fnv64Msg(parent)
		p4 = st.rollup.ObserveParentApex(clientIP, apexHash, subEntropy, nowNs)
		if p4.CompositeP4Score > pipeMsgThrP4 {
			cls = "P4"
			reason = engine.ReasonP4MultiParentSharding
		}
	}

	if reason != engine.ReasonNone {
		verdict.Decision = DecisionEscalateSLM
	} else {
		verdict.Decision = DecisionFastPass
	}
	return verdict, cls, reason, nil
}

// EvaluateDNSMessage décode un message DNS bidirectionnel (QR=0/1) et renvoie la décision du pipeline en 0 B/op.
func (p *Pipeline) EvaluateDNSMessage(raw []byte, nowNs int64, srcIP, dstIP [16]byte) (EvaluationResult, error) {
	verdict, _, _, err := p.EvaluateDNSMessageWithReason(raw, nowNs, srcIP, dstIP)
	return verdict, err
}
