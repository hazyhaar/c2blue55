package c2blue55

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"sync"

	"github.com/hazyhaar/c2blue55/internal/engine"
)

// BenchObservation décrit chaque trame, indépendamment d'une vérité terrain.
type BenchObservation struct {
	TimestampNs  uint64   `json:"timestamp_ns"`
	PacketSHA256 string   `json:"packet_sha256"`
	Protocol     string   `json:"protocol"`
	SrcIP        string   `json:"src_ip"`
	DstIP        string   `json:"dst_ip"`
	SrcPort      uint16   `json:"src_port"`
	DstPort      uint16   `json:"dst_port"`
	Status       string   `json:"status"`
	Reasons      []string `json:"reasons"`
}

// BenchObserver possède ses suivis SOA, AAAA et ICMP ainsi qu'un Pipeline privé,
// qui détient ses états DNS et leur verrou sans registre partagé entre instances.
// Les bornes et agrégats internes des détecteurs d'une instance sont conservés.
type BenchObserver struct {
	mu       sync.Mutex
	pipeline *Pipeline
	dnsPorts []uint16
	soa      engine.SOANegativeTracker
	aaaa     engine.AAAAIIDTracker
	icmp     engine.ICMPEchoParityTracker
	closed   bool
}

// NewBenchObserver construit un moteur sans journal ni arbitre externe.
func NewBenchObserver(dnsPorts []uint16) (*BenchObserver, error) {
	if len(dnsPorts) == 0 || slices.Contains(dnsPorts, 0) {
		return nil, fmt.Errorf("bench observer: ports DNS non nuls requis")
	}
	pipeline, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		return nil, err
	}
	return &BenchObserver{pipeline: pipeline, dnsPorts: slices.Clone(dnsPorts)}, nil
}

// Close attend l'observation en cours sur cette instance et ferme son Pipeline privé.
// Les appels suivants à ObservePacket sont refusés ; la fermeture est idempotente.
// Les tableaux d'état restent détenus par les instances jusqu'à leur libération mémoire.
func (observer *BenchObserver) Close() error {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	observer.closed = true
	return observer.pipeline.Close()
}

// ObservePacket conserve l'identité entière de la trame et explicite les refus.
// Si une erreur opérationnelle est rendue, l'observation retournée n'est pas exploitable.
func (observer *BenchObserver) ObservePacket(packet BenchPacket) (BenchObservation, error) {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	digest := sha256.Sum256(packet.Frame)
	observation := BenchObservation{
		TimestampNs: packet.TimestampNs, PacketSHA256: hex.EncodeToString(digest[:]),
		Status: "non_target",
	}
	if observer.closed {
		return observation, ErrPipelineClosed
	}
	if packet.TimestampNs > math.MaxInt64 {
		return observation, fmt.Errorf("bench observer: horodatage supérieur à MaxInt64")
	}
	refuse := func(status, reason string) (BenchObservation, error) {
		observation.Status = status
		observation.Reasons = []string{reason}
		return observation, nil
	}
	ip := packet.Frame
	var etherType uint16
	switch packet.LinkType {
	case 1:
		if len(ip) < 14 {
			return refuse("malformed", "en-tête Ethernet incomplet")
		}
		etherType, ip = binary.BigEndian.Uint16(ip[12:]), ip[14:]
	case 101:
	case 113:
		if len(ip) < 16 {
			return refuse("malformed", "en-tête Linux cooked v1 incomplet")
		}
		etherType, ip = binary.BigEndian.Uint16(ip[14:]), ip[16:]
	case 276:
		if len(ip) < 20 {
			return refuse("malformed", "en-tête Linux cooked v2 incomplet")
		}
		etherType, ip = binary.BigEndian.Uint16(ip), ip[20:]
	default:
		return refuse("unsupported", "type de lien inconnu")
	}
	if packet.LinkType != 101 {
		switch etherType {
		case 0x0800, 0x86dd:
		case 0x8100, 0x88a8:
			return refuse("unsupported", "enveloppe VLAN non décodée")
		default:
			return observation, nil
		}
	}
	if len(ip) == 0 {
		return refuse("malformed", "en-tête IP absent")
	}
	var source, destination [16]byte
	var segment []byte
	var transport byte
	version := ip[0] >> 4
	if (etherType == 0x0800 && version != 4) || (etherType == 0x86dd && version != 6) {
		return refuse("malformed", "version IP différente du protocole de lien")
	}
	switch version {
	case 4:
		if len(ip) < 20 {
			return refuse("malformed", "en-tête IPv4 incomplet")
		}
		header, total := int(ip[0]&15)*4, int(binary.BigEndian.Uint16(ip[2:]))
		if header < 20 || total < header || total > len(ip) {
			return refuse("malformed", "longueurs IPv4 invalides")
		}
		source = netip.AddrFrom4([4]byte(ip[12:16])).As16()
		destination = netip.AddrFrom4([4]byte(ip[16:20])).As16()
		observation.SrcIP = netip.AddrFrom16(source).Unmap().String()
		observation.DstIP = netip.AddrFrom16(destination).Unmap().String()
		if binary.BigEndian.Uint16(ip[6:])&0x3fff != 0 {
			return refuse("unsupported", "fragmentation IPv4 non réassemblée")
		}
		transport, segment = ip[9], ip[header:total]
		ip = ip[:total]
	case 6:
		if len(ip) < 40 {
			return refuse("malformed", "en-tête IPv6 incomplet")
		}
		total := 40 + int(binary.BigEndian.Uint16(ip[4:]))
		if total > len(ip) {
			return refuse("malformed", "longueur IPv6 invalide")
		}
		copy(source[:], ip[8:24])
		copy(destination[:], ip[24:40])
		observation.SrcIP = netip.AddrFrom16(source).String()
		observation.DstIP = netip.AddrFrom16(destination).String()
		transport, segment = ip[6], ip[40:total]
		switch transport {
		case 0, 43, 44, 50, 51, 60, 135, 139, 140, 147, 253, 254:
			return refuse("unsupported", "extension IPv6 non traitée")
		}
	default:
		return refuse("malformed", "version IP inconnue")
	}
	addReason := func(reason string) {
		if reason != "" && reason != engine.ReasonNone && !slices.Contains(observation.Reasons, reason) {
			observation.Reasons = append(observation.Reasons, reason)
		}
	}
	switch transport {
	case 1:
		if version != 4 {
			return refuse("unsupported", "ICMP IPv4 annoncé dans IPv6")
		}
		observation.Protocol = "icmp"
		if len(segment) < 8 {
			return refuse("malformed", "message ICMP incomplet")
		}
		_, reason := observer.icmp.ObserveIPv4(int64(packet.TimestampNs), ip)
		addReason(reason)
		observation.Status = "observed"
	case 6, 17:
		if len(segment) < 4 {
			return refuse("malformed", "ports de transport incomplets")
		}
		observation.SrcPort = binary.BigEndian.Uint16(segment)
		observation.DstPort = binary.BigEndian.Uint16(segment[2:])
		isDNS := slices.Contains(observer.dnsPorts, observation.SrcPort) || slices.Contains(observer.dnsPorts, observation.DstPort)
		if transport == 6 {
			observation.Protocol = "tcp"
			if len(segment) < 20 || int(segment[12]>>4)*4 < 20 || int(segment[12]>>4)*4 > len(segment) {
				return refuse("malformed", "en-tête TCP invalide")
			}
			if isDNS {
				return refuse("unsupported", "DNS sur TCP non réassemblé")
			}
			return observation, nil
		}
		observation.Protocol = "udp"
		if len(segment) < 8 {
			return refuse("malformed", "en-tête UDP incomplet")
		}
		length := int(binary.BigEndian.Uint16(segment[4:]))
		if length < 8 || length != len(segment) {
			return refuse("malformed", "longueur UDP différente de la charge IP")
		}
		if !isDNS {
			return observation, nil
		}
		observation.Protocol = "dns"
		wire := segment[8:length]
		var message DNSMessage
		if err := ParseDNSMessage(wire, &message); err != nil {
			return refuse("malformed", "message DNS invalide: "+err.Error())
		}
		_, _, reason, err := observer.pipeline.EvaluateDNSMessageWithReason(wire, int64(packet.TimestampNs), source, destination)
		if err != nil {
			return observation, err
		}
		addReason(reason)
		_, reason = observer.soa.ObserveResponse(int64(packet.TimestampNs), destination, wire)
		addReason(reason)
		_, reason = observer.aaaa.ObserveResponse(int64(packet.TimestampNs), destination, wire)
		addReason(reason)
		observation.Status = "observed"
	}
	return observation, nil
}
