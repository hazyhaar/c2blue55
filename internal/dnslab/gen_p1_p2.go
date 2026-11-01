package dnslab

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
)

var (
	ErrSameRunLeak      = errors.New("dnslab: seedA et seedB identiques ou fuite entre Run-A et Run-B")
	ErrLiveRateContract = errors.New("dnslab: violation de la garde anti-spam live OVH (F-21)")
)

const MaxLiveQPS = 5

type GeneratedExchange struct {
	Family       string // "P1".."P13", "M-01".."M-04", "BENIGN"
	DomainApex   string
	Subdomain    string
	QType        uint16
	AnswerRData  []byte
	HasNonLDH    bool
	TimestampNs  int64
	RequestWire  []byte
	ResponseWire []byte
}

type DisjointP1P2Corpus struct {
	RunAID string
	RunBID string
	RunA   []GeneratedExchange
	RunB   []GeneratedExchange
}

const (
	perFamilyPerRun = 32
	p1RDataLen      = 300
	tsBaseNs        = int64(1_780_000_000_000_000_000)
	tsStepNs        = int64(1_000)
)

func deriveP1P2Bytes(label string, seed uint64, idx int, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	var buf [8]byte
	for ctr := uint32(0); len(out) < n; ctr++ {
		h := sha256.New()
		h.Write([]byte(label))
		binary.BigEndian.PutUint64(buf[:], seed)
		h.Write(buf[:])
		binary.BigEndian.PutUint64(buf[:], uint64(idx))
		h.Write(buf[:])
		binary.BigEndian.PutUint32(buf[:4], ctr)
		h.Write(buf[:4])
		out = h.Sum(out)
	}
	return out[:n]
}

func buildP1P2Run(letter string, seed uint64, tld string) []GeneratedExchange {
	run := "run" + letter
	ex := make([]GeneratedExchange, 0, 3*perFamilyPerRun)
	ts := tsBaseNs

	for i := range perFamilyPerRun {
		qt := uint16(16)
		if i%2 == 1 {
			qt = 10
		}
		ex = append(ex, GeneratedExchange{
			Family:      "P1",
			DomainApex:  fmt.Sprintf("%s-p1-%02d.test", run, i+1),
			Subdomain:   fmt.Sprintf("p1%s%02d", letter, i+1),
			QType:       qt,
			AnswerRData: deriveP1P2Bytes(run+"/p1", seed, i, p1RDataLen),
			TimestampNs: ts,
		})
		ts += tsStepNs
	}

	for i := range perFamilyPerRun {
		ex = append(ex, GeneratedExchange{
			Family:      "P2",
			DomainApex:  fmt.Sprintf("%s-p2-%02d.test", run, i+1),
			Subdomain:   hex.EncodeToString(deriveP1P2Bytes(run+"/p2", seed, i, 18)),
			QType:       1,
			TimestampNs: ts,
		})
		ts += tsStepNs
	}

	for i := range perFamilyPerRun {
		ex = append(ex, GeneratedExchange{
			Family:      "BENIGN",
			DomainApex:  fmt.Sprintf("%s-benign-%02d.%s", run, i+1, tld),
			Subdomain:   fmt.Sprintf("www-%s%02d", letter, i+1),
			QType:       1,
			TimestampNs: ts,
		})
		ts += tsStepNs
	}
	return ex
}

func disjointExchanges(a, b []GeneratedExchange) bool {
	seen := make(map[string]struct{}, 2*len(a))
	for _, e := range a {
		seen["apex:"+e.DomainApex] = struct{}{}
		seen["sub:"+e.Subdomain] = struct{}{}
	}
	for _, e := range b {
		if _, ok := seen["apex:"+e.DomainApex]; ok {
			return false
		}
		if _, ok := seen["sub:"+e.Subdomain]; ok {
			return false
		}
	}
	return true
}

func GenerateP1P2DisjointPairs(seedA, seedB uint64) (*DisjointP1P2Corpus, error) {
	if seedA == seedB {
		return nil, ErrSameRunLeak
	}
	a := buildP1P2Run("a", seedA, "org")
	b := buildP1P2Run("b", seedB, "net")
	if !disjointExchanges(a, b) {
		return nil, ErrSameRunLeak
	}
	return &DisjointP1P2Corpus{
		RunAID: fmt.Sprintf("run-a-%016x", seedA),
		RunBID: fmt.Sprintf("run-b-%016x", seedB),
		RunA:   a,
		RunB:   b,
	}, nil
}

func ValidateLiveRateGuard(targetIP string, maxQPS int, maxPackets int) error {
	ip := net.ParseIP(targetIP)
	if ip == nil {
		return fmt.Errorf("%w: IP invalide %q", ErrLiveRateContract, targetIP)
	}
	_, loopback, _ := net.ParseCIDR("127.0.0.0/8")
	_, lab, _ := net.ParseCIDR("10.55.0.0/24")
	if !loopback.Contains(ip) && !lab.Contains(ip) {
		return fmt.Errorf("%w: cible %s hors 127.0.0.0/8 et 10.55.0.0/24", ErrLiveRateContract, targetIP)
	}
	if maxQPS <= 0 || maxQPS > 5 {
		return fmt.Errorf("%w: maxQPS=%d hors [1,5]", ErrLiveRateContract, maxQPS)
	}
	if maxPackets <= 0 || maxPackets > 200 {
		return fmt.Errorf("%w: maxPackets=%d hors [1,200]", ErrLiveRateContract, maxPackets)
	}
	return nil
}
