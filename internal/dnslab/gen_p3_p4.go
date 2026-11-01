package dnslab

import (
	"encoding/hex"
	"fmt"
)

// DisjointP3P4Corpus contient deux runs sans DomainApex ni Subdomain communs.
type DisjointP3P4Corpus struct {
	RunAID string
	RunBID string
	RunA   []GeneratedExchange
	RunB   []GeneratedExchange
}

const (
	p3Count      = 35
	p4Count      = 36
	p4ApexCount  = 12
	benignCount  = 35
	benignApexes = 5
	baseTimeNs   = int64(1793059200_000_000_000)
	p3PeriodNs   = int64(60_000_000_000)
)

var (
	p3QTypes    = [...]uint16{1, 28, 16, 10, 5}
	benignTwins = [...]string{"cdn", "api", "www", "doh"}
)

type splitmix64 struct{ s uint64 }

func (r *splitmix64) next() uint64 {
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (r *splitmix64) rdata(qtype uint16) []byte {
	n := 8
	switch qtype {
	case 1:
		n = 4
	case 28:
		n = 16
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.next())
	}
	return b
}

func buildP3P4Run(tag string, seed uint64) []GeneratedExchange {
	rng := &splitmix64{s: seed}
	tld := "net"
	if tag == "b" {
		tld = "org"
	}
	out := make([]GeneratedExchange, 0, p3Count+p4Count+benignCount)
	runBase := baseTimeNs + int64(rng.next()%1000)*1_000_000

	// P3 : balise périodique avec rotation déterministe des QTYPE.
	beaconApex := fmt.Sprintf("beacon-%s.com", tag)
	for i := range p3Count {
		ts := runBase + int64(i)*p3PeriodNs + int64(rng.next()%500)*1_000_000
		qt := p3QTypes[i%len(p3QTypes)]
		out = append(out, GeneratedExchange{
			Family:      "P3",
			DomainApex:  beaconApex,
			Subdomain:   fmt.Sprintf("t%s%03d", tag, i),
			QType:       qt,
			AnswerRData: rng.rdata(qt),
			TimestampNs: ts,
		})
	}

	// P4 : 12 apex distincts, sous-domaines haute entropie cadencés à 500 ms.
	p4Base := runBase + int64(p3Count)*p3PeriodNs
	for i := range p4Count {
		apex := fmt.Sprintf("p4-%s-%02d.%s", tag, i%p4ApexCount, tld)
		raw := deriveP1P2Bytes("p4/"+tag, seed, i, 16)
		sub := tag + hex.EncodeToString(raw)
		ts := p4Base + int64(i)*500_000_000
		out = append(out, GeneratedExchange{
			Family:      "P4",
			DomainApex:  apex,
			Subdomain:   sub,
			QType:       16,
			AnswerRData: rng.rdata(16),
			TimestampNs: ts,
		})
	}

	// BENIGN : jumeaux difficiles à basse entropie et pauses humaines irrégulières.
	benignBase := p4Base + int64(p4Count)*500_000_000
	ts := benignBase
	for i := range benignCount {
		apex := fmt.Sprintf("benign-%s-%02d.com", tag, i%benignApexes)
		sub := fmt.Sprintf("%s-%s%02d", benignTwins[i%len(benignTwins)], tag, i)
		ts += 1_000_000_000 + int64((i*7919)%40)*250_000_000
		out = append(out, GeneratedExchange{
			Family:      "BENIGN",
			DomainApex:  apex,
			Subdomain:   sub,
			QType:       1,
			AnswerRData: rng.rdata(1),
			TimestampNs: ts,
		})
	}
	return out
}

// GenerateP3P4DisjointPairs produit deux runs P3/P4/BENIGN disjoints.
func GenerateP3P4DisjointPairs(seedA, seedB uint64) (*DisjointP3P4Corpus, error) {
	if seedA == seedB {
		return nil, ErrSameRunLeak
	}
	return &DisjointP3P4Corpus{
		RunAID: fmt.Sprintf("p3p4-a-%016x", seedA),
		RunBID: fmt.Sprintf("p3p4-b-%016x", seedB),
		RunA:   buildP3P4Run("a", seedA),
		RunB:   buildP3P4Run("b", seedB),
	}, nil
}
