package engine

import "math"

// MaxEpisodeStoreEntries borne le nombre total de slots pré-alloués.
const MaxEpisodeStoreEntries = 4096

const (
	episodeWays    = 4
	episodeBuckets = MaxEpisodeStoreEntries / episodeWays
	episodeRing    = 16
	fnvOffset64    = 14695981039346656037
	fnvPrime64     = 1099511628211
	rcodeNXDomain  = 3
)

// DNSExchangeObs est une observation DNS normalisée (requête ou réponse).
type DNSExchangeObs struct {
	TimestampNs int64
	SrcIP       [16]byte
	TxID        uint16
	IsResponse  bool
	RCode       uint8
	QType       uint16
	ParentApex  []byte
	Subdomain   []byte
	AnswerRData []byte
	AnswerCount uint8
	HasNonLDH   bool
}

// DNSEpisodeSnapshot est l'état agrégé d'un couple (SrcIP, ParentApex).
type DNSEpisodeSnapshot struct {
	Queries          uint32
	MatchedReplies   uint32
	OrphanResponses  uint32
	NXDomainCount    uint32
	ReqBytesTotal    uint64
	RespBytesTotal   uint64
	DownlinkRatio    float32
	MeanRDataEntropy float32
	Base32HexScore   float32
	CompositeP1P2    float32
}

type episodeSlot struct {
	used       bool
	key        uint64
	lastNs     int64
	ring       [episodeRing]uint16
	pend       uint16
	head       uint8
	entropySum float64
	entropyN   uint32
	snap       DNSEpisodeSnapshot
}

// DNSEpisodeStore : table fixe associative à 4 voies, sans allocation sur le chemin chaud.
type DNSEpisodeStore struct {
	buckets [episodeBuckets][episodeWays]episodeSlot
}

func NewDNSEpisodeStore() *DNSEpisodeStore {
	return &DNSEpisodeStore{}
}

// ObserveExchange met à jour l'épisode concerné et renseigne dst512 si non nil.
func (s *DNSEpisodeStore) ObserveExchange(obs DNSExchangeObs, dst512 *[EmbeddingDim]float32) (DNSEpisodeSnapshot, bool) {
	sl := s.slotFor(episodeKey(&obs.SrcIP, obs.ParentApex), obs.TimestampNs)
	sn := &sl.snap
	if obs.IsResponse {
		if sl.take(obs.TxID) {
			sn.MatchedReplies++
		} else {
			sn.OrphanResponses++
		}
		if obs.RCode == rcodeNXDomain {
			sn.NXDomainCount++
		}
		sn.RespBytesTotal += uint64(len(obs.AnswerRData))
		if len(obs.AnswerRData) > 0 {
			sl.entropySum += rdataShannonBits(obs.AnswerRData)
			sl.entropyN++
			sn.MeanRDataEntropy = float32(sl.entropySum / float64(sl.entropyN))
		}
	} else {
		sn.Queries++
		sn.ReqBytesTotal += uint64(len(obs.Subdomain))
		sl.push(obs.TxID)
		if sc := base32HexScore(obs.Subdomain); sc > sn.Base32HexScore {
			sn.Base32HexScore = sc
		}
	}
	sn.DownlinkRatio = float32(sn.RespBytesTotal) / float32(max(sn.ReqBytesTotal, 1))
	sn.CompositeP1P2 = compositeP1P2(sn)
	if dst512 != nil {
		fillEmbedding(dst512, sn)
	}
	return *sn, true
}

func (s *DNSEpisodeStore) slotFor(key uint64, nowNs int64) *episodeSlot {
	b := &s.buckets[key&(episodeBuckets-1)]
	victim := 0
	for i := range b {
		if b[i].used && b[i].key == key {
			b[i].lastNs = nowNs
			return &b[i]
		}
		if !b[i].used || (b[victim].used && b[i].lastNs < b[victim].lastNs) {
			victim = i
		}
	}
	b[victim] = episodeSlot{used: true, key: key, lastNs: nowNs}
	return &b[victim]
}

func (sl *episodeSlot) push(txid uint16) {
	for i := range sl.ring {
		if sl.pend&(uint16(1)<<uint(i)) == 0 {
			sl.ring[i] = txid
			sl.pend |= uint16(1) << uint(i)
			return
		}
	}
	sl.ring[sl.head] = txid
	sl.pend |= uint16(1) << uint(sl.head)
	sl.head = (sl.head + 1) % episodeRing
}

func (sl *episodeSlot) take(txid uint16) bool {
	for i := range sl.ring {
		bit := uint16(1) << uint(i)
		if sl.pend&bit != 0 && sl.ring[i] == txid {
			sl.pend &^= bit
			return true
		}
	}
	return false
}

func episodeKey(src *[16]byte, apex []byte) uint64 {
	h := uint64(fnvOffset64)
	for _, c := range src {
		h ^= uint64(c)
		h *= fnvPrime64
	}
	for _, c := range apex {
		h ^= uint64(c)
		h *= fnvPrime64
	}
	return h
}

func rdataShannonBits(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var hist [256]uint16
	for _, c := range b {
		hist[c]++
	}
	n := float64(len(b))
	var h float64
	for _, c := range hist {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func isB32Hex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'v') || (c >= 'A' && c <= 'V')
}

func base32HexScore(sub []byte) float32 {
	if len(sub) < 16 {
		return 0
	}
	var n int
	for _, c := range sub {
		if isB32Hex(c) {
			n++
		}
	}
	frac := float32(n) / float32(len(sub))
	ent := rdataShannonBits(sub) / 5
	if ent > 1 {
		ent = 1
	}
	return frac * float32(ent)
}

func compositeP1P2(sn *DNSEpisodeSnapshot) float32 {
	p1 := sn.DownlinkRatio > 2.0
	p2 := sn.Base32HexScore > 0.35
	if !p1 && !p2 {
		return -0.5
	}
	score := 0.45*episodeClamp01((sn.DownlinkRatio-1)/4) +
		0.35*episodeClamp01((sn.MeanRDataEntropy-4)/4) +
		0.65*sn.Base32HexScore
	if score > 1 {
		score = 1
	}
	return score
}

func episodeClamp01(x float32) float32 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

func fillEmbedding(dst *[EmbeddingDim]float32, sn *DNSEpisodeSnapshot) {
	*dst = [EmbeddingDim]float32{}
	dst[0] = float32(sn.Queries)
	dst[1] = float32(sn.MatchedReplies)
	dst[2] = float32(sn.OrphanResponses)
	dst[3] = float32(sn.NXDomainCount)
	dst[4] = sn.DownlinkRatio
	dst[5] = sn.MeanRDataEntropy
	dst[6] = sn.Base32HexScore
	dst[7] = sn.CompositeP1P2
}
