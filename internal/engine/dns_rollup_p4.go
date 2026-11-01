package engine

import "math/bits"

const (
	highEntropyMin = 0.55
	apexSlotCap    = 32
	clientSlotN    = 256
)

// ClientP4Features résume le comportement multi-parents d'un client DNS.
type ClientP4Features struct {
	DistinctApexCount      uint16
	DistinctHighEntParents uint16
	CrossParentSeqCorr     float32
	CompositeP4Score       float32
}

type clientRollupSlot struct {
	ip            [16]byte
	used          bool
	apexes        [apexSlotCap]uint64
	nApex         uint8
	highMask      uint32
	lastApex      uint64
	lastTsNs      int64
	lastDeltaNs   int64
	crossSwitches uint32
	paced         uint32
	highObs       uint32
	totalObs      uint32
}

// DNSClientRollup : table fixe de 256 slots, sans allocation par observation.
type DNSClientRollup struct {
	slots [clientSlotN]clientRollupSlot
}

func NewDNSClientRollup() *DNSClientRollup {
	return &DNSClientRollup{}
}

// ObserveParentApex met à jour le slot du client et renvoie ses features P4.
func (r *DNSClientRollup) ObserveParentApex(srcIP [16]byte, apexHash uint64, subEntropy float32, tsNs int64) ClientP4Features {
	h := uint32(2166136261)
	for _, b := range srcIP {
		h ^= uint32(b)
		h *= 16777619
	}
	s := &r.slots[h&(clientSlotN-1)]
	if !s.used || s.ip != srcIP {
		*s = clientRollupSlot{ip: srcIP, used: true}
	}

	high := subEntropy >= highEntropyMin
	var delta int64
	if s.totalObs > 0 {
		delta = tsNs - s.lastTsNs
		if high {
			if apexHash != s.lastApex {
				s.crossSwitches++
			} else if delta == s.lastDeltaNs {
				s.paced++
			}
		}
		s.lastDeltaNs = delta
	}

	idx := -1
	for i := uint8(0); i < s.nApex; i++ {
		if s.apexes[i] == apexHash {
			idx = int(i)
			break
		}
	}
	if idx < 0 && s.nApex < apexSlotCap {
		idx = int(s.nApex)
		s.apexes[idx] = apexHash
		s.nApex++
	}
	if high {
		s.highObs++
		if idx >= 0 {
			s.highMask |= 1 << uint(idx)
		}
	}
	s.lastApex = apexHash
	s.lastTsNs = tsNs
	s.totalObs++

	f := ClientP4Features{
		DistinctApexCount:      uint16(s.nApex),
		DistinctHighEntParents: uint16(bits.OnesCount32(s.highMask)),
	}
	if s.highObs > 0 {
		f.CrossParentSeqCorr = float32(s.crossSwitches+s.paced) / float32(s.highObs)
	}
	f.CompositeP4Score = compositeP4(f)
	return f
}

func compositeP4(f ClientP4Features) float32 {
	if f.DistinctHighEntParents <= 1 {
		return -0.60
	}
	n := min(f.DistinctHighEntParents, 12)
	return 0.5*float32(n)/12 + 0.5*f.CrossParentSeqCorr
}
