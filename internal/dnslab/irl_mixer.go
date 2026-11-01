package dnslab

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
)

type GroundTruthPacket struct {
	FrameIndex   int    `json:"frame_index"`
	TimestampNs  int64  `json:"timestamp_ns"`
	Family       string `json:"family"`
	MotifFamily  string `json:"motif_family,omitempty"`
	IsHostile    bool   `json:"is_hostile"`
	DomainApex   string `json:"domain_apex"`
	Subdomain    string `json:"subdomain"`
	QType        uint16 `json:"qtype"`
	PacketSHA256 string `json:"packet_sha256"`
}

var irlHumanJitterWeights = [...]int64{
	45, 130, 820, 65, 1450, 190, 95, 1120, 55, 410, 1680, 80, 290,
}

func deriveP4ShardSubdomain(seed uint64, idx int) string {
	perm := deriveP1P2Bytes("irl/p4", seed, idx, 8)
	digitStart := int(perm[0]) % 10
	digitStep := [4]int{1, 3, 7, 9}[perm[1]&3]
	alphaStart := int(perm[2]) % 26
	alphaStep := [4]int{1, 3, 5, 7}[perm[3]&3]

	var label [15]byte
	label[0] = 's'
	for pairIdx := range 7 {
		label[1+2*pairIdx] = byte('0' + (digitStart+pairIdx*digitStep)%10)
		ch := byte('a' + (alphaStart+pairIdx*alphaStep)%26)
		if ch == 's' && pairIdx == 0 {
			ch = 't'
		}
		label[2+2*pairIdx] = ch
	}
	return string(label[:])
}

// BuildIRLDilutedStream produit un flux IRL dilué : échanges hostiles P1..P4
// entrelacés avec des échanges bénins, accompagné de sa vérité terrain.
func BuildIRLDilutedStream(seed uint64, benignRatio float64, maxExchanges int) ([]GeneratedExchange, []GroundTruthPacket, error) {
	if benignRatio < 0.70 || benignRatio > 0.95 || maxExchanges < 40 || maxExchanges > 600 {
		return nil, nil, ErrLiveRateContract
	}

	hostileTotal := max(int(math.Round(float64(maxExchanges)*(1.0-benignRatio))), 24)
	benignTotal := maxExchanges - hostileTotal

	nonLDH := func(s string) bool { return strings.Contains(s, "_") }

	families := []string{"P1", "P2", "P3", "P4"}
	happyEyeballsPairs := 8

	var p3Exchanges []GeneratedExchange
	byOtherFamily := make([][]GeneratedExchange, 0, 3)
	for f, family := range families {
		familyQuota := hostileTotal / len(families)
		if f < hostileTotal%len(families) {
			familyQuota++
		}
		var famList []GeneratedExchange
		for i := 0; i < familyQuota; i++ {
			var ex GeneratedExchange
			switch family {
			case "P1":
				qtype := uint16(16)
				if i%2 == 1 {
					qtype = 10
				}
				ex = GeneratedExchange{
					Family:      "P1",
					DomainApex:  fmt.Sprintf("irl-p1-%02d.org", i%4+1),
					Subdomain:   fmt.Sprintf("p1dl%03d", i),
					QType:       qtype,
					AnswerRData: deriveP1P2Bytes("irl/p1", seed, i, 240),
				}
			case "P2":
				ex = GeneratedExchange{
					Family:      "P2",
					DomainApex:  fmt.Sprintf("irl-p2-%02d.net", i%4+1),
					Subdomain:   hex.EncodeToString(deriveP1P2Bytes("irl/p2", seed, i, 18)),
					QType:       1,
					AnswerRData: []byte{10, 55, 0, byte(i + 1)},
				}
			case "P3":
				ex = GeneratedExchange{
					Family:      "P3",
					DomainApex:  "irl-beacon-sync.com",
					Subdomain:   fmt.Sprintf("t%03d", i),
					QType:       p3QTypes[i%len(p3QTypes)],
					AnswerRData: []byte{10, 55, 1, byte(i + 1)},
				}
			case "P4":
				ex = GeneratedExchange{
					Family:      "P4",
					DomainApex:  fmt.Sprintf("irl-p4-%02d.org", i%6+1),
					Subdomain:   deriveP4ShardSubdomain(seed, i),
					QType:       16,
					AnswerRData: deriveP1P2Bytes("irl/p4r", seed, i, 8),
				}
			}
			ex.HasNonLDH = nonLDH(ex.Subdomain)
			famList = append(famList, ex)
		}
		if family == "P3" {
			p3Exchanges = famList
		} else {
			byOtherFamily = append(byOtherFamily, famList)
		}
	}

	otherHostileTotal := hostileTotal - len(p3Exchanges)
	otherHostile := make([]GeneratedExchange, 0, otherHostileTotal)
	for j := 0; len(otherHostile) < otherHostileTotal; j++ {
		for f := range byOtherFamily {
			if j < len(byOtherFamily[f]) {
				otherHostile = append(otherHostile, byOtherFamily[f][j])
			}
		}
	}

	benign := make([][]GeneratedExchange, 0, benignTotal)
	for p := range happyEyeballsPairs {
		benign = append(benign, []GeneratedExchange{
			{
				Family:      "BENIGN",
				DomainApex:  "cdn-edge-01.com",
				Subdomain:   "www",
				QType:       1,
				AnswerRData: []byte{93, 184, 216, byte(p + 1)},
			},
			{
				Family:      "BENIGN",
				DomainApex:  "cdn-edge-01.com",
				Subdomain:   "www",
				QType:       28,
				AnswerRData: []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(p + 1)},
			},
		})
	}

	txtSubdomains := []string{"default._domainkey", "_spf", "_acme-challenge"}
	cdnSubdomains := []string{"assets", "static", "img"}
	for k := 0; k < benignTotal-2*happyEyeballsPairs; k++ {
		var ex GeneratedExchange
		if k < len(txtSubdomains) {
			ex = GeneratedExchange{
				Family:      "BENIGN",
				DomainApex:  "mail-corp.org",
				Subdomain:   txtSubdomains[k],
				QType:       16,
				AnswerRData: []byte("v=spf1 -all"),
			}
		} else {
			ex = GeneratedExchange{
				Family:      "BENIGN",
				DomainApex:  fmt.Sprintf("benign-cdn-%02d.com", k%5+1),
				Subdomain:   cdnSubdomains[k%len(cdnSubdomains)],
				QType:       1,
				AnswerRData: []byte{93, 184, 216, byte(k + 1)},
			}
		}
		ex.HasNonLDH = nonLDH(ex.Subdomain)
		benign = append(benign, []GeneratedExchange{ex})
	}

	bgGroups := make([][]GeneratedExchange, 0, len(benign)+len(otherHostile))
	bi, hi := 0, 0
	for bi < len(benign) || hi < len(otherHostile) {
		takeBenign := hi >= len(otherHostile) || (bi < len(benign) && bi*len(otherHostile) <= hi*len(benign))
		if takeBenign {
			bgGroups = append(bgGroups, benign[bi])
			bi++
		} else {
			bgGroups = append(bgGroups, []GeneratedExchange{otherHostile[hi]})
			hi++
		}
	}

	const baseTs = int64(1_785_000_000_000_000_000)
	const p3PeriodNs = int64(10_000_000_000)
	for m := range p3Exchanges {
		microJitter := int64((m*13+int(seed&7))%5) * 1_000_000
		p3Exchanges[m].TimestampNs = baseTs + int64(m+1)*p3PeriodNs + microJitter
	}

	var totalWeight int64
	for gIdx := 1; gIdx < len(bgGroups); gIdx++ {
		totalWeight += irlHumanJitterWeights[(gIdx*7+int(seed&0x1f))%len(irlHumanJitterWeights)]
	}
	if totalWeight <= 0 {
		totalWeight = 1
	}
	targetSpanNs := int64(len(p3Exchanges))*p3PeriodNs + p3PeriodNs/2

	exchanges := make([]GeneratedExchange, 0, maxExchanges)
	bgTs := baseTs
	p3Idx := 0
	for gIdx, grp := range bgGroups {
		if gIdx > 0 {
			w := irlHumanJitterWeights[(gIdx*7+int(seed&0x1f))%len(irlHumanJitterWeights)]
			stepNs := max((w*targetSpanNs)/totalWeight, 12_000_000)
			bgTs += stepNs
		}
		groupEndTs := bgTs
		if len(grp) > 1 {
			groupEndTs += 5_000_000
		}
		for p3Idx < len(p3Exchanges) && p3Exchanges[p3Idx].TimestampNs <= groupEndTs {
			exchanges = append(exchanges, p3Exchanges[p3Idx])
			if bgTs < p3Exchanges[p3Idx].TimestampNs+1_000_000 {
				bgTs = p3Exchanges[p3Idx].TimestampNs + 1_000_000
				groupEndTs = bgTs
				if len(grp) > 1 {
					groupEndTs += 5_000_000
				}
			}
			p3Idx++
		}
		for m, item := range grp {
			if m > 0 {
				bgTs += 5_000_000
			}
			item.TimestampNs = bgTs
			exchanges = append(exchanges, item)
		}
	}
	for p3Idx < len(p3Exchanges) {
		if p3Exchanges[p3Idx].TimestampNs < bgTs {
			p3Exchanges[p3Idx].TimestampNs = bgTs + 1_000_000
			bgTs = p3Exchanges[p3Idx].TimestampNs
		}
		exchanges = append(exchanges, p3Exchanges[p3Idx])
		p3Idx++
	}

	truth := make([]GroundTruthPacket, len(exchanges))
	for i, ex := range exchanges {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s:%s:%s:%d", i, ex.Family, ex.Subdomain, ex.DomainApex, ex.TimestampNs)))
		truth[i] = GroundTruthPacket{
			FrameIndex:   i,
			TimestampNs:  ex.TimestampNs,
			Family:       ex.Family,
			IsHostile:    ex.Family != "BENIGN",
			DomainApex:   ex.DomainApex,
			Subdomain:    ex.Subdomain,
			QType:        ex.QType,
			PacketSHA256: hex.EncodeToString(sum[:]),
		}
	}

	return exchanges, truth, nil
}
