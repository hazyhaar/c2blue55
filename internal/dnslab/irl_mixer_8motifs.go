package dnslab

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
)

var dgaConsonantSeeds = [...]string{
	"qzvxkptlrmnbvcxz",
	"xzkvqptlrmnghjkl",
	"vqxzptlkrmnbvcdf",
	"kqzvxptlrmnghjfp",
	"zqxvkptlrmnbvcwt",
	"pqzvxktlrmnghjsc",
	"mxzvkptlrmnbvcdq",
	"rqzvxptlrmnghjkz",
}

var m02HighShannonTokens = [...]string{
	"aB3dE5fG7hJ9kL1mN4pQrS",
	"xY2zW4vU6tS8rQ0pO1nM3k",
	"cF5gH7jK9lM2nP4qR6sT8v",
	"wX1yZ3aB5cD7eF9gH2iJ4k",
	"mN6pQ8rS0tU2vW4xY7zA9b",
	"dE1fG3hI5jK7lM9nO2pQ4r",
	"sT5uV7wX9yZ1aB3cD6eF8g",
	"hJ2kL4mN6pQ8rS1tV3wX5z",
}

var hex28Payloads = [...]string{
	"0123456789abcdef0123456789ab",
	"123456789abcdef0123456789abc",
	"23456789abcdef0123456789abcd",
	"3456789abcdef0123456789abcde",
	"456789abcdef0123456789abcdef",
	"56789abcdef0123456789abcdef0",
	"6789abcdef0123456789abcdef01",
	"789abcdef0123456789abcdef012",
}

// BuildLabResponse8Motifs étend BuildLabResponseP1P4 en renvoyant RCode=3 (NXDOMAIN)
// sur les requêtes DGA M-04 (identifiées sans état par préfixe consonantique ou domaine dga-).
func BuildLabResponse8Motifs(question []byte, seed uint64, response []byte) (int, Decision, error) {
	n, dec, err := BuildLabResponseP1P4(question, seed, response)
	if err != nil {
		return n, dec, err
	}
	qname := dec.QName[:dec.QNameLen]
	if hasSubBytes(qname, ".dga-") || hasSubBytes(qname, "qzvx") || hasSubBytes(qname, "xzkv") ||
		hasSubBytes(qname, "vqxz") || hasSubBytes(qname, "kqzv") || hasSubBytes(qname, "zqxv") ||
		hasSubBytes(qname, "pqzv") || hasSubBytes(qname, "mxzv") || hasSubBytes(qname, "rqzv") {
		dec.Verdict = VerdictNoData
		dec.RCode = 3
		// En-tête + section question sans enregistrement de réponse (ANCOUNT=0, RCode=3 NXDOMAIN).
		qEnd := 12
		for qEnd < len(question) {
			l := int(question[qEnd])
			qEnd++
			if l == 0 {
				break
			}
			qEnd += l
		}
		qEnd += 4
		if qEnd > len(question) {
			qEnd = 12
		}
		binary.BigEndian.PutUint16(response[2:4], 0x8403)
		response[7] = 0
		return qEnd, dec, nil
	}
	return n, dec, nil
}

// BuildIRLDilutedStream8Motifs génère un flux dilué à 85% de bruit bénin IRL et 15% d'anomalies
// réparties équitablement sur les 8 familles (M-01..M-04 + P1..P4).
func BuildIRLDilutedStream8Motifs(seed uint64, benignRatio float64, totalExchanges int) ([]GeneratedExchange, []GroundTruthPacket, error) {
	if benignRatio < 0.70 || benignRatio > 0.90 || totalExchanges < 160 || totalExchanges > 600 {
		return nil, nil, ErrLiveRateContract
	}

	hostileTotal := max(int(math.Round(float64(totalExchanges)*(1.0-benignRatio))), 48)
	benignTotal := totalExchanges - hostileTotal

	families := []string{"M-01", "M-02", "M-03", "M-04", "P1", "P2", "P3", "P4"}
	var m03Exchanges []GeneratedExchange
	var p3Exchanges []GeneratedExchange
	byOtherFamily := make([][]GeneratedExchange, 0, 6)

	for fIdx, fam := range families {
		familyQuota := hostileTotal / len(families)
		if fIdx < hostileTotal%len(families) {
			familyQuota++
		}
		var famList []GeneratedExchange
		for i := 0; i < familyQuota; i++ {
			var ex GeneratedExchange
			switch fam {
			case "M-01":
				ex = GeneratedExchange{
					Family:      "M-01",
					DomainApex:  "m01-volumetric.org",
					Subdomain:   fmt.Sprintf("chunk1a%02dabcdef0123456789.chunk2b%02dabcdef0123456789abcdef", i, i),
					QType:       16,
					AnswerRData: []byte("ack-m01"),
				}
			case "M-02":
				ex = GeneratedExchange{
					Family:      "M-02",
					DomainApex:  "m02-shannon.net",
					Subdomain:   m02HighShannonTokens[i%len(m02HighShannonTokens)],
					QType:       1,
					AnswerRData: []byte{10, 55, 2, byte(i + 1)},
				}
			case "M-03":
				ex = GeneratedExchange{
					Family:      "M-03",
					DomainApex:  "m03-burst.org",
					Subdomain:   fmt.Sprintf("bst-%03d", i),
					QType:       1,
					AnswerRData: []byte{10, 55, 3, byte(i + 1)},
				}
			case "M-04":
				ex = GeneratedExchange{
					Family:     "M-04",
					DomainApex: fmt.Sprintf("dga-%02d.org", i%6+1),
					Subdomain:  dgaConsonantSeeds[i%len(dgaConsonantSeeds)],
					QType:      1,
				}
			case "P1":
				qt := uint16(16)
				if i%2 == 1 {
					qt = 10
				}
				ex = GeneratedExchange{
					Family:      "P1",
					DomainApex:  fmt.Sprintf("irl-p1-%02d.org", i%4+1),
					Subdomain:   fmt.Sprintf("p1dl%02d", i),
					QType:       qt,
					AnswerRData: deriveP1P2Bytes("irl8/p1", seed, i, 240),
				}
			case "P2":
				ex = GeneratedExchange{
					Family:      "P2",
					DomainApex:  fmt.Sprintf("irl-p2-%02d.net", i%3+1),
					Subdomain:   hex28Payloads[i%len(hex28Payloads)],
					QType:       1,
					AnswerRData: []byte{10, 55, 4, byte(i + 1)},
				}
			case "P3":
				ex = GeneratedExchange{
					Family:      "P3",
					DomainApex:  "irl-beacon-sync.com",
					Subdomain:   fmt.Sprintf("hb%03d", i),
					QType:       p3QTypes[i%len(p3QTypes)],
					AnswerRData: []byte{10, 55, 5, byte(i + 1)},
				}
			case "P4":
				ex = GeneratedExchange{
					Family:      "P4",
					DomainApex:  fmt.Sprintf("irl-p4-shard-%02d.org", i),
					Subdomain:   fmt.Sprintf("s%d9f8e7d6c5b4a39", i%10),
					QType:       16,
					AnswerRData: []byte("shard-ok"),
				}
			}
			ex.HasNonLDH = strings.Contains(ex.Subdomain, "_")
			famList = append(famList, ex)
		}
		switch fam {
		case "M-03":
			m03Exchanges = famList
		case "P3":
			p3Exchanges = famList
		default:
			byOtherFamily = append(byOtherFamily, famList)
		}
	}

	otherHostileTotal := hostileTotal - len(m03Exchanges) - len(p3Exchanges)
	var otherHostile []GeneratedExchange
	for j := 0; len(otherHostile) < otherHostileTotal; j++ {
		for fIdx := range byOtherFamily {
			if j < len(byOtherFamily[fIdx]) {
				otherHostile = append(otherHostile, byOtherFamily[fIdx][j])
			}
		}
	}

	// Construction des échanges bénins IRL (Happy Eyeballs A+AAAA, TXT _domainkey/_spf/_acme-challenge, CDN).
	var benignGroups [][]GeneratedExchange
	txtSubs := []string{"default._domainkey", "_spf", "_acme-challenge"}
	cdnSubs := []string{"www", "assets", "static", "img", "api"}
	for k := 0; k < benignTotal; {
		switch {
		case k+1 < benignTotal && k < 20:
			apex := fmt.Sprintf("cdn-edge-%02d.com", (k/2)%4+1)
			benignGroups = append(benignGroups, []GeneratedExchange{
				{
					Family:      "BENIGN",
					DomainApex:  apex,
					Subdomain:   "www",
					QType:       1,
					AnswerRData: []byte{93, 184, 216, byte(k + 1)},
				},
				{
					Family:      "BENIGN",
					DomainApex:  apex,
					Subdomain:   "www",
					QType:       28,
					AnswerRData: []byte{93, 184, 216, byte(k + 2)},
				},
			})
			k += 2
		case k < 26:
			sub := txtSubs[k%len(txtSubs)]
			benignGroups = append(benignGroups, []GeneratedExchange{{
				Family:      "BENIGN",
				DomainApex:  "mail-corp.org",
				Subdomain:   sub,
				QType:       16,
				AnswerRData: []byte("v=spf1 -all"),
				HasNonLDH:   true,
			}})
			k++
		default:
			benignGroups = append(benignGroups, []GeneratedExchange{{
				Family:      "BENIGN",
				DomainApex:  fmt.Sprintf("benign-cdn-%02d.com", k%5+1),
				Subdomain:   cdnSubs[k%len(cdnSubs)],
				QType:       1,
				AnswerRData: []byte{93, 184, 216, byte(k + 1)},
			}})
			k++
		}
	}

	bgGroups := make([][]GeneratedExchange, 0, len(benignGroups)+len(otherHostile))
	bi, hi := 0, 0
	for bi < len(benignGroups) || hi < len(otherHostile) {
		takeBenign := hi >= len(otherHostile) || (bi < len(benignGroups) && bi*len(otherHostile) <= hi*len(benignGroups))
		if takeBenign {
			bgGroups = append(bgGroups, benignGroups[bi])
			bi++
		} else {
			bgGroups = append(bgGroups, []GeneratedExchange{otherHostile[hi]})
			hi++
		}
	}

	const baseTs = int64(1_785_000_000_000_000_000)
	const p3PeriodNs = int64(10_000_000_000)
	var scheduled []GeneratedExchange
	for idx := range m03Exchanges {
		m03Exchanges[idx].TimestampNs = baseTs + 4_000_000_000 + int64(idx)*15_000_000
		scheduled = append(scheduled, m03Exchanges[idx])
	}
	for idx := range p3Exchanges {
		microJitter := int64((idx*11+int(seed&7))%5) * 1_000_000
		p3Exchanges[idx].TimestampNs = baseTs + int64(idx+1)*p3PeriodNs + microJitter
		scheduled = append(scheduled, p3Exchanges[idx])
	}
	// Tri par TimestampNs croissant des événements M-03 et P3
	for a := 1; a < len(scheduled); a++ {
		cur := scheduled[a]
		b := a - 1
		for b >= 0 && scheduled[b].TimestampNs > cur.TimestampNs {
			scheduled[b+1] = scheduled[b]
			b--
		}
		scheduled[b+1] = cur
	}

	var totalWeight int64
	for gIdx := 1; gIdx < len(bgGroups); gIdx++ {
		totalWeight += irlHumanJitterWeights[(gIdx*7+int(seed&0x1f))%len(irlHumanJitterWeights)]
	}
	if totalWeight <= 0 {
		totalWeight = 1
	}
	targetSpanNs := int64(len(p3Exchanges))*p3PeriodNs + p3PeriodNs/2

	exchanges := make([]GeneratedExchange, 0, totalExchanges)
	bgTs := baseTs
	schedIdx := 0
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
		for schedIdx < len(scheduled) && scheduled[schedIdx].TimestampNs <= groupEndTs {
			exchanges = append(exchanges, scheduled[schedIdx])
			if bgTs < scheduled[schedIdx].TimestampNs+1_000_000 {
				bgTs = scheduled[schedIdx].TimestampNs + 1_000_000
				groupEndTs = bgTs
				if len(grp) > 1 {
					groupEndTs += 5_000_000
				}
			}
			schedIdx++
		}
		for m, item := range grp {
			if m > 0 {
				bgTs += 5_000_000
			}
			item.TimestampNs = bgTs
			exchanges = append(exchanges, item)
		}
	}
	for schedIdx < len(scheduled) {
		if scheduled[schedIdx].TimestampNs < bgTs {
			scheduled[schedIdx].TimestampNs = bgTs + 1_000_000
			bgTs = scheduled[schedIdx].TimestampNs
		}
		exchanges = append(exchanges, scheduled[schedIdx])
		schedIdx++
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

// SplitLiveSalves découpe une campagne en micro-salves respectant la bride live OVH (<= 200 paquets req+resp et <= 5 QPS).
func SplitLiveSalves(exchanges []GeneratedExchange, maxPacketsPerSalve int, maxQPS int) ([][]GeneratedExchange, error) {
	if len(exchanges) == 0 || maxPacketsPerSalve <= 0 || maxPacketsPerSalve > 200 || maxQPS <= 0 || maxQPS > 5 {
		return nil, ErrLiveRateContract
	}
	maxExPerSalve := maxPacketsPerSalve / 2
	if maxExPerSalve <= 0 {
		return nil, ErrLiveRateContract
	}
	var salves [][]GeneratedExchange
	for i := 0; i < len(exchanges); i += maxExPerSalve {
		end := min(i+maxExPerSalve, len(exchanges))
		chunk := make([]GeneratedExchange, end-i)
		copy(chunk, exchanges[i:end])
		salves = append(salves, chunk)
	}
	return salves, nil
}
