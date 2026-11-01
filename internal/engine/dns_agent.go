// Package engine — dns_agent.go
// Agent #24 : Détection unifiée de DNS Tunneling (sous-domaines) et DGA (domaines apex)
// sur double disquette .c2book scellée HMAC-SHA256, évaluation Cold-Family Split et
// découverte de nouveaux motifs sur le banc expérimental redhost (mythos).
package engine

import (
	"bufio"
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hazyhaar/c2blue55/internal/goclassifier"
)

const (
	// FloppyFamilyDNSTunnel identifie la disquette dédiée aux canaux d'exfiltration par sous-domaine.
	FloppyFamilyDNSTunnel uint16 = 2
	// FloppyFamilyDNSDGA identifie la disquette dédiée aux domaines apex générés algorithmiquement (DGA).
	FloppyFamilyDNSDGA uint16 = 4
)

// DNSQueryView transporte sans allocation les tranches découpées d'une requête DNS
// (binaire RFC 1035 ou QNAME textuel) vers l'évaluateur bi-tête du Core 2.
type DNSQueryView struct {
	FQDN            []byte
	Subdomain       []byte
	SLD             []byte
	TLD             []byte
	QType           uint16
	LabelCount      uint8
	MaxLabelLen     uint8
	HasEncodingChar bool
	SubCardinality  uint32
}

// ColdSplitMetrics rassemble les comptes bruts opposables et l'AUC sur une partition
// tenue à l'écart (familles inconnues à l'entraînement).
type ColdSplitMetrics struct {
	Total             int
	MajorityClassRate float64
	TP                int
	FP                int
	TN                int
	FN                int
	QuarantineHostile int
	QuarantineBenign  int
	L0Blocks          int
	L1aPasses         int
	L1bBlocks         int
	AUC               float64
}

func matchDiskKeywordZeroAlloc(d *FloppyDisk, payload []byte) bool {
	if d == nil || len(payload) == 0 || len(d.Keywords) == 0 {
		return false
	}
	for i := range d.Keywords {
		kw := d.Keywords[i]
		kLen := len(kw)
		if kLen == 0 || len(payload) < kLen {
			continue
		}
		limit := len(payload) - kLen
		for pos := 0; pos <= limit; pos++ {
			if equalFoldASCII(payload[pos:pos+kLen], kw) {
				return true
			}
		}
	}
	return false
}

func evalSingleDNSFloppy(features *[EmbeddingDim]float32, disk *FloppyDisk) CascadeVerdict {
	var v CascadeVerdict
	v.Stage = StageL1a
	v.Action = VerdictPass

	var bitcode [codebookWords]uint64
	QuantizeFHT512(features[:], &bitcode)

	if probe := disk.Probe(); probe != nil {
		stats, err := probe.Probe(features[:], 0, 1)
		if err == nil {
			if stats.Verdict == goclassifier.ProbeConfirm && !disk.nearThreat(&bitcode) {
				v.Action = VerdictPass
				return v
			} else if stats.Verdict == goclassifier.ProbeAnomaly {
				v.Flags |= 0x0004
			}
		}
	}

	v.Stage = StageL1b

	match, dist, found := disk.SearchCentroid(&bitcode, 128)
	if found {
		v.HammingDist = dist
		v.ThreatID = match.ThreatID
		if dist <= disk.BlockRadius() {
			v.Action = VerdictBlock
			v.Flags |= 0x0002
			v.ConfidenceQ8 = uint16((128 - dist) * 2)
			return v
		}
	}

	predClass, _, conforms := disk.PredictINT8(features[:])
	if predClass == 1 && conforms {
		v.Action = VerdictBlock
		v.Flags |= 0x0002
		v.ConfidenceQ8 = 220
		return v
	}
	if predClass == 1 && !conforms {
		v.Action = VerdictQuarantine
		v.Flags |= 0x0004
		v.ConfidenceQ8 = 128
		return v
	}

	return v
}

// EvaluateDNSView évalue sans allocation (0 B/op) une requête DNS découpée en
// aiguillant la tranche Subdomain vers tunnelDisk (si len(Subdomain) > 0) et le
// label enregistrable SLD vers dgaDisk, selon la monotonie défensive L0 -> L1a -> L1b.
func EvaluateDNSView(view DNSQueryView, tunnelDisk, dgaDisk *FloppyDisk) CascadeVerdict {
	if view.HasEncodingChar || dnsHasEncodingChars(view.Subdomain) || dnsHasEncodingChars(view.FQDN) ||
		matchDiskKeywordZeroAlloc(tunnelDisk, view.FQDN) || matchDiskKeywordZeroAlloc(tunnelDisk, view.Subdomain) ||
		matchDiskKeywordZeroAlloc(dgaDisk, view.FQDN) || matchDiskKeywordZeroAlloc(dgaDisk, view.SLD) {
		return CascadeVerdict{
			Stage:        StageL0,
			Action:       VerdictBlock,
			Flags:        0x0002,
			ConfidenceQ8: 256,
		}
	}

	var vTunnel CascadeVerdict
	hasTunnelEval := false

	if len(view.Subdomain) > 0 && tunnelDisk != nil {
		var tunnelFeatures [EmbeddingDim]float32
		if ExtractDNSTunnel512(view.Subdomain, view.QType, view.LabelCount, view.MaxLabelLen, view.SubCardinality, tunnelFeatures[:]) {
			vTunnel = evalSingleDNSFloppy(&tunnelFeatures, tunnelDisk)
			hasTunnelEval = true
			if vTunnel.Action == VerdictBlock || dgaDisk == nil || len(view.SLD) == 0 {
				return vTunnel
			}
		}
	}

	if len(view.SLD) > 0 && dgaDisk != nil {
		var dgaFeatures [EmbeddingDim]float32
		if ExtractDNSDGA512(view.SLD, view.TLD, dgaFeatures[:]) {
			vDGA := evalSingleDNSFloppy(&dgaFeatures, dgaDisk)
			if !hasTunnelEval {
				return vDGA
			}
			// Monotonie défensive : le verdict le plus sévère l'emporte toujours.
			if vDGA.Action == VerdictBlock {
				return vDGA
			}
			if vTunnel.Action == VerdictQuarantine {
				return vTunnel
			}
			if vDGA.Action == VerdictQuarantine {
				return vDGA
			}
			return vTunnel
		}
	}

	if hasTunnelEval {
		return vTunnel
	}
	return CascadeVerdict{Stage: StageL0, Action: VerdictPass}
}

// splitDNSNameBytes découpe sans allocation un nom de domaine textuel en
// Subdomain, SLD, TLD, ParentDomain et métadonnées structurelles.
func splitDNSNameBytes(qname []byte) (sub, sld, tld, parent []byte, labelCount, maxLabelLen uint8, hasEnc bool, ok bool) {
	n := len(qname)
	for n > 0 && (qname[n-1] == '.' || qname[n-1] == '\r' || qname[n-1] == '\n' || qname[n-1] == ' ') {
		n--
	}
	if n == 0 || n > 253 {
		return nil, nil, nil, nil, 0, 0, false, false
	}
	qname = qname[:n]

	var offsets [128]uint8
	lStart := 0
	lCount := 0
	maxLen := 0

	for i := range n {
		b := qname[i]
		if b == '.' {
			lLen := i - lStart
			if lLen == 0 || lLen > 63 {
				return nil, nil, nil, nil, 0, 0, false, false
			}
			if lCount < len(offsets) {
				offsets[lCount] = uint8(lStart)
			}
			lCount++
			if lLen > maxLen {
				maxLen = lLen
			}
			lStart = i + 1
			continue
		}
		if b == '+' || b == '/' || b == '=' {
			hasEnc = true
		}
	}
	lastLen := n - lStart
	if lastLen == 0 || lastLen > 63 {
		return nil, nil, nil, nil, 0, 0, false, false
	}
	if lCount < len(offsets) {
		offsets[lCount] = uint8(lStart)
	}
	lCount++
	if lastLen > maxLen {
		maxLen = lastLen
	}

	if lCount < 2 || lCount-2 >= len(offsets) {
		return nil, qname, nil, qname, uint8(lCount), uint8(maxLen), hasEnc, true
	}

	tldIdx := lCount - 1
	sldIdx := lCount - 2
	if lCount >= 3 {
		twoStart := int(offsets[lCount-2])
		suffixCand := qname[twoStart:n]
		for _, s := range twoLevelSuffixes {
			if len(suffixCand) == len(s) && equalFoldASCII(suffixCand, s) {
				tldIdx = lCount - 2
				sldIdx = lCount - 3
				break
			}
		}
	}

	parentStart := int(offsets[sldIdx])
	tldStart := int(offsets[tldIdx])
	parent = qname[parentStart:n]
	if tldStart > parentStart+1 {
		sld = qname[parentStart : tldStart-1]
	}
	tld = qname[tldStart:n]
	if parentStart > 1 {
		sub = qname[:parentStart-1]
	}
	return sub, sld, tld, parent, uint8(lCount), uint8(maxLen), hasEnc, true
}

func clampWeightInt8(v float32) int8 {
	if v > 127.0 {
		return 127
	}
	if v < -127.0 {
		return -127
	}
	return int8(v)
}

func buildEmpiricalDecisionHead(benignVecs, hostileVecs [][EmbeddingDim]float32) []DecisionClass {
	var meanBenign, meanHostile [EmbeddingDim]float32
	if len(benignVecs) > 0 {
		inv := 1.0 / float32(len(benignVecs))
		for i := range benignVecs {
			for d := range EmbeddingDim {
				meanBenign[d] += benignVecs[i][d] * inv
			}
		}
	}
	if len(hostileVecs) > 0 {
		inv := 1.0 / float32(len(hostileVecs))
		for i := range hostileVecs {
			for d := range EmbeddingDim {
				meanHostile[d] += hostileVecs[i][d] * inv
			}
		}
	}

	head := make([]DecisionClass, 2)
	for d := range EmbeddingDim {
		diff := (meanBenign[d] - meanHostile[d]) * 127.0
		w := clampWeightInt8(diff)
		head[0].Weights[d] = w
		head[1].Weights[d] = -w
	}

	// Calibrer Bias au point milieu entre le score moyen bénin et le score moyen hostile
	scoreOn := func(vecs [][EmbeddingDim]float32, cls *DecisionClass) float64 {
		if len(vecs) == 0 {
			return 0
		}
		var sum float64
		for i := range vecs {
			var acc int32
			for d := range EmbeddingDim {
				f := vecs[i][d]
				var q int32
				if f > 1.0 {
					q = 127
				} else if f < -1.0 {
					q = -127
				} else {
					q = int32(f * 127.0)
				}
				acc += q * int32(cls.Weights[d])
			}
			sum += float64(acc)
		}
		return sum / float64(len(vecs))
	}

	meanHostileOn1 := scoreOn(hostileVecs, &head[1])
	meanBenignOn1 := scoreOn(benignVecs, &head[1])
	mid1 := int32((meanHostileOn1 + meanBenignOn1) * 0.5)
	head[1].Bias = -mid1
	head[0].Bias = mid1

	adjHostile := (meanHostileOn1 - float64(mid1)) / (127.0 * float64(EmbeddingDim))
	if adjHostile > 0.02 {
		head[1].QHat = float32(adjHostile * 0.25)
	} else {
		head[1].QHat = 0.01
	}

	meanBenignOn0 := scoreOn(benignVecs, &head[0])
	adjBenign := (meanBenignOn0 + float64(mid1)) / (127.0 * float64(EmbeddingDim))
	if adjBenign > 0.02 {
		head[0].QHat = float32(adjBenign * 0.25)
	} else {
		head[0].QHat = 0.01
	}

	return head
}

func selectDNSPrototypes(class uint16, vecs [][EmbeddingDim]float32, maxCount int) []FloppyPrototype {
	n := len(vecs)
	if n == 0 {
		return nil
	}
	k := min(n, maxCount)
	out := make([]FloppyPrototype, 0, k)
	for i := range k {
		out = append(out, FloppyPrototype{
			Class:  class,
			Vector: vecs[i*n/k],
		})
	}
	return out
}

func isDynamicDNSParent(parent []byte) bool {
	switch string(parent) {
	case "ddns.net", "dyndns.org", "mooo.com", "dynserv.com", "yi.org",
		"no-ip.org", "no-ip.biz", "hopto.org", "zapto.org", "sytes.net":
		return true
	}
	return false
}

func extractDGACandidate(sub, sld, tld, parent []byte) (candSLD, candTLD []byte) {
	if len(sub) > 0 && isDynamicDNSParent(parent) {
		dot := 0
		for dot < len(sub) && sub[dot] != '.' {
			dot++
		}
		if dot > 0 {
			return sub[:dot], parent
		}
	}
	return sld, tld
}

func isDGATrainFamily(fam string) bool {
	switch fam {
	case "banjori", "emotet", "rovnix", "tinba", "Post",
		"ramnit", "pykspa_v1", "necurs", "qakbot", "murofet",
		"simda", "ranbyus", "pykspa", "shiotob/urlzone/bebloh", "gameover",
		"suppobox", "Volatile", "virut", "symmi":
		return true
	}
	return false
}

// coldSplitNeutralQType est le QType neutre (TypeA = 1) appliqué uniformément
// à toutes les lignes des fichiers CSV hors-ligne (netrack_dns/train.csv et test.csv)
// qui ne comportent pas de colonne QType, garantissant zéro fuite d'étiquette F-10
// et zéro décalage train/évaluation.
const coldSplitNeutralQType uint16 = 1

// BuildDNSFloppiesColdSplit compile sur données réelles (netrack_dns et abusayed_dga_full.csv)
// les deux disquettes floppy_dns_tunnel.c2book et floppy_dns_dga.c2book sous protocole
// Cold-Family Split, sans aucun nom de domaine du corpus en mot-clé L0.
func BuildDNSFloppiesColdSplit(dataDir, outDir string, hmacKey []byte) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	// Mots-clés L0 génériques d'infrastructure C2 hors corpus d'évaluation
	tunnelKeywords := []string{".onion", ".b33con", "dnscat2-", "iodine-c2"}
	dgaKeywords := []string{".onion", ".b33con"}

	// =========================================================================
	// 1. Forgerie de floppy_dns_tunnel.c2book (famille tuns.org exclue)
	// =========================================================================
	trainPath := filepath.Join(dataDir, "netrack_dns", "train.csv")
	tf, err := os.Open(trainPath)
	if err != nil {
		return fmt.Errorf("ouverture netrack_dns/train.csv: %w", err)
	}
	defer tf.Close()

	var tunnelHostileVecs [][EmbeddingDim]float32
	var tunnelBenignVecs [][EmbeddingDim]float32
	var tunnelEntries []CodebookEntry

	perFamilyCount := map[string]int{}
	parentCard := map[string]uint32{}
	seenParentSub := map[string]bool{}
	threatID := uint32(2101)

	sc := bufio.NewScanner(tf)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		comma := strings.IndexByte(line, ',')
		if comma <= 0 || comma+1 >= len(line) {
			continue
		}
		label := line[:comma]
		domain := line[comma+1:]
		sub, sld, _, parent, labelCount, maxLabelLen, _, ok := splitDNSNameBytes([]byte(domain))
		if !ok {
			continue
		}
		parentStr := strings.ToLower(string(parent))
		// Cold-Family Split : exclure strictement tuns.org de l'entraînement
		if parentStr == "tuns.org" || strings.HasSuffix(parentStr, ".tuns.org") {
			continue
		}

		if len(sub) > 0 {
			key := parentStr + "\x00" + strings.ToLower(string(sub))
			if !seenParentSub[key] {
				seenParentSub[key] = true
				parentCard[parentStr]++
			}
		}
		card := max(parentCard[parentStr], 1)

		switch label {
		case "1":
			if len(sub) == 0 {
				continue
			}
			if perFamilyCount[parentStr] >= 600 {
				continue
			}
			var vec [EmbeddingDim]float32
			if !ExtractDNSTunnel512(sub, coldSplitNeutralQType, labelCount, maxLabelLen, card, vec[:]) {
				continue
			}
			perFamilyCount[parentStr]++
			var bitcode [codebookWords]uint64
			QuantizeFHT512(vec[:], &bitcode)
			tunnelEntries = append(tunnelEntries, CodebookEntry{
				Bitcode:   bitcode,
				ThreatID:  threatID,
				Subsystem: 3,
				Severity:  SeverityHigh,
			})
			threatID++
			tunnelHostileVecs = append(tunnelHostileVecs, vec)

		case "0":
			if len(tunnelBenignVecs) >= 2000 {
				continue
			}
			sampleSub := sub
			sampleLC := labelCount
			sampleMax := maxLabelLen
			if len(sampleSub) == 0 && len(sld) > 0 {
				// Dans train.csv, les domaines bénins sont en majorité apex :
				// leur SLD fournit un label lexical bénin authentique.
				sampleSub = sld
				sampleLC = 3
				sampleMax = uint8(len(sld))
			}
			if len(sampleSub) == 0 {
				continue
			}
			var vec [EmbeddingDim]float32
			if ExtractDNSTunnel512(sampleSub, coldSplitNeutralQType, sampleLC, sampleMax, card, vec[:]) {
				tunnelBenignVecs = append(tunnelBenignVecs, vec)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("lecture netrack_dns/train.csv: %w", err)
	}

	// =========================================================================
	// 2. Forgerie de floppy_dns_dga.c2book (15 familles DGA d'entraînement,
	//    toutes les autres familles DGA tenues à l'écart)
	// =========================================================================
	dgaPath := filepath.Join(dataDir, "abusayed_dga_full.csv")
	df, err := os.Open(dgaPath)
	if err != nil {
		return fmt.Errorf("ouverture abusayed_dga_full.csv: %w", err)
	}
	defer df.Close()

	var dgaHostileVecs [][EmbeddingDim]float32
	var dgaBenignVecs [][EmbeddingDim]float32
	var dgaEntries []CodebookEntry

	dgaFamilyCounts := map[string]int{}
	normalIdx := 0
	dgaThreatID := uint32(4101)

	dsc := bufio.NewScanner(df)
	dsc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	firstLine := true
	for dsc.Scan() {
		if firstLine {
			firstLine = false
			continue
		}
		line := strings.TrimSpace(dsc.Text())
		c1 := strings.IndexByte(line, ',')
		if c1 <= 0 {
			continue
		}
		rest := line[c1+1:]
		c2 := strings.IndexByte(rest, ',')
		if c2 <= 0 {
			continue
		}
		fam := line[:c1]
		domain := rest[:c2]
		kind := rest[c2+1:]

		sub, sld, tld, parent, lc, maxLen, _, ok := splitDNSNameBytes([]byte(domain))
		if !ok || len(sld) == 0 {
			continue
		}
		candSLD, candTLD := extractDGACandidate(sub, sld, tld, parent)

		if kind == "Normal" || fam == "none" {
			isTrainNormal := (normalIdx % 2) == 0
			normalIdx++
			if !isTrainNormal {
				continue
			}
			// Enrichir également le corpus bénin de sous-domaines réels pour tunnelDisk
			if len(sub) > 0 && len(tunnelBenignVecs) < 2500 {
				parentStr := strings.ToLower(string(parent))
				key := parentStr + "\x00" + strings.ToLower(string(sub))
				if !seenParentSub[key] {
					seenParentSub[key] = true
					parentCard[parentStr]++
				}
				card := max(parentCard[parentStr], 1)
				var tvec [EmbeddingDim]float32
				if ExtractDNSTunnel512(sub, coldSplitNeutralQType, lc, maxLen, card, tvec[:]) {
					tunnelBenignVecs = append(tunnelBenignVecs, tvec)
				}
			}
			if len(dgaBenignVecs) < 1600 {
				var vec [EmbeddingDim]float32
				if ExtractDNSDGA512(candSLD, candTLD, vec[:]) {
					dgaBenignVecs = append(dgaBenignVecs, vec)
				}
			}
		} else if kind == "DGA" {
			if !isDGATrainFamily(fam) {
				continue
			}
			if dgaFamilyCounts[fam] >= 80 {
				continue
			}
			var vec [EmbeddingDim]float32
			if !ExtractDNSDGA512(candSLD, candTLD, vec[:]) {
				continue
			}
			dgaFamilyCounts[fam]++
			var bitcode [codebookWords]uint64
			QuantizeFHT512(vec[:], &bitcode)
			dgaEntries = append(dgaEntries, CodebookEntry{
				Bitcode:   bitcode,
				ThreatID:  dgaThreatID,
				Subsystem: 3,
				Severity:  SeverityHigh,
			})
			dgaThreatID++
			dgaHostileVecs = append(dgaHostileVecs, vec)
		}

		if len(dgaBenignVecs) >= 1600 && len(dgaHostileVecs) >= 1100 {
			break
		}
	}
	if err := dsc.Err(); err != nil {
		return fmt.Errorf("lecture abusayed_dga_full.csv: %w", err)
	}

	// Sauvegarde de floppy_dns_tunnel.c2book
	tunnelHead := buildEmpiricalDecisionHead(tunnelBenignVecs, tunnelHostileVecs)
	tunnelProtos := append(selectDNSPrototypes(0, tunnelBenignVecs, 24), selectDNSPrototypes(1, tunnelHostileVecs, 24)...)
	tunnelRadius := CalibrateBlockRadius(tunnelEntries, tunnelBenignVecs, 0.005)
	tunnelOut := filepath.Join(outDir, "floppy_dns_tunnel.c2book")
	if err := SaveFloppyFile(tunnelOut, FloppyFamilyDNSTunnel, tunnelKeywords, tunnelEntries, tunnelHead, tunnelProtos, tunnelRadius, hmacKey); err != nil {
		return fmt.Errorf("sauvegarde floppy_dns_tunnel.c2book: %w", err)
	}

	// Sauvegarde de floppy_dns_dga.c2book
	dgaHead := buildEmpiricalDecisionHead(dgaBenignVecs, dgaHostileVecs)
	dgaProtos := append(selectDNSPrototypes(0, dgaBenignVecs, 24), selectDNSPrototypes(1, dgaHostileVecs, 24)...)
	dgaRadius := CalibrateBlockRadius(dgaEntries, dgaBenignVecs, 0.005)
	dgaOut := filepath.Join(outDir, "floppy_dns_dga.c2book")
	if err := SaveFloppyFile(dgaOut, FloppyFamilyDNSDGA, dgaKeywords, dgaEntries, dgaHead, dgaProtos, dgaRadius, hmacKey); err != nil {
		return fmt.Errorf("sauvegarde floppy_dns_dga.c2book: %w", err)
	}

	return nil
}

type scoredSample struct {
	score   float64
	hostile bool
}

func computeExactROC_AUC(samples []scoredSample) float64 {
	if len(samples) == 0 {
		return 0
	}
	slices.SortFunc(samples, func(a, b scoredSample) int {
		return cmp.Compare(a.score, b.score)
	})

	var nPos, nNeg int
	for _, s := range samples {
		if s.hostile {
			nPos++
		} else {
			nNeg++
		}
	}
	if nPos == 0 || nNeg == 0 {
		return 0
	}

	// Méthode de Mann-Whitney-Wilcoxon avec gestion exacte des ex-aequo
	var rankSumPos float64
	i := 0
	n := len(samples)
	for i < n {
		j := i + 1
		for j < n && samples[j].score == samples[i].score {
			j++
		}
		avgRank := float64(i+1+j) * 0.5
		posInTie := 0
		for k := i; k < j; k++ {
			if samples[k].hostile {
				posInTie++
			}
		}
		rankSumPos += float64(posInTie) * avgRank
		i = j
	}

	uStat := rankSumPos - float64(nPos)*float64(nPos+1)*0.5
	return uStat / (float64(nPos) * float64(nNeg))
}

func continuousFloppyThreatScore(features *[EmbeddingDim]float32, disk *FloppyDisk) float64 {
	if disk == nil || len(disk.Head) < 2 {
		return float64(features[aggregateBase+27])
	}
	cls0 := &disk.Head[0]
	cls1 := &disk.Head[1]
	var acc0 int32 = cls0.Bias
	var acc1 int32 = cls1.Bias
	for d := range EmbeddingDim {
		f := features[d]
		var q int32
		if f > 1.0 {
			q = 127
		} else if f < -1.0 {
			q = -127
		} else {
			q = int32(f * 127.0)
		}
		acc0 += q * int32(cls0.Weights[d])
		acc1 += q * int32(cls1.Weights[d])
	}
	margin := float64(acc1-acc0) / (254.0 * float64(EmbeddingDim))
	return 0.75*margin + 0.25*float64(features[aggregateBase+27])
}

func accumulateVerdictMetrics(m *ColdSplitMetrics, v CascadeVerdict, isHostile bool) {
	m.Total++
	switch v.Stage {
	case StageL0:
		if v.Action == VerdictBlock {
			m.L0Blocks++
		}
	case StageL1a:
		if v.Action == VerdictPass {
			m.L1aPasses++
		}
	case StageL1b:
		if v.Action == VerdictBlock {
			m.L1bBlocks++
		}
	}

	switch v.Action {
	case VerdictBlock:
		if isHostile {
			m.TP++
		} else {
			m.FP++
		}
	case VerdictQuarantine:
		if isHostile {
			m.QuarantineHostile++
		} else {
			m.QuarantineBenign++
		}
	default:
		if isHostile {
			m.FN++
		} else {
			m.TN++
		}
	}
}

func finalizeColdSplitMetrics(m *ColdSplitMetrics, posCount, negCount int, samples []scoredSample) {
	if m.Total > 0 {
		maj := max(posCount, negCount)
		m.MajorityClassRate = float64(maj) / float64(m.Total)
	}
	m.AUC = computeExactROC_AUC(samples)
}

// EvaluateDNSColdSplit évalue les deux disquettes compilées sur les familles tenues à l'écart
// (famille tuns.org exclue de l'entraînement pour le tunnel ; familles DGA exclues pour le DGA)
// et retourne les comptes bruts, le taux de la classe majoritaire et l'AUC hors-distribution.
func EvaluateDNSColdSplit(dataDir, floppyDir string, hmacKey []byte) (tunnelMetrics ColdSplitMetrics, dgaMetrics ColdSplitMetrics, err error) {
	tunnelDisk, err := LoadFloppyMmap(filepath.Join(floppyDir, "floppy_dns_tunnel.c2book"), hmacKey)
	if err != nil {
		return ColdSplitMetrics{}, ColdSplitMetrics{}, fmt.Errorf("ouverture floppy_dns_tunnel.c2book: %w", err)
	}
	defer tunnelDisk.Close()

	dgaDisk, err := LoadFloppyMmap(filepath.Join(floppyDir, "floppy_dns_dga.c2book"), hmacKey)
	if err != nil {
		return ColdSplitMetrics{}, ColdSplitMetrics{}, fmt.Errorf("ouverture floppy_dns_dga.c2book: %w", err)
	}
	defer dgaDisk.Close()

	// =========================================================================
	// 1. Évaluation Cold-Family Split Tunnel sur netrack_dns/test.csv
	//    (Seule la famille tuns.org est retenue côté hostile face aux bénins)
	// =========================================================================
	testPath := filepath.Join(dataDir, "netrack_dns", "test.csv")
	tf, err := os.Open(testPath)
	if err != nil {
		return ColdSplitMetrics{}, ColdSplitMetrics{}, fmt.Errorf("ouverture netrack_dns/test.csv: %w", err)
	}
	defer tf.Close()

	parentCard := map[string]uint32{}
	seenParentSub := map[string]bool{}
	var tunnelSamples []scoredSample
	var tunnelPos, tunnelNeg int

	sc := bufio.NewScanner(tf)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		comma := strings.IndexByte(line, ',')
		if comma <= 0 || comma+1 >= len(line) {
			continue
		}
		label := line[:comma]
		domain := line[comma+1:]
		sub, sld, tld, parent, lc, maxLen, hasEnc, ok := splitDNSNameBytes([]byte(domain))
		if !ok {
			continue
		}
		parentStr := strings.ToLower(string(parent))
		isHostile := label == "1"

		if isHostile {
			// Ne retenir que la famille tuns.org tenue à l'écart à l'entraînement
			if parentStr != "tuns.org" && !strings.HasSuffix(parentStr, ".tuns.org") {
				continue
			}
		}

		if len(sub) > 0 {
			key := parentStr + "\x00" + strings.ToLower(string(sub))
			if !seenParentSub[key] {
				seenParentSub[key] = true
				parentCard[parentStr]++
			}
		}
		card := max(parentCard[parentStr], 1)
		qtype := coldSplitNeutralQType

		view := DNSQueryView{
			FQDN:            []byte(domain),
			Subdomain:       sub,
			SLD:             sld,
			TLD:             tld,
			QType:           qtype,
			LabelCount:      lc,
			MaxLabelLen:     maxLen,
			HasEncodingChar: hasEnc,
			SubCardinality:  card,
		}

		v := EvaluateDNSView(view, tunnelDisk, nil)
		accumulateVerdictMetrics(&tunnelMetrics, v, isHostile)
		if isHostile {
			tunnelPos++
		} else {
			tunnelNeg++
		}

		var score float64
		if v.Stage == StageL0 && v.Action == VerdictBlock {
			score = 10.0
		} else if len(sub) > 0 {
			var feats [EmbeddingDim]float32
			if ExtractDNSTunnel512(sub, qtype, lc, maxLen, card, feats[:]) {
				score = continuousFloppyThreatScore(&feats, tunnelDisk)
			}
		} else {
			score = -2.0
		}
		tunnelSamples = append(tunnelSamples, scoredSample{score: score, hostile: isHostile})
	}
	if err := sc.Err(); err != nil {
		return ColdSplitMetrics{}, ColdSplitMetrics{}, fmt.Errorf("lecture netrack_dns/test.csv: %w", err)
	}
	finalizeColdSplitMetrics(&tunnelMetrics, tunnelPos, tunnelNeg, tunnelSamples)

	// =========================================================================
	// 2. Évaluation Cold-Family Split DGA sur abusayed_dga_full.csv
	//    (Uniquement les familles DGA exclues de l'entraînement + Normal tenus à l'écart)
	// =========================================================================
	dgaPath := filepath.Join(dataDir, "abusayed_dga_full.csv")
	df, err := os.Open(dgaPath)
	if err != nil {
		return ColdSplitMetrics{}, ColdSplitMetrics{}, fmt.Errorf("ouverture abusayed_dga_full.csv: %w", err)
	}
	defer df.Close()

	var dgaSamples []scoredSample
	var dgaPos, dgaNeg int
	heldOutFamCounts := map[string]int{}
	normalIdx := 0

	dsc := bufio.NewScanner(df)
	dsc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	firstLine := true
	for dsc.Scan() {
		if firstLine {
			firstLine = false
			continue
		}
		line := strings.TrimSpace(dsc.Text())
		c1 := strings.IndexByte(line, ',')
		if c1 <= 0 {
			continue
		}
		rest := line[c1+1:]
		c2 := strings.IndexByte(rest, ',')
		if c2 <= 0 {
			continue
		}
		fam := line[:c1]
		domain := rest[:c2]
		kind := rest[c2+1:]

		sub, sld, tld, parent, lc, maxLen, hasEnc, ok := splitDNSNameBytes([]byte(domain))
		if !ok || len(sld) == 0 {
			continue
		}
		candSLD, candTLD := extractDGACandidate(sub, sld, tld, parent)

		var isHostile bool
		if kind == "Normal" || fam == "none" {
			isHeldOutNormal := (normalIdx % 2) == 1
			normalIdx++
			if !isHeldOutNormal || dgaNeg >= 1500 {
				continue
			}
			isHostile = false
		} else if kind == "DGA" {
			if isDGATrainFamily(fam) {
				continue
			}
			if heldOutFamCounts[fam] >= 100 || dgaPos >= 1500 {
				continue
			}
			heldOutFamCounts[fam]++
			isHostile = true
		} else {
			continue
		}

		view := DNSQueryView{
			FQDN:            []byte(domain),
			Subdomain:       nil,
			SLD:             candSLD,
			TLD:             candTLD,
			QType:           1,
			LabelCount:      lc,
			MaxLabelLen:     maxLen,
			HasEncodingChar: hasEnc,
		}

		v := EvaluateDNSView(view, nil, dgaDisk)
		accumulateVerdictMetrics(&dgaMetrics, v, isHostile)
		if isHostile {
			dgaPos++
		} else {
			dgaNeg++
		}

		var feats [EmbeddingDim]float32
		var score float64
		if ExtractDNSDGA512(candSLD, candTLD, feats[:]) {
			score = continuousFloppyThreatScore(&feats, dgaDisk)
		}
		dgaSamples = append(dgaSamples, scoredSample{score: score, hostile: isHostile})

		if dgaPos >= 1500 && dgaNeg >= 1500 {
			break
		}
	}
	if err := dsc.Err(); err != nil {
		return ColdSplitMetrics{}, ColdSplitMetrics{}, fmt.Errorf("lecture abusayed_dga_full.csv: %w", err)
	}
	finalizeColdSplitMetrics(&dgaMetrics, dgaPos, dgaNeg, dgaSamples)

	return tunnelMetrics, dgaMetrics, nil
}

// DiscoverRedhostPatterns analyse un lot de requêtes capturées sur le serveur DNS
// expérimental redhost (mythos), isole les nouveaux motifs d'exfiltration ou de DGA
// non couverts par les centroïdes existants et produit les entrées CodebookEntry candidates.
func DiscoverRedhostPatterns(views []DNSQueryView, tunnelDisk, dgaDisk *FloppyDisk) ([]CodebookEntry, error) {
	var out []CodebookEntry
	nextThreatID := uint32(9001)

	alreadyCovered := func(code *[codebookWords]uint64, disk *FloppyDisk) bool {
		if disk != nil && disk.nearThreat(code) {
			return true
		}
		radius := int(FloppyDefaultBlockRadius)
		if disk != nil {
			radius = disk.BlockRadius()
		}
		for i := range out {
			if codebookHammingBounded(code, &out[i], radius) <= radius {
				return true
			}
		}
		return false
	}

	for _, v := range views {
		if len(v.Subdomain) > 0 {
			var feats [EmbeddingDim]float32
			if !ExtractDNSTunnel512(v.Subdomain, v.QType, v.LabelCount, v.MaxLabelLen, v.SubCardinality, feats[:]) {
				continue
			}
			// Score composite du sous-domaine (feats[31] stocké dans aggregateBase+27)
			compositeScore := feats[aggregateBase+27]
			isSuspicious := compositeScore > 0.10 ||
				len(v.Subdomain) >= 24 ||
				v.SubCardinality >= 16 ||
				v.QType == 10 || v.QType == 16
			if !isSuspicious {
				continue
			}
			var bitcode [codebookWords]uint64
			QuantizeFHT512(feats[:], &bitcode)
			if alreadyCovered(&bitcode, tunnelDisk) {
				continue
			}
			out = append(out, CodebookEntry{
				Bitcode:   bitcode,
				ThreatID:  nextThreatID,
				Subsystem: 3,
				Severity:  SeverityHigh,
			})
			nextThreatID++
		} else if len(v.SLD) > 0 {
			var feats [EmbeddingDim]float32
			if !ExtractDNSDGA512(v.SLD, v.TLD, feats[:]) {
				continue
			}
			if feats[aggregateBase+27] <= 0.20 {
				continue
			}
			var bitcode [codebookWords]uint64
			QuantizeFHT512(feats[:], &bitcode)
			if alreadyCovered(&bitcode, dgaDisk) {
				continue
			}
			out = append(out, CodebookEntry{
				Bitcode:   bitcode,
				ThreatID:  nextThreatID,
				Subsystem: 3,
				Severity:  SeverityHigh,
			})
			nextThreatID++
		}
	}

	return out, nil
}
