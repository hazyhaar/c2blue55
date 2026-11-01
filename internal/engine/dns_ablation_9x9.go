package engine

import (
	"errors"
	"math"
	"strings"
)

// Codes de raison médico-légale des 4 motifs connus (KNOWN_BASELINE).
const (
	ReasonM01LongMultiLabel   = "REASON_M01_LONG_MULTILABEL"
	ReasonM02HighShannonQName = "REASON_M02_HIGH_SHANNON_QNAME"
	ReasonM03MonoApexBurst    = "REASON_M03_MONO_APEX_BURST"
	ReasonM04DGANXDomain      = "REASON_M04_DGA_NXDOMAIN"
)

// Motif8EvalPoint décrit une observation unitaire soumise au banc 9x9 et à l'ablation N vs N+1.
type Motif8EvalPoint struct {
	PacketIndex int
	TimestampNs int64
	TrueClass   string // "BENIGN", "M-01", "M-02", "M-03", "M-04", "P1", "P2", "P3", "P4"
	DomainApex  string
	Subdomain   string
	QType       uint16
	RCode       uint8
	RDataLen    int
	RDataEnt    float32
}

// Confusion9x9Report résume la matrice de confusion 9x9 et le test d'ablation N vs N+1.
type Confusion9x9Report struct {
	Classes                []string                  `json:"classes"`
	MatrixN1               map[string]map[string]int `json:"matrix_n1"`
	RecallBaselineN        map[string]float64        `json:"recall_baseline_n"`
	RecallExtendedN1       map[string]float64        `json:"recall_extended_n1"`
	BenignFPR              float64                   `json:"benign_fpr"`
	CrossConfusionM02P2    int                       `json:"cross_confusion_m02_p2"`
	RollupP4PollutionCount int                       `json:"rollup_p4_pollution_count"`
	AblationPass           bool                      `json:"ablation_pass"`
}

func shannonAndCard(s string) (float64, int, bool) {
	var counts [256]int
	n := 0
	allHex := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			continue
		}
		counts[c]++
		n++
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			allHex = false
		}
	}
	if n == 0 {
		return 0, 0, false
	}
	var h float64
	card := 0
	nf := float64(n)
	for _, c := range counts {
		if c > 0 {
			card++
			p := float64(c) / nf
			h -= p * math.Log2(p)
		}
	}
	return h, card, allHex
}

func isDGAConsonantSuspect(sub string) bool {
	if IsRFCUnderscoreSubdomain(sub) {
		return false
	}
	run := 0
	maxRun := 0
	for i := 0; i < len(sub); i++ {
		c := sub[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c < 'a' || c > 'z' {
			run = 0
			continue
		}
		if c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u' || c == 'y' {
			run = 0
		} else {
			run++
			if run > maxRun {
				maxRun = run
			}
		}
	}
	return maxRun >= 5 && len(sub) >= 12
}

// EvaluateConfusion9x9AndAblation évalue la matrice de confusion 9x9 ("BENIGN", "M-01".."M-04", "P1".."P4")
// et vérifie l'ablation N (KNOWN_BASELINE seul) vs N+1 (KNOWN_BASELINE + NEW_GHSA) avec isolation consumed de P4.
func EvaluateConfusion9x9AndAblation(obs []Motif8EvalPoint) (Confusion9x9Report, error) {
	if len(obs) == 0 {
		return Confusion9x9Report{}, errors.New("engine: observations vides pour EvaluateConfusion9x9AndAblation")
	}

	classes := []string{"BENIGN", "M-01", "M-02", "M-03", "M-04", "P1", "P2", "P3", "P4"}
	matrixN1 := make(map[string]map[string]int, len(classes))
	for _, c1 := range classes {
		matrixN1[c1] = make(map[string]int, len(classes))
	}

	// Pré-passe d'agrégation par domaine parent et par ClientIP (pour M-03, M-04, P3 et P4 qualifié).
	apexQueries := make(map[string]int)
	apexDistinctSubs := make(map[string]map[string]bool)
	apexFastIntervals := make(map[string]int)
	apexLastTs := make(map[string]int64)
	apexIntervals := make(map[string][]int64)
	apexQTypes := make(map[string][]uint16)
	distinctNXDGA := make(map[string]bool)

	for _, pt := range obs {
		if IsRFCUnderscoreSubdomain(pt.Subdomain) {
			continue
		}
		apexQueries[pt.DomainApex]++
		if apexDistinctSubs[pt.DomainApex] == nil {
			apexDistinctSubs[pt.DomainApex] = make(map[string]bool)
		}
		apexDistinctSubs[pt.DomainApex][pt.Subdomain] = true

		if prev, ok := apexLastTs[pt.DomainApex]; ok {
			dt := pt.TimestampNs - prev
			if dt >= 0 && dt <= 50_000_000 {
				apexFastIntervals[pt.DomainApex]++
			}
			apexIntervals[pt.DomainApex] = append(apexIntervals[pt.DomainApex], dt)
		}
		apexLastTs[pt.DomainApex] = pt.TimestampNs
		apexQTypes[pt.DomainApex] = append(apexQTypes[pt.DomainApex], pt.QType)

		if pt.RCode == 3 && isDGAConsonantSuspect(pt.Subdomain) {
			distinctNXDGA[pt.Subdomain+"."+pt.DomainApex] = true
		}
	}

	// Qualification stricte des parents éligibles au rollup P4 (consumed == false, RCode == 0, 1 <= n_p <= 3, SubLen < 48).
	qualifiedP4Parents := make(map[string]bool)
	rollupPollution := 0
	for _, pt := range obs {
		if IsRFCUnderscoreSubdomain(pt.Subdomain) || pt.RCode != 0 {
			continue
		}
		h, card, allHex := shannonAndCard(pt.Subdomain)
		isM01 := len(pt.Subdomain) >= 48 && strings.Contains(pt.Subdomain, ".")
		isP2 := allHex && len(pt.Subdomain) >= 24 && len(pt.Subdomain) <= 36 && h < 4.00
		isM02 := !isP2 && card > 16 && h >= 4.10
		isM03 := len(apexDistinctSubs[pt.DomainApex]) >= 6 && apexFastIntervals[pt.DomainApex] >= 4
		isP1 := pt.RDataLen >= 200 && pt.RDataEnt > 4.0

		// Masque de consommation amont (opus-5-5 / glm-5.3 / argon) :
		if isM01 || isM02 || isM03 || isP1 || isP2 {
			continue
		}
		if apexQueries[pt.DomainApex] >= 1 && apexQueries[pt.DomainApex] <= 3 && len(pt.Subdomain) >= 14 && len(pt.Subdomain) < 24 && h >= 3.30 {
			qualifiedP4Parents[pt.DomainApex] = true
			if pt.TrueClass == "M-01" || pt.TrueClass == "M-02" || pt.TrueClass == "M-04" || pt.TrueClass == "P2" {
				rollupPollution++
			}
		}
	}

	totalByClass := make(map[string]int)
	hitsN := make(map[string]int)
	hitsN1 := make(map[string]int)
	benignFP := 0

	for _, pt := range obs {
		totalByClass[pt.TrueClass]++

		if IsRFCUnderscoreSubdomain(pt.Subdomain) {
			matrixN1[pt.TrueClass]["BENIGN"]++
			continue
		}

		h, card, allHex := shannonAndCard(pt.Subdomain)
		predN := "BENIGN"
		switch {
		case pt.RCode == 3 && isDGAConsonantSuspect(pt.Subdomain) && len(distinctNXDGA) >= 3:
			predN = "M-04"
		case len(apexDistinctSubs[pt.DomainApex]) >= 6 && apexFastIntervals[pt.DomainApex] >= 4:
			predN = "M-03"
		case len(pt.Subdomain) >= 48 && strings.Contains(pt.Subdomain, "."):
			predN = "M-01"
		case !(allHex && len(pt.Subdomain) >= 24 && len(pt.Subdomain) <= 36) && card > 16 && h >= 4.10:
			predN = "M-02"
		}

		predN1 := predN
		if predN1 == "BENIGN" {
			switch {
			case pt.RDataLen >= 200 && pt.RDataEnt > 4.0:
				predN1 = "P1"
			case allHex && len(pt.Subdomain) >= 24 && len(pt.Subdomain) <= 36 && h < 4.00:
				predN1 = "P2"
			default:
				p3 := ComputeEpisodeP3TimingFeatures(apexIntervals[pt.DomainApex], apexQTypes[pt.DomainApex], 50_000_000)
				if p3.InterArrivalCV < 0.12 && p3.MarkovEntropy > 0.40 && len(apexQTypes[pt.DomainApex]) >= 5 {
					predN1 = "P3"
				} else if qualifiedP4Parents[pt.DomainApex] && len(qualifiedP4Parents) >= 4 {
					predN1 = "P4"
				}
			}
		}

		if predN == pt.TrueClass && pt.TrueClass != "BENIGN" {
			hitsN[pt.TrueClass]++
		}
		if predN1 == pt.TrueClass && pt.TrueClass != "BENIGN" {
			hitsN1[pt.TrueClass]++
		}
		if pt.TrueClass == "BENIGN" && predN1 != "BENIGN" {
			benignFP++
		}
		matrixN1[pt.TrueClass][predN1]++
	}

	recallN := make(map[string]float64)
	recallN1 := make(map[string]float64)
	allPass := benignFP == 0 && rollupPollution == 0

	for _, fam := range []string{"M-01", "M-02", "M-03", "M-04", "P1", "P2", "P3", "P4"} {
		tot := totalByClass[fam]
		if tot > 0 {
			recallN[fam] = float64(hitsN[fam]) / float64(tot)
			recallN1[fam] = float64(hitsN1[fam]) / float64(tot)
		}
		if fam[0] == 'M' && (recallN[fam] < 0.95 || recallN1[fam] < 0.95) {
			allPass = false
		}
		if fam[0] == 'P' && (recallN[fam] != 0.0 || recallN1[fam] < 0.95) {
			allPass = false
		}
	}

	crossM02P2 := matrixN1["M-02"]["P2"] + matrixN1["P2"]["M-02"]
	if crossM02P2 != 0 {
		allPass = false
	}

	var benignFPR float64
	if totalByClass["BENIGN"] > 0 {
		benignFPR = float64(benignFP) / float64(totalByClass["BENIGN"])
	}

	return Confusion9x9Report{
		Classes:                classes,
		MatrixN1:               matrixN1,
		RecallBaselineN:        recallN,
		RecallExtendedN1:       recallN1,
		BenignFPR:              benignFPR,
		CrossConfusionM02P2:    crossM02P2,
		RollupP4PollutionCount: rollupPollution,
		AblationPass:           allPass,
	}, nil
}
