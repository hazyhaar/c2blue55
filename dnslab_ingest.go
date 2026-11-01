package c2blue55

import (
	"bytes"
	"math"
	"strings"

	"github.com/hazyhaar/c2blue55/internal/engine"
)

// LabeledDNSQueryView est une vue DNS prête pour la cascade, portant la
// provenance de la question dans le run de laboratoire.
type LabeledDNSQueryView struct {
	View             engine.DNSQueryView
	RunID            string
	Label            string
	Record           uint32
	Timestamp        uint64
	ClientIP         [16]byte
	Grammar          QNameGrammarProfile
	NonLDHBurstBlock bool
	NonLDHReason     string
}

// RedhostLabRun rassemble le manifeste, les comptes intégraux de la capture et
// les vues étiquetées d'un run ; len(Views) == Stats.Accepted.
type RedhostLabRun struct {
	Manifest RedhostLabManifest
	Stats    PCAPIngestStats
	Views    []LabeledDNSQueryView
}

// IngestRedhostLabRun charge le manifeste puis la capture et construit une vue
// étiquetée par question acceptée, avec SubCardinality calculée sur le run
// (sous-domaines distincts sous le même parent, minimum 1).
func IngestRedhostLabRun(pcapPath, manifestPath string) (RedhostLabRun, error) {
	manifest, err := LoadRedhostLabManifest(manifestPath)
	if err != nil {
		return RedhostLabRun{}, err
	}
	run := RedhostLabRun{Manifest: manifest}
	parents := make([]string, 0)
	counts := make(map[string]uint32)
	seen := make(map[struct{ parent, sub string }]bool)
	run.Stats, err = ReadPCAPDNSQuestions(pcapPath, func(meta PCAPQuestionMeta, ev *DNSEvent) error {
		parent := strings.Clone(strings.ToLower(ev.Parent()))
		sub := strings.Clone(strings.ToLower(ev.Sub()))
		parents = append(parents, parent)
		key := struct{ parent, sub string }{parent, sub}
		if !seen[key] {
			seen[key] = true
			counts[parent]++
		}
		run.Views = append(run.Views, LabeledDNSQueryView{
			View: engine.DNSQueryView{
				FQDN:            bytes.Clone(ev.Name[:ev.NameLen]),
				Subdomain:       bytes.Clone(ev.Subdomain[:ev.SubdomainLen]),
				SLD:             bytes.Clone(ev.SLD[:ev.SLDLen]),
				TLD:             bytes.Clone(ev.TLD[:ev.TLDLen]),
				QType:           ev.QType,
				LabelCount:      ev.LabelCount,
				MaxLabelLen:     ev.MaxLabelLen,
				HasEncodingChar: ev.HasEncoding,
			},
			RunID:     manifest.RunID,
			Label:     manifest.Label,
			Record:    meta.Record,
			Timestamp: meta.Timestamp,
			ClientIP:  ev.ClientIP,
		})
		return nil
	})
	if err != nil {
		return RedhostLabRun{}, err
	}
	for index := range run.Views {
		run.Views[index].View.SubCardinality = max(counts[parents[index]], 1)
	}
	return run, nil
}

// IngestRedhostLabRunTolerant charge le manifeste puis la capture via
// ReadPCAPDNSQuestionsTolerant et annote chaque vue hors LDH par NonLDHBurstGuard.
func IngestRedhostLabRunTolerant(pcapPath, manifestPath string) (RedhostLabRun, error) {
	manifest, err := LoadRedhostLabManifest(manifestPath)
	if err != nil {
		return RedhostLabRun{}, err
	}
	run := RedhostLabRun{Manifest: manifest}
	parents := make([]string, 0)
	cardinalites := make(map[string]uint32)
	dejaVus := make(map[struct{ parent, sub string }]bool)
	var garde NonLDHBurstGuard

	run.Stats, err = ReadPCAPDNSQuestionsTolerant(pcapPath, func(meta PCAPQuestionMeta, ev *DNSEvent) error {
		parent := strings.Clone(strings.ToLower(ev.Parent()))
		sub := strings.Clone(strings.ToLower(ev.Sub()))
		parents = append(parents, parent)
		cle := struct{ parent, sub string }{parent, sub}
		if !dejaVus[cle] {
			dejaVus[cle] = true
			cardinalites[parent]++
		}
		var instantNs int64
		if meta.Timestamp <= uint64(math.MaxInt64/1000) {
			instantNs = int64(meta.Timestamp) * 1000
		} else {
			instantNs = math.MaxInt64
		}
		decisionGarde := garde.Observe(
			ev.ParentDomain[:ev.ParentDomainLen],
			ev.Subdomain[:ev.SubdomainLen],
			ev.Grammar,
			ev.QType,
			instantNs,
		)
		run.Views = append(run.Views, LabeledDNSQueryView{
			View: engine.DNSQueryView{
				FQDN:            bytes.Clone(ev.Name[:ev.NameLen]),
				Subdomain:       bytes.Clone(ev.Subdomain[:ev.SubdomainLen]),
				SLD:             bytes.Clone(ev.SLD[:ev.SLDLen]),
				TLD:             bytes.Clone(ev.TLD[:ev.TLDLen]),
				QType:           ev.QType,
				LabelCount:      ev.LabelCount,
				MaxLabelLen:     ev.MaxLabelLen,
				HasEncodingChar: ev.HasEncoding,
			},
			RunID:            manifest.RunID,
			Label:            manifest.Label,
			Record:           meta.Record,
			Timestamp:        meta.Timestamp,
			ClientIP:         ev.ClientIP,
			Grammar:          ev.Grammar,
			NonLDHBurstBlock: decisionGarde.Hostile,
			NonLDHReason:     decisionGarde.Reason,
		})
		return nil
	})
	if err != nil {
		return RedhostLabRun{}, err
	}
	for index := range run.Views {
		run.Views[index].View.SubCardinality = max(cardinalites[parents[index]], 1)
	}
	return run, nil
}

// QueryViews rend les vues nues dans l'ordre des enregistrements, pour
// engine.DiscoverRedhostPatterns.
func (r *RedhostLabRun) QueryViews() []engine.DNSQueryView {
	views := make([]engine.DNSQueryView, len(r.Views))
	for index := range r.Views {
		views[index] = r.Views[index].View
	}
	return views
}
