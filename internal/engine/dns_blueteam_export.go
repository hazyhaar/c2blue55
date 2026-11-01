package engine

import (
	"errors"
	"fmt"
)

// PhysicalInvariantBounds regroupe les bornes physiques utilisées pour
// paramétrer les règles de détection exportées vers le Blue Team.
type PhysicalInvariantBounds struct {
	MinRDataBytes      int     `json:"min_rdata_bytes"`
	MinDownlinkEntropy float32 `json:"min_downlink_entropy"`
	MinSubdomainLen    int     `json:"min_subdomain_len"`
	MaxBeaconCV        float32 `json:"max_beacon_cv"`
	MinHighEntParents  int     `json:"min_high_ent_parents"`
}

// BlueTeamBundle contient les artefacts de détection générés à partir d'une
// preuve OOS validée.
type BlueTeamBundle struct {
	SigmaRulesYAML string   `json:"sigma_rules_yaml"`
	SuricataRules  string   `json:"suricata_rules"`
	CoveredMotifs  []string `json:"covered_motifs"`
}

// blueTeamMotifs liste les motifs DNS couverts par l'export.
var blueTeamMotifs = []string{"P1", "P2", "P3", "P4"}

// DefaultPhysicalBounds renvoie les bornes physiques de référence.
func DefaultPhysicalBounds() PhysicalInvariantBounds {
	return PhysicalInvariantBounds{
		MinRDataBytes:      200,
		MinDownlinkEntropy: 4.5,
		MinSubdomainLen:    24,
		MaxBeaconCV:        0.15,
		MinHighEntParents:  4,
	}
}

// ExportBlueTeamArtifacts génère les règles Sigma et Suricata couvrant les
// motifs P1 à P4, à condition que la preuve OOS soit complète et validée.
func ExportBlueTeamArtifacts(proof OOSPatternProof, bounds PhysicalInvariantBounds) (BlueTeamBundle, error) {
	if !proof.AllPass || len(proof.Families) < 4 {
		return BlueTeamBundle{}, errors.New("engine: preuve OOS incomplète ou non validée")
	}

	for _, id := range blueTeamMotifs {
		f, ok := proof.Families[id]
		if !ok || f.Recall < 0.90 || f.FalsePositives != 0 {
			return BlueTeamBundle{}, fmt.Errorf("engine: motif %s absent ou non conforme (recall=%.2f, faux positifs=%d)", id, f.Recall, f.FalsePositives)
		}
	}

	if bounds.MinRDataBytes <= 0 {
		bounds = DefaultPhysicalBounds()
	}

	sigma := fmt.Sprintf(sigmaRulesTemplate,
		bounds.MinRDataBytes,
		bounds.MinDownlinkEntropy,
		bounds.MinSubdomainLen,
		bounds.MaxBeaconCV,
		bounds.MinHighEntParents,
	)

	suricata := fmt.Sprintf(suricataRulesTemplate,
		bounds.MinRDataBytes,
		bounds.MinDownlinkEntropy,
		bounds.MinSubdomainLen,
		bounds.MaxBeaconCV,
		bounds.MinHighEntParents,
	)

	return BlueTeamBundle{
		SigmaRulesYAML: sigma,
		SuricataRules:  suricata,
		CoveredMotifs:  []string{"P1", "P2", "P3", "P4"},
	}, nil
}

const sigmaRulesTemplate = `title: C2BLUE55 DNS P1 - RDATA volumineux
status: experimental
description: Motif P1, RDATA >= %[1]d octets, exclusions RFC conservées
logsource:
    category: dns
detection:
    selection:
        ResponseLength|gte: %[1]d
    filter_rfc:
        QueryName|contains:
            - '_domainkey'
            - '_acme-challenge'
    condition: selection and not filter_rfc
level: high
---
title: C2BLUE55 DNS P2 - Entropie descendante élevée
status: experimental
description: Motif P2, entropie de la réponse >= %[2]g, exclusions RFC conservées
logsource:
    category: dns
detection:
    selection:
        ResponseEntropy|gte: %[2]g
    filter_rfc:
        QueryName|contains:
            - '_domainkey'
            - '_acme-challenge'
    condition: selection and not filter_rfc
level: high
---
title: C2BLUE55 DNS P3 - Sous-domaine long à faible variance temporelle
status: experimental
description: Motif P3, sous-domaine >= %[3]d caractères, CV inter-requêtes <= %[4]g, exclusions RFC conservées
logsource:
    category: dns
detection:
    selection:
        QueryName|re: '^[a-z0-9]{%[3]d,}\.'
        InterQueryCV|lte: %[4]g
    filter_rfc:
        QueryName|contains:
            - '_domainkey'
            - '_acme-challenge'
    condition: selection and not filter_rfc
level: high
---
title: C2BLUE55 DNS P4 - Parents à haute entropie
status: experimental
description: Motif P4, nombre de parents à haute entropie >= %[5]d, exclusions RFC conservées
logsource:
    category: dns
detection:
    selection:
        HighEntropyParentCount|gte: %[5]d
    filter_rfc:
        QueryName|contains:
            - '_domainkey'
            - '_acme-challenge'
    condition: selection and not filter_rfc
level: high
`

const suricataRulesTemplate = `alert dns any any -> any any (msg:"C2BLUE55 P1 RDATA volumineux >= %[1]d octets"; dns.query; content:!"_domainkey"; content:!"_acme-challenge"; dsize:>%[1]d; classtype:trojan-activity; sid:9550001; rev:1;)
alert dns any any -> any any (msg:"C2BLUE55 P2 entropie descendante >= %[2]g"; dns.query; content:!"_domainkey"; content:!"_acme-challenge"; dns.rrtype:TXT; classtype:trojan-activity; sid:9550002; rev:1;)
alert dns any any -> any any (msg:"C2BLUE55 P3 sous-domaine >= %[3]d caractères, CV <= %[4]g"; dns.query; content:!"_domainkey"; content:!"_acme-challenge"; pcre:"/^[a-z0-9]{%[3]d,}\./i"; classtype:trojan-activity; sid:9550003; rev:1;)
alert dns any any -> any any (msg:"C2BLUE55 P4 parents à haute entropie >= %[5]d"; dns.query; content:!"_domainkey"; content:!"_acme-challenge"; threshold:type both, track by_src, count %[5]d, seconds 300; classtype:trojan-activity; sid:9550004; rev:1;)
`
