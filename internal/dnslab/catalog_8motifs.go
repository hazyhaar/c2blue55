package dnslab

// Catégories normatives du catalogue des 8 motifs DNS C2.
const (
	CategoryKnownBaseline = "KNOWN_BASELINE"
	CategoryNewGHSA       = "NEW_GHSA"
)

// PatternSpec documente un motif d'anomalie DNS émis par le laboratoire et détecté par c2blue55.
type PatternSpec struct {
	ID                 string `json:"id,omitempty"`
	Code               string `json:"code"`
	Category           string `json:"category"`
	Name               string `json:"name"`
	ToolRepresentative string `json:"tool_representative"`
	PhysicalInvariant  string `json:"physical_invariant"`
	ReasonCode         string `json:"reason_code,omitempty"`
	ExpectedReasonCode string `json:"expected_reason_code"`
	OrthogonalGuard    string `json:"orthogonal_guard,omitempty"`
	OrthogonalityGuard string `json:"orthogonality_guard"`
}

var catalog8Motifs = []PatternSpec{
	{
		Code:               "M-01",
		Category:           CategoryKnownBaseline,
		Name:               "Tunnel volumétrique à QNAME long multi-labels",
		ToolRepresentative: "dnscat2 / dns2tcp classique",
		PhysicalInvariant:  "SubdomainLen >= 48 octets et >= 2 sous-labels imbriqués (chunk1.chunk2.apex)",
		ExpectedReasonCode: "REASON_M01_LONG_MULTILABEL",
		OrthogonalityGuard: "Consommé en amont de P4 (SubdomainLen >= 48 exclu du rollup multi-parents)",
	},
	{
		Code:               "M-02",
		Category:           CategoryKnownBaseline,
		Name:               "Exfiltration QNAME à haute entropie de Shannon",
		ToolRepresentative: "Exfiltration chiffrée AES / Base64URL",
		PhysicalInvariant:  "Entropie de Shannon H >= 4.10 bits/octet et AlphabetCard > 16 symboles",
		ExpectedReasonCode: "REASON_M02_HIGH_SHANNON_QNAME",
		OrthogonalityGuard: "Séparation spectrale 2D contre P2 (AlphabetCard > 16 hors Hex [0-9a-f] et H >= 4.10)",
	},
	{
		Code:               "M-03",
		Category:           CategoryKnownBaseline,
		Name:               "Rafale rapide mono-domaine (Fast Burst Tunnel)",
		ToolRepresentative: "iodine / dns2tcp en transfert intensif",
		PhysicalInvariant:  ">= 6 sous-domaines distincts vers le même apex avec dt <= 50 ms (BurstIdleRatio élevé)",
		ExpectedReasonCode: "REASON_M03_MONO_APEX_BURST",
		OrthogonalityGuard: "Exclu de P4 par dépassement du plafond n_p <= 3 requêtes par domaine parent",
	},
	{
		Code:               "M-04",
		Category:           CategoryKnownBaseline,
		Name:               "Domaine généré algorithmiquement (DGA) & rafale NXDOMAIN",
		ToolRepresentative: "Botnets DGA (Ramnit / Conficker / Matsnu)",
		PhysicalInvariant:  "Conjonction par QNAME distinct : RCode == 3 (NXDOMAIN) ET séquence consonantique DGA (>= 5 consonnes consécutives) sur >= 3 QNAME distincts",
		ExpectedReasonCode: "REASON_M04_DGA_NXDOMAIN",
		OrthogonalityGuard: "Déduplication par QNAME distinct (immunisé contre les fautes de frappe réessayées en A+AAAA) et exclu de P4 par RCode != 0",
	},
	{
		Code:               "P1",
		Category:           CategoryNewGHSA,
		Name:               "Exfiltration descendante asymétrique Answer RDATA & handshake iodine NULL",
		ToolRepresentative: "iodine NULL stateful (V/L/I/Z/p) & C2 descendant TXT/NULL",
		PhysicalInvariant:  "Answer RDATA >= 200 octets haute entropie (MeanRDataEntropy > 4.0, DownlinkRatio > 2.0) avec QNAME court bénin",
		ExpectedReasonCode: "REASON_P1_DOWNLINK_EXFIL",
		OrthogonalityGuard: "Priorité 1 sur la réponse descendante ; QNAME court (< 16 octets) ne déclenchant ni M-01 ni M-02",
	},
	{
		Code:               "P2",
		Category:           CategoryNewGHSA,
		Name:               "Stéganographie lexicale Hex / Base32 à entropie de Shannon bornée",
		ToolRepresentative: "Encodeur Hex / Base32 RFC 4648 sous le seuil de Shannon",
		PhysicalInvariant:  "SubdomainLen in [24,36], alphabet strictement Hex [0-9a-f] (K <= 16, H_max <= 4.00 bits/octet) et Base32HexScore > 0.35",
		ExpectedReasonCode: "REASON_P2_DENSE_ENCODING",
		OrthogonalityGuard: "Plafond mathématique H <= log2(16) = 4.00 bits/octet garantissant Confusion(P2, M-02) == 0",
	},
	{
		Code:               "P3",
		Category:           CategoryNewGHSA,
		Name:               "Balise lente (Low-and-Slow) & rotation Markov des QTYPE",
		ToolRepresentative: "Balise C2 périodique multi-QTYPE (A -> AAAA -> TXT -> NULL -> CNAME)",
		PhysicalInvariant:  "InterArrivalCV < 0.12 après fusion Happy Eyeballs A+AAAA (dt <= 50 ms) et MarkovEntropy > 0.40",
		ExpectedReasonCode: "REASON_P3_BEACON_MARKOV",
		OrthogonalityGuard: "Fusion préalable des paires dual-stack A+AAAA éliminant les faux positifs Happy Eyeballs",
	},
	{
		Code:               "P4",
		Category:           CategoryNewGHSA,
		Name:               "Sharding lent distribué multi-parents (Multi-Apex Low-Volume)",
		ToolRepresentative: "Exfiltrateur distribué multi-domaines (< 3 req/parent)",
		PhysicalInvariant:  "DistinctHighEntParents >= 3 sur des domaines parents ayant chacun 1 <= n_p <= 3 requêtes NOERROR non consommées par M-01..M-04/P1..P2",
		ExpectedReasonCode: "REASON_P4_MULTIPARENT_SHARDING",
		OrthogonalityGuard: "Masque de consommation amont (consumed=1) et exemption des préfixes RFC (_domainkey, _acme-challenge, _dmarc, _spf)",
	},
}

// PatternCatalog retourne la copie du catalogue complet des 8 motifs (4 connus + 4 nouveaux).
func PatternCatalog() []PatternSpec {
	out := make([]PatternSpec, len(catalog8Motifs))
	copy(out, catalog8Motifs)
	return out
}

// LookupPatternSpec recherche un motif par son code ("M-01".."M-04", "P1".."P4").
func LookupPatternSpec(code string) (PatternSpec, bool) {
	for _, sp := range catalog8Motifs {
		if sp.Code == code {
			return sp, true
		}
	}
	return PatternSpec{}, false
}
