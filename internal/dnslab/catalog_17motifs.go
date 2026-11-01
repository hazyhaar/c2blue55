package dnslab

var catalog17Motifs = [17]PatternSpec{
	{
		ID:                "M-01",
		Name:              "Volumetric Long Label Tunneling",
		Category:          CategoryKnownBaseline,
		PhysicalInvariant: "MaxLabelLen >= 44 octets",
		ReasonCode:        "KNOWN_M01_LONG_LABEL",
		OrthogonalGuard:   "Priorité lexicale n°1 avant P2/P12/M-02 ; pose le masque consumed vis-à-vis de P4.",
	},
	{
		ID:                "M-02",
		Name:              "High-Entropy Subdomain Encoding",
		Category:          CategoryKnownBaseline,
		PhysicalInvariant: "ShannonEntropy >= 4.10 bits/octet && AlphabetCard > 16 && MaxLabelLen >= 22 (hors signature Base58 wire P12)",
		ReasonCode:        "KNOWN_M02_HIGH_ENTROPY",
		OrthogonalGuard:   "Évalué après P2 (AlphabetCard <= 16) et après P12 (Base58 wire brut sans 0/O/I/l/-) ; pose le masque consumed.",
	},
	{
		ID:                "M-03",
		Name:              "High-Frequency Volumetric Burst",
		Category:          CategoryKnownBaseline,
		PhysicalInvariant: "BurstRate >= 15 requêtes / fenêtre de 2 secondes sur le flux résiduel non consommé",
		ReasonCode:        "KNOWN_M03_VOLUMETRIC_BURST",
		OrthogonalGuard:   "Évalué en Niveau 4 uniquement sur les requêtes non consommées par Niveaux 1..3, M-04, P11 et P4.",
	},
	{
		ID:                "M-04",
		Name:              "DGA Consonant Run + NXDOMAIN Flood",
		Category:          CategoryKnownBaseline,
		PhysicalInvariant: "RCode == 3 (NXDOMAIN) && DGAConsonantRun >= 5 && DistinctNXQNames >= 4 par ClientIP",
		ReasonCode:        "KNOWN_M04_DGA_NXDOMAIN",
		OrthogonalGuard:   "Comptage par QNAME distincts en échec RCode=3 (immunisé contre 6 retransmissions Happy Eyeballs sur faute de frappe unique).",
	},
	{
		ID:                "P1",
		Name:              "Asymétrie RDATA Descendante & Handshake Stateful iodine",
		Category:          CategoryNewGHSA,
		PhysicalInvariant: "QType in {10, 16} && (DownlinkRatio >= 3.5 avec RDLength >= 180 || Handshake iodine NULL V/L/I/Z/p)",
		ReasonCode:        "GHSA_P1_RDATA_ASYMMETRY",
		OrthogonalGuard:   "Borné à QType in {10 (NULL), 16 (TXT)} pour ne jamais intercepter P5 (AXFR), P8 (CNAME), P10 (A TTL) ou P13 (ANY).",
	},
	{
		ID:                "P2",
		Name:              "Stéganographie Base32/Hex Lisse Courte",
		Category:          CategoryNewGHSA,
		PhysicalInvariant: "Alphabet hexadécimal strict [0-9a-f] (AlphabetCard <= 16, H_max <= 4.00) sur 24 <= LabelLen <= 36",
		ReasonCode:        "GHSA_P2_SMOOTH_HEX_BASE32",
		OrthogonalGuard:   "Séparation bidimensionnelle stricte AlphabetCard <= 16 face à M-02 (AlphabetCard > 16) et P12 (Base58 mixte).",
	},
	{
		ID:                "P3",
		Name:              "Balise Lente Régulière & Modulation Markov QTYPE",
		Category:          CategoryNewGHSA,
		PhysicalInvariant: "InterArrivalCV < 0.12 && MarkovEntropy > 0.40 && DistinctQTypes >= 5 (après collapse Happy Eyeballs A+AAAA < 50ms)",
		ReasonCode:        "GHSA_P3_MARKOV_BEACON",
		OrthogonalGuard:   "Évalué en fin de Niveau 4 sur les échanges non consommés (exclut QType=255 ANY, SRV=33, AXFR=252).",
	},
	{
		ID:                "P4",
		Name:              "Sharding Multi-Parents Lent (Low-and-Slow)",
		Category:          CategoryNewGHSA,
		PhysicalInvariant: "DistinctQualifiedParents >= 16 par ClientIP && MaxQueriesPerApex <= 3 && RCode == 0 && LabelLen in [10..20]",
		ReasonCode:        "GHSA_P4_MULTIPARENT_SHARDING",
		OrthogonalGuard:   "Masque amont consumed excluant tout domaine déjà qualifié par M-01..M-04, P1..P2 ou P5..P13.",
	},
	{
		ID:                "P5",
		Name:              "Tunnel par Transfert de Zone AXFR/IXFR",
		Category:          CategoryNewGHSA,
		PhysicalInvariant: "QType in {251 (IXFR), 252 (AXFR)} && AnswerCount >= 3 vers un apex externe non autoritaire",
		ReasonCode:        "GHSA_P5_ZONE_TRANSFER_TUNNEL",
		OrthogonalGuard:   "Évalué en Niveau 1 (n°2 après Opcode=5) ; court-circuite P1, P9 et P13.",
	},
	{
		ID:                "P6",
		Name:              "Tunnel par Mise à Jour Dynamique DNS (RFC 2136 UPDATE)",
		Category:          CategoryNewGHSA,
		PhysicalInvariant: "Header.Opcode == 5 (UPDATE) && NSCount (Update Section) >= 1 hors TSIG autorisé",
		ReasonCode:        "GHSA_P6_DYNAMIC_UPDATE_TUNNEL",
		OrthogonalGuard:   "Évalué en Niveau 1 absolu (n°1) sur Opcode == 5 ; exclusif de tout QType standard.",
	},
	{
		ID:                "P7",
		Name:              "Canal C2 par Enregistrement SRV (QType=33)",
		Category:          CategoryNewGHSA,
		PhysicalInvariant: "QType == 33 (SRV) && Port SRV hors registre standard {53,80,88,389,443,445,464,636,3268,3269,5060,5061,5222,5269,8448} && Target encodée",
		ReasonCode:        "GHSA_P7_SRV_RECORD_C2",
		OrthogonalGuard:   "Conjonction Port non-standard + cible encodée immunisant Active Directory (_ldap, _gc, _kerberos) et Matrix/SIP.",
	},
	{
		ID:                "P8",
		Name:              "Chaîne CNAME / Aplatissement CNAME Porteur",
		Category:          CategoryNewGHSA,
		PhysicalInvariant: "CNAMEChainDepth >= 2 en section Answer && Cible RDATA CNAME porteuse (TargetLabelLen >= 22) sur QNAME initial court (< 20)",
		ReasonCode:        "GHSA_P8_CNAME_CHAIN_TUNNEL",
		OrthogonalGuard:   "Exige une charge encodée dans le RDATA CNAME de réponse (jamais la seule profondeur CNAME >= 3 des CDN CloudFlare/Akamai).",
	},
	{
		ID:                "P9",
		Name:              "Canal Caché EDNS0 / OPT Record (RR Type=41)",
		Category:          CategoryNewGHSA,
		PhysicalInvariant: "RR Type == 41 en section Additional contenant une option TLV privée (OptionCode in 65001..65534) ou NSID (OptionCode=3) >= 24 octets",
		ReasonCode:        "GHSA_P9_EDNS0_OPT_TUNNEL",
		OrthogonalGuard:   "Exclut explicitement les options EDNS0 standards légitimes : 8 (ECS), 10 (Cookie), 12 (Padding RFC 7830) et 15 (EDE).",
	},
	{
		ID:                "P10",
		Name:              "Stéganographie par Divergence de TTL Intra-RRset",
		Category:          CategoryNewGHSA,
		PhysicalInvariant: "Réponse Type == 1 (A, RDLength == 4) avec >= 3 RR A partageant le même nom et >= 3 TTL distincts (violation RFC 2181 §5.2)",
		ReasonCode:        "GHSA_P10_TTL_STEGANOGRAPHY",
		OrthogonalGuard:   "Filtré strictement sur les seuls RR Type == 1 (immunisé contre [CNAME TTL=3600 + A TTL=60] des CDN et disjoint de P1 RDLength >= 180).",
	},
	{
		ID:                "P11",
		Name:              "Stéganographie Combinatoire par Longueur de Labels",
		Category:          CategoryNewGHSA,
		PhysicalInvariant: "Sous-domaine de k in [4..6] sous-labels alphabétiques [a-z] courts (MaxLabelLen <= 9, H < 3.75) avec >= 5 tuples de longueurs (l_1..l_k) distincts",
		ReasonCode:        "GHSA_P11_LABEL_LENGTH_STEGO",
		OrthogonalGuard:   "Restriction aux labels purement alphabétiques [a-z] courts <= 9 octets (exclut les pods Kubernetes avec chiffres/tirets et disjoint de M-01/M-02/P2).",
	},
	{
		ID:                "P12",
		Name:              "Encodage Multi-Casse Base58 / Base64url Calibré",
		Category:          CategoryNewGHSA,
		PhysicalInvariant: "Premier label wire 22 <= Len <= 34 avec FirstLabelUpper > 0 && FirstLabelLower > 0 && FirstLabelDigits > 0 && !FirstLabelHasZeroOIl && !FirstLabelHasHyphen",
		ReasonCode:        "GHSA_P12_BASE58_SUBDOMAIN",
		OrthogonalGuard:   "Inspecté sur la trame wire brute avant pliage en minuscules et évalué avant M-02 ; l'exclusion de '-' et de {0,O,I,l} élimine le DNS-0x20 bénin.",
	},
	{
		ID:                "P13",
		Name:              "Amplification ANY (QType=255) & Sous-domaine Wildcard",
		Category:          CategoryNewGHSA,
		PhysicalInvariant: "QType == 255 (ANY) avec AnswerCount >= 3 couvrant >= 3 types RR distincts en RCode == 0",
		ReasonCode:        "GHSA_P13_ANY_WILDCARD_C2",
		OrthogonalGuard:   "Évalué en Niveau 1 (n°3) ; pose le masque consumed et exclut QType=255 de P1 et du compteur Markov de P3.",
	},
}

// PatternCatalog17 retourne une copie du catalogue des 17 motifs DNS.
func PatternCatalog17() []PatternSpec {
	out := make([]PatternSpec, len(catalog17Motifs))
	for i := range catalog17Motifs {
		s := catalog17Motifs[i]
		s.Code = s.ID
		s.ExpectedReasonCode = s.ReasonCode
		s.OrthogonalityGuard = s.OrthogonalGuard
		out[i] = s
	}
	return out
}

// LookupPatternSpec17 recherche un motif par son identifiant dans PatternCatalog17.
func LookupPatternSpec17(id string) (PatternSpec, bool) {
	for i := range catalog17Motifs {
		if catalog17Motifs[i].ID == id {
			s := catalog17Motifs[i]
			s.Code = s.ID
			s.ExpectedReasonCode = s.ReasonCode
			s.OrthogonalityGuard = s.OrthogonalGuard
			return s, true
		}
	}
	return PatternSpec{}, false
}
