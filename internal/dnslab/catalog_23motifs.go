package dnslab

// CategoryExotic distingue les motifs DNS rares (DNSKEY, NOTIFY, TKEY/SIG(0)) dont la
// donnée réelle est peu fréquente et qui complètent le catalogue 17 motifs.
const CategoryExotic = "EXOTIC"

// catalog23Motifs porte les 6 motifs DNS hors du catalogue 17 (P14..P19) :
// P14 DoH/DoT (canal TLS), P15 résolveur non-53, P16 empoisonnement de cache,
// P17 DNSKEY, P18 NOTIFY, P19 TKEY/SIG(0).
var catalog23Motifs = [6]PatternSpec{
	{
		ID:                 "P14",
		Name:               "Tunnel DNS chiffré DoH/DoT (canal TLS)",
		Category:           CategoryNewGHSA,
		ToolRepresentative: "dnscat2 en mode DoH / iodine sur TLS 443",
		PhysicalInvariant:  "IsEncryptedDNS && (QNameEntropy > 4.0 || RDataEntropy > 4.0) avec SNI/ALPN non résolveur public",
		ReasonCode:         "GHSA_P14_DOH_DOT_TUNNEL",
		OrthogonalGuard:    "Évalué en Niveau 1 ; le canal TLS est disjoint de tout motif UDP/53 (P1..P13) et de P15..P19.",
	},
	{
		ID:                 "P15",
		Name:               "Résolveur C2 sur port non standard",
		Category:           CategoryNewGHSA,
		ToolRepresentative: "Balise C2 vers un résolveur d'appoint port 853/443/5353",
		PhysicalInvariant:  "ResolverPort != 53 vers une adresse C2 (hors 127.0.0.1 et 10.55.0.0/24 lab)",
		ReasonCode:         "GHSA_P15_NONSTD_RESOLVER",
		OrthogonalGuard:    "Évalué en Niveau 1 ; le port résolveur est disjoint de tout motif QNAME/RDATA (P1..P14).",
	},
	{
		ID:                 "P16",
		Name:               "Empoisonnement de cache DNS hors chaîne CNAME légitime",
		Category:           CategoryNewGHSA,
		ToolRepresentative: "Cache poisoning par insertion d'un RR hors bailliage et hors chaîne CNAME valide",
		PhysicalInvariant:  "ResponseName != QueryName dans une réponse RCode == 0 sans chaîne CNAME légitime reliant QueryName au RR",
		ReasonCode:         "GHSA_P16_CACHE_POISONING",
		OrthogonalGuard:    "Évalué en Niveau 2 après validation de toute chaîne CNAME légitime dans Answer ; disjoint de tout motif QNAME/RDATA (P1..P15).",
	},
	{
		ID:                 "P17",
		Name:               "Canal C2 par enregistrement DNSKEY (QType=48)",
		Category:           CategoryExotic,
		ToolRepresentative: "Balise C2 masquée en requête/réponse DNSKEY hors DNSSEC",
		PhysicalInvariant:  "QType == 48 (DNSKEY) avec RDATA clé >= 68 octets (4 octets d'en-tête RFC 4034 + 64 octets ECDSA P-256) hors zone DNSSEC signée",
		ReasonCode:         "GHSA_P17_DNSKEY_C2",
		OrthogonalGuard:    "Évalué en Niveau 1 ; le QType 48 est exclusif et disjoint de P5/P13/P18/P19.",
	},
	{
		ID:                 "P18",
		Name:               "Canal C2 par message DNS NOTIFY (OPCODE=4)",
		Category:           CategoryExotic,
		ToolRepresentative: "Balise C2 masquée en message NOTIFY (RFC 1996, OPCODE=4) vers un apex non autoritaire",
		PhysicalInvariant:  "OPCODE == 4 (NOTIFY) vers un apex externe non autoritaire (distinct de QType 64 qui désigne SVCB RFC 9460)",
		ReasonCode:         "GHSA_P18_NOTIFY_C2",
		OrthogonalGuard:    "Évalué en Niveau 1 sur l'en-tête OPCODE == 4 ; exclusif d'OPCODE 0 (QUERY) et d'OPCODE 5 (UPDATE/P6).",
	},
	{
		ID:                 "P19",
		Name:               "Canal C2 par SIG(0) / TKEY / TSIG (QType=24/249/250)",
		Category:           CategoryExotic,
		ToolRepresentative: "Balise C2 masquée en SIG(0) (RFC 2931), TKEY (RFC 2930) ou TSIG (RFC 8945)",
		PhysicalInvariant:  "QType in {24 (SIG(0)), 249 (TKEY), 250 (TSIG)} avec RDATA >= 16 octets hors transaction d'infrastructure autorisée",
		ReasonCode:         "GHSA_P19_TKEY_SIG0_C2",
		OrthogonalGuard:    "Évalué en Niveau 1 ; les QType 24/249/250 sont exclusifs et disjoints de P5/P13/P17/P18.",
	},
}

// PatternCatalog23 retourne la copie du catalogue complet des 23 motifs DNS
// (les 17 du catalogue 17 + les 6 P14..P19).
func PatternCatalog23() []PatternSpec {
	out := make([]PatternSpec, 0, 23)
	out = append(out, PatternCatalog17()...)
	for i := range catalog23Motifs {
		spec := catalog23Motifs[i]
		spec.Code = spec.ID
		spec.ExpectedReasonCode = spec.ReasonCode
		spec.OrthogonalityGuard = spec.OrthogonalGuard
		out = append(out, spec)
	}
	return out
}

// LookupPatternSpec23 recherche un motif par son identifiant dans PatternCatalog23.
func LookupPatternSpec23(id string) (PatternSpec, bool) {
	if spec, ok := LookupPatternSpec17(id); ok {
		return spec, true
	}
	for i := range catalog23Motifs {
		if catalog23Motifs[i].ID == id {
			spec := catalog23Motifs[i]
			spec.Code = spec.ID
			spec.ExpectedReasonCode = spec.ReasonCode
			spec.OrthogonalityGuard = spec.OrthogonalGuard
			return spec, true
		}
	}
	return PatternSpec{}, false
}
