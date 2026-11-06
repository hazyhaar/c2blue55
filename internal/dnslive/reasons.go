package dnslive

import (
	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

type reasonGuide struct {
	ReasonCode   string   `json:"reason_code"`
	Class        string   `json:"class"`
	Mechanism    string   `json:"mechanism"`
	Measurements []string `json:"measurements"`
	Thresholds   []string `json:"thresholds"`
	Windows      []string `json:"windows"`
	BenignGuards []string `json:"benign_guards"`
}

// reasonGuides décrit uniquement les contrôles réellement exécutés par le
// pipeline et les traqueurs spécialisés du service. Les mesures internes qui ne
// figurent pas dans liveEvent sont nommées comme telles, sans valeur fictive.
func reasonGuides() []reasonGuide {
	return []reasonGuide{
		{
			ReasonCode:   c2blue55.ReasonDNSParseError,
			Class:        "PARSE_ERR",
			Mechanism:    "Le parseur DNS refuse le datagramme et le verdict échoue fermé au lieu d'inventer des faits protocolaires.",
			Measurements: []string{"octets intégraux du datagramme", "parse_error", "txid si au moins deux octets sont présents"},
			Thresholds:   []string{"paquet < 12 octets, RR > 16, RDATA > 1536 octets ou pointeurs > 8 selon l'erreur rencontrée"},
			Windows:      []string{"Datagramme courant uniquement."},
			BenignGuards: []string{"Aucune réponse de laboratoire n'est émise après une erreur de parse.", "QName et compteurs restent à zéro sur un paquet indécodable."},
		},
		{
			ReasonCode: engine.ReasonM01LongLabel, Class: "M-01",
			Mechanism:    "Un sous-domaine très long porte un volume de label incompatible avec une résolution ordinaire.",
			Measurements: []string{"subdomain_len", "label_count", "max_label_len"},
			Thresholds:   []string{"subdomain_len >= 44 octets"}, Windows: []string{"Paquet courant, sans fenêtre temporelle."},
			BenignGuards: []string{"Les requêtes RFC à labels underscore autorisés sont exemptées avant ce contrôle.", "Le kind du run n'entre pas dans la mesure."},
		},
		{
			ReasonCode: engine.ReasonM02HighEntropy, Class: "M-02",
			Mechanism:    "Le premier label combine une diversité de caractères et une entropie de Shannon élevées.",
			Measurements: []string{"premier label du QNAME", "entropie Shannon interne en bits/octet", "cardinal interne des caractères"},
			Thresholds:   []string{"longueur du premier label >= 20 octets", "entropie >= 4.10 bits/octet", "cardinal > 16 caractères distincts"},
			Windows:      []string{"Paquet courant ; les réponses NXDOMAIN sont exclues de ce contrôle."},
			BenignGuards: []string{"Les labels de moins de 20 octets ne déclenchent pas M-02.", "Les priorités P2, P12 et M-01 restent appliquées avant M-02."},
		},
		{
			ReasonCode: engine.ReasonM03Burst, Class: "M-03",
			Mechanism:    "Une rafale de requêtes vers le même apex dépasse la cadence ordinaire dans une fenêtre courte.",
			Measurements: []string{"horodatages des requêtes", "parent apex", "anneau interne de 16 instants"},
			Thresholds:   []string{"nombre de requêtes >= 15", "intervalle entre la plus ancienne et la courante > 0 et <= 2 secondes"},
			Windows:      []string{"Fenêtre glissante de 16 requêtes au maximum et de 2 secondes par apex et par pipeline."},
			BenignGuards: []string{"Les réponses ne remplissent pas l'anneau de rafale.", "Chaque run possède son propre anneau."},
		},
		{
			ReasonCode: engine.ReasonM04DGAConsonantNX, Class: "M-04",
			Mechanism:    "Des QNAME à longues suites de consonnes reçoivent plusieurs réponses NXDOMAIN distinctes.",
			Measurements: []string{"qname", "suite maximale de consonnes", "RCODE", "empreintes internes de QNAME distincts"},
			Thresholds:   []string{"suite de consonnes >= 5", "QNAME distincts >= 4", "RCODE = 3 (NXDOMAIN)"},
			Windows:      []string{"Historique du pipeline, 16 empreintes au maximum, sans expiration temporelle."},
			BenignGuards: []string{"Un NXDOMAIN seul ne suffit pas.", "Les ports sources et les runs ne partagent aucun compteur."},
		},
		{
			ReasonCode: engine.ReasonP1DownlinkExfil, Class: "P1",
			Mechanism:    "Une réponse TXT ou NULL transporte un RDATA descendant volumineux ; un rapport descendant et une entropie d'épisode peuvent aussi confirmer le motif.",
			Measurements: []string{"rdata_bytes", "answer_count", "qtype", "rapport descendant et entropie RDATA internes d'épisode"},
			Thresholds:   []string{"Answer[0].RDLength >= 180 octets pour QTYPE 10 ou 16", "ou rapport descendant > 2.0 avec entropie RDATA moyenne > 4.0"},
			Windows:      []string{"Paquet courant pour RDATA ; épisode courant pour la voie agrégée."},
			BenignGuards: []string{"Les préfixes RFC underscore TXT sont exemptés de la voie RDATA directe.", "La première réponse doit contenir au moins 1 Answer."},
		},
		{
			ReasonCode: engine.ReasonP2DenseEncoding, Class: "P2",
			Mechanism:    "Le premier label est un bloc hexadécimal minuscule dense de taille bornée.",
			Measurements: []string{"premier label du QNAME", "alphabet hexadécimal"},
			Thresholds:   []string{"longueur du premier label >= 24 et <= 36 octets"}, Windows: []string{"Paquet courant."},
			BenignGuards: []string{"Tout caractère hors [0-9a-f] invalide le motif."},
		},
		{
			ReasonCode: engine.ReasonP3BeaconMarkov, Class: "P3",
			Mechanism:    "Une cadence très régulière et une diversité Markov de QTYPE suggèrent une balise automatisée.",
			Measurements: []string{"intervalles de requêtes", "QTYPE", "CV interne", "entropie Markov interne"},
			Thresholds:   []string{"QTYPE distincts >= 5", "CV inter-arrivée < 0.12", "entropie Markov > 0.40"},
			Windows:      []string{"Huit requêtes au maximum ; les paires Happy Eyeballs A/AAAA espacées de <= 50 ms sont fusionnées."},
			BenignGuards: []string{"Les réponses ne participent pas à cette fenêtre.", "Les paires A/AAAA proches ne gonflent pas la cardinalité temporelle."},
		},
		{
			ReasonCode: engine.ReasonP4MultiParentSharding, Class: "P4",
			Mechanism:    "Un sous-domaine unique est fragmenté entre plusieurs parents, avec une agrégation client complémentaire.",
			Measurements: []string{"subdomain_len", "parent apex", "score composite P4 interne"},
			Thresholds:   []string{"longueur du sous-domaine >= 10 et <= 32 octets", "parents distincts >= 4", "ou score composite P4 > 0.40"},
			Windows:      []string{"32 parents dans le classifieur de flux et 256 clients dans l'agrégation propre au pipeline."},
			BenignGuards: []string{"Les labels contenant point, tiret ou underscore ne remplissent pas ce compteur."},
		},
		{
			ReasonCode: engine.ReasonP5AXFRBulk, Class: "P5",
			Mechanism:    "Une réponse de transfert de zone contient un volume ou des enregistrements porteurs inhabituels.",
			Measurements: []string{"qtype", "answer_count", "RDATA cumulé interne", "plus grand RDATA interne"},
			Thresholds:   []string{"QTYPE = 251 ou 252", "ANCOUNT >= 3", "RDATA cumulé >= 24 octets ou plus grand RDATA >= 16 octets"},
			Windows:      []string{"Réponse courante."}, BenignGuards: []string{"La synchronisation autoritaire d'apex avec petit RDATA est exemptée."},
		},
		{
			ReasonCode: engine.ReasonP6DynamicUpdate, Class: "P6",
			Mechanism:    "Un message UPDATE transporte une section Authority au lieu d'une question ordinaire.",
			Measurements: []string{"opcode", "NSCOUNT"}, Thresholds: []string{"OPCODE = 5", "NSCOUNT >= 1"},
			Windows: []string{"Message courant."}, BenignGuards: []string{"Les OPCODE ordinaires ne suivent pas cette branche."},
		},
		{
			ReasonCode: engine.ReasonP7SRVC2Endpoint, Class: "P7",
			Mechanism:    "Une réponse SRV associe un port non standard à une cible à long label.",
			Measurements: []string{"qtype", "port SRV", "labels de la cible SRV"},
			Thresholds:   []string{"QTYPE = 33", "label cible maximal >= 20 octets", "port != chacun des 15 ports standards"},
			Windows:      []string{"Réponse courante."}, BenignGuards: []string{"Les services SRV sur ports standards sont acceptés."},
		},
		{
			ReasonCode: engine.ReasonP8CNameChain, Class: "P8",
			Mechanism:    "Une chaîne CNAME multiple mène vers une cible dont le label est porteur.",
			Measurements: []string{"answer_count", "nombre interne de CNAME", "labels des cibles", "subdomain_len"},
			Thresholds:   []string{"CNAME >= 2", "label cible maximal >= 22 octets", "subdomain_len < 20 octets"},
			Windows:      []string{"Réponse courante."}, BenignGuards: []string{"Les chaînes CDN à cibles courtes ne satisfont pas le seuil."},
		},
		{
			ReasonCode: engine.ReasonP9EDNS0PrivateOption, Class: "P9",
			Mechanism:    "Une option OPT privée ou suspecte transporte une charge suffisamment longue dans Additional.",
			Measurements: []string{"option EDNS0", "code et longueur de chaque option OPT"},
			Thresholds:   []string{"65001 <= code option <= 65534 avec longueur >= 16 octets", "ou code option = 3 avec longueur >= 24 octets"},
			Windows:      []string{"Toutes les options de la réponse courante."},
			BenignGuards: []string{"Les options 8, 10, 12 et 15 sont explicitement ignorées."},
		},
		{
			ReasonCode: engine.ReasonP10TTLStegoIntraA, Class: "P10",
			Mechanism:    "Un RRset A utilise plusieurs TTL distincts comme canal de signalisation.",
			Measurements: []string{"answer_count", "TTL des RR A", "rdata_bytes"},
			Thresholds:   []string{"RR A avec RDLength = 4 : nombre >= 3", "TTL distincts >= 3"},
			Windows:      []string{"RRset de la réponse courante."}, BenignGuards: []string{"Les TTL uniformes et les autres types ne remplissent pas le compteur."},
		},
		{
			ReasonCode: engine.ReasonP11LengthTupleStego, Class: "P11",
			Mechanism:    "Les longueurs de labels alphabétiques forment des tuples stéganographiques renouvelés.",
			Measurements: []string{"label_count", "longueurs des labels", "tuples internes distincts"},
			Thresholds:   []string{"labels >= 4 et <= 6", "chaque longueur >= 3 et <= 9 octets", "tuples distincts >= 5"},
			Windows:      []string{"Huit tuples au maximum par apex dans le pipeline."}, BenignGuards: []string{"Tout caractère non alphabétique invalide le tuple."},
		},
		{
			ReasonCode: engine.ReasonP12Base58Case, Class: "P12",
			Mechanism:    "Le premier label présente une casse et des chiffres compatibles avec une charge Base58.",
			Measurements: []string{"premier label", "casse et chiffres du QNAME"},
			Thresholds:   []string{"longueur du premier label >= 22 et <= 34 octets", "majuscules >= 1, minuscules >= 1 et chiffres >= 1"},
			Windows:      []string{"Paquet courant."}, BenignGuards: []string{"Les caractères ambigus 0, O, I, l et le tiret excluent le motif."},
		},
		{
			ReasonCode: engine.ReasonP13ANYWildcard, Class: "P13",
			Mechanism:    "Une réponse ANY renvoie un agrégat anormalement riche en types.",
			Measurements: []string{"qtype", "answer_count", "types internes distincts"},
			Thresholds:   []string{"QTYPE = 255", "Answers >= 3", "types distincts >= 3"},
			Windows:      []string{"Réponse courante."}, BenignGuards: []string{"Une réponse ANY à un ou deux types reste bénigne sur ce contrôle."},
		},
		{
			ReasonCode: engine.ReasonP14NegativeAnswerPayload, Class: "P14",
			Mechanism:    "Une réponse NXDOMAIN contient des enregistrements porteurs au lieu d'une négation protocolaire ordinaire.",
			Measurements: []string{"answer_count", "sections Authority et Additional", "types des RR"},
			Thresholds:   []string{"RCODE = 3 avec au moins 1 RR porteur non exempté"},
			Windows:      []string{"Réponse courante."}, BenignGuards: []string{"SOA, DNSSEC, CNAME et DNAME autorisés par les règles du classifieur sont exemptés."},
		},
		{
			ReasonCode: engine.ReasonP15RDataRenewal, Class: "P15",
			Mechanism:    "Les empreintes RRset se renouvellent fortement avec un RDATA moyen porteur.",
			Measurements: []string{"rdata_bytes", "empreintes RRset internes", "taux interne de renouvellement"},
			Thresholds:   []string{"réponses >= 8", "renouvellement >= 750 pour mille", "RDLength moyen >= 128 octets"},
			Windows:      []string{"16 réponses au maximum sur 10 minutes, avec contrôle aussi sur les 8 plus récentes."},
			BenignGuards: []string{"Les réponses tronquées, négatives ou sans Answer ne participent pas."},
		},
		{
			ReasonCode: engine.ReasonP20SOANegDownlink, Class: "P20",
			Mechanism:    "Les champs MNAME, RNAME et SERIAL des SOA de réponses négatives se renouvellent pour transporter un canal descendant.",
			Measurements: []string{"MNAME, RNAME et SERIAL du SOA en section Authority", "empreintes SOA distinctes internes par client et propriétaire"},
			Thresholds:   []string{"empreintes SOA distinctes >= 3"},
			Windows:      []string{"Huit empreintes au maximum sur 10 minutes par client et propriétaire SOA."},
			BenignGuards: []string{"Seules les réponses sans Answer, de RCODE 0 ou 3 et portant un SOA en Authority participent.", "Une empreinte répétée ne fait pas croître la diversité."},
		},
		{
			ReasonCode: engine.ReasonP21AAAAIIDDownlink, Class: "P21",
			Mechanism:    "Les identifiants d'interface des réponses AAAA se renouvellent sous un même préfixe pour transporter un canal descendant.",
			Measurements: []string{"préfixe /64 et IID des RR AAAA", "IID pleine largeur distincts internes par client et préfixe"},
			Thresholds:   []string{"IID pleine largeur distincts >= 8"},
			Windows:      []string{"Seize IID au maximum sur 600 s par client et préfixe /64."},
			BenignGuards: []string{"Un IID contenant un octet nul n'est pas pleine largeur et ne participe pas.", "Seules les réponses AAAA complètes de RCODE 0 participent."},
		},
	}
}

func reasonGuidesForLanguage(language string) []reasonGuide {
	if language == "en" {
		return englishReasonGuides()
	}
	return reasonGuides()
}

func englishReasonGuides() []reasonGuide {
	return []reasonGuide{
		{
			ReasonCode:   c2blue55.ReasonDNSParseError,
			Class:        "PARSE_ERR",
			Mechanism:    "The DNS parser rejects the datagram and the verdict fails closed instead of inventing protocol facts.",
			Measurements: []string{"complete datagram bytes", "parse_error", "txid when at least two bytes are present"},
			Thresholds:   []string{"packet < 12 bytes, RR > 16, RDATA > 1536 bytes, or pointers > 8 depending on the encountered error"},
			Windows:      []string{"Current datagram only."},
			BenignGuards: []string{"No laboratory response is emitted after a parse error.", "QName and counters remain zero on an undecodable packet."},
		},
		{
			ReasonCode: engine.ReasonM01LongLabel, Class: "M-01",
			Mechanism:    "A very long subdomain carries a label volume incompatible with ordinary resolution.",
			Measurements: []string{"subdomain_len", "label_count", "max_label_len"},
			Thresholds:   []string{"subdomain_len >= 44 bytes"}, Windows: []string{"Current packet, with no time window."},
			BenignGuards: []string{"RFC queries with permitted underscore labels are exempted before this check.", "The run kind does not enter the measurement."},
		},
		{
			ReasonCode: engine.ReasonM02HighEntropy, Class: "M-02",
			Mechanism:    "The first label combines high character diversity and high Shannon entropy.",
			Measurements: []string{"first QNAME label", "internal Shannon entropy in bits/byte", "internal character cardinality"},
			Thresholds:   []string{"first label length >= 20 bytes", "entropy >= 4.10 bits/byte", "cardinality > 16 distinct characters"},
			Windows:      []string{"Current packet; NXDOMAIN responses are excluded from this check."},
			BenignGuards: []string{"Labels shorter than 20 bytes do not trigger M-02.", "P2, P12 and M-01 priorities still apply before M-02."},
		},
		{
			ReasonCode: engine.ReasonM03Burst, Class: "M-03",
			Mechanism:    "A burst of queries to the same apex exceeds the ordinary rate within a short window.",
			Measurements: []string{"query timestamps", "apex parent", "internal ring of 16 instants"},
			Thresholds:   []string{"query count >= 15", "interval between the oldest and current query > 0 and <= 2 seconds"},
			Windows:      []string{"Sliding window of at most 16 queries and 2 seconds per apex and per pipeline."},
			BenignGuards: []string{"Responses do not fill the burst ring.", "Each run owns its own ring."},
		},
		{
			ReasonCode: engine.ReasonM04DGAConsonantNX, Class: "M-04",
			Mechanism:    "QNAMEs with long consonant sequences receive several distinct NXDOMAIN responses.",
			Measurements: []string{"qname", "maximum consonant sequence", "RCODE", "internal hashes of distinct QNAMEs"},
			Thresholds:   []string{"consonant sequence >= 5", "distinct QNAMEs >= 4", "RCODE = 3 (NXDOMAIN)"},
			Windows:      []string{"Pipeline history, at most 16 hashes, with no time expiration."},
			BenignGuards: []string{"A single NXDOMAIN is insufficient.", "Source ports and runs share no counters."},
		},
		{
			ReasonCode: engine.ReasonP1DownlinkExfil, Class: "P1",
			Mechanism:    "A TXT or NULL response carries a large downlink RDATA payload; a downlink ratio and episode entropy can also confirm the pattern.",
			Measurements: []string{"rdata_bytes", "answer_count", "qtype", "internal episode downlink ratio and RDATA entropy"},
			Thresholds:   []string{"Answer[0].RDLength >= 180 bytes for QTYPE 10 or 16", "or downlink ratio > 2.0 with mean RDATA entropy > 4.0"},
			Windows:      []string{"Current packet for RDATA; current episode for the aggregate path."},
			BenignGuards: []string{"RFC underscore TXT prefixes are exempted from the direct RDATA path.", "The first response must contain at least 1 Answer."},
		},
		{
			ReasonCode: engine.ReasonP2DenseEncoding, Class: "P2",
			Mechanism:    "The first label is a dense, bounded lowercase hexadecimal block.",
			Measurements: []string{"first QNAME label", "hexadecimal alphabet"},
			Thresholds:   []string{"first label length >= 24 and <= 36 bytes"}, Windows: []string{"Current packet."},
			BenignGuards: []string{"Any character outside [0-9a-f] invalidates the pattern."},
		},
		{
			ReasonCode: engine.ReasonP3BeaconMarkov, Class: "P3",
			Mechanism:    "A highly regular cadence and Markov QTYPE diversity suggest an automated beacon.",
			Measurements: []string{"query intervals", "QTYPE", "internal CV", "internal Markov entropy"},
			Thresholds:   []string{"distinct QTYPEs >= 5", "inter-arrival CV < 0.12", "Markov entropy > 0.40"},
			Windows:      []string{"At most eight queries; Happy Eyeballs A/AAAA pairs separated by <= 50 ms are merged."},
			BenignGuards: []string{"Responses do not participate in this window.", "Nearby A/AAAA pairs do not inflate temporal cardinality."},
		},
		{
			ReasonCode: engine.ReasonP4MultiParentSharding, Class: "P4",
			Mechanism:    "A single subdomain is fragmented across several parents, with complementary client aggregation.",
			Measurements: []string{"subdomain_len", "apex parent", "internal P4 composite score"},
			Thresholds:   []string{"subdomain length >= 10 and <= 32 bytes", "distinct parents >= 4", "or P4 composite score > 0.40"},
			Windows:      []string{"32 parents in the stream classifier and 256 clients in pipeline-specific aggregation."},
			BenignGuards: []string{"Labels containing a dot, hyphen or underscore do not fill this counter."},
		},
		{
			ReasonCode: engine.ReasonP5AXFRBulk, Class: "P5",
			Mechanism:    "A zone transfer response contains an unusual volume or unusual carrying records.",
			Measurements: []string{"qtype", "answer_count", "internal total RDATA", "internal largest RDATA"},
			Thresholds:   []string{"QTYPE = 251 or 252", "ANCOUNT >= 3", "total RDATA >= 24 bytes or largest RDATA >= 16 bytes"},
			Windows:      []string{"Current response."}, BenignGuards: []string{"Authoritative apex synchronization with small RDATA is exempted."},
		},
		{
			ReasonCode: engine.ReasonP6DynamicUpdate, Class: "P6",
			Mechanism:    "An UPDATE message carries an Authority section instead of an ordinary question.",
			Measurements: []string{"opcode", "NSCOUNT"}, Thresholds: []string{"OPCODE = 5", "NSCOUNT >= 1"},
			Windows: []string{"Current message."}, BenignGuards: []string{"Ordinary OPCODEs do not follow this branch."},
		},
		{
			ReasonCode: engine.ReasonP7SRVC2Endpoint, Class: "P7",
			Mechanism:    "An SRV response associates a non-standard port with a target containing a long label.",
			Measurements: []string{"qtype", "SRV port", "SRV target labels"},
			Thresholds:   []string{"QTYPE = 33", "maximum target label >= 20 bytes", "port != each of the 15 standard ports"},
			Windows:      []string{"Current response."}, BenignGuards: []string{"SRV services on standard ports are accepted."},
		},
		{
			ReasonCode: engine.ReasonP8CNameChain, Class: "P8",
			Mechanism:    "A multiple CNAME chain leads to a target whose label carries a payload.",
			Measurements: []string{"answer_count", "internal CNAME count", "target labels", "subdomain_len"},
			Thresholds:   []string{"CNAME >= 2", "maximum target label >= 22 bytes", "subdomain_len < 20 bytes"},
			Windows:      []string{"Current response."}, BenignGuards: []string{"CDN chains with short targets do not meet the threshold."},
		},
		{
			ReasonCode: engine.ReasonP9EDNS0PrivateOption, Class: "P9",
			Mechanism:    "A private or suspicious OPT option carries a sufficiently long payload in Additional.",
			Measurements: []string{"EDNS0 option", "code and length of each OPT option"},
			Thresholds:   []string{"65001 <= option code <= 65534 with length >= 16 bytes", "or option code = 3 with length >= 24 bytes"},
			Windows:      []string{"All options in the current response."},
			BenignGuards: []string{"Options 8, 10, 12 and 15 are explicitly ignored."},
		},
		{
			ReasonCode: engine.ReasonP10TTLStegoIntraA, Class: "P10",
			Mechanism:    "An A RRset uses several distinct TTLs as a signaling channel.",
			Measurements: []string{"answer_count", "TTLs of A RRs", "rdata_bytes"},
			Thresholds:   []string{"A RRs with RDLength = 4: count >= 3", "distinct TTLs >= 3"},
			Windows:      []string{"RRset in the current response."}, BenignGuards: []string{"Uniform TTLs and other types do not fill the counter."},
		},
		{
			ReasonCode: engine.ReasonP11LengthTupleStego, Class: "P11",
			Mechanism:    "Alphabetic label lengths form renewed steganographic tuples.",
			Measurements: []string{"label_count", "label lengths", "distinct internal tuples"},
			Thresholds:   []string{"labels >= 4 and <= 6", "each length >= 3 and <= 9 bytes", "distinct tuples >= 5"},
			Windows:      []string{"At most eight tuples per apex in the pipeline."}, BenignGuards: []string{"Any non-alphabetic character invalidates the tuple."},
		},
		{
			ReasonCode: engine.ReasonP12Base58Case, Class: "P12",
			Mechanism:    "The first label has letter cases and digits compatible with a Base58 payload.",
			Measurements: []string{"first label", "QNAME letter cases and digits"},
			Thresholds:   []string{"first label length >= 22 and <= 34 bytes", "uppercase letters >= 1, lowercase letters >= 1 and digits >= 1"},
			Windows:      []string{"Current packet."}, BenignGuards: []string{"Ambiguous characters 0, O, I, l and the hyphen exclude the pattern."},
		},
		{
			ReasonCode: engine.ReasonP13ANYWildcard, Class: "P13",
			Mechanism:    "An ANY response returns an abnormally type-rich aggregate.",
			Measurements: []string{"qtype", "answer_count", "distinct internal types"},
			Thresholds:   []string{"QTYPE = 255", "Answers >= 3", "distinct types >= 3"},
			Windows:      []string{"Current response."}, BenignGuards: []string{"An ANY response with one or two types remains benign for this check."},
		},
		{
			ReasonCode: engine.ReasonP14NegativeAnswerPayload, Class: "P14",
			Mechanism:    "An NXDOMAIN response contains carrying records instead of an ordinary protocol negative answer.",
			Measurements: []string{"answer_count", "Authority and Additional sections", "RR types"},
			Thresholds:   []string{"RCODE = 3 with at least 1 non-exempted carrying RR"},
			Windows:      []string{"Current response."}, BenignGuards: []string{"SOA, DNSSEC, CNAME and DNAME records allowed by classifier rules are exempted."},
		},
		{
			ReasonCode: engine.ReasonP15RDataRenewal, Class: "P15",
			Mechanism:    "RRset hashes renew heavily while mean RDATA remains carrying.",
			Measurements: []string{"rdata_bytes", "internal RRset hashes", "internal renewal rate"},
			Thresholds:   []string{"responses >= 8", "renewal >= 750 per mille", "mean RDLength >= 128 bytes"},
			Windows:      []string{"At most 16 responses over 10 minutes, also checking the 8 most recent."},
			BenignGuards: []string{"Truncated, negative or Answer-free responses do not participate."},
		},
		{
			ReasonCode: engine.ReasonP20SOANegDownlink, Class: "P20",
			Mechanism:    "The MNAME, RNAME and SERIAL fields of SOAs in negative responses renew to carry a downlink channel.",
			Measurements: []string{"SOA MNAME, RNAME and SERIAL in the Authority section", "distinct internal SOA hashes per client and owner"},
			Thresholds:   []string{"distinct SOA hashes >= 3"},
			Windows:      []string{"At most eight hashes over 10 minutes per client and SOA owner."},
			BenignGuards: []string{"Only responses without Answers, with RCODE 0 or 3 and an Authority SOA participate.", "A repeated hash does not increase diversity."},
		},
		{
			ReasonCode: engine.ReasonP21AAAAIIDDownlink, Class: "P21",
			Mechanism:    "The interface identifiers of AAAA responses renew under the same prefix to carry a downlink channel.",
			Measurements: []string{"AAAA RR /64 prefix and IID", "distinct internal full-width IIDs per client and prefix"},
			Thresholds:   []string{"distinct full-width IIDs >= 8"},
			Windows:      []string{"At most sixteen IIDs over 600 s per client and /64 prefix."},
			BenignGuards: []string{"An IID containing a zero byte is not full-width and does not participate.", "Only complete AAAA responses with RCODE 0 participate."},
		},
	}
}
