package dnslab

// catalog29Motifs porte les 6 motifs QUIC / DNS chiffré / relais loopback (P20..P25)
// issus de l'audit combinatoire RFC 9000/9001/9114/9221/9250/9298/9369/8484/8467.
var catalog29Motifs = [6]PatternSpec{
	{
		ID:                 "P20",
		Name:               "Angle mort de réassemblage Initial QUIC et ClientHello TLS",
		Category:           CategoryNewGHSA,
		ToolRepresentative: "Hypothèse défensive RFC 9000 §12.2/§19.6 et RFC 9001 §4/§4.3 ; aucune charge utile",
		PhysicalInvariant:  `Soit CH1 le verdict d'un parseur limité au premier datagramme et CH* le verdict après décapsulation de tous les paquets coalescés et réassemblage ordonné des CRYPTO par (offset,length). Le motif vaut D = 1[CH1=INCOMPLET] × 1[CH*=COMPLET_AEAD], avec au moins deux fragments CRYPTO ou au moins deux types de paquets coalescés. Versions admises : 0x00000001 et 0x6b3343cf, avec sel et étiquettes propres à chacune. Au plus 32 fragments et 65 536 octets de CH sont acceptés ; tout trou persistant, fragment dupliqué incohérent ou dépassement rend UNOBSERVABLE. Mesure 0-allocation : compteurs de fragments, bitmap de couverture, bornes min/max d'offset et état AEAD dans une session préallouée.`,
		ReasonCode:         "GHSA_P20_QUIC_INITIAL_REASSEMBLY",
		OrthogonalGuard:    `P20 est exclusivement une preuve de couverture parseur : il ne provoque aucune escalade C2 seul. Un navigateur HTTP/3, WebRTC, un NAT rebinding ou un résolveur partagé peut produire le même différentiel sans hostilité ; G-WEB/G-RTC/G-MIG/G-REL imposent alors seulement la réparation de l'observabilité. Le motif est disjoint de M-01..M-04/P1..P19 car il ne lit aucun QNAME/RDATA et précède P21..P24 ; G-DISJ interdit le double comptage.`,
	},
	{
		ID:                 "P21",
		Name:               "Transport DoQ ou DoH3 persistant vers un résolveur non autorisé",
		Category:           CategoryNewGHSA,
		ToolRepresentative: "Hypothèse défensive RFC 9250 §4.1–4.2 et RFC 8484 sur RFC 9114 ; aucune charge utile",
		PhysicalInvariant:  `Le motif vaut R=1 ET EndpointNonAutorise ET Duree>=30 s ET N_datagrammes>=32, avec N_up>=8 et N_down>=8. R est la preuve de transport DNS définie au §6.2 ; ALPN=doq suffit, tandis que ALPN=h3 exige application/dns-message au relais ou la corrélation hôte. Le port est libre, y compris 853/udp, 443/udp ou un port mutuellement convenu ; la version v1/v2 et l'absence de SNI sont neutres. Les compteurs, directions et durées sont lus dans des anneaux fixes sur PCAP ; aucune entropie de QNAME/RDATA n'intervient.`,
		ReasonCode:         "GHSA_P21_ENCRYPTED_DNS_TRANSPORT",
		OrthogonalGuard:    `G-WEB et G-RTC imposent R=1 et excluent donc la navigation et les appels sans preuve DNS. G-MIG conserve les compteurs sur le graphe de session au lieu de réinitialiser la durée à chaque tuple. G-REL n'autorise l'attribution à un enfant qu'avec preuve de flux ; sinon le verdict reste limité à l'endpoint. Un endpoint DoQ/DoH approuvé ou un relais approuvé inhibe le feu. Le motif remplace P14/P15, n'utilise aucun QTYPE et reste disjoint de M-01..M-04/P1..P13/P16..P19 par G-DISJ.`,
	},
	{
		ID:                 "P22",
		Name:               "Balise DoQ ou DoH3 réassemblée à travers migration QUIC",
		Category:           CategoryNewGHSA,
		ToolRepresentative: "Hypothèse défensive RFC 9000 §5.1–5.2/§9 ; aucune charge utile",
		PhysicalInvariant:  `Sur un graphe dont les arêtes exigent le même DCID non nul et des directions cohérentes, soit K>=2 tuples réunis, N>=32 événements sur au moins quatre fenêtres disjointes de 30 s, et Δ_i les intervalles entre bursts montants. Le motif vaut R=1 ET K>=2 ET N>=32 ET CV(Δ)<0,12 ET |mediane(Δ_avant)-mediane(Δ_après)|/mediane(Δ_avant)<=0,20, avec au moins huit événements de chaque direction. Les timestamps, CID et tuples sont stockés dans des tableaux fixes ; les fenêtres sans événement ne sont pas interpolées.`,
		ReasonCode:         "GHSA_P22_MIGRATION_BEACON_REASSEMBLY",
		OrthogonalGuard:    `G-MIG exige un CID partagé ou la même socket hôte ; CID nul, collision ou ambiguïté impose l'abstention. Une seule migration NAT ne suffit pas. G-WEB exclut un flux sans R et un téléchargement dont les bursts montants ne satisfont pas la périodicité ; G-RTC exclut le temps réel sans R. G-REL interdit l'accusation d'un enfant si le relais mélange les sessions. P22 n'utilise ni QTYPE ni entropie Markov, donc reste disjoint de P3 et de M-01..M-04/P1..P2/P4..P19 par G-DISJ.`,
	},
	{
		ID:                 "P23",
		Name:               "Alternance requête-réponse DoQ ou DoH3 sous padding et couverture",
		Category:           CategoryNewGHSA,
		ToolRepresentative: "Hypothèse défensive RFC 9250 §5.4 et RFC 8467 §6 ; aucune charge utile",
		PhysicalInvariant:  `Les datagrammes sont groupés en bursts séparés par un silence d'au moins 50 ms. Soit B>=32 bursts sur >=60 s, T = (1/(B-1)) Σ_i 1[dir(B_i)!=dir(B_{i-1})], R_octets = octets_down/octets_up et P_i les débuts de bursts montants. Le motif vaut R=1 ET T>=0,50 ET 1/8<=R_octets<=8 ET CV(diff(P))<=0,35 ET au moins huit bursts dans chaque direction. Tailles et entropies de paquets ne servent pas de critère ; seuls direction, temps, volume et preuve R sont conservés dans des anneaux fixes.`,
		ReasonCode:         "GHSA_P23_PADDED_DNS_TURN_EXCHANGE",
		OrthogonalGuard:    `G-WEB inhibe si R_octets>8 ou T<0,25, ce qui écarte le téléchargement unidirectionnel ; sans preuve DNS, aucun feu n'est possible. G-RTC exclut WebRTC/QUIC sans R. G-MIG réunit d'abord les tuples et évite de compter une migration comme un nouveau burst. G-REL exige l'identité du flux enfant ou limite le verdict au relais. Le motif ne mesure ni rafale QNAME/2 s ni Markov QTYPE : il reste disjoint de M-03, P3 et des autres motifs en clair par G-DISJ.`,
	},
	{
		ID:                 "P24",
		Name:               "Canal DATAGRAM QUIC multiplexé corrélé à des transactions DNS",
		Category:           CategoryNewGHSA,
		ToolRepresentative: "Hypothèse défensive RFC 9221 §3–6 et RFC 9298 §3–6 ; aucune charge utile",
		PhysicalInvariant:  `Précondition obligatoire : le relais expose des compteurs réels DATAGRAM et de streams, car leur type est chiffré sur PCAP. Sur 60 s, soit D_up,D_down>=16 trames DATAGRAM effectivement comptées par le relais, S>=8 transactions/stream FIN, Q>=16 requêtes DNS locales, et M appariements un-à-un avec sorties DATAGRAM dans un délai de 0 à 250 ms. Le motif vaut R=1 ET M/min(Q,D_up)>=0,80 ET D_down>=16 ET S>=8. La négociation max_datagram_frame_size>0 est seulement un indice et ne remplace jamais les compteurs effectifs. Les événements sont des structs à champs fixes dans des anneaux ; aucune lecture du type de trame chiffré n'est inventée.`,
		ReasonCode:         "GHSA_P24_QUIC_DATAGRAM_COVER_CHANNEL",
		OrthogonalGuard:    `G-RTC exclut WebRTC et les médias sans transactions DNS prouvées ; G-WEB exclut MASQUE ou un téléchargement sans R. G-MIG conserve la socket et les compteurs du relais plutôt que le 5-tuple. G-REL impose une correspondance par stream ou un producteur unique ; sinon P24 s'abstient. Sans télémétrie DATAGRAM effective, le motif ne tire pas sur PCAP seul. Il est disjoint de P9 (option EDNS en clair), de P23 (bursts sans compteurs DATAGRAM), de P25 (corrélation générique sans preuve de canal non fiable) et de tous les motifs QNAME/RDATA par G-DISJ.`,
	},
	{
		ID:                 "P25",
		Name:               "Corrélation inter-processus entre DNS loopback et émissions QUIC du relais",
		Category:           CategoryNewGHSA,
		ToolRepresentative: "Hypothèse défensive de bout en bout /proc + inet_diag + PCAP ; aucune charge utile",
		PhysicalInvariant:  `Soient q_i des requêtes DNS loopback attribuées à un enfant (PID,starttime,socket), r_j des datagrammes sortants du relais (PID,starttime,inode), et M les appariements injectifs avec 0<=t(r_j)-t(q_i)<=250 ms. Sur 60 s, Q>=16 et le motif vaut M/min(Q,R_out)>=0,80 ET MADM(lag)/mediane(lag)<=0,25 ET Z>=5. Ici Z=(rho-rho_shift_max)/(MADM_shift+epsilon), avec rho=M/min(Q,R_out), et rho_shift_max le maximum sur onze décalages de ±1 à ±5 s en dehors de la fenêtre de lag. R_out est le nombre de datagrammes candidats après exclusion des autres producteurs. Les réponses doivent aussi présenter une correspondance dans au moins 60 % des transactions appariées. Compteurs et décalages sont calculés dans des anneaux fixes ; les deltas CPU/syscalls sont des preuves secondaires sans seuil universel.`,
		ReasonCode:         "GHSA_P25_RELAY_LOOPBACK_QUIC_CORRELATION",
		OrthogonalGuard:    `G-REL est souverain : si d'autres enfants sont actifs et si le relais n'expose pas la correspondance par stream, R_out ne peut pas être établi et le motif s'abstient ; un cache hit ou un batch non résolu abstient également. G-WEB et G-RTC excluent les flux sans requêtes DNS loopback corrélées. G-MIG suit PID+starttime+inode plutôt que le 5-tuple externe et n'exige pas de CID. Le motif ne tire pas sur la seule suspicion ConnexionSansDNS, ne duplique pas un motif loopback déjà consommé et reste disjoint de P14/P15 ainsi que de M-01..M-04/P1..P19 par G-DISJ.`,
	},
}

// PatternCatalog29 retourne la copie du catalogue complet des 29 motifs DNS et
// transport chiffré (les 23 du catalogue 23 + les 6 motifs P20..P25).
func PatternCatalog29() []PatternSpec {
	catalogue := make([]PatternSpec, 0, 29)
	catalogue = append(catalogue, PatternCatalog23()...)
	for indice := range catalog29Motifs {
		motif := catalog29Motifs[indice]
		motif.Code = motif.ID
		motif.ExpectedReasonCode = motif.ReasonCode
		motif.OrthogonalityGuard = motif.OrthogonalGuard
		catalogue = append(catalogue, motif)
	}
	return catalogue
}

// LookupPatternSpec29 recherche un motif par son identifiant dans PatternCatalog29.
func LookupPatternSpec29(id string) (PatternSpec, bool) {
	if motif, ok := LookupPatternSpec23(id); ok {
		return motif, true
	}
	for indice := range catalog29Motifs {
		if catalog29Motifs[indice].ID == id {
			motif := catalog29Motifs[indice]
			motif.Code = motif.ID
			motif.ExpectedReasonCode = motif.ReasonCode
			motif.OrthogonalityGuard = motif.OrthogonalGuard
			return motif, true
		}
	}
	return PatternSpec{}, false
}
