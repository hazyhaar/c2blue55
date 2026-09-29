package engine

// Motifs croisés 04 : catalogue de signatures croisant la pile microservices,
// les reverse proxies (HAProxy, Nginx, Envoy, Traefik), les passerelles d'API
// (Kong, Envoy ext_authz, grpc-gateway), les API GraphQL et les magasins NoSQL.
// Chaque définition porte une fenêtre canonique de 96 octets, le sous-système et
// la sévérité. L'encodage RaBitQ 512D réemploie FeatureExtractor.ExtractTo puis
// Encode512, sans nouvelle voie de calcul.
//
// Les dix premiers motifs (ThreatID 0x0401..0x040A) sont des signatures de code
// vulnérable construites pour la détection. Les cinq suivants (ThreatID
// 0x04B1..0x04B5) sont des observables reconstruits de classes d'exploitation
// documentées par leurs CVE, dont la provenance est citée dans la note
// /devhoros/recherche/motifs_croises_04_stack_microservices.md. Aucune charge
// réelle n'est revendiquée et aucune preuve de concept propriétaire n'est
// reproduite.
//
// Le vocabulaire de sous-systèmes et d'actions est celui de c2blue55.go. Les
// constantes de sous-système, MotifDef, mustMotifWindow et EncodeMotif sont déjà
// déclarés par la série 05 et sont réemployés tels quels ; aucun symbole commun
// n'est redéclaré.

// MotifsCroises04 rend le catalogue complet des quinze motifs. L'ordre est
// stable : motifs de code vulnérable, puis traces authentiques.
func MotifsCroises04() []MotifDef {
	return []MotifDef{
		{
			ThreatID:  0x0401,
			Name:      "http-desync-cl-te-smuggling",
			Source:    "CL.TE; CVE-2021-40346, CVE-2019-20372",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("POST / HTTP/1.1\r\nContent-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1"),
		},
		{
			ThreatID:  0x0402,
			Name:      "http-desync-te-cl-smuggling",
			Source:    "TE.CL; CVE-2021-22959, CVE-2021-40346",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("POST / HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST /admin HTTP/1.1"),
		},
		{
			ThreatID:  0x0403,
			Name:      "transfer-encoding-obfuscation-proxy-bypass",
			Source:    "CVE-2021-22959, CVE-2023-29013; Kong request-transformer",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("POST / HTTP/1.1\r\nTransfer-Encoding : chunked\r\nTransfer-Encoding: x\r\nContent-Length: 6"),
		},
		{
			ThreatID:  0x0404,
			Name:      "http2-downgrade-h2-cl-smuggling",
			Source:    "H2.CL; CVE-2020-25017, CVE-2023-44487",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("POST / HTTP/2\r\ncontent-length: 0\r\n\r\nGET /admin HTTP/1.1\r\nX-Forwarded-For: 127.0.0.1"),
		},
		{
			ThreatID:  0x0405,
			Name:      "internal-auth-header-usurpation-ext-authz",
			Source:    "CVE-2021-32777, CVE-2021-32813; Envoy ext_authz",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("GET /internal/orders HTTP/1.1\r\nX-Authenticated-User: admin\r\nX-Internal-Token: 00 Host: api"),
		},
		{
			ThreatID:  0x0406,
			Name:      "x-forwarded-prefix-traefik-host-usurpation",
			Source:    "CVE-2020-15129, CVE-2024-52003",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("GET /dashboard/ HTTP/1.1\r\nX-Forwarded-Prefix: //evil.example\r\nHost: traefik.internal"),
		},
		{
			ThreatID:  0x0407,
			Name:      "graphql-batching-dos-alias-overload",
			Source:    "OWASP API4:2023; alias sans limite de coût",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("{\"query\":\"{a0:u(i:1){e} a1:u(i:2){e} a2:u(i:3){e} a3:u(i:4){e} a4:u(i:5){e}}\"}"),
		},
		{
			ThreatID:  0x0408,
			Name:      "graphql-deep-recursion-cycloid-depth",
			Source:    "Classe DoS applicative; fragment cyclique",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityMedium,
			Window:    mustMotifWindow("{\"query\":\"query{me{friends{friends{friends{friends{friends{friends{id}}}}}}}}\"}"),
		},
		{
			ThreatID:  0x0409,
			Name:      "grpc-gateway-transcoding-path-confusion",
			Source:    "CVE-2021-32779, CVE-2024-7246; grpc-gateway",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("POST /v1/../../admin.UserService/Get HTTP/2\r\n:path: /v1/../../admin.UserService/Get"),
		},
		{
			ThreatID:  0x040A,
			Name:      "nosql-injection-operator-json-bypass",
			Source:    "CVE-2021-22911, CVE-2022-22980; MongoDB",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("{\"username\":{\"$ne\":null},\"password\":{\"$gt\":\"\"},\"role\":{\"$in\":[\"admin\",\"root\"]}}"),
		},
		{
			ThreatID:  0x04B1,
			Name:      "cve-2021-40346-haproxy-cl-overflow",
			Source:    "HAProxy 2.0..2.5; htx_add_header",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("POST / HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nCVE-2021-40346 HAProxy"),
		},
		{
			ThreatID:  0x04B2,
			Name:      "cve-2019-9900-envoy-nul-header-bypass",
			Source:    "Envoy <=1.9.0; octet NUL en valeur d'en-tête",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("GET /admin HTTP/1.1\r\nHost: edge.internal\r\nX-Authenticated-User: admin\x00bypass CVE-2019-9900"),
		},
		{
			ThreatID:  0x04B3,
			Name:      "cve-2024-45410-traefik-connection-hop-hop",
			Source:    "CVE-2021-32813, CVE-2024-45410; en-tête hop-by-hop",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("GET /admin HTTP/1.1\r\nConnection: close, X-Authenticated-User Traefik CVE-2024-45410"),
		},
		{
			ThreatID:  0x04B4,
			Name:      "cve-2024-7246-grpc-hpack-poisoning",
			Source:    "gRPC C++/Python/Ruby; table HPACK partagée",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow(":path=/svc/Get\n:path=/svc/Get\n:authorization=bearer CVE-2024-7246 gRPC HPACK"),
		},
		{
			ThreatID:  0x04B5,
			Name:      "cve-2022-22980-spring-data-mongo-spel-nosql",
			Source:    "Spring Data MongoDB; opérateur $where",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("{\"username\":{\"$where\":\"sleep(5000)\"}} Spring Data MongoDB SpEL CVE-2022-22980"),
		},
	}
}

// BuildMotifsCroises04Codebook encode le catalogue complet et rend un codebook
// contigu, prêt pour la recherche par distance de Hamming.
func BuildMotifsCroises04Codebook() (*Codebook, error) {
	defs := MotifsCroises04()
	entries := make([]CodebookEntry, 0, len(defs))
	for i := range defs {
		entry, _, _, err := EncodeMotif(&defs[i])
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return NewCodebook(entries), nil
}

// SaveMotifsCroises04Codebook écrit le catalogue encodé au format .c2book.
func SaveMotifsCroises04Codebook(path string) error {
	cb, err := BuildMotifsCroises04Codebook()
	if err != nil {
		return err
	}
	return SaveCodebook(path, cb.entries)
}
