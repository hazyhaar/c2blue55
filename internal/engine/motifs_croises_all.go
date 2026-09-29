package engine

// MotifsCroisesAll agrège les catalogues de motifs croisés multi-stacks 01 à 05.
// Il fournit 75 signatures authentiques d'attaques et de vulnérabilités couvrant :
// - Stack 01 : Node.js × Redis × Files (BullMQ, SSRF, RESP CRLF, Lua sandbox escape)
// - Stack 02 : Kubernetes × Conteneurs × Runtime Linux (hostPath, cgroups v1, runc escape)
// - Stack 03 : Apache Kafka × Pipelines Flux × JVM / Spring (désérialisation, JNDI, JAAS)
// - Stack 04 : Microservices × Proxies × gRPC / NoSQL (HTTP desync, HPACK, NoSQL injections)
// - Stack 05 : Cloud Secrets × CI/CD × IMDS (AWS IMDS, GCP metadata, GitHub Actions)
func MotifsCroisesAll() []MotifDef {
	total := 15 * 5
	out := make([]MotifDef, 0, total)
	out = append(out, MotifsCroises01()...)
	out = append(out, MotifsCroises02()...)
	out = append(out, MotifsCroises03()...)
	out = append(out, MotifsCroises04()...)
	out = append(out, MotifsCroises05()...)
	return out
}

// BuildMotifsCroisesAllCodebook encode l'ensemble des 75 motifs et rend le codebook unifié.
func BuildMotifsCroisesAllCodebook() (*Codebook, error) {
	defs := MotifsCroisesAll()
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

// SaveMotifsCroisesAllCodebook sérialise le catalogue unifié au format .c2book.
func SaveMotifsCroisesAllCodebook(path string) error {
	cb, err := BuildMotifsCroisesAllCodebook()
	if err != nil {
		return err
	}
	return SaveCodebook(path, cb.entries)
}
