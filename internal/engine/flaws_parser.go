package engine

// Flaws parser : catalogue de quinze anti-patterns de désynchronisation de
// parseurs. Chaque définition porte une fenêtre canonique de 96 octets, le
// sous-système et la sévérité. L'encodage RaBitQ 512D réemploie
// FeatureExtractor.ExtractTo puis Encode512, sans nouvelle voie de calcul.
//
// Les motifs couvrent l'omission de validation du type de câble Protobuf, la
// perte de précision des grands entiers JSON, les confusions de longueur TLV,
// ainsi que les expansions d'entités XML et les injections de formules de
// tableur. Le motif 0x2001 reprend la vulnérabilité critique de Celer Network
// (CELER-VULN-01, PbBridge.sol:30-46), dont la validation du wire type est
// absente avant la lecture du champ.
//
// Le vocabulaire de sous-systèmes, d'actions et de sévérités est déjà déclaré
// par la série 05 ; MotifDef, mustMotifWindow et EncodeMotif sont réemployés
// tels quels.

// FlawsParser rend le catalogue complet des quinze motifs. L'ordre est stable
// et suit la progression des identifiants de menace 0x2001 à 0x200F.
func FlawsParser() []MotifDef {
	return []MotifDef{
		{
			ThreatID:  0x2001,
			Name:      "protobuf-solidity-wire-type-omission",
			Source:    "CELER-VULN-01; PbBridge.sol:30-46",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("(tag, wire) = buf.decKey(); if (tag == 2) { m.receiver = buf.decBytes(); }"),
		},
		{
			ThreatID:  0x2002,
			Name:      "protobuf-duplicate-field-last-wins",
			Source:    "Protobuf encoding; champs répétés non singuliers",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("for buf.hasMore() { tag := buf.readTag(); msg.field = buf.readBytes() }"),
		},
		{
			ThreatID:  0x2003,
			Name:      "tlv-length-exceeds-buffer-boundary",
			Source:    "Décodage TLV; longueur non validée",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("tag := buf[0]; len := int(buf[1]); val := buf[2 : 2+len] // sans check len"),
		},
		{
			ThreatID:  0x2004,
			Name:      "json-large-int64-float-precision-loss",
			Source:    "encoding/json vers map[string]interface{}",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("var m map[string]interface{}; json.Unmarshal(data, &m); id := m[\"id\"].(float64)"),
		},
		{
			ThreatID:  0x2005,
			Name:      "asn1-ber-indefinite-length-recursion",
			Source:    "encoding/asn1; longueur indéfinie BER",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("asn1.Unmarshal(derBytes, &val); // récursion non bornée sur BER indefinite"),
		},
		{
			ThreatID:  0x2006,
			Name:      "rlp-unbounded-list-item-traversal",
			Source:    "Recursive Length Prefix; items non bornés",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("elems, err := rlp.DecodeList(data); for _, el := range elems { decode(el) }"),
		},
		{
			ThreatID:  0x2007,
			Name:      "yaml-anchor-merge-bomb-expansion",
			Source:    "gopkg.in/yaml; alias circulaire DoS",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("yaml.Unmarshal(content, &cfg); // alias circular expansion DoS"),
		},
		{
			ThreatID:  0x2008,
			Name:      "http-header-whitespace-line-folding",
			Source:    "RFC 7230 obs-fold; repli de ligne non rejeté",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("header := readHeader(); if strings.HasPrefix(header, \" \") // line folding"),
		},
		{
			ThreatID:  0x2009,
			Name:      "null-byte-string-termination-split",
			Source:    "CWE-158; paramètre de requête concaténé",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("filename := req.Query(\"file\"); path := \"/var/data/\" + filename + \".txt\""),
		},
		{
			ThreatID:  0x200A,
			Name:      "xml-entity-expansion-billion-laughs",
			Source:    "CWE-776; entités DTD non désactivées",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("xml.NewDecoder(r).Decode(&doc); // entités DTD sans désactivation externe"),
		},
		{
			ThreatID:  0x200B,
			Name:      "varint-zigzag-decode-overflow",
			Source:    "encoding/binary; zigzag sur entier non borné",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("v, n := binary.Uvarint(buf); decoded := int64(v>>1) ^ -int64(v&1)"),
		},
		{
			ThreatID:  0x200C,
			Name:      "url-path-traversal-double-encoding",
			Source:    "CWE-22; double décodage de chemin",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("unescaped, _ := url.PathUnescape(raw); if strings.Contains(unescaped, \"..\")"),
		},
		{
			ThreatID:  0x200D,
			Name:      "protobuf-packed-repeated-field-mismatch",
			Source:    "Protobuf packed repeated; type de câble divergent",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityMedium,
			Window:    mustMotifWindow("if wire == WireTypeLengthDelim { for hasBytes() { list.append(decVarint()) } }"),
		},
		{
			ThreatID:  0x200E,
			Name:      "bson-document-length-prefix-trust",
			Source:    "BSON; longueur de document non validée",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("docLen := binary.LittleEndian.Uint32(b[:4]); doc := b[4:docLen]"),
		},
		{
			ThreatID:  0x200F,
			Name:      "csv-formula-injection-unquoted-prefix",
			Source:    "CWE-1236; préfixe de formule non neutralisé",
			Subsystem: motifSubFile,
			Action:    motifActRead,
			Severity:  SeverityMedium,
			Window:    mustMotifWindow("if cell[0] == '=' || cell[0] == '+' || cell[0] == '-' || cell[0] == '@'"),
		},
	}
}

// BuildFlawsParserCodebook encode le catalogue complet et rend un codebook
// contigu, prêt pour la recherche par distance de Hamming.
func BuildFlawsParserCodebook() (*Codebook, error) {
	defs := FlawsParser()
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

// SaveFlawsParserCodebook écrit le catalogue encodé au format .c2book.
func SaveFlawsParserCodebook(path string) error {
	cb, err := BuildFlawsParserCodebook()
	if err != nil {
		return err
	}
	return SaveCodebook(path, cb.entries)
}
