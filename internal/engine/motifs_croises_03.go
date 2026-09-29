package engine

// Motifs croisés 03 : catalogue de signatures croisant la pile Apache Kafka,
// les brokers distribués, les pipelines de flux et les applications
// consommatrices JVM/Spring. Chaque définition porte une fenêtre canonique de
// 96 octets, le sous-système et la sévérité. L'encodage RaBitQ 512D réemploie
// FeatureExtractor.ExtractTo puis Encode512, sans nouvelle voie de calcul.
//
// Les dix premiers motifs (ThreatID 0x0301..0x030A) sont des signatures de code
// vulnérable construites pour la détection. Les cinq suivants (ThreatID
// 0x03B1..0x03B5) sont des observables reconstruits d'exploitations
// authentiques, dont la provenance est citée dans le workfile
// /devhoros/c2blue55-motifs-croises-03.work. Aucune charge réelle n'est
// revendiquée.
//
// Le vocabulaire de sous-systèmes est celui de c2blue55.go : il n'existe pas de
// sous-système mémoire dédié, de sorte que les indicateurs W^X sont portés par
// motifSubProc avec l'action motifActMmapExec. Les constantes de sous-système,
// MotifDef, mustMotifWindow et EncodeMotif sont déjà déclarés par la série 05 et
// sont réemployés tels quels.

// motifActMmapExec est l'action d'exécution mémoire de c2blue55.go:31. Elle
// prolonge le vocabulaire d'actions sans collision avec les valeurs 1..6.
const motifActMmapExec uint16 = 7

// MotifsCroises03 rend le catalogue complet des quinze motifs. L'ordre est
// stable : motifs de code vulnérable, puis traces authentiques.
func MotifsCroises03() []MotifDef {
	return []MotifDef{
		{
			ThreatID:  0x0301,
			Name:      "kafka-consumer-java-native-deserialization",
			Source:    "ysoserial; ConsumerRecord.value()",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("ObjectInputStream.readObject() ConsumerRecord.value() ac ed 00 05 CommonsCollections1"),
		},
		{
			ThreatID:  0x0302,
			Name:      "jackson-default-typing-jndi-gadget",
			Source:    "Jackson enableDefaultTyping(); JdbcRowSetImpl",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("ObjectMapper.enableDefaultTyping() @class JdbcRowSetImpl ldap://"),
		},
		{
			ThreatID:  0x0303,
			Name:      "spring-kafka-jsondeserializer-trusted-wildcard",
			Source:    "Spring Kafka JsonDeserializer; type headers",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("spring.json.trusted.packages=* use.type.headers=true __TypeId__ JsonDeserializer"),
		},
		{
			ThreatID:  0x0304,
			Name:      "kafka-connect-rest-jndi-jaas-override",
			Source:    "CVE-2023-25194; Connect REST POST /connectors",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("POST /connectors producer.override.sasl.jaas.config JndiLoginModule ldap://"),
		},
		{
			ThreatID:  0x0305,
			Name:      "log4shell-jndi-record-value-logged",
			Source:    "CVE-2021-44228; Connect/Streams logger",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("${jndi:ldap://attacker/a} Kafka Connect record.value logged by log4j"),
		},
		{
			ThreatID:  0x0306,
			Name:      "jmx-rmi-unauthenticated-mbean-instantiate",
			Source:    "JMX RMI ports 1099/9999; broker et Connect",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("service:jmx:rmi:///jndi/rmi://broker:9999/jmxrmi MBeanInstantiator.instantiate"),
		},
		{
			ThreatID:  0x0307,
			Name:      "kafka-streams-kryo-unregistered-class-gadget",
			Source:    "Kryo setRegistrationRequired(false); Chill Serde",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("kryo.setRegistrationRequired(false) chill-scala Serde instantiate gadget"),
		},
		{
			ThreatID:  0x0308,
			Name:      "go-kafka-consumer-unsafe-decode-plugin",
			Source:    "Sarama/Confluent; encoding/gob non sûr",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("encoding/gob.NewDecoder(msg.Value).Decode(&plugin) sarama consumer unsafe"),
		},
		{
			ThreatID:  0x0309,
			Name:      "kafka-plaintext-sasl-credentials-listener",
			Source:    "Broker listeners; SASL/PLAIN sur PLAINTEXT",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("listeners=PLAINTEXT://0.0.0.0:9092 sasl.mechanism=PLAIN username password"),
		},
		{
			ThreatID:  0x030A,
			Name:      "kafka-9092-magic-wx-exec-correlation",
			Source:    "Corrélation SubNet x SubProc (W^X)",
			Subsystem: motifSubProc,
			Action:    motifActMmapExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("9092 burst ac ed 00 05 memfd W^X JIT exec sh -c curl"),
		},
		{
			ThreatID:  0x03B1,
			Name:      "cve-2023-25194-connect-jndi-jaas",
			Source:    "Apache Kafka 2.3.0..3.3.2; correctif 3.4.0",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("producer.override.sasl.jaas.config JndiLoginModule ldap:// CVE-2023-25194"),
		},
		{
			ThreatID:  0x03B2,
			Name:      "cve-2021-44228-log4shell-kafka",
			Source:    "Log4j2 2.0-beta9..2.15.0; CISA KEV 2021-12-10",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("${jndi:ldap://x/a} log4j-core 2.14.1 record value substitution"),
		},
		{
			ThreatID:  0x03B3,
			Name:      "cve-2023-34040-spring-kafka-header-deser",
			Source:    "Spring for Apache Kafka 3.0.9/2.9.10; CWE-502",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("spring_json_header_types ErrorHandlingDeserializer checkDeserExWhenValueNull CVE-2023-34040"),
		},
		{
			ThreatID:  0x03B4,
			Name:      "cve-2024-31141-configprovider-file-read",
			Source:    "Kafka Clients 2.3.0..3.7.0; CWE-552; correctif 3.8.0",
			Subsystem: motifSubFile,
			Action:    motifActRead,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("FileConfigProvider DirectoryConfigProvider arbitrary file read CVE-2024-31141"),
		},
		{
			ThreatID:  0x03B5,
			Name:      "cve-2025-27817-oauthbearer-file-ssrf",
			Source:    "Kafka Client 3.1.0..3.9.0; CWE-918; correctif 3.9.1/4.0.0",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("sasl.oauthbearer.token.endpoint.url=file:///etc/passwd jaas CVE-2025-27817"),
		},
	}
}

// BuildMotifsCroises03Codebook encode le catalogue complet et rend un codebook
// contigu, prêt pour la recherche par distance de Hamming.
func BuildMotifsCroises03Codebook() (*Codebook, error) {
	defs := MotifsCroises03()
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

// SaveMotifsCroises03Codebook écrit le catalogue encodé au format .c2book.
func SaveMotifsCroises03Codebook(path string) error {
	cb, err := BuildMotifsCroises03Codebook()
	if err != nil {
		return err
	}
	return SaveCodebook(path, cb.entries)
}
