package engine

// Motifs croisés 01 : catalogue de signatures croisant la pile Node.js, les
// files de travail (Bull/BullMQ sur Redis), les parseurs HTTP embarqués et les
// désérialisations non restreintes. Chaque définition porte une fenêtre
// canonique de 96 octets, le sous-système et la sévérité. L'encodage RaBitQ 512D
// réemploie FeatureExtractor.ExtractTo puis Encode512, sans nouvelle voie de
// calcul.
//
// Les dix premiers motifs (ThreatID 0x0101..0x010A) sont des signatures de code
// vulnérable construites pour la détection. Les cinq suivants (ThreatID
// 0x01B1..0x01B5) sont des observables reconstruits d'exploitations
// authentiques, dont la provenance est citée dans le workfile
// /devhoros/audits/wps_c2blue_cross_stack/output_cross_01_node_redis.md. Aucune
// charge réelle n'est revendiquée.
//
// Le vocabulaire de sous-systèmes et d'actions est celui de c2blue55.go. Les
// constantes motifSub*, motifAct*, Severity*, MotifDef, mustMotifWindow et
// EncodeMotif sont déjà déclarés par la série 05 et sont réemployés tels quels.

// MotifsCroises01 rend le catalogue complet des quinze motifs. L'ordre est
// stable : motifs de code vulnérable, puis traces authentiques.
func MotifsCroises01() []MotifDef {
	return []MotifDef{
		{
			ThreatID:  0x0101,
			Name:      "ssrf-fetch-axios-unvalidated-url",
			Source:    "Express req.query; fetch/axios/https.get",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("fetch(req.query.url) axios.get(url) https.get(target)"),
		},
		{
			ThreatID:  0x0102,
			Name:      "resp-crlf-injection-raw-socket",
			Source:    "Enveloppe RESP écrite sur socket brut",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("*3\r\n$3\r\nSET\r\n$4\r\nkey\r\n$4\r\nval\r\n EVAL CONFIG SLAVEOF"),
		},
		{
			ThreatID:  0x0103,
			Name:      "c-http-parser-snprintf-redis-crlf",
			Source:    "Parseur HTTP en C; snprintf vers socket Redis",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("snprintf(buf, sizeof buf, \"*2\\r\\n$3\\r\\nGET\\r\\n$%zu\\r\\n%s\\r\\n\", klen, key)"),
		},
		{
			ThreatID:  0x0104,
			Name:      "python-ssrf-urlopen-requests-redis",
			Source:    "Flask request.args/form; urllib/requests",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("urlopen(request.args.get(\"url\")) requests.get(request.form['url'])"),
		},
		{
			ThreatID:  0x0105,
			Name:      "prototype-pollution-job-merge-proto",
			Source:    "Object.assign / _.merge sur job.data",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("Object.assign(target, job.data) {\"__proto__\": {\"polluted\": true}}"),
		},
		{
			ThreatID:  0x0106,
			Name:      "child-process-exec-shell-true-injection",
			Source:    "child_process.exec; option shell:true",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("child_process.exec('convert ' + job.data.file, { shell: true }) ; curl | bash"),
		},
		{
			ThreatID:  0x0107,
			Name:      "ejs-template-injection-output-function-name",
			Source:    "CVE-2022-29078 / CVE-2023-29827; ejs.render",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("ejs.render(template, { settings: job.data.settings }) outputFunctionName"),
		},
		{
			ThreatID:  0x0108,
			Name:      "celery-pickle-unrestricted-deserialization",
			Source:    "Celery task_serializer=pickle; pickle.loads",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("pickle.loads(app.backend.get(key)) task_serializer='pickle' cposix\nsystem\n"),
		},
		{
			ThreatID:  0x0109,
			Name:      "dynamic-require-import-job-handler",
			Source:    "Chargeur dynamique piloté par job.data",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("require(job.data.handler) import(payload.module) mod.run(job.data.args)"),
		},
		{
			ThreatID:  0x010A,
			Name:      "redis-config-set-dir-ssh-authorized-keys",
			Source:    "Rogue server Redis; CONFIG SET dir /root/.ssh",
			Subsystem: motifSubFile,
			Action:    motifActRead,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("CONFIG SET dir /root/.ssh CONFIG SET dbfilename authorized_keys BGREWRITEAOF"),
		},
		{
			ThreatID:  0x01B1,
			Name:      "cve-2022-0543-redis-lua-sandbox-escape",
			Source:    "Debian Redis; CISA KEV 2022-03-28",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("EVAL \"local io_l=package.loadlib('/usr/lib/x86_64-linux-gnu/liblua5.1.so.0','luaopen_io')\" 0"),
		},
		{
			ThreatID:  0x01B2,
			Name:      "cve-2021-32625-stralgo-lcs-int-overflow",
			Source:    "Redis < 6.0.14 et 6.2.0..6.2.4",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("STRALGO LCS IDX KEYS k1 k2 LEN integer overflow heap corruption"),
		},
		{
			ThreatID:  0x01B3,
			Name:      "cve-2024-31449-redis-lua-bit-stack-overflow",
			Source:    "Redis 6.2.16 / 7.2.6 / 7.4.1; bibliothèque bit",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("SCRIPT LOAD EVAL bit.tobit bit.bnot bit.bor stack overflow"),
		},
		{
			ThreatID:  0x01B4,
			Name:      "cve-2025-49844-redishell-lua-uaf",
			Source:    "Redis < 8.2.2; RediShell",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("EVALSHA collectgarbage setmetatable use-after-free RediShell CVE-2025-49844"),
		},
		{
			ThreatID:  0x01B5,
			Name:      "cve-2021-23727-celery-redis-pickle-stored-rce",
			Source:    "Celery < 5.2.2; métadonnée de résultat en pickle",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("\x80\x04cposix\nsystem\nq\x00X\x06\x00\x00\x00whoamiq\x01\x85q\x02Rq\x03. Celery Redis backend"),
		},
	}
}

// BuildMotifsCroises01Codebook encode le catalogue complet et rend un codebook
// contigu, prêt pour la recherche par distance de Hamming.
func BuildMotifsCroises01Codebook() (*Codebook, error) {
	defs := MotifsCroises01()
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

// SaveMotifsCroises01Codebook écrit le catalogue encodé au format .c2book.
func SaveMotifsCroises01Codebook(path string) error {
	cb, err := BuildMotifsCroises01Codebook()
	if err != nil {
		return err
	}
	return SaveCodebook(path, cb.entries)
}
