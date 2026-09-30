// Package engine - thematic_corpora.go
// Forge hors-ligne et ingestion des gisements reels de vulnerabilites et d'attaques
// en disquettes compactes RaBitQ 512D (.c2book) sous /devhoros/data/vuln_corpora/.
package engine

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Constantes de chemins par defaut des gisements reels sous /devhoros.
const (
	DefaultCVEExploitationSignalsPath = "/devhoros/.llmcall/call-2492922534/000-threatcluster__cve-exploitation-signals__data.jsonl"
	DefaultCVE5YearsPath              = "/devhoros/.llmcall/call-2492922534/001-sk75__2021_2026_CVE_Exploit_Dataset__cve_dataset_5years.jsonl"
	DefaultKernelVulnCSVPath          = "/devhoros/.llmcall/call-1856088084/001-quguanni__kernel-vuln-dataset__vuln_commits_full.csv"
	DefaultCyberNativeDPOPath         = "/devhoros/.llmcall/call-2296473354/001-CyberNative__Code_Vulnerability_Security_DPO__secure_programming_dpo.json"
	DefaultFilelessTestdataPath       = "/devhoros/pkg/c2blue55/internal/probes/testdata"
	DefaultVulnCorporaOutputDir       = "/devhoros/data/vuln_corpora"
)

// resolveThematicPath résout un chemin en consultant d'abord la variable d'environnement
// fournie, puis le chemin par défaut, avec repli relatif pour les données internes au dépôt.
func resolveThematicPath(envVar, defaultPath string, relativeCandidates ...string) string {
	if envVar != "" {
		if v := os.Getenv(envVar); v != "" {
			return v
		}
	}
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath
	}
	for _, cand := range relativeCandidates {
		if _, err := os.Stat(cand); err == nil {
			return cand
		}
	}
	return defaultPath
}

const (
	motifSubWeb uint16 = 4
)

// fnv1a32 calcule l'empreinte 32 bits deterministe d'une chaine.
func fnv1a32(s string) uint32 {
	const (
		offset = uint32(2166136261)
		prime  = uint32(16777619)
	)
	h := offset
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= prime
	}
	return h
}

// splitPayloadInWindows decoupe un tableau d'octets en fenetres de taille window avec pas stride.
func splitPayloadInWindows(data []byte, window, stride int) [][]byte {
	n := len(data)
	if n == 0 {
		return nil
	}
	if n <= window {
		win := make([]byte, n)
		copy(win, data)
		return [][]byte{win}
	}
	var out [][]byte
	for off := 0; off+window <= n; off += stride {
		win := make([]byte, window)
		copy(win, data[off:off+window])
		out = append(out, win)
	}
	if n > window && (n-window)%stride != 0 {
		lastOff := n - window
		win := make([]byte, window)
		copy(win, data[lastOff:])
		out = append(out, win)
	}
	return out
}

// encodePayloadWindow projette une fenetre en vecteur 512D et quantifie l'entree.
func encodePayloadWindow(fe *FeatureExtractor, win []byte, threatID uint32, subsystem, severity, action uint16) (CodebookEntry, bool) {
	var ev Event
	ev.Ts_ns = uint64(threatID)
	ev.Subsystem = subsystem
	ev.Action = action
	copy(ev.Payload[:], win)

	var vec [EmbeddingDim]float32
	vecSlice := vec[:]
	if !fe.ExtractTo(&ev, vecSlice) {
		return CodebookEntry{}, false
	}
	var e CodebookEntry
	bitcodeRef := &e.Bitcode
	Quantize512(vecSlice, bitcodeRef)
	e.ThreatID = threatID
	e.Subsystem = subsystem
	e.Severity = severity
	return e, true
}

// mapSeverityFromCVSS convertit un score ou libelle CVSS en constante de severite du moteur.
func mapSeverityFromCVSS(sevStr string, score float64) uint16 {
	s := strings.ToUpper(strings.TrimSpace(sevStr))
	switch {
	case strings.Contains(s, "CRITICAL") || score >= 9.0:
		return SeverityCritical
	case strings.Contains(s, "HIGH") || score >= 7.0:
		return SeverityHigh
	case strings.Contains(s, "MEDIUM") || score >= 4.0:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

// mapSubsystemFromText infere le sous-systeme a partir des mots-cles de la vulnerabilite.
func mapSubsystemFromText(desc, cwe string) uint16 {
	txt := strings.ToLower(desc + " " + cwe)
	switch {
	case strings.Contains(txt, "web") || strings.Contains(txt, "http") ||
		strings.Contains(txt, "sql") || strings.Contains(txt, "xss") ||
		strings.Contains(txt, "csrf") || strings.Contains(txt, "ssrf") ||
		strings.Contains(txt, "injection") || strings.Contains(txt, "cwe-79") ||
		strings.Contains(txt, "cwe-89") || strings.Contains(txt, "wordpress"):
		return motifSubWeb
	case strings.Contains(txt, "net") || strings.Contains(txt, "socket") ||
		strings.Contains(txt, "packet") || strings.Contains(txt, "tcp") ||
		strings.Contains(txt, "udp") || strings.Contains(txt, "ipv4") ||
		strings.Contains(txt, "ipv6") || strings.Contains(txt, "dns") ||
		strings.Contains(txt, "dos") || strings.Contains(txt, "remote"):
		return motifSubNet
	case strings.Contains(txt, "file") || strings.Contains(txt, "path") ||
		strings.Contains(txt, "directory") || strings.Contains(txt, "traversal") ||
		strings.Contains(txt, "cwe-22") || strings.Contains(txt, "read") ||
		strings.Contains(txt, "write") || strings.Contains(txt, "fs"):
		return motifSubFile
	default:
		return motifSubProc
	}
}

// BuildThematicCVECorpus ingere les gisements de CVE reels (2021-2026) et produit le codebook.
func BuildThematicCVECorpus(paths ...string) (*Codebook, error) {
	if len(paths) == 0 {
		paths = []string{
			resolveThematicPath("C2BLUE_CVE_SIGNALS_PATH", DefaultCVEExploitationSignalsPath),
			resolveThematicPath("C2BLUE_CVE_5YEARS_PATH", DefaultCVE5YearsPath),
		}
	}

	fe := NewFeatureExtractor()
	fePtr := &fe
	var entries []CodebookEntry

	type cveItem struct {
		CveID          string   `json:"cve_id"`
		Description    string   `json:"description"`
		DescriptionEn  string   `json:"description_en"`
		CvssV3Severity string   `json:"cvss_v3_severity"`
		Severity       string   `json:"severity"`
		CvssV3Score    string   `json:"cvss_v3_score"`
		BaseScore      float64  `json:"base_score"`
		CweIds         []string `json:"cwe_ids"`
		Cwe            string   `json:"cwe"`
	}

	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			return nil, fmt.Errorf("cve corpus: open %s: %w", p, err)
		}

		scanner := bufio.NewScanner(f)
		buf := make([]byte, 1<<20)
		scanner.Buffer(buf, 1<<20)

		for {
			if !scanner.Scan() {
				break
			}
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			var item cveItem
			if jerr := json.Unmarshal(line, &item); jerr != nil {
				continue
			}

			cveID := item.CveID
			if cveID == "" {
				continue
			}

			desc := item.Description
			if desc == "" {
				desc = item.DescriptionEn
			}
			if desc == "" {
				continue
			}

			cweStr := item.Cwe
			if len(item.CweIds) > 0 {
				cweStr += " " + strings.Join(item.CweIds, " ")
			}

			sevStr := item.CvssV3Severity
			if sevStr == "" {
				sevStr = item.Severity
			}

			var score float64
			if item.BaseScore > 0 {
				score = item.BaseScore
			}

			sev := mapSeverityFromCVSS(sevStr, score)
			sub := mapSubsystemFromText(desc, cweStr)
			thID := fnv1a32(cveID)

			textPayload := cveID + " " + desc
			windows := splitPayloadInWindows([]byte(textPayload), FeaturePayloadBytes, 48)
			for _, win := range windows {
				if e, ok := encodePayloadWindow(fePtr, win, thID, sub, sev, motifActExec); ok {
					entries = append(entries, e)
				}
			}
		}
		f.Close()
		if scErr := scanner.Err(); scErr != nil && scErr != io.EOF {
			return nil, fmt.Errorf("cve corpus: scanner %s: %w", p, scErr)
		}
	}

	return NewCodebook(entries), nil
}

// BuildThematicKernelCorpus ingere le CSV de vulnerabilites et correctifs reels du noyau Linux.
func BuildThematicKernelCorpus(csvPath string) (*Codebook, error) {
	if csvPath == "" {
		csvPath = resolveThematicPath("C2BLUE_KERNEL_VULN_PATH", DefaultKernelVulnCSVPath)
	}

	f, err := os.Open(csvPath)
	if err != nil {
		return nil, fmt.Errorf("kernel corpus: open %s: %w", csvPath, err)
	}
	defer f.Close()

	reader := csv.NewReader(f)
	reader.FieldsPerRecord = -1

	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("kernel corpus: read header: %w", err)
	}

	colMap := make(map[string]int)
	for i, col := range header {
		colMap[strings.TrimSpace(col)] = i
	}

	fe := NewFeatureExtractor()
	fePtr := &fe
	var entries []CodebookEntry

	for {
		record, rerr := reader.Read()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			continue
		}

		getCol := func(name string) string {
			if idx, ok := colMap[name]; ok && idx < len(record) {
				return record[idx]
			}
			return ""
		}

		fixingCommit := getCol("fixing_commit")
		subsystem := getCol("subsystem")
		subsystemPath := getCol("subsystem_path")
		bugType := getCol("bug_type")
		severityHint := getCol("severity_hint")
		fixSubject := getCol("fix_subject")
		keywords := getCol("keywords")

		if fixingCommit == "" || fixSubject == "" {
			continue
		}

		thID := fnv1a32(fixingCommit)

		var sub uint16
		subLower := strings.ToLower(subsystem + " " + subsystemPath)
		switch {
		case strings.Contains(subLower, "net") || strings.Contains(subLower, "ipv"):
			sub = motifSubNet
		case strings.Contains(subLower, "fs") || strings.Contains(subLower, "btrfs") || strings.Contains(subLower, "ext4"):
			sub = motifSubFile
		default:
			sub = motifSubProc
		}

		var sev uint16
		sevLower := strings.ToLower(severityHint + " " + bugType)
		switch {
		case strings.Contains(sevLower, "security") || strings.Contains(sevLower, "critical") || strings.Contains(sevLower, "deadlock"):
			sev = SeverityCritical
		case strings.Contains(sevLower, "high") || strings.Contains(sevLower, "crash") || strings.Contains(sevLower, "out-of-bounds"):
			sev = SeverityHigh
		case strings.Contains(sevLower, "low") || strings.Contains(sevLower, "refcount"):
			sev = SeverityLow
		default:
			sev = SeverityMedium
		}

		textPayload := fmt.Sprintf("%s: %s [%s, %s, %s]", subsystemPath, fixSubject, bugType, keywords, fixingCommit)
		windows := splitPayloadInWindows([]byte(textPayload), FeaturePayloadBytes, 48)
		for _, win := range windows {
			if e, ok := encodePayloadWindow(fePtr, win, thID, sub, sev, motifActExec); ok {
				entries = append(entries, e)
			}
		}
	}

	return NewCodebook(entries), nil
}

// BuildThematicDPOCorpus ingere les anti-patterns de programmation vulnerable reels de CyberNative DPO.
func BuildThematicDPOCorpus(jsonPath string) (*Codebook, error) {
	if jsonPath == "" {
		jsonPath = resolveThematicPath("C2BLUE_DPO_PATH", DefaultCyberNativeDPOPath)
	}

	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, fmt.Errorf("dpo corpus: read %s: %w", jsonPath, err)
	}

	type dpoEntry struct {
		Lang          string `json:"lang"`
		Vulnerability string `json:"vulnerability"`
		Question      string `json:"question"`
		Chosen        string `json:"chosen"`
		Rejected      string `json:"rejected"`
	}

	var dpoList []dpoEntry

	if uerr := json.Unmarshal(data, &dpoList); uerr != nil {
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		buf := make([]byte, 1<<20)
		scanner.Buffer(buf, 1<<20)
		for {
			if !scanner.Scan() {
				break
			}
			var item dpoEntry
			if err := json.Unmarshal(scanner.Bytes(), &item); err == nil {
				dpoList = append(dpoList, item)
			}
		}
	}

	fe := NewFeatureExtractor()
	fePtr := &fe
	var entries []CodebookEntry

	for i, item := range dpoList {
		vulnCode := item.Rejected
		if vulnCode == "" {
			continue
		}

		thID := fnv1a32(fmt.Sprintf("dpo_%s_%d_%s", item.Lang, i, item.Vulnerability[:minInt(len(item.Vulnerability), 32)]))
		sub := mapSubsystemFromText(item.Vulnerability, item.Lang)

		var sev uint16 = SeverityHigh
		vulnLower := strings.ToLower(item.Vulnerability)
		if strings.Contains(vulnLower, "overflow") || strings.Contains(vulnLower, "execution") || strings.Contains(vulnLower, "injection") {
			sev = SeverityCritical
		}

		cleanCode := strings.ReplaceAll(vulnCode, "```"+item.Lang, "")
		cleanCode = strings.ReplaceAll(cleanCode, "```", "")
		cleanCode = strings.TrimSpace(cleanCode)

		windows := splitPayloadInWindows([]byte(cleanCode), FeaturePayloadBytes, 32)
		for _, win := range windows {
			if e, ok := encodePayloadWindow(fePtr, win, thID, sub, sev, motifActExec); ok {
				entries = append(entries, e)
			}
		}
	}

	return NewCodebook(entries), nil
}

// BuildThematicFilelessCorpus ingere les signatures d'evasion memoire reelles de /proc/pid/maps et /proc/pid/exe.
func BuildThematicFilelessCorpus(testdataDir string) (*Codebook, error) {
	if testdataDir == "" {
		testdataDir = resolveThematicPath("C2BLUE_FILELESS_TESTDATA_PATH", DefaultFilelessTestdataPath,
			filepath.Join("..", "probes", "testdata"),
			filepath.Join("internal", "probes", "testdata"),
		)
	}

	fe := NewFeatureExtractor()
	fePtr := &fe
	var entries []CodebookEntry

	targets := []struct {
		filename  string
		subsystem uint16
		severity  uint16
		action    uint16
	}{
		{"exe_memfd.txt", motifSubProc, SeverityCritical, motifActExec},
		{"exe_deleted.txt", motifSubProc, SeverityHigh, motifActExec},
		{"maps_wx_anon.txt", motifSubProc, SeverityCritical, motifActExec},
		{"maps_tmp_exec.txt", motifSubProc, SeverityHigh, motifActExec},
		{"maps_deleted_tmp.txt", motifSubProc, SeverityHigh, motifActExec},
		{"maps_node_jit.txt", motifSubProc, SeverityLow, motifActExec},
		{"maps_python_clean.txt", motifSubProc, SeverityLow, motifActExec},
	}

	for _, tgt := range targets {
		p := filepath.Join(testdataDir, tgt.filename)
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		lineNum := 0
		for {
			if !scanner.Scan() {
				break
			}
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			lineNum++
			thID := fnv1a32(fmt.Sprintf("%s:%d:%s", tgt.filename, lineNum, line))

			windows := splitPayloadInWindows([]byte(line), FeaturePayloadBytes, 48)
			for _, win := range windows {
				if e, ok := encodePayloadWindow(fePtr, win, thID, tgt.subsystem, tgt.severity, tgt.action); ok {
					entries = append(entries, e)
				}
			}
		}
	}

	return NewCodebook(entries), nil
}

// BuildThematicFIMCorpus compile le catalogue des 25 signatures d'invariance et de persistance critique FIM Linux.
func BuildThematicFIMCorpus(extraPaths ...string) (*Codebook, error) {
	fe := NewFeatureExtractor()
	fePtr := &fe
	var entries []CodebookEntry

	type fimDef struct {
		threatID  uint32
		subsystem uint16
		severity  uint16
		action    uint16
		pattern   string
	}

	patterns := []fimDef{
		{0x5101, motifSubFile, SeverityCritical, motifActExec, "/etc/cron.d/backdoor * * * * * root /bin/bash -c 'tcp c2 connection'"},
		{0x5102, motifSubFile, SeverityCritical, motifActExec, "/etc/crontab: write job python3 -c 'import socket,subprocess,os'"},
		{0x5103, motifSubFile, SeverityCritical, motifActExec, "/var/spool/cron/crontabs/root: fetch http://malware.site/install.sh"},
		{0x5104, motifSubFile, SeverityHigh, motifActExec, "/etc/cron.hourly/syssync: exec /tmp/.kworker payload"},
		{0x5105, motifSubFile, SeverityHigh, motifActExec, "/etc/cron.daily/logrotate_clean: touch /var/log/audit/tampered.log"},

		{0x5201, motifSubFile, SeverityCritical, motifActExec, "/etc/ld.so.preload: /lib/x86_64-linux-gnu/libprocesshider.so injected"},
		{0x5202, motifSubFile, SeverityCritical, motifActExec, "/etc/ld.so.preload: /tmp/evil_hook.so overwriting libc open/read"},
		{0x5203, motifSubFile, SeverityCritical, motifActExec, "/etc/ld.so.conf.d/00-malware.conf: /opt/stealth/lib path appended"},
		{0x5204, motifSubFile, SeverityHigh, motifActExec, "LD_PRELOAD=/tmp/libhook.so /usr/bin/sudo -S id"},

		{0x5301, motifSubFile, SeverityCritical, motifActExec, "/root/.ssh/authorized_keys: append ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 rogue@c2"},
		{0x5302, motifSubFile, SeverityCritical, motifActExec, "/home/*/.ssh/authorized_keys: unauthorized backdoor key deployed"},
		{0x5303, motifSubFile, SeverityHigh, motifActExec, "/etc/ssh/sshd_config: PermitRootLogin yes, PasswordAuthentication yes"},
		{0x5304, motifSubFile, SeverityHigh, motifActExec, "/etc/ssh/sshd_config.d/backdoor.conf: AuthorizedKeysCommand /bin/sh"},

		{0x5401, motifSubFile, SeverityCritical, motifActExec, "/etc/systemd/system/persist.service: ExecStart=/usr/local/bin/agent_k"},
		{0x5402, motifSubFile, SeverityCritical, motifActExec, "/lib/systemd/system/cron-helper.service: WantedBy=multi-user.target"},
		{0x5403, motifSubFile, SeverityHigh, motifActExec, "/etc/systemd/system/default.target.wants/sysmon.service link forged"},

		{0x5501, motifSubFile, SeverityCritical, motifActExec, "/etc/sudoers.d/99-backdoor: ALL=(ALL) NOPASSWD: ALL"},
		{0x5502, motifSubFile, SeverityCritical, motifActExec, "/etc/pam.d/common-auth: auth sufficient pam_permit.so"},
		{0x5503, motifSubFile, SeverityCritical, motifActExec, "/etc/shadow: root hash replaced with zero password salt"},
		{0x5504, motifSubFile, SeverityHigh, motifActExec, "/etc/passwd: toor:x:0:0:root:/root:/bin/bash added uid=0"},
		{0x5505, motifSubFile, SeverityHigh, motifActExec, "/etc/profile.d/00-env.sh: export PROMPT_COMMAND='beacon c2 4444'"},
		{0x5506, motifSubFile, SeverityHigh, motifActExec, "/root/.bashrc: alias sudo='sudo_sniffer' credentials harvesting"},

		{0x5601, motifSubProc, SeverityCritical, motifActExec, "prctl PR_SET_NAME '[kworker/0:0H]' masquerading kernel thread"},
		{0x5602, motifSubProc, SeverityCritical, motifActExec, "memfd_create('kworker', MFD_CLOEXEC) executing in-memory payload"},
		{0x5603, motifSubProc, SeverityHigh, motifActExec, "execveat(/proc/self/fd/3, '', NULL, NULL, AT_EMPTY_PATH) anonymous run"},
	}

	for _, p := range patterns {
		windows := splitPayloadInWindows([]byte(p.pattern), FeaturePayloadBytes, 48)
		for _, win := range windows {
			if e, ok := encodePayloadWindow(fePtr, win, p.threatID, p.subsystem, p.severity, p.action); ok {
				entries = append(entries, e)
			}
		}
	}

	return NewCodebook(entries), nil
}

// ThematicCorpusResult consigne les metadonnees de forge d'une disquette .c2book.
type ThematicCorpusResult struct {
	Name       string
	Path       string
	EntryCount int
	SizeBytes  int64
}

// BuildThematicAllCodebooks compile l'ensemble des 5 catalogues thematiques dans outDir.
func BuildThematicAllCodebooks(outDir string) ([]ThematicCorpusResult, error) {
	if outDir == "" {
		outDir = DefaultVulnCorporaOutputDir
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", outDir, err)
	}

	type builderTask struct {
		name    string
		outFile string
		builder func(arg string) (*Codebook, error)
		arg     string
	}

	tasks := []builderTask{
		{
			name:    "CVE recents (2021-2026)",
			outFile: filepath.Join(outDir, "cve_exploits_2026.c2book"),
			builder: func(arg string) (*Codebook, error) {
				return BuildThematicCVECorpus()
			},
		},
		{
			name:    "Vulnerabilites noyau Linux",
			outFile: filepath.Join(outDir, "kernel_vulns.c2book"),
			builder: func(arg string) (*Codebook, error) {
				return BuildThematicKernelCorpus(arg)
			},
		},
		{
			name:    "Code vulnerable DPO (CyberNative)",
			outFile: filepath.Join(outDir, "code_flaws_dpo.c2book"),
			builder: func(arg string) (*Codebook, error) {
				return BuildThematicDPOCorpus(arg)
			},
		},
		{
			name:    "Traces evasion memoire et fileless",
			outFile: filepath.Join(outDir, "fileless_memory_threats.c2book"),
			builder: func(arg string) (*Codebook, error) {
				return BuildThematicFilelessCorpus(arg)
			},
		},
		{
			name:    "Invariance et Persistance FIM Linux",
			outFile: filepath.Join(outDir, "persistence_fim.c2book"),
			builder: func(arg string) (*Codebook, error) {
				return BuildThematicFIMCorpus()
			},
		},
	}

	var results []ThematicCorpusResult
	for _, t := range tasks {
		cb, err := t.builder(t.arg)
		if err != nil {
			return nil, fmt.Errorf("forge %s: %w", t.name, err)
		}
		if err := SaveCodebook(t.outFile, cb.entries); err != nil {
			return nil, fmt.Errorf("save %s: %w", t.outFile, err)
		}
		st, err := os.Stat(t.outFile)
		if err != nil {
			return nil, err
		}
		results = append(results, ThematicCorpusResult{
			Name:       t.name,
			Path:       t.outFile,
			EntryCount: cb.Len(),
			SizeBytes:  st.Size(),
		})
	}

	return results, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
