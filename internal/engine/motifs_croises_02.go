package engine

// Motifs croisés 02 : catalogue de signatures croisant la pile Kubernetes, les
// conteneurs et le runtime Linux (cgroups, namespaces, /proc). Chaque définition
// porte une fenêtre canonique de 96 octets, le sous-système, l'action et la
// sévérité. L'encodage RaBitQ 512D réemploie FeatureExtractor.ExtractTo puis
// Encode512, sans nouvelle voie de calcul.
//
// Les dix premiers motifs (ThreatID 0x0201..0x020A) sont des signatures de code
// ou de configuration vulnérable construites pour la détection. Les cinq suivants
// (ThreatID 0x02B1..0x02B5) sont des observables reconstruits d'exploitations
// d'évasion de conteneur authentiques, dont la provenance est citée dans le
// livrable /devhoros/audits/wps_c2blue_cross_stack/output_cross_02_k8s_container.md.
// Aucune charge réelle n'est revendiquée.
//
// Le paquet engine étant interne et sans dépendance vers son parent, le
// vocabulaire de sous-systèmes et d'actions est celui déjà déclaré par la série
// 05 (motifSubProc, motifSubFile, motifSubNet, motifActExec, motifActConnect,
// motifActRead) et par la série 03 (motifActMmapExec). MotifDef, mustMotifWindow
// et EncodeMotif sont réemployés tels quels, sans redéclaration.

// MotifsCroises02 rend le catalogue complet des quinze motifs. L'ordre est
// stable : motifs de code ou de configuration vulnérable, puis traces
// d'exploitation authentiques.
func MotifsCroises02() []MotifDef {
	return []MotifDef{
		{
			ThreatID:  0x0201,
			Name:      "k8s-pod-hostpath-root-mount",
			Source:    "Manifeste Pod; hostPath / monté sur /host",
			Subsystem: motifSubFile,
			Action:    motifActRead,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("hostPath:/ mountPath:/host readOnly:false open:/host/etc/kubernetes/admin.conf"),
		},
		{
			ThreatID:  0x0202,
			Name:      "k8s-pod-docker-containerd-socket-mount",
			Source:    "Manifeste Pod; sockets du runtime montés",
			Subsystem: motifSubFile,
			Action:    motifActRead,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("hostPath:/var/run/docker.sock hostPath:/run/containerd/containerd.sock open:AF_UNIX"),
		},
		{
			ThreatID:  0x0203,
			Name:      "cgroups-v1-release-agent-abuse",
			Source:    "cgroups v1; release_agent puis cgroup.procs",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("cgroup.release_agent notify_on_release cgroup.procs notify_on_release=1 exec:/payload"),
		},
		{
			ThreatID:  0x0204,
			Name:      "core-pattern-pipe-host-exec-divert",
			Source:    "proc/sys/kernel/core_pattern; pipe |",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("core_pattern |/tmp/x %P ulimit -c unlimited kill -SEGV proc/sys/kernel write"),
		},
		{
			ThreatID:  0x0205,
			Name:      "nsenter-unshare-pod-pivot-init-ns",
			Source:    "nsenter --target 1; unshare --map-root-user",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("nsenter --target 1 --mount --uts --ipc --net --pid /bin/sh unshare --user --map-root-user"),
		},
		{
			ThreatID:  0x0206,
			Name:      "serviceaccount-token-unauthorized-read",
			Source:    "Jeton de compte de service; lecture directe",
			Subsystem: motifSubFile,
			Action:    motifActRead,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("/var/run/secrets/kubernetes.io/serviceaccount/token ca.crt namespace read"),
		},
		{
			ThreatID:  0x0207,
			Name:      "apiserver-anomalous-bearer-user-agent",
			Source:    "API server; Bearer volé et agent curl",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("GET kubernetes.default.svc/api/v1/namespaces/default/secrets Bearer User-Agent:curl"),
		},
		{
			ThreatID:  0x0208,
			Name:      "forged-unsigned-jwt-exfil-none-alg",
			Source:    "JWT alg none forgé puis exfiltré",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow(`{"alg":"none","typ":"JWT"}.eyJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQifQ. exfil/collect`),
		},
		{
			ThreatID:  0x0209,
			Name:      "memfd-create-fexecve-correlated-chain",
			Source:    "memfd_create; fexecve; chaîne corrélée",
			Subsystem: motifSubProc,
			Action:    motifActMmapExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("memfd_create fexecve MFD_CLOEXEC /proc/self/fd/ elf_payload kworker correlated"),
		},
		{
			ThreatID:  0x020A,
			Name:      "proc-recon-mounts-overlay-kubelet",
			Source:    "Reconnaissance /proc/1/root et /proc/*/mounts",
			Subsystem: motifSubFile,
			Action:    motifActRead,
			Severity:  SeverityHigh,
			Window:    mustMotifWindow("/proc/1/root/etc/hostname /proc/*/mounts overlay /var/lib/kubelet /proc/self/root read"),
		},
		{
			ThreatID:  0x02B1,
			Name:      "cve-2019-5736-runc-host-binary-overwrite",
			Source:    "runc < 1.0-rc6; /proc/self/exe; CVE-2019-5736",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("docker exec /proc/self/exe runc overwrite /bin/sh CVE-2019-5736 root host escape"),
		},
		{
			ThreatID:  0x02B2,
			Name:      "cve-2024-21626-leaky-vessels-workdir-escape",
			Source:    "runc 1.1.12; descripteur fuité; CVE-2024-21626",
			Subsystem: motifSubFile,
			Action:    motifActRead,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("WORKDIR /proc/self/fd/7 leaky vessels runc 1.1.12 escape CVE-2024-21626"),
		},
		{
			ThreatID:  0x02B3,
			Name:      "cve-2022-0492-cgroups-release-agent-privesc",
			Source:    "cgroups v1; espace de noms utilisateur; CVE-2022-0492",
			Subsystem: motifSubProc,
			Action:    motifActExec,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("cgroup.release_agent notify_on_release unshare user namespace CVE-2022-0492"),
		},
		{
			ThreatID:  0x02B4,
			Name:      "cve-2020-15257-containerd-shim-ttrpc-escape",
			Source:    "containerd < 1.3.9/1.4.3; socket abstrait; CVE-2020-15257",
			Subsystem: motifSubNet,
			Action:    motifActConnect,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("@/containerd-shim/ abstract unix domain socket ttrpc escape CVE-2020-15257"),
		},
		{
			ThreatID:  0x02B5,
			Name:      "cve-2022-0847-dirty-pipe-page-cache-privesc",
			Source:    "Noyau < 5.16.11; tampon de tube; CVE-2022-0847",
			Subsystem: motifSubFile,
			Action:    motifActRead,
			Severity:  SeverityCritical,
			Window:    mustMotifWindow("pipe buffer splice /etc/passwd root overwrite Dirty Pipe CVE-2022-0847"),
		},
	}
}

// BuildMotifsCroises02Codebook encode le catalogue complet et rend un codebook
// contigu, prêt pour la recherche par distance de Hamming.
func BuildMotifsCroises02Codebook() (*Codebook, error) {
	defs := MotifsCroises02()
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

// SaveMotifsCroises02Codebook écrit le catalogue encodé au format .c2book.
func SaveMotifsCroises02Codebook(path string) error {
	cb, err := BuildMotifsCroises02Codebook()
	if err != nil {
		return err
	}
	return SaveCodebook(path, cb.entries)
}
