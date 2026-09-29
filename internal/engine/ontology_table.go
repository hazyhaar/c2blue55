// Package engine - ontology_table.go
// Moteur d'évaluation ontologique 4-axes (4xontoLang) en temps constant O(1),
// zéro allocation tas (0 B/op), basé sur des tables d'invariance et masques binaires.
package engine

// Constantes des 4 axes ontologiques quantifiés (20 bits au total).
// Axe 1 : Sujet (6 bits, 0..63)
const (
	SubjUnknown         uint8 = 0
	SubjRootSystemd     uint8 = 1 // Démon système racine géré par systemd
	SubjRootInteractive uint8 = 2 // Shell root interactif
	SubjUserInteractive uint8 = 3 // Shell utilisateur normal
	SubjServiceUnpriv   uint8 = 4 // Service applicatif non privilégié (www-data, redis)
	SubjContainerK8s    uint8 = 5 // Processus sous conteneur / cgroups
	SubjMemfdAnon       uint8 = 6 // Processus issu de /memfd ou anonyme en mémoire
	SubjDeletedBinary   uint8 = 7 // Processus dont le fichier binaire a été supprimé
	SubjKernelWorker    uint8 = 8 // Thread noyau kworker
	SubjMax             uint8 = 63
)

// Axe 2 : Action (5 bits, 0..31)
const (
	ActUnknown     uint8 = 0
	ActExecve      uint8 = 1 // Exécution de binaire / script
	ActMemfdCreate uint8 = 2 // Création de segment anonyme exécutable
	ActMprotectWX  uint8 = 3 // Allocation de mémoire W+X (écriture et exécution)
	ActConnectNet  uint8 = 4 // Établissement de connexion réseau
	ActWriteFile   uint8 = 5 // Écriture / modification de fichier
	ActUnlinkFile  uint8 = 6 // Suppression de fichier
	ActSetxattr    uint8 = 7 // Modification d'attributs étendus de sécurité
	ActPrctlMasq   uint8 = 8 // Masquage de nom de processus (PR_SET_NAME)
	ActDnsTunnel   uint8 = 9 // Requête DNS suspecte / haute entropie
	ActMax         uint8 = 31
)

// Axe 3 : Cible / Objet (5 bits, 0..31)
const (
	TgtUnknown         uint8 = 0
	TgtFIMEtc          uint8 = 1 // Invariance FIM /etc/ (cron, ld.so.preload, sudoers, shadow)
	TgtFIMSsh          uint8 = 2 // Invariance FIM SSH (~/.ssh/authorized_keys, sshd_config)
	TgtTmpExec         uint8 = 3 // Répertoires temporaires (/tmp, /var/tmp, /dev/shm)
	TgtProcSelf        uint8 = 4 // Système de fichiers virtuel /proc/self/maps, mem
	TgtNetExternal     uint8 = 5 // Destination réseau externe
	TgtBinSystem       uint8 = 6 // Binaires système protégés (/bin, /usr/bin, /sbin)
	TgtPipeInterpreter uint8 = 7 // Tube vers interpréteur de commandes (sh, bash, python)
	TgtMax             uint8 = 31
)

// Axe 4 : Contexte (4 bits, 0..15)
const (
	CtxDefault        uint8 = 0
	CtxBootInit       uint8 = 1  // Phase de démarrage du système
	CtxSystemdUnit    uint8 = 2  // Service géré par unité systemd
	CtxInteractiveTTY uint8 = 3  // Session interactive avec terminal
	CtxCronBatch      uint8 = 4  // Tâche planifiée cron légitime
	CtxHighEntropy    uint8 = 5  // Charge à forte entropie Shannon
	CtxNetworkBurst   uint8 = 6  // Rafale d'événements réseau anormale
	CtxMemfdSpoof     uint8 = 7  // Image anonyme memfd_create
	CtxDeletedExe     uint8 = 8  // Image dont le binaire disque a été délié/supprimé
	CtxAnonWX         uint8 = 9  // Présence de mémoire W+X sans exemption JIT
	CtxTmpResidence   uint8 = 10 // Résidence en répertoire temporaire (/tmp, /var/tmp, /dev/shm)
	CtxKworkerSpoof   uint8 = 11 // Usurpation d'identité kworker hors thread noyau
	CtxMax            uint8 = 15
)

// Verdicts de l'évaluation ontologique 4-axes.
const (
	OntoVerdictUnknown   uint8 = 0
	OntoVerdictAllow     uint8 = 1 // Conforme aux invariants formels du système
	OntoVerdictDeny      uint8 = 2 // Violation formelle d'un axiome d'invariance
	OntoVerdictAmbiguous uint8 = 3 // Zone d'ambiguïté nécessitant la corrélation vectorielle
)

// OntoKey est la clé binaire compacte 20 bits représentant le quadruplet ontologique.
// Layout : [12 bits non utilisés][4 bits Contexte][5 bits Cible][5 bits Action][6 bits Sujet]
type OntoKey uint32

// PackOntoKey compacte les 4 dimensions ontologiques en un mot de 20 bits.
func PackOntoKey(subject, action, target, context uint8) OntoKey {
	k := uint32(subject&0x3F) |
		(uint32(action&0x1F) << 6) |
		(uint32(target&0x1F) << 11) |
		(uint32(context&0x0F) << 16)
	return OntoKey(k)
}

// Unpack décompresse la clé ontologique en ses 4 composantes.
func (k OntoKey) Unpack() (subject, action, target, context uint8) {
	u := uint32(k)
	subject = uint8(u & 0x3F)
	action = uint8((u >> 6) & 0x1F)
	target = uint8((u >> 11) & 0x1F)
	context = uint8((u >> 16) & 0x0F)
	return subject, action, target, context
}

// EvaluateOntology applique la batterie d'axiomes d'invariance déterministes.
// L'évaluation est garantie sans boucle, sans récursion et sans allocation tas (0 B/op).
func EvaluateOntology(k OntoKey) uint8 {
	subj, act, tgt, ctx := k.Unpack()

	// Axiome A1 : Invariance FIM critique (/etc/cron*, /etc/ld.so.preload, sudoers, ssh)
	// Toute modification ou suppression par un sujet non-systemd racine est un refus absolu.
	if (tgt == TgtFIMEtc || tgt == TgtFIMSsh) && (act == ActWriteFile || act == ActUnlinkFile || act == ActSetxattr) {
		if subj == SubjRootSystemd && ctx == CtxSystemdUnit {
			return OntoVerdictAllow
		}
		return OntoVerdictDeny
	}

	// Axiome A2 : Invariance mémoire exécutable et évasion fileless
	// Toute exécution ou connexion depuis /memfd ou un binaire supprimé est formellement interdite.
	if (subj == SubjMemfdAnon || subj == SubjDeletedBinary) && (act == ActExecve || act == ActConnectNet || act == ActMprotectWX) {
		return OntoVerdictDeny
	}

	// Axiome A3 : Création de segments mémoire WX ou memfd anonyme depuis un service non privilégié
	if (act == ActMemfdCreate || act == ActMprotectWX) && (subj == SubjServiceUnpriv || subj == SubjContainerK8s) {
		return OntoVerdictDeny
	}

	// Axiome A4 : Masquage hostile de processus (PR_SET_NAME)
	// Seul un thread noyau légitime peut porter l'identité noyau.
	if act == ActPrctlMasq && subj != SubjKernelWorker {
		return OntoVerdictDeny
	}

	// Axiome A5 : Exécution depuis les répertoires temporaires par un démon
	if tgt == TgtTmpExec && act == ActExecve && (subj == SubjServiceUnpriv || ctx == CtxSystemdUnit) {
		return OntoVerdictDeny
	}

	// Axiome A6 : Exécution via tube direct vers un interpréteur
	if tgt == TgtPipeInterpreter && act == ActExecve {
		return OntoVerdictDeny
	}

	// Axiome A7 : Tunnel DNS avec forte entropie
	if act == ActDnsTunnel && ctx == CtxHighEntropy && tgt == TgtNetExternal {
		return OntoVerdictDeny
	}

	// Axiome A8 : Détection d'usurpation de contexte noyau ou d'évasion mémoire
	// (kworker usurpé, exécution memfd_create, binaire supprimé ou pages anonymes W+X)
	if ctx == CtxKworkerSpoof || ctx == CtxMemfdSpoof || ctx == CtxDeletedExe || ctx == CtxAnonWX {
		return OntoVerdictDeny
	}

	// Axiome A9 : Exécution ou connexion réseau depuis répertoires temporaires sensibles
	if ctx == CtxTmpResidence && (act == ActExecve || act == ActConnectNet) {
		return OntoVerdictDeny
	}

	// Axiome B1 : Bénignité certifiée des opérations système nominales
	if subj == SubjRootSystemd && ctx == CtxSystemdUnit && act == ActExecve && tgt == TgtBinSystem {
		return OntoVerdictAllow
	}
	if subj == SubjUserInteractive && ctx == CtxInteractiveTTY && act == ActExecve && tgt == TgtBinSystem {
		return OntoVerdictAllow
	}

	// Hors des axiomes tranchés d'avance : cas limite ambigu nécessitant l'analyse vectorielle.
	return OntoVerdictAmbiguous
}

// DeriveOntoContext dérive mécaniquement le contexte ontologique à partir des constatations
// matérielles et système réelles (liens symboliques /proc/<pid>/exe, cartographie mémoire /proc/<pid>/maps, comm).
// Cette fonction élimine tout spoofing en refusant les déclarations passives d'un processus.
func DeriveOntoContext(exeTarget []byte, isMemfd bool, isDeleted bool, hasWXAnon bool, comm []byte, pid uint32) uint8 {
	// 1. Usurpation de kworker : un thread noyau légitime a typiquement un PID bas (PID <= 2 ou pas de binaire userspace).
	// Si un processus déclare "kworker" dans comm mais détient une cible d'exécutable non-nulle ou un PID applicatif :
	if isKworker(comm) && (pid > 2 || len(exeTarget) > 0) {
		return CtxKworkerSpoof
	}

	// 2. Fichier anonyme memfd_create
	if isMemfd || indexOfStr(exeTarget, "/memfd:") >= 0 {
		return CtxMemfdSpoof
	}

	// 3. Binaire supprimé du disque (deleted)
	if isDeleted || indexOfStr(exeTarget, "(deleted)") >= 0 {
		return CtxDeletedExe
	}

	// 4. Régions mémoire inscriptibles et exécutables anonymes
	if hasWXAnon {
		return CtxAnonWX
	}

	// 5. Exécution depuis répertoires temporaires sensibles
	if indexOfStr(exeTarget, "/tmp/") >= 0 || indexOfStr(exeTarget, "/var/tmp/") >= 0 || indexOfStr(exeTarget, "/dev/shm/") >= 0 {
		return CtxTmpResidence
	}

	return CtxDefault
}

func isKworker(comm []byte) bool {
	return len(comm) >= 7 && string(comm[:7]) == "kworker"
}

func indexOfStr(b []byte, s string) int {
	n := len(s)
	if n == 0 {
		return 0
	}
	if len(b) < n {
		return -1
	}
	for i := 0; i <= len(b)-n; i++ {
		match := true
		for j := 0; j < n; j++ {
			if b[i+j] != s[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// OntoDiagnostic traduit un quadruplet ontologique en diagnostic textuel explicite pour HITL.
func OntoDiagnostic(k OntoKey) string {
	subj, act, tgt, ctx := k.Unpack()
	v := EvaluateOntology(k)

	subjStr := "Inconnu"
	switch subj {
	case SubjRootSystemd:
		subjStr = "RootSystemd"
	case SubjRootInteractive:
		subjStr = "RootInteractif"
	case SubjUserInteractive:
		subjStr = "UserInteractif"
	case SubjServiceUnpriv:
		subjStr = "ServiceNonPrivilege"
	case SubjContainerK8s:
		subjStr = "ConteneurK8s"
	case SubjMemfdAnon:
		subjStr = "MemfdAnonyme"
	case SubjDeletedBinary:
		subjStr = "BinaireSupprime"
	case SubjKernelWorker:
		subjStr = "KernelWorker"
	}

	actStr := "Inconnue"
	switch act {
	case ActExecve:
		actStr = "Execve"
	case ActMemfdCreate:
		actStr = "MemfdCreate"
	case ActMprotectWX:
		actStr = "MprotectWX"
	case ActConnectNet:
		actStr = "ConnectNet"
	case ActWriteFile:
		actStr = "WriteFile"
	case ActUnlinkFile:
		actStr = "UnlinkFile"
	case ActSetxattr:
		actStr = "Setxattr"
	case ActPrctlMasq:
		actStr = "PrctlMasquerade"
	case ActDnsTunnel:
		actStr = "DnsTunnel"
	}

	tgtStr := "Inconnue"
	switch tgt {
	case TgtFIMEtc:
		tgtStr = "FIM:/etc"
	case TgtFIMSsh:
		tgtStr = "FIM:~/.ssh"
	case TgtTmpExec:
		tgtStr = "TmpExec:/tmp"
	case TgtProcSelf:
		tgtStr = "ProcSelf:/proc"
	case TgtNetExternal:
		tgtStr = "ReseauExterne"
	case TgtBinSystem:
		tgtStr = "BinairesSysteme"
	case TgtPipeInterpreter:
		tgtStr = "PipeInterpreteur"
	}

	ctxStr := "Defaut"
	switch ctx {
	case CtxBootInit:
		ctxStr = "BootInit"
	case CtxSystemdUnit:
		ctxStr = "SystemdUnit"
	case CtxInteractiveTTY:
		ctxStr = "InteractiveTTY"
	case CtxCronBatch:
		ctxStr = "CronBatch"
	case CtxHighEntropy:
		ctxStr = "HighEntropy"
	case CtxNetworkBurst:
		ctxStr = "NetworkBurst"
	case CtxMemfdSpoof:
		ctxStr = "MemfdSpoof"
	case CtxDeletedExe:
		ctxStr = "DeletedExe"
	case CtxAnonWX:
		ctxStr = "AnonWX"
	case CtxTmpResidence:
		ctxStr = "TmpResidence"
	case CtxKworkerSpoof:
		ctxStr = "KworkerSpoof"
	}

	vStr := "AMBIGU"
	if v == OntoVerdictAllow {
		vStr = "CONFORME"
	} else if v == OntoVerdictDeny {
		vStr = "VIOLATION"
	}

	return "[Onto4x:" + vStr + "] Sujet=" + subjStr + " Action=" + actStr + " Cible=" + tgtStr + " Contexte=" + ctxStr
}
