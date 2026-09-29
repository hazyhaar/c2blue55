// Package c2blue55 — subsystems.go
// Définitions canoniques unifiées des sous-systèmes d'observation,
// correspondances bijectives avec l'oracle de santé serveur et utilitaires d'audit.
package c2blue55

import (
	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

// Constantes canoniques des sous-systèmes de capture d'observation.
// Ces identifiants sont strictement disjoints et immuables.
const (
	SubProc    uint16 = 1 // Processus (fork, exec, LOLBAS)
	SubFile    uint16 = 2 // Système de fichiers (fanotify, altération doctrine)
	SubNet     uint16 = 3 // Réseau (sockets, balises beaconing, exfiltration)
	SubMCP     uint16 = 4 // Proxy JSON-RPC 2.0 des outils MCP d'agents IA
	SubHarness uint16 = 5 // Intégrité doctrinale (AGENTS.md, gardes, commit)
	SubEntropy uint16 = 6 // Entropie de Shannon et classification de charge utile
	SubGPU     uint16 = 7 // Tenseurs et mémoire VRAM GPU
)

// SubMem est un alias historique conservé pour rétro-compatibilité,
// pointant désormais explicitement sur SubMCP (0x0004).
const SubMem uint16 = SubMCP

// SubsystemName retourne la désignation textuelle canonique d'un sous-système.
func SubsystemName(sub uint16) string {
	switch sub {
	case SubProc:
		return "Process"
	case SubFile:
		return "Filesystem"
	case SubNet:
		return "Network"
	case SubMCP:
		return "MCP-Agent"
	case SubHarness:
		return "Harness"
	case SubEntropy:
		return "Entropy"
	case SubGPU:
		return "GPU"
	default:
		return "Unknown"
	}
}

// SubsystemToOracle convertit un identifiant de sous-système c2blue55 vers
// l'identifiant correspondant dans l'oracle de santé journalier (engine.OracleSub*).
func SubsystemToOracle(sub uint16) uint16 {
	switch sub {
	case SubProc:
		return engine.OracleSubProc
	case SubFile:
		return engine.OracleSubStorage
	case SubNet:
		return engine.OracleSubNet
	case SubMCP:
		return engine.OracleSubAgent
	case SubHarness:
		return engine.OracleSubService
	case SubEntropy:
		return engine.OracleSubKernel
	case SubGPU:
		return engine.OracleSubKernel
	default:
		return engine.OracleSubKernel
	}
}

// OracleToSubsystem convertit un identifiant d'oracle de santé vers le sous-système
// canonique c2blue55 correspondant.
func OracleToSubsystem(oracleSub uint16) uint16 {
	switch oracleSub {
	case engine.OracleSubProc:
		return SubProc
	case engine.OracleSubStorage:
		return SubFile
	case engine.OracleSubNet:
		return SubNet
	case engine.OracleSubAgent:
		return SubMCP
	case engine.OracleSubService:
		return SubHarness
	case engine.OracleSubKernel, engine.OracleSubAuth:
		return SubProc
	default:
		return SubProc
	}
}
