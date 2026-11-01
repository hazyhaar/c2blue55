//go:build linux

package probes

import (
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// Constantes internes de transcription, alignées sur les vocabulaires publics
// du moteur c2blue55 (sous-système fichier, actions, drapeaux de verdict).
const (
	subFile uint16 = 2

	actExec  uint16 = 1
	actOpen  uint16 = 2
	actWrite uint16 = 6

	flagVerdictOK uint32 = 0x0001
	flagBlocked   uint32 = 0x0002
)

// Constantes de réponse du protocole fanotify.
const (
	fanAllow = uint32(unix.FAN_ALLOW) // 0x1
	fanDeny  = uint32(unix.FAN_DENY)  // 0x2
)

// pathRule associe une racine protégée à la liste close des noms de commande
// légitimement habilités à la manipuler. Toute commande hors de cette liste
// est réputée hostile sur cette racine.
type pathRule struct {
	prefix string
	allow  []string
}

// pathRules est la table statique des points critiques définis par WP03.
var pathRules = [...]pathRule{
	{
		prefix: "/var/spool/cron",
		allow:  []string{"cron", "crond", "crontab", "atd"},
	},
	{
		prefix: "/etc/ld.so.preload",
		allow:  []string{"ldconfig", "systemd", "dpkg", "apt", "apt-get", "rpm", "pacman"},
	},
	{
		prefix: "/etc/ld.so.conf.d",
		allow:  []string{"ldconfig", "systemd", "dpkg", "apt", "apt-get", "rpm", "pacman"},
	},
	{
		prefix: "/etc/shadow",
		allow:  []string{"passwd", "chpasswd", "usermod", "useradd", "groupadd", "gpasswd", "visudo", "sudo", "su", "systemd", "dpkg"},
	},
	{
		prefix: "/etc/sudoers",
		allow:  []string{"visudo", "sudo", "su", "systemd", "dpkg"},
	},
	{
		prefix: "/etc/sudoers.d",
		allow:  []string{"visudo", "sudo", "su", "systemd", "dpkg"},
	},
}

// classifyPath retourne l'indice de la racine protégée couvrant le chemin, ou
// -1 si le chemin n'est pas protégé. Le rapprochement respecte strictement la
// frontière de segment '/' (par exemple /var/spool/cron/crontabs/root matche
// /var/spool/cron, mais /etc/shadowed ne matche pas /etc/shadow).
func classifyPath(path string) int {
	for len(path) > 1 && path[len(path)-1] == '/' {
		path = path[:len(path)-1]
	}
	for i := range pathRules {
		if matchesProtectedSegment(path, pathRules[i].prefix) {
			return i
		}
	}
	return -1
}

func matchesProtectedSegment(cleanPath, pattern string) bool {
	if before, ok := strings.CutSuffix(pattern, "/"); ok {
		trimmed := before
		return cleanPath == trimmed || strings.HasPrefix(cleanPath, pattern)
	}
	if !strings.HasPrefix(cleanPath, pattern) {
		return false
	}
	if len(cleanPath) == len(pattern) {
		return true
	}
	return cleanPath[len(pattern)] == '/'
}

// commAllowed vérifie l'appartenance du nom de commande à la liste close de la
// classe protégée.
func commAllowed(class int, comm string) bool {
	if class < 0 || class >= len(pathRules) {
		return false
	}
	return slices.Contains(pathRules[class].allow, comm)
}

// DecideVeto arbitre un événement selon son masque, le chemin visé et le nom de
// commande de l'auteur. Il retourne d'une part l'obligation de répondre (vrai
// uniquement pour les événements de permission, seuls à attendre une réponse du
// noyau) et d'autre part la réponse native FAN_ALLOW ou FAN_DENY. Le couple
// (PID, chemin) est matérialisé par le chemin résolu et le nom de commande lu
// dans /proc/<pid>/comm.
func DecideVeto(mask uint64, path, comm string) (respond bool, response uint32) {
	respond = mask&unix.FAN_OPEN_PERM != 0 || mask&unix.FAN_OPEN_EXEC_PERM != 0
	class := classifyPath(path)
	if class < 0 || commAllowed(class, comm) {
		return respond, fanAllow
	}
	return respond, fanDeny
}
