// Package c2blue55 — server_oracle_logline.go
// Analyse d'une ligne de journal pour le silo d'oracle : horodatage (ISO 8601
// / RFC 3339 avec fuseau et fractions, syslog BSD, préfixe de priorité
// syslog), acteur émetteur, et gabarit normalisé de la ligne.
package c2blue55

import (
	"path/filepath"
	"strings"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

// tsStatus qualifie l'horodatage en tête de ligne.
type tsStatus uint8

const (
	tsAbsent  tsStatus = iota // aucune forme d'horodatage reconnue
	tsValid                   // horodatage reconnu et valide
	tsInvalid                 // forme d'horodatage reconnue, valeur impossible
)

// nowFunc donne l'instant de référence de l'inférence d'année syslog BSD ;
// variable pour les tests.
var nowFunc = time.Now

// parseTimestamp lit l'horodatage en tête de ligne et rend le temps Unix, la
// suite de la ligne (espaces de tête retirés) et son statut. Formes reconnues,
// après un éventuel préfixe de priorité syslog « <PRI> » ou « <PRI>1 » :
//
//   - ISO 8601 / RFC 3339 : « 2026-09-19T18:45:00 », « 2026-09-19 18:45:00 »,
//     avec fraction facultative (« .123456 », « ,5 ») et fuseau facultatif
//     (« Z », « +02:00 », « -0500 », « +02 ») ; sans fuseau, l'heure est UTC ;
//   - syslog BSD : « Sep 19 18:45:00 » ou « Sep  9 18:45:00 », l'année étant
//     celle de l'instant présent, ou la précédente si la date tomberait plus
//     de deux jours dans le futur (journal de décembre lu en janvier).
//
// Une ligne qui commence comme une date (« AAAA-MM-JJ » ou mois syslog suivi
// d'un jour) mais dont la suite est mal formée, ou dont la valeur est
// impossible (13e mois, 30 février, 25 h, avant 1970), rend tsInvalid. Aucune
// lecture ne dépasse la longueur de la ligne.
func parseTimestamp(line string) (uint64, string, tsStatus) {
	line = stripSyslogPriority(line)
	if ts, n, st := parseISOTimestamp(line); st != tsAbsent {
		if st != tsValid {
			return 0, line, st
		}
		return ts, strings.TrimLeft(line[n:], " \t"), tsValid
	}
	if ts, n, st := parseBSDTimestamp(line); st != tsAbsent {
		if st != tsValid {
			return 0, line, st
		}
		return ts, strings.TrimLeft(line[n:], " \t"), tsValid
	}
	return 0, line, tsAbsent
}

// stripSyslogPriority retire « <PRI> » (1 à 3 chiffres) et, pour RFC 5424, la
// version « 1 » qui le suit.
func stripSyslogPriority(line string) string {
	if len(line) < 3 || line[0] != '<' {
		return line
	}
	i := 1
	for i < len(line) && i <= 3 && isDigit(line[i]) {
		i++
	}
	if i == 1 || i >= len(line) || line[i] != '>' {
		return line
	}
	rest := line[i+1:]
	if len(rest) >= 2 && rest[0] == '1' && rest[1] == ' ' {
		rest = rest[2:]
	}
	return rest
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// digitsAt lit n chiffres à partir de i ; faux si la ligne est trop courte ou
// si un caractère n'est pas un chiffre.
func digitsAt(s string, i, n int) (int, bool) {
	if i < 0 || i+n > len(s) {
		return 0, false
	}
	v := 0
	for k := i; k < i+n; k++ {
		if !isDigit(s[k]) {
			return 0, false
		}
		v = v*10 + int(s[k]-'0')
	}
	return v, true
}

// validDate construit l'instant et vérifie qu'il ne résulte d'aucune
// normalisation (30 février, 24:00…) ni ne précède 1970.
func validDate(year, month, day, hour, minute, sec, nsec int, loc *time.Location) (time.Time, bool) {
	if year < 1970 || year > 9999 || month < 1 || month > 12 || day < 1 || day > 31 ||
		hour > 23 || minute > 59 || sec > 60 {
		return time.Time{}, false
	}
	if sec == 60 { // seconde intercalaire : ramenée à la dernière seconde de la minute
		sec = 59
	}
	t := time.Date(year, time.Month(month), day, hour, minute, sec, nsec, loc)
	lt := t.In(loc)
	if lt.Year() != year || int(lt.Month()) != month || lt.Day() != day || t.Unix() < 0 {
		return time.Time{}, false
	}
	return t, true
}

// parseISOTimestamp lit un horodatage ISO 8601 / RFC 3339 et rend le temps
// Unix et le nombre d'octets consommés.
func parseISOTimestamp(s string) (uint64, int, tsStatus) {
	year, ok1 := digitsAt(s, 0, 4)
	if !ok1 || len(s) < 10 || s[4] != '-' {
		return 0, 0, tsAbsent
	}
	month, ok2 := digitsAt(s, 5, 2)
	day, ok3 := digitsAt(s, 8, 2)
	if !ok2 || !ok3 || s[7] != '-' {
		return 0, 0, tsAbsent
	}
	// À partir d'ici la ligne commence par une date : toute suite mal formée est invalide.
	if len(s) < 19 || (s[10] != 'T' && s[10] != 't' && s[10] != ' ') || s[13] != ':' || s[16] != ':' {
		return 0, 0, tsInvalid
	}
	hour, ok4 := digitsAt(s, 11, 2)
	minute, ok5 := digitsAt(s, 14, 2)
	sec, ok6 := digitsAt(s, 17, 2)
	if !ok4 || !ok5 || !ok6 {
		return 0, 0, tsInvalid
	}
	i := 19
	nsec := 0
	if i < len(s) && (s[i] == '.' || s[i] == ',') {
		j := i + 1
		scale := 100_000_000
		for j < len(s) && isDigit(s[j]) {
			nsec += int(s[j]-'0') * scale
			scale /= 10
			j++
		}
		if j == i+1 {
			return 0, 0, tsInvalid
		}
		i = j
	}
	loc := time.UTC
	if i < len(s) {
		switch c := s[i]; {
		case c == 'Z' || c == 'z':
			i++
		case c == '+' || c == '-':
			oh, okh := digitsAt(s, i+1, 2)
			if !okh || oh > 14 {
				return 0, 0, tsInvalid
			}
			j := i + 3
			om := 0
			if j < len(s) && s[j] == ':' {
				m, okm := digitsAt(s, j+1, 2)
				if !okm {
					return 0, 0, tsInvalid
				}
				om, j = m, j+3
			} else if m, okm := digitsAt(s, j, 2); okm {
				om, j = m, j+2
			}
			if om > 59 {
				return 0, 0, tsInvalid
			}
			off := oh*3600 + om*60
			if c == '-' {
				off = -off
			}
			loc = time.FixedZone("", off)
			i = j
		}
	}
	if i < len(s) && s[i] != ' ' && s[i] != '\t' {
		return 0, 0, tsInvalid
	}
	t, ok := validDate(year, month, day, hour, minute, sec, nsec, loc)
	if !ok {
		return 0, 0, tsInvalid
	}
	return uint64(t.Unix()), i, tsValid
}

var bsdMonths = [...]string{"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}

// parseBSDTimestamp lit « Mmm jj HH:MM:SS » (jour éventuellement précédé d'une espace).
func parseBSDTimestamp(s string) (uint64, int, tsStatus) {
	if len(s) < 6 || s[3] != ' ' {
		return 0, 0, tsAbsent
	}
	month := 0
	for i, m := range bsdMonths {
		if s[:3] == m {
			month = i + 1
			break
		}
	}
	if month == 0 {
		return 0, 0, tsAbsent
	}
	var day int
	switch {
	case s[4] == ' ' && isDigit(s[5]):
		day = int(s[5] - '0')
	case isDigit(s[4]) && isDigit(s[5]):
		day = int(s[4]-'0')*10 + int(s[5]-'0')
	default:
		return 0, 0, tsAbsent
	}
	if len(s) < 15 || s[6] != ' ' || s[9] != ':' || s[12] != ':' {
		return 0, 0, tsInvalid
	}
	hour, ok1 := digitsAt(s, 7, 2)
	minute, ok2 := digitsAt(s, 10, 2)
	sec, ok3 := digitsAt(s, 13, 2)
	if !ok1 || !ok2 || !ok3 || (len(s) > 15 && s[15] != ' ' && s[15] != '\t') {
		return 0, 0, tsInvalid
	}
	now := nowFunc().UTC()
	t, ok := validDate(now.Year(), month, day, hour, minute, sec, 0, time.UTC)
	if !ok || t.After(now.Add(48*time.Hour)) {
		t, ok = validDate(now.Year()-1, month, day, hour, minute, sec, 0, time.UTC)
	}
	if !ok {
		return 0, 0, tsInvalid
	}
	return uint64(t.Unix()), 15, tsValid
}

// LogActor rend l'acteur qui a émis la ligne rem (ligne privée de son
// horodatage) : l'étiquette syslog « nom[pid]: » en premier mot, ou « nom: »
// / « nom[pid]: » en second mot après le nom d'hôte, ou « kernel: » ; un chemin
// absolu d'étiquette (« /usr/sbin/cron[12]: ») est réduit à son dernier
// élément. Sans étiquette, l'acteur est le nom de la source normalisé
// (NormalizeLogActor de son dernier élément), indépendant de la rotation.
// Le résultat est en minuscules.
func LogActor(rem, logSource string) string {
	t1, rest := nextField(rem)
	t2, _ := nextField(rest)
	if name, pid, ok := syslogTag(t1); ok && (pid || name == "kernel") {
		return strings.ToLower(name)
	}
	if !strings.ContainsAny(t1, ":[") {
		if name, _, ok := syslogTag(t2); ok {
			return strings.ToLower(name)
		}
	}
	return NormalizeLogActor(filepath.Base(logSource))
}

// nextField rend le premier mot de s et la suite.
func nextField(s string) (string, string) {
	s = strings.TrimLeft(s, " \t")
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i:]
}

// syslogTag reconnaît « nom: » ou « nom[pid]: » ; pid dit si un PID numérique
// était présent. Le nom ne contient que lettres, chiffres et « ._-@/ », au
// plus 64 caractères.
func syslogTag(tok string) (name string, pid bool, ok bool) {
	body, found := strings.CutSuffix(tok, ":")
	if !found || body == "" {
		return "", false, false
	}
	if strings.HasSuffix(body, "]") {
		open := strings.LastIndexByte(body, '[')
		if open <= 0 {
			return "", false, false
		}
		digits := body[open+1 : len(body)-1]
		if digits == "" {
			return "", false, false
		}
		for i := 0; i < len(digits); i++ {
			if !isDigit(digits[i]) {
				return "", false, false
			}
		}
		body, pid = body[:open], true
	}
	if len(body) > 64 {
		return "", false, false
	}
	for i := 0; i < len(body); i++ {
		c := body[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || isDigit(c) || c == '.' || c == '_' || c == '-' || c == '@' || c == '/') {
			return "", false, false
		}
	}
	if strings.HasPrefix(body, "/") {
		body = body[strings.LastIndexByte(body, '/')+1:]
	}
	if body == "" {
		return "", false, false
	}
	return body, pid, true
}

// NormalizeLogActor ramène un nom d'acteur ou de fichier journal à sa forme
// stable : minuscules, puis retrait répété des suffixes de compression (.gz,
// .xz, .bz2, .zst, .lz4), de rotation (.1, -20260901) et de « .log ».
// Ainsi auth.log, auth.log.1 et auth.log.2.gz donnent « auth ».
func NormalizeLogActor(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	for {
		prev := name
		for _, ext := range []string{".gz", ".xz", ".bz2", ".zst", ".lz4", ".log"} {
			name = strings.TrimSuffix(name, ext)
		}
		if i := strings.LastIndexAny(name, ".-"); i > 0 && allDigits(name[i+1:]) &&
			(name[i] == '.' || len(name)-i-1 >= 8) {
			name = name[:i]
		}
		if name == prev {
			return name
		}
	}
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

// LogActorID rend l'identité d'entité d'un acteur : FNV-1a de sa forme
// normalisée par NormalizeLogActor.
func LogActorID(actor string) uint64 {
	return FNV1a64String(NormalizeLogActor(actor))
}

// templateWriter remplit la charge d'un instantané sans allouer ; toute
// écriture au-delà de la capacité est abandonnée.
type templateWriter struct {
	dst *[engine.FeaturePayloadBytes]byte
	n   int
}

func (w *templateWriter) byte1(c byte) {
	if w.n < len(w.dst) {
		w.dst[w.n] = c
		w.n++
	}
}

func (w *templateWriter) str(s string) {
	for i := 0; i < len(s); i++ {
		w.byte1(s[i])
	}
}

// volatileRoots sont les répertoires dont le contenu est éphémère : leur
// sous-chemin est masqué, la racine est gardée (exécuter depuis /tmp reste un signal).
var volatileRoots = []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"}

// LogTemplate écrit dans dst le gabarit normalisé de msg, tronqué à la
// capacité de dst et complété d'octets nuls, et rend sa longueur. Chaque mot
// (séparé par des blancs, ponctuation de bord conservée) est masqué ainsi :
// adresse IPv4 (port éventuel) ou IPv6 → « <ip> », UUID → « <uuid> »,
// chemin sous /tmp, /var/tmp, /dev/shm ou /run/user → racine suivie de « * »,
// suite hexadécimale d'au moins 8 caractères mêlant chiffres et lettres →
// « <hex> », toute suite de chiffres → « # ». Les blancs consécutifs sont
// réduits à une espace. Aucune allocation.
func LogTemplate(dst *[engine.FeaturePayloadBytes]byte, msg string) int {
	w := templateWriter{dst: dst}
	space := false
	for i := 0; i < len(msg) && w.n < len(dst); {
		if msg[i] == ' ' || msg[i] == '\t' {
			space = true
			i++
			continue
		}
		if space && w.n > 0 {
			w.byte1(' ')
		}
		space = false
		j := i
		for j < len(msg) && msg[j] != ' ' && msg[j] != '\t' {
			j++
		}
		templateWord(&w, msg[i:j])
		i = j
	}
	for k := w.n; k < len(dst); k++ {
		dst[k] = 0
	}
	return w.n
}

// templateWord masque un mot.
func templateWord(w *templateWriter, tok string) {
	lead := 0
	for lead < len(tok) && strings.IndexByte("([<\"'=", tok[lead]) >= 0 {
		lead++
	}
	trail := len(tok)
	for trail > lead && strings.IndexByte(",;)]>\"'.:", tok[trail-1]) >= 0 {
		trail--
	}
	w.str(tok[:lead])
	core := tok[lead:trail]
	// Une affectation « clé=valeur » masque la valeur seule.
	if eq := strings.IndexByte(core, '='); eq > 0 && eq < len(core)-1 {
		templateMask(w, core[:eq+1])
		templateWord(w, core[eq+1:])
		w.str(tok[trail:])
		return
	}
	// Adresse IPv6 entre crochets suivie d'un port : « [2001:db8::1]:443 ».
	if k := strings.IndexByte(core, ']'); k > 0 && isIPv6(core[:k]) {
		w.str("<ip>")
		templateMask(w, core[k:])
		w.str(tok[trail:])
		return
	}
	switch {
	case isIPv4(core) || isIPv6(core):
		w.str("<ip>")
	case isUUID(core):
		w.str("<uuid>")
	default:
		masked := false
		for _, root := range volatileRoots {
			if len(core) > len(root) && strings.HasPrefix(core, root) {
				w.str(root)
				w.byte1('*')
				masked = true
				break
			}
		}
		if !masked {
			templateMask(w, core)
		}
	}
	w.str(tok[trail:])
}

// templateMask remplace les suites de chiffres par « # » et les suites
// hexadécimales mixtes d'au moins 8 caractères par « <hex> ».
func templateMask(w *templateWriter, s string) {
	for i := 0; i < len(s); {
		c := s[i]
		if !isAlnum(c) {
			w.byte1(c)
			i++
			continue
		}
		j := i
		hex, digit, letter := true, false, false
		for j < len(s) && isAlnum(s[j]) {
			d := s[j]
			switch {
			case isDigit(d):
				digit = true
			case d >= 'a' && d <= 'f' || d >= 'A' && d <= 'F':
				letter = true
			default:
				hex = false
			}
			j++
		}
		if hex && digit && letter && j-i >= 8 {
			w.str("<hex>")
			i = j
			continue
		}
		for k := i; k < j; {
			if isDigit(s[k]) {
				for k < j && isDigit(s[k]) {
					k++
				}
				w.byte1('#')
				continue
			}
			w.byte1(s[k])
			k++
		}
		i = j
	}
}

func isAlnum(c byte) bool {
	return isDigit(c) || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// isIPv4 reconnaît a.b.c.d (octets ≤ 255), suivi éventuellement de « :port » ou « /masque ».
func isIPv4(s string) bool {
	if i := strings.IndexAny(s, ":/"); i > 0 {
		if !allDigits(s[i+1:]) {
			return false
		}
		s = s[:i]
	}
	parts := 0
	for len(s) > 0 {
		i := strings.IndexByte(s, '.')
		part := s
		if i >= 0 {
			part, s = s[:i], s[i+1:]
			if s == "" {
				return false
			}
		} else {
			s = ""
		}
		if len(part) == 0 || len(part) > 3 || !allDigits(part) {
			return false
		}
		if v, _ := digitsAt(part, 0, len(part)); v > 255 {
			return false
		}
		parts++
	}
	return parts == 4
}

// isIPv6 reconnaît un mot hexadécimal à deux « : » au moins, qui contient « :: »
// ou une lettre a-f (une heure « 12:34:56 » n'en est pas une).
func isIPv6(s string) bool {
	colons, letter := 0, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == ':':
			colons++
		case c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F':
			letter = true
		case isDigit(c):
		case c == '.' || c == '%': // IPv4 imbriquée, zone
		default:
			return false
		}
	}
	return colons >= 2 && (letter || strings.Contains(s, "::"))
}

// isUUID reconnaît la forme 8-4-4-4-12 hexadécimale.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !(isDigit(c) || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}
