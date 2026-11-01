// Package probes inspecte la mémoire d'un processus Linux à partir des
// interfaces textuelles de /proc, sans conversion de chaînes et sans
// allocation sur le chemin chaud.
//
// La sonde couvre trois familles d'anomalies :
//   - l'exécution sans fichier (memfd_create suivi de fexecve, ou binaire
//     supprimé du disque après exécution) ;
//   - les violations W^X (segment simultanément accessible en écriture et en
//     exécution) hors des processus à compilation juste-à-temps ;
//   - l'injection dynamique de bibliothèques, repérée par une cartographie
//     originaire de /tmp, /dev/shm ou /var/tmp.
//
// Le paquet ne lit pas lui-même /proc : l'appelant fournit le contenu des
// pseudo-fichiers, ce qui rend l'analyse testable sur des captures réelles.
package probes

import "slices"

// Perm encode le champ de permission à quatre caractères d'une ligne de
// /proc/<pid>/maps (par exemple « rwxp »).
type Perm uint8

const (
	PermRead Perm = 1 << iota
	PermWrite
	PermExec
	PermShared
)

// CanRead indique la présence du droit de lecture.
func (p Perm) CanRead() bool { return p&PermRead != 0 }

// CanWrite indique la présence du droit d'écriture.
func (p Perm) CanWrite() bool { return p&PermWrite != 0 }

// CanExec indique la présence du droit d'exécution.
func (p Perm) CanExec() bool { return p&PermExec != 0 }

// IsShared indique une cartographie partagée plutôt que privée.
func (p Perm) IsShared() bool { return p&PermShared != 0 }

// String restitue les quatre caractères du champ de permission.
func (p Perm) String() string {
	var b [4]byte
	if p&PermRead != 0 {
		b[0] = 'r'
	} else {
		b[0] = '-'
	}
	if p&PermWrite != 0 {
		b[1] = 'w'
	} else {
		b[1] = '-'
	}
	if p&PermExec != 0 {
		b[2] = 'x'
	} else {
		b[2] = '-'
	}
	if p&PermShared != 0 {
		b[3] = 's'
	} else {
		b[3] = 'p'
	}
	return string(b[:])
}

// Segment décrit une ligne de /proc/<pid>/maps. Le champ Path est une
// sous-tranche du tampon fourni à ParseMaps : il n'est valide que tant que
// ce tampon reste vivant et inchangé.
type Segment struct {
	Start    uint64
	End      uint64
	Perms    Perm
	Offset   uint64
	DevMajor uint32
	DevMinor uint32
	Inode    uint64
	Path     []byte
	Deleted  bool
}

// ParseMaps décode le contenu textuel de /proc/<pid>/maps dans out et retourne
// le nombre de segments retenus, plafonné à limit. Aucune allocation n'est
// effectuée : les chemins aliassent mapsBytes.
func ParseMaps(mapsBytes []byte, out []Segment, limit int) int {
	if limit < 0 {
		limit = 0
	}
	if limit > len(out) {
		limit = len(out)
	}
	n := 0
	off := 0
	for off < len(mapsBytes) {
		var seg Segment
		next, ok := parseLine(mapsBytes, off, &seg)
		if next <= off {
			next = off + 1
		}
		off = next
		if !ok {
			continue
		}
		if n < limit {
			out[n] = seg
			n++
		}
	}
	return n
}

// parseLine décode une ligne démarrant à mapsBytes[off] et écrit le segment dans
// seg. Elle retourne l'offset de la ligne suivante et indique si la ligne
// était bien formée. Une ligne malformée est ignorée.
func parseLine(mapsBytes []byte, off int, seg *Segment) (int, bool) {
	if off >= len(mapsBytes) {
		return len(mapsBytes), false
	}
	end := off
	for end < len(mapsBytes) && mapsBytes[end] != '\n' {
		end++
	}
	line := mapsBytes[off:end]
	next := end
	if next < len(mapsBytes) {
		next++
	}
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	if len(line) == 0 {
		return next, false
	}

	p := 0
	start, k := parseHex64(line, p)
	if k == 0 {
		return next, false
	}
	p += k
	if p >= len(line) || line[p] != '-' {
		return next, false
	}
	p++
	segEnd, k := parseHex64(line, p)
	if k == 0 {
		return next, false
	}
	p += k

	p = skipSpaces(line, p)
	if p+4 > len(line) {
		return next, false
	}
	var perms Perm
	for i := range 4 {
		switch line[p+i] {
		case 'r':
			perms |= PermRead
		case 'w':
			perms |= PermWrite
		case 'x':
			perms |= PermExec
		case 's':
			perms |= PermShared
		}
	}
	p += 4

	p = skipSpaces(line, p)
	offset, k := parseHex64(line, p)
	if k == 0 {
		return next, false
	}
	p += k

	p = skipSpaces(line, p)
	devMajor, k := parseHex64(line, p)
	if k == 0 {
		return next, false
	}
	p += k
	if p >= len(line) || line[p] != ':' {
		return next, false
	}
	p++
	devMinor, k := parseHex64(line, p)
	if k == 0 {
		return next, false
	}
	p += k

	p = skipSpaces(line, p)
	inode, k := parseDec64(line, p)
	if k == 0 {
		return next, false
	}
	p += k

	p = skipSpaces(line, p)
	path := line[p:]

	seg.Start = start
	seg.End = segEnd
	seg.Perms = perms
	seg.Offset = offset
	seg.DevMajor = uint32(devMajor)
	seg.DevMinor = uint32(devMinor)
	seg.Inode = inode
	seg.Path = path
	seg.Deleted = indexOfStr(path, "(deleted)") >= 0
	return next, true
}

func skipSpaces(b []byte, p int) int {
	for p < len(b) && (b[p] == ' ' || b[p] == '\t') {
		p++
	}
	return p
}

func parseHex64(b []byte, p int) (uint64, int) {
	var v uint64
	i := 0
	for p+i < len(b) {
		c := b[p+i]
		var d uint64
		switch {
		case c >= '0' && c <= '9':
			d = uint64(c - '0')
		case c >= 'a' && c <= 'f':
			d = uint64(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = uint64(c-'A') + 10
		default:
			return v, i
		}
		v = v<<4 | d
		i++
	}
	return v, i
}

func parseDec64(b []byte, p int) (uint64, int) {
	var v uint64
	i := 0
	for p+i < len(b) {
		c := b[p+i]
		if c < '0' || c > '9' {
			return v, i
		}
		v = v*10 + uint64(c-'0')
		i++
	}
	return v, i
}

func indexOfStr(s []byte, sub string) int {
	if len(sub) == 0 {
		return 0
	}
	if len(sub) > len(s) {
		return -1
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		j := 0
		for j < len(sub) && s[i+j] == sub[j] {
			j++
		}
		if j == len(sub) {
			return i
		}
	}
	return -1
}

func hasPrefixStr(s []byte, prefix string) bool {
	if len(s) < len(prefix) {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		if s[i] != prefix[i] {
			return false
		}
	}
	return true
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func basename(target []byte) []byte {
	for i, t := range slices.Backward(target) {
		if t == '/' {
			return target[i+1:]
		}
	}
	return target
}

func tokenPresent(list string, tok []byte) bool {
	if len(tok) == 0 || len(tok)+1 >= len(list) {
		return false
	}
	for i := 0; i+len(tok)+1 < len(list); i++ {
		if list[i] != ' ' {
			continue
		}
		j := 0
		for j < len(tok) && list[i+1+j] == tok[j] {
			j++
		}
		if j == len(tok) && list[i+1+len(tok)] == ' ' {
			return true
		}
	}
	return false
}
