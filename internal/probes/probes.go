//go:build linux

// Sonde réseau hôte de WP04 : détection déterministe de reverse shell
// interactif par inspection des descripteurs de processus, corrélation
// inode/PID, et détection d'egress de démons passifs. Le chemin chaud
// n'alloue rien sur le tas et ne parse jamais textuellement /proc/net/tcp.
package probes

import (
	"bytes"
	"encoding/binary"
	"slices"
	"unsafe"

	"golang.org/x/sys/unix"

	blue "github.com/hazyhaar/c2blue55"
)

// DefaultProcRoot est le point de montage procfs standard.
const DefaultProcRoot = "/proc"

// atFDCWD reproduit AT_FDCWD sans dépendre d'un symbole convertible en uintptr.
const atFDCWD = ^uintptr(99)

// direntHdrLen est la taille d'un enregistrement linux_dirent64 sans nom.
const direntHdrLen = 19

// PushSink est le puits d'événements réseau. Tout anneau réseau exposant
// Push(*blue.Event) int (par exemple *RingNet) le satisfait.
type PushSink interface {
	Push(ev *blue.Event) int
}

// Interpreter classe les interpréteurs interactifs visés par la sonde.
type Interpreter uint8

const (
	InterpNone Interpreter = iota
	InterpSh
	InterpBash
	InterpPython
	InterpPerl
	InterpNetcat
)

// ReverseShellHit décrit une correspondance de reverse shell.
type ReverseShellHit struct {
	Interp    Interpreter
	Inode     uint64
	FDBitmask uint8
}

// Flags retourne le verdict critique associé.
func (h ReverseShellHit) Flags() uint32 {
	return blue.FlagBlocked | blue.FlagAnomaly
}

func asciiEq(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := range b {
		if b[i] != s[i] {
			return false
		}
	}
	return true
}

// pathBuilder assemble un chemin NUL-terminé dans un tampon d'appelant sans
// allocation. Tout dépassement invalide le chemin (done retourne nil).
type pathBuilder struct {
	buf []byte
	n   int
	ok  bool
}

func newPathBuilder(buf []byte) pathBuilder {
	return pathBuilder{buf: buf, ok: len(buf) > 1}
}

func (p *pathBuilder) putStr(s string) {
	if !p.ok || p.n+len(s) > len(p.buf)-1 {
		p.ok = false
		return
	}
	p.n += copy(p.buf[p.n:], s)
}

func (p *pathBuilder) putU32(v uint32) {
	if !p.ok {
		return
	}
	var tmp [10]byte
	i := len(tmp)
	if v == 0 {
		i--
		tmp[i] = '0'
	} else {
		for v > 0 {
			i--
			tmp[i] = byte('0' + v%10)
			v /= 10
		}
	}
	if p.n+(len(tmp)-i) > len(p.buf)-1 {
		p.ok = false
		return
	}
	p.n += copy(p.buf[p.n:], tmp[i:])
}

func (p *pathBuilder) done() []byte {
	if !p.ok {
		return nil
	}
	p.buf[p.n] = 0
	p.n++
	return p.buf[:p.n]
}

func rawReadlinkat(path, out []byte) (int, error) {
	if len(path) == 0 || len(out) == 0 {
		return 0, unix.EINVAL
	}
	r0, _, e1 := unix.Syscall6(unix.SYS_READLINKAT, atFDCWD,
		uintptr(unsafe.Pointer(&path[0])), uintptr(unsafe.Pointer(&out[0])),
		uintptr(len(out)), 0, 0)
	if e1 != 0 {
		return 0, e1
	}
	return int(r0), nil
}

func rawOpenDir(path []byte) (int, error) {
	if len(path) == 0 {
		return -1, unix.EINVAL
	}
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC
	r0, _, e1 := unix.Syscall6(unix.SYS_OPENAT, atFDCWD,
		uintptr(unsafe.Pointer(&path[0])), uintptr(flags), 0, 0, 0)
	if e1 != 0 {
		return -1, e1
	}
	return int(r0), nil
}

// visitDir énumère un répertoire via getdents64 sans allocation tas.
func visitDir(path, dbuf []byte, fn func(name []byte) bool) {
	fd, err := rawOpenDir(path)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	for {
		n, err := unix.Getdents(fd, dbuf)
		if err != nil || n <= 0 {
			return
		}
		off := 0
		for off+direntHdrLen <= n {
			reclen := int(binary.NativeEndian.Uint16(dbuf[off+16:]))
			if reclen < direntHdrLen || off+reclen > n {
				break
			}
			name := dbuf[off+19 : off+reclen]
			if i := bytes.IndexByte(name, 0); i >= 0 {
				name = name[:i]
			}
			if !fn(name) {
				return
			}
			off += reclen
		}
	}
}

func parseUint32(b []byte) (uint32, bool) {
	if len(b) == 0 || len(b) > 10 {
		return 0, false
	}
	var v uint32
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		d := uint32(c - '0')
		if v > (0xFFFFFFFF-d)/10 {
			return 0, false
		}
		v = v*10 + d
	}
	return v, true
}

// parseSocketInode reconnaît un lien "socket:[<inode>]".
func parseSocketInode(link []byte) (uint64, bool) {
	const prefix = "socket:["
	if len(link) < len(prefix)+2 || link[len(link)-1] != ']' {
		return 0, false
	}
	for i := range len(prefix) {
		if link[i] != prefix[i] {
			return 0, false
		}
	}
	digits := link[len(prefix) : len(link)-1]
	if len(digits) == 0 || len(digits) > 20 {
		return 0, false
	}
	var v uint64
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + uint64(c-'0')
	}
	return v, true
}

// baseName retire le préfixe de répertoire sans allocation.
func baseName(p []byte) []byte {
	for i, v := range slices.Backward(p) {
		if v == '/' {
			return p[i+1:]
		}
	}
	return p
}

func matchVersioned(b []byte, prefix string) bool {
	if len(b) <= len(prefix) || !hasPrefixStr(b, prefix) {
		return false
	}
	for _, c := range b[len(prefix):] {
		if (c < '0' || c > '9') && c != '.' {
			return false
		}
	}
	return true
}

// ClassifyInterpreter identifie sh, bash, python, perl et netcat, y compris
// les formes versionnées (python3.11, perl5.36). Zéro allocation.
func ClassifyInterpreter(comm []byte) Interpreter {
	base := baseName(comm)
	switch {
	case asciiEq(base, "sh"), asciiEq(base, "dash"), asciiEq(base, "ash"),
		asciiEq(base, "zsh"), asciiEq(base, "ksh"):
		return InterpSh
	case asciiEq(base, "bash"):
		return InterpBash
	case asciiEq(base, "nc"), asciiEq(base, "ncat"),
		asciiEq(base, "netcat"), asciiEq(base, "socat"):
		return InterpNetcat
	case asciiEq(base, "perl"), asciiEq(base, "perl5"):
		return InterpPerl
	case asciiEq(base, "python"), asciiEq(base, "python3"), asciiEq(base, "python2"):
		return InterpPython
	}
	switch {
	case matchVersioned(base, "python"):
		return InterpPython
	case matchVersioned(base, "perl"):
		return InterpPerl
	}
	return InterpNone
}

// readFDSocket lit le lien d'un descripteur et retourne son inode de socket.
func readFDSocket(procRoot string, pid, fd uint32, pathBuf, link []byte) (uint64, bool) {
	pb := newPathBuilder(pathBuf)
	pb.putStr(procRoot)
	if procRoot != "" && procRoot[len(procRoot)-1] != '/' {
		pb.putStr("/")
	}
	pb.putU32(pid)
	pb.putStr("/fd/")
	pb.putU32(fd)
	path := pb.done()
	if path == nil {
		return 0, false
	}
	n, err := rawReadlinkat(path, link)
	if err != nil || n <= 0 {
		return 0, false
	}
	return parseSocketInode(link[:n])
}

// DetectReverseShell inspecte /proc/<pid>/fd/0,1,2 dès qu'un PROC_EVENT_EXEC
// porte un interpréteur connu. Si l'un des trois flux standard est adossé à
// un socket, la détection retourne vrai sans allocation tas.
func DetectReverseShell(procRoot string, pid uint32, comm []byte) (ReverseShellHit, bool) {
	hit := ReverseShellHit{Interp: ClassifyInterpreter(comm)}
	if hit.Interp == InterpNone || pid == 0 {
		return ReverseShellHit{}, false
	}
	if procRoot == "" {
		procRoot = DefaultProcRoot
	}
	var pathBuf [256]byte
	var link [64]byte
	found := false
	for fd := range uint32(3) {
		ino, ok := readFDSocket(procRoot, pid, fd, pathBuf[:], link[:])
		if !ok {
			continue
		}
		hit.Inode = ino
		hit.FDBitmask |= 1 << uint8(fd)
		found = true
	}
	if !found {
		return ReverseShellHit{}, false
	}
	return hit, true
}

// SocketOwnerInPID vérifie qu'un pid détient l'inode de socket donné en
// parcourant ses descripteurs via getdents64, sans allocation tas.
func SocketOwnerInPID(procRoot string, pid uint32, inode uint64) bool {
	if pid == 0 {
		return false
	}
	if procRoot == "" {
		procRoot = DefaultProcRoot
	}
	var dirBuf [256]byte
	pb := newPathBuilder(dirBuf[:])
	pb.putStr(procRoot)
	if procRoot != "" && procRoot[len(procRoot)-1] != '/' {
		pb.putStr("/")
	}
	pb.putU32(pid)
	pb.putStr("/fd")
	dirPath := pb.done()
	if dirPath == nil {
		return false
	}
	var dbuf [4096]byte
	var lpath [256]byte
	var link [64]byte
	found := false
	visitDir(dirPath, dbuf[:], func(name []byte) bool {
		fd, ok := parseUint32(name)
		if !ok {
			return true
		}
		ino, ok := readFDSocket(procRoot, pid, fd, lpath[:], link[:])
		if !ok || ino != inode {
			return true
		}
		found = true
		return false
	})
	return found
}

// MapInodeToPID associe un inode de socket à son PID propriétaire en
// parcourant les pid de procfs. Zéro allocation tas.
func MapInodeToPID(procRoot string, inode uint64) (uint32, bool) {
	if procRoot == "" {
		procRoot = DefaultProcRoot
	}
	var rootBuf [256]byte
	pb := newPathBuilder(rootBuf[:])
	pb.putStr(procRoot)
	rootPath := pb.done()
	if rootPath == nil {
		return 0, false
	}
	var dbuf [4096]byte
	var owner uint32
	found := false
	visitDir(rootPath, dbuf[:], func(name []byte) bool {
		pid, ok := parseUint32(name)
		if !ok || pid == 0 {
			return true
		}
		if SocketOwnerInPID(procRoot, pid, inode) {
			owner = pid
			found = true
			return false
		}
		return true
	})
	return owner, found
}

func putAt(dst []byte, off int, s string) int {
	if off >= len(dst) {
		return len(dst)
	}
	if off+len(s) > len(dst) {
		s = s[:len(dst)-off]
	}
	return off + copy(dst[off:], s)
}

func putBytes(dst []byte, off int, src []byte) int {
	if off >= len(dst) {
		return len(dst)
	}
	if off+len(src) > len(dst) {
		src = src[:len(dst)-off]
	}
	return off + copy(dst[off:], src)
}

func fdMaskString(mask uint8) string {
	switch mask {
	case 0:
		return "none"
	case 1:
		return "stdin"
	case 2:
		return "stdout"
	case 4:
		return "stderr"
	case 7:
		return "0,1,2"
	default:
		return "mixed"
	}
}

// TranscribeReverseShell remplit un Event de 128 octets déjà alloué par
// l'appelant. C'est le cœur de transcription, garanti zéro allocation tas.
func TranscribeReverseShell(ev *blue.Event, tsNs uint64, pid uint32, comm []byte, hit ReverseShellHit) {
	if ev == nil {
		return
	}
	ev.Ts_ns = tsNs
	ev.Pid = pid
	ev.Tid = pid
	ev.Subsystem = blue.SubNet
	ev.Action = blue.ActConnect
	ev.Flags = hit.Flags()
	ev.Src = hit.Inode
	off := putAt(ev.Payload[:], 0, "revshell:")
	off = putBytes(ev.Payload[:], off, baseName(comm))
	off = putAt(ev.Payload[:], off, " fd=")
	off = putAt(ev.Payload[:], off, fdMaskString(hit.FDBitmask))
	_ = off
}

// emitReverseShell transcrit une alerte reverse shell en Event de 128 octets
// et l'écrit dans RingNet. La transcription est zéro allocation ; l'unique
// allocation possible est celle du report de l'Event vers un puits d'interface.
func emitReverseShell(sink PushSink, tsNs uint64, pid uint32, comm []byte, hit ReverseShellHit) int {
	if sink == nil {
		return -1
	}
	var ev blue.Event
	TranscribeReverseShell(&ev, tsNs, pid, comm, hit)
	return sink.Push(&ev)
}

// HandleExec évalue un PROC_EVENT_EXEC : si le processus est un interpréteur
// adossé à un socket, une alerte critique FlagBlocked|FlagAnomaly est émise
// vers RingNet. Retourne 0 si une alerte a été émise, -1 sinon.
func HandleExec(sink PushSink, procRoot string, tsNs uint64, pid uint32, comm []byte) int {
	hit, ok := DetectReverseShell(procRoot, pid, comm)
	if !ok {
		return -1
	}
	return emitReverseShell(sink, tsNs, pid, comm, hit)
}

// EmitReverseShell expose la transcription à un puits quelconque (RingNet).
func EmitReverseShell(sink PushSink, tsNs uint64, pid uint32, comm []byte, hit ReverseShellHit) int {
	return emitReverseShell(sink, tsNs, pid, comm, hit)
}
