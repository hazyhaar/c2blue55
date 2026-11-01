//go:build linux

package probes

import (
	"encoding/binary"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Constantes de dimensionnement de la sonde.
const (
	// readBlockSize est la taille du bloc de lecture imposée par WP03.
	readBlockSize = 4096
	// metadataLen est la taille de fanotify_event_metadata.
	metadataLen = unix.FAN_EVENT_METADATA_LEN
	// maxPathLen borne la résolution d'un chemin via /proc/self/fd.
	maxPathLen = 256
	// maxCommLen borne la lecture du nom de commande via /proc/<pid>/comm.
	maxCommLen = 64
)

// fdCWD est la valeur native AT_FDCWD exprimée sans constante négative, pour
// les appels système directs.
const fdCWD = ^uintptr(99)

// markMask est le masque de marquage exigé par WP03 : ouverture en permission
// (bloquante), fermeture après écriture, et exécution.
const markMask = unix.FAN_OPEN_PERM | unix.FAN_CLOSE_WRITE | unix.FAN_OPEN_EXEC

// protectedPaths est la liste des points critiques marqués au démarrage.
var protectedPaths = [...]string{
	"/var/spool/cron",
	"/etc/ld.so.preload",
	"/etc/ld.so.conf.d",
	"/etc/shadow",
	"/etc/sudoers",
}

// Seams de test : ces trois fonctions sont substituables dans le paquet pour
// injecter un chemin, un nom de commande ou un horodatage sans dépendre du
// noyau ni de privilèges.
var (
	resolveEventPath = resolvePathProc
	readEventComm    = readCommProc
	eventTimestamp   = nowNanos
)

// FileProbe porte le descripteur fanotify de la sonde fichier.
type FileProbe struct {
	fd int
}

// InitFanotify ouvre un descripteur fanotify en classe de contenu, ce qui
// autorise l'interception synchrone bloquante et l'émission d'un veto.
func InitFanotify() (int, error) {
	return unix.FanotifyInit(unix.FAN_CLOEXEC|unix.FAN_CLASS_CONTENT, unix.O_RDONLY)
}

// NewFileProbe ouvre le descripteur fanotify puis marque l'ensemble des points
// critiques. Un point absent du système (ENOENT) est toléré ; l'échec n'est
// remonté que si aucun point n'a pu être marqué.
func NewFileProbe() (*FileProbe, error) {
	fd, err := InitFanotify()
	if err != nil {
		return nil, err
	}
	p := &FileProbe{fd: fd}
	if err := p.MarkProtected(); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return p, nil
}

// MarkProtected inscrit les marques de contenu sur tous les points critiques.
func (p *FileProbe) MarkProtected() error {
	marked := 0
	var firstErr error
	for i := range protectedPaths {
		err := unix.FanotifyMark(p.fd, unix.FAN_MARK_ADD, markMask, unix.AT_FDCWD, protectedPaths[i])
		if err == nil {
			marked++
			continue
		}
		if err == unix.ENOENT {
			continue
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if marked == 0 && firstErr != nil {
		return firstErr
	}
	return nil
}

// FD retourne le descripteur fanotify sous-jacent.
func (p *FileProbe) FD() int {
	if p == nil {
		return -1
	}
	return p.fd
}

// Close ferme le descripteur fanotify.
func (p *FileProbe) Close() error {
	if p == nil || p.fd < 0 {
		return nil
	}
	err := unix.Close(p.fd)
	p.fd = -1
	return err
}

// Serve lit le flux fanotify par blocs de 4096 octets et traite chaque bloc.
// L'arrêt est coopératif : le drapeau stop, s'il est fourni, est consulté entre
// deux lectures.
func (p *FileProbe) Serve(ring *RingFile, stop *atomic.Bool) {
	var buf [readBlockSize]byte
	for stop == nil || !stop.Load() {
		n, err := unix.Read(p.fd, buf[:])
		if err != nil {
			if err == unix.EINTR || err == unix.EAGAIN {
				continue
			}
			return
		}
		if n <= 0 {
			continue
		}
		p.HandleBlock(buf[:n], ring)
	}
}

// HandleBlock dépile un bloc de fanotify_event_metadata. Pour chaque événement,
// il résout le chemin, lit le nom de commande de l'auteur, arbitre le veto,
// répond au noyau pour les événements de permission, transcrit l'événement vers
// le fichier anneau, puis referme le descripteur d'objet. Il retourne le nombre
// d'événements traités et le nombre de vetos opposés.
func (p *FileProbe) HandleBlock(buf []byte, ring *RingFile) (eventCount, denied int) {
	off := 0
	for off+metadataLen <= len(buf) {
		evLen := int(binary.NativeEndian.Uint32(buf[off:]))
		if evLen < metadataLen || off+evLen > len(buf) {
			break
		}
		mask := binary.NativeEndian.Uint64(buf[off+8:])
		fd := int32(binary.NativeEndian.Uint32(buf[off+16:]))
		pid := int32(binary.NativeEndian.Uint32(buf[off+20:]))

		var pathBuf [maxPathLen]byte
		pathLen := 0
		if fd != unix.FAN_NOFD {
			pathLen = resolveEventPath(fd, pathBuf[:])
		}
		path := bytesToString(pathBuf[:pathLen])

		var commBuf [maxCommLen]byte
		commLen := readEventComm(pid, commBuf[:])
		comm := bytesToString(commBuf[:commLen])

		respond, response := DecideVeto(mask, path, comm)

		if respond && fd != unix.FAN_NOFD {
			if response == fanDeny {
				denied++
			}
			var resp [8]byte
			encodeResponse(&resp, fd, response)
			_, _ = unix.Write(p.fd, resp[:])
		}

		if ring != nil {
			var ev Event
			transcribe(&ev, pid, mask, response, path)
			_ = ring.Write(&ev)
		}

		if fd != unix.FAN_NOFD {
			_ = unix.Close(int(fd))
		}

		eventCount++
		off += evLen
	}
	return eventCount, denied
}

// encodeResponse inscrit la structure fanotify_response (fd int32, response
// uint32) dans l'ordre natif de la machine, sans allocation.
func encodeResponse(dst *[8]byte, fd int32, response uint32) {
	binary.NativeEndian.PutUint32(dst[0:4], uint32(fd))
	binary.NativeEndian.PutUint32(dst[4:8], response)
}

// transcribe remplit l'enregistrement canonique de 128 octets à partir de
// l'événement noyau.
func transcribe(ev *Event, pid int32, mask uint64, response uint32, path string) {
	ev.Ts_ns = eventTimestamp()
	ev.Pid = uint32(pid)
	ev.Tid = uint32(pid)
	ev.Subsystem = subFile
	ev.Action = actionOf(mask)
	if response == fanDeny {
		ev.Flags = flagBlocked
	} else {
		ev.Flags = flagVerdictOK
	}
	ev.Src = fnv1a64(path)
	n := copy(ev.Payload[:], path)
	for i := n; i < len(ev.Payload); i++ {
		ev.Payload[i] = 0
	}
}

// actionOf projette le masque fanotify sur l'action canonique du moteur.
func actionOf(mask uint64) uint16 {
	switch {
	case mask&unix.FAN_OPEN_EXEC != 0:
		return actExec
	case mask&unix.FAN_CLOSE_WRITE != 0:
		return actWrite
	default:
		return actOpen
	}
}

// nowNanos retourne l'horloge monotone en nanosecondes, sans allocation.
func nowNanos() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Nano())
}

// fnv1a64 calcule l'empreinte FNV-1a du chemin, qui sert d'identité stable dans
// l'enregistrement sans conserver le chemin complet.
func fnv1a64(s string) uint64 {
	const (
		offset = uint64(14695981039346656037)
		prime  = uint64(1099511628211)
	)
	h := offset
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime
	}
	return h
}

// bytesToString convertit une tranche d'octets en chaîne sans allocation.
// L'appelant garantit que la chaîne ne survit pas au tampon source.
func bytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(&b[0], len(b))
}

// resolvePathProc résout le chemin d'un descripteur d'objet fanotify en lisant
// le lien /proc/self/fd/<fd> par appel système direct, sans allocation.
func resolvePathProc(fd int32, out []byte) int {
	if fd < 0 || len(out) == 0 {
		return 0
	}
	var path [32]byte
	n := buildProcFdPath(path[:], fd)
	if n <= 0 {
		return 0
	}
	r, _, errno := unix.Syscall6(
		unix.SYS_READLINKAT,
		fdCWD,
		uintptr(unsafe.Pointer(&path[0])),
		uintptr(unsafe.Pointer(&out[0])),
		uintptr(len(out)),
		0, 0,
	)
	if errno != 0 {
		return 0
	}
	nr := min(int(r), len(out))
	return nr
}

// readCommProc lit le nom de commande de l'auteur dans /proc/<pid>/comm par
// appels système directs, sans allocation, et retire le saut de ligne final.
func readCommProc(pid int32, out []byte) int {
	if pid <= 0 || len(out) == 0 {
		return 0
	}
	var path [32]byte
	n := buildProcCommPath(path[:], pid)
	if n <= 0 {
		return 0
	}
	fd, _, errno := unix.Syscall6(
		unix.SYS_OPENAT,
		fdCWD,
		uintptr(unsafe.Pointer(&path[0])),
		uintptr(unix.O_RDONLY|unix.O_CLOEXEC),
		0, 0, 0,
	)
	if errno != 0 {
		return 0
	}
	rfd := int(fd)
	r, _, errno := unix.Syscall(
		unix.SYS_READ,
		uintptr(rfd),
		uintptr(unsafe.Pointer(&out[0])),
		uintptr(len(out)),
	)
	_, _, _ = unix.Syscall(unix.SYS_CLOSE, uintptr(rfd), 0, 0)
	if errno != 0 || r == 0 {
		return 0
	}
	nr := int(r)
	for nr > 0 && (out[nr-1] == '\n' || out[nr-1] == '\r' || out[nr-1] == 0) {
		nr--
	}
	return nr
}

// buildProcFdPath écrit "/proc/self/fd/<fd>\x00" et retourne la longueur
// écrite, terminateur inclus, ou 0 si la capacité est insuffisante.
func buildProcFdPath(dst []byte, fd int32) int {
	const prefix = "/proc/self/fd/"
	if len(dst) < len(prefix)+11 {
		return 0
	}
	i := copy(dst, prefix)
	i += appendDecimal(dst[i:], uint32(fd))
	dst[i] = 0
	return i + 1
}

// buildProcCommPath écrit "/proc/<pid>/comm\x00" et retourne la longueur
// écrite, terminateur inclus, ou 0 si la capacité est insuffisante.
func buildProcCommPath(dst []byte, pid int32) int {
	const prefix = "/proc/"
	const suffix = "/comm"
	if len(dst) < len(prefix)+11+len(suffix)+1 {
		return 0
	}
	i := copy(dst, prefix)
	i += appendDecimal(dst[i:], uint32(pid))
	i += copy(dst[i:], suffix)
	dst[i] = 0
	return i + 1
}

// appendDecimal écrit la représentation décimale de v et retourne le nombre
// d'octets écrits.
func appendDecimal(dst []byte, v uint32) int {
	if len(dst) == 0 {
		return 0
	}
	if v == 0 {
		dst[0] = '0'
		return 1
	}
	var tmp [10]byte
	i := len(tmp)
	for v > 0 {
		i--
		tmp[i] = byte('0' + v%10)
		v /= 10
	}
	return copy(dst, tmp[i:])
}
