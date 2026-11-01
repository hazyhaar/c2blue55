//go:build linux

package probes

import (
	"errors"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"
)

// errInvalidRing signale un fichier anneau mal formé ou non initialisé.
var errInvalidRing = errors.New("probes: fichier anneau invalide")

// maxRingSlots borne la taille d'un anneau pour prévenir un dimensionnement
// déraisonnable.
const maxRingSlots = 1 << 24

// RingFile est un fichier anneau de capacité fixe, composé de slots de
// EventSize octets. L'index d'écriture est atomique ; les écritures se font par
// Pwrite positionné, sans allocation ni verrou.
type RingFile struct {
	fd    int
	slots uint64
	head  atomic.Uint64
}

// RingFileOpen ouvre ou crée un fichier anneau à slots entrées de 128 octets,
// puis fixe sa taille par Ftruncate.
func RingFileOpen(path string, slots int) (*RingFile, error) {
	if slots <= 0 || slots > maxRingSlots {
		return nil, errInvalidRing
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Ftruncate(fd, int64(slots)*EventSize); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &RingFile{fd: fd, slots: uint64(slots)}, nil
}

// Write inscrit un événement au slot courant et avance la tête d'écriture.
func (r *RingFile) Write(ev *Event) error {
	if r == nil || ev == nil || r.fd < 0 {
		return errInvalidRing
	}
	n := r.head.Add(1) - 1
	off := int64(n%r.slots) * EventSize
	buf := unsafe.Slice((*byte)(unsafe.Pointer(ev)), EventSize)
	_, err := unix.Pwrite(r.fd, buf, off)
	return err
}

// ReadAt relit l'événement du slot logique demandé.
func (r *RingFile) ReadAt(slot uint64, ev *Event) error {
	if r == nil || ev == nil || r.fd < 0 {
		return errInvalidRing
	}
	off := int64(slot%r.slots) * EventSize
	buf := unsafe.Slice((*byte)(unsafe.Pointer(ev)), EventSize)
	_, err := unix.Pread(r.fd, buf, off)
	return err
}

// Head retourne le nombre total d'écritures effectuées.
func (r *RingFile) Head() uint64 {
	if r == nil {
		return 0
	}
	return r.head.Load()
}

// Slots retourne la capacité de l'anneau.
func (r *RingFile) Slots() uint64 {
	if r == nil {
		return 0
	}
	return r.slots
}

// Close ferme le fichier anneau.
func (r *RingFile) Close() error {
	if r == nil || r.fd < 0 {
		return nil
	}
	err := unix.Close(r.fd)
	r.fd = -1
	return err
}
