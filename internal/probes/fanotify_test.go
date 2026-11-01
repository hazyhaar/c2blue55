//go:build linux

package probes

import (
	"encoding/binary"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestEventLayout128 vérifie que l'enregistrement canonique fait exactement
// 128 octets.
func TestEventLayout128(t *testing.T) {
	if got := int(unsafe.Sizeof(Event{})); got != EventSize {
		t.Fatalf("taille Event = %d octets, attendu %d", got, EventSize)
	}
}

// TestDecideVeto couvre l'arbitrage du couple (PID, chemin) : un redis-server
// ouvrant cron est refusé, un cron légitime est autorisé, un chemin non protégé
// est toujours autorisé, et un événement de notification n'appelle aucune
// réponse.
func TestDecideVeto(t *testing.T) {
	cases := []struct {
		name     string
		mask     uint64
		path     string
		comm     string
		respond  bool
		response uint32
	}{
		{
			name:     "redis-server hostile sur cron",
			mask:     unix.FAN_OPEN_PERM,
			path:     "/var/spool/cron/crontabs/root",
			comm:     "redis-server",
			respond:  true,
			response: fanDeny,
		},
		{
			name:     "cron legitime sur cron",
			mask:     unix.FAN_OPEN_PERM,
			path:     "/var/spool/cron/crontabs/root",
			comm:     "cron",
			respond:  true,
			response: fanAllow,
		},
		{
			name:     "processus hostile sur ld.so.preload",
			mask:     unix.FAN_OPEN_PERM,
			path:     "/etc/ld.so.preload",
			comm:     "redis-server",
			respond:  true,
			response: fanDeny,
		},
		{
			name:     "ldconfig legitime sur ld.so.conf.d",
			mask:     unix.FAN_OPEN_PERM,
			path:     "/etc/ld.so.conf.d/zz.conf",
			comm:     "ldconfig",
			respond:  true,
			response: fanAllow,
		},
		{
			name:     "chemin non protege",
			mask:     unix.FAN_OPEN_PERM,
			path:     "/tmp/neutre",
			comm:     "redis-server",
			respond:  true,
			response: fanAllow,
		},
		{
			name:     "notification sans reponse",
			mask:     unix.FAN_CLOSE_WRITE,
			path:     "/var/spool/cron/crontabs/root",
			comm:     "redis-server",
			respond:  false,
			response: fanDeny,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			respond, response := DecideVeto(tc.mask, tc.path, tc.comm)
			if respond != tc.respond {
				t.Fatalf("respond = %v, attendu %v", respond, tc.respond)
			}
			if response != tc.response {
				t.Fatalf("response = %#x, attendu %#x", response, tc.response)
			}
		})
	}
}

// TestFanotifyResponseProtocol valide le protocole de réponse fanotify : la
// structure fanotify_response écrite sur le descripteur contient bien le
// descripteur d'objet et la décision FAN_DENY ou FAN_ALLOW, dans l'ordre natif
// de 8 octets attendu par le noyau. Un tube tient lieu de descripteur fanotify,
// ce qui rend le test exécutable sans privilège.
func TestFanotifyResponseProtocol(t *testing.T) {
	cases := []struct {
		name     string
		comm     string
		path     string
		response uint32
		denied   int
	}{
		{
			name:     "veto physique sur redis-server et cron",
			comm:     "redis-server",
			path:     "/var/spool/cron/crontabs/root",
			response: fanDeny,
			denied:   1,
		},
		{
			name:     "autorisation d'un cron legitime",
			comm:     "cron",
			path:     "/var/spool/cron/crontabs/root",
			response: fanAllow,
			denied:   0,
		},
	}

	oldResolve, oldComm := resolveEventPath, readEventComm
	defer func() {
		resolveEventPath = oldResolve
		readEventComm = oldComm
	}()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var fds [2]int
			if err := unix.Pipe2(fds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
				t.Fatalf("Pipe2: %v", err)
			}
			defer unix.Close(fds[0])
			defer unix.Close(fds[1])

			objectFD, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatalf("Open /dev/null: %v", err)
			}

			resolveEventPath = func(fd int32, out []byte) int {
				return copy(out, tc.path)
			}
			readEventComm = func(pid int32, out []byte) int {
				return copy(out, tc.comm)
			}

			var buf [readBlockSize]byte
			binary.NativeEndian.PutUint32(buf[0:], metadataLen)
			buf[4] = 3
			binary.NativeEndian.PutUint16(buf[6:], metadataLen)
			binary.NativeEndian.PutUint64(buf[8:], unix.FAN_OPEN_PERM)
			binary.NativeEndian.PutUint32(buf[16:], uint32(objectFD))
			binary.NativeEndian.PutUint32(buf[20:], 4242)

			p := &FileProbe{fd: fds[1]}
			eventCount, denied := p.HandleBlock(buf[:metadataLen], nil)
			if eventCount != 1 {
				t.Fatalf("evenements traites = %d, attendu 1", eventCount)
			}
			if denied != tc.denied {
				t.Fatalf("vetos = %d, attendu %d", denied, tc.denied)
			}

			var resp [8]byte
			n, err := unix.Read(fds[0], resp[:])
			if err != nil {
				t.Fatalf("lecture de la reponse: %v", err)
			}
			if n != 8 {
				t.Fatalf("taille de fanotify_response = %d octets, attendu 8", n)
			}
			gotFD := int32(binary.NativeEndian.Uint32(resp[0:4]))
			gotResponse := binary.NativeEndian.Uint32(resp[4:8])
			if gotFD != int32(objectFD) {
				t.Fatalf("fd de la reponse = %d, attendu %d", gotFD, objectFD)
			}
			if gotResponse != tc.response {
				t.Fatalf("reponse fanotify = %#x, attendu %#x", gotResponse, tc.response)
			}
		})
	}
}

// TestFanotifyNotificationWithoutResponse vérifie qu'un événement de
// notification (sans bit de permission) ne produit aucune écriture de réponse.
func TestFanotifyNotificationWithoutResponse(t *testing.T) {
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatalf("Pipe2: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	objectFD, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("Open /dev/null: %v", err)
	}

	oldResolve, oldComm := resolveEventPath, readEventComm
	resolveEventPath = func(fd int32, out []byte) int {
		return copy(out, "/var/spool/cron/crontabs/root")
	}
	readEventComm = func(pid int32, out []byte) int {
		return copy(out, "redis-server")
	}
	defer func() {
		resolveEventPath = oldResolve
		readEventComm = oldComm
	}()

	var buf [readBlockSize]byte
	binary.NativeEndian.PutUint32(buf[0:], metadataLen)
	binary.NativeEndian.PutUint16(buf[6:], metadataLen)
	binary.NativeEndian.PutUint64(buf[8:], unix.FAN_CLOSE_WRITE)
	binary.NativeEndian.PutUint32(buf[16:], uint32(objectFD))
	binary.NativeEndian.PutUint32(buf[20:], 4242)

	p := &FileProbe{fd: fds[1]}
	eventCount, denied := p.HandleBlock(buf[:metadataLen], nil)
	if eventCount != 1 || denied != 0 {
		t.Fatalf("count=%d denied=%d, attendu count=1 denied=0", eventCount, denied)
	}
	var resp [8]byte
	if _, err := unix.Read(fds[0], resp[:]); err != unix.EAGAIN {
		t.Fatalf("reponse inattendue pour une notification: err=%v", err)
	}
}

// TestRingFileTranscription valide la transcription aller-retour d'un
// enregistrement de 128 octets dans le fichier anneau.
func TestRingFileTranscription(t *testing.T) {
	ring, err := RingFileOpen(filepath.Join(t.TempDir(), "ring.bin"), 4)
	if err != nil {
		t.Fatalf("RingFileOpen: %v", err)
	}
	defer ring.Close()

	var want Event
	want.Ts_ns = 123456789
	want.Pid = 4242
	want.Tid = 4242
	want.Subsystem = subFile
	want.Action = actWrite
	want.Flags = flagBlocked
	want.Src = fnv1a64("/var/spool/cron/crontabs/root")
	copy(want.Payload[:], "/var/spool/cron/crontabs/root")

	if err := ring.Write(&want); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if ring.Head() != 1 {
		t.Fatalf("Head = %d, attendu 1", ring.Head())
	}

	var got Event
	if err := ring.ReadAt(0, &got); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if got != want {
		t.Fatalf("enregistrement relu different:\n got=%+v\nwant=%+v", got, want)
	}
}

// TestBuildProcPaths vérifie la construction sans allocation des chemins
// procfs utilisés par la résolution d'objet et la lecture du nom de commande.
func TestBuildProcPaths(t *testing.T) {
	var fdPath [32]byte
	n := buildProcFdPath(fdPath[:], 17)
	if n == 0 || bytesToString(fdPath[:n-1]) != "/proc/self/fd/17" {
		t.Fatalf("buildProcFdPath = %q", bytesToString(fdPath[:n-1]))
	}
	var commPath [32]byte
	n = buildProcCommPath(commPath[:], 4242)
	if n == 0 || bytesToString(commPath[:n-1]) != "/proc/4242/comm" {
		t.Fatalf("buildProcCommPath = %q", bytesToString(commPath[:n-1]))
	}
}

// TestHotPathZeroAlloc vérifie que la chaîne chaude d'un événement (arbitrage,
// encodage de la réponse, transcription, écriture au fichier anneau) n'alloue
// aucun objet sur le tas.
func TestHotPathZeroAlloc(t *testing.T) {
	ring, err := RingFileOpen(filepath.Join(t.TempDir(), "ring.bin"), 8)
	if err != nil {
		t.Fatalf("RingFileOpen: %v", err)
	}
	defer ring.Close()

	const hostilePath = "/var/spool/cron/crontabs/root"
	var ev Event
	var resp [8]byte

	allocs := testing.AllocsPerRun(500, func() {
		_, response := DecideVeto(unix.FAN_OPEN_PERM, hostilePath, "redis-server")
		encodeResponse(&resp, 3, response)
		transcribe(&ev, 4242, unix.FAN_OPEN_PERM, response, hostilePath)
		if err := ring.Write(&ev); err != nil {
			t.Fatalf("Write: %v", err)
		}
	})
	if allocs != 0 {
		t.Fatalf("allocs/op = %v, attendu 0", allocs)
	}
}
