//go:build linux

package probes

import (
	"context"
	"encoding/binary"
	"os"
	"testing"
	"time"

	blue "github.com/hazyhaar/c2blue55"
	"golang.org/x/sys/unix"
)

// procTestFrame assemble une trame Netlink connecteur complete a partir de
// l'enum what, de l'horodatage et de l'union binaire du struct proc_event.
// Utilisee uniquement par les tests pour simuler une capture controlee.
func procTestFrame(what uint32, ts uint64, union []byte) []byte {
	procPayload := make([]byte, procEventHeader+len(union))
	binary.LittleEndian.PutUint32(procPayload[0:], what)
	binary.LittleEndian.PutUint64(procPayload[8:], ts)
	copy(procPayload[procEventHeader:], union)

	cn := make([]byte, cnMessageLen+len(procPayload))
	binary.LittleEndian.PutUint32(cn[0:], cnIdxProc)
	binary.LittleEndian.PutUint32(cn[4:], cnValProc)
	binary.LittleEndian.PutUint16(cn[16:], uint16(len(procPayload)))
	copy(cn[cnMessageLen:], procPayload)

	frame := make([]byte, netlinkHeaderLen+len(cn))
	binary.LittleEndian.PutUint32(frame[0:], uint32(len(frame)))
	binary.LittleEndian.PutUint16(frame[4:], unix.NLMSG_DONE)
	copy(frame[netlinkHeaderLen:], cn)
	return frame
}

func procTestUIDUnion(pid, tgid, uid, euid uint32) []byte {
	u := make([]byte, 16)
	binary.LittleEndian.PutUint32(u[0:], pid)
	binary.LittleEndian.PutUint32(u[4:], tgid)
	binary.LittleEndian.PutUint32(u[8:], uid)
	binary.LittleEndian.PutUint32(u[12:], euid)
	return u
}

func TestBuildProcListenRequestLayout(t *testing.T) {
	req := buildProcListenRequest()
	if len(req) != 40 {
		t.Fatalf("longueur requete = %d, attendu 40", len(req))
	}
	if got := binary.LittleEndian.Uint32(req[0:]); got != 40 {
		t.Fatalf("nlmsg_len = %d, attendu 40", got)
	}
	if got := binary.LittleEndian.Uint16(req[4:]); got != unix.NLMSG_DONE {
		t.Fatalf("nlmsg_type = %#x, attendu %#x", got, unix.NLMSG_DONE)
	}
	if got := binary.LittleEndian.Uint32(req[16:]); got != cnIdxProc {
		t.Fatalf("cn.id.idx = %d, attendu %d", got, cnIdxProc)
	}
	if got := binary.LittleEndian.Uint32(req[20:]); got != cnValProc {
		t.Fatalf("cn.id.val = %d, attendu %d", got, cnValProc)
	}
	if got := binary.LittleEndian.Uint16(req[32:]); got != 4 {
		t.Fatalf("cn.len = %d, attendu 4", got)
	}
	if got := binary.LittleEndian.Uint32(req[36:]); got != procCnMcastListen {
		t.Fatalf("op = %d, attendu PROC_CN_MCAST_LISTEN", got)
	}
}

func TestProcDecodeFork(t *testing.T) {
	union := make([]byte, 16)
	binary.LittleEndian.PutUint32(union[0:], 1000)  // parent_pid
	binary.LittleEndian.PutUint32(union[4:], 1000)  // parent_tgid
	binary.LittleEndian.PutUint32(union[8:], 4242)  // child_pid
	binary.LittleEndian.PutUint32(union[12:], 4242) // child_tgid

	var ring RingProc
	var dec ProcDecoder
	if n := dec.Decode(procTestFrame(procEventFork, 123456789, union), &ring); n != 1 {
		t.Fatalf("evenements transcrits = %d, attendu 1", n)
	}
	var ev blue.Event
	if ring.Read(&ev) != 1 {
		t.Fatal("aucun evenement dans l'anneau")
	}
	if ev.Subsystem != blue.SubProc || ev.Action != blue.ActFork {
		t.Fatalf("couple (subsystem, action) = (%d, %d)", ev.Subsystem, ev.Action)
	}
	if ev.Ts_ns != 123456789 {
		t.Fatalf("horodatage = %d", ev.Ts_ns)
	}
	if ev.Pid != 4242 || ev.Tid != 4242 || ev.Src != 1000 {
		t.Fatalf("filiation = pid %d, tid %d, ppid %d", ev.Pid, ev.Tid, ev.Src)
	}
}

func TestProcDecodeExec(t *testing.T) {
	union := make([]byte, 8+taskCommLen)
	binary.LittleEndian.PutUint32(union[0:], 7)
	binary.LittleEndian.PutUint32(union[4:], 7)
	copy(union[8:], []byte("bash"))

	var ring RingProc
	var dec ProcDecoder
	if n := dec.Decode(procTestFrame(procEventExec, 55, union), &ring); n != 1 {
		t.Fatalf("evenements transcrits = %d, attendu 1", n)
	}
	var ev blue.Event
	ring.Read(&ev)
	if ev.Action != blue.ActExec || ev.Pid != 7 || ev.Tid != 7 {
		t.Fatalf("exec = action %d pid %d tid %d", ev.Action, ev.Pid, ev.Tid)
	}
	if got := string(ev.Payload[:4]); got != "bash" {
		t.Fatalf("comm = %q, attendu %q", got, "bash")
	}
}

func TestProcDecodeUIDPrivEsc(t *testing.T) {
	var ring RingProc
	var dec ProcDecoder

	prime := procTestUIDUnion(7, 7, 1000, 1000)
	if n := dec.Decode(procTestFrame(procEventUID, 1, prime), &ring); n != 1 {
		t.Fatal("amorce UID non transcrite")
	}
	ring.Reset()

	escape := procTestUIDUnion(7, 7, 0, 0)
	if n := dec.Decode(procTestFrame(procEventUID, 2, escape), &ring); n != 1 {
		t.Fatal("elevation UID non transcrite")
	}
	var ev blue.Event
	ring.Read(&ev)
	old := uint32(ev.Src >> 32)
	newEUID := uint32(ev.Src)
	if old != 1000 || newEUID != 0 {
		t.Fatalf("couple UID = (%d, %d), attendu (1000, 0)", old, newEUID)
	}
	if ev.Action != blue.ActPrivEsc {
		t.Fatalf("action = %d, attendu ActPrivEsc", ev.Action)
	}
	if ev.Flags&blue.FlagAnomaly == 0 {
		t.Fatal("elevation vers root non marquee FlagAnomaly")
	}
}

func TestProcDecodeUIDFirstRootNotFlagged(t *testing.T) {
	var ring RingProc
	var dec ProcDecoder
	escape := procTestUIDUnion(9, 9, 0, 0)
	dec.Decode(procTestFrame(procEventUID, 1, escape), &ring)
	var ev blue.Event
	ring.Read(&ev)
	if ev.Flags&blue.FlagAnomaly != 0 {
		t.Fatal("premier UID effectif inconnu: elevation presumee a tort")
	}
}

func TestProcDecodeExit(t *testing.T) {
	union := make([]byte, 16)
	binary.LittleEndian.PutUint32(union[0:], 31)
	binary.LittleEndian.PutUint32(union[4:], 31)
	binary.LittleEndian.PutUint32(union[8:], 139)
	binary.LittleEndian.PutUint32(union[12:], 11)

	var ring RingProc
	var dec ProcDecoder
	dec.Decode(procTestFrame(procEventExit, 77, union), &ring)
	var ev blue.Event
	ring.Read(&ev)
	if ev.Action != blue.ActExit || ev.Pid != 31 || ev.Tid != 31 {
		t.Fatalf("exit = action %d pid %d tid %d", ev.Action, ev.Pid, ev.Tid)
	}
	if got := binary.LittleEndian.Uint32(ev.Payload[0:]); got != 139 {
		t.Fatalf("code de sortie = %d, attendu 139", got)
	}
}

func TestProcDecodeConcatenatedMessages(t *testing.T) {
	fork := make([]byte, 16)
	binary.LittleEndian.PutUint32(fork[0:], 1)
	binary.LittleEndian.PutUint32(fork[4:], 1)
	binary.LittleEndian.PutUint32(fork[8:], 2)
	binary.LittleEndian.PutUint32(fork[12:], 2)
	exit := make([]byte, 16)
	binary.LittleEndian.PutUint32(exit[0:], 2)
	binary.LittleEndian.PutUint32(exit[4:], 2)

	buf := append(procTestFrame(procEventFork, 1, fork), procTestFrame(procEventExit, 2, exit)...)

	var ring RingProc
	var dec ProcDecoder
	if n := dec.Decode(buf, &ring); n != 2 {
		t.Fatalf("evenements transcrits = %d, attendu 2", n)
	}
}

func TestProcDecodeRejectsMalformed(t *testing.T) {
	var ring RingProc
	var dec ProcDecoder
	if n := dec.Decode(nil, &ring); n != 0 {
		t.Fatalf("tampon nul: %d evenements", n)
	}
	if n := dec.Decode(make([]byte, netlinkHeaderLen-1), &ring); n != 0 {
		t.Fatalf("en-tete tronque: %d evenements", n)
	}
	// Message connecteur etranger (identifiant different).
	foreign := procTestFrame(procEventExec, 1, make([]byte, 8))
	binary.LittleEndian.PutUint32(foreign[netlinkHeaderLen:], 99)
	if n := dec.Decode(foreign, &ring); n != 0 {
		t.Fatalf("connecteur etranger: %d evenements", n)
	}
	// Evenement tronque au milieu de l'union.
	truncatedEvent := make([]byte, procEventHeader+4)
	binary.LittleEndian.PutUint32(truncatedEvent[0:], procEventFork)
	if n := dec.decodeProcEvent(truncatedEvent, &ring); n {
		t.Fatal("evenement fork tronque accepte")
	}
}

func TestRingProcSPSC(t *testing.T) {
	var ring RingProc
	var ev blue.Event
	for i := range ProcRingSlots {
		ev.Pid = uint32(i)
		if rc := ring.Write(&ev); rc != 0 {
			t.Fatalf("ecriture %d: rc=%d", i, rc)
		}
	}
	if rc := ring.Write(&ev); rc != -2 {
		t.Fatalf("saturation: rc=%d, attendu -2", rc)
	}
	if ring.Drops() != 1 {
		t.Fatalf("rejets = %d, attendu 1", ring.Drops())
	}
	var out blue.Event
	for i := range ProcRingSlots {
		if ring.Read(&out) != 1 || out.Pid != uint32(i) {
			t.Fatalf("lecture %d: pid=%d", i, out.Pid)
		}
	}
	if ring.Read(&out) != 0 {
		t.Fatal("anneau non vide apres vidage complet")
	}
}

func TestProcDecodeNoAlloc(t *testing.T) {
	ring := NewRingProc()
	var dec ProcDecoder
	union := make([]byte, 8+taskCommLen)
	copy(union[8:], []byte("bash"))
	frame := procTestFrame(procEventExec, 42, union)
	if allocs := testing.AllocsPerRun(1000, func() {
		dec.Decode(frame, ring)
	}); allocs != 0 {
		t.Fatalf("allocations par decodage = %v, attendu 0", allocs)
	}
}

func TestOpenProcProbeIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("abonnement cn_proc soumis a CAP_NET_ADMIN")
	}
	var ring RingProc
	p, err := OpenProcProbe(&ring)
	if err != nil {
		t.Skipf("connecteur de processus indisponible: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := p.Run(ctx); err != nil {
		t.Fatalf("boucle epoll: %v", err)
	}
}
