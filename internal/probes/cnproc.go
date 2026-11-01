//go:build linux

// Sonde de filiation de processus par le connecteur noyau cn_proc. Le module
// ouvre un socket Netlink de type NETLINK_CONNECTOR, s'abonne aux evenements
// de processus par PROC_CN_MCAST_LISTEN, puis transcrit sans allocation tas
// chaque message recu vers l'anneau SPSC RingProc. Le noyau doit exposer
// CONFIG_CONNECTOR=y et CONFIG_PROC_EVENTS=y ; l'abonnement requiert la
// capacite CAP_NET_ADMIN.
package probes

import (
	"context"
	"encoding/binary"
	"errors"
	"sync/atomic"

	blue "github.com/hazyhaar/c2blue55"
	"golang.org/x/sys/unix"
)

// Identifiants du connecteur de processus : CN_IDX_PROC / CN_VAL_PROC.
const (
	cnIdxProc = 1
	cnValProc = 1
)

// Ordre d'abonnement au flux processus (enum proc_cn_mcast_op).
const procCnMcastListen = 1

// Disposition binaire du protocole Netlink connecteur.
const (
	netlinkHeaderLen = 16 // struct nlmsghdr
	cnMessageLen     = 20 // struct cn_msg sans donnees
	netlinkAlignTo   = 4  // NLMSG_ALIGNTO
	procEventHeader  = 16 // what + cpu + timestamp_ns
	taskCommLen      = 16 // TASK_COMM_LEN
)

// Valeurs de l'enum proc_cn_event retenues par la sonde.
const (
	procEventFork = 0x00000001
	procEventExec = 0x00000002
	procEventUID  = 0x00000004
	procEventExit = 0x80000000
)

// Dimensionnements fixes : tampon de reception statique de 8 Kio et anneau de
// 1024 slots. Ces bornes evitent toute croissance dynamique au runtime.
const (
	ProcRecvBufSize = 8192
	ProcRingSlots   = 1024
	procUIDTableLen = 1024
)

// uidUnknown marque l'absence d'UID effectif anterieur connu pour un PID.
const uidUnknown = ^uint32(0)

// Erreurs de la sonde.
var (
	errNilProcRing  = errors.New("probes: anneau RingProc nul")
	errNilProcProbe = errors.New("probes: sonde processus non ouverte")
)

// RingProc est un anneau SPSC lock-free de ProRingSlots evenements canoniques.
// Un unique producteur (la boucle Netlink) et un unique consommateur peuvent
// l'utiliser sans verrou ; toute autre concurrence est interdite.
type RingProc struct {
	Slots [ProcRingSlots]blue.Event
	head  atomic.Uint64
	drops atomic.Uint64
	_     [48]byte
	tail  atomic.Uint64
	_     [56]byte
}

// NewRingProc alloue un anneau de processus pret a l'emploi. L'allocation est
// unique et hors du chemin chaud ; un appelant soucieux du placement peut
// plutot declarer un RingProc en memoire statique et le passer a la sonde.
func NewRingProc() *RingProc {
	return &RingProc{}
}

// Write depose un evenement. Retourne 0 en succes, -1 sur argument invalide et
// -2 sur saturation, avec increment atomique du compteur de rejets.
func (r *RingProc) Write(ev *blue.Event) int {
	if r == nil || ev == nil {
		return -1
	}
	h := r.head.Load()
	if h-r.tail.Load() >= ProcRingSlots {
		r.drops.Add(1)
		return -2
	}
	r.Slots[h&(ProcRingSlots-1)] = *ev
	r.head.Store(h + 1)
	return 0
}

// Push est l'alias de Write par lequel RingProc satisfait le puits d'alerte
// commun de la sonde (interface PushSink), sans changement de semantique.
func (r *RingProc) Push(ev *blue.Event) int {
	return r.Write(ev)
}

// Read extrait un evenement. Retourne 1 si un evenement a ete lu, 0 si
// l'anneau est vide et -1 sur argument invalide.
func (r *RingProc) Read(ev *blue.Event) int {
	if r == nil || ev == nil {
		return -1
	}
	t := r.tail.Load()
	if t >= r.head.Load() {
		return 0
	}
	*ev = r.Slots[t&(ProcRingSlots-1)]
	r.tail.Store(t + 1)
	return 1
}

// Drops retourne le nombre cumule d'evenements rejetes par saturation.
func (r *RingProc) Drops() uint64 {
	if r == nil {
		return 0
	}
	return r.drops.Load()
}

// Reset vide l'anneau et remet les compteurs a zero. L'appel ne doit pas etre
// concurrent avec une ecriture ou une lecture.
func (r *RingProc) Reset() {
	if r == nil {
		return
	}
	r.head.Store(0)
	r.tail.Store(0)
	r.drops.Store(0)
}

// procUIDEntry conserve le dernier UID effectif observe pour un PID, afin de
// distinguer une elevation reelle d'une simple relecture d'un meme contexte.
type procUIDEntry struct {
	pid  uint32
	euid uint32
}

// ProcDecoder transcrit les trames Netlink connecteur vers RingProc. La table
// d'UID anterieurs est bornee et a adressage direct : aucune allocation tas
// n'intervient pendant le decodage.
type ProcDecoder struct {
	uid [procUIDTableLen]procUIDEntry
}

// Decode parcourt un tampon Netlink pouvant contenir plusieurs messages
// concatenes et retourne le nombre d'evenements processus transcrits.
func (d *ProcDecoder) Decode(buf []byte, ring *RingProc) int {
	if ring == nil {
		return 0
	}
	le := binary.LittleEndian
	total := 0
	for off := 0; off+netlinkHeaderLen <= len(buf); {
		msgLen := int(le.Uint32(buf[off:]))
		if msgLen < netlinkHeaderLen || off+msgLen > len(buf) {
			break
		}
		msgType := le.Uint16(buf[off+4:])
		payload := buf[off+netlinkHeaderLen : off+msgLen]
		if msgType != unix.NLMSG_ERROR && len(payload) >= cnMessageLen {
			if le.Uint32(payload[0:]) == cnIdxProc && le.Uint32(payload[4:]) == cnValProc {
				eventBytes := payload[cnMessageLen:]
				if cLen := int(le.Uint16(payload[16:])); cLen <= len(eventBytes) {
					eventBytes = eventBytes[:cLen]
				}
				if d.decodeProcEvent(eventBytes, ring) {
					total++
				}
			}
		}
		off += (msgLen + netlinkAlignTo - 1) &^ (netlinkAlignTo - 1)
	}
	return total
}

// decodeProcEvent transcrit le corps d'un struct proc_event. Le champ Src porte,
// selon l'action, le PID parent (fork), le couple (ancien<<32 | nouveau) des
// UID effectifs (uid), ou le code de sortie (exit). La charge utile conserve
// les valeurs longues : comm pour exec, signal pour exit, UID reels pour uid.
func (d *ProcDecoder) decodeProcEvent(eventBytes []byte, ring *RingProc) bool {
	if len(eventBytes) < procEventHeader {
		return false
	}
	le := binary.LittleEndian
	what := le.Uint32(eventBytes[0:])
	body := eventBytes[procEventHeader:]

	var ev blue.Event
	ev.Ts_ns = le.Uint64(eventBytes[8:])
	ev.Subsystem = blue.SubProc

	switch what {
	case procEventFork:
		if len(body) < 16 {
			return false
		}
		ev.Action = blue.ActFork
		ev.Src = uint64(le.Uint32(body[0:])) // parent_pid
		ev.Pid = le.Uint32(body[8:])         // child_pid
		ev.Tid = le.Uint32(body[12:])        // child_tgid
		le.PutUint32(ev.Payload[0:], le.Uint32(body[4:]))
	case procEventExec:
		if len(body) < 8 {
			return false
		}
		ev.Action = blue.ActExec
		ev.Pid = le.Uint32(body[0:]) // process_pid
		ev.Tid = le.Uint32(body[4:]) // process_tgid
		if len(body) >= 8+taskCommLen {
			copy(ev.Payload[:taskCommLen], body[8:8+taskCommLen])
		}
	case procEventUID:
		if len(body) < 16 {
			return false
		}
		ev.Action = blue.ActPrivEsc
		ev.Pid = le.Uint32(body[0:]) // child_pid
		ev.Tid = le.Uint32(body[4:]) // child_tgid
		realUID := le.Uint32(body[8:])
		newEUID := le.Uint32(body[12:])
		old := d.lookupUID(ev.Pid)
		ev.Src = uint64(old)<<32 | uint64(newEUID)
		le.PutUint32(ev.Payload[0:], realUID)
		le.PutUint32(ev.Payload[4:], newEUID)
		if newEUID == 0 && old != 0 && old != uidUnknown {
			ev.Flags |= blue.FlagAnomaly
		}
		d.storeUID(ev.Pid, newEUID)
	case procEventExit:
		if len(body) < 16 {
			return false
		}
		ev.Action = blue.ActExit
		ev.Pid = le.Uint32(body[0:])                       // process_pid
		ev.Tid = le.Uint32(body[4:])                       // process_tgid
		le.PutUint32(ev.Payload[0:], le.Uint32(body[8:]))  // exit_code
		le.PutUint32(ev.Payload[4:], le.Uint32(body[12:])) // exit_signal
	default:
		return false
	}

	ring.Write(&ev)
	return true
}

// lookupUID retourne l'UID effectif anterieur d'un PID, ou uidUnknown.
func (d *ProcDecoder) lookupUID(pid uint32) uint32 {
	e := &d.uid[pid&(procUIDTableLen-1)]
	if e.pid == pid {
		return e.euid
	}
	return uidUnknown
}

// storeUID memorise l'UID effectif courant d'un PID dans la table directe.
func (d *ProcDecoder) storeUID(pid, euid uint32) {
	e := &d.uid[pid&(procUIDTableLen-1)]
	e.pid = pid
	e.euid = euid
}

// ProcProbe pilote le socket Netlink connecteur et sa boucle epoll.
type ProcProbe struct {
	fd   int
	epfd int
	ring *RingProc
	dec  ProcDecoder
	buf  [ProcRecvBufSize]byte
}

// buildProcListenRequest assemble le message d'abonnement
// CN_IDX_PROC / PROC_CN_MCAST_LISTEN : en-tete Netlink, cn_msg puis l'ordre
// sur quatre octets, dans un tampon statique de 40 octets.
func buildProcListenRequest() [netlinkHeaderLen + cnMessageLen + 4]byte {
	var req [netlinkHeaderLen + cnMessageLen + 4]byte
	le := binary.LittleEndian
	le.PutUint32(req[0:], uint32(len(req))) // nlmsg_len
	le.PutUint16(req[4:], unix.NLMSG_DONE)  // nlmsg_type
	le.PutUint16(req[6:], 0)                // nlmsg_flags
	le.PutUint32(req[8:], 1)                // nlmsg_seq
	le.PutUint32(req[12:], 0)               // nlmsg_pid
	le.PutUint32(req[16:], cnIdxProc)       // cn.id.idx
	le.PutUint32(req[20:], cnValProc)       // cn.id.val
	le.PutUint32(req[24:], 0)               // cn.seq
	le.PutUint32(req[28:], 0)               // cn.ack
	le.PutUint16(req[32:], 4)               // cn.len
	le.PutUint16(req[34:], 0)               // cn.flags
	le.PutUint32(req[36:], procCnMcastListen)
	return req
}

// OpenProcProbe cree le socket Netlink connecteur, l'abonne aux evenements de
// processus et prepare la boucle epoll. L'echec d'abonnement (EPERM sans
// CAP_NET_ADMIN, ENOSYS sans CONFIG_CONNECTOR) ferme proprement les
// descripteurs avant retour.
func OpenProcProbe(ring *RingProc) (*ProcProbe, error) {
	if ring == nil {
		return nil, errNilProcRing
	}
	fd, err := unix.Socket(unix.AF_NETLINK,
		unix.SOCK_DGRAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC,
		unix.NETLINK_CONNECTOR)
	if err != nil {
		return nil, err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<20); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	epfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	ev := &unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}
	if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, fd, ev); err != nil {
		unix.Close(epfd)
		unix.Close(fd)
		return nil, err
	}

	p := &ProcProbe{fd: fd, epfd: epfd, ring: ring}
	req := buildProcListenRequest()
	if err := unix.Sendto(fd, req[:], 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		p.Close()
		return nil, err
	}
	return p, nil
}

// Run attend les datagrammes sur epoll avec un delai borne, ce qui rend la
// boucle receptive a l'annulation du contexte sans reveil par signal. Chaque
// datagramme disponible est draine puis transcrit dans RingProc.
func (p *ProcProbe) Run(ctx context.Context) error {
	if p == nil || p.fd < 0 {
		return errNilProcProbe
	}
	var events [4]unix.EpollEvent
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, err := unix.EpollWait(p.epfd, events[:], 200)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return err
		}
		for i := range n {
			if events[i].Events&unix.EPOLLIN == 0 {
				continue
			}
			if err := p.drain(); err != nil {
				return err
			}
		}
	}
}

// drain vide le socket non bloquant jusqu'a EAGAIN et transcrit chaque
// datagramme. Le tampon de reception appartient a la sonde et est reutilise
// sans reallocation d'un evenement a l'autre.
func (p *ProcProbe) drain() error {
	for {
		n, _, err := unix.Recvfrom(p.fd, p.buf[:], 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				return nil
			}
			if err == unix.EINTR {
				continue
			}
			return err
		}
		if n <= 0 {
			return nil
		}
		p.dec.Decode(p.buf[:n], p.ring)
	}
}

// Close ferme le descripteur epoll puis le socket. Il est idempotent.
func (p *ProcProbe) Close() error {
	if p == nil {
		return nil
	}
	var err error
	if p.epfd >= 0 {
		err = unix.Close(p.epfd)
		p.epfd = -1
	}
	if p.fd >= 0 {
		if cerr := unix.Close(p.fd); err == nil {
			err = cerr
		}
		p.fd = -1
	}
	return err
}
