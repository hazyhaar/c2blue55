//go:build linux

package probes

import (
	"encoding/binary"
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Constantes du protocole netlink inet_diag.
const (
	nlmsgHdrLen      = 16
	diagReqSize      = nlmsgHdrLen + 56
	inetDiagMsgLen   = 72
	nlmsgAlign       = 4
	sockDiagByFamily = 20
	nlmsgError       = 2
	nlmsgDone        = 3
	nlmFRequest      = 0x01
	nlmFDump         = 0x300
)

// États TCP du noyau, valeurs de inet_diag_msg.idiag_state.
const (
	tcpEstablished uint8 = 1
	tcpSynSent     uint8 = 2
	tcpClose       uint8 = 7
)

// Erreurs de parsing netlink.
var (
	ErrDiagShortMsg = errors.New("probes: message netlink inet_diag tronqué")
	ErrDiagRequest  = errors.New("probes: requête inet_diag invalide")
	ErrDiagKernel   = errors.New("probes: erreur netlink du noyau")
)

// SocketInfo décrit un socket TCP/UDP actif extrait par inet_diag.
type SocketInfo struct {
	Family   uint8
	State    uint8
	Protocol uint8
	SrcPort  uint16
	DstPort  uint16
	Src      [16]byte
	Dst      [16]byte
	UID      uint32
	Inode    uint32
}

// OpenInetDiag ouvre et lie une socket NETLINK_INET_DIAG. Appel de mise en
// place, hors chemin chaud.
func OpenInetDiag() (int, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, unix.NETLINK_INET_DIAG)
	if err != nil {
		return -1, err
	}
	var sa [12]byte
	putNetlinkSockaddr(sa[:], 0)
	r0, _, e1 := unix.Syscall6(unix.SYS_BIND, uintptr(fd),
		uintptr(unsafe.Pointer(&sa[0])), uintptr(len(sa)), 0, 0, 0)
	if e1 != 0 {
		unix.Close(fd)
		return -1, e1
	}
	_ = r0
	return fd, nil
}

func putNetlinkSockaddr(b []byte, pid uint32) {
	b[0] = byte(unix.AF_NETLINK)
	b[1] = 0
	b[2] = 0
	b[3] = 0
	binary.NativeEndian.PutUint32(b[4:], pid)
	binary.NativeEndian.PutUint32(b[8:], 0)
}

func rawSendto(fd int, msg, sa []byte) error {
	if len(msg) == 0 {
		return nil
	}
	r0, _, e1 := unix.Syscall6(unix.SYS_SENDTO, uintptr(fd),
		uintptr(unsafe.Pointer(&msg[0])), uintptr(len(msg)), 0,
		uintptr(unsafe.Pointer(&sa[0])), uintptr(len(sa)))
	if e1 != 0 {
		return e1
	}
	_ = r0
	return nil
}

func rawRecvfrom(fd int, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, unix.EINVAL
	}
	r0, _, e1 := unix.Syscall6(unix.SYS_RECVFROM, uintptr(fd),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, 0, 0)
	if e1 != 0 {
		return 0, e1
	}
	return int(r0), nil
}

// buildDiagRequest encode un inet_diag_req_v2 de 72 octets.
func buildDiagRequest(req []byte, family, protocol uint8, stateMask, seq uint32) int {
	if len(req) < diagReqSize {
		return 0
	}
	for i := range diagReqSize {
		req[i] = 0
	}
	binary.NativeEndian.PutUint32(req[0:], uint32(diagReqSize))
	binary.NativeEndian.PutUint16(req[4:], sockDiagByFamily)
	binary.NativeEndian.PutUint16(req[6:], nlmFRequest|nlmFDump)
	binary.NativeEndian.PutUint32(req[8:], seq)
	binary.NativeEndian.PutUint32(req[12:], 0)
	req[16] = family
	req[17] = protocol
	req[18] = 0
	req[19] = 0
	binary.NativeEndian.PutUint32(req[20:], stateMask)
	return diagReqSize
}

// parseInetDiagMsg décode un inet_diag_msg de 72 octets.
func parseInetDiagMsg(b []byte) SocketInfo {
	var s SocketInfo
	s.Family = b[0]
	s.State = b[1]
	s.SrcPort = binary.BigEndian.Uint16(b[4:6])
	s.DstPort = binary.BigEndian.Uint16(b[6:8])
	copy(s.Src[:], b[8:24])
	copy(s.Dst[:], b[24:40])
	s.UID = binary.NativeEndian.Uint32(b[64:68])
	s.Inode = binary.NativeEndian.Uint32(b[68:72])
	return s
}

// parseDiagMessages parcourt un lot de messages netlink et remplit dst.
func parseDiagMessages(buf []byte, dst []SocketInfo) (stop bool, added int, err error) {
	off := 0
	for off+nlmsgHdrLen <= len(buf) {
		msgLen := int(binary.NativeEndian.Uint32(buf[off:]))
		if msgLen < nlmsgHdrLen || off+msgLen > len(buf) {
			return true, added, ErrDiagShortMsg
		}
		typ := binary.NativeEndian.Uint16(buf[off+4:])
		switch typ {
		case nlmsgDone:
			return true, added, nil
		case nlmsgError:
			return true, added, ErrDiagKernel
		case sockDiagByFamily:
			payload := buf[off+nlmsgHdrLen : off+msgLen]
			if len(payload) >= inetDiagMsgLen && added < len(dst) {
				dst[added] = parseInetDiagMsg(payload)
				added++
			}
		}
		off += (msgLen + nlmsgAlign - 1) &^ (nlmsgAlign - 1)
	}
	return false, added, nil
}

// DumpInetDiag émet une requête SOCK_DIAG_BY_FAMILY et décode les réponses.
// dst et buf sont fournis par l'appelant : aucune allocation tas interne.
// stateMask est le masque (1<<état) des états demandés.
func DumpInetDiag(fd int, family, protocol uint8, stateMask uint32, dst []SocketInfo, buf []byte, seq uint32) (int, error) {
	var req [diagReqSize]byte
	n := buildDiagRequest(req[:], family, protocol, stateMask, seq)
	if n == 0 {
		return 0, ErrDiagRequest
	}
	var sa [12]byte
	putNetlinkSockaddr(sa[:], 0)
	if err := rawSendto(fd, req[:n], sa[:]); err != nil {
		return 0, err
	}
	socketCount := 0
	for {
		m, err := rawRecvfrom(fd, buf)
		if err != nil {
			return socketCount, err
		}
		if m < nlmsgHdrLen {
			return socketCount, ErrDiagShortMsg
		}
		stop, added, perr := parseDiagMessages(buf[:m], dst[socketCount:])
		socketCount += added
		if perr != nil {
			return socketCount, perr
		}
		if stop {
			return socketCount, nil
		}
	}
}

// StateMaskAll demande tous les états de sockets.
const StateMaskAll = 0xFFFFFFFF

// StateMaskTCP établit le masque TCP établi + SYN envoyé.
const StateMaskTCP = (1 << tcpEstablished) | (1 << tcpSynSent)
