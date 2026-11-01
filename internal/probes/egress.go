//go:build linux

package probes

import (
	blue "github.com/hazyhaar/c2blue55"
	"golang.org/x/sys/unix"
)

// EgressHit décrit un flux sortant anormal initié par un démon passif.
type EgressHit struct {
	State   uint8
	Dst     [16]byte
	DstPort uint16
	Inode   uint32
}

// Flags retourne le verdict critique associé.
func (h EgressHit) Flags() uint32 {
	return blue.FlagBlocked | blue.FlagAnomaly
}

// IsPassiveDaemon reconnaît les démons qui ne devraient jamais initier de
// connexion sortante. Zéro allocation.
func IsPassiveDaemon(comm []byte) bool {
	base := baseName(comm)
	switch {
	case asciiEq(base, "redis-server"), asciiEq(base, "mysqld"),
		asciiEq(base, "mariadbd"), asciiEq(base, "postgres"),
		asciiEq(base, "postmaster"), asciiEq(base, "mongod"),
		asciiEq(base, "memcached"):
		return true
	}
	return false
}

// IsRemote indique si l'adresse de destination est distante, c'est-à-dire ni
// boucle locale, ni non spécifiée, ni locale-lien, ni ULA.
func IsRemote(family uint8, ip [16]byte) bool {
	switch family {
	case unix.AF_INET:
		if ip[0] == 127 || ip[0] == 0 {
			return false
		}
		if ip[0] == 169 && ip[1] == 254 {
			return false
		}
		return true
	case unix.AF_INET6:
		allZero := true
		for _, b := range ip[:15] {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero && (ip[15] == 0 || ip[15] == 1) {
			return false
		}
		if ip[0] == 0xfe && ip[1]&0xc0 == 0x80 {
			return false
		}
		if ip[0]&0xfe == 0xfc {
			return false
		}
		return true
	}
	return false
}

// DetectDaemonEgress lève l'anomalie si un démon passif ouvre un flux
// SYN_SENT ou ESTABLISHED vers une adresse distante. Zéro allocation.
func DetectDaemonEgress(comm []byte, s SocketInfo) (EgressHit, bool) {
	if !IsPassiveDaemon(comm) {
		return EgressHit{}, false
	}
	if s.State != tcpSynSent && s.State != tcpEstablished {
		return EgressHit{}, false
	}
	if !IsRemote(s.Family, s.Dst) {
		return EgressHit{}, false
	}
	return EgressHit{
		State:   s.State,
		Dst:     s.Dst,
		DstPort: s.DstPort,
		Inode:   s.Inode,
	}, true
}

func putU16Dec(dst []byte, off int, v uint16) int {
	var tmp [5]byte
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
	return putBytes(dst, off, tmp[i:])
}

// emitDaemonEgress transcrit l'anomalie egress en Event 128 octets vers le
// RingNet. Zéro allocation tas.
func emitDaemonEgress(sink PushSink, tsNs uint64, pid uint32, comm []byte, hit EgressHit) int {
	if sink == nil {
		return -1
	}
	var ev blue.Event
	ev.Ts_ns = tsNs
	ev.Pid = pid
	ev.Tid = pid
	ev.Subsystem = blue.SubNet
	ev.Action = blue.ActConnect
	ev.Flags = hit.Flags()
	ev.Src = uint64(hit.Inode)
	off := putAt(ev.Payload[:], 0, "egress:")
	off = putBytes(ev.Payload[:], off, baseName(comm))
	off = putAt(ev.Payload[:], off, " state=")
	if hit.State == tcpSynSent {
		off = putAt(ev.Payload[:], off, "SYN_SENT")
	} else {
		off = putAt(ev.Payload[:], off, "ESTABLISHED")
	}
	off = putAt(ev.Payload[:], off, " dport=")
	off = putU16Dec(ev.Payload[:], off, hit.DstPort)
	_ = off
	return sink.Push(&ev)
}

// EmitDaemonEgress expose la transcription à un puits quelconque (RingNet).
func EmitDaemonEgress(sink PushSink, tsNs uint64, pid uint32, comm []byte, hit EgressHit) int {
	return emitDaemonEgress(sink, tsNs, pid, comm, hit)
}
