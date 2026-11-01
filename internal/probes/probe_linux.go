//go:build linux

package probes

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/hazyhaar/c2blue55"
)

// Dimensionnement de l'anneau mmap tpacket2 : 64 blocs de 64 Kio, soit 4 Mio.
const (
	DefaultBlockSize = 1 << 16
	DefaultBlockNr   = 64
	DefaultFrameSize = DefaultBlockSize
	DefaultFrameNr   = DefaultBlockNr * (DefaultBlockSize / DefaultFrameSize)
	DefaultRingBytes = DefaultBlockSize * DefaultBlockNr
)

// PacketProbe pilote un socket AF_PACKET en anneau mmap tpacket2 et projette
// chaque trame retenue par le filtre cBPF vers un puits RingNet.
type PacketProbe struct {
	fd      int
	ring    []byte
	ringNet RingNet
	frameNr int
}

// Open crée le socket AF_PACKET, attache le filtre cBPF, configure l'anneau
// PACKET_RX_RING et le projette en mémoire utilisateur. Une interface vide
// capte toutes les interfaces. L'ouverture requiert CAP_NET_RAW.
func Open(iface string, ringNet RingNet) (*PacketProbe, error) {
	if ringNet == nil {
		return nil, fmt.Errorf("probes: receptable RingNet nul")
	}
	proto := int(htons16(unix.ETH_P_ALL))
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_NONBLOCK, proto)
	if err != nil {
		return nil, err
	}
	ifaceIdx := 0
	if iface != "" {
		ifi, err := net.InterfaceByName(iface)
		if err != nil {
			unix.Close(fd)
			return nil, err
		}
		ifaceIdx = ifi.Index
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons16(unix.ETH_P_ALL), Ifindex: ifaceIdx}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.SetsockoptInt(fd, unix.SOL_PACKET, unix.PACKET_VERSION, unix.TPACKET_V2); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := attachFilter(fd); err != nil {
		unix.Close(fd)
		return nil, err
	}
	req := unix.TpacketReq{
		Block_size: DefaultBlockSize,
		Block_nr:   DefaultBlockNr,
		Frame_size: DefaultFrameSize,
		Frame_nr:   DefaultFrameNr,
	}
	if err := unix.SetsockoptTpacketReq(fd, unix.SOL_PACKET, unix.PACKET_RX_RING, &req); err != nil {
		unix.Close(fd)
		return nil, err
	}
	ring, err := unix.Mmap(fd, 0, DefaultRingBytes, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return &PacketProbe{fd: fd, ring: ring, ringNet: ringNet, frameNr: int(DefaultFrameNr)}, nil
}

// attachFilter injecte le programme cBPF dans le noyau via SO_ATTACH_FILTER.
func attachFilter(fd int) error {
	filter := BuildFilterDNSICMP()
	fprog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &fprog)
}

// Poll draine les trames disponibles de l'anneau sans copie intermédiaire et
// retourne le nombre de trames restituées au noyau. Une trame non décodable
// est comptabilisée puis écartée sans injection.
func (p *PacketProbe) Poll() int {
	if p == nil || len(p.ring) == 0 {
		return 0
	}
	processed := 0
	for i := 0; i < p.frameNr; i++ {
		off := i * DefaultFrameSize
		if off+unix.SizeofTpacket2Hdr > len(p.ring) {
			break
		}
		hdr := (*unix.Tpacket2Hdr)(unsafe.Pointer(&p.ring[off]))
		status := atomic.LoadUint32(&hdr.Status)
		if status&unix.TP_STATUS_USER == 0 {
			break
		}
		if status&unix.TP_STATUS_COPY == 0 && hdr.Snaplen > 0 {
			mac := off + int(hdr.Mac)
			end := mac + int(hdr.Snaplen)
			if end <= len(p.ring) {
				var ev c2blue55.Event
				ts := uint64(hdr.Sec)*1_000_000_000 + uint64(hdr.Nsec)
				if DecodePacket(p.ring[mac:end], ts, &ev) == 0 {
					p.ringNet.Write(&ev)
				}
			}
		}
		atomic.StoreUint32(&hdr.Status, unix.TP_STATUS_KERNEL)
		processed++
	}
	return processed
}

// Run draine l'anneau jusqu'à annulation du contexte et retourne le total de
// trames traitées. L'attente s'appuie sur poll(2) avec un délai borné.
func (p *PacketProbe) Run(ctx context.Context) int {
	total := 0
	fds := []unix.PollFd{{Fd: int32(p.fd), Events: unix.POLLIN}}
	for {
		select {
		case <-ctx.Done():
			return total
		default:
		}
		n := p.Poll()
		total += n
		if n > 0 {
			continue
		}
		if _, err := unix.Poll(fds, 100); err != nil && err != unix.EINTR {
			return total
		}
	}
}

// Close libère la projection mmap puis ferme le socket.
func (p *PacketProbe) Close() error {
	if p == nil {
		return nil
	}
	var err error
	if p.ring != nil {
		err = unix.Munmap(p.ring)
		p.ring = nil
	}
	if p.fd > 0 {
		if cerr := unix.Close(p.fd); err == nil {
			err = cerr
		}
		p.fd = -1
	}
	return err
}

// htons16 convertit un entier de l'ordre hôte vers l'ordre réseau.
func htons16(v uint16) uint16 {
	return v<<8 | v>>8
}
