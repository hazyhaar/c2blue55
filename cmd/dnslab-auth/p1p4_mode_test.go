package main

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

func TestServeP1P4Packet(t *testing.T) {
	var qBuf, rBuf [512]byte

	// 1. Paquet tronqué -> refus propre sans panique (SH-S18a-01).
	if _, _, err := ServeP1P4Packet([]byte{0x01, 0x02}, 0x55, rBuf[:]); !errors.Is(err, dnslab.ErrQueryTooShort) {
		t.Fatalf("attendu ErrQueryTooShort, obtenu %v", err)
	}

	// 2. Boucle UDP loopback mêlant requête P1 TXT et sonde iodine NULL.
	srvConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket srv: %v", err)
	}
	defer srvConn.Close()

	cliConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket cli: %v", err)
	}
	defer cliConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		var pkt, ans [512]byte
		for range 2 {
			n, addr, err := srvConn.ReadFrom(pkt[:])
			if err != nil {
				return
			}
			respLen, _, err := ServeP1P4Packet(pkt[:n], 0x123456, ans[:])
			if err == nil && respLen > 0 {
				_, _ = srvConn.WriteTo(ans[:respLen], addr)
			}
		}
	}()

	for idx, q := range []struct {
		name  string
		qtype uint16
	}{
		{"p1dl01.irl-p1-01.org", 16},
		{"p01.iodine-tun.org", 10},
	} {
		qLen, err := dnslab.BuildQuery(uint16(0x100+idx), []byte(q.name), q.qtype, qBuf[:])
		if err != nil {
			t.Fatalf("BuildQuery(%s): %v", q.name, err)
		}
		if _, err := cliConn.WriteTo(qBuf[:qLen], srvConn.LocalAddr()); err != nil {
			t.Fatalf("WriteTo(%s): %v", q.name, err)
		}
		_ = cliConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _, err := cliConn.ReadFrom(rBuf[:])
		if err != nil {
			t.Fatalf("ReadFrom(%s): %v", q.name, err)
		}
		if n < 220 {
			t.Fatalf("réponse %s trop courte: %d octets (< 220)", q.name, n)
		}
	}
	<-done
}
