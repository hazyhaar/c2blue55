//go:build linux

package probes

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/hazyhaar/c2blue55"
	"golang.org/x/sys/unix"
)

func TestAuditDecodePacketConserveReponseDNS(t *testing.T) {
	chargeDNS := []byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	trame := make([]byte, 14+20+8+len(chargeDNS))
	binary.BigEndian.PutUint16(trame[12:14], 0x0800)
	enteteIP := trame[14:]
	enteteIP[0] = 0x45
	binary.BigEndian.PutUint16(enteteIP[2:4], uint16(20+8+len(chargeDNS)))
	enteteIP[9] = 17
	enteteIP[12], enteteIP[13], enteteIP[14], enteteIP[15] = 198, 51, 100, 53
	enteteIP[16], enteteIP[17], enteteIP[18], enteteIP[19] = 10, 55, 0, 2
	enteteUDP := enteteIP[20:]
	binary.BigEndian.PutUint16(enteteUDP[0:2], 53)
	binary.BigEndian.PutUint16(enteteUDP[2:4], 40000)
	binary.BigEndian.PutUint16(enteteUDP[4:6], uint16(8+len(chargeDNS)))
	copy(enteteUDP[8:], chargeDNS)

	var evenement c2blue55.Event
	if codeRetour := DecodePacket(trame, 1, &evenement); codeRetour != 0 {
		t.Fatalf("une reponse UDP DNS (srcPort=53, dstPort=40000) est ecartee: rc=%d", codeRetour)
	}
	if !bytes.Equal(evenement.Payload[:len(chargeDNS)], chargeDNS) {
		t.Fatalf("charge DNS restituee alteree: obtenu=%x attendu=%x", evenement.Payload[:len(chargeDNS)], chargeDNS)
	}
}

func TestAuditFrontiereCheminProtege(t *testing.T) {
	for _, cheminVoisinBenin := range []string{"/etc/shadowed", "/etc/sudoers.d.bak"} {
		_, decision := DecideVeto(unix.FAN_OPEN_PERM, cheminVoisinBenin, "redis-server")
		if decision != unix.FAN_ALLOW {
			t.Errorf("DecideVeto(%q) = %d, attendu FAN_ALLOW (%d)", cheminVoisinBenin, decision, unix.FAN_ALLOW)
		}
	}

	for _, cheminSensible := range []string{"/etc/shadow", "/var/spool/cron/crontabs/root"} {
		_, decision := DecideVeto(unix.FAN_OPEN_PERM, cheminSensible, "redis-server")
		if decision != unix.FAN_DENY {
			t.Errorf("DecideVeto(%q) = %d, attendu FAN_DENY (%d)", cheminSensible, decision, unix.FAN_DENY)
		}
	}
}
