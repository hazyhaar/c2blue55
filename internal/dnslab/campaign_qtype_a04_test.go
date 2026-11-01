package dnslab_test

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

// Strate A-04 : Campaign.QType choisit le type des questions émises (28 pour
// la campagne AAAA) ; la valeur zéro vaut 16 (TXT) comme avant. Validate
// n'admet que 0, 1, 16 et 28.

func a04FirstDatagram(t *testing.T, qtype uint16) []byte {
	t.Helper()
	recv := listenLocal(t)
	port := uint16(recv.LocalAddr().(*net.UDPAddr).Port)
	names, err := dnslab.GenerateNegativeNames(4, "lab.pound2pound.fr", 5)
	if err != nil {
		t.Fatal(err)
	}
	c := dnslab.Campaign{
		RunID: "a04", Family: "redhost-negative-soa", Tool: "replay",
		Server: "127.0.0.1", ServerPort: port, Zone: "lab.pound2pound.fr",
		Duration: time.Second, MaxQPS: 5, Names: names, Recursive: true, QType: qtype,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate(QType=%d): %v", qtype, err)
	}
	sender := listenLocal(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := dnslab.RunReplay(ctx, sender, c.ServerAddr(), &c, steppedNow(time.Unix(1_700_000_000, 0), 200*time.Millisecond)); err != nil {
		t.Fatalf("RunReplay: %v", err)
	}
	if err := recv.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	premier := make([]byte, 1500)
	n, _, err := recv.ReadFrom(premier)
	if err != nil || n < 17 {
		t.Fatalf("aucun datagramme reçu (n=%d, err=%v)", n, err)
	}
	return premier[:n]
}

func a04QType(t *testing.T, q []byte) uint16 {
	t.Helper()
	off := 12
	for off < len(q) && q[off] != 0 {
		off += 1 + int(q[off])
	}
	off++
	if off+4 > len(q) {
		t.Fatalf("question tronquée (%d octets)", len(q))
	}
	return binary.BigEndian.Uint16(q[off : off+2])
}

func TestCampaignQType_AAAAAndDefault(t *testing.T) {
	if got := a04QType(t, a04FirstDatagram(t, 28)); got != 28 {
		t.Errorf("QType=28 : question de type %d", got)
	}
	if got := a04QType(t, a04FirstDatagram(t, 0)); got != 16 {
		t.Errorf("QType=0 : question de type %d, attendu 16", got)
	}
	if got := a04QType(t, a04FirstDatagram(t, 1)); got != 1 {
		t.Errorf("QType=1 : question de type %d", got)
	}
}

func TestCampaignQType_ValidateRejectsOthers(t *testing.T) {
	names, _ := dnslab.GenerateNegativeNames(4, "lab.pound2pound.fr", 3)
	for _, bad := range []uint16{2, 15, 255, 65535} {
		c := dnslab.Campaign{RunID: "a04", Family: "redhost-negative-soa", Tool: "replay", Server: "10.55.0.2", Zone: "lab.pound2pound.fr", Duration: time.Second, MaxQPS: 5, Names: names, QType: bad}
		if err := c.Validate(); err == nil {
			t.Errorf("QType=%d accepté", bad)
		}
	}
}
