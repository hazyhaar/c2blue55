package dnslab_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

// Strate N-04b : une campagne destinée à un résolveur récursif (Unbound
// interposé) doit poser le drapeau RD sur ses questions, sinon le récursif
// répond REFUSED sans rien transmettre (mesuré sur redbo le 2026-10-29 : 600
// questions envoyées, zéro reçue par redhost). Campaign.Recursive = true ⇒
// RD = 1 ; false ⇒ RD = 0 comme avant (chemin direct vers l'autoritaire).

func n04bReplayFirstDatagram(t *testing.T, recursive bool) []byte {
	t.Helper()
	recv := listenLocal(t)
	port := uint16(recv.LocalAddr().(*net.UDPAddr).Port)
	names, err := dnslab.GenerateNegativeNames(3, "lab.pound2pound.fr", 5)
	if err != nil {
		t.Fatal(err)
	}
	c := dnslab.Campaign{
		RunID: "n04b", Family: "redhost-negative-soa", Tool: "replay",
		Server: "127.0.0.1", ServerPort: port, Zone: "lab.pound2pound.fr",
		Duration: time.Second, MaxQPS: 5, Names: names, Recursive: recursive,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
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
	if err != nil || n < 12 {
		t.Fatalf("aucun datagramme reçu (n=%d, err=%v)", n, err)
	}
	return premier[:n]
}

func TestRecursiveCampaign_SetsRDFlag(t *testing.T) {
	avec := n04bReplayFirstDatagram(t, true)
	if avec[2]&0x01 == 0 {
		t.Errorf("Recursive=true : RD absent (octet 2 = %#x)", avec[2])
	}
	if avec[2]&0x80 != 0 {
		t.Errorf("Recursive=true : QR posé à tort (octet 2 = %#x)", avec[2])
	}
	sans := n04bReplayFirstDatagram(t, false)
	if sans[2]&0x01 != 0 {
		t.Errorf("Recursive=false : RD posé à tort (octet 2 = %#x)", sans[2])
	}
}
