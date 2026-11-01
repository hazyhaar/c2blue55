package dnslab_test

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

// Strate N-04 : campagne de noms inexistants « nx- » (famille redhost-negative-soa,
// outil replay) rejouée vers le résolveur récursif interposé (port configurable,
// 5335 pour Unbound sur redbo). Les noms sont engendrés par graine : deux graines
// donnent deux ensembles disjoints (Run-A / Run-B).

func n04Campaign(t *testing.T, seed uint64, port uint16) dnslab.Campaign {
	t.Helper()
	names, err := dnslab.GenerateNegativeNames(seed, "lab.pound2pound.fr", 50)
	if err != nil {
		t.Fatalf("GenerateNegativeNames: %v", err)
	}
	return dnslab.Campaign{
		RunID:      "n04-test",
		Family:     "redhost-negative-soa",
		Tool:       "replay",
		Server:     "10.55.0.2",
		ServerPort: port,
		Zone:       "lab.pound2pound.fr",
		Duration:   2 * time.Second,
		MaxQPS:     5,
		Names:      names,
	}
}

func TestNegativeNames_DeterministicDisjointInZone(t *testing.T) {
	a1, err := dnslab.GenerateNegativeNames(0xA, "lab.pound2pound.fr", 100)
	if err != nil {
		t.Fatal(err)
	}
	a2, _ := dnslab.GenerateNegativeNames(0xA, "lab.pound2pound.fr", 100)
	b, _ := dnslab.GenerateNegativeNames(0xB, "lab.pound2pound.fr", 100)
	if len(a1) != 100 || len(b) != 100 {
		t.Fatalf("tailles %d / %d, attendu 100", len(a1), len(b))
	}
	seen := map[string]bool{}
	for i, name := range a1 {
		if name != a2[i] {
			t.Fatalf("non déterministe à l'indice %d : %q vs %q", i, name, a2[i])
		}
		if !strings.HasPrefix(name, "nx-") || !strings.HasSuffix(name, ".lab.pound2pound.fr") {
			t.Fatalf("forme invalide : %q", name)
		}
		if seen[name] {
			t.Fatalf("doublon dans Run-A : %q", name)
		}
		seen[name] = true
		var query [512]byte
		if _, err := dnslab.BuildQuery(1, []byte(name), 1, query[:]); err != nil {
			t.Fatalf("BuildQuery(%q): %v", name, err)
		}
	}
	for _, name := range b {
		if seen[name] {
			t.Fatalf("Run-B partage un nom avec Run-A : %q", name)
		}
	}
	if _, err := dnslab.GenerateNegativeNames(1, "lab.pound2pound.fr", 201); !errors.Is(err, dnslab.ErrCampaignContract) {
		t.Errorf("201 noms : err = %v, attendu ErrCampaignContract", err)
	}
	if _, err := dnslab.GenerateNegativeNames(1, "lab.pound2pound.fr", 0); !errors.Is(err, dnslab.ErrCampaignContract) {
		t.Errorf("0 nom : err = %v, attendu ErrCampaignContract", err)
	}
}

func TestNegativeCampaign_ValidateFamilyAndPort(t *testing.T) {
	c := n04Campaign(t, 1, 5335)
	if err := c.Validate(); err != nil {
		t.Fatalf("campagne nominale refusée : %v", err)
	}
	if addr := c.ServerAddr(); addr.String() != "10.55.0.2:5335" {
		t.Errorf("ServerAddr = %s, attendu 10.55.0.2:5335", addr.String())
	}
	def := n04Campaign(t, 1, 0)
	if err := def.Validate(); err != nil {
		t.Fatalf("port 0 (défaut 53) refusé : %v", err)
	}
	if addr := def.ServerAddr(); addr.String() != "10.55.0.2:53" {
		t.Errorf("ServerAddr par défaut = %s, attendu 10.55.0.2:53", addr.String())
	}
	bad := n04Campaign(t, 1, 5335)
	bad.Tool = "iodine"
	if err := bad.Validate(); !errors.Is(err, dnslab.ErrCampaignContract) {
		t.Errorf("famille negative-soa avec outil iodine : err = %v, attendu ErrCampaignContract", err)
	}
	out := n04Campaign(t, 1, 5335)
	out.Server = "8.8.8.8"
	if err := out.Validate(); !errors.Is(err, dnslab.ErrCampaignContract) {
		t.Errorf("serveur hors labo : err = %v", err)
	}
	legacy := n04Campaign(t, 1, 0)
	legacy.Family, legacy.Tool = "redhost-replay", "replay"
	if err := legacy.Validate(); err != nil {
		t.Errorf("la famille historique redhost-replay doit rester acceptée : %v", err)
	}
}

func TestNegativeCampaign_ReplayHitsConfiguredPort(t *testing.T) {
	recv := listenLocal(t)
	port := uint16(recv.LocalAddr().(*net.UDPAddr).Port)
	c := n04Campaign(t, 7, port)
	c.Server = "127.0.0.1"
	c.Duration = time.Second
	c.MaxQPS = 5
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	sender := listenLocal(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Le rejeu vise c.ServerAddr(), donc le port configuré, et non un port 53 codé en dur.
	rep, err := dnslab.RunReplay(ctx, sender, c.ServerAddr(), &c, steppedNow(time.Unix(1_700_000_000, 0), 200*time.Millisecond))
	if err != nil {
		t.Fatalf("RunReplay: %v", err)
	}
	if rep.Sent == 0 {
		t.Fatalf("aucun datagramme envoyé (sent=%d)", rep.Sent)
	}
	// RunReplay revient avant l'arrivée des datagrammes sur la boucle locale :
	// lecture bloquante avec échéance, au lieu d'une fermeture immédiate du récepteur.
	if err := recv.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	premier := make([]byte, 1500)
	n, _, err := recv.ReadFrom(premier)
	if err != nil || n == 0 {
		t.Fatalf("aucun datagramme reçu sur le port %d (sent=%d, err=%v)", port, rep.Sent, err)
	}
	got := [][]byte{premier[:n]}
	name := c.Names[0]
	if !strings.Contains(strings.ToLower(string(got[0])), strings.ToLower(strings.SplitN(name, ".", 2)[0])) {
		t.Errorf("le premier datagramme ne porte pas le premier nom %q", name)
	}
}
