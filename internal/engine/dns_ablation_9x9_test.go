package engine

import (
	"fmt"
	"testing"
)

func TestConfusion9x9AndAblation(t *testing.T) {
	if _, err := EvaluateConfusion9x9AndAblation(nil); err == nil {
		t.Fatalf("EvaluateConfusion9x9AndAblation(nil) devait échouer")
	}

	var obs []Motif8EvalPoint
	ts := int64(1_785_000_000_000_000_000)

	// 1. Bruit bénin IRL (60 requêtes) : Happy Eyeballs A+AAAA, TXT _domainkey/_acme-challenge, CDN,
	// ET une faute de frappe bénigne réessayée 4 fois en A+AAAA sur le même QNAME (RCode=3).
	for i := range 50 {
		sub := fmt.Sprintf("www-%02d", i%5)
		apex := fmt.Sprintf("cdn-benign-%02d.com", i%4)
		qt := uint16(1)
		if i%2 == 1 {
			qt = 28
		}
		if i%10 == 0 {
			sub = "default._domainkey"
			apex = "mail-org.com"
			qt = 16
		}
		obs = append(obs, Motif8EvalPoint{
			PacketIndex: len(obs),
			TimestampNs: ts,
			TrueClass:   "BENIGN",
			DomainApex:  apex,
			Subdomain:   sub,
			QType:       qt,
			RCode:       0,
			RDataLen:    16,
			RDataEnt:    2.2,
		})
		ts += 50_000_000
	}
	// Faute de frappe utilisateur réessayée 6 fois sur le MÊME QNAME en NXDOMAIN : ne doit PAS déclencher M-04 !
	for r := range 6 {
		qt := uint16(1)
		if r%2 == 1 {
			qt = 28
		}
		obs = append(obs, Motif8EvalPoint{
			PacketIndex: len(obs),
			TimestampNs: ts,
			TrueClass:   "BENIGN",
			DomainApex:  "example-corp.com",
			Subdomain:   "wwvv-typo",
			QType:       qt,
			RCode:       3,
		})
		ts += 10_000_000
	}

	// 2. Injection des 4 motifs connus (M-01..M-04) sur le même ClientIP.
	for i := range 6 {
		obs = append(obs, Motif8EvalPoint{
			PacketIndex: len(obs),
			TimestampNs: ts,
			TrueClass:   "M-01",
			DomainApex:  "m01-tun.org",
			Subdomain:   fmt.Sprintf("chunk1a%02dabcdef0123456789.chunk2b%02dabcdef0123456789abcdef", i, i),
			QType:       16,
			RCode:       0,
			RDataLen:    16,
			RDataEnt:    2.5,
		})
		ts += 200_000_000
	}
	for i := range 6 {
		// M-02 : Alphabet alphanumérique large (> 16 symboles, H >= 4.10) sur 22 octets.
		obs = append(obs, Motif8EvalPoint{
			PacketIndex: len(obs),
			TimestampNs: ts,
			TrueClass:   "M-02",
			DomainApex:  "m02-exfil.net",
			Subdomain:   fmt.Sprintf("aB3dE5fG7hJ9kL1mN4pQ%dZ", i),
			QType:       1,
			RCode:       0,
			RDataLen:    4,
			RDataEnt:    1.5,
		})
		ts += 200_000_000
	}
	for i := range 6 {
		// M-03 : Rafale rapide de 6 sous-domaines distincts sur le même apex (dt = 15 ms).
		obs = append(obs, Motif8EvalPoint{
			PacketIndex: len(obs),
			TimestampNs: ts + int64(i)*15_000_000,
			TrueClass:   "M-03",
			DomainApex:  "m03-burst.org",
			Subdomain:   fmt.Sprintf("bst-%02d", i),
			QType:       1,
			RCode:       0,
			RDataLen:    4,
			RDataEnt:    1.5,
		})
	}
	ts += 500_000_000
	dgaSubs := []string{"qzvxkptlrmnbvcx", "xzkvqptlrmnghjk", "vqxzptlkrmnbvcd", "kqzvxptlrmnghjf", "zqxvkptlrmnbvcw", "pqzvxktlrmnghjs"}
	for i, s := range dgaSubs {
		// M-04 : 6 QNAME distincts à séquences consonantiques DGA + RCode=3 (NXDOMAIN).
		obs = append(obs, Motif8EvalPoint{
			PacketIndex: len(obs),
			TimestampNs: ts + int64(i)*100_000_000,
			TrueClass:   "M-04",
			DomainApex:  fmt.Sprintf("dga-%02d.org", i),
			Subdomain:   s,
			QType:       1,
			RCode:       3,
		})
	}
	ts += 1_000_000_000

	// 3. Injection des 4 nouveaux motifs d'évasion (P1..P4) sur le même ClientIP.
	for i := range 6 {
		obs = append(obs, Motif8EvalPoint{
			PacketIndex: len(obs),
			TimestampNs: ts + int64(i)*200_000_000,
			TrueClass:   "P1",
			DomainApex:  "p1-dl.org",
			Subdomain:   fmt.Sprintf("id%02d", i),
			QType:       10,
			RCode:       0,
			RDataLen:    240,
			RDataEnt:    5.4,
		})
	}
	ts += 2_000_000_000
	hexPayloads := []string{
		"0123456789abcdef0123456789ab",
		"123456789abcdef0123456789abc",
		"23456789abcdef0123456789abcd",
		"3456789abcdef0123456789abcde",
		"456789abcdef0123456789abcdef",
		"56789abcdef0123456789abcdef0",
	}
	for i, hp := range hexPayloads {
		// P2 : Hex strict [0-9a-f] de longueur 28 (H <= 4.00 par construction).
		obs = append(obs, Motif8EvalPoint{
			PacketIndex: len(obs),
			TimestampNs: ts + int64(i)*250_000_000,
			TrueClass:   "P2",
			DomainApex:  "p2-hex.net",
			Subdomain:   hp,
			QType:       1,
			RCode:       0,
			RDataLen:    4,
			RDataEnt:    1.5,
		})
	}
	ts += 2_000_000_000
	qtypesP3 := []uint16{1, 28, 16, 10, 5, 1}
	for i, qt := range qtypesP3 {
		// P3 : Balise périodique dt = 60 s strict + rotation Markov des QTYPE.
		obs = append(obs, Motif8EvalPoint{
			PacketIndex: len(obs),
			TimestampNs: ts + int64(i)*60_000_000_000,
			TrueClass:   "P3",
			DomainApex:  "p3-beacon.com",
			Subdomain:   fmt.Sprintf("hb%02d", i),
			QType:       qt,
			RCode:       0,
			RDataLen:    8,
			RDataEnt:    2.0,
		})
	}
	ts += 400_000_000_000
	for i := range 6 {
		// P4 : Sharding sur 6 domaines parents distincts (1 requête par parent, sous-domaine court 16 octets).
		obs = append(obs, Motif8EvalPoint{
			PacketIndex: len(obs),
			TimestampNs: ts + int64(i)*500_000_000,
			TrueClass:   "P4",
			DomainApex:  fmt.Sprintf("p4-shard-%02d.org", i),
			Subdomain:   fmt.Sprintf("s%d9f8e7d6c5b4a39", i),
			QType:       16,
			RCode:       0,
			RDataLen:    16,
			RDataEnt:    2.5,
		})
	}

	rep, err := EvaluateConfusion9x9AndAblation(obs)
	if err != nil {
		t.Fatalf("EvaluateConfusion9x9AndAblation: %v", err)
	}
	if !rep.AblationPass {
		t.Fatalf("AblationPass == false: %+v", rep)
	}
	if rep.BenignFPR != 0 {
		t.Fatalf("BenignFPR=%.4f (attendu 0)", rep.BenignFPR)
	}
	if rep.CrossConfusionM02P2 != 0 {
		t.Fatalf("CrossConfusionM02P2=%d (attendu 0)", rep.CrossConfusionM02P2)
	}
	if rep.RollupP4PollutionCount != 0 {
		t.Fatalf("RollupP4PollutionCount=%d (attendu 0 : M-01/M-02/M-04/P2 ne doivent pas polluer P4)", rep.RollupP4PollutionCount)
	}
	for _, m := range []string{"M-01", "M-02", "M-03", "M-04"} {
		if rep.RecallBaselineN[m] < 0.95 || rep.RecallExtendedN1[m] < 0.95 {
			t.Fatalf("rappel insuffisant sur motif connu %s: N=%.2f N+1=%.2f", m, rep.RecallBaselineN[m], rep.RecallExtendedN1[m])
		}
	}
	for _, p := range []string{"P1", "P2", "P3", "P4"} {
		if rep.RecallBaselineN[p] != 0.0 {
			t.Fatalf("le moteur baseline N ne devait pas détecter %s (obtenu %.2f)", p, rep.RecallBaselineN[p])
		}
		if rep.RecallExtendedN1[p] < 0.95 {
			t.Fatalf("le moteur étendu N+1 devait détecter %s >= 0.95 (obtenu %.2f)", p, rep.RecallExtendedN1[p])
		}
	}
}
