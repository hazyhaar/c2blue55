package dnslab

import (
	"errors"
	"testing"
)

func TestBuildIRLDilutedStream8Motifs(t *testing.T) {
	// 1. Vérification des gardes de contrat (SH-S20b-01).
	if _, _, err := BuildIRLDilutedStream8Motifs(42, 0.50, 320); !errors.Is(err, ErrLiveRateContract) {
		t.Fatalf("attendu ErrLiveRateContract sur benignRatio=0.50, obtenu %v", err)
	}
	if _, _, err := BuildIRLDilutedStream8Motifs(42, 0.85, 80); !errors.Is(err, ErrLiveRateContract) {
		t.Fatalf("attendu ErrLiveRateContract sur totalExchanges=80 (<160), obtenu %v", err)
	}

	// 2. Génération nominale de 320 échanges dilués à 85% couvrant les 8 familles (M-01..M-04 + P1..P4).
	exchanges, truth, err := BuildIRLDilutedStream8Motifs(0x8855AA, 0.85, 320)
	if err != nil {
		t.Fatalf("BuildIRLDilutedStream8Motifs: %v", err)
	}
	if len(exchanges) != 320 || len(truth) != 320 {
		t.Fatalf("longueur inattendue: ex=%d truth=%d (attendu 320)", len(exchanges), len(truth))
	}

	counts := make(map[string]int)
	var qBuf, rBuf [512]byte
	for i, ex := range exchanges {
		counts[ex.Family]++
		if truth[i].FrameIndex != i || truth[i].Family != ex.Family || len(truth[i].PacketSHA256) != 64 {
			t.Fatalf("vérité terrain invalide à i=%d: %+v", i, truth[i])
		}
		if ex.Family == "P2" {
			// Séparation spectrale 2D : P2 doit être strictement hexadécimal [0-9a-f] (H_max <= 4.0) et de longueur [24,36].
			if len(ex.Subdomain) < 24 || len(ex.Subdomain) > 36 {
				t.Fatalf("P2 SubdomainLen=%d hors [24,36]", len(ex.Subdomain))
			}
			for _, c := range ex.Subdomain {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
					t.Fatalf("P2 contient un caractère hors Hex [0-9a-f]: %q", ex.Subdomain)
				}
			}
		}
		if ex.Family == "M-04" {
			// Vérifie que BuildLabResponse8Motifs renvoie RCode=3 (NXDOMAIN) sur les requêtes DGA M-04.
			qLen, err := BuildQuery(uint16(0x3000+i), []byte(ex.Subdomain+"."+ex.DomainApex), ex.QType, qBuf[:])
			if err != nil {
				t.Fatalf("BuildQuery M-04: %v", err)
			}
			_, dec, err := BuildLabResponse8Motifs(qBuf[:qLen], 0x8855AA, rBuf[:])
			if err != nil || dec.RCode != 3 {
				t.Fatalf("M-04 devait recevoir RCode=3 (NXDOMAIN), obtenu RCode=%d err=%v", dec.RCode, err)
			}
		}
	}

	for _, fam := range []string{"M-01", "M-02", "M-03", "M-04", "P1", "P2", "P3", "P4"} {
		if counts[fam] < 6 {
			t.Fatalf("famille %s sous-représentée: %d < 6", fam, counts[fam])
		}
	}

	// 3. Découpage en salves live sous bride OVH (<= 160 paquets req+resp soit <= 80 échanges par salve).
	salves, err := SplitLiveSalves(exchanges, 160, 5)
	if err != nil {
		t.Fatalf("SplitLiveSalves: %v", err)
	}
	if len(salves) != 4 {
		t.Fatalf("attendu 4 salves pour 320 échanges à <=80 échanges/salve, obtenu %d", len(salves))
	}
	totalSplit := 0
	for idx, s := range salves {
		if len(s)*2 > 160 {
			t.Fatalf("salve %d dépasse 160 paquets: %d paquets", idx, len(s)*2)
		}
		totalSplit += len(s)
	}
	if totalSplit != len(exchanges) {
		t.Fatalf("perte d'échanges lors du découpage: %d != %d", totalSplit, len(exchanges))
	}
}
