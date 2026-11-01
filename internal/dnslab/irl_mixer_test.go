package dnslab

import (
	"errors"
	"math"
	"strings"
	"testing"
)

func TestBuildIRLDilutedStream(t *testing.T) {
	// 1. Contrat de garde : refus hors bornes (SH-S15b-01).
	if _, _, err := BuildIRLDilutedStream(101, 0.50, 120); !errors.Is(err, ErrLiveRateContract) {
		t.Fatalf("attendu ErrLiveRateContract sur benignRatio=0.50, obtenu %v", err)
	}
	if _, _, err := BuildIRLDilutedStream(101, 0.85, 700); !errors.Is(err, ErrLiveRateContract) {
		t.Fatalf("attendu ErrLiveRateContract sur maxExchanges=700 (>600), obtenu %v", err)
	}
	if _, _, err := BuildIRLDilutedStream(101, 0.85, 10); !errors.Is(err, ErrLiveRateContract) {
		t.Fatalf("attendu ErrLiveRateContract sur maxExchanges=10 (<40), obtenu %v", err)
	}

	// 2. Génération nominale diluée à 85 % sur 200 échanges.
	exchanges, truth, err := BuildIRLDilutedStream(0x55AA01, 0.85, 200)
	if err != nil {
		t.Fatalf("BuildIRLDilutedStream: %v", err)
	}
	if len(exchanges) != 200 || len(truth) != 200 {
		t.Fatalf("longueurs inattendues: exchanges=%d truth=%d (attendu 200)", len(exchanges), len(truth))
	}

	famCounts := make(map[string]int)
	p4Apexes := make(map[string]bool)
	hasUnderscoreBenign := false
	dualStackPairs := 0

	for i := range exchanges {
		ex := exchanges[i]
		gt := truth[i]
		if gt.FrameIndex != i || len(gt.PacketSHA256) != 64 || gt.Family != ex.Family {
			t.Fatalf("désalignement vérité terrain à l'indice %d: %+v vs %+v", i, ex, gt)
		}
		if i > 0 && ex.TimestampNs < exchanges[i-1].TimestampNs {
			t.Fatalf("horodatage non monotone à i=%d: %d < %d", i, ex.TimestampNs, exchanges[i-1].TimestampNs)
		}
		famCounts[ex.Family]++
		if ex.Family == "P4" {
			p4Apexes[ex.DomainApex] = true
		}
		if ex.Family == "BENIGN" {
			if strings.Contains(ex.Subdomain, "_domainkey") || strings.Contains(ex.Subdomain, "_spf") || strings.Contains(ex.Subdomain, "_acme-challenge") {
				hasUnderscoreBenign = true
			}
			if i+1 < len(exchanges) && exchanges[i+1].Family == "BENIGN" &&
				ex.DomainApex == exchanges[i+1].DomainApex &&
				((ex.QType == 1 && exchanges[i+1].QType == 28) || (ex.QType == 28 && exchanges[i+1].QType == 1)) &&
				exchanges[i+1].TimestampNs-ex.TimestampNs <= 50_000_000 {
				dualStackPairs++
			}
		}
	}

	benignFrac := float64(famCounts["BENIGN"]) / float64(len(exchanges))
	if math.Abs(benignFrac-0.85) > 0.06 {
		t.Fatalf("ratio bénin hors cible: %.3f (attendu ~0.85)", benignFrac)
	}
	for _, fam := range []string{"P1", "P2", "P3", "P4"} {
		if famCounts[fam] < 6 {
			t.Fatalf("quota famille %s insuffisant: %d < 6", fam, famCounts[fam])
		}
	}
	if len(p4Apexes) < 4 {
		t.Fatalf("P4 doit couvrir >= 4 apex distincts, obtenu %d", len(p4Apexes))
	}
	if !hasUnderscoreBenign {
		t.Fatalf("bruit bénin IRL dépourvu d'enregistrements RFC à underscore (_domainkey/_spf/_acme-challenge)")
	}
	if dualStackPairs < 5 {
		t.Fatalf("bruit bénin IRL dépourvu de paires Happy Eyeballs A+AAAA: %d < 5", dualStackPairs)
	}
}
