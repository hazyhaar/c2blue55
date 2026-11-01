package dnslab

import (
	"encoding/binary"
	"testing"
)

func TestBuildIRLDilutedStream17Motifs(t *testing.T) {
	exchanges, truth, err := BuildIRLDilutedStream17Motifs(0x5517A, 0.80, 480)
	if err != nil {
		t.Fatalf("BuildIRLDilutedStream17Motifs : %v", err)
	}
	if len(exchanges) != 480 || len(truth) != 480 {
		t.Fatalf("len(exchanges)=%d len(truth)=%d, attendu 480/480", len(exchanges), len(truth))
	}

	counts := map[string]int{}
	benignAXFRCount := 0
	for i := range exchanges {
		fam := truth[i].MotifFamily
		counts[fam]++
		if fam == "BENIGN" && (exchanges[i].QType == 252 || exchanges[i].QType == 251) {
			benignAXFRCount++
		}

		reqWire := exchanges[i].RequestWire
		respWire := exchanges[i].ResponseWire
		if len(reqWire) < 17 || len(respWire) < 17 {
			t.Fatalf("pkt[%d] (%s) trame wire trop courte : req=%d resp=%d", i, fam, len(reqWire), len(respWire))
		}
		reqFlags := binary.BigEndian.Uint16(reqWire[2:4])
		reqOpcode := uint8((reqFlags >> 11) & 0x0F)
		reqNSCount := binary.BigEndian.Uint16(reqWire[8:10])
		respANCount := binary.BigEndian.Uint16(respWire[6:8])
		respARCount := binary.BigEndian.Uint16(respWire[10:12])

		switch fam {
		case "P5":
			if exchanges[i].QType != 252 && exchanges[i].QType != 251 {
				t.Errorf("P5 QType = %d, attendu 252 (AXFR) ou 251 (IXFR)", exchanges[i].QType)
			}
			if respANCount < 3 {
				t.Errorf("P5 ANCount = %d, attendu >= 3", respANCount)
			}
		case "P6":
			if reqOpcode != 5 || reqNSCount < 1 {
				t.Errorf("P6 Opcode=%d NSCount=%d, attendu 5 et >= 1", reqOpcode, reqNSCount)
			}
		case "P7":
			if exchanges[i].QType != 33 || respANCount == 0 {
				t.Errorf("P7 QType=%d ANCount=%d, attendu 33 et >= 1", exchanges[i].QType, respANCount)
			}
		case "P8":
			if respANCount < 3 {
				t.Errorf("P8 ANCount = %d, attendu >= 3 (chaîne CNAME)", respANCount)
			}
		case "P9":
			if respARCount == 0 {
				t.Errorf("P9 ARCount = 0, attendu >= 1 (RR OPT Type=41)")
			}
		case "P10":
			if respANCount < 3 {
				t.Errorf("P10 ANCount = %d, attendu >= 3 RR A à TTL divergents", respANCount)
			}
		case "P13":
			if exchanges[i].QType != 255 || respANCount < 3 {
				t.Errorf("P13 ANY QType=%d ANCount=%d, attendu 255 et >= 3", exchanges[i].QType, respANCount)
			}
		}
	}

	allMotifs := []string{
		"M-01", "M-02", "M-03", "M-04",
		"P1", "P2", "P3", "P4",
		"P5", "P6", "P7", "P8", "P9", "P10", "P11", "P12", "P13",
	}
	for _, m := range allMotifs {
		if counts[m] < 4 {
			t.Errorf("motif %s sous-représenté : %d échanges, attendu >= 4", m, counts[m])
		}
	}
	if benignAXFRCount < 4 {
		t.Errorf("baseline bénigne AXFR/IXFR même canal absente : %d échanges, attendu >= 4", benignAXFRCount)
	}

	// Découpage en 6 salves live <= 160 paquets sous bride F-21
	salves, err := SplitLiveSalves(exchanges, 160, MaxLiveQPS)
	if err != nil {
		t.Fatalf("SplitLiveSalves : %v", err)
	}
	if len(salves) != 6 {
		t.Errorf("len(salves) = %d, attendu 6", len(salves))
	}

	// Preuve 0 B/op sur BuildLabResponse17Motifs
	var dst [512]byte
	sampleReq := exchanges[0].RequestWire
	allocs := testing.AllocsPerRun(100, func() {
		_, _ = BuildLabResponse17Motifs(sampleReq, "P5", dst[:])
		_, _ = BuildLabResponse17Motifs(sampleReq, "P9", dst[:])
		_, _ = BuildLabResponse17Motifs(sampleReq, "P10", dst[:])
	})
	if allocs != 0 {
		t.Errorf("BuildLabResponse17Motifs AllocsPerRun = %.2f, attendu 0", allocs)
	}
}
