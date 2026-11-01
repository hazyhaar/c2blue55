package engine

import "testing"

func TestForensicAndStreamTTD(t *testing.T) {
	if _, err := ComputeStreamTTD(nil); err == nil {
		t.Fatalf("ComputeStreamTTD(nil) devait échouer")
	}

	// Vérification de l'exemption RFC underscore (_domainkey, _acme-challenge, _dmarc, _spf).
	if !IsRFCUnderscoreSubdomain("default._domainkey.mail") || !IsRFCUnderscoreSubdomain("_acme-challenge.tls") {
		t.Fatalf("IsRFCUnderscoreSubdomain devait reconnaître _domainkey et _acme-challenge")
	}
	if IsRFCUnderscoreSubdomain("a1b2c3d4e5f60718") {
		t.Fatalf("IsRFCUnderscoreSubdomain ne devait pas exempter un label hexadécimal P2/P4")
	}

	// Construction d'un flux dilué 90% bénin (incluant _domainkey à haute entropie apparente) + 10% P1..P4.
	var stream []StreamEvalPoint
	ts := int64(1_780_000_000_000_000_000)

	// 36 événements bénins (dont des _domainkey et _acme-challenge avec P4/P2 artificiellement hauts pour tester le garde-fou).
	for i := range 36 {
		sub := "www-cdn"
		p4 := ClientP4Features{DistinctApexCount: 2, DistinctHighEntParents: 1, CompositeP4Score: -0.60}
		snap := DNSEpisodeSnapshot{Queries: 2, MatchedReplies: 2, DownlinkRatio: 0.8, MeanRDataEntropy: 2.1, Base32HexScore: 0.05}
		if i%6 == 0 {
			sub = "sel1._domainkey"
			// Même si un enregistrement DKIM a une entropie élevée sur plusieurs domaines, il doit être exempté.
			p4 = ClientP4Features{DistinctApexCount: 5, DistinctHighEntParents: 4, CompositeP4Score: 0.55}
			snap.Base32HexScore = 0.65
		}
		stream = append(stream, StreamEvalPoint{
			PacketIndex: len(stream),
			TimestampNs: ts,
			TrueFamily:  "BENIGN",
			Subdomain:   sub,
			Snap:        snap,
			P3:          EpisodeP3Features{CompositeP3Score: -0.50},
			P4:          p4,
		})
		ts += 50_000_000
	}

	// Injection P1 : détecté au 2e paquet de la famille P1 (dès la réponse RDATA haute entropie).
	stream = append(stream,
		StreamEvalPoint{
			PacketIndex: len(stream),
			TimestampNs: ts,
			TrueFamily:  "P1",
			Subdomain:   "p1q01",
			Snap:        DNSEpisodeSnapshot{Queries: 1, DownlinkRatio: 0.2},
		},
		StreamEvalPoint{
			PacketIndex: len(stream) + 1,
			TimestampNs: ts + 10_000_000,
			TrueFamily:  "P1",
			Subdomain:   "p1q01",
			Snap:        DNSEpisodeSnapshot{Queries: 1, MatchedReplies: 1, DownlinkRatio: 8.5, MeanRDataEntropy: 5.2},
		},
	)
	ts += 100_000_000

	// Injection P2 : détecté dès le 1er paquet (sous-domaine Base32/Hex dense).
	stream = append(stream, StreamEvalPoint{
		PacketIndex: len(stream),
		TimestampNs: ts,
		TrueFamily:  "P2",
		Subdomain:   "9f8e7d6c5b4a392817263544",
		Snap:        DNSEpisodeSnapshot{Queries: 1, Base32HexScore: 0.72},
	})
	ts += 100_000_000

	// Injection P3 : 5 paquets avant franchissement du seuil temporel/Markov.
	for k := range 5 {
		score := float32(0.10)
		if k >= 3 {
			score = 0.48
		}
		stream = append(stream, StreamEvalPoint{
			PacketIndex: len(stream),
			TimestampNs: ts + int64(k)*60_000_000_000,
			TrueFamily:  "P3",
			Subdomain:   "t001",
			P3:          EpisodeP3Features{InterArrivalCV: 0.04, MarkovEntropy: 0.62, CompositeP3Score: score},
		})
	}
	ts += 350_000_000_000

	// Injection P4 : 4 paquets sur 4 domaines parents distincts (détecté au 3e parent haute entropie).
	for k := 1; k <= 4; k++ {
		comp := float32(-0.60)
		if k >= 3 {
			comp = 0.42
		}
		stream = append(stream, StreamEvalPoint{
			PacketIndex: len(stream),
			TimestampNs: ts + int64(k)*500_000_000,
			TrueFamily:  "P4",
			Subdomain:   "a1b2c3d4e5f6071899aa",
			P4:          ClientP4Features{DistinctApexCount: uint16(k), DistinctHighEntParents: uint16(k), CompositeP4Score: comp},
		})
	}

	reports, err := ComputeStreamTTD(stream)
	if err != nil {
		t.Fatalf("ComputeStreamTTD: %v", err)
	}
	wantReasons := map[string]string{
		"P1": ReasonP1DownlinkExfil,
		"P2": ReasonP2DenseEncoding,
		"P3": ReasonP3BeaconMarkov,
		"P4": ReasonP4MultiParentSharding,
	}
	for fam, wantReason := range wantReasons {
		rep, ok := reports[fam]
		if !ok || !rep.Detected {
			t.Fatalf("famille %s non détectée: %+v", fam, rep)
		}
		if rep.BenignFalsePositives != 0 {
			t.Fatalf("famille %s: BenignFalsePositives=%d (attendu 0)", fam, rep.BenignFalsePositives)
		}
		if rep.PacketsToDetect <= 0 || rep.PacketsToDetect > 6 {
			t.Fatalf("famille %s: PacketsToDetect=%d hors [1,6]", fam, rep.PacketsToDetect)
		}
		if rep.FirstReasonCode != wantReason {
			t.Fatalf("famille %s: FirstReasonCode=%q attendu %q", fam, rep.FirstReasonCode, wantReason)
		}
	}
}

func TestStreamingDNS18State_All17MotifsAndBenignTraps(t *testing.T) {
	var st StreamingDNS18State
	clientIP := [16]byte{10, 55, 0, 2}
	ts := int64(1_795_000_000_000_000_000)

	// Test Base58 (P12) vs DNS-0x20 bénin
	b58Wire := buildWireQuerySimple(0x101, "5HueCGU8rMjxEXxiPuD5BDku4Mk.b58-stego-c2.org", 1)
	cls, reason, consumed := st.ObserveAndClassify18(b58Wire, ts, clientIP, []byte("5huecgu8rmjxexxipud5bdku4mk"), []byte("b58-stego-c2.org"), 1, DNSEpisodeSnapshot{}, EpisodeP3Features{})
	if cls != "P12" || reason != ReasonP12Base58Case || !consumed {
		t.Errorf("P12 Base58 : cls=%q reason=%q consumed=%v, attendu P12 / %s / true", cls, reason, consumed, ReasonP12Base58Case)
	}

	dns0x20Wire := buildWireQuerySimple(0x102, "WwW-01OIl.example-corp.com", 1)
	clsB, reasonB, _ := st.ObserveAndClassify18(dns0x20Wire, ts+1000, clientIP, []byte("www-01oil"), []byte("example-corp.com"), 1, DNSEpisodeSnapshot{}, EpisodeP3Features{})
	if clsB != "BENIGN" || reasonB != ReasonNone {
		t.Errorf("DNS-0x20 bénin : cls=%q reason=%q, attendu BENIGN / REASON_NONE", clsB, reasonB)
	}

	allocs := testing.AllocsPerRun(100, func() {
		_, _, _ = st.ObserveAndClassify18(b58Wire, ts, clientIP, []byte("5huecgu8rmjxexxipud5bdku4mk"), []byte("b58-stego-c2.org"), 1, DNSEpisodeSnapshot{}, EpisodeP3Features{})
	})
	if allocs != 0 {
		t.Errorf("ObserveAndClassify18 AllocsPerRun = %.2f, attendu 0", allocs)
	}
}
