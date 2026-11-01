package c2blue55

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

func TestRecordSessionSync(t *testing.T) {
	dir := t.TempDir()
	pipe := NewDefaultPipeline()
	defer pipe.Close()

	rs, err := NewRecordSession(dir, "run-sync-01", pipe)
	if err != nil {
		t.Fatalf("NewRecordSession: %v", err)
	}

	clientIP := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 55, 0, 2}
	serverIP := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 55, 0, 1}

	var qBuf, rBuf [512]byte
	// 1. Échange P1 bidirectionnel où QR=0 a (src=client, dst=server) et QR=1 a (src=server, dst=client) (SH-S16a-01).
	qLen, err := dnslab.BuildQuery(0x4242, []byte("p1dl01.irl-p1-01.org"), 16, qBuf[:])
	if err != nil {
		t.Fatalf("BuildQuery: %v", err)
	}
	rLen, _, err := dnslab.BuildLabResponseP1P4(qBuf[:qLen], 0xCAFE, rBuf[:])
	if err != nil {
		t.Fatalf("BuildLabResponseP1P4: %v", err)
	}

	ts := int64(1_785_000_000_000_000_000)
	if _, err := rs.RecordDNSMessage(qBuf[:qLen], ts, clientIP, serverIP); err != nil {
		t.Fatalf("RecordDNSMessage(QR=0): %v", err)
	}
	// Injection d'un paquet DNS malformé au milieu de la session : doit être rejeté sans corrompre le PCAP.
	if _, err := rs.RecordDNSMessage([]byte{0x01, 0x02, 0x03}, ts+1000, clientIP, serverIP); err == nil {
		t.Fatalf("attendu erreur sur paquet DNS malformé")
	}
	// Réponse QR=1 avec inversion réaliste srcIP=serverIP, dstIP=clientIP.
	if _, err := rs.RecordDNSMessage(rBuf[:rLen], ts+5_000_000, serverIP, clientIP); err != nil {
		t.Fatalf("RecordDNSMessage(QR=1): %v", err)
	}

	if err := rs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Relecture croisée du PCAP et du JSONL.
	stats, err := ReadPCAPDNSMessages(rs.PCAPPath(), nil)
	if err != nil {
		t.Fatalf("ReadPCAPDNSMessages: %v", err)
	}
	if stats.TotalPackets != 2 || stats.DecodedQueries != 1 || stats.DecodedReplies != 1 || stats.MalformedCount != 0 {
		t.Fatalf("stats PCAP inattendues: %+v", stats)
	}

	f, err := os.Open(rs.JSONLPath())
	if err != nil {
		t.Fatalf("Open JSONL: %v", err)
	}
	defer f.Close()

	var lines []RecordedEpisodeLine
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var line RecordedEpisodeLine
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatalf("Unmarshal JSONL: %v", err)
		}
		lines = append(lines, line)
	}
	if len(lines) != stats.TotalPackets {
		t.Fatalf("désynchronisation PCAP (%d) vs JSONL (%d)", stats.TotalPackets, len(lines))
	}
	// Vérifie que la normalisation directionnelle QR=1 a permis l'appariement TxID et le déclenchement P1.
	if !lines[1].IsResponse || lines[1].DownlinkRatio <= 2.0 || lines[1].ReasonCode != engine.ReasonP1DownlinkExfil {
		t.Fatalf("appariement QR=1 ou attribution P1 défaillante: %+v", lines[1])
	}
}

func TestRecordSession_18ClassesReasonCodes(t *testing.T) {
	dir := t.TempDir()
	pipe := NewDefaultPipeline()
	defer pipe.Close()

	rs, err := NewRecordSession(dir, "run-18classes-01", pipe)
	if err != nil {
		t.Fatalf("NewRecordSession: %v", err)
	}

	clientIP := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 55, 0, 2}
	serverIP := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 55, 0, 1}

	exchanges, truth, err := dnslab.BuildIRLDilutedStream17Motifs(0x2602, 0.80, 480)
	if err != nil {
		t.Fatalf("BuildIRLDilutedStream17Motifs: %v", err)
	}

	for _, ex := range exchanges {
		if _, err := rs.RecordDNSMessage(ex.RequestWire, ex.TimestampNs, clientIP, serverIP); err != nil {
			t.Fatalf("RecordDNSMessage req: %v", err)
		}
		if _, err := rs.RecordDNSMessage(ex.ResponseWire, ex.TimestampNs+1_000_000, serverIP, clientIP); err != nil {
			t.Fatalf("RecordDNSMessage resp: %v", err)
		}
	}
	if err := rs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	f, err := os.Open(rs.JSONLPath())
	if err != nil {
		t.Fatalf("Open JSONL: %v", err)
	}
	defer f.Close()

	var lines []RecordedEpisodeLine
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var line RecordedEpisodeLine
		if err := json.Unmarshal(sc.Bytes(), &line); err != nil {
			t.Fatalf("Unmarshal JSONL: %v", err)
		}
		lines = append(lines, line)
	}
	if len(lines) != len(exchanges)*2 {
		t.Fatalf("len(lines)=%d, attendu %d", len(lines), len(exchanges)*2)
	}

	seenReasons := map[string]int{}
	for i := range exchanges {
		qLine := lines[i*2]
		rLine := lines[i*2+1]
		fam := truth[i].MotifFamily
		if fam == "BENIGN" {
			if qLine.ReasonCode != engine.ReasonNone || rLine.ReasonCode != engine.ReasonNone {
				t.Errorf("échange bénin %d (%s.%s) a produit ReasonCode req=%s resp=%s",
					i, exchanges[i].Subdomain, exchanges[i].DomainApex, qLine.ReasonCode, rLine.ReasonCode)
			}
		} else {
			if qLine.ReasonCode != engine.ReasonNone {
				seenReasons[qLine.ReasonCode]++
			}
			if rLine.ReasonCode != engine.ReasonNone {
				seenReasons[rLine.ReasonCode]++
			}
		}
	}

	wantReasons := []string{
		engine.ReasonM01LongLabel,
		engine.ReasonM02HighEntropy,
		engine.ReasonM03Burst,
		engine.ReasonM04DGAConsonantNX,
		engine.ReasonP1DownlinkExfil,
		engine.ReasonP2DenseEncoding,
		engine.ReasonP3BeaconMarkov,
		engine.ReasonP4MultiParentSharding,
		engine.ReasonP5AXFRBulk,
		engine.ReasonP6DynamicUpdate,
		engine.ReasonP7SRVC2Endpoint,
		engine.ReasonP8CNameChain,
		engine.ReasonP9EDNS0PrivateOption,
		engine.ReasonP10TTLStegoIntraA,
		engine.ReasonP11LengthTupleStego,
		engine.ReasonP12Base58Case,
		engine.ReasonP13ANYWildcard,
	}
	for _, wr := range wantReasons {
		if seenReasons[wr] == 0 {
			t.Errorf("ReasonCode %s jamais émis dans <run_id>.episodes.jsonl sur le flux 17 motifs", wr)
		}
	}
}
