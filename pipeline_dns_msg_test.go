package c2blue55

import (
	"encoding/binary"
	"math/rand"
	"strings"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
	"github.com/hazyhaar/c2blue55/internal/engine"
)

func buildDNSMessage(txID uint16, qr bool, qname string, qtype uint16, rdata []byte) []byte {
	flags := uint16(0x0100)
	var ancount uint16
	if qr {
		flags = 0x8180
	}
	if rdata != nil {
		ancount = 1
	}
	b := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(b[0:], txID)
	binary.BigEndian.PutUint16(b[2:], flags)
	binary.BigEndian.PutUint16(b[4:], 1)
	binary.BigEndian.PutUint16(b[6:], ancount)
	for label := range strings.SplitSeq(qname, ".") {
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1)
	if rdata != nil {
		b = append(b, 0xC0, 0x0C)
		b = binary.BigEndian.AppendUint16(b, qtype)
		b = binary.BigEndian.AppendUint16(b, 1)
		b = binary.BigEndian.AppendUint32(b, 60)
		b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
		b = append(b, rdata...)
	}
	return b
}

func TestPipelineEvaluateDNSMessage(t *testing.T) {
	p, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline : %v", err)
	}
	defer p.Close()

	var src, dst [16]byte
	src[15], dst[15] = 1, 2
	const now = int64(1_000_000_000)

	query := buildDNSMessage(0x1001, false, "api.hazyhaar.fr", 1, nil)
	reply := buildDNSMessage(0x1001, true, "api.hazyhaar.fr", 1, []byte{1, 2, 3, 4})
	for i, msg := range [][]byte{query, reply} {
		res, err := p.EvaluateDNSMessage(msg, now+int64(i), src, dst)
		if err != nil {
			t.Fatalf("message bénin %d : erreur inattendue : %v", i, err)
		}
		if res.Decision != DecisionFastPass {
			t.Errorf("message bénin %d : décision = %v, attendu DecisionFastPass", i, res.Decision)
		}
	}

	const hostile = "a.tunnel-c2.org"
	rng := rand.New(rand.NewSource(0x5EED))
	var res EvaluationResult
	for i := range 4 {
		txID := uint16(0x2000 + i)
		payload := make([]byte, 240)
		rng.Read(payload)
		q := buildDNSMessage(txID, false, hostile, 16, nil)
		r := buildDNSMessage(txID, true, hostile, 16, payload)
		ts := now + int64(10+2*i)
		if _, err := p.EvaluateDNSMessage(q, ts, src, dst); err != nil {
			t.Fatalf("échange %d, requête : erreur inattendue : %v", i, err)
		}
		res, err = p.EvaluateDNSMessage(r, ts+1, src, dst)
		if err != nil {
			t.Fatalf("échange %d, réponse : erreur inattendue : %v", i, err)
		}
	}
	if res.Decision != DecisionEscalateSLM {
		t.Errorf("P1 après 4 échanges : décision = %v, attendu DecisionEscalateSLM", res.Decision)
	}

	allocs := testing.AllocsPerRun(100, func() {
		_, _ = p.EvaluateDNSMessage(query, now, src, dst)
	})
	if allocs != 0 {
		t.Errorf("EvaluateDNSMessage : %v allocs/op, attendu 0", allocs)
	}
}

func TestPipelineEvaluateDNSMessage_18ClassesAndZeroAlloc(t *testing.T) {
	p, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline : %v", err)
	}
	defer p.Close()

	exchanges, truth, err := dnslab.BuildIRLDilutedStream17Motifs(0x2601, 0.80, 480)
	if err != nil {
		t.Fatalf("BuildIRLDilutedStream17Motifs : %v", err)
	}

	var src, dst [16]byte
	src[15], dst[15] = 2, 1

	detectedFamilies := map[string]int{}
	benignFalsePositives := 0

	for i, ex := range exchanges {
		fam := truth[i].MotifFamily
		resQ, clsQ, reasonQ, errQ := p.EvaluateDNSMessageWithReason(ex.RequestWire, ex.TimestampNs, src, dst)
		if errQ != nil {
			t.Fatalf("req[%d] (%s) : %v", i, fam, errQ)
		}
		resR, clsR, reasonR, errR := p.EvaluateDNSMessageWithReason(ex.ResponseWire, ex.TimestampNs+1_000_000, src, dst)
		if errR != nil {
			t.Fatalf("resp[%d] (%s) : %v", i, fam, errR)
		}

		if fam == "BENIGN" {
			if resQ.Decision != DecisionFastPass || resR.Decision != DecisionFastPass || reasonQ != engine.ReasonNone || reasonR != engine.ReasonNone {
				benignFalsePositives++
				t.Errorf("faux positif bénin sur échange[%d] (%s.%s qtype=%d) : req=(%v,%s,%s) resp=(%v,%s,%s)",
					i, ex.Subdomain, ex.DomainApex, ex.QType, resQ.Decision, clsQ, reasonQ, resR.Decision, clsR, reasonR)
			}
		} else {
			if resQ.Decision == DecisionEscalateSLM || resR.Decision == DecisionEscalateSLM {
				detectedFamilies[fam]++
			}
		}
	}

	if benignFalsePositives != 0 {
		t.Errorf("benignFalsePositives = %d, attendu 0 sur tous les pièges bénins du même canal", benignFalsePositives)
	}

	allMotifs := []string{
		"M-01", "M-02", "M-03", "M-04",
		"P1", "P2", "P3", "P4",
		"P5", "P6", "P7", "P8", "P9", "P10", "P11", "P12", "P13",
	}
	for _, m := range allMotifs {
		if detectedFamilies[m] == 0 {
			t.Errorf("famille %s non détectée en flux temps réel par Pipeline.EvaluateDNSMessageWithReason", m)
		}
	}

	sampleReq := exchanges[0].RequestWire
	sampleResp := exchanges[0].ResponseWire
	allocs := testing.AllocsPerRun(100, func() {
		_, _, _, _ = p.EvaluateDNSMessageWithReason(sampleReq, 1_800_000_000, src, dst)
		_, _, _, _ = p.EvaluateDNSMessageWithReason(sampleResp, 1_800_000_001, src, dst)
	})
	if allocs != 0 {
		t.Errorf("EvaluateDNSMessageWithReason AllocsPerRun = %.2f, attendu 0", allocs)
	}
}
