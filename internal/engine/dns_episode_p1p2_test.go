package engine

import "testing"

func p1p2Fill(b []byte, seed uint32) {
	for i := range b {
		seed = seed*1664525 + 1013904223
		b[i] = byte(seed >> 24)
	}
}

func p1p2Base32Label(n int, seed uint32) []byte {
	const alpha = "0123456789abcdefghijklmnopqrstuv"
	out := make([]byte, n)
	for i := range out {
		seed = seed*1664525 + 1013904223
		out[i] = alpha[seed>>27]
	}
	return out
}

func TestDNSEpisodeP1P2(t *testing.T) {
	var dst [EmbeddingDim]float32
	src := [16]byte{15: 1}
	apex := []byte("example.com")

	s1 := NewDNSEpisodeStore()
	var snap DNSEpisodeSnapshot
	for i := range 10 {
		q := DNSExchangeObs{
			TimestampNs: int64(i) * 1e6, SrcIP: src, TxID: uint16(i + 1),
			QType: 16, ParentApex: apex, Subdomain: []byte("a"),
		}
		snap, _ = s1.ObserveExchange(q, &dst)
	}
	for i := range 10 {
		rdata := make([]byte, 300)
		p1p2Fill(rdata, uint32(i+1))
		r := DNSExchangeObs{
			TimestampNs: int64(10+i) * 1e6, SrcIP: src, TxID: uint16(i + 1),
			IsResponse: true, QType: 16, ParentApex: apex, Subdomain: []byte("a"),
			AnswerRData: rdata, AnswerCount: 1,
		}
		snap, _ = s1.ObserveExchange(r, &dst)
	}
	if snap.MatchedReplies != 10 {
		t.Fatalf("P1 : MatchedReplies = %d, attendu 10", snap.MatchedReplies)
	}
	if snap.DownlinkRatio <= 3.0 {
		t.Errorf("P1 : DownlinkRatio = %f, attendu > 3.0", snap.DownlinkRatio)
	}
	if snap.CompositeP1P2 <= 0.35 {
		t.Errorf("P1 : CompositeP1P2 = %f, attendu > 0.35", snap.CompositeP1P2)
	}

	s2 := NewDNSEpisodeStore()
	for i := range 10 {
		q := DNSExchangeObs{
			TimestampNs: int64(i) * 1e6, SrcIP: src, TxID: uint16(100 + i),
			QType: 16, ParentApex: apex, Subdomain: p1p2Base32Label(32, uint32(i*7919+3)),
		}
		snap, _ = s2.ObserveExchange(q, &dst)
	}
	if snap.Base32HexScore <= 0.40 {
		t.Errorf("P2 : Base32HexScore = %f, attendu > 0.40", snap.Base32HexScore)
	}
	if snap.CompositeP1P2 <= 0.35 {
		t.Errorf("P2 : CompositeP1P2 = %f, attendu > 0.35", snap.CompositeP1P2)
	}

	s3 := NewDNSEpisodeStore()
	for i := range 5 {
		r := DNSExchangeObs{SrcIP: src, TxID: uint16(900 + i), IsResponse: true, ParentApex: apex}
		snap, _ = s3.ObserveExchange(r, &dst)
	}
	if snap.OrphanResponses != 5 {
		t.Fatalf("SH-S10a-01 : OrphanResponses = %d, attendu 5", snap.OrphanResponses)
	}

	flood := DNSExchangeObs{ParentApex: apex, Subdomain: []byte("f")}
	for i := range 5000 {
		flood.SrcIP[14], flood.SrcIP[15] = byte(i>>8), byte(i)
		flood.TxID = uint16(i)
		s3.ObserveExchange(flood, &dst)
	}
	allocs := testing.AllocsPerRun(100, func() {
		flood.TxID++
		s3.ObserveExchange(flood, &dst)
	})
	if allocs != 0 {
		t.Errorf("SH-S10a-01 : %v allocations/op, attendu 0", allocs)
	}
}
