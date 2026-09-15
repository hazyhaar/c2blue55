package c2blue55

// All inputs are explicit local protocol/policy fixtures or fault injections.
// None is claimed to be a captured attack, training sample or accuracy benchmark.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCorrectionDNSQuestionResetAndRecovery(t *testing.T) {
	valid := buildDNSQueryWire("before.example.test", TypeTXT)
	var ev DNSEvent
	ev.Timestamp, ev.ClientIP[15] = 42, 7
	badDot := append([]byte(nil), valid[:12]...)
	badDot = append(badDot, byte(len("bad-exfil-test.xyz")))
	badDot = append(badDot, "bad-exfil-test.xyz"...)
	badDot = append(badDot, 0, 0, 1, 0, 1)
	cases := [][]byte{nil, valid[:len(valid)-4], valid[:len(valid)-1], badDot}
	for _, qd := range []byte{0, 2} {
		bad := bytes.Clone(valid)
		bad[5] = qd
		cases = append(cases, bad)
	}
	for _, change := range []func([]byte){
		func(b []byte) { b[2] |= 0x80 },
		func(b []byte) { b[len(b)-1] = 3 },
		func(b []byte) { b[13] = '\\' },
		func(b []byte) { b[13] = 0 },
	} {
		bad := bytes.Clone(valid)
		change(bad)
		cases = append(cases, bad)
	}
	for i, bad := range cases {
		if err := ParseDNSQuery(valid, &ev); err != nil {
			t.Fatal(err)
		}
		if err := ParseDNSQuery(bad, &ev); err == nil {
			t.Fatalf("case %d accepted", i)
		}
		if ev.NameLen != 0 || ev.SubdomainLen != 0 || ev.ParentDomainLen != 0 || ev.QType != 0 || ev.ID != 0 || ev.MaxLabelLen != 0 {
			t.Fatalf("case %d retained derived state: %+v", i, ev)
		}
		if ev.Timestamp != 42 || ev.ClientIP[15] != 7 {
			t.Fatal("caller metadata lost")
		}
		if err := ParseDNSQuery(buildDNSQueryWire("example.test", TypeA), &ev); err != nil {
			t.Fatal(err)
		}
		if ev.FQDN() != "example.test" || ev.Sub() != "" || ev.QType != TypeA {
			t.Fatal("recovery retained old question")
		}
	}
}

func TestCorrectionDNSFullLengthAndCompressedLabels(t *testing.T) {
	name := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	var ev DNSEvent
	if err := ParseDNSQuery(buildDNSQueryWire(name, TypeA), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.NameLen != 253 || ev.SubdomainLen != 127 || ev.MaxLabelLen != 63 {
		t.Fatalf("boundary: %+v", ev)
	}
	longSub := strings.Repeat("a.", 120) + "example.test"
	if err := ParseDNSQuery(buildDNSQueryWire(longSub, TypeA), &ev); err != nil {
		t.Fatal(err)
	}
	if ev.Sub() != strings.TrimSuffix(strings.Repeat("a.", 120), ".") {
		t.Fatal("long subdomain omitted")
	}
	if err := ParseDNSQuery(buildDNSQueryWire(name+"d", TypeA), &ev); err != ErrNameTooLong {
		t.Fatalf("254 text bytes: %v", err)
	}
	// One-hop compression fixture with a 63-byte target label at offset 18.
	plain := buildDNSQueryWire(strings.Repeat("z", 63)+".example.test", TypeTXT)
	compressed := append(bytes.Clone(plain[:12]), 0xc0, 18, 0, 16, 0, 1)
	compressed = append(compressed, plain[12:len(plain)-4]...)
	if err := ParseDNSQuery(compressed, &ev); err != nil {
		t.Fatal(err)
	}
	if ev.MaxLabelLen != 63 || ev.LabelCount != 3 || ev.QType != TypeTXT {
		t.Fatal("compressed metrics incomplete")
	}
	compressed[19] = '.'
	if err := ParseDNSQuery(compressed, &ev); err != ErrInvalidLabel {
		t.Fatalf("compressed binary label: %v", err)
	}
	if err := ParseDNSQuery(plain, &ev); err != nil || ev.MaxLabelLen != 63 {
		t.Fatalf("recovery: %v", err)
	}
	if n := testing.AllocsPerRun(100, func() { _ = ParseDNSQuery(plain, &ev) }); n != 0 {
		t.Fatalf("allocations: %g", n)
	}
}

func correctionDNSTable(t testing.TB, entries []BuildEntry) *ReputationTable {
	t.Helper()
	snap, err := CompileReputationSnapshot(entries)
	if err != nil {
		t.Fatal(err)
	}
	table, err := NewReputationTable(snap)
	if err != nil {
		t.Fatal(err)
	}
	return table
}

func TestCorrectionDNSReputationPermutationAndCollisions(t *testing.T) {
	entries := []BuildEntry{
		{"example.test", RepClassAllowTranco, MatchSubtree},
		{"example.test", RepClassBlockC2, MatchSubtree},
		{"a.example.test", RepClassAllowVendor, MatchExact},
		{"example.test", RepClassProtocolCrypto, MatchSubtree},
	}
	want, err := CompileReputationSnapshot(entries)
	if err != nil {
		t.Fatal(err)
	}
	var permute func(int)
	permute = func(i int) {
		if i == len(entries) {
			snap, err := CompileReputationSnapshot(entries)
			if err != nil || !bytes.Equal(want, snap) {
				t.Fatalf("noncanonical permutation: %v", err)
			}
			table := correctionDNSTable(t, entries)
			for _, name := range []string{"example.test", "a.example.test", "b.example.test"} {
				if res, ok := table.Match(name); !ok || res.Classification != RepClassBlockC2 {
					t.Fatalf("block lost: %s %+v", name, res)
				}
			}
			if table.numEntries != 2 {
				t.Fatalf("unmerged entries: %d", table.numEntries)
			}
			return
		}
		for j := i; j < len(entries); j++ {
			entries[i], entries[j] = entries[j], entries[i]
			permute(i + 1)
			entries[i], entries[j] = entries[j], entries[i]
		}
	}
	permute(0)
	// Fault injection forces a collision bucket. It is not a claimed FNV collision.
	// Production loading separately rejects forged hashes; this tests bucket search.
	table := correctionDNSTable(t, []BuildEntry{
		{"a.test", RepClassAllowTranco, MatchSubtree},
		{"b.test", RepClassAllowVendor, MatchExact},
		{"b.test", RepClassBlockC2, MatchSubtree},
		{"c.test", RepClassAllowTranco, MatchExact},
	})
	for i := 0; i < table.numEntries; i++ {
		binary.LittleEndian.PutUint64(table.entriesData[i*16:], 7)
	}
	for _, name := range []string{"a.test", "b.test", "c.test"} {
		res, ok := table.matchHash(name, 7, true)
		if !ok || res.MatchedDomain != name || name == "b.test" && res.Classification != RepClassBlockC2 {
			t.Fatalf("collision bucket: %+v %v", res, ok)
		}
	}
	if _, ok := table.matchHash("not.test", 7, true); ok {
		t.Fatal("hash alone matched")
	}
}

func TestCorrectionDNSSnapshotIntegrityOwnershipAndRecovery(t *testing.T) {
	entries := []BuildEntry{{"a.test", RepClassBlockC2, MatchExact}, {"b.test", RepClassAllowTranco, MatchSubtree}}
	snap, err := CompileReputationSnapshot(entries)
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func([]byte){
		func(b []byte) { b[4]++ },
		func(b []byte) { b[18]++ },
		func(b []byte) { b[39]++ },
		func(b []byte) { b[37] = 255 },
		func(b []byte) { b[38] = 0 },
		func(b []byte) { b[36] = 0 },
		func(b []byte) { b[24] ^= 1 },
		func(b []byte) { b[len(b)-1] = '/' },
		func(b []byte) { binary.LittleEndian.PutUint32(b[10:], 24) },
		func(b []byte) { binary.LittleEndian.PutUint32(b[6:], ^uint32(0)) },
		func(b []byte) { first := bytes.Clone(b[24:40]); copy(b[24:40], b[40:56]); copy(b[40:56], first) },
	}
	for i, mutate := range mutations {
		bad := bytes.Clone(snap)
		mutate(bad)
		if _, err := NewReputationTable(bad); err == nil {
			t.Fatalf("corruption %d accepted", i)
		}
		table, err := NewReputationTable(snap)
		if err != nil {
			t.Fatal(err)
		}
		if res, ok := table.Match("a.test"); !ok || res.Classification != RepClassBlockC2 {
			t.Fatal("restore failed")
		}
	}
	input := bytes.Clone(snap)
	table, err := NewReputationTable(input)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range input {
			input[i] ^= 255
		}
	}()
	for i := 0; i < 100; i++ {
		if res, ok := table.Match("a.test"); !ok || res.Classification != RepClassBlockC2 {
			t.Error("borrowed caller memory")
		}
	}
	wg.Wait()
	ar := NewAtomicReputation(table)
	for _, domain := range []string{"", "a..test", "a/test", "a\\test", "-a.test", "a-.test", strings.Repeat("a", 64) + ".test", strings.Repeat("a.", 128) + "test"} {
		if err := ar.ReloadFromEntries([]BuildEntry{{domain, RepClassBlockC2, MatchExact}}); err == nil {
			t.Fatalf("invalid domain accepted: %q", domain)
		}
		if _, ok := ar.Match("a.test"); !ok {
			t.Fatal("rejection changed active snapshot")
		}
	}
	if err := ar.ReloadFromEntries([]BuildEntry{{"restored.test", RepClassBlockC2, MatchExact}}); err != nil {
		t.Fatal(err)
	}
	if _, ok := ar.Match("restored.test"); !ok {
		t.Fatal("reload recovery failed")
	}
}

func TestCorrectionDNSSharedHostingAndPreFastPassControls(t *testing.T) {
	table, err := GetDefaultReputationTable()
	if err != nil {
		t.Fatal(err)
	}
	for _, root := range []string{"amazonaws.com", "cloudfront.net", "trafficmanager.net", "githubusercontent.com"} {
		if _, ok := table.Match("tenant." + root); ok {
			t.Fatalf("tenant inherited seed reputation: %s", root)
		}
		custom := correctionDNSTable(t, []BuildEntry{{root, RepClassAllowVendor, MatchSubtree}})
		if _, ok := custom.Match("tenant." + root); ok {
			t.Fatalf("compiler granted shared subtree: %s", root)
		}
	}
	for _, parent := range []string{"google.com", "sophosxl.com", "amazonaws.com"} {
		p, err := NewPipeline(PipelineConfig{}, table)
		if err != nil {
			t.Fatal(err)
		}
		wire := buildDNSQueryWire(strings.Repeat("ab", 25)+"._domainkey."+parent, TypeTXT)
		res, err := p.EvaluatePacket(wire, 10)
		if err != nil || res.Decision != DecisionEscalateSLM || res.EntropyQ8 == 0 || !res.ArbitrationQueued {
			t.Fatalf("protocol bypass %s: %+v %v", parent, res, err)
		}
		if v, _, _ := p.ApplyDeterministicVeto(res.Incident, "DNS_TUNNEL_CONFIRMED"); strings.HasPrefix(v, "BENIGN") {
			t.Fatal("veto undid protocol control")
		}
		// Same parent recovers after expiration with a bounded question.
		res, err = p.EvaluatePacket(buildDNSQueryWire("k1._domainkey."+parent, TypeTXT), 4000)
		if err != nil || res.Decision != DecisionFastPass || res.UniqueSubdomains != 1 {
			t.Fatalf("protocol recovery %s: %+v %v", parent, res, err)
		}
		_ = p.Close()
	}
	p, err := NewPipeline(PipelineConfig{}, table)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	for i := 0; i < 5; i++ {
		res, err := p.EvaluatePacket(buildDNSQueryWire(fmt.Sprintf("key%d._domainkey.google.com", i), TypeTXT), 10)
		if err != nil {
			t.Fatal(err)
		}
		if i == 4 && res.Decision != DecisionEscalateSLM {
			t.Fatal("protocol exemption bypassed cardinality")
		}
	}
}

func TestCorrectionDNSTrackerExpiryIdentityAndEviction(t *testing.T) {
	tracker := NewTemporalTracker()
	a, b := findSameSlotDomains(t)
	tracker.RecordQuery(a, "old", 1)
	tracker.RecordQuery(b, "first", 1000)
	tracker.RecordQuery(b, "second", 3500)
	if _, unique, count := tracker.RecordQuery(b, "third", 3601); count != 3 || unique != 3 {
		t.Fatalf("expired anchor hid identity: %d %d", count, unique)
	}
	if _, unique, count := tracker.RecordQuery(b, "fresh", 7201); count != 1 || unique != 1 {
		t.Fatalf("Bloom window survived expiration: %d %d", count, unique)
	}
	if _, unique, count := tracker.RecordQuery(b, "next", 7202); count != 2 || unique != 2 {
		t.Fatal("window failed to resume")
	}
	// Fill one eight-slot probe using real RecordQuery calls, not prewritten counts.
	groups := make(map[uint64][]string)
	var colliders []string
	for i := 0; i < 1000000 && colliders == nil; i++ {
		name := fmt.Sprintf("collision-%d.test", i)
		h := FNV1a64String(name)
		key := h%MaxTrackedDomains*8 + ((mix64(h) & 7) | 1)
		groups[key] = append(groups[key], name)
		if len(groups[key]) == 9 {
			colliders = groups[key]
		}
	}
	if colliders == nil {
		t.Fatal("no nine-way fixture found")
	}
	tracker = NewTemporalTracker()
	for _, name := range colliders {
		tracker.RecordQuery(name, "one", 100)
	}
	if tracker.Evictions() != 1 {
		t.Fatalf("invisible eviction: %d", tracker.Evictions())
	}
	if _, _, count := tracker.RecordQuery(colliders[8], "two", 101); count != 2 {
		t.Fatal("victim replacement not retained")
	}
	if _, _, count := tracker.RecordQuery(colliders[0], "returned", 102); count != 1 {
		t.Fatal("evicted identity not reinitialized")
	}
	if tracker.Evictions() != 2 {
		t.Fatal("second eviction not counted")
	}
}

type correctionDNSArbitrator func(context.Context, *SLMIncident) (SLMArbitrationResponse, error)

func (f correctionDNSArbitrator) Arbitrate(ctx context.Context, inc *SLMIncident) (SLMArbitrationResponse, error) {
	return f(ctx, inc)
}

func TestCorrectionDNSQueueSaturationDrainAndClose(t *testing.T) {
	p, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	wire := buildDNSQueryWire("0123456789abcdef0123456789.example.test", TypeTXT)
	for i := 0; i < 65; i++ {
		res, err := p.EvaluatePacket(wire, 100)
		if i < 64 && (err != nil || !res.ArbitrationQueued) {
			t.Fatalf("early queue failure %d: %v", i, err)
		}
		if i == 64 && (!errors.Is(err, ErrSLMQueueFull) || res.ArbitrationQueued || res.Incident == nil) {
			t.Fatalf("loss not explicit: %+v %v", res, err)
		}
	}
	if p.Stats().SLMRejected != 1 {
		t.Fatal("loss counter")
	}
	// Caller-controlled external consumer releases one slot, then re-enqueues successfully.
	<-p.SLMQueue()
	if res, err := p.EvaluatePacket(wire, 101); err != nil || !res.ArbitrationQueued {
		t.Fatalf("queue recovery: %v", err)
	}
	started := make(chan struct{})
	callbacks := make(chan string, 64)
	p.StartArbitratorWorker(context.Background(), correctionDNSArbitrator(func(ctx context.Context, _ *SLMIncident) (SLMArbitrationResponse, error) {
		close(started)
		<-ctx.Done()
		return SLMArbitrationResponse{}, ctx.Err()
	}), func(_ SLMIncident, verdict string, confidence float64, reason string) {
		if confidence != 0 || !strings.Contains(reason, "ARBITRATION_UNAVAILABLE") {
			t.Error("cancelled work certified")
		}
		callbacks <- verdict
	})
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}
	done := make(chan error, 1)
	go func() { done <- p.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not join worker")
	}
	if len(callbacks) != 64 || p.Stats().ArbitrationErrors != 64 {
		t.Fatalf("incomplete drain: callbacks=%d stats=%+v", len(callbacks), p.Stats())
	}
	for i := 0; i < 64; i++ {
		if <-callbacks != "INSUFFICIENT_EVIDENCE" {
			t.Fatal("invalid cancellation verdict")
		}
	}
	if _, err := p.EvaluatePacket(wire, 102); !errors.Is(err, ErrPipelineClosed) {
		t.Fatal("packet accepted after Close")
	}
	if err := p.Close(); err != nil {
		t.Fatal("Close not idempotent")
	}
	// A new instance has a working nominal lifecycle after the closed instance rejects.
	q, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if res, err := q.EvaluatePacket(buildDNSQueryWire("www.example.test", TypeA), 103); err != nil || res.Decision != DecisionFastPass {
		t.Fatal("new instance did not recover")
	}
}

func TestCorrectionDNSInvalidVerdictThenRecovery(t *testing.T) {
	p, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	inc := SLMIncident{FQDN: "example.test", QueryCount: 5, EntropyBits: 4.8}
	if v, c, why := p.ApplyDeterministicVeto(&inc, "ALLOW_ANYTHING"); v != "INSUFFICIENT_EVIDENCE" || c != 0 || why != "INVALID_ARBITRATION_VERDICT" {
		t.Fatal("unknown verdict accepted")
	}
	if v, _, _ := p.ApplyDeterministicVeto(nil, "DNS_TUNNEL_CONFIRMED"); v != "INSUFFICIENT_EVIDENCE" {
		t.Fatal("nil incident accepted")
	}
	responses := []SLMArbitrationResponse{{Verdict: "UNKNOWN", Confidence: 0.9}, {Verdict: "DNS_TUNNEL_CONFIRMED", Confidence: math.NaN()}, {Verdict: "DNS_TUNNEL_CONFIRMED", Confidence: 1.1}, {Verdict: "DNS_TUNNEL_CONFIRMED", Confidence: 0.37}}
	n := 0
	results := make(chan SLMArbitrationResponse, len(responses))
	p.StartArbitratorWorker(context.Background(), correctionDNSArbitrator(func(context.Context, *SLMIncident) (SLMArbitrationResponse, error) {
		result := responses[n]
		n++
		return result, nil
	}), func(_ SLMIncident, verdict string, confidence float64, _ string) {
		results <- SLMArbitrationResponse{Verdict: verdict, Confidence: confidence}
	})
	for range responses {
		p.slmQueue <- inc
	}
	for i := range responses {
		select {
		case result := <-results:
			if i < 3 && (result.Verdict != "INSUFFICIENT_EVIDENCE" || result.Confidence != 0) {
				t.Fatal("invalid response accepted")
			}
			if i == 3 && (result.Verdict != "DNS_TUNNEL_CONFIRMED" || result.Confidence != 0.37) {
				t.Fatalf("confidence replaced or no recovery: %+v", result)
			}
		case <-time.After(time.Second):
			t.Fatal("worker failed to resume")
		}
	}
	if p.Stats().ArbitrationErrors != 3 {
		t.Fatal("invalid response counter")
	}
}

func TestCorrectionDNSConcurrentCloseAndUnservedQueue(t *testing.T) {
	p, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	attack := buildDNSQueryWire("0123456789abcdef0123456789.example.test", TypeTXT)
	if res, err := p.EvaluatePacket(attack, 100); err != nil || !res.ArbitrationQueued {
		t.Fatal("initial enqueue failed")
	}
	nominal := buildDNSQueryWire("www.google.com", TypeA)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, err := p.EvaluatePacket(nominal, 100)
				if err != nil && !errors.Is(err, ErrPipelineClosed) {
					t.Errorf("concurrent evaluation: %v", err)
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := p.Close(); !errors.Is(err, ErrSLMAbandoned) {
				t.Errorf("unserved work hidden: %v", err)
			}
		}()
	}
	wg.Wait()
	if p.Stats().SLMAbandoned != 1 {
		t.Fatalf("abandoned count: %+v", p.Stats())
	}
	if _, ok := <-p.SLMQueue(); ok {
		t.Fatal("closed queue not drained")
	}
	q, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res, err := q.EvaluatePacket(nominal, 100); err != nil || res.Decision != DecisionFastPass {
		t.Fatal("fresh lifecycle failed")
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCorrectionDNSAuditErrorsAndRecovery(t *testing.T) {
	// /dev/full is a real failing writer, not an injected success/failure flag.
	p, err := NewPipeline(PipelineConfig{LogPath: "/dev/full"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = p.logEvent("fixture.test", "TEST", "private fixture", 0)
	if err := p.Close(); err == nil {
		t.Fatal("audit failure hidden by Close")
	}
	if p.Stats().AuditErrors == 0 || p.AuditError() == nil {
		t.Fatal("audit failure counter missing")
	}
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	q, err := NewPipeline(PipelineConfig{LogPath: path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.logEvent("fixture.test", "RECOVERED", "private fixture", 0); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(data, []byte("RECOVERED")) || bytes.Count(data, []byte{'\n'}) != 1 {
		t.Fatalf("audit recovery: %s %v", data, err)
	}
	// Isolate the bounded producer from disk/encoder allocation in a private queue.
	isolated := &Pipeline{auditQueue: make(chan auditRecord, 1)}
	if err := isolated.logEvent("fixture.test", "TEST", "fixture", 0); err != nil {
		t.Fatal(err)
	}
	if err := isolated.logEvent("fixture.test", "TEST", "fixture", 0); !errors.Is(err, ErrAuditQueueFull) {
		t.Fatal("audit saturation hidden")
	}
	if isolated.auditRejected.Load() != 1 {
		t.Fatal("audit loss counter")
	}
	<-isolated.auditQueue
	_ = isolated.logEvent("fixture.test", "RECOVERY", "fixture", 0)
	if (<-isolated.auditQueue).Action != "RECOVERY" {
		t.Fatal("audit enqueue did not recover")
	}
	if n := testing.AllocsPerRun(100, func() { _ = isolated.logEvent("fixture.test", "TEST", "fixture", 0); <-isolated.auditQueue }); n != 0 {
		t.Fatalf("audit producer allocations: %g", n)
	}
}

func TestCorrectionDNSSyncValidationConflictProvenanceRecovery(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.txt")
	content := []byte("# private fixture\n0.0.0.0 google.com\nfixture.test\n")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	ar := NewAtomicReputation(correctionDNSTable(t, DefaultBuildEntries))
	successes := 0
	s := NewReputationSyncer(SyncerConfig{Sources: []ReputationSource{{Name: "private fixture", URI: "file://" + path, Classification: RepClassBlockC2, MatchKind: MatchSubtree}}, OnSyncSuccess: func(int) { successes++ }}, ar)
	if _, err := s.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if res, ok := ar.Match("mail.google.com"); !ok || res.Classification != RepClassBlockC2 {
		t.Fatal("seed won over source block")
	}
	proof := s.Provenance()
	digest := sha256.Sum256(content)
	if len(proof) != 1 || proof[0].SHA256 != fmt.Sprintf("%x", digest) || proof[0].Entries != 2 || proof[0].URI != "file://"+path || proof[0].FetchedAt.IsZero() {
		t.Fatalf("missing provenance: %+v", proof)
	}
	proof[0].SHA256 = "caller mutation"
	if s.Provenance()[0].SHA256 == proof[0].SHA256 {
		t.Fatal("borrowed provenance")
	}
	for _, bad := range []string{"https://bad.test/path\n", "a..test\n", "0.0.0.0 valid.test garbage\n", strings.Repeat("a", 64) + ".test\n"} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := s.SyncOnce(context.Background()); err == nil {
			t.Fatalf("invalid source accepted: %q", bad)
		}
		if res, ok := ar.Match("mail.google.com"); !ok || res.Classification != RepClassBlockC2 {
			t.Fatal("source error lost active deny")
		}
		if successes != 1 || s.Provenance()[0].Error == "" {
			t.Fatal("degraded sync reported success")
		}
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SyncOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if successes != 2 || s.Provenance()[0].SHA256 != fmt.Sprintf("%x", digest) {
		t.Fatal("source did not recover")
	}
	empty := NewReputationSyncer(SyncerConfig{}, ar)
	before := ar.Load()
	if _, err := empty.SyncOnce(context.Background()); err == nil || ar.Load() != before {
		t.Fatal("no-source sync pretended to update")
	}
}

func BenchmarkCorrectionDNSPaths(b *testing.B) {
	for _, name := range []string{"www.google.com", "x.bad-exfil-test.xyz"} {
		b.Run(name, func(b *testing.B) {
			p, err := NewPipeline(PipelineConfig{}, nil)
			if err != nil {
				b.Fatal(err)
			}
			defer p.Close()
			wire := buildDNSQueryWire(name, TypeA)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := p.EvaluatePacket(wire, 100); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
