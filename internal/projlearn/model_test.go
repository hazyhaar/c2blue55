package projlearn_test

import (
	"math"
	"math/bits"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/projlearn"
)

func contractShapes(cfg projlearn.Config) (embedN, convWN, convBN, dense1WN, dense1BN, dense2WN, dense2BN, readoutWN, readoutBN int) {
	embedN = 256 * cfg.EmbedDim
	convWN = cfg.ConvOut * cfg.Kernel * cfg.EmbedDim
	convBN = cfg.ConvOut
	dense1WN = cfg.Hidden * (cfg.ConvOut + cfg.StructFeatures)
	dense1BN = cfg.Hidden
	dense2WN = cfg.CodeBits * cfg.Hidden
	dense2BN = cfg.CodeBits
	readoutWN = cfg.CodeBits
	readoutBN = 1
	return
}

func requireShapes(t *testing.T, p *projlearn.Params, cfg projlearn.Config) {
	t.Helper()
	if p == nil {
		t.Fatal("Params nil : écart fonctionnel, paramètres absents")
	}
	embedN, convWN, convBN, dense1WN, dense1BN, dense2WN, dense2BN, readoutWN, readoutBN := contractShapes(cfg)
	checks := []struct {
		name string
		got  int
		want int
	}{
		{"Embed", len(p.Embed), embedN},
		{"ConvW", len(p.ConvW), convWN},
		{"ConvB", len(p.ConvB), convBN},
		{"Dense1W", len(p.Dense1W), dense1WN},
		{"Dense1B", len(p.Dense1B), dense1BN},
		{"Dense2W", len(p.Dense2W), dense2WN},
		{"Dense2B", len(p.Dense2B), dense2BN},
		{"ReadoutW", len(p.ReadoutW), readoutWN},
		{"ReadoutB", len(p.ReadoutB), readoutBN},
	}
	for _, check := range checks {
		if check.got != check.want {
			t.Fatalf("%s: longueur %d, attendu %d", check.name, check.got, check.want)
		}
	}
}

func zeroLike(p *projlearn.Params) *projlearn.Params {
	return &projlearn.Params{
		Embed:    make([]float32, len(p.Embed)),
		ConvW:    make([]float32, len(p.ConvW)),
		ConvB:    make([]float32, len(p.ConvB)),
		Dense1W:  make([]float32, len(p.Dense1W)),
		Dense1B:  make([]float32, len(p.Dense1B)),
		Dense2W:  make([]float32, len(p.Dense2W)),
		Dense2B:  make([]float32, len(p.Dense2B)),
		ReadoutW: make([]float32, len(p.ReadoutW)),
		ReadoutB: make([]float32, len(p.ReadoutB)),
	}
}

func rejectNonFinite(t *testing.T, name string, slot []float32) {
	t.Helper()
	for i, x := range slot {
		if math.IsNaN(float64(x)) || math.IsInf(float64(x), 0) {
			t.Fatalf("%s[%d]=%g non fini", name, i, x)
		}
	}
}

func populationStddev(slot []float32) float64 {
	var sum float64
	for _, x := range slot {
		sum += float64(x)
	}
	mean := sum / float64(len(slot))
	var acc float64
	for _, x := range slot {
		d := float64(x) - mean
		acc += d * d
	}
	return math.Sqrt(acc / float64(len(slot)))
}

func TestForward_DeterministicAndBinarized(t *testing.T) {
	cfg := projlearn.DefaultConfig()
	if cfg.CodeBits != 512 {
		t.Fatalf("DefaultConfig.CodeBits=%d, attendu 512", cfg.CodeBits)
	}
	params := projlearn.NewParams(cfg, 7)
	requireShapes(t, params, cfg)
	ws := projlearn.NewWorkspace(cfg, 253, 64)
	if ws == nil {
		t.Fatal("NewWorkspace a rendu nil")
	}
	nameBytes := []byte("probe-6-4dxnddw7p74v4h4twfqfgtiw7ct2cpejpx7dddq.lab")
	if len(nameBytes) != 51 || nameBytes[47] != '.' || string(nameBytes[48:]) != "lab" {
		t.Fatalf("nom réel mal formé: len=%d", len(nameBytes))
	}
	ex := projlearn.Example{
		Name:   nameBytes,
		Labels: []int{0, 47, 48, 51},
		Struct: projlearn.StructFeatures(1, 4, 47, 9, false, 51),
		Label:  1,
		Family: "pound2pound.fr",
	}
	code1, hidden1, score1 := projlearn.Forward(params, cfg, &ex, ws)
	if len(hidden1) != 512 {
		t.Fatalf("len(h)=%d, attendu 512", len(hidden1))
	}
	hiddenCopy := append([]float32(nil), hidden1...)
	code2, hidden2, score2 := projlearn.Forward(params, cfg, &ex, ws)
	if code1 != code2 {
		t.Fatalf("code non déterministe: %#x puis %#x", code1, code2)
	}
	if math.Float32bits(score1) != math.Float32bits(score2) {
		t.Fatalf("score non déterministe: %g puis %g", score1, score2)
	}
	if len(hidden2) != len(hiddenCopy) {
		t.Fatalf("len(h) %d puis %d", len(hiddenCopy), len(hidden2))
	}
	for i := range hiddenCopy {
		if math.Float32bits(hiddenCopy[i]) != math.Float32bits(hidden2[i]) {
			t.Fatalf("h[%d] non déterministe", i)
		}
		if math.IsNaN(float64(hiddenCopy[i])) || hiddenCopy[i] > 1 || hiddenCopy[i] < -1 {
			t.Fatalf("h[%d]=%g hors [-1, 1]", i, hiddenCopy[i])
		}
		word := i >> 6
		bit := uint(i & 63)
		got := (code1[word] >> bit) & 1
		var want uint64
		if hiddenCopy[i] >= 0 {
			want = 1
		}
		if got != want {
			t.Fatalf("bit %d: code=%d, signe de h=%d", i, got, want)
		}
	}
	allocs := testing.AllocsPerRun(100, func() {
		projlearn.Forward(params, cfg, &ex, ws)
	})
	if allocs != 0 {
		t.Fatalf("AllocsPerRun(100, Forward)=%g, attendu 0", allocs)
	}
}

func TestNewParams_SeedAndShapes(t *testing.T) {
	cfg := projlearn.DefaultConfig()
	if cfg.EmbedDim != 16 || cfg.ConvOut != 32 || cfg.Kernel != 5 || cfg.Hidden != 128 || cfg.CodeBits != 512 || cfg.StructFeatures != 8 {
		t.Fatalf("DefaultConfig hors contrat: %+v", cfg)
	}
	first := projlearn.NewParams(cfg, 7)
	requireShapes(t, first, cfg)
	second := projlearn.NewParams(cfg, 7)
	requireShapes(t, second, cfg)
	other := projlearn.NewParams(cfg, 8)
	requireShapes(t, other, cfg)
	pairs := []struct {
		name string
		a, b []float32
	}{
		{"Embed", first.Embed, second.Embed},
		{"ConvW", first.ConvW, second.ConvW},
		{"ConvB", first.ConvB, second.ConvB},
		{"Dense1W", first.Dense1W, second.Dense1W},
		{"Dense1B", first.Dense1B, second.Dense1B},
		{"Dense2W", first.Dense2W, second.Dense2W},
		{"Dense2B", first.Dense2B, second.Dense2B},
		{"ReadoutW", first.ReadoutW, second.ReadoutW},
		{"ReadoutB", first.ReadoutB, second.ReadoutB},
	}
	for _, pair := range pairs {
		rejectNonFinite(t, pair.name, pair.a)
		for i := range pair.a {
			if math.Float32bits(pair.a[i]) != math.Float32bits(pair.b[i]) {
				t.Fatalf("même graine: %s[%d] diffère", pair.name, i)
			}
		}
	}
	sameEmbed := true
	for i := range first.Embed {
		if math.Float32bits(first.Embed[i]) != math.Float32bits(other.Embed[i]) {
			sameEmbed = false
			break
		}
	}
	if sameEmbed {
		t.Fatal("graines 7 et 8 rendent le même Embed")
	}
	std := populationStddev(first.ConvW)
	if std < 0.01 || std > 1 {
		t.Fatalf("écart-type de ConvW=%g, attendu dans [0,01, 1]", std)
	}
}

func scalarLoss(hidden []float32, score float32, direction []float32, scoreWeight float32) float64 {
	var sum float64
	for i := range hidden {
		sum += float64(hidden[i]) * float64(direction[i])
	}
	sum += float64(score) * float64(scoreWeight)
	return sum
}

func eachSlot(p *projlearn.Params, visit func(name string, slot []float32)) {
	visit("Embed", p.Embed)
	visit("ConvW", p.ConvW)
	visit("ConvB", p.ConvB)
	visit("Dense1W", p.Dense1W)
	visit("Dense1B", p.Dense1B)
	visit("Dense2W", p.Dense2W)
	visit("Dense2B", p.Dense2B)
	visit("ReadoutW", p.ReadoutW)
	visit("ReadoutB", p.ReadoutB)
}

func TestBackward_MatchesFiniteDifferences(t *testing.T) {
	cfg := projlearn.Config{EmbedDim: 2, ConvOut: 3, Kernel: 3, Hidden: 4, CodeBits: 64, StructFeatures: 8}
	params := projlearn.NewParams(cfg, 7)
	requireShapes(t, params, cfg)
	ws := projlearn.NewWorkspace(cfg, 16, 4)
	if ws == nil {
		t.Fatal("NewWorkspace a rendu nil")
	}
	nameBytes := []byte("lab")
	ex := projlearn.Example{
		Name:   nameBytes,
		Labels: []int{0, 3},
		Struct: projlearn.StructFeatures(1, 1, 3, 1, false, 3),
		Label:  1,
		Family: "lab",
	}
	direction := make([]float32, cfg.CodeBits)
	for i := range direction {
		direction[i] = float32(i%5-2) * 0.05
	}
	const scoreWeight float32 = 0.3
	_, hidden, _ := projlearn.Forward(params, cfg, &ex, ws)
	if len(hidden) != cfg.CodeBits {
		t.Fatalf("Forward: len(h)=%d, attendu %d", len(hidden), cfg.CodeBits)
	}
	grads := zeroLike(params)
	projlearn.Backward(params, cfg, &ex, ws, direction, scoreWeight, grads)
	eachSlot(params, func(name string, slot []float32) {
		var grad []float32
		switch name {
		case "Embed":
			grad = grads.Embed
		case "ConvW":
			grad = grads.ConvW
		case "ConvB":
			grad = grads.ConvB
		case "Dense1W":
			grad = grads.Dense1W
		case "Dense1B":
			grad = grads.Dense1B
		case "Dense2W":
			grad = grads.Dense2W
		case "Dense2B":
			grad = grads.Dense2B
		case "ReadoutW":
			grad = grads.ReadoutW
		case "ReadoutB":
			grad = grads.ReadoutB
		}
		if len(grad) != len(slot) {
			t.Fatalf("grads.%s longueur %d, attendu %d", name, len(grad), len(slot))
		}
	})
	present := [256]bool{}
	for _, b := range nameBytes {
		present[b] = true
	}
	for row := range 256 {
		if present[row] {
			continue
		}
		base := row * cfg.EmbedDim
		for d := 0; d < cfg.EmbedDim; d++ {
			if grads.Embed[base+d] != 0 {
				t.Fatalf("Embed reçoit un gradient sur l'octet %d absent du nom", row)
			}
		}
	}
	const eps = 1e-3
	var peak float64
	eachSlot(params, func(name string, slot []float32) {
		var grad []float32
		switch name {
		case "Embed":
			grad = grads.Embed
		case "ConvW":
			grad = grads.ConvW
		case "ConvB":
			grad = grads.ConvB
		case "Dense1W":
			grad = grads.Dense1W
		case "Dense1B":
			grad = grads.Dense1B
		case "Dense2W":
			grad = grads.Dense2W
		case "Dense2B":
			grad = grads.Dense2B
		case "ReadoutW":
			grad = grads.ReadoutW
		case "ReadoutB":
			grad = grads.ReadoutB
		}
		for i := range slot {
			orig := slot[i]
			slot[i] = float32(float64(orig) + eps)
			_, hPlus, scorePlus := projlearn.Forward(params, cfg, &ex, ws)
			if len(hPlus) != cfg.CodeBits {
				t.Fatalf("Forward perturbé: len(h)=%d", len(hPlus))
			}
			lossPlus := scalarLoss(hPlus, scorePlus, direction, scoreWeight)
			slot[i] = float32(float64(orig) - eps)
			_, hMinus, scoreMinus := projlearn.Forward(params, cfg, &ex, ws)
			if len(hMinus) != cfg.CodeBits {
				t.Fatalf("Forward perturbé: len(h)=%d", len(hMinus))
			}
			lossMinus := scalarLoss(hMinus, scoreMinus, direction, scoreWeight)
			slot[i] = orig
			numerical := (lossPlus - lossMinus) / (2 * eps)
			analytical := float64(grad[i])
			if math.Abs(numerical) > peak {
				peak = math.Abs(numerical)
			}
			gap := math.Abs(numerical - analytical)
			limit := 1e-2 * (1 + math.Abs(analytical))
			if gap > limit {
				t.Fatalf("%s[%d]: numérique=%g analytique=%g écart=%g limite=%g", name, i, numerical, analytical, gap, limit)
			}
		}
	})
	if peak < 1e-8 {
		t.Fatal("Forward insensible aux paramètres : gradient numérique nul partout")
	}
}

func clamp01(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

func nearFeature(got, want float32) bool {
	d := float64(got) - float64(want)
	if d < 0 {
		d = -d
	}
	return d <= 1e-5
}

func TestStructFeatures_Bounds(t *testing.T) {
	qtypes := []uint16{1, 16, 10, 255}
	cards := []uint32{0, 1, 2, 15, 255, 65535, 1000000}
	nameLens := []int{0, 1, 127, 253}
	for _, qtype := range qtypes {
		for labelCount := 0; labelCount <= 64; labelCount++ {
			for maxLabelLen := 0; maxLabelLen <= 63; maxLabelLen++ {
				for _, subCardinality := range cards {
					for _, encoded := range []bool{false, true} {
						for _, nameLen := range nameLens {
							got := projlearn.StructFeatures(qtype, uint8(labelCount), uint8(maxLabelLen), subCardinality, encoded, nameLen)
							want := expectedStruct(qtype, labelCount, maxLabelLen, subCardinality, encoded, nameLen)
							for i := range got {
								if got[i] < 0 || got[i] > 1 || math.IsNaN(float64(got[i])) {
									t.Fatalf("Struct[%d]=%g hors [0, 1] pour qtype=%d labelCount=%d maxLabelLen=%d sub=%d encoded=%v nameLen=%d", i, got[i], qtype, labelCount, maxLabelLen, subCardinality, encoded, nameLen)
								}
								if !nearFeature(got[i], want[i]) {
									t.Fatalf("Struct[%d]=%g, attendu %g (qtype=%d labelCount=%d maxLabelLen=%d sub=%d encoded=%v nameLen=%d)", i, got[i], want[i], qtype, labelCount, maxLabelLen, subCardinality, encoded, nameLen)
								}
							}
						}
					}
				}
			}
		}
	}
	var previous float32 = -1
	for _, subCardinality := range []uint32{0, 1, 2, 3, 7, 15, 31, 63, 127, 255, 1023, 4095, 65535, 100000, 1000000} {
		got := projlearn.StructFeatures(1, 4, 8, subCardinality, false, 12)
		if got[3] < previous {
			t.Fatalf("Struct[3] non monotone: subCardinality=%d valeur=%g précédente=%g", subCardinality, got[3], previous)
		}
		previous = got[3]
	}
}

// expectedStruct lit la signature du registre : QType/255, LabelCount/16,
// MaxLabelLen/64, log2(SubCardinality+1)/16, Encoded, len/253, 0, 0.
// Les composantes qui dépassent 1 sur les plages exigées sont saturées,
// sinon le vecteur sortirait de [0, 1].
func expectedStruct(qtype uint16, labelCount, maxLabelLen int, subCardinality uint32, encoded bool, nameLen int) [8]float32 {
	var encodedBit float64
	if encoded {
		encodedBit = 1
	}
	return [8]float32{
		float32(clamp01(float64(qtype) / 255)),
		float32(clamp01(float64(labelCount) / 16)),
		float32(clamp01(float64(maxLabelLen) / 64)),
		float32(clamp01(math.Log2(float64(subCardinality)+1) / 16)),
		float32(encodedBit),
		float32(clamp01(float64(nameLen) / 253)),
		0,
		0,
	}
}

// Référence PCG XSL RR 128/64 (pcg-random.org, pcg_setseq_128_xsl_rr_64).
// Multiplicateur 2549297995355413924<<64 | 4865540595714422341.
// Amorçage pcg_setseq_128_srandom(initstate=seed, initseq=0) : état nul,
// incrément 1, un pas, ajout de la graine, un pas. Chaque tirage avance
// puis rend la rotation droite de (haut xor bas), de (état >> 122) bits.
// Les trois premières sorties de la graine 42 sont celles de gcc -O2.

type u128 struct {
	hi uint64
	lo uint64
}

func mul128(a, b u128) u128 {
	hi, lo := bits.Mul64(a.lo, b.lo)
	_, crossHiLo := bits.Mul64(a.hi, b.lo)
	_, crossLoHi := bits.Mul64(a.lo, b.hi)
	return u128{hi: hi + crossHiLo + crossLoHi, lo: lo}
}

func add128(a, b u128) u128 {
	lo, carry := bits.Add64(a.lo, b.lo, 0)
	hi, _ := bits.Add64(a.hi, b.hi, carry)
	return u128{hi: hi, lo: lo}
}

func xslRR(state u128) uint64 {
	rot := int(state.hi >> 58)
	xsl := state.hi ^ state.lo
	return bits.RotateLeft64(xsl, -rot)
}

type refPCG struct {
	state u128
	inc   u128
	mult  u128
}

func (g *refPCG) step() {
	g.state = add128(mul128(g.state, g.mult), g.inc)
}

func newRefPCG(seed uint64) *refPCG {
	g := &refPCG{
		inc:  u128{lo: 1},
		mult: u128{hi: 2549297995355413924, lo: 4865540595714422341},
	}
	g.step()
	g.state = add128(g.state, u128{lo: seed})
	g.step()
	return g
}

func (g *refPCG) Uint64() uint64 {
	g.step()
	return xslRR(g.state)
}

func TestPCG64_KnownSequence(t *testing.T) {
	ref := newRefPCG(42)
	official := [3]uint64{4540806433264105130, 7249376888367367666, 1981322806045522308}
	for i := range official {
		if got := ref.Uint64(); got != official[i] {
			t.Fatalf("référence interne incohérente au tirage %d: %d, attendu %d", i, got, official[i])
		}
	}
	rng := projlearn.NewPCG64(42)
	if rng == nil {
		t.Fatal("NewPCG64 a rendu nil")
	}
	for i := range official {
		if got := rng.Uint64(); got != official[i] {
			t.Fatalf("NewPCG64(42) tirage %d = %d, attendu %d", i, got, official[i])
		}
	}
	left := projlearn.NewPCG64(42)
	right := projlearn.NewPCG64(42)
	if left == nil || right == nil {
		t.Fatal("NewPCG64 a rendu nil")
	}
	for i := range 32 {
		if left.Uint64() != right.Uint64() {
			t.Fatalf("même graine, tirage %d différent", i)
		}
	}
	seedA := projlearn.NewPCG64(42)
	seedB := projlearn.NewPCG64(43)
	if seedA == nil || seedB == nil {
		t.Fatal("NewPCG64 a rendu nil")
	}
	identical := true
	for range 8 {
		if seedA.Uint64() != seedB.Uint64() {
			identical = false
			break
		}
	}
	if identical {
		t.Fatal("graines 42 et 43 rendent la même séquence")
	}
	period := projlearn.NewPCG64(42)
	if period == nil {
		t.Fatal("NewPCG64 a rendu nil")
	}
	const draws = 100000
	seen := make(map[uint64]int, draws)
	for i := range draws {
		x := period.Uint64()
		if prev, ok := seen[x]; ok {
			t.Fatalf("période courte: valeur répétée au tirage %d (déjà au tirage %d)", i, prev)
		}
		seen[x] = i
	}
}
