package engine

import (
	"math"
	"math/bits"
	"math/rand/v2"
	"testing"
)

// refDistance512 est l'oracle exact : il rejoue la formule de
// horosvec/rabitq.go (rabitqDistanceAsym avec centroïde nul) sans aucune
// quantification de la requête. BitProductScalar doit coïncider avec lui dès
// que la requête est représentable exactement sur la grille de 32 niveaux.
func refDistance512(queryCentered []float64, code [rabitqWords512]uint64, storedSqNorm, storedL1Norm float64) float64 {
	if storedL1Norm == 0 {
		return storedSqNorm
	}
	var querySqNorm, signDot float64
	for i := 0; i < rabitqDim512; i++ {
		v := queryCentered[i]
		querySqNorm += v * v
		if code[i>>6]&(1<<(uint(i)&63)) != 0 {
			signDot += v
		} else {
			signDot -= v
		}
	}
	return querySqNorm + storedSqNorm - 2.0*storedSqNorm*signDot/storedL1Norm
}

func checkCodeBits512(t *testing.T, vec []float32, code [rabitqWords512]uint64) {
	t.Helper()
	for i := 0; i < rabitqDim512; i++ {
		want := vec[i] >= 0
		got := code[i>>6]&(1<<(uint(i)&63)) != 0
		if got != want {
			t.Fatalf("bit %d: got %v want %v (composante %g)", i, got, want, vec[i])
		}
	}
}

func TestEncode512SignsAndNorms(t *testing.T) {
	vec := make([]float32, rabitqDim512)
	var wantSq, wantL1 float64
	for i := range vec {
		v := float32(i) - 256.5
		vec[i] = v
		c := float64(v)
		wantSq += c * c
		if c >= 0 {
			wantL1 += c
		} else {
			wantL1 -= c
		}
	}

	var code [rabitqWords512]uint64
	gotSq, gotL1 := Encode512(vec, &code)

	if gotSq != wantSq {
		t.Fatalf("norme L2²: got %g want %g", gotSq, wantSq)
	}
	if gotL1 != wantL1 {
		t.Fatalf("norme L1: got %g want %g", gotL1, wantL1)
	}
	checkCodeBits512(t, vec, code)
}

func TestEncode512FillsExactlyEightWords(t *testing.T) {
	var code [rabitqWords512]uint64
	vec := make([]float32, rabitqDim512)
	for i := range vec {
		vec[i] = 1
	}
	Encode512(vec, &code)
	if code != [rabitqWords512]uint64{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)} {
		t.Fatalf("toutes les composantes positives doivent remplir les 64 octets: %016x", code)
	}

	var over [rabitqWords512]uint64
	Encode512(make([]float32, rabitqDim512+64), &over)
	if over != code {
		t.Fatal("les dimensions au-delà de 512 ne doivent pas être encodées")
	}
}

func gridQuery512(rng *rand.Rand) ([]float64, float64) {
	const levels = 32
	const vMin, vMax = -1.0, 1.0
	delta := (vMax - vMin) / float64(levels-1)
	q := make([]float64, rabitqDim512)
	for i := range q {
		q[i] = vMin + float64(rng.IntN(levels))*delta
	}
	q[0], q[1] = vMin, vMax
	var sq float64
	for _, v := range q {
		sq += v * v
	}
	return q, sq
}

func randomStored512(rng *rand.Rand) ([]float32, [rabitqWords512]uint64, float64, float64) {
	stored := make([]float32, rabitqDim512)
	for i := range stored {
		stored[i] = float32(rng.NormFloat64())
	}
	var code [rabitqWords512]uint64
	sq, l1 := Encode512(stored, &code)
	return stored, code, sq, l1
}

func TestBitProductScalarExactOnGrid(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x524142495451, 512))
	for trial := 0; trial < 64; trial++ {
		_, code, storedSq, storedL1 := randomStored512(rng)
		query, querySq := gridQuery512(rng)

		want := refDistance512(query, code, storedSq, storedL1)

		var qp QueryPlanes512
		prepareQueryPlanes(query, &qp)
		got := BitProductScalar(&qp, querySq, &code, storedSq, storedL1)

		if math.Abs(got-want) > 1e-6 {
			t.Fatalf("essai %d: BitProductScalar=%g oracle=%g écart=%g", trial, got, want, got-want)
		}
	}
}

func TestBitProductScalarConstantQueryExact(t *testing.T) {
	rng := rand.New(rand.NewPCG(0xC057A27, 512))
	_, code, storedSq, storedL1 := randomStored512(rng)

	query := make([]float64, rabitqDim512)
	for i := range query {
		query[i] = 0.375
	}
	var querySq float64
	for _, v := range query {
		querySq += v * v
	}

	want := refDistance512(query, code, storedSq, storedL1)

	var qp QueryPlanes512
	prepareQueryPlanes(query, &qp)
	if qp.Delta != 1 {
		t.Fatalf("requête constante: pas de quantification attendu 1, obtenu %g", qp.Delta)
	}
	got := BitProductScalar(&qp, querySq, &code, storedSq, storedL1)
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("requête constante: BitProductScalar=%g oracle=%g", got, want)
	}
}

func TestBitProductScalarZeroL1(t *testing.T) {
	var code [rabitqWords512]uint64
	var qp QueryPlanes512
	got := BitProductScalar(&qp, 3.0, &code, 2.5, 0)
	if got != 2.5 {
		t.Fatalf("L1 nul: got %g want storedSqNorm 2.5", got)
	}
}

func TestBitProductScalarApproachesOracle(t *testing.T) {
	rng := rand.New(rand.NewPCG(0xA990C1, 512))
	for trial := 0; trial < 32; trial++ {
		_, code, storedSq, storedL1 := randomStored512(rng)
		query := make([]float64, rabitqDim512)
		var querySq float64
		for i := range query {
			query[i] = rng.NormFloat64()
			querySq += query[i] * query[i]
		}

		want := refDistance512(query, code, storedSq, storedL1)

		var qp QueryPlanes512
		prepareQueryPlanes(query, &qp)
		got := BitProductScalar(&qp, querySq, &code, storedSq, storedL1)

		tol := 0.1 * (math.Abs(storedSq) + math.Abs(querySq) + 1)
		if math.Abs(got-want) > tol {
			t.Fatalf("essai %d: écart %g supérieur à la tolérance %g (got=%g want=%g)", trial, math.Abs(got-want), tol, got, want)
		}
	}
}

func TestRabitq512ZeroAllocation(t *testing.T) {
	rng := rand.New(rand.NewPCG(0x0A110C, 512))
	stored := make([]float32, rabitqDim512)
	for i := range stored {
		stored[i] = float32(rng.NormFloat64())
	}
	query := make([]float64, rabitqDim512)
	for i := range query {
		query[i] = rng.NormFloat64()
	}

	var code [rabitqWords512]uint64
	var qp QueryPlanes512
	var sq, l1 float64

	if n := testing.AllocsPerRun(200, func() {
		sq, l1 = Encode512(stored, &code)
	}); n != 0 {
		t.Fatalf("Encode512 alloue %v objets par appel", n)
	}

	if n := testing.AllocsPerRun(200, func() {
		prepareQueryPlanes(query, &qp)
	}); n != 0 {
		t.Fatalf("prepareQueryPlanes alloue %v objets par appel", n)
	}

	prepareQueryPlanes(query, &qp)
	if n := testing.AllocsPerRun(200, func() {
		_ = BitProductScalar(&qp, 1.0, &code, sq, l1)
	}); n != 0 {
		t.Fatalf("BitProductScalar alloue %v objets par appel", n)
	}
}

func BenchmarkBitProductScalar512(b *testing.B) {
	rng := rand.New(rand.NewPCG(0xBE0C, 512))
	stored := make([]float32, rabitqDim512)
	for i := range stored {
		stored[i] = float32(rng.NormFloat64())
	}
	query := make([]float64, rabitqDim512)
	var querySq float64
	for i := range query {
		query[i] = rng.NormFloat64()
		querySq += query[i] * query[i]
	}

	var code [rabitqWords512]uint64
	storedSq, storedL1 := Encode512(stored, &code)
	var qp QueryPlanes512
	prepareQueryPlanes(query, &qp)

	var sink float64
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sink += BitProductScalar(&qp, querySq, &code, storedSq, storedL1)
	}
	_ = sink
}

func BenchmarkEncode512(b *testing.B) {
	vec := make([]float32, rabitqDim512)
	for i := range vec {
		vec[i] = float32(i) - 256
	}
	var code [rabitqWords512]uint64
	var sink float64
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sq, l1 := Encode512(vec, &code)
		sink += sq + l1
	}
	_ = sink
}

// sylvesterHadamardOracle calcule la transformée de Walsh-Hadamard orthonormée par
// produit matriciel direct O(N^2) H[i,j] = (-1)^popcount(i & j) / sqrt(512),
// sans transformée rapide papillon, servant d'oracle mathématique indépendant.
func sylvesterHadamardOracle(vec []float32) ([codebookWords]uint64, float64, float64) {
	const N = 512
	const invSqrtN = float32(0.04419417382415922) // 1 / sqrt(512)
	const seed uint64 = 0x9E3779B97F4A7C15

	// Signes déterministes de Rademacher (splitmix64)
	var signs [N]float32
	z := seed
	for i := range signs {
		z += seed
		v := z
		v = (v ^ (v >> 30)) * 0xBF58476D1CE4E5B9
		v = (v ^ (v >> 27)) * 0x94D049BB133111EB
		v ^= v >> 31
		if v&1 == 0 {
			signs[i] = 1
		} else {
			signs[i] = -1
		}
	}

	// Entrée pondérée et complétée par des zéros
	var signedInput [N]float32
	for i := 0; i < N && i < len(vec); i++ {
		signedInput[i] = vec[i] * signs[i]
	}

	// Produit matriciel direct de Sylvester H_512
	var proj [N]float32
	for i := 0; i < N; i++ {
		var sum float32
		for j := 0; j < N; j++ {
			if bits.OnesCount(uint(i&j))%2 == 0 {
				sum += signedInput[j]
			} else {
				sum -= signedInput[j]
			}
		}
		proj[i] = sum * invSqrtN
	}

	// Quantification par centrage sur la moyenne arithmétique
	var mean float32
	for i := 0; i < N; i++ {
		mean += proj[i]
	}
	mean /= float32(N)

	var code [codebookWords]uint64
	var l1, l2 float32
	for w := 0; w < codebookWords; w++ {
		base := w * 64
		for b := 0; b < 64; b++ {
			c := proj[base+b] - mean
			if c >= 0 {
				code[w] |= uint64(1) << uint(b)
				l1 += c
			} else {
				l1 -= c
			}
			l2 += c * c
		}
	}
	return code, float64(l2), float64(l1)
}

func TestQuantizeFHT512_Harmonization(t *testing.T) {
	vec := make([]float32, rabitqDim512)
	for i := range vec {
		vec[i] = float32(i%17) - 8.0
	}

	var codeFHT [codebookWords]uint64
	sq, l1 := QuantizeFHT512(vec, &codeFHT)
	if sq <= 0 || l1 <= 0 {
		t.Fatalf("QuantizeFHT512 a renvoyé des normes non positives: sq=%g, l1=%g", sq, l1)
	}

	// Vérification bit-à-bit contre l'oracle mathématique indépendant (Sylvester O(N^2))
	oracleCode, oracleSq, oracleL1 := sylvesterHadamardOracle(vec)
	for w := 0; w < codebookWords; w++ {
		if codeFHT[w] != oracleCode[w] {
			t.Fatalf("mot %d discordant avec l'oracle Sylvester: codeFHT=%016x oracle=%016x", w, codeFHT[w], oracleCode[w])
		}
	}
	if math.Abs(sq-oracleSq) > 1e-3 {
		t.Fatalf("norme sq discordante: codeFHT=%g oracle=%g", sq, oracleSq)
	}
	if math.Abs(l1-oracleL1) > 1e-3 {
		t.Fatalf("norme l1 discordante: codeFHT=%g oracle=%g", l1, oracleL1)
	}

	// Vecteur d'or scellé (golden vector) pour garantir l'absence de régression temporelle
	goldenWords := [codebookWords]uint64{
		0xd6d3d07689d6891f,
		0x49a315fe7364811b,
		0x3974ecdcc5998f9c,
		0xff1de80f2c529b16,
		0x15c5ce5d5102fe52,
		0x4538249decb40abb,
		0x86505cea0351f978,
		0x5860fd24209ea3eb,
	}
	for w := 0; w < codebookWords; w++ {
		if codeFHT[w] != goldenWords[w] {
			t.Fatalf("mot %d discordant avec le vecteur d'or: codeFHT=%016x golden=%016x", w, codeFHT[w], goldenWords[w])
		}
	}

	// Le code doit avoir des bits non triviaux
	hasOnes := false
	hasZeros := false
	for _, word := range codeFHT {
		if word != 0 {
			hasOnes = true
		}
		if word != ^uint64(0) {
			hasZeros = true
		}
	}
	if !hasOnes || !hasZeros {
		t.Fatalf("QuantizeFHT512 a produit un bitcode dégénéré")
	}

	var codeMean [codebookWords]uint64
	sqMean, l1Mean := QuantizeMeanCentered512(vec, &codeMean)
	if sqMean <= 0 || l1Mean <= 0 {
		t.Fatalf("QuantizeMeanCentered512 a renvoyé des normes non positives")
	}
}
