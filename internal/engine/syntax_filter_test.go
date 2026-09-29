package engine

import (
	"math"
	"strings"
	"testing"
)

// normalizeWindow applique NormalizeCodeWindow et rend le résultat sous forme
// de chaîne, avec un tampon de capacité strictement égale à la source.
func normalizeWindow(src string) string {
	in := []byte(src)
	out := make([]byte, len(in))
	n := NormalizeCodeWindow(in, out)
	return string(out[:n])
}

func TestNormalizeCodeWindow_Comments(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "fin-de-ligne-slash",
			in:   "int x = 1; // commentaire\nint y = 2;",
			want: "int x = 1; int y = 2;",
		},
		{
			name: "fin-de-ligne-diese",
			in:   "x := 1 # commentaire\ny := 2",
			want: "x := 1 y := 2",
		},
		{
			name: "multi-lignes",
			in:   "a /* bloc\nsur deux lignes */ b",
			want: "a b",
		},
		{
			name: "chaine-double-preservee",
			in:   `const s = "// pas un commentaire"`,
			want: `const s = "// pas un commentaire"`,
		},
		{
			name: "bloc-dans-chaine",
			in:   `const s = "/* texte */"`,
			want: `const s = "/* texte */"`,
		},
		{
			name: "chaine-simple-et-diese",
			in:   `a := '#' + "#define"`,
			want: `a := '#' + "#define"`,
		},
		{
			name: "chaine-echappee",
			in:   `s := "a \" // b"`,
			want: `s := "a \" // b"`,
		},
		{
			name: "bloc-non-ferme",
			in:   "int a; /* ouvert\nint b;",
			want: "int a; ",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeWindow(tc.in); got != tc.want {
				t.Fatalf("normalisation divergente:\n  entrée %q\n  obtenu %q\n  attendu %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeCodeWindow_WhitespaceCollapse(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "tabulation-retour-saut-espaces", in: "int\t\r\n   x", want: "int x"},
		{name: "sequence-seule", in: "\t\r\n   ", want: " "},
		{name: "espaces-multiples", in: "a \t  b", want: "a b"},
		{name: "deja-normalise", in: "int x", want: "int x"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeWindow(tc.in); got != tc.want {
				t.Fatalf("effondrement divergent:\n  entrée %q\n  obtenu %q\n  attendu %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCalculateShannonEntropy(t *testing.T) {
	if h := CalculateShannonEntropy(nil); h != 0.0 {
		t.Fatalf("entrée vide: H = %v, attendu 0", h)
	}

	zero := make([]byte, 256)
	if h := CalculateShannonEntropy(zero); h != 0.0 {
		t.Fatalf("octet unique répété: H = %v, attendu 0", h)
	}

	uniform := make([]byte, 256)
	for i := range uniform {
		uniform[i] = byte(i)
	}
	h := CalculateShannonEntropy(uniform)
	if math.Abs(h-8.0) > 0.001 {
		t.Fatalf("distribution uniforme 256 octets: H = %v, attendu 8.0 ± 0.001", h)
	}

	code := []byte("#include <stdio.h>\nint main(void){const char *m=\"hello\";printf(\"%s\\n\",m);return 0;}")
	hc := CalculateShannonEntropy(code)
	if hc < 3.5 || hc > 5.5 {
		t.Fatalf("code C ordinaire: H = %v, attendu dans [3.5, 5.5]", hc)
	}
}

func TestCalculateEntropyQ8(t *testing.T) {
	if q8 := CalculateEntropyQ8(nil); q8 != 0 {
		t.Fatalf("entrée vide: Q8 = %v, attendu 0", q8)
	}

	zero := make([]byte, 256)
	if q8 := CalculateEntropyQ8(zero); q8 != 0 {
		t.Fatalf("octet unique répété: Q8 = %v, attendu 0", q8)
	}

	uniform := make([]byte, 256)
	for i := range uniform {
		uniform[i] = byte(i)
	}
	q8 := CalculateEntropyQ8(uniform)
	if q8 != 2048 {
		t.Fatalf("distribution uniforme 256 octets: Q8 = %v, attendu 2048 (8.0 * 256)", q8)
	}
}

func TestIsBoilerplateOrLowEntropy_V8Autopsy(t *testing.T) {
	banner := "// " + strings.Repeat("=", 66)
	if !IsBoilerplateOrLowEntropy([]byte(banner), DefaultMinEntropy) {
		t.Fatalf("bannière V8 non élaguée: %q", banner)
	}

	alignment := strings.Repeat(" ", 78)
	if !IsBoilerplateOrLowEntropy([]byte(alignment), DefaultMinEntropy) {
		t.Fatalf("alignement de 78 espaces non élagué")
	}

	if !IsBoilerplateOrLowEntropy(nil, DefaultMinEntropy) {
		t.Fatal("bloc vide non élagué")
	}

	real := []byte(`EVAL "package.loadlib('/usr/lib/liblua5.1.so','luaopen_io')"`)
	if IsBoilerplateOrLowEntropy(real, DefaultMinEntropy) {
		t.Fatalf("code vulnérable réel élagué à tort: %q", real)
	}

	gadget := []byte("pop rdi; ret; 48 8b 05 12 34 56 78; jmp rax; mov rsi, rsp; syscall")
	if IsBoilerplateOrLowEntropy(gadget, DefaultMinEntropy) {
		t.Fatalf("gadget ROP élagué à tort: %q", gadget)
	}

	separators := []byte(strings.Repeat("-", 200))
	if !IsBoilerplateOrLowEntropy(separators, DefaultMinEntropy) {
		t.Fatal("séparateurs '-' non élagués")
	}
}

func TestNormalizeCodeWindowZeroAlloc(t *testing.T) {
	src := []byte("int x = 1; // commentaire\n\tconst char *s = \"a/*b*/\";\n")
	dst := make([]byte, len(src))
	if n := testing.AllocsPerRun(1000, func() {
		_ = NormalizeCodeWindow(src, dst)
	}); n != 0 {
		t.Fatalf("NormalizeCodeWindow alloue %v objets par appel", n)
	}
	if n := testing.AllocsPerRun(1000, func() {
		_ = CalculateShannonEntropy(src)
	}); n != 0 {
		t.Fatalf("CalculateShannonEntropy alloue %v objets par appel", n)
	}
}

func BenchmarkNormalizeCodeWindow(b *testing.B) {
	line := "int x = 1; // commentaire\n\tconst char *s = \"a/*b*/\";\n"
	src := []byte(strings.Repeat(line, 64))
	dst := make([]byte, len(src))

	b.ReportAllocs()
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = NormalizeCodeWindow(src, dst)
	}
}
