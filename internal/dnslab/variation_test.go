package dnslab_test

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

const variationParent = "t"

func TestGenerateVariationNames_Bounds(t *testing.T) {
	benign := benignLabNames(t)
	suffix := "." + variationParent + "." + zoneApex
	alphabets := []string{"base32", "base64", "hex", "base128"}
	labelLens := []int{8, 32, 63}
	labelCounts := []int{1, 2, 4}
	dilutions := []int{0, 3}
	for _, alphabet := range alphabets {
		for _, labelLen := range labelLens {
			for _, labels := range labelCounts {
				for _, dilution := range dilutions {
					name := alphabet + "/len" + itoa(labelLen) + "/labels" + itoa(labels) + "/dil" + itoa(dilution)
					t.Run(name, func(t *testing.T) {
						varied := referenceVariation()
						varied.Alphabet = alphabet
						varied.LabelLen = labelLen
						varied.Labels = labels
						varied.Dilution = dilution
						left := generateNames(t, varied, 100, 11)
						right := generateNames(t, varied, 100, 11)
						other := generateNames(t, varied, 100, 12)
						if !slices.Equal(left, right) {
							t.Fatalf("graine 11: deux appels diffèrent")
						}
						if slices.Equal(left, other) {
							t.Fatal("graines 11 et 12 rendent les mêmes noms")
						}
						assertVariationBatch(t, left, suffix, alphabet, labelLen, labels, dilution, benign)
					})
				}
			}
		}
	}
}

func TestGenerateVariationNames_Refusals(t *testing.T) {
	base := referenceVariation()
	cases := []struct {
		name string
		edit func(*dnslab.Variation)
		n    int
	}{
		{"parent_evil_example", func(v *dnslab.Variation) { v.Parent = "evil.example" }, 4},
		{"parent_vide", func(v *dnslab.Variation) { v.Parent = "" }, 4},
		{"parent_point", func(v *dnslab.Variation) { v.Parent = "." }, 4},
		{"cadence_500", func(v *dnslab.Variation) { v.Cadence = 500 }, 4},
		{"label_64", func(v *dnslab.Variation) { v.LabelLen = 64 }, 4},
		{"labels_5", func(v *dnslab.Variation) { v.Labels = 5 }, 4},
		{"alphabet_inconnu", func(v *dnslab.Variation) { v.Alphabet = "base36" }, 4},
		{"zero_noms", func(*dnslab.Variation) {}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			varied := base
			tc.edit(&varied)
			_, err := dnslab.GenerateVariationNames(varied, zoneApex, tc.n, dnslab.NewSeededBytes(1))
			if !errors.Is(err, dnslab.ErrVariationContract) {
				t.Fatalf("GenerateVariationNames: %v, attendu ErrVariationContract", err)
			}
		})
	}

	t.Run("jumeau_valide", func(t *testing.T) {
		names, err := dnslab.GenerateVariationNames(base, zoneApex, 8, dnslab.NewSeededBytes(3))
		if err != nil {
			t.Fatalf("variation valide: %v", err)
		}
		if len(names) == 0 {
			t.Fatal("variation valide: aucun nom")
		}
		campaign := replayCampaign(names, base.Cadence)
		if err := campaign.Validate(); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})

	t.Run("validate_cadence_500", func(t *testing.T) {
		campaign := replayCampaign([]string{"a." + zoneApex}, 500)
		if err := campaign.Validate(); !errors.Is(err, dnslab.ErrCampaignContract) {
			t.Fatalf("Validate cadence 500: %v", err)
		}
	})

	t.Run("validate_nom_tiers", func(t *testing.T) {
		campaign := replayCampaign([]string{"a.evil.example"}, 10)
		if err := campaign.Validate(); !errors.Is(err, dnslab.ErrCampaignContract) {
			t.Fatalf("Validate nom tiers: %v", err)
		}
	})
}

func TestSeededBytes_Deterministic(t *testing.T) {
	const draws = 1000
	left := collectSeed(42, draws)
	right := collectSeed(42, draws)
	if !slices.Equal(left, right) {
		t.Fatalf("graine 42: deux générateurs diffèrent")
	}
	seedZero := collectSeed(0, draws)
	seedOne := collectSeed(1, draws)
	if slices.Equal(seedZero, seedOne) {
		t.Errorf("graine 0 et graine 1 rendent la même suite de %d octets", draws)
	}
	seen := make([]bool, 256)
	wide := dnslab.NewSeededBytes(7)
	const span = 100000
	for range span {
		seen[wide.Next()] = true
	}
	missing := 0
	first := -1
	for octet := range 256 {
		if !seen[octet] {
			if first < 0 {
				first = octet
			}
			missing++
		}
	}
	if missing != 0 {
		t.Errorf("%d octets absents sur %d tirages, premier %#x", missing, span, first)
	}
}

func referenceVariation() dnslab.Variation {
	return dnslab.Variation{
		Alphabet: "base32",
		LabelLen: 32,
		Labels:   2,
		QType:    16,
		Cadence:  10,
		Dilution: 0,
		Parent:   variationParent,
	}
}

func replayCampaign(names []string, cadence uint32) dnslab.Campaign {
	return dnslab.Campaign{
		RunID:    "s07-variation-valide",
		Family:   "redhost-replay",
		Tool:     "replay",
		Server:   "10.55.0.1",
		Zone:     zoneApex,
		Duration: time.Second,
		MaxQPS:   cadence,
		Names:    names,
	}
}

func generateNames(t *testing.T, varied dnslab.Variation, n int, seed uint64) []string {
	t.Helper()
	names, err := dnslab.GenerateVariationNames(varied, zoneApex, n, dnslab.NewSeededBytes(seed))
	if err != nil {
		t.Fatalf("GenerateVariationNames: %v", err)
	}
	return names
}

func assertVariationBatch(t *testing.T, names []string, suffix, alphabet string, labelLen, labels, dilution int, benign []string) {
	t.Helper()
	if len(names) != 100 {
		t.Fatalf("len = %d, attendu 100", len(names))
	}
	variedN := 0
	benignN := 0
	for _, name := range names {
		if len(name) > 253 {
			t.Errorf("nom de %d octets, plafond 253: %q", len(name), name)
		}
		if !strings.HasSuffix(name, suffix) {
			t.Errorf("nom %q non suffixé %s", name, suffix)
		}
		if recognizableBenignName(name, suffix, benign) {
			benignN++
			continue
		}
		if !variationName(name, suffix, alphabet, labelLen, labels) {
			t.Errorf("nom ni varié ni bénin reconnaissable: %q", name)
			continue
		}
		variedN++
	}
	if dilution == 0 {
		if benignN != 0 || variedN != 100 {
			t.Errorf("Dilution 0: %d variés et %d bénins, attendu 100 et 0", variedN, benignN)
		}
		return
	}
	if benignN != 3*variedN || variedN == 0 {
		t.Errorf("Dilution 3: %d bénins pour %d variés, attendu 3 pour 1", benignN, variedN)
	}
}

func variationName(name, suffix, alphabet string, labelLen, labels int) bool {
	if !strings.HasSuffix(name, suffix) || len(name) > 253 {
		return false
	}
	head := strings.TrimSuffix(name, suffix)
	if head == "" || strings.HasSuffix(head, ".") {
		return false
	}
	parts := strings.Split(head, ".")
	untruncated := labels*labelLen + labels - 1 + len(suffix)
	if untruncated <= 253 {
		if len(parts) != labels {
			return false
		}
		for _, part := range parts {
			if len(part) != labelLen || !labelInAlphabet(part, alphabet) {
				return false
			}
		}
		return true
	}
	if len(parts) == 0 || len(parts) > labels {
		return false
	}
	for _, part := range parts {
		if len(part) == 0 || len(part) > labelLen || len(part) > 63 || !labelInAlphabet(part, alphabet) {
			return false
		}
	}
	return true
}

func recognizableBenignName(name, suffix string, benign []string) bool {
	folded := strings.ToLower(name)
	head := strings.TrimSuffix(folded, suffix)
	for _, known := range benign {
		knownFolded := strings.ToLower(known)
		if folded == knownFolded {
			return true
		}
		if strings.HasSuffix(folded, suffix) && head == knownFolded {
			return true
		}
	}
	return false
}

func labelInAlphabet(label, alphabet string) bool {
	if label == "" {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch alphabet {
		case "base32":
			if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')) {
				return false
			}
		case "base64":
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return false
			}
		case "hex":
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		case "base128":
			if !((c >= 0x80) || (c >= 'a' && c <= 'z')) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func benignLabNames(t *testing.T) []string {
	t.Helper()
	runID := "local-dns-20261027T113715Z"
	lab := redhostLabDir(t)
	run, err := c2blue55.IngestRedhostLabRun(
		filepath.Join(lab, runID+".pcap"),
		filepath.Join(lab, runID+".manifest.json"),
	)
	if err != nil {
		t.Fatalf("ingestion du run bénin: %v", err)
	}
	seen := make(map[string]struct{})
	names := make([]string, 0, len(s03BenignNames))
	for _, labeled := range run.Views {
		fqdn := string(labeled.View.FQDN)
		if _, ok := seen[fqdn]; ok {
			continue
		}
		seen[fqdn] = struct{}{}
		names = append(names, fqdn)
	}
	slices.Sort(names)
	want := append([]string(nil), s03BenignNames...)
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Fatalf("noms bénins = %v, attendu la vérité terrain S-03 %v", names, want)
	}
	return names
}

var s03BenignNames = []string{
	"fcteucqacmalnaiwlgubgjv7lw6ykjmerb9xu9ecaybvc0z7fghqa.t.lab.pound2pound.fr",
	"hazyhaar.fr",
	"lab.pound2pound.fr",
	"pound2pound.fr",
	"probe-1-omi23y5l2lltcrbvqya6jeom22g3wxca4kdxzny.lab.pound2pound.fr",
	"probe-2-3ertutpjrmp7ujxf5o6xu7zegy2dnwwd3kc7zia.lab.pound2pound.fr",
	"probe-3-jo6im5xkqi27s2zhsml3viptjqbwg34b2xetr6y.lab.pound2pound.fr",
	"probe-4-gu2dtyncdhrca4awargiwfpfkktvplj47bmiuli.lab.pound2pound.fr",
	"probe-5-gnh3cd23tsgzjz44ba24mbs2fsliwchyj5klp6q.lab.pound2pound.fr",
	"probe-6-4dxnddw7p74v4h4twfqfgtiw7ct2cpejpx7dddq.lab.pound2pound.fr",
	"www.hazyhaar.fr",
}

func collectSeed(seed uint64, draws int) []byte {
	rng := dnslab.NewSeededBytes(seed)
	out := make([]byte, draws)
	for i := range out {
		out[i] = rng.Next()
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits [4]byte
	cursor := len(digits)
	for n > 0 {
		cursor--
		digits[cursor] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[cursor:])
}
