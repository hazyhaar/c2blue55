package dnslab

import (
	"errors"
	"fmt"
)

// ErrVariationContract signale une variation hors bornes (alphabet inconnu,
// longueurs, cadence > 50, parent hors zone).
var ErrVariationContract = errors.New("dnslab: variation hors contrat")

// LabBenignNames provient de la capture réelle local-dns-20261027T113715Z
// (les onze noms distincts de la vérité terrain S-03).
var LabBenignNames = []string{
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

// Variation décrit une dimension de variation des noms rejoués (strate S-07).
type Variation struct {
	Alphabet string
	LabelLen int
	Labels   int
	QType    uint16
	Cadence  uint32
	Dilution int
	Parent   string
}

// SeededBytes est un générateur déterministe d'octets (xorshift64*).
type SeededBytes struct {
	state uint64
}

// NewSeededBytes construit le générateur.
func NewSeededBytes(seed uint64) *SeededBytes {
	if seed == 0 {
		// Le décalage évite de confondre la graine 0 avec la constante elle-même.
		seed = (seed ^ 0x9e3779b97f4a7c15) + 1
	}
	return &SeededBytes{state: seed}
}

// Next rend l'octet suivant.
func (g *SeededBytes) Next() byte {
	g.state ^= g.state >> 12
	g.state ^= g.state << 25
	g.state ^= g.state >> 27
	return byte((g.state * 2685821657736338717) >> 56)
}

// GenerateVariationNames engendre nameCount noms sous <Parent>.<zone> aux
// paramètres de la variation ; refuse tout Parent hors zone.
func GenerateVariationNames(v Variation, zone string, nameCount int, rng *SeededBytes) ([]string, error) {
	var alphabet string
	switch v.Alphabet {
	case "base32":
		alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	case "base64":
		alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	case "hex":
		alphabet = "0123456789abcdef"
	case "base128":
		// Les octets hauts sont conservés tels quels dans le nom DNS sur le fil.
	default:
		return nil, ErrVariationContract
	}
	if nameCount < 1 || rng == nil || v.LabelLen < 8 || v.LabelLen > 63 || v.Labels < 1 || v.Labels > 4 ||
		v.Cadence < 1 || v.Cadence > 50 || v.Dilution < 0 || v.Dilution > 9 ||
		len(v.Parent) < 1 || len(v.Parent) > 63 || !variationLabel(v.Parent) {
		return nil, ErrVariationContract
	}
	if _, err := NewZone(zone, [4]byte{}, "", 0); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrVariationContract, err)
	}
	suffix := "." + v.Parent + "." + zone
	if len(suffix)+8 > 253 {
		return nil, ErrVariationContract
	}
	if v.Dilution > 0 {
		for _, benign := range LabBenignNames {
			if len(benign)+len(suffix) > 253 {
				return nil, ErrVariationContract
			}
		}
	}

	names := make([]string, 0, nameCount)
	benignIndex := 0
	for len(names) < nameCount {
		// Raccourcir un label seulement si huit octets au moins restent disponibles.
		budget := 253 - len(suffix)
		name := make([]byte, 0, budget)
		for label := 0; label < v.Labels; label++ {
			if label > 0 {
				if budget < 1+8 {
					break
				}
				name = append(name, '.')
				budget--
			}
			length := min(v.LabelLen, budget)
			if length < 8 {
				break
			}
			for i := range length {
				b := rng.Next()
				if v.Alphabet == "base128" {
					name = append(name, 0x80+(b&0x7f))
				} else {
					c := alphabet[int(b)%len(alphabet)]
					if v.Alphabet == "base64" && c == '-' && (i == 0 || i == length-1) {
						c = 'A'
					}
					name = append(name, c)
				}
			}
			budget -= length
		}
		names = append(names, string(name)+suffix)
		for i := 0; i < v.Dilution && len(names) < nameCount; i++ {
			names = append(names, LabBenignNames[benignIndex%len(LabBenignNames)]+suffix)
			benignIndex++
		}
	}
	return names, nil
}

func variationLabel(label string) bool {
	for i := 0; i < len(label); i++ {
		c := label[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || (c == '-' && i > 0 && i < len(label)-1)) {
			return false
		}
	}
	return true
}
