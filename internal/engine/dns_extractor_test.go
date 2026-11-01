// Package engine — dns_extractor_test.go
// Tests d'acceptation des extracteurs 512D spécialisés pour l'agent DNS (#24) :
//   - TestExtractDNSTunnel512_ParentBlindness (EXG-DNS-02, SH-DNS-01, 0 B/op, jumeau négatif) ;
//   - TestExtractDNSDGA512_ApexDiscrimination (EXG-DNS-03, 0 B/op, jumeau négatif).
package engine

import (
	"math"
	"testing"
)

// TestExtractDNSTunnel512_ParentBlindness vérifie EXG-DNS-02 et SH-DNS-01 :
// deux requêtes de tunnel portant exactement la même charge utile de sous-domaine
// sous deux domaines parents distincts produisent exactement le même vecteur 512D
// bit à bit, la cardinalité temporelle influence effectivement la projection,
// le chemin chaud s'exécute en 0 B/op et les entrées invalides sont refusées.
func TestExtractDNSTunnel512_ParentBlindness(t *testing.T) {
	// Deux tampons sous-jacents complets portant deux domaines parents distincts
	// juste après la tranche de sous-domaine : si l'extracteur lisait au-delà de
	// len(sub) dans cap(sub), les vecteurs divergeraient.
	fullAlpha := []byte("4a6f686e446f653132333435367890ab.0.b.1.hidemyself.org")
	fullBeta := []byte("4a6f686e446f653132333435367890ab.0.b.1.tuns.org")
	const subLen = len("4a6f686e446f653132333435367890ab.0.b.1")
	subAlpha := fullAlpha[:subLen]
	subBeta := fullBeta[:subLen]

	var vecAlpha, vecBeta [EmbeddingDim]float32
	okAlpha := ExtractDNSTunnel512(subAlpha, 16, 6, 32, 48, vecAlpha[:])
	okBeta := ExtractDNSTunnel512(subBeta, 16, 6, 32, 48, vecBeta[:])
	if !okAlpha || !okBeta {
		t.Fatalf("ExtractDNSTunnel512 a échoué: okAlpha=%v okBeta=%v", okAlpha, okBeta)
	}

	nonZero := 0
	for i := range EmbeddingDim {
		if math.IsNaN(float64(vecAlpha[i])) || math.IsInf(float64(vecAlpha[i]), 0) {
			t.Fatalf("vecAlpha[%d] non fini: %v", i, vecAlpha[i])
		}
		if vecAlpha[i] != 0 {
			nonZero++
		}
		if math.Float32bits(vecAlpha[i]) != math.Float32bits(vecBeta[i]) {
			t.Fatalf("SH-DNS-01 fuite parent à la dimension %d: alpha=%v (0x%08x) != beta=%v (0x%08x)",
				i, vecAlpha[i], math.Float32bits(vecAlpha[i]), vecBeta[i], math.Float32bits(vecBeta[i]))
		}
	}
	if nonZero == 0 {
		t.Fatalf("vecteur 512D intégralement nul")
	}

	// Preuve par l'écart : la cardinalité temporelle (subCardinality) doit
	// modifier effectivement le vecteur projeté.
	var vecLowCard [EmbeddingDim]float32
	if !ExtractDNSTunnel512(subAlpha, 16, 6, 32, 1, vecLowCard[:]) {
		t.Fatalf("ExtractDNSTunnel512(subCardinality=1) a échoué")
	}
	if vecLowCard == vecAlpha {
		t.Errorf("la cardinalité temporelle (1 vs 48) n'a modifié aucune dimension du vecteur 512D")
	}

	// Preuve par l'écart : un sous-domaine bénin court diffère d'une charge de tunnel.
	var vecBenignSub [EmbeddingDim]float32
	if !ExtractDNSTunnel512([]byte("www"), 1, 3, 3, 1, vecBenignSub[:]) {
		t.Fatalf("ExtractDNSTunnel512(www) a échoué")
	}
	if vecBenignSub == vecAlpha {
		t.Errorf("le sous-domaine bénin 'www' produit le même vecteur que la charge de tunnel")
	}

	// Preuve 0 B/op
	allocs := testing.AllocsPerRun(1000, func() {
		_ = ExtractDNSTunnel512(subAlpha, 16, 6, 32, 48, vecAlpha[:])
	})
	if allocs != 0 {
		t.Errorf("ExtractDNSTunnel512 AllocsPerRun = %.2f, attendu 0 (0 B/op)", allocs)
	}

	// Jumeaux négatifs : sous-domaine vide ou tampon dst trop court (< 512)
	if ExtractDNSTunnel512(nil, 16, 2, 4, 1, vecAlpha[:]) {
		t.Errorf("ExtractDNSTunnel512(sub=nil) devait retourner false")
	}
	if ExtractDNSTunnel512([]byte{}, 16, 2, 4, 1, vecAlpha[:]) {
		t.Errorf("ExtractDNSTunnel512(sub=\"\") devait retourner false")
	}
	var shortDst [EmbeddingDim - 1]float32
	if ExtractDNSTunnel512(subAlpha, 16, 6, 32, 48, shortDst[:]) {
		t.Errorf("ExtractDNSTunnel512(len(dst)=511) devait retourner false")
	}
}

// TestExtractDNSDGA512_ApexDiscrimination vérifie EXG-DNS-03 :
// projection 512D du label enregistrable (SLD) et de son suffixe public (TLD)
// pour discriminer les domaines apex générés algorithmiquement (DGA) des domaines
// normaux, en 0 B/op, avec jumeaux négatifs sur SLD vide et tampon trop court.
func TestExtractDNSDGA512_ApexDiscrimination(t *testing.T) {
	var vecBenign, vecDGA [EmbeddingDim]float32
	if !ExtractDNSDGA512([]byte("forbesmiddleeast"), []byte("com"), vecBenign[:]) {
		t.Fatalf("ExtractDNSDGA512(forbesmiddleeast, com) a échoué")
	}
	if !ExtractDNSDGA512([]byte("qx7v9k2m4p8w1z9x8c"), []byte("com"), vecDGA[:]) {
		t.Fatalf("ExtractDNSDGA512(qx7v9k2m4p8w1z9x8c, com) a échoué")
	}

	nonZeroBenign, nonZeroDGA := 0, 0
	for i := range EmbeddingDim {
		if math.IsNaN(float64(vecBenign[i])) || math.IsInf(float64(vecBenign[i]), 0) {
			t.Fatalf("vecBenign[%d] non fini: %v", i, vecBenign[i])
		}
		if math.IsNaN(float64(vecDGA[i])) || math.IsInf(float64(vecDGA[i]), 0) {
			t.Fatalf("vecDGA[%d] non fini: %v", i, vecDGA[i])
		}
		if vecBenign[i] != 0 {
			nonZeroBenign++
		}
		if vecDGA[i] != 0 {
			nonZeroDGA++
		}
	}
	if nonZeroBenign == 0 || nonZeroDGA == 0 {
		t.Fatalf("vecteur DGA 512D nul: nonZeroBenign=%d nonZeroDGA=%d", nonZeroBenign, nonZeroDGA)
	}
	if vecBenign == vecDGA {
		t.Fatalf("ExtractDNSDGA512 produit le même vecteur pour un SLD lexical et un SLD DGA")
	}

	var codeBenign, codeDGA [codebookWords]uint64
	QuantizeFHT512(vecBenign[:], &codeBenign)
	QuantizeFHT512(vecDGA[:], &codeDGA)
	dist := codebookHamming(&codeBenign, &CodebookEntry{Bitcode: codeDGA})
	if dist == 0 {
		t.Errorf("distance de Hamming RaBitQ nulle entre SLD lexical et SLD DGA")
	}

	// Preuve 0 B/op
	sldSample := []byte("minhacasamelhor")
	tldSample := []byte("com.br")
	allocs := testing.AllocsPerRun(1000, func() {
		_ = ExtractDNSDGA512(sldSample, tldSample, vecBenign[:])
	})
	if allocs != 0 {
		t.Errorf("ExtractDNSDGA512 AllocsPerRun = %.2f, attendu 0 (0 B/op)", allocs)
	}

	// Jumeaux négatifs : SLD vide ou tampon dst < 512
	if ExtractDNSDGA512(nil, []byte("com"), vecBenign[:]) {
		t.Errorf("ExtractDNSDGA512(sld=nil) devait retourner false")
	}
	if ExtractDNSDGA512([]byte{}, []byte("com"), vecBenign[:]) {
		t.Errorf("ExtractDNSDGA512(sld=\"\") devait retourner false")
	}
	var shortDst [256]float32
	if ExtractDNSDGA512(sldSample, tldSample, shortDst[:]) {
		t.Errorf("ExtractDNSDGA512(len(dst)=256) devait retourner false")
	}
}
