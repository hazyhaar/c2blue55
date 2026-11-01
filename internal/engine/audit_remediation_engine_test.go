package engine

import (
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"testing"
)

func TestAuditOOSExigeRappelOperationnel(t *testing.T) {
	// Cas 1 : toutes les familles P1..P4 ont Recall == 0, FalsePositives == 0, AUC == 1.0 -> AllPass doit être false.
	corpusA := &EpisodeRunCorpus{RunID: "audit-oos-run-a"}
	corpusB := &EpisodeRunCorpus{RunID: "audit-oos-run-b"}
	for _, famille := range oosFamilies {
		corpusA.Samples = append(corpusA.Samples, EpisodeVectorSample{
			Family:     famille,
			DomainApex: "a-" + strings.ToLower(famille) + ".example",
			Features:   [8]float32{1.0},
		})
		corpusB.Samples = append(corpusB.Samples, EpisodeVectorSample{
			Family:     famille,
			DomainApex: "b-" + strings.ToLower(famille) + ".example",
			Features:   [8]float32{2.0},
		})
	}
	corpusA.Samples = append(corpusA.Samples, EpisodeVectorSample{Family: "BENIGN", DomainApex: "a-benin.example", Features: [8]float32{0.0}})
	corpusB.Samples = append(corpusB.Samples, EpisodeVectorSample{Family: "BENIGN", DomainApex: "b-benin.example", Features: [8]float32{3.0}})

	preuveRappelNul, err := ProvePatternOutOfSample(corpusA, corpusB)
	if err != nil {
		t.Fatalf("ProvePatternOutOfSample (rappel nul): %v", err)
	}
	for _, famille := range oosFamilies {
		metriques := preuveRappelNul.Families[famille]
		if metriques.Recall != 0 || metriques.FalsePositives != 0 || metriques.AUC != 1.0 {
			t.Fatalf("fixture cas 1 non discriminante pour %s: %+v", famille, metriques)
		}
	}
	if preuveRappelNul.AllPass {
		t.Errorf("ProvePatternOutOfSample accepte AllPass=true alors que Recall==0 sur P1..P4")
	}

	// Cas 2 : runB vide ou dépourvu de positifs pour une famille (ex. P4 absent de runB) -> AllPass doit être false.
	corpusAComplet := &EpisodeRunCorpus{RunID: "audit-oos-complet-a"}
	corpusBSansP4 := &EpisodeRunCorpus{RunID: "audit-oos-sans-p4-b"}
	corpusBVide := &EpisodeRunCorpus{RunID: "audit-oos-vide-b"}
	corpusAComplet.Samples = append(corpusAComplet.Samples, EpisodeVectorSample{
		Family: "BENIGN", DomainApex: "benin-a.example", Features: [8]float32{0, 0, 0, 0, 0, 0, 0, 0},
	})
	corpusBSansP4.Samples = append(corpusBSansP4.Samples, EpisodeVectorSample{
		Family: "BENIGN", DomainApex: "benin-b.example", Features: [8]float32{0, 0, 0, 0, 0, 0, 0, 0},
	})
	for indice, famille := range oosFamilies {
		var vecteurFamille [8]float32
		vecteurFamille[indice] = 10.0
		corpusAComplet.Samples = append(corpusAComplet.Samples, EpisodeVectorSample{
			Family: famille, DomainApex: "hostile-a-" + strings.ToLower(famille) + ".example", Features: vecteurFamille,
		})
		if famille != "P4" {
			corpusBSansP4.Samples = append(corpusBSansP4.Samples, EpisodeVectorSample{
				Family: famille, DomainApex: "hostile-b-" + strings.ToLower(famille) + ".example", Features: vecteurFamille,
			})
		}
	}

	if preuveSansP4, errSansP4 := ProvePatternOutOfSample(corpusAComplet, corpusBSansP4); errSansP4 == nil && preuveSansP4.AllPass {
		t.Errorf("ProvePatternOutOfSample accepte AllPass=true alors que P4 n'a aucun positif dans runB")
	}
	if preuveVide, errVide := ProvePatternOutOfSample(corpusAComplet, corpusBVide); errVide == nil && preuveVide.AllPass {
		t.Errorf("ProvePatternOutOfSample accepte AllPass=true alors que runB est vide")
	}
}

func TestAuditHoldoutReellementEvalue(t *testing.T) {
	var bitsBenin [codebookWords]uint64
	for i := range bitsBenin {
		bitsBenin[i] = 0x5555555555555555
	}

	// 1. holdout == nil -> doit rendre ErrHoldoutUnvalidated.
	quarantaineNil := NewQuarantineChamber(4)
	if _, err := quarantaineNil.EnqueueIncident(bitsBenin, 0, CascadeFastDrop, 101, 1, 2); err != nil {
		t.Fatal(err)
	}
	if admis, err := quarantaineNil.ValidateAgainstHoldoutSet(nil, 0); !errors.Is(err, ErrHoldoutUnvalidated) {
		t.Errorf("ValidateAgainstHoldoutSet(nil, 0): attendu ErrHoldoutUnvalidated, obtenu admis=%d err=%v", len(admis), err)
	}

	// 2. holdout vide (Len() == 0) -> doit rendre ErrHoldoutUnvalidated.
	quarantaineVide := NewQuarantineChamber(4)
	if _, err := quarantaineVide.EnqueueIncident(bitsBenin, 0, CascadeFastDrop, 102, 1, 2); err != nil {
		t.Fatal(err)
	}
	holdoutVide := NewCodebook(nil)
	if admis, err := quarantaineVide.ValidateAgainstHoldoutSet(holdoutVide, 0); !errors.Is(err, ErrHoldoutUnvalidated) {
		t.Errorf("ValidateAgainstHoldoutSet(holdoutVide, 0): attendu ErrHoldoutUnvalidated, obtenu admis=%d err=%v", len(admis), err)
	}

	// 3. holdout contenant une entrée bénigne de référence et candidat portant exactement le même Bitcode (collision) -> rejet !
	holdoutRef := NewCodebook([]CodebookEntry{
		{Bitcode: bitsBenin, ThreatID: 0, Subsystem: 1, Severity: 1},
	})
	quarantaineCollision := NewQuarantineChamber(4)
	if _, err := quarantaineCollision.EnqueueIncident(bitsBenin, 0, CascadeFastDrop, 103, 1, 2); err != nil {
		t.Fatal(err)
	}
	if admis, err := quarantaineCollision.ValidateAgainstHoldoutSet(holdoutRef, 0); !errors.Is(err, ErrHoldoutUnvalidated) {
		t.Errorf("ValidateAgainstHoldoutSet(collision avec holdoutRef): attendu ErrHoldoutUnvalidated, obtenu admis=%d err=%v", len(admis), err)
	}

	// 4. Candidat à distance de Hamming franche (512 bits >= 200 bits) de toutes les entrées bénignes de holdoutRef -> promotion valide !
	var bitsDistant [codebookWords]uint64
	for i := range bitsDistant {
		bitsDistant[i] = ^bitsBenin[i]
	}
	quarantaineSaine := NewQuarantineChamber(4)
	if _, err := quarantaineSaine.EnqueueIncident(bitsDistant, 0, CascadeFastDrop, 104, 1, 2); err != nil {
		t.Fatal(err)
	}
	admisSains, errSaine := quarantaineSaine.ValidateAgainstHoldoutSet(holdoutRef, 0)
	if errSaine != nil || len(admisSains) != 1 || admisSains[0].Bitcode != bitsDistant {
		t.Errorf("ValidateAgainstHoldoutSet(candidat distant >= 200 bits): attendu 1 promu sans erreur, obtenu len=%d err=%v", len(admisSains), errSaine)
	}
}

func TestAuditDeriveRefuseNaN(t *testing.T) {
	// 1. Sur une garde vierge, un vecteur initial contenant NaN ne doit PAS s'installer comme référence.
	gardeVierge := NewCusumDriftGuard(DefaultDriftGuardConfig())
	vecteurInitialNaN := make([]float32, EmbeddingDim)
	vecteurInitialNaN[0] = float32(math.NaN())
	accepteInit, motifInit := gardeVierge.CheckUpdate(vecteurInitialNaN)
	_, _, alertesInit := gardeVierge.Stats()
	if accepteInit || alertesInit == 0 {
		t.Errorf("garde vierge face a NaN: accepte=%v motif=%q alertes=%d (attendu rejet et alertes > 0)", accepteInit, motifInit, alertesInit)
	}

	// 2. Après installation d'une référence saine finie, NaN et Inf doivent être refusés, incrémenter AlertCount et préserver la référence.
	garde := NewCusumDriftGuard(DefaultDriftGuardConfig())
	var referenceSaine [EmbeddingDim]float32
	for i := range referenceSaine {
		referenceSaine[i] = 0.25
	}
	if accepteBase, motifBase := garde.CheckUpdate(referenceSaine[:]); !accepteBase {
		t.Fatalf("installation reference saine refusee: %s", motifBase)
	}

	vecteurAvecNaN := referenceSaine
	vecteurAvecNaN[7] = float32(math.NaN())
	_, _, alertesAvantNaN := garde.Stats()
	accepteNaN, motifNaN := garde.CheckUpdate(vecteurAvecNaN[:])
	_, _, alertesApresNaN := garde.Stats()
	if accepteNaN || alertesApresNaN <= alertesAvantNaN {
		t.Errorf("CheckUpdate(NaN): accepte=%v motif=%q alertes=%d->%d (attendu rejet et increment d'alerte)",
			accepteNaN, motifNaN, alertesAvantNaN, alertesApresNaN)
	}
	if garde.lastCentroid != referenceSaine {
		t.Errorf("la reference saine a ete corrompue apres soumission d'un NaN")
	}

	vecteurAvecInf := referenceSaine
	vecteurAvecInf[13] = float32(math.Inf(1))
	_, _, alertesAvantInf := garde.Stats()
	accepteInf, motifInf := garde.CheckUpdate(vecteurAvecInf[:])
	_, _, alertesApresInf := garde.Stats()
	if accepteInf || alertesApresInf <= alertesAvantInf {
		t.Errorf("CheckUpdate(+Inf): accepte=%v motif=%q alertes=%d->%d (attendu rejet et increment d'alerte)",
			accepteInf, motifInf, alertesAvantInf, alertesApresInf)
	}
	if garde.lastCentroid != referenceSaine {
		t.Errorf("la reference saine a ete corrompue apres soumission d'un +Inf")
	}
}

func TestAuditChargeLongueIntegrale(t *testing.T) {
	if utilise := payloadUsed(make([]byte, 4096)); utilise != 4096 {
		t.Errorf("payloadUsed(make([]byte, 4096)) = %d, attendu 4096", utilise)
	}

	chargeA := make([]byte, 4096)
	chargeB := make([]byte, 4096)
	for i := range 96 {
		chargeA[i] = byte('A' + (i % 26))
		chargeB[i] = chargeA[i]
	}
	// Octet NUL à l'indice 40 dans le préfixe identique des deux charges longues.
	chargeA[40] = 0x00
	chargeB[40] = 0x00
	for i := 96; i < 4096; i++ {
		chargeA[i] = byte('a' + (i % 23))
		chargeB[i] = byte('0' + ((i * 7) % 10))
	}

	reservoir := DefaultArenaPool()
	var evA, evB Event
	evA.Subsystem = 3
	evA.Action = 7
	evB.Subsystem = 3
	evB.Action = 7
	if stockeA := reservoir.StorePayload(&evA, chargeA); stockeA != 4096 {
		t.Fatalf("StorePayload(evA) = %d, attendu 4096", stockeA)
	}
	if stockeB := reservoir.StorePayload(&evB, chargeB); stockeB != 4096 {
		t.Fatalf("StorePayload(evB) = %d, attendu 4096", stockeB)
	}

	extracteur := NewFeatureExtractor()
	var vecA, vecB [EmbeddingDim]float32
	if !extracteur.ExtractTo(&evA, vecA[:]) {
		t.Fatal("ExtractTo(evA) a echoue")
	}
	if !extracteur.ExtractTo(&evB, vecB[:]) {
		t.Fatal("ExtractTo(evB) a echoue")
	}
	if vecA == vecB {
		t.Errorf("deux charges longues de 4096 octets identiques sur 0..95 (NUL en 40) mais distinctes sur 96..4095 produisent exactement le meme vecteur 512D")
	}

	indicesRatios := []struct {
		nom    string
		indice int
	}{
		{nom: "hdrPayloadUsed", indice: headerBase + hdrPayloadUsed},
		{nom: "aggUsedRatio", indice: aggregateBase + aggUsedRatio},
		{nom: "aggNulPos", indice: aggregateBase + aggNulPos},
	}

	for nomVec, vec := range map[string][EmbeddingDim]float32{"vecA": vecA, "vecB": vecB} {
		for dim, coord := range vec {
			if math.IsNaN(float64(coord)) || math.IsInf(float64(coord), 0) {
				t.Fatalf("%s[%d] non fini: %v", nomVec, dim, coord)
			}
		}
		for _, specRatio := range indicesRatios {
			valeur := vec[specRatio.indice]
			if valeur < 0.0 || valeur > 1.0 {
				t.Errorf("%s[%s] hors bornes [0, 1]: %f", nomVec, specRatio.nom, valeur)
			}
		}
	}
}

func TestAuditAblation18x18ExecuteVraimentMoteurN(t *testing.T) {
	ipCliente := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 55, 0, 9}

	// 1. Point bénin standard (www.example.org, QType A).
	reqBenigne := buildWireQuerySimple(0x7001, "www.example.org", 1)
	var tamponBenin [512]byte
	copy(tamponBenin[:len(reqBenigne)], reqBenigne)
	binary.BigEndian.PutUint16(tamponBenin[2:4], 0x8180)
	binary.BigEndian.PutUint16(tamponBenin[4:6], 1)
	binary.BigEndian.PutUint16(tamponBenin[6:8], 1)
	finBenin := appendWireRRSimple(tamponBenin[:], len(reqBenigne), 1, 300, []byte{93, 184, 216, 34})
	repBenigne := append([]byte(nil), tamponBenin[:finBenin]...)

	// 2. Point hostile P5 (QType=252 AXFR, apex="zone-axfr.example", sous-domaine de longueur 52 >= 44).
	// En N+1 (18 classes), il est classé "P5". En N (M-01..M-04 uniquement), il est détecté par M-01 (len(sub) >= 44) !
	sousDomaineLong := strings.Repeat("a", 26) + "." + strings.Repeat("b", 25) // 26 + 1 + 25 = 52 octets
	if len(sousDomaineLong) != 52 {
		t.Fatalf("longueur sous-domaine inattendue: %d", len(sousDomaineLong))
	}
	apexCible := "zone-axfr.example"
	reqHostileP5 := buildWireQuerySimple(0x7002, sousDomaineLong+"."+apexCible, 252)
	var tamponP5 [512]byte
	copy(tamponP5[:len(reqHostileP5)], reqHostileP5)
	binary.BigEndian.PutUint16(tamponP5[2:4], 0x8400)
	binary.BigEndian.PutUint16(tamponP5[4:6], 1)
	binary.BigEndian.PutUint16(tamponP5[6:8], 3)
	curseurP5 := len(reqHostileP5)
	blocTXT := append([]byte{32}, []byte("0123456789abcdef0123456789abcdef")...)
	for range 3 {
		curseurP5 = appendWireRRSimple(tamponP5[:], curseurP5, 16, 60, blocTXT)
	}
	repHostileP5 := append([]byte(nil), tamponP5[:curseurP5]...)

	observations := []Motif17EvalPoint{
		{
			TimestampNs:  1_790_000_000_000_000_000,
			ClientIP:     ipCliente,
			TrueClass:    "BENIGN",
			DomainApex:   "example.org",
			Subdomain:    "www",
			QType:        1,
			RequestWire:  reqBenigne,
			ResponseWire: repBenigne,
		},
		{
			TimestampNs:  1_790_000_000_500_000_000,
			ClientIP:     ipCliente,
			TrueClass:    "P5",
			DomainApex:   apexCible,
			Subdomain:    sousDomaineLong,
			QType:        252,
			RequestWire:  reqHostileP5,
			ResponseWire: repHostileP5,
		},
	}

	bilan, err := EvaluateConfusion18x18AndAblation(observations)
	if err != nil {
		t.Fatalf("EvaluateConfusion18x18AndAblation: %v", err)
	}
	if bilan.Ablation.UpgradedNewGHSARecall != 1.0 {
		t.Fatalf("UpgradedNewGHSARecall = %.4f, attendu 1.0", bilan.Ablation.UpgradedNewGHSARecall)
	}
	if bilan.Ablation.LegacyNewGHSARecall != 1.0 {
		t.Fatalf("LegacyNewGHSARecall = %.4f, attendu 1.0 (le moteur N M-01..M-04 n'a pas ete execute independamment sur le point P5 de 52 octets)",
			bilan.Ablation.LegacyNewGHSARecall)
	}
}
