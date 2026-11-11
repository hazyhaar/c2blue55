// Package c2blue55 — compact_reputation_suffixes_test.go
// Tests de contrat de la strate L1-S2 : la recherche de réputation remonte
// les suffixes d'un FQDN à la frontière de label même quand un label de tête
// sort de la grammaire de réputation (tiret en tête ou en queue, '+', '/',
// '='), tandis qu'un nom vide, dépassant 253 octets, porteur d'un label vide
// ou sans suffixe connu reste sans correspondance (D-C2B-L1-02 : les labels
// de tête hors grammaire sont sautés, jamais normalisés ni réécrits).
//
// Chaque sous-test de cas (C01 à C05, et aucun autre) appelle d'abord Match
// ou cleanDomain directement à son premier niveau et compare le résultat
// structuré aux sorties attendues ; les épreuves en table ne viennent qu'en
// complément, après cet appel et son assertion. Le scénario hostile
// SH-L1S2-1 (premier label contenant '+', '/' ou '=', ou bordé de tirets,
// sous un domaine bloqué en sous-arbre) est vérifié dans le corps du
// sous-test C01, sans sous-test distinct.
package c2blue55

import (
	"strings"
	"testing"
)

// TestReputationMatchSuffixes transcrit les cas prescrits C01 à C05 de la
// strate L1-S2 ; cette fonction n'ouvre que les sous-tests C01 à C05.
func TestReputationMatchSuffixes(t *testing.T) {
	compilerTable := func(t *testing.T, entrees []BuildEntry) *ReputationTable {
		t.Helper()
		raw, err := CompileReputationSnapshot(entrees)
		if err != nil {
			t.Fatalf("CompileReputationSnapshot: %v", err)
		}
		table, err := NewReputationTable(raw)
		if err != nil {
			t.Fatalf("NewReputationTable: %v", err)
		}
		return table
	}

	t.Run("C01", func(t *testing.T) {
		table := compilerTable(t, []BuildEntry{
			{Domain: "evil-s2.example", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
		})
		attendu := MatchResult{MatchedDomain: "evil-s2.example", Classification: RepClassBlockC2, MatchKind: MatchSubtree}
		obtenu, trouve := table.Match("-a.evil-s2.example")
		if !trouve || obtenu != attendu {
			t.Errorf("Match(%q) = (%+v, %t) ; attendu (%+v, true)",
				"-a.evil-s2.example", obtenu, trouve, attendu)
		}
		// Épreuve en table complémentaire : tiret en queue de premier label,
		// '=', '+', tiret du second label et nom complet déjà présent : le
		// blocage par sous-arbre s'applique à chaque fois, quels que soient
		// les octets des labels de gauche (scénario hostile SH-L1S2-1).
		for _, fqdn := range []string{
			"a-.evil-s2.example",
			"ab=.evil-s2.example",
			"a+b.evil-s2.example",
			"x.-y.evil-s2.example",
			"evil-s2.example",
		} {
			autreObtenu, autreTrouve := table.Match(fqdn)
			if !autreTrouve || autreObtenu != attendu {
				t.Errorf("Match(%q) = (%+v, %t) ; attendu (%+v, true)",
					fqdn, autreObtenu, autreTrouve, attendu)
			}
		}
		// Complément de borne : un nom d'exactement 253 octets terminé par
		// .evil-s2.example est encore trouvé ; 237 + 16 = 253 octets.
		nomBorne := strings.Repeat("a", 237) + ".evil-s2.example"
		obtenuBorne, trouveBorne := table.Match(nomBorne)
		if !trouveBorne || obtenuBorne != attendu {
			t.Errorf("Match(253 octets) = (%+v, %t) ; attendu (%+v, true)",
				obtenuBorne, trouveBorne, attendu)
		}
		// Complément de nettoyage : majuscules ASCII et point final sont
		// abaissés/retirés avant la recherche, sans autre normalisation.
		obtenuCas, trouveCas := table.Match("-A.EVIL-S2.EXAMPLE.")
		if !trouveCas || obtenuCas != attendu {
			t.Errorf("Match(%q) = (%+v, %t) ; attendu (%+v, true)",
				"-A.EVIL-S2.EXAMPLE.", obtenuCas, trouveCas, attendu)
		}
		// Complément filaire : une question DNS de type A pour
		// ab=.evil-s2.example, acceptée par ParseDNSQuery, est bloquée par
		// la remontée des suffixes (décision de dépôt immédiat).
		paquet := []byte{
			0x1a, 0x2b, // Identifiant de transaction
			0x00, 0x00, // Fanions : QR=0, OPCODE=0 (contrat de question)
			0x00, 0x01, // QDCOUNT = 1
			0x00, 0x00, // ANCOUNT = 0
			0x00, 0x00, // NSCOUNT = 0
			0x00, 0x00, // ARCOUNT = 0
			0x03, 'a', 'b', '=', // label de tête "ab=" hors LDH, admis filaire
			0x07, 'e', 'v', 'i', 'l', '-', 's', '2', // label "evil-s2"
			0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', // label "example"
			0x00,                          // octet nul de fin de QNAME
			byte(TypeA >> 8), byte(TypeA), // QTYPE = A (1), gros boutiste
			0x00, 0x01, // QCLASS = IN
		}
		pipeline, errPipeline := NewPipeline(PipelineConfig{}, table)
		if errPipeline != nil {
			t.Fatalf("NewPipeline: %v", errPipeline)
		}
		t.Cleanup(func() { _ = pipeline.Close() })
		evaluation, errEvaluation := pipeline.EvaluatePacket(paquet, 1000)
		if errEvaluation != nil {
			t.Fatalf("EvaluatePacket: %v", errEvaluation)
		}
		if evaluation.Decision != DecisionFastDrop {
			t.Errorf("EvaluatePacket(ab=.evil-s2.example) Decision = %d ; attendu DecisionFastDrop (%d)",
				evaluation.Decision, DecisionFastDrop)
		}
	})

	t.Run("C02", func(t *testing.T) {
		table := compilerTable(t, []BuildEntry{
			{Domain: "evil-s2.example", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
			{Domain: "exact-s2.example", Classification: RepClassBlockC2, MatchKind: MatchExact},
		})
		// Témoin de vivacité au premier niveau : la même table doit encore
		// reconnaître son domaine bloqué, de sorte qu'un Match vidé rendant
		// (structure nulle, false) échoue ici par assertion au lieu de
		// passer en silence.
		attenduTemoin := MatchResult{MatchedDomain: "evil-s2.example", Classification: RepClassBlockC2, MatchKind: MatchSubtree}
		obtenuTemoin, trouveTemoin := table.Match("evil-s2.example")
		if !trouveTemoin || obtenuTemoin != attenduTemoin {
			t.Errorf("témoin Match(%q) = (%+v, %t) ; attendu (%+v, true)",
				"evil-s2.example", obtenuTemoin, trouveTemoin, attenduTemoin)
		}
		// Tables dégénérées au premier niveau : une table nulle et une
		// table compilée sans aucune entrée restent sans correspondance,
		// sans panique et sans faux positif.
		var tableNulle *ReputationTable
		obtenuNulle, trouveNulle := tableNulle.Match("evil-s2.example")
		if trouveNulle || obtenuNulle != (MatchResult{}) {
			t.Errorf("Match sur table nulle = (%+v, %t) ; attendu (MatchResult nul, false)",
				obtenuNulle, trouveNulle)
		}
		rawSansEntree, errSansEntree := CompileReputationSnapshot(nil)
		if errSansEntree != nil {
			t.Fatalf("CompileReputationSnapshot(nil): %v", errSansEntree)
		}
		tableSansEntree, errTableSansEntree := NewReputationTable(rawSansEntree)
		if errTableSansEntree != nil {
			t.Fatalf("NewReputationTable(instantane sans entree): %v", errTableSansEntree)
		}
		obtenuSansEntree, trouveSansEntree := tableSansEntree.Match("evil-s2.example")
		if trouveSansEntree || obtenuSansEntree != (MatchResult{}) {
			t.Errorf("Match sur table sans entree = (%+v, %t) ; attendu (MatchResult nul, false)",
				obtenuSansEntree, trouveSansEntree)
		}
		// Nom vide : refus franc, le nettoyage rendant une chaîne vide.
		obtenuNomVide, trouveNomVide := table.Match("")
		if trouveNomVide || obtenuNomVide != (MatchResult{}) {
			t.Errorf("Match(%q) = (%+v, %t) ; attendu (MatchResult nul, false)",
				"", obtenuNomVide, trouveNomVide)
		}
		// Négatif de tête au premier niveau : suffixe absent de la table.
		obtenuNegatif, trouveNegatif := table.Match("-a.absent-s2.example")
		if trouveNegatif || obtenuNegatif != (MatchResult{}) {
			t.Errorf("Match(%q) = (%+v, %t) ; attendu (MatchResult nul, false)",
				"-a.absent-s2.example", obtenuNegatif, trouveNegatif)
		}
		// Épreuve en table complémentaire : label vide (deux points
		// consécutifs), point initial, suffixe d'une entrée MatchExact
		// (jamais couverte par exact) et nom de 254 octets (238 + 16).
		nomOversize := strings.Repeat("a", 238) + ".evil-s2.example"
		for _, fqdn := range []string{
			"a..evil-s2.example",
			".evil-s2.example",
			"-x.exact-s2.example",
			nomOversize,
		} {
			autreObtenu, autreTrouve := table.Match(fqdn)
			if autreTrouve || autreObtenu != (MatchResult{}) {
				t.Errorf("Match(%q) = (%+v, %t) ; attendu (MatchResult nul, false)",
					fqdn, autreObtenu, autreTrouve)
			}
		}
	})

	t.Run("C03", func(t *testing.T) {
		table := compilerTable(t, []BuildEntry{
			{Domain: "evil-s2.example", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
		})
		attendu := MatchResult{MatchedDomain: "evil-s2.example", Classification: RepClassBlockC2, MatchKind: MatchSubtree}
		obtenu, trouve := table.Match("-a.evil-s2.example")
		if !trouve || obtenu != attendu {
			t.Errorf("Match(%q) = (%+v, %t) ; attendu (%+v, true)",
				"-a.evil-s2.example", obtenu, trouve, attendu)
		}
		// Mesure d'allocations après l'appel direct asserté ci-dessus ;
		// l'entrée est déjà en minuscules, donc zéro allocation par appel.
		allocationsParAppel := testing.AllocsPerRun(100, func() {
			obtenu, trouve = table.Match("-a.evil-s2.example")
		})
		if allocationsParAppel != 0 {
			t.Errorf("AllocsPerRun sur Match(%q) = %.2f ; attendu 0 allocation par appel",
				"-a.evil-s2.example", allocationsParAppel)
		}
		if !trouve || obtenu != attendu {
			t.Errorf("dernier Match(%q) de la mesure = (%+v, %t) ; attendu (%+v, true)",
				"-a.evil-s2.example", obtenu, trouve, attendu)
		}
		// Le même nom terminé par un point final est trouvé avec le même
		// résultat : le retrait du point passe par la sous-chaîne sans
		// copie, avant toute mesure d'allocation.
		obtenuPoint, trouvePoint := table.Match("-a.evil-s2.example.")
		if !trouvePoint || obtenuPoint != attendu {
			t.Errorf("Match(%q) = (%+v, %t) ; attendu (%+v, true)",
				"-a.evil-s2.example.", obtenuPoint, trouvePoint, attendu)
		}
		allocationsPoint := testing.AllocsPerRun(100, func() {
			obtenuPoint, trouvePoint = table.Match("-a.evil-s2.example.")
		})
		if allocationsPoint != 0 {
			t.Errorf("AllocsPerRun sur Match(%q) = %.2f ; attendu 0 allocation par appel",
				"-a.evil-s2.example.", allocationsPoint)
		}
		if !trouvePoint || obtenuPoint != attendu {
			t.Errorf("dernier Match(%q) de la mesure = (%+v, %t) ; attendu (%+v, true)",
				"-a.evil-s2.example.", obtenuPoint, trouvePoint, attendu)
		}
		// Le nettoyage d'un nom déjà en minuscules terminé par un point
		// revient en sous-chaîne, sans allocation.
		var nettoyeePointFroide string
		allocationsNettoyagePoint := testing.AllocsPerRun(100, func() {
			nettoyeePointFroide = cleanDomain("evil-s2.example.")
		})
		if allocationsNettoyagePoint != 0 {
			t.Errorf("AllocsPerRun de cleanDomain(%q) = %.2f ; attendu 0 allocation par appel",
				"evil-s2.example.", allocationsNettoyagePoint)
		}
		if nettoyeePointFroide != "evil-s2.example" {
			t.Errorf("cleanDomain(%q) de la mesure = %q ; attendu %q",
				"evil-s2.example.", nettoyeePointFroide, "evil-s2.example")
		}
	})

	t.Run("C04", func(t *testing.T) {
		table := compilerTable(t, []BuildEntry{
			{Domain: "bloc.multi-s2.example", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
			{Domain: "multi-s2.example", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
		})
		// Le blocage trouvé sur le suffixe long prime sur l'autorisation
		// trouvée sur le suffixe plus court : la règle de rang décide,
		// quel que soit l'ordre de parcours des suffixes.
		attenduBloc := MatchResult{MatchedDomain: "bloc.multi-s2.example", Classification: RepClassBlockC2, MatchKind: MatchSubtree}
		obtenuBloc, trouveBloc := table.Match("a.bloc.multi-s2.example")
		if !trouveBloc || obtenuBloc != attenduBloc {
			t.Errorf("Match(%q) = (%+v, %t) ; attendu (%+v, true)",
				"a.bloc.multi-s2.example", obtenuBloc, trouveBloc, attenduBloc)
		}
		attenduPermis := MatchResult{MatchedDomain: "multi-s2.example", Classification: RepClassAllowVendor, MatchKind: MatchSubtree}
		obtenuPermis, trouvePermis := table.Match("a.multi-s2.example")
		if !trouvePermis || obtenuPermis != attenduPermis {
			t.Errorf("Match(%q) = (%+v, %t) ; attendu (%+v, true)",
				"a.multi-s2.example", obtenuPermis, trouvePermis, attenduPermis)
		}
		// Ordre inverse de découverte : le suffixe bloqué est cette fois
		// le plus court et doit remplacer l'autorisation trouvée avant
		// lui sur le suffixe long, quelle que soit la chronologie de
		// parcours des suffixes.
		tableInverse := compilerTable(t, []BuildEntry{
			{Domain: "vendeur.court-s2.example", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
			{Domain: "court-s2.example", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
		})
		attenduInverse := MatchResult{MatchedDomain: "court-s2.example", Classification: RepClassBlockC2, MatchKind: MatchSubtree}
		obtenuInverse, trouveInverse := tableInverse.Match("a.vendeur.court-s2.example")
		if !trouveInverse || obtenuInverse != attenduInverse {
			t.Errorf("Match(%q) = (%+v, %t) ; attendu (%+v, true)",
				"a.vendeur.court-s2.example", obtenuInverse, trouveInverse, attenduInverse)
		}
	})

	t.Run("C05", func(t *testing.T) {
		// Nettoyage : majuscules ASCII abaissées et point final retiré.
		nettoyeeCas := cleanDomain("Evil-S2.EXAMPLE.")
		if nettoyeeCas != "evil-s2.example" {
			t.Errorf("cleanDomain(%q) = %q ; attendu %q", "Evil-S2.EXAMPLE.", nettoyeeCas, "evil-s2.example")
		}
		// Majuscules sans point final : le chemin lent abaisse la casse et
		// ne retire rien d'autre que le point final éventuel.
		nettoyeeMajuscules := cleanDomain("EVIL-S2.Example")
		if nettoyeeMajuscules != "evil-s2.example" {
			t.Errorf("cleanDomain(%q) = %q ; attendu %q", "EVIL-S2.Example", nettoyeeMajuscules, "evil-s2.example")
		}
		// Minuscules avec point final : le point final seul est retiré, le
		// nom déjà bas reste inchangé par ailleurs.
		nettoyeePointFinal := cleanDomain("evil-s2.example.")
		if nettoyeePointFinal != "evil-s2.example" {
			t.Errorf("cleanDomain(%q) = %q ; attendu %q", "evil-s2.example.", nettoyeePointFinal, "evil-s2.example")
		}
		// Chaîne déjà en minuscules, octets UTF-8 hors ASCII : rendue
		// inchangée octet pour octet, sans gonflement de longueur.
		const dejaBasse = "déjà-minuscule.example"
		nettoyeeBasse := cleanDomain(dejaBasse)
		if nettoyeeBasse != dejaBasse {
			t.Errorf("cleanDomain(%q) = %q ; attendu la chaîne inchangée octet pour octet", dejaBasse, nettoyeeBasse)
		}
		// Cent octets 0xFF : conservés tels quels, longueur intacte.
		brute := strings.Repeat("\xff", 100)
		nettoyeeBrute := cleanDomain(brute)
		if nettoyeeBrute != brute || len(nettoyeeBrute) != 100 {
			t.Errorf("cleanDomain(100 octets 0xFF) = (%d octets, inchangée=%t) ; attendu (100, true)",
				len(nettoyeeBrute), nettoyeeBrute == brute)
		}
		// Chaîne vide : rendue vide, sans lecture d'octet.
		nettoyeeVide := cleanDomain("")
		if nettoyeeVide != "" {
			t.Errorf("cleanDomain(\"\") = %q ; attendu \"\"", nettoyeeVide)
		}
		// Nom réduit au seul point : après retrait du point, la chaîne
		// restante est vide.
		nettoyeePointSeul := cleanDomain(".")
		if nettoyeePointSeul != "" {
			t.Errorf("cleanDomain(%q) = %q ; attendu %q", ".", nettoyeePointSeul, "")
		}
		// Majuscule unique suivi du point final : retrait du point puis
		// abaissement de la seule lettre.
		nettoyeeMajusculePoint := cleanDomain("A.")
		if nettoyeeMajusculePoint != "a" {
			t.Errorf("cleanDomain(%q) = %q ; attendu %q", "A.", nettoyeeMajusculePoint, "a")
		}
		// Majuscules en première et dernière positions, de part et
		// d'autre d'une minuscule : l'abaissement démarre à la première
		// majuscule trouvée et couvre toute la fin du nom.
		nettoyeeMelange := cleanDomain("Ab.cD")
		if nettoyeeMelange != "ab.cd" {
			t.Errorf("cleanDomain(%q) = %q ; attendu %q", "Ab.cD", nettoyeeMelange, "ab.cd")
		}
		// Majuscule en dernière position, sans point final.
		nettoyeeFin := cleanDomain("aZ")
		if nettoyeeFin != "az" {
			t.Errorf("cleanDomain(%q) = %q ; attendu %q", "aZ", nettoyeeFin, "az")
		}
		// La longueur nettoyée du nom de 107 octets (1 + 90 + 16) reste
		// sous la borne : les octets 0xFF du label de tête sont sautés et
		// le suffixe bloqué est trouvé.
		table := compilerTable(t, []BuildEntry{
			{Domain: "evil-s2.example", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
		})
		nomHorsGrammaire := "A" + strings.Repeat("\xff", 90) + ".evil-s2.example"
		obtenuHors, trouveHors := table.Match(nomHorsGrammaire)
		attenduHors := MatchResult{MatchedDomain: "evil-s2.example", Classification: RepClassBlockC2, MatchKind: MatchSubtree}
		if !trouveHors || obtenuHors != attenduHors {
			t.Errorf("Match(107 octets) = (%+v, %t) ; attendu (%+v, true)",
				obtenuHors, trouveHors, attenduHors)
		}
		// Une entrée déjà en minuscules sans point final est rendue sans
		// allocation : zéro allocation par appel.
		var nettoyeeFroide string
		allocationsNettoyage := testing.AllocsPerRun(100, func() {
			nettoyeeFroide = cleanDomain("deja-minuscule.example")
		})
		if allocationsNettoyage != 0 {
			t.Errorf("AllocsPerRun de cleanDomain = %.2f ; attendu 0 allocation par appel", allocationsNettoyage)
		}
		if nettoyeeFroide != "deja-minuscule.example" {
			t.Errorf("cleanDomain(%q) de la mesure = %q ; attendu %q",
				"deja-minuscule.example", nettoyeeFroide, "deja-minuscule.example")
		}
	})

	t.Run("C06", func(t *testing.T) {
		hachageVide := FNV1a64String("")
		if hachageVide != 14695981039346656037 {
			t.Errorf(`FNV1a64String("") = %d ; attendu 14695981039346656037`, hachageVide)
		}
		hachageLettre := FNV1a64String("a")
		if hachageLettre != 0xaf63dc4c8601ec8c {
			t.Errorf(`FNV1a64String("a") = %#x ; attendu 0xaf63dc4c8601ec8c`, hachageLettre)
		}
		hachageDomaine := FNV1a64String("evil-s2.example")
		if hachageDomaine != FNV1a64([]byte("evil-s2.example")) {
			t.Errorf(`FNV1a64String("evil-s2.example") = %#x ; attendu FNV1a64 des mêmes octets, %#x`, hachageDomaine, FNV1a64([]byte("evil-s2.example")))
		}
		tableMutualisee := compilerTable(t, []BuildEntry{
			{Domain: "githubusercontent.com", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
			{Domain: "github.io", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
		})
		blocageMutualise, blocageTrouve := tableMutualisee.Match("charge.githubusercontent.com")
		if !blocageTrouve || blocageMutualise.MatchedDomain != "githubusercontent.com" || blocageMutualise.Classification != RepClassBlockC2 {
			t.Errorf(`Match("charge.githubusercontent.com") = (%+v, %t) ; attendu le blocage de githubusercontent.com`, blocageMutualise, blocageTrouve)
		}
		autorisationMutualisee, autorisationTrouvee := tableMutualisee.Match("locataire.github.io")
		if autorisationTrouvee {
			t.Errorf(`Match("locataire.github.io") = (%+v, true) ; attendu aucun résultat : une autorisation ne s'étend pas aux sous-domaines d'un hébergement mutualisé`, autorisationMutualisee)
		}
	})
}
