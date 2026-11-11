// Command c2agent — ecoute_bilan_test.go
// Tests de contrat de la strate L1-S3 : chaque datagramme reçu est compté dans
// une issue exactement, les escalades rejetées pour file pleine sont comptées
// et affichées sans être confondues avec des paquets corrompus, les erreurs
// d'analyse ne s'affichent qu'en mode verbeux, un refus par réputation dont
// l'écriture du journal d'audit a échoué reste compté dans refus et n'est
// signalé que par une seule ligne [JOURNAL D'AUDIT EN ERREUR], au premier
// échec, sans être confondu avec une erreur d'analyse, et ecrireBilan écrit
// une ligne de bilan exacte et rend l'erreur d'écriture éventuelle.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55"
)

// questionDNSBilan construit une question DNS filaire à une seule question
// (QDCOUNT=1, QCLASS IN) portant les labels fournis et le QTYPE demandé.
func questionDNSBilan(qtype uint16, labels ...string) []byte {
	var question bytes.Buffer
	// En-tête de 12 octets : identifiant 0x1234, drapeaux RD, QDCOUNT=1.
	question.Write([]byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	for _, label := range labels {
		question.WriteByte(byte(len(label)))
		question.WriteString(label)
	}
	question.WriteByte(0)
	question.WriteByte(byte(qtype >> 8))
	question.WriteByte(byte(qtype))
	question.Write([]byte{0x00, 0x01})
	return question.Bytes()
}

// pipelineBilanContrat crée le pipeline de contrat de la strate : configuration
// par défaut (seuils standard), sans table de réputation externe et sans worker
// d'arbitrage, la file SLM bornée à 64 places restant donc sans consommateur.
func pipelineBilanContrat(t *testing.T) *c2blue55.Pipeline {
	t.Helper()
	pipeline, err := c2blue55.NewPipeline(c2blue55.PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("initialisation du pipeline de contrat : %v", err)
	}
	t.Cleanup(func() { _ = pipeline.Close() })
	return pipeline
}

// tableRefusS3Contrat compile la table de réputation de contrat des cas C05
// et C06 : une entrée bloquante en correspondance de sous-arbre portant sur
// refus-s3.example.
func tableRefusS3Contrat(t *testing.T) *c2blue55.ReputationTable {
	t.Helper()
	instantane, err := c2blue55.CompileReputationSnapshot([]c2blue55.BuildEntry{
		{Domain: "refus-s3.example", Classification: c2blue55.RepClassBlockC2, MatchKind: c2blue55.MatchSubtree},
	})
	if err != nil {
		t.Fatalf("compilation de l'instantané de réputation : %v", err)
	}
	table, err := c2blue55.NewReputationTable(instantane)
	if err != nil {
		t.Fatalf("chargement de la table de réputation : %v", err)
	}
	return table
}

// ecrivainEnErreur est un io.Writer de contrat dont toute écriture échoue,
// utilisé pour prouver que ecrireBilan rend l'erreur de son support d'écriture.
type ecrivainEnErreur struct{}

func (ecrivainEnErreur) Write(_ []byte) (int, error) {
	return 0, errors.New("écriture refusée par l'écrivain de contrat")
}

// TestEcouteBilanContrat transcrit les cas prescrits C01 à C07 de la strate
// L1-S3 sur traiterDatagramme et ecrireBilan.
func TestEcouteBilanContrat(t *testing.T) {
	t.Run("C01", func(t *testing.T) {
		pipeline := pipelineBilanContrat(t)
		compteurs := &compteursEcoute{}
		sortie := &bytes.Buffer{}
		question := questionDNSBilan(c2blue55.TypeA, "www", "example", "com")
		traiterDatagramme(pipeline, question, 1000, compteurs, sortie, true)
		if got := compteurs.passes.Load(); got != 1 {
			t.Errorf("passes = %d ; attendu 1", got)
		}
		if got := compteurs.refus.Load(); got != 0 {
			t.Errorf("refus = %d ; attendu 0", got)
		}
		if got := compteurs.escalades.Load(); got != 0 {
			t.Errorf("escalades = %d ; attendu 0", got)
		}
		if got := compteurs.erreursAnalyse.Load(); got != 0 {
			t.Errorf("erreursAnalyse = %d ; attendu 0", got)
		}
		if got := compteurs.escaladesRejetees.Load(); got != 0 {
			t.Errorf("escaladesRejetees = %d ; attendu 0", got)
		}
		if sortie.Len() != 0 {
			t.Errorf("sortie = %q ; attendu vide (pas de correspondance de réputation)", sortie.String())
		}
	})

	t.Run("C02", func(t *testing.T) {
		pipeline := pipelineBilanContrat(t)
		compteurs := &compteursEcoute{}
		sortie := &bytes.Buffer{}
		invalideCourt := []byte{0xde, 0xad, 0xbe, 0xef, 0x00}
		invalideBinaire := questionDNSBilan(1, "a\x80b", "exemple", "test")

		traiterDatagramme(pipeline, invalideCourt, 1000, compteurs, sortie, false)
		traiterDatagramme(pipeline, invalideBinaire, 1000, compteurs, sortie, false)
		if got := compteurs.erreursAnalyse.Load(); got != 2 {
			t.Errorf("erreursAnalyse = %d ; attendu 2", got)
		}
		if compteurs.passes.Load() != 0 || compteurs.refus.Load() != 0 ||
			compteurs.escalades.Load() != 0 || compteurs.escaladesRejetees.Load() != 0 {
			t.Errorf("issues positives ou d'escalade comptées sur datagrammes invalides : passes=%d refus=%d escalades=%d escaladesRejetees=%d ; attendu 0 partout",
				compteurs.passes.Load(), compteurs.refus.Load(), compteurs.escalades.Load(), compteurs.escaladesRejetees.Load())
		}
		if sortie.Len() != 0 {
			t.Errorf("verbeux faux : sortie = %q ; attendu vide (D-C2B-L1-03)", sortie.String())
		}

		traiterDatagramme(pipeline, invalideCourt, 1001, compteurs, sortie, true)
		traiterDatagramme(pipeline, invalideBinaire, 1001, compteurs, sortie, true)
		if got := compteurs.erreursAnalyse.Load(); got != 4 {
			t.Errorf("erreursAnalyse = %d après quatre datagrammes invalides ; attendu 4", got)
		}
		lignes := strings.Split(strings.TrimRight(sortie.String(), "\n"), "\n")
		if len(lignes) != 2 {
			t.Fatalf("lignes écrites = %d ; attendu 2\n%s", len(lignes), sortie.String())
		}
		for _, ligne := range lignes {
			if !strings.HasPrefix(ligne, "[ERREUR ANALYSE] ") {
				t.Errorf("ligne = %q ; attendu préfixe « [ERREUR ANALYSE] » suivi du texte de l'erreur", ligne)
			}
		}
	})

	t.Run("C03", func(t *testing.T) {
		pipeline := pipelineBilanContrat(t)
		compteurs := &compteursEcoute{}
		sortie := &bytes.Buffer{}
		questionPremiere := questionDNSBilan(c2blue55.TypeTXT, fmt.Sprintf("%040x", 0), "exemple", "test")
		traiterDatagramme(pipeline, questionPremiere, 1000, compteurs, sortie, false)
		if got := compteurs.escalades.Load(); got != 1 {
			t.Errorf("escalades = %d après le premier datagramme ; attendu 1", got)
		}
		for indice := 1; indice < 80; indice++ {
			etiquette := fmt.Sprintf("%040x", indice)
			question := questionDNSBilan(c2blue55.TypeTXT, etiquette, "exemple", "test")
			traiterDatagramme(pipeline, question, uint32(1000+indice), compteurs, sortie, false)
		}
		if got := compteurs.escalades.Load(); got != 80 {
			t.Errorf("escalades = %d ; attendu 80", got)
		}
		if got := compteurs.escaladesRejetees.Load(); got != 16 {
			t.Errorf("escaladesRejetees = %d ; attendu 16", got)
		}
		if got := compteurs.erreursAnalyse.Load(); got != 0 {
			t.Errorf("erreursAnalyse = %d ; attendu 0 (aucune escalade rejetée confondue avec un paquet corrompu)", got)
		}
		if compteurs.passes.Load() != 0 || compteurs.refus.Load() != 0 {
			t.Errorf("passes=%d refus=%d ; attendu 0 partout", compteurs.passes.Load(), compteurs.refus.Load())
		}
		// Les 64 premières questions remplissent la file d'arbitrage de 64
		// places ; les 16 suivantes sont rejetées sans être comptées corrompues.
		// La première ligne d'escalade porte le FQDN complet de la première
		// question et la première ligne de rejet celui de la 65e question.
		fqdnPremiere := fmt.Sprintf("%040x.exemple.test", 0)
		fqdnSoixanteCinquieme := fmt.Sprintf("%040x.exemple.test", 64)
		escaladesAffichees, rejetsAffiches := 0, 0
		ligneEscaladePremiere, ligneRejetPremiere := "", ""
		for ligne := range strings.SplitSeq(sortie.String(), "\n") {
			if strings.HasPrefix(ligne, "[GREY ZONE ESCALADE] ") {
				escaladesAffichees++
				if ligneEscaladePremiere == "" {
					ligneEscaladePremiere = ligne
				}
			}
			if strings.HasPrefix(ligne, "[ESCALADE REJETEE: FILE PLEINE] ") {
				rejetsAffiches++
				if ligneRejetPremiere == "" {
					ligneRejetPremiere = ligne
				}
			}
		}
		if escaladesAffichees != 64 {
			t.Errorf("lignes « [GREY ZONE ESCALADE] » = %d ; attendu 64\n%s", escaladesAffichees, sortie.String())
		}
		if rejetsAffiches != 16 {
			t.Errorf("lignes « [ESCALADE REJETEE: FILE PLEINE] » = %d ; attendu 16\n%s", rejetsAffiches, sortie.String())
		}
		if !strings.Contains(ligneEscaladePremiere, fqdnPremiere) {
			t.Errorf("première ligne d'escalade = %q ; attendu le FQDN complet de la première question %q", ligneEscaladePremiere, fqdnPremiere)
		}
		if !strings.Contains(ligneRejetPremiere, fqdnSoixanteCinquieme) {
			t.Errorf("première ligne de rejet = %q ; attendu le FQDN complet de la 65e question %q", ligneRejetPremiere, fqdnSoixanteCinquieme)
		}
	})

	t.Run("C04", func(t *testing.T) {
		compteurs := &compteursEcoute{}
		compteurs.passes.Store(3)
		compteurs.refus.Store(1)
		compteurs.escalades.Store(2)
		compteurs.erreursAnalyse.Store(4)
		compteurs.escaladesRejetees.Store(1)
		var tampon bytes.Buffer
		err := compteurs.ecrireBilan(&tampon)
		if err != nil {
			t.Errorf("ecrireBilan = %v ; attendu nil", err)
		}
		attendu := "[c2agent] bilan: passes=3 refus=1 escalades=2 erreurs_analyse=4 escalades_rejetees=1\n"
		if tampon.String() != attendu {
			t.Errorf("bilan = %q ; attendu exactement %q", tampon.String(), attendu)
		}
		if err := compteurs.ecrireBilan(ecrivainEnErreur{}); err == nil {
			t.Errorf("ecrireBilan sur un écrivain en erreur = nil ; attendu une erreur non nulle")
		}
	})

	t.Run("C05", func(t *testing.T) {
		pipeline, err := c2blue55.NewPipeline(c2blue55.PipelineConfig{}, tableRefusS3Contrat(t))
		if err != nil {
			t.Fatalf("initialisation du pipeline C05 : %v", err)
		}
		t.Cleanup(func() {
			if err := pipeline.Close(); err != nil {
				t.Logf("fermeture du pipeline C05 : %v", err)
			}
		})
		compteurs := &compteursEcoute{}
		sortie := &bytes.Buffer{}
		question := questionDNSBilan(c2blue55.TypeA, "x", "refus-s3", "example")
		traiterDatagramme(pipeline, question, 1000, compteurs, sortie, false)
		if got := compteurs.refus.Load(); got != 1 {
			t.Errorf("refus = %d ; attendu 1", got)
		}
		if got := compteurs.passes.Load(); got != 0 {
			t.Errorf("passes = %d ; attendu 0", got)
		}
		if got := compteurs.escalades.Load(); got != 0 {
			t.Errorf("escalades = %d ; attendu 0", got)
		}
		if got := compteurs.erreursAnalyse.Load(); got != 0 {
			t.Errorf("erreursAnalyse = %d ; attendu 0", got)
		}
		if got := compteurs.escaladesRejetees.Load(); got != 0 {
			t.Errorf("escaladesRejetees = %d ; attendu 0", got)
		}
		attendu := "[OBSERVATION: REFUS RECOMMANDE, NON APPLIQUE] refus-s3.example (correspondance reputation)\n"
		if sortie.String() != attendu {
			t.Errorf("sortie = %q ; attendu exactement %q", sortie.String(), attendu)
		}
	})

	t.Run("C06", func(t *testing.T) {
		pipeline, err := c2blue55.NewPipeline(c2blue55.PipelineConfig{LogPath: "/dev/full"}, tableRefusS3Contrat(t))
		if err != nil {
			t.Fatalf("initialisation du pipeline C06 : %v", err)
		}
		t.Cleanup(func() {
			if err := pipeline.Close(); err != nil {
				t.Logf("fermeture du pipeline C06 : %v", err)
			}
		})
		compteurs := &compteursEcoute{}
		sortie := &bytes.Buffer{}
		question := questionDNSBilan(c2blue55.TypeA, "x", "refus-s3", "example")
		traiterDatagramme(pipeline, question, 1000, compteurs, sortie, false)
		appels := 1
		if got := compteurs.refus.Load(); got != 1 {
			t.Errorf("refus = %d après le premier datagramme ; attendu 1", got)
		}
		// Le deuxième appel est inconditionnel : l'échec d'écriture du journal
		// d'audit est asynchrone, la scrutation pourrait donc s'arrêter
		// immédiatement, et le cas exige au moins trois appels au total pour
		// prouver l'unicité du signalement.
		traiterDatagramme(pipeline, question, uint32(1000+appels), compteurs, sortie, false)
		appels++
		echeance := time.Now().Add(5 * time.Second)
		for pipeline.AuditError() == nil && time.Now().Before(echeance) {
			time.Sleep(10 * time.Millisecond)
			traiterDatagramme(pipeline, question, uint32(1000+appels), compteurs, sortie, false)
			appels++
		}
		if pipeline.AuditError() == nil {
			t.Fatalf("AuditError resté nul après la scrutation bornée à 5 secondes (%d appels)", appels)
		}
		traiterDatagramme(pipeline, question, uint32(1000+appels), compteurs, sortie, false)
		appels++
		if appels < 3 {
			t.Errorf("appels = %d ; attendu au moins 3", appels)
		}
		if got := compteurs.refus.Load(); got != uint64(appels) {
			t.Errorf("refus = %d ; attendu %d (un par datagramme reçu)", got, appels)
		}
		if got := compteurs.erreursAnalyse.Load(); got != 0 {
			t.Errorf("erreursAnalyse = %d ; attendu 0 (échec de journal d'audit non confondu avec une erreur d'analyse)", got)
		}
		if compteurs.passes.Load() != 0 || compteurs.escalades.Load() != 0 || compteurs.escaladesRejetees.Load() != 0 {
			t.Errorf("issues parasites comptées : passes=%d escalades=%d escaladesRejetees=%d ; attendu 0 partout",
				compteurs.passes.Load(), compteurs.escalades.Load(), compteurs.escaladesRejetees.Load())
		}
		observations, journaux := 0, 0
		for ligne := range strings.SplitSeq(sortie.String(), "\n") {
			if strings.HasPrefix(ligne, "[OBSERVATION: REFUS RECOMMANDE, NON APPLIQUE]") {
				observations++
			}
			if strings.HasPrefix(ligne, "[JOURNAL D'AUDIT EN ERREUR]") {
				journaux++
			}
		}
		if observations != appels {
			t.Errorf("lignes d'observation de refus = %d ; attendu %d\n%s", observations, appels, sortie.String())
		}
		if journaux != 1 {
			t.Errorf("lignes « [JOURNAL D'AUDIT EN ERREUR] » = %d ; attendu exactement 1 (un seul signalement, au premier échec)\n%s", journaux, sortie.String())
		}
	})

	t.Run("C07", func(t *testing.T) {
		pipeline, err := c2blue55.NewPipeline(c2blue55.PipelineConfig{LogPath: "/dev/full"}, tableRefusS3Contrat(t))
		if err != nil {
			t.Fatalf("initialisation du pipeline C07 : %v", err)
		}
		t.Cleanup(func() {
			if err := pipeline.Close(); err != nil {
				t.Logf("fermeture du pipeline C07 : %v", err)
			}
		})
		question := questionDNSBilan(c2blue55.TypeA, "x", "refus-s3", "example")
		// Établissement de l'erreur de journal comme en C06 : scrutation bornée
		// de AuditError avec des compteurs et un tampon à part, non comptés.
		compteursAmorce := &compteursEcoute{}
		sortieAmorce := &bytes.Buffer{}
		appelsAmorce := 0
		echeance := time.Now().Add(5 * time.Second)
		for pipeline.AuditError() == nil && time.Now().Before(echeance) {
			time.Sleep(10 * time.Millisecond)
			appelsAmorce++
			traiterDatagramme(pipeline, question, uint32(1000+appelsAmorce), compteursAmorce, sortieAmorce, false)
		}
		if pipeline.AuditError() == nil {
			t.Fatalf("AuditError resté nul après la scrutation bornée à 5 secondes (%d appels d'amorce)", appelsAmorce)
		}
		// Premier appel de premier niveau : la sortie échoue, le signalement
		// perdu du journal en erreur doit être remis à faux pour être retenté
		// par le refus suivant.
		compteurs := &compteursEcoute{}
		traiterDatagramme(pipeline, question, 2000, compteurs, ecrivainEnErreur{}, false)
		if got := compteurs.refus.Load(); got != 1 {
			t.Errorf("refus = %d après le premier appel ; attendu 1", got)
		}
		// Second appel de premier niveau : le tampon doit porter la ligne
		// d'observation de refus et le signalement retenté avec succès.
		sortie := &bytes.Buffer{}
		traiterDatagramme(pipeline, question, 2001, compteurs, sortie, false)
		if got := compteurs.refus.Load(); got != 2 {
			t.Errorf("refus = %d après le second appel ; attendu 2", got)
		}
		if got := compteurs.erreursAnalyse.Load(); got != 0 {
			t.Errorf("erreursAnalyse = %d ; attendu 0 (échec de journal d'audit non confondu avec une erreur d'analyse)", got)
		}
		observations, journaux := 0, 0
		for ligne := range strings.SplitSeq(sortie.String(), "\n") {
			if strings.HasPrefix(ligne, "[OBSERVATION: REFUS RECOMMANDE, NON APPLIQUE]") {
				observations++
			}
			if strings.HasPrefix(ligne, "[JOURNAL D'AUDIT EN ERREUR]") {
				journaux++
			}
		}
		if observations != 1 {
			t.Errorf("lignes d'observation de refus = %d ; attendu 1\n%s", observations, sortie.String())
		}
		if journaux != 1 {
			t.Errorf("lignes « [JOURNAL D'AUDIT EN ERREUR] » = %d ; attendu exactement 1 (signalement perdu au premier appel retenté)\n%s", journaux, sortie.String())
		}
	})
}
