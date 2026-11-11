package enveloppedepot

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// phraseSentinelle est le fragment distinctif du message porté par
// ErrDepotIntrouvable : chaque cas négatif vérifie que l'erreur rendue le
// transporte, au-delà de la seule identité de la sentinelle.
const phraseSentinelle = "aucun dépôt Git exploitable au-dessus du répertoire"

// ecrireMarqueurGit prépare sous t un arbre de travail portant un marqueur
// .git au contenu donné ; tout échec de préparation interrompt le cas par
// t.Fatalf.
func ecrireMarqueurGit(t *testing.T, arbre, contenuMarqueur string) {
	t.Helper()
	if errPreparation := os.MkdirAll(arbre, 0o750); !errors.Is(errPreparation, nil) {
		t.Fatalf("préparation de %s: %v", arbre, errPreparation)
	}
	cheminMarqueur := filepath.Join(arbre, ".git")
	if errPreparation := os.WriteFile(cheminMarqueur, []byte(contenuMarqueur), 0o600); !errors.Is(errPreparation, nil) {
		t.Fatalf("préparation de %s: %v", cheminMarqueur, errPreparation)
	}
}

// TestEnveloppeDepotContratL1S5 éprouve le contrat de la strate L1-S5 :
// RacineDepotPrincipal, CheminDansEnveloppe et CandidatDansEnveloppe
// localisent l'enveloppe du projet depuis tout arbre de travail lié, et
// refusent franc tout marqueur .git qui ne désigne pas
// <principal>/.git/worktrees/<nom>.
func TestEnveloppeDepotContratL1S5(t *testing.T) {
	t.Run("C01", func(t *testing.T) {
		base := t.TempDir()
		principal := filepath.Join(base, "projet", "depot")
		arbreAilleurs := filepath.Join(base, "ailleurs", "profond", "arbre")
		arbreRelatif := filepath.Join(base, "projet", "desks", "coding", "tree")
		departPrincipal := filepath.Join(principal, "internal", "x")
		departAilleurs := filepath.Join(arbreAilleurs, "cmd", "y")
		enveloppeAttendue := filepath.Join(base, "projet", "wittgenstein", "redhost_lab")
		cheminWorktreesLie := filepath.Join(principal, ".git", "worktrees", "lie")
		if errPreparation := os.MkdirAll(cheminWorktreesLie, 0o750); !errors.Is(errPreparation, nil) {
			t.Fatalf("C01: création de %s: %v", cheminWorktreesLie, errPreparation)
		}
		ecrireMarqueurGit(t, arbreAilleurs, "gitdir: "+filepath.Join(principal, ".git", "worktrees", "lie")+"\n")
		ecrireMarqueurGit(t, arbreRelatif, "gitdir: ../../../depot/.git/worktrees/lie\n")
		if errPreparation := os.MkdirAll(departPrincipal, 0o750); !errors.Is(errPreparation, nil) {
			t.Fatalf("C01: création de %s: %v", departPrincipal, errPreparation)
		}
		if errPreparation := os.MkdirAll(departAilleurs, 0o750); !errors.Is(errPreparation, nil) {
			t.Fatalf("C01: création de %s: %v", departAilleurs, errPreparation)
		}
		cheminPrincipal, errPrincipal := CheminDansEnveloppe(departPrincipal, "wittgenstein", "redhost_lab")
		if !errors.Is(errPrincipal, nil) {
			t.Errorf("C01: CheminDansEnveloppe(%s): %v", departPrincipal, errPrincipal)
		}
		if cheminPrincipal != enveloppeAttendue {
			t.Errorf("C01: CheminDansEnveloppe(%s): %s au lieu de %s", departPrincipal, cheminPrincipal, enveloppeAttendue)
		}
		cheminAilleurs, errAilleurs := CheminDansEnveloppe(departAilleurs, "wittgenstein", "redhost_lab")
		if !errors.Is(errAilleurs, nil) {
			t.Errorf("C01: CheminDansEnveloppe(%s): %v", departAilleurs, errAilleurs)
		}
		if cheminAilleurs != enveloppeAttendue {
			t.Errorf("C01: CheminDansEnveloppe(%s): %s au lieu de %s", departAilleurs, cheminAilleurs, enveloppeAttendue)
		}
		cheminRelatif, errRelatif := CheminDansEnveloppe(arbreRelatif, "wittgenstein", "redhost_lab")
		if !errors.Is(errRelatif, nil) {
			t.Errorf("C01: CheminDansEnveloppe(%s): %v", arbreRelatif, errRelatif)
		}
		if cheminRelatif != enveloppeAttendue {
			t.Errorf("C01: CheminDansEnveloppe(%s): %s au lieu de %s", arbreRelatif, cheminRelatif, enveloppeAttendue)
		}
		racineDepuisPrincipal, errRacineDepuisPrincipal := RacineDepotPrincipal(departPrincipal)
		if !errors.Is(errRacineDepuisPrincipal, nil) {
			t.Errorf("C01: RacineDepotPrincipal(%s): %v", departPrincipal, errRacineDepuisPrincipal)
		}
		if racineDepuisPrincipal != principal {
			t.Errorf("C01: RacineDepotPrincipal(%s): %s au lieu de %s", departPrincipal, racineDepuisPrincipal, principal)
		}
		racineDepuisAilleurs, errRacineDepuisAilleurs := RacineDepotPrincipal(departAilleurs)
		if !errors.Is(errRacineDepuisAilleurs, nil) {
			t.Errorf("C01: RacineDepotPrincipal(%s): %v", departAilleurs, errRacineDepuisAilleurs)
		}
		if racineDepuisAilleurs != principal {
			t.Errorf("C01: RacineDepotPrincipal(%s): %s au lieu de %s", departAilleurs, racineDepuisAilleurs, principal)
		}
		racineDepuisRelatif, errRacineDepuisRelatif := RacineDepotPrincipal(arbreRelatif)
		if !errors.Is(errRacineDepuisRelatif, nil) {
			t.Errorf("C01: RacineDepotPrincipal(%s): %v", arbreRelatif, errRacineDepuisRelatif)
		}
		if racineDepuisRelatif != principal {
			t.Errorf("C01: RacineDepotPrincipal(%s): %s au lieu de %s", arbreRelatif, racineDepuisRelatif, principal)
		}
	})
	t.Run("C02", func(t *testing.T) {
		base := t.TempDir()
		arbreSansGitdir := filepath.Join(base, "arbre-sans-gitdir")
		arbreSousModule := filepath.Join(base, "arbre-sous-module")
		arbreGrandParent := filepath.Join(base, "arbre-grand-parent")
		arbreSurdimensionne := filepath.Join(base, "arbre-surdimensionne")
		arbreLienSymbolique := filepath.Join(base, "arbre-lien-symbolique")
		ecrireMarqueurGit(t, arbreSansGitdir, "ref: refs/heads/main\n")
		ecrireMarqueurGit(t, arbreSousModule, "gitdir: "+filepath.Join(base, "p", ".git", "modules", "m")+"\n")
		ecrireMarqueurGit(t, arbreGrandParent, "gitdir: "+filepath.Join(base, "p", "autre", "worktrees", "m")+"\n")
		ecrireMarqueurGit(t, arbreSurdimensionne, "gitdir: /"+strings.Repeat("a", tailleMaxFichierGit))
		if errPreparation := os.MkdirAll(arbreLienSymbolique, 0o750); !errors.Is(errPreparation, nil) {
			t.Fatalf("C02: création de %s: %v", arbreLienSymbolique, errPreparation)
		}
		if errPreparation := os.Symlink("/nulle/part", filepath.Join(arbreLienSymbolique, ".git")); !errors.Is(errPreparation, nil) {
			t.Fatalf("C02: création du lien symbolique sous %s: %v", arbreLienSymbolique, errPreparation)
		}
		renduSansGitdir, errSansGitdir := RacineDepotPrincipal(arbreSansGitdir)
		if !errors.Is(errSansGitdir, ErrDepotIntrouvable) || !strings.Contains(errSansGitdir.Error(), phraseSentinelle) {
			t.Errorf("C02: RacineDepotPrincipal(%s): %v", arbreSansGitdir, errSansGitdir)
		}
		if renduSansGitdir != "" {
			t.Errorf("C02: RacineDepotPrincipal(%s): %s au lieu de chaîne vide", arbreSansGitdir, renduSansGitdir)
		}
		renduSousModule, errSousModule := RacineDepotPrincipal(arbreSousModule)
		if !errors.Is(errSousModule, ErrDepotIntrouvable) || !strings.Contains(errSousModule.Error(), phraseSentinelle) {
			t.Errorf("C02: RacineDepotPrincipal(%s): %v", arbreSousModule, errSousModule)
		}
		if renduSousModule != "" {
			t.Errorf("C02: RacineDepotPrincipal(%s): %s au lieu de chaîne vide", arbreSousModule, renduSousModule)
		}
		renduGrandParent, errGrandParent := RacineDepotPrincipal(arbreGrandParent)
		if !errors.Is(errGrandParent, ErrDepotIntrouvable) || !strings.Contains(errGrandParent.Error(), phraseSentinelle) {
			t.Errorf("C02: RacineDepotPrincipal(%s): %v", arbreGrandParent, errGrandParent)
		}
		if renduGrandParent != "" {
			t.Errorf("C02: RacineDepotPrincipal(%s): %s au lieu de chaîne vide", arbreGrandParent, renduGrandParent)
		}
		renduSurdimensionne, errSurdimensionne := RacineDepotPrincipal(arbreSurdimensionne)
		if !errors.Is(errSurdimensionne, ErrDepotIntrouvable) || !strings.Contains(errSurdimensionne.Error(), phraseSentinelle) {
			t.Errorf("C02: RacineDepotPrincipal(%s): %v", arbreSurdimensionne, errSurdimensionne)
		}
		if renduSurdimensionne != "" {
			t.Errorf("C02: RacineDepotPrincipal(%s): %s au lieu de chaîne vide", arbreSurdimensionne, renduSurdimensionne)
		}
		renduLienSymbolique, errLienSymbolique := RacineDepotPrincipal(arbreLienSymbolique)
		if !errors.Is(errLienSymbolique, ErrDepotIntrouvable) || !strings.Contains(errLienSymbolique.Error(), phraseSentinelle) {
			t.Errorf("C02: RacineDepotPrincipal(%s): %v", arbreLienSymbolique, errLienSymbolique)
		}
		if renduLienSymbolique != "" {
			t.Errorf("C02: RacineDepotPrincipal(%s): %s au lieu de chaîne vide", arbreLienSymbolique, renduLienSymbolique)
		}
		cheminSansGitdir, errCheminSansGitdir := CheminDansEnveloppe(arbreSansGitdir, "wittgenstein")
		if !errors.Is(errCheminSansGitdir, ErrDepotIntrouvable) || !strings.Contains(errCheminSansGitdir.Error(), phraseSentinelle) {
			t.Errorf("C02: CheminDansEnveloppe(%s): %v", arbreSansGitdir, errCheminSansGitdir)
		}
		if cheminSansGitdir != "" {
			t.Errorf("C02: CheminDansEnveloppe(%s): %s au lieu de chaîne vide", arbreSansGitdir, cheminSansGitdir)
		}
	})
	t.Run("C04", func(t *testing.T) {
		base := t.TempDir()
		cheminWorktreeBorne := filepath.Join(base, "projet", "depot", ".git", "worktrees", "lie")
		if errRepertoire := os.MkdirAll(cheminWorktreeBorne, 0o700); errRepertoire != nil {
			t.Fatalf("C04: création de %s: %v", cheminWorktreeBorne, errRepertoire)
		}
		ligneGitdir := "gitdir: " + cheminWorktreeBorne + "\n"
		arbreAuDela := filepath.Join(base, "arbre-au-dela")
		ecrireMarqueurGit(t, arbreAuDela, ligneGitdir+strings.Repeat(" ", tailleMaxFichierGit+1-len(ligneGitdir)))
		arbreALaBorne := filepath.Join(base, "arbre-a-la-borne")
		ecrireMarqueurGit(t, arbreALaBorne, ligneGitdir+strings.Repeat(" ", tailleMaxFichierGit-len(ligneGitdir)))
		racineAuDela, errAuDela := RacineDepotPrincipal(arbreAuDela)
		if racineAuDela != "" {
			t.Errorf("C04: RacineDepotPrincipal(marqueur valide de %d octets) = %q, attendu vide", tailleMaxFichierGit+1, racineAuDela)
		}
		if !errors.Is(errAuDela, ErrDepotIntrouvable) {
			t.Errorf("C04: RacineDepotPrincipal(marqueur valide de %d octets): err = %v, attendu enveloppant ErrDepotIntrouvable", tailleMaxFichierGit+1, errAuDela)
		}
		racineALaBorne, errALaBorne := RacineDepotPrincipal(arbreALaBorne)
		if errALaBorne != nil {
			t.Errorf("C04: RacineDepotPrincipal(marqueur valide de %d octets): %v, attendu nil", tailleMaxFichierGit, errALaBorne)
		}
		if racineALaBorne != filepath.Join(base, "projet", "depot") {
			t.Errorf("C04: RacineDepotPrincipal(marqueur valide de %d octets) = %q, attendu %q", tailleMaxFichierGit, racineALaBorne, filepath.Join(base, "projet", "depot"))
		}
	})

	t.Run("C03", func(t *testing.T) {
		base := t.TempDir()
		principal := filepath.Join(base, "projet", "depot")
		arbreAilleurs := filepath.Join(base, "ailleurs", "profond", "arbre")
		cheminWorktreesLie := filepath.Join(principal, ".git", "worktrees", "lie")
		if errPreparation := os.MkdirAll(cheminWorktreesLie, 0o750); !errors.Is(errPreparation, nil) {
			t.Fatalf("C03: création de %s: %v", cheminWorktreesLie, errPreparation)
		}
		ecrireMarqueurGit(t, arbreAilleurs, "gitdir: "+filepath.Join(principal, ".git", "worktrees", "lie")+"\n")
		baseSansGitdir := t.TempDir()
		arbreSansGitdir := filepath.Join(baseSansGitdir, "arbre-sans-gitdir")
		ecrireMarqueurGit(t, arbreSansGitdir, "ref: refs/heads/main\n")
		candidatEnveloppe := CandidatDansEnveloppe(arbreAilleurs, "wittgenstein")
		if candidatEnveloppe != filepath.Join(base, "projet", "wittgenstein") {
			t.Errorf("C03: CandidatDansEnveloppe(%s): %s au lieu de %s", arbreAilleurs, candidatEnveloppe, filepath.Join(base, "projet", "wittgenstein"))
		}
		candidatSansGitdir := CandidatDansEnveloppe(arbreSansGitdir, "wittgenstein")
		if candidatSansGitdir != filepath.Join(arbreSansGitdir, "wittgenstein") {
			t.Errorf("C03: CandidatDansEnveloppe(%s): %s au lieu de %s", arbreSansGitdir, candidatSansGitdir, filepath.Join(arbreSansGitdir, "wittgenstein"))
		}
	})
}
