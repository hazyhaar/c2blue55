// Package enveloppedepot localise l'enveloppe du projet (le répertoire qui
// contient le dépôt canonique et les données hors dépôt, dont wittgenstein)
// depuis n'importe quel arbre de travail Git du dépôt, quel que soit
// l'emplacement de cet arbre sur le disque.
//
// Un arbre lié (git worktree) porte un fichier .git de la forme
// « gitdir: <dépôt principal>/.git/worktrees/<nom> » : le dépôt principal s'en
// déduit sans exécuter git, donc sans dépendre du chemin de l'arbre lui-même.
package enveloppedepot

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// tailleMaxFichierGit borne la lecture du fichier .git d'un arbre lié.
const tailleMaxFichierGit = 4096

// ErrDepotIntrouvable signale l'absence de .git exploitable au-dessus du répertoire donné.
var ErrDepotIntrouvable = errors.New("enveloppedepot: aucun dépôt Git exploitable au-dessus du répertoire")

// RacineDepotPrincipal rend la racine du dépôt principal dont dépend l'arbre de
// travail contenant repertoire : la racine de l'arbre lui-même s'il porte un
// répertoire .git, sinon le dépôt désigné par son fichier .git d'arbre lié.
func RacineDepotPrincipal(repertoire string) (string, error) {
	courant, err := filepath.Abs(repertoire)
	if err != nil {
		return "", fmt.Errorf("enveloppedepot: chemin absolu de %s: %w", repertoire, err)
	}
	for {
		marqueur := filepath.Join(courant, ".git")
		info, errStat := os.Lstat(marqueur)
		if errStat == nil {
			if info.IsDir() {
				return courant, nil
			}
			if !info.Mode().IsRegular() {
				return "", fmt.Errorf("%w: %s n'est ni un répertoire ni un fichier régulier", ErrDepotIntrouvable, marqueur)
			}
			return racineDepuisFichierGit(marqueur)
		}
		if !errors.Is(errStat, fs.ErrNotExist) {
			return "", fmt.Errorf("enveloppedepot: examen de %s: %w", marqueur, errStat)
		}
		parent := filepath.Dir(courant)
		if parent == courant {
			return "", fmt.Errorf("%w: %s: %w", ErrDepotIntrouvable, repertoire, errStat)
		}
		courant = parent
	}
}

// racineDepuisFichierGit lit « gitdir: <principal>/.git/worktrees/<nom> » et rend <principal>.
func racineDepuisFichierGit(marqueur string) (racine string, err error) {
	racineArbre, err := os.OpenRoot(filepath.Dir(marqueur))
	if err != nil {
		return "", fmt.Errorf("enveloppedepot: ouverture de %s: %w", filepath.Dir(marqueur), err)
	}
	defer func() {
		if errFermeture := racineArbre.Close(); errFermeture != nil {
			err = errors.Join(err, fmt.Errorf("enveloppedepot: fermeture de %s: %w", filepath.Dir(marqueur), errFermeture))
		}
	}()
	fichier, err := racineArbre.Open(filepath.Base(marqueur))
	if err != nil {
		return "", fmt.Errorf("enveloppedepot: ouverture de %s: %w", marqueur, err)
	}
	defer func() {
		if errFermeture := fichier.Close(); errFermeture != nil {
			err = errors.Join(err, fmt.Errorf("enveloppedepot: fermeture de %s: %w", marqueur, errFermeture))
		}
	}()
	contenu, err := io.ReadAll(io.LimitReader(fichier, tailleMaxFichierGit+1))
	if err != nil {
		return "", fmt.Errorf("enveloppedepot: lecture de %s: %w", marqueur, err)
	}
	if len(contenu) > tailleMaxFichierGit {
		return "", fmt.Errorf("%w: %s dépasse %d octets", ErrDepotIntrouvable, marqueur, tailleMaxFichierGit)
	}
	ligne, _, _ := bytes.Cut(contenu, []byte("\n"))
	cible, trouve := strings.CutPrefix(strings.TrimSpace(string(ligne)), "gitdir:")
	if !trouve {
		return "", fmt.Errorf("%w: %s sans ligne gitdir", ErrDepotIntrouvable, marqueur)
	}
	cible = strings.TrimSpace(cible)
	if !filepath.IsAbs(cible) {
		cible = filepath.Join(filepath.Dir(marqueur), cible)
	}
	cible = filepath.Clean(cible)
	repertoireArbres := filepath.Dir(cible)
	repertoireGit := filepath.Dir(repertoireArbres)
	if filepath.Base(repertoireArbres) != "worktrees" || filepath.Base(repertoireGit) != ".git" {
		return "", fmt.Errorf("%w: %s désigne %s, forme <principal>/.git/worktrees/<nom> attendue", ErrDepotIntrouvable, marqueur, cible)
	}
	return filepath.Dir(repertoireGit), nil
}

// CheminDansEnveloppe rend le chemin de elements sous l'enveloppe du projet,
// c'est-à-dire sous le parent du dépôt principal de l'arbre contenant repertoire.
func CheminDansEnveloppe(repertoire string, elements ...string) (string, error) {
	racine, err := RacineDepotPrincipal(repertoire)
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{filepath.Dir(racine)}, elements...)...), nil
}

// CandidatDansEnveloppe rend CheminDansEnveloppe, ou le chemin de elements sous
// repertoire lorsque le dépôt principal est introuvable : l'appelant qui
// éprouve une liste de candidats par os.Stat n'a pas d'erreur à traiter.
func CandidatDansEnveloppe(repertoire string, elements ...string) string {
	chemin, err := CheminDansEnveloppe(repertoire, elements...)
	if err != nil {
		return filepath.Join(append([]string{repertoire}, elements...)...)
	}
	return chemin
}
