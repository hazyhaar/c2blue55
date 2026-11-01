// Package ecritureatomique publie un fichier par remplacement atomique.
package ecritureatomique

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Ecrire remplace destination par contenu, en mode 0600, sans créer son parent.
// Le contexte est contrôlé à l'entrée et juste avant le renommage. Après celui-ci,
// une erreur indique explicitement que la publication a déjà eu lieu : elle ne
// signifie pas que l'ancien fichier a été restauré.
func Ecrire(ctx context.Context, destination string, contenu []byte) (retour error) {
	if ctx == nil {
		return errors.New("écriture atomique : contexte nil")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("écriture atomique : contexte refusé : %w", err)
	}
	if destination == "" {
		return errors.New("écriture atomique : destination vide")
	}
	statut, err := os.Lstat(destination)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("examiner la destination %q : %w", destination, err)
	}
	if err == nil && statut.IsDir() {
		return fmt.Errorf("destination %q refusée : répertoire", destination)
	}

	parent := filepath.Dir(destination)
	repertoire, err := os.Open(parent)
	if err != nil {
		return fmt.Errorf("ouvrir le parent %q : %w", parent, err)
	}
	publie := false
	defer func() {
		if err := repertoire.Close(); err != nil {
			if publie {
				retour = errors.Join(retour, fmt.Errorf("publication déjà effectuée vers %q ; fermer le parent %q : %w", destination, parent, err))
			} else {
				retour = errors.Join(retour, fmt.Errorf("fermer le parent %q : %w", parent, err))
			}
		}
	}()

	temporaire, err := os.CreateTemp(parent, ".ecritureatomique-*")
	if err != nil {
		return fmt.Errorf("créer le temporaire dans %q : %w", parent, err)
	}
	cheminTemporaire := temporaire.Name()
	defer func() {
		if temporaire != nil {
			if err := temporaire.Close(); err != nil {
				retour = errors.Join(retour, fmt.Errorf("fermer le temporaire %q : %w", cheminTemporaire, err))
			}
		}
		if !publie {
			if err := os.Remove(cheminTemporaire); err != nil {
				retour = errors.Join(retour, fmt.Errorf("nettoyer le temporaire %q : %w", cheminTemporaire, err))
			}
		}
	}()

	for reste := contenu; len(reste) > 0; {
		ecrits, err := temporaire.Write(reste)
		if err != nil {
			return fmt.Errorf("écrire le temporaire %q : %w", cheminTemporaire, err)
		}
		if ecrits == 0 {
			return fmt.Errorf("écrire le temporaire %q : %w", cheminTemporaire, io.ErrShortWrite)
		}
		reste = reste[ecrits:]
	}
	if err := temporaire.Chmod(0o600); err != nil {
		return fmt.Errorf("imposer le mode 0600 au temporaire %q : %w", cheminTemporaire, err)
	}
	if err := temporaire.Sync(); err != nil {
		return fmt.Errorf("synchroniser le temporaire %q : %w", cheminTemporaire, err)
	}
	err = temporaire.Close()
	// Close invalide le descripteur même lorsqu'il rend une erreur.
	temporaire = nil
	if err != nil {
		return fmt.Errorf("fermer le temporaire %q : %w", cheminTemporaire, err)
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("publication annulée vers %q : %w", destination, err)
	}
	if err := os.Rename(cheminTemporaire, destination); err != nil {
		return fmt.Errorf("publier vers %q : %w", destination, err)
	}
	publie = true
	if err := repertoire.Sync(); err != nil {
		return fmt.Errorf("publication déjà effectuée vers %q ; synchroniser le parent %q : %w", destination, parent, err)
	}
	return nil
}
