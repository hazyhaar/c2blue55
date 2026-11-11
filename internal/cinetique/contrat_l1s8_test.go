//go:build linux

package cinetique_test

import (
	"testing"

	"github.com/hazyhaar/c2blue55/internal/cinetique"
)

// TestAttenteFileDominanteContratL1S8 éprouve le contrat de la méthode
// PreuveArchetypeReel.AttenteFileDominante prescrite par la strate L1-S8 :
// l'attente en file d'exécution est dominante dès qu'elle vaut au moins le
// dixième de la durée d'horloge de l'épisode, borne incluse, et une durée
// d'horloge nulle n'a jamais d'attente dominante.
func TestAttenteFileDominanteContratL1S8(t *testing.T) {
	t.Run("C01", func(t *testing.T) {
		preuveEpisodeCharge := cinetique.PreuveArchetypeReel{DureeHorlogeUs: 43189, AttenteFileUs: 16486}
		dominanteEpisodeCharge := preuveEpisodeCharge.AttenteFileDominante()
		if !dominanteEpisodeCharge {
			t.Fatalf("AttenteFileDominante attendu true pour duree_horloge=43189us attente_file=16486us (164860 >= 43189), obtenu %v", dominanteEpisodeCharge)
		}
		preuveBorneIncluse := cinetique.PreuveArchetypeReel{DureeHorlogeUs: 1000, AttenteFileUs: 100}
		dominanteBorneIncluse := preuveBorneIncluse.AttenteFileDominante()
		if !dominanteBorneIncluse {
			t.Fatalf("AttenteFileDominante attendu true a la borne incluse pour duree_horloge=1000us attente_file=100us (1000 >= 1000), obtenu %v", dominanteBorneIncluse)
		}
	})
	t.Run("C02", func(t *testing.T) {
		preuveSousSeuil := cinetique.PreuveArchetypeReel{DureeHorlogeUs: 1000, AttenteFileUs: 99}
		dominanteSousSeuil := preuveSousSeuil.AttenteFileDominante()
		if dominanteSousSeuil {
			t.Fatalf("AttenteFileDominante attendu false sous le dixieme pour duree_horloge=1000us attente_file=99us (990 < 1000), obtenu %v", dominanteSousSeuil)
		}
		preuveSansAttente := cinetique.PreuveArchetypeReel{DureeHorlogeUs: 5178, AttenteFileUs: 0}
		dominanteSansAttente := preuveSansAttente.AttenteFileDominante()
		if dominanteSansAttente {
			t.Fatalf("AttenteFileDominante attendu false pour attente en file nulle duree_horloge=5178us attente_file=0us, obtenu %v", dominanteSansAttente)
		}
		preuveDureeNulle := cinetique.PreuveArchetypeReel{}
		dominanteDureeNulle := preuveDureeNulle.AttenteFileDominante()
		if dominanteDureeNulle {
			t.Fatalf("AttenteFileDominante attendu false pour duree d'horloge nulle (preuve vide), obtenu %v", dominanteDureeNulle)
		}
		preuveTemoinContention := cinetique.PreuveArchetypeReel{DureeHorlogeUs: 1000, AttenteFileUs: 500}
		dominanteTemoinContention := preuveTemoinContention.AttenteFileDominante()
		if !dominanteTemoinContention {
			t.Errorf("AttenteFileDominante temoin attendu true pour duree_horloge=1000us attente_file=500us (5000 >= 1000), obtenu %v", dominanteTemoinContention)
		}
	})
}
