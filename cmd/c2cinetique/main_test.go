//go:build linux

package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	c2cli "github.com/hazyhaar/c2blue55/cmd/c2cinetique"
	"github.com/hazyhaar/c2blue55/internal/cinetique"
)

func TestCLISousCommandesEtEcritureAtomique0600(t *testing.T) {
	var fluxStd, fluxErr bytes.Buffer

	if code := c2cli.ExecuterCLI(nil, &fluxStd, &fluxErr); code != 2 {
		t.Fatalf("attendu code 2 sans argument, obtenu %d", code)
	}
	if code := c2cli.ExecuterCLI([]string{"inconnue"}, &fluxStd, &fluxErr); code != 2 {
		t.Fatalf("attendu code 2 sur sous-commande inconnue, obtenu %d", code)
	}

	dossier := t.TempDir()
	sortieHybride := filepath.Join(dossier, "hybride.json")
	fluxStd.Reset()
	fluxErr.Reset()
	codeHyb := c2cli.ExecuterCLI(
		[]string{"etalonner-hybride", "-dossier", dossier, "-repetitions", "8", "-out", sortieHybride},
		&fluxStd,
		&fluxErr,
	)
	if codeHyb != 0 {
		t.Fatalf("etalonner-hybride en echec (%d): %s", codeHyb, fluxErr.String())
	}
	statHyb, errStat := os.Stat(sortieHybride)
	if errStat != nil {
		t.Fatalf("fichier hybride absent: %v", errStat)
	}
	if statHyb.Mode().Perm() != 0600 {
		t.Fatalf("permissions attendues 0600, obtenu %o", statHyb.Mode().Perm())
	}
	octetsHyb, errRead := os.ReadFile(sortieHybride)
	if errRead != nil {
		t.Fatalf("lecture rapport hybride: %v", errRead)
	}
	var rapportHyb cinetique.RapportInvarianceHybride
	if errJSON := json.Unmarshal(octetsHyb, &rapportHyb); errJSON != nil {
		t.Fatalf("JSON hybride invalide: %v", errJSON)
	}
	if len(rapportHyb.Quotients) != cinetique.NombreQuotientsEpisode {
		t.Fatalf("nombre de quotients inattendu: %d", len(rapportHyb.Quotients))
	}

	// Test sonder-pid sur le processus de test courant.
	sortiePID := filepath.Join(dossier, "sondage_pid.json")
	fluxStd.Reset()
	fluxErr.Reset()
	codePID := c2cli.ExecuterCLI(
		[]string{"sonder-pid", "-pid", strconv.Itoa(os.Getpid()), "-duree-ms", "20", "-nom", "test_cli", "-out", sortiePID},
		&fluxStd,
		&fluxErr,
	)
	if codePID != 0 {
		t.Fatalf("sonder-pid en echec (%d): %s", codePID, fluxErr.String())
	}
	if infoPID, err := os.Stat(sortiePID); err != nil || infoPID.Mode().Perm() != 0600 {
		t.Fatalf("fichier sonder-pid absent ou permissions != 0600: err=%v", err)
	}

	// Test chaine-complete de bout en bout (attribution socket inet_diag + ratios + arbitre SIMD).
	sortieChaine := filepath.Join(dossier, "chaine_complete.json")
	fluxStd.Reset()
	fluxErr.Reset()
	codeChaine := c2cli.ExecuterCLI(
		[]string{"chaine-complete", "-dossier", dossier, "-out", sortieChaine},
		&fluxStd,
		&fluxErr,
	)
	if codeChaine != 0 {
		t.Fatalf("chaine-complete en echec (%d): %s", codeChaine, fluxErr.String())
	}
	infoChaine, errStatChaine := os.Stat(sortieChaine)
	if errStatChaine != nil || infoChaine.Mode().Perm() != 0600 {
		t.Fatalf("fichier chaine-complete absent ou permissions != 0600: err=%v", errStatChaine)
	}
	octetsChaine, errReadChaine := os.ReadFile(sortieChaine)
	if errReadChaine != nil {
		t.Fatalf("lecture chaine-complete: %v", errReadChaine)
	}
	var rapportChaine cinetique.RapportChaineComplete
	if errJSONChaine := json.Unmarshal(octetsChaine, &rapportChaine); errJSONChaine != nil {
		t.Fatalf("JSON chaine-complete invalide: %v", errJSONChaine)
	}
	if rapportChaine.PIDProcessus != os.Getpid() || len(rapportChaine.Chaines) < 4 {
		t.Fatalf("rapport chaine-complete incomplet: %+v", rapportChaine)
	}

	// Jumeaux négatifs CLI (GLM C-23) : options obligatoires manquantes, valeurs hors bornes, fichiers absents.
	for _, argsInvalides := range [][]string{
		{"evaluer-powerlog"},
		{"evaluer-powerlog", "-degrade", "seul.csv"},
		{"evaluer-powerlog", "-flag-inconnu"},
		{"sonder-pid", "-pid", "0"},
		{"sonder-pid", "-duree-ms", "-5"},
		{"etalonner-hybride", "-flag-inconnu"},
		{"chaine-complete", "-flag-inconnu"},
	} {
		fluxStd.Reset()
		fluxErr.Reset()
		if code := c2cli.ExecuterCLI(argsInvalides, &fluxStd, &fluxErr); code != 2 {
			t.Fatalf("attendu code 2 pour %v, obtenu %d", argsInvalides, code)
		}
	}

	fluxStd.Reset()
	fluxErr.Reset()
	if code := c2cli.ExecuterCLI(
		[]string{"evaluer-powerlog", "-degrade", filepath.Join(dossier, "absent1.csv"), "-nominal", filepath.Join(dossier, "absent2.csv")},
		&fluxStd,
		&fluxErr,
	); code != 1 {
		t.Fatalf("attendu code 1 sur CSV inexistant, obtenu %d", code)
	}

	// Exécution nominale de evaluer-powerlog avec écriture atomique 0600 + fsync répertoire.
	csvDeg := filepath.Join(dossier, "deg.csv")
	csvNom := filepath.Join(dossier, "nom.csv")
	contenuDeg := "ts,cpu_pkg_w,cpu_pkg_temp_c,load1\n" +
		"2026-10-28T10:00:00Z,65.0,88.0,4.0\n" +
		"2026-10-28T10:00:01Z,65.0,88.5,4.0\n"
	contenuNom := "ts,cpu_pkg_w,cpu_pkg_temp_c,load1\n" +
		"2026-10-29T10:00:00Z,65.0,58.0,4.0\n" +
		"2026-10-29T10:00:01Z,65.0,58.5,4.0\n"
	if err := os.WriteFile(csvDeg, []byte(contenuDeg), 0600); err != nil {
		t.Fatalf("ecriture csvDeg: %v", err)
	}
	if err := os.WriteFile(csvNom, []byte(contenuNom), 0600); err != nil {
		t.Fatalf("ecriture csvNom: %v", err)
	}
	sortiePower := filepath.Join(dossier, "bilan_power.json")
	fluxStd.Reset()
	fluxErr.Reset()
	codePow := c2cli.ExecuterCLI(
		[]string{"evaluer-powerlog", "-degrade", csvDeg, "-nominal", csvNom, "-fenetre", "2", "-out", sortiePower},
		&fluxStd,
		&fluxErr,
	)
	if codePow != 0 {
		t.Fatalf("evaluer-powerlog en echec (%d): %s", codePow, fluxErr.String())
	}
	if infoPow, err := os.Stat(sortiePower); err != nil || infoPow.Mode().Perm() != 0600 {
		t.Fatalf("sortie powerlog absente ou permissions != 0600: err=%v", err)
	}
}
