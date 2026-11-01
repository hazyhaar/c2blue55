//go:build linux

// La commande c2cinetique exécute hors bande l'étalonnage d'invariance hybride
// (cpu_core vs cpu_atom), l'évaluation hors-distribution des journaux thermiques
// powerlog et le sondage ponctuel d'un processus actif sans compteurs PMU.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/hazyhaar/c2blue55/internal/cinetique"
)

func main() {
	os.Exit(ExecuterCLI(os.Args[1:], os.Stdout, os.Stderr))
}

// ExecuterCLI pilote les sous-commandes de c2cinetique et rend un code de sortie POSIX.
func ExecuterCLI(arguments []string, sortieStd, sortieErr io.Writer) int {
	if len(arguments) == 0 {
		afficherUsage(sortieErr)
		return 2
	}
	switch arguments[0] {
	case "etalonner-hybride":
		return executerEtalonnerHybride(arguments[1:], sortieStd, sortieErr)
	case "evaluer-powerlog":
		return executerEvaluerPowerlog(arguments[1:], sortieStd, sortieErr)
	case "sonder-pid":
		return executerSonderPID(arguments[1:], sortieStd, sortieErr)
	case "chaine-complete":
		return executerChaineComplete(arguments[1:], sortieStd, sortieErr)
	default:
		_, _ = fmt.Fprintf(sortieErr, "sous-commande inconnue : %q\n", arguments[0])
		afficherUsage(sortieErr)
		return 2
	}
}

func afficherUsage(flux io.Writer) {
	_, _ = fmt.Fprintln(flux, "usage : c2cinetique <etalonner-hybride|evaluer-powerlog|sonder-pid|chaine-complete> [options]")
}

func executerChaineComplete(arguments []string, sortieStd, sortieErr io.Writer) int {
	drapeaux := flag.NewFlagSet("chaine-complete", flag.ContinueOnError)
	drapeaux.SetOutput(sortieErr)
	dossier := drapeaux.String("dossier", "", "repertoire de travail NVMe/ext4 (defaut: repertoire temporaire dedie)")
	modeleQwen := drapeaux.String("modele-qwen", "", "chemin optionnel du modele GGUF Qwen2.5-0.5B pour l'arbitrage neuronal reel")
	delaiSec := drapeaux.Int("timeout-sec", 60, "delai maximal d'execution en secondes")
	cheminSortie := drapeaux.String("out", "", "chemin JSON de sortie ecrit atomiquement (0600)")
	if err := drapeaux.Parse(arguments); err != nil {
		return 2
	}

	dossierEffectif := *dossier
	nettoyerDossier := false
	if dossierEffectif == "" {
		cree, errTemp := os.MkdirTemp("", "c2cinetique-chaine-*")
		if errTemp != nil {
			_, _ = fmt.Fprintf(sortieErr, "creation dossier temporaire : %v\n", errTemp)
			return 1
		}
		dossierEffectif = cree
		nettoyerDossier = true
	}
	if nettoyerDossier {
		defer func() { _ = os.RemoveAll(dossierEffectif) }()
	}

	ctx, annuler := context.WithTimeout(context.Background(), time.Duration(*delaiSec)*time.Second)
	defer annuler()

	rapport, errChaine := cinetique.ExecuterBancChaineComplete(ctx, dossierEffectif, *modeleQwen)
	if errChaine != nil {
		_, _ = fmt.Fprintf(sortieErr, "echec chaine-complete : %v\n", errChaine)
		return 1
	}
	if errEcriture := emettreJSON(rapport, *cheminSortie, sortieStd); errEcriture != nil {
		_, _ = fmt.Fprintf(sortieErr, "ecriture rapport : %v\n", errEcriture)
		return 1
	}
	return 0
}

func executerEtalonnerHybride(arguments []string, sortieStd, sortieErr io.Writer) int {
	drapeaux := flag.NewFlagSet("etalonner-hybride", flag.ContinueOnError)
	drapeaux.SetOutput(sortieErr)
	dossier := drapeaux.String("dossier", "", "repertoire de travail NVMe/ext4 (defaut: repertoire temporaire dedie)")
	repetitions := drapeaux.Int("repetitions", 12, "nombre d'episodes reels par domaine de coeur (>= 8)")
	cheminSortie := drapeaux.String("out", "", "chemin JSON de sortie ecrit atomiquement (0600)")
	if err := drapeaux.Parse(arguments); err != nil {
		return 2
	}

	dossierEffectif := *dossier
	nettoyerDossier := false
	if dossierEffectif == "" {
		cree, errTemp := os.MkdirTemp("", "c2cinetique-banc-*")
		if errTemp != nil {
			_, _ = fmt.Fprintf(sortieErr, "creation dossier temporaire : %v\n", errTemp)
			return 1
		}
		dossierEffectif = cree
		nettoyerDossier = true
	}
	if nettoyerDossier {
		defer func() { _ = os.RemoveAll(dossierEffectif) }()
	}

	rapport, errBanc := cinetique.ExecuterBancInvarianceHybride(dossierEffectif, *repetitions)
	if errBanc != nil {
		_, _ = fmt.Fprintf(sortieErr, "echec banc invariance : %v\n", errBanc)
		return 1
	}
	if errEcriture := emettreJSON(rapport, *cheminSortie, sortieStd); errEcriture != nil {
		_, _ = fmt.Fprintf(sortieErr, "ecriture rapport : %v\n", errEcriture)
		return 1
	}
	return 0
}

func executerEvaluerPowerlog(arguments []string, sortieStd, sortieErr io.Writer) int {
	drapeaux := flag.NewFlagSet("evaluer-powerlog", flag.ContinueOnError)
	drapeaux.SetOutput(sortieErr)
	cheminDegrade := drapeaux.String("degrade", "", "chemin du CSV powerlog en regime degrade")
	cheminNominal := drapeaux.String("nominal", "", "chemin du CSV powerlog en regime nominal")
	fenetre := drapeaux.Int("fenetre", 60, "taille des episodes disjoints en echantillons")
	tempRepos := drapeaux.Float64("temp-repos", 25.0, "temperature de repos de reference en degres Celsius")
	plancherW := drapeaux.Float64("plancher-w", 35.0, "puissance minimale moyenne d'un episode actif (W)")
	plancherLoad := drapeaux.Float64("plancher-load", 1.0, "charge load1 minimale moyenne d'un episode actif")
	maxEcartSec := drapeaux.Int64("max-ecart-sec", 15, "ecart temporel maximal autorise entre deux mesures consecutives d'un episode (s)")
	sansCalibrationRepos := drapeaux.Bool("sans-calibration-repos", false, "desactiver la calibration affine de T_repos sur le journal nominal")
	cheminSortie := drapeaux.String("out", "", "chemin JSON de sortie ecrit atomiquement (0600)")
	if err := drapeaux.Parse(arguments); err != nil {
		return 2
	}
	if *cheminDegrade == "" || *cheminNominal == "" {
		_, _ = fmt.Fprintln(sortieErr, "les options -degrade et -nominal sont obligatoires")
		return 2
	}

	journalDeg, errDeg := cinetique.ChargerFichierPuissanceCSV(*cheminDegrade)
	if errDeg != nil {
		_, _ = fmt.Fprintf(sortieErr, "lecture journal degrade : %v\n", errDeg)
		return 1
	}
	journalNom, errNom := cinetique.ChargerFichierPuissanceCSV(*cheminNominal)
	if errNom != nil {
		_, _ = fmt.Fprintf(sortieErr, "lecture journal nominal : %v\n", errNom)
		return 1
	}

	cfg := cinetique.ConfigPowerlogParDefaut()
	cfg.TemperatureReposMilliC = int64(math.Round(*tempRepos * 1000.0))
	cfg.PlancherPuissanceMilliW = int64(math.Round(*plancherW * 1000.0))
	cfg.PlancherChargeMilli = int64(math.Round(*plancherLoad * 1000.0))
	cfg.FenetreEpisode = *fenetre
	cfg.MaxEcartEchantillonSec = *maxEcartSec
	cfg.DesactiverCalibrationTempRepos = *sansCalibrationRepos
	bilan, errEval := cinetique.EvaluerCampagnePowerlog(journalDeg, journalNom, cfg)
	if errEval != nil {
		_, _ = fmt.Fprintf(sortieErr, "evaluation powerlog : %v\n", errEval)
		return 1
	}
	if errEcriture := emettreJSON(bilan, *cheminSortie, sortieStd); errEcriture != nil {
		_, _ = fmt.Fprintf(sortieErr, "ecriture bilan : %v\n", errEcriture)
		return 1
	}
	return 0
}

type rapportSondagePID struct {
	PID                   int                        `json:"pid"`
	DureeMs               int                        `json:"duree_ms"`
	Quotients             cinetique.QuotientsEpisode `json:"quotients"`
	DifferentielStructure string                     `json:"differentiel_structure"`
}

func executerSonderPID(arguments []string, sortieStd, sortieErr io.Writer) int {
	drapeaux := flag.NewFlagSet("sonder-pid", flag.ContinueOnError)
	drapeaux.SetOutput(sortieErr)
	pid := drapeaux.Int("pid", os.Getpid(), "PID Linux a observer")
	dureeMs := drapeaux.Int("duree-ms", 200, "duree de la fenetre d'observation en millisecondes")
	nomBin := drapeaux.String("nom", "processus_observe", "etiquette binaire pour le jeton differentiel")
	cheminSortie := drapeaux.String("out", "", "chemin JSON de sortie ecrit atomiquement (0600)")
	if err := drapeaux.Parse(arguments); err != nil {
		return 2
	}
	if *pid <= 0 || *dureeMs <= 0 {
		_, _ = fmt.Fprintln(sortieErr, "-pid et -duree-ms doivent etre strictement positifs")
		return 2
	}

	capteur, errCapteur := cinetique.OuvrirCapteurProcLinux()
	if errCapteur != nil {
		_, _ = fmt.Fprintf(sortieErr, "ouverture /proc : %v\n", errCapteur)
		return 1
	}
	defer func() { _ = capteur.Fermer() }()

	topologie, _, _ := cinetique.ChargerTopologieHybride()
	psiDebut, _ := capteur.LirePressionPSI(time.Now().UnixNano())
	snapDebut, errDebut := capteur.LireInstantaneProcessus(*pid, time.Now().UnixNano())
	if errDebut != nil {
		_, _ = fmt.Fprintf(sortieErr, "lecture initiale PID %d : %v\n", *pid, errDebut)
		return 1
	}

	time.Sleep(time.Duration(*dureeMs) * time.Millisecond)

	snapFin, errFin := capteur.LireInstantaneProcessus(*pid, time.Now().UnixNano())
	if errFin != nil {
		_, _ = fmt.Fprintf(sortieErr, "lecture finale PID %d : %v\n", *pid, errFin)
		return 1
	}
	psiFin, _ := capteur.LirePressionPSI(time.Now().UnixNano())

	episode, errEp := cinetique.EvaluerEpisodeCinetique(
		snapDebut,
		snapFin,
		psiDebut,
		psiFin,
		cinetique.CompteursReseauEpisode{},
		topologie,
		cinetique.ConfigPlanchersParDefaut(),
	)
	if errEp != nil {
		_, _ = fmt.Fprintf(sortieErr, "evaluation episode : %v\n", errEp)
		return 1
	}

	var diag cinetique.DiagnosticEpisodeCinetique
	diag.ClasseCoeur = episode.ClasseCoeurFin
	diag.Orientation = cinetique.OrientationAmorcage
	diag.Episode = episode

	var tampon [512]byte
	jeton, errFmt := cinetique.FormaterDifferentielEpisode(tampon[:0], *nomBin, diag)
	if errFmt != nil {
		_, _ = fmt.Fprintf(sortieErr, "formatage differentiel : %v\n", errFmt)
		return 1
	}

	sortie := rapportSondagePID{
		PID:                   *pid,
		DureeMs:               *dureeMs,
		Quotients:             episode,
		DifferentielStructure: string(jeton),
	}
	if errEcriture := emettreJSON(sortie, *cheminSortie, sortieStd); errEcriture != nil {
		_, _ = fmt.Fprintf(sortieErr, "ecriture rapport : %v\n", errEcriture)
		return 1
	}
	return 0
}

func emettreJSON(charge any, cheminSortie string, sortieStd io.Writer) error {
	octets, errMarshal := json.MarshalIndent(charge, "", "  ")
	if errMarshal != nil {
		return errMarshal
	}
	octets = append(octets, '\n')
	if cheminSortie == "" {
		_, errWrite := sortieStd.Write(octets)
		return errWrite
	}
	return ecrireFichierAtomique0600(cheminSortie, octets)
}

func ecrireFichierAtomique0600(cheminCible string, contenu []byte) error {
	dossier := filepath.Dir(cheminCible)
	if errMkdir := os.MkdirAll(dossier, 0750); errMkdir != nil {
		return errMkdir
	}
	fichierTemp, errTemp := os.CreateTemp(dossier, ".c2cinetique-*.tmp")
	if errTemp != nil {
		return errTemp
	}
	nomTemp := fichierTemp.Name()
	nettoyer := true
	defer func() {
		if nettoyer {
			_ = os.Remove(nomTemp)
		}
	}()

	if _, errWrite := fichierTemp.Write(contenu); errWrite != nil {
		_ = fichierTemp.Close()
		return errWrite
	}
	if errChmod := fichierTemp.Chmod(0600); errChmod != nil {
		_ = fichierTemp.Close()
		return errChmod
	}
	if errSync := fichierTemp.Sync(); errSync != nil {
		_ = fichierTemp.Close()
		return errSync
	}
	if errClose := fichierTemp.Close(); errClose != nil {
		return errClose
	}
	if errRename := os.Rename(nomTemp, cheminCible); errRename != nil {
		return errRename
	}
	nettoyer = false
	repParent, errOuvrirRep := os.Open(dossier)
	if errOuvrirRep != nil {
		return errOuvrirRep
	}
	errSyncRep := repParent.Sync()
	errFermerRep := repParent.Close()
	return errors.Join(errSyncRep, errFermerRep)
}
