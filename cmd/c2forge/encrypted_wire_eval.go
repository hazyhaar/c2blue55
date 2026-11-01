package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hazyhaar/c2blue55"
)

const tailleMaxManifesteChiffre = 16 << 20

type encryptedManifestEntry struct {
	Path           string `json:"path"`
	Family         string `json:"family"`
	RunID          string `json:"run_id"`
	Hostile        bool   `json:"hostile"`
	ExpectedRegime string `json:"expected_regime,omitempty"`
}

func runEncryptedEval(args []string, output io.Writer) (int, error) {
	flags := flag.NewFlagSet("encrypted-eval", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	cheminPCAP := flags.String("pcap", "", "Capture PCAP chiffrée à évaluer (DoQ / DoH2 / DoH3 / QUIC)")
	cheminSortie := flags.String("out", "", "Chemin optionnel du rapport JSON d'une capture unique")
	cheminManifeste := flags.String("manifest", "", "Manifeste JSON [{path, family, run_id, hostile}] pour LOFO strict")
	cheminRapport := flags.String("report", "", "Chemin obligatoire du rapport JSON en mode -manifest")
	agregationHote := flags.Bool("hote", false, "Activer l'agrégation multi-résolveurs par hôte client")
	listePortsDoH := flags.String("doh-ports", "", "Liste CSV optionnelle de ports DoH/DoQ additionnels (1..65535, max 8)")
	if err := flags.Parse(args); err != nil {
		return 2, err
	}
	if flags.NArg() != 0 {
		return 2, fmt.Errorf("encrypted-eval refuse tout argument positionnel supplémentaire")
	}

	modeUnique := *cheminPCAP != "" && *cheminManifeste == "" && *cheminRapport == ""
	modeManifeste := *cheminManifeste != "" && *cheminRapport != "" && *cheminPCAP == "" && *cheminSortie == ""
	if !modeUnique && !modeManifeste {
		return 2, fmt.Errorf("encrypted-eval exige soit -pcap [-out], soit -manifest et -report")
	}

	portsAdditionnels, errPorts := parserPortsResolveurCSV(*listePortsDoH)
	if errPorts != nil {
		return 2, errPorts
	}
	configEvaluation := c2blue55.EncryptedWireConfig{
		AgregationHote:         *agregationHote,
		PortsResolveurChiffres: portsAdditionnels,
	}

	if modeUnique {
		constat, err := c2blue55.EvaluateEncryptedWirePCAP(*cheminPCAP, configEvaluation)
		if err != nil {
			return 2, err
		}
		octetsJSON, err := json.MarshalIndent(constat, "", "  ")
		if err != nil {
			return 2, err
		}
		octetsJSON = append(octetsJSON, '\n')
		if *cheminSortie == "" {
			if _, err := output.Write(octetsJSON); err != nil {
				return 2, err
			}
			return 0, nil
		}
		if err := ecrireFichierAtomiqueForge(*cheminSortie, octetsJSON); err != nil {
			return 2, err
		}
		if *agregationHote {
			if _, err := fmt.Fprintf(output, "%s sha256=%s conversations=%d hotes=%d\n",
				constat.Chemin, constat.SHA256, len(constat.Conversations), len(constat.Hotes)); err != nil {
				return 2, err
			}
			return 0, nil
		}
		if _, err := fmt.Fprintf(output, "%s sha256=%s conversations=%d\n",
			constat.Chemin, constat.SHA256, len(constat.Conversations)); err != nil {
			return 2, err
		}
		return 0, nil
	}

	entrees, err := chargerManifesteChiffre(*cheminManifeste)
	if err != nil {
		return 2, err
	}
	echantillons := make([]c2blue55.EncryptedWireSample, 0, len(entrees))
	for indice, entree := range entrees {
		if entree.Path == "" || entree.Family == "" || entree.RunID == "" {
			return 2, fmt.Errorf("manifeste entrée %d incomplète (path, family et run_id obligatoires)", indice)
		}
		regimeAttendu, regimeConnu, errRegime := parserRegimeAttendu(entree.ExpectedRegime)
		if errRegime != nil {
			return 2, fmt.Errorf("manifeste entrée %d (%s): %w", indice, entree.RunID, errRegime)
		}
		constat, errEval := c2blue55.EvaluateEncryptedWirePCAP(entree.Path, configEvaluation)
		if errEval != nil {
			return 2, fmt.Errorf("manifeste entrée %d (%s): %w", indice, entree.RunID, errEval)
		}
		jugeables := 0
		for _, verdict := range constat.Conversations {
			if verdict.Insuffisante {
				continue
			}
			jugeables++
			echantillons = append(echantillons, c2blue55.EncryptedWireSample{
				Famille:       entree.Family,
				RunID:         entree.RunID,
				Hostile:       entree.Hostile,
				RegimeAttendu: regimeAttendu,
				RegimeConnu:   regimeConnu,
				Verdict:       verdict,
			})
		}
		if jugeables == 0 {
			return 2, fmt.Errorf("manifeste entrée %d (%s): aucune conversation jugeable", indice, entree.RunID)
		}
	}

	rapport, err := c2blue55.EvaluateEncryptedWireSamples(echantillons)
	if err != nil {
		return 2, err
	}
	octetsRapport, err := json.MarshalIndent(rapport, "", "  ")
	if err != nil {
		return 2, err
	}
	octetsRapport = append(octetsRapport, '\n')
	if err := ecrireFichierAtomiqueForge(*cheminRapport, octetsRapport); err != nil {
		return 2, err
	}
	for _, bilan := range rapport.FamillesHostiles {
		if _, err := fmt.Fprintf(output, "%s hostile captures=%d tpr=%g fpr=%g majority=%g auc=%g insuffisant_auc=%t\n",
			bilan.Famille, bilan.Captures, bilan.TPR, bilan.FPR, bilan.MajorityClassRate, bilan.ROCAUC, bilan.InsuffisantPourAUC); err != nil {
			return 2, err
		}
	}
	for _, bilan := range rapport.FamillesBenignes {
		if _, err := fmt.Fprintf(output, "%s benin captures=%d fpr=%g\n",
			bilan.Famille, bilan.Captures, bilan.FPR); err != nil {
			return 2, err
		}
	}
	return 0, nil
}

func chargerManifesteChiffre(chemin string) ([]encryptedManifestEntry, error) {
	fichier, err := os.Open(chemin)
	if err != nil {
		return nil, err
	}
	etat, errStat := fichier.Stat()
	if errStat != nil {
		_ = fichier.Close()
		return nil, errStat
	}
	if !etat.Mode().IsRegular() || etat.Size() > tailleMaxManifesteChiffre {
		_ = fichier.Close()
		return nil, fmt.Errorf("manifeste %s hors contrat (fichier régulier <= %d octets requis)", chemin, tailleMaxManifesteChiffre)
	}
	octets, errLecture := io.ReadAll(io.LimitReader(fichier, tailleMaxManifesteChiffre))
	errFermeture := fichier.Close()
	if errLecture != nil {
		return nil, errLecture
	}
	if errFermeture != nil {
		return nil, errFermeture
	}
	decodeur := json.NewDecoder(bytes.NewReader(octets))
	decodeur.DisallowUnknownFields()
	var entrees []encryptedManifestEntry
	if err := decodeur.Decode(&entrees); err != nil {
		return nil, fmt.Errorf("manifeste %s invalide: %w", chemin, err)
	}
	if decodeur.More() {
		return nil, fmt.Errorf("manifeste %s contient des données excédentaires", chemin)
	}
	if len(entrees) == 0 {
		return nil, fmt.Errorf("manifeste %s vide", chemin)
	}
	return entrees, nil
}

func parserPortsResolveurCSV(texte string) ([c2blue55.MaxPortsResolveurChiffres]uint16, error) {
	var ports [c2blue55.MaxPortsResolveurChiffres]uint16
	if texte == "" {
		return ports, nil
	}
	segments := strings.Split(texte, ",")
	if len(segments) > c2blue55.MaxPortsResolveurChiffres {
		return ports, fmt.Errorf("-doh-ports dépasse la capacité maximale de %d ports (%d fournis)", c2blue55.MaxPortsResolveurChiffres, len(segments))
	}
	nbRetenus := 0
	for _, segment := range segments {
		jeton := strings.TrimSpace(segment)
		if jeton == "" {
			return ports, fmt.Errorf("-doh-ports contient une entrée vide dans %q", texte)
		}
		port64, errParse := strconv.ParseUint(jeton, 10, 16)
		if errParse != nil || port64 == 0 {
			return ports, fmt.Errorf("-doh-ports contient un port invalide %q (plage 1..65535 requise)", jeton)
		}
		port := uint16(port64)
		dejaPresent := false
		for indice := range nbRetenus {
			if ports[indice] == port {
				dejaPresent = true
				break
			}
		}
		if !dejaPresent {
			ports[nbRetenus] = port
			nbRetenus++
		}
	}
	return ports, nil
}

func parserRegimeAttendu(libelle string) (c2blue55.EncryptedRegime, bool, error) {
	switch libelle {
	case "":
		return 0, false, nil
	case "R0a":
		return c2blue55.RegimeR0aResolutionSporadique, true, nil
	case "R0b":
		return c2blue55.RegimeR0bTelechargement, true, nil
	case "R1a":
		return c2blue55.RegimeR1aTunnelInteractif, true, nil
	case "R1b":
		return c2blue55.RegimeR1bBalisageLent, true, nil
	default:
		return 0, false, fmt.Errorf("régime attendu inconnu %q (admis: R0a, R0b, R1a, R1b)", libelle)
	}
}

func ecrireFichierAtomiqueForge(chemin string, contenu []byte) (err error) {
	repertoire := filepath.Dir(chemin)
	temporaire, err := os.CreateTemp(repertoire, filepath.Base(chemin)+".tmp-*")
	if err != nil {
		return err
	}
	cheminTemporaire := temporaire.Name()
	defer os.Remove(cheminTemporaire)
	defer func() {
		if temporaire != nil {
			err = errors.Join(err, temporaire.Close())
		}
	}()
	if err = temporaire.Chmod(0o600); err != nil {
		return err
	}
	if _, err = temporaire.Write(contenu); err != nil {
		return err
	}
	if err = temporaire.Sync(); err != nil {
		return err
	}
	errFermeture := temporaire.Close()
	temporaire = nil
	if errFermeture != nil {
		return errFermeture
	}
	if err = os.Rename(cheminTemporaire, chemin); err != nil {
		return err
	}
	descripteurRep, err := os.Open(repertoire)
	if err != nil {
		return err
	}
	err = descripteurRep.Sync()
	return errors.Join(err, descripteurRep.Close())
}
