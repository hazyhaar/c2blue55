package c2blue55

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// tailleMaxReadmeV83 borne la lecture d'un README : au-delà, l'analyse serait
// tronquée, donc refusée.
const tailleMaxReadmeV83 = 1 << 20

// readmeV83 décrit un README de la version v8.3 : son chemin, sa première
// ligne exacte, le titre de sa section 4e et la phrase qui borne la liste des
// méthodes MCP transmises sans inspection.
type readmeV83 struct {
	chemin         string
	premiereLigne  string
	titreSection   string
	marqueTransmis string
}

var readmesV83 = []readmeV83{
	{
		chemin:         "README.md",
		premiereLigne:  "# c2blue55 — CPU-Native Host & DNS Threat Detection Engine",
		titreSection:   "## 4e. Post-Audit Closed Lists & Header-Independent Vectors (2026-11-11, v8.3)",
		marqueTransmis: "are forwarded without inspection.",
	},
	{
		chemin:         "README.fr.md",
		premiereLigne:  "# c2blue55 — Moteur CPU-Natif de Détection de Menaces Hôte & DNS",
		titreSection:   "## 4e. Listes Fermées Post-Audit & Vecteur Indépendant de l'En-Tête (2026-11-11, v8.3)",
		marqueTransmis: "sont transmises sans inspection.",
	},
}

// jetonsAttendusReadmeV83 doivent figurer dans chaque README, quelle que soit sa langue.
var jetonsAttendusReadmeV83 = []string{
	"`v8.3`", "`cmd/c2blue-mcp-guard`", "`initialize`", "`ping`", "`tools/list`", "`notifications/*`",
	"`-32601`", "`-32600`", "`resources/read`", "`internal/engine/feature_extractor.go`",
	"`compact_reputation.go`", "`cmd/c2agent`", "`ServiceLive`", "`internal/dnslive`",
	"`TestContextBound_EdgeCases`", "`TestBancChaineCompleteBoutEnBout`",
	"│   ├── c2blue-dns-live/", "│   ├── dnslive/", "│   ├── enveloppedepot/",
}

// methodesRefuseesReadmeV83 ne doivent jamais figurer dans la phrase qui liste
// les méthodes transmises sans inspection.
var methodesRefuseesReadmeV83 = []string{"resources/read", "prompts/get", "completion/complete", "sampling/createMessage", "tools/call"}

var (
	lienInterneReadmeV83  = regexp.MustCompile(`\]\(#([^)\s]*)\)`)
	titreReadmeV83        = regexp.MustCompile(`(?m)^#{1,6}[ \t]+(.+?)[ \t]*$`)
	formeVersionModuleV83 = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

// lireReadmeV83 lit un README en entier dans la borne, sans troncature silencieuse.
func lireReadmeV83(chemin string) (contenu string, err error) {
	fichier, err := os.Open(chemin)
	if err != nil {
		return "", fmt.Errorf("ouverture de %s: %w", chemin, err)
	}
	defer func() {
		if errFermeture := fichier.Close(); errFermeture != nil {
			err = errors.Join(err, fmt.Errorf("fermeture de %s: %w", chemin, errFermeture))
		}
	}()
	octets, err := io.ReadAll(io.LimitReader(fichier, tailleMaxReadmeV83+1))
	if err != nil {
		return "", fmt.Errorf("lecture de %s: %w", chemin, err)
	}
	if len(octets) > tailleMaxReadmeV83 {
		return "", fmt.Errorf("%s dépasse %d octets, analyse tronquée refusée", chemin, tailleMaxReadmeV83)
	}
	if !utf8.Valid(octets) {
		return "", fmt.Errorf("%s n'est pas de l'UTF-8 valide", chemin)
	}
	return string(octets), nil
}

// ancreTitreReadmeV83 rend l'ancre que GitHub dérive d'un titre : minuscules,
// lettres, chiffres, tirets et traits de soulignement conservés, espaces
// changées en tirets, tout autre signe retiré.
func ancreTitreReadmeV83(titre string) string {
	var ancre strings.Builder
	for _, caractere := range strings.ToLower(titre) {
		switch {
		case unicode.IsLetter(caractere), unicode.IsDigit(caractere), caractere == '-', caractere == '_':
			ancre.WriteRune(caractere)
		case caractere == ' ':
			ancre.WriteRune('-')
		}
	}
	return ancre.String()
}

// anomaliesIntegriteReadmeV83 rend les défauts de forme d'un README : première
// ligne inattendue, ou lien interne dont l'ancre ne correspond à aucun titre.
func anomaliesIntegriteReadmeV83(document readmeV83, contenu string) []string {
	var anomalies []string
	premiere, _, _ := strings.Cut(contenu, "\n")
	if premiere != document.premiereLigne {
		anomalies = append(anomalies, fmt.Sprintf("%s : première ligne %q, attendu %q", document.chemin, premiere, document.premiereLigne))
	}
	ancres := map[string]bool{}
	for _, titre := range titreReadmeV83.FindAllStringSubmatch(contenu, -1) {
		ancres[ancreTitreReadmeV83(titre[1])] = true
	}
	for _, lien := range lienInterneReadmeV83.FindAllStringSubmatch(contenu, -1) {
		if lien[1] != "" && !ancres[lien[1]] {
			anomalies = append(anomalies, fmt.Sprintf("%s : lien interne vers l'ancre %q, qu'aucun titre ne porte", document.chemin, lien[1]))
		}
	}
	return anomalies
}

// anomaliesContenuReadmeV83 rend les jetons attendus absents d'un README.
func anomaliesContenuReadmeV83(document readmeV83, contenu string) []string {
	var anomalies []string
	if !strings.Contains(contenu, "\n"+document.titreSection+"\n") {
		anomalies = append(anomalies, fmt.Sprintf("%s : titre de section %q absent", document.chemin, document.titreSection))
	}
	for _, jeton := range jetonsAttendusReadmeV83 {
		if !strings.Contains(contenu, jeton) {
			anomalies = append(anomalies, fmt.Sprintf("%s omet %q", document.chemin, jeton))
		}
	}
	return anomalies
}

// anomaliesListeTransmiseReadmeV83 rend les méthodes refusées par la garde qui
// figureraient à tort dans la phrase des méthodes transmises sans inspection.
func anomaliesListeTransmiseReadmeV83(document readmeV83, contenu string) []string {
	fin := strings.Index(contenu, document.marqueTransmis)
	if fin < 0 {
		return []string{fmt.Sprintf("%s : phrase des méthodes transmises (%q) absente", document.chemin, document.marqueTransmis)}
	}
	debut := strings.LastIndex(contenu[:fin], "\n")
	phrase := contenu[debut+1 : fin]
	var anomalies []string
	for _, methode := range methodesRefuseesReadmeV83 {
		if strings.Contains(phrase, methode) {
			anomalies = append(anomalies, fmt.Sprintf("%s présente %q comme transmise sans inspection", document.chemin, methode))
		}
	}
	return anomalies
}

// TestReadmeV83Contrat porte les cas prescrits de la strate de version : C01
// exige que VersionModule rende 8.3.0 et que les deux README portent la section
// 4e, ses jetons et les entrées d'arborescence ; C02 refuse une version mal
// formée, un README qui ne cite pas la version courante, et une méthode
// refusée par la garde MCP présentée comme transmise. Les deux cas exigent en
// outre l'intégrité de forme de chaque README.
func TestReadmeV83Contrat(t *testing.T) {
	t.Run("C01", func(t *testing.T) {
		versionCourante := VersionModule()
		if versionCourante != "8.3.0" {
			t.Fatalf("C01: VersionModule() = %q, attendu \"8.3.0\"", versionCourante)
		}
		for _, document := range readmesV83 {
			contenu, err := lireReadmeV83(document.chemin)
			if err != nil {
				t.Fatalf("C01: %v", err)
			}
			for _, anomalie := range anomaliesIntegriteReadmeV83(document, contenu) {
				t.Errorf("C01: %s", anomalie)
			}
			for _, anomalie := range anomaliesContenuReadmeV83(document, contenu) {
				t.Errorf("C01: %s", anomalie)
			}
		}
	})
	t.Run("C02", func(t *testing.T) {
		versionCourante := VersionModule()
		if !formeVersionModuleV83.MatchString(versionCourante) {
			t.Fatalf("C02: VersionModule() = %q, hors de la forme majeur.mineur.correctif", versionCourante)
		}
		mineure := "`v" + versionCourante[:strings.LastIndex(versionCourante, ".")] + "`"
		for _, document := range readmesV83 {
			contenu, err := lireReadmeV83(document.chemin)
			if err != nil {
				t.Fatalf("C02: %v", err)
			}
			for _, anomalie := range anomaliesIntegriteReadmeV83(document, contenu) {
				t.Errorf("C02: %s", anomalie)
			}
			for _, anomalie := range anomaliesListeTransmiseReadmeV83(document, contenu) {
				t.Errorf("C02: %s", anomalie)
			}
			if !strings.Contains(contenu, mineure) {
				t.Errorf("C02: %s ne cite pas la version %s rendue par VersionModule", document.chemin, mineure)
			}
			// Jumeau négatif : le validateur doit refuser un README qui range
			// resources/read parmi les méthodes transmises.
			falsifie := strings.Replace(contenu, document.marqueTransmis, "`resources/read` "+document.marqueTransmis, 1)
			if len(anomaliesListeTransmiseReadmeV83(document, falsifie)) == 0 {
				t.Errorf("C02: %s : le jumeau falsifié n'a déclenché aucun refus", document.chemin)
			}
		}
	})
}
