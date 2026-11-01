package cinetique

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	// ErrEnTetePowerlogInvalide signale l'absence d'une colonne requise dans le CSV powerlog.
	ErrEnTetePowerlogInvalide = errors.New("cinetique: en-tete CSV powerlog invalide ou colonne requise absente")
	// ErrEchantillonVide signale un effectif positif ou négatif nul empêchant le calcul d'AUC.
	ErrEchantillonVide = errors.New("cinetique: effectif positif ou negatif nul pour l'evaluation ROC")
)

// MesurePowerlog représente une ligne valide d'un journal /inference/log/power/*.csv
// convertie en entiers à virgule fixe (milliwatts, millidegrés Celsius, milli-unités de load1).
type MesurePowerlog struct {
	HorodatageISO      string
	HorodatageUnixMs   int64
	HorodatageValide   bool
	PuissancePkgMilliW int64
	PuissanceCoreMW    int64
	TempPkgMilliC      int64
	TempCoreMaxMilliC  int64
	Charge1Milli       int64
}

// JournalPuissanceCharge regroupe l'intégralité des mesures lues et le compte
// explicite des lignes placées en quarantaine de schéma (ex. Nodeviceswerefound).
type JournalPuissanceCharge struct {
	NombreColonnesEnTete    int              `json:"nombre_colonnes_entete"`
	LignesTotales           int              `json:"lignes_totales"`
	LignesValides           int              `json:"lignes_valides"`
	LignesQuarantaineSchema int              `json:"lignes_quarantaine_schema"`
	PremierHorodatage       string           `json:"premier_horodatage"`
	DernierHorodatage       string           `json:"dernier_horodatage"`
	Mesures                 []MesurePowerlog `json:"-"`
}

// ConfigEvaluationPowerlog paramètre les planchers physiques, la continuité
// temporelle inter-échantillons et la fenêtre d'épisode.
type ConfigEvaluationPowerlog struct {
	TemperatureReposMilliC         int64
	PlancherPuissanceMilliW        int64
	PlancherChargeMilli            int64
	FenetreEpisode                 int
	MaxEcartEchantillonSec         int64
	DesactiverCalibrationTempRepos bool
}

// ConfigPowerlogParDefaut fournit la paramétrisation standard (T_repos de repli = 25 °C,
// calibration affine sur le seul journal nominal active, écart maximal inter-lignes 15 s,
// plancher actif 35 W et load1 >= 1.0, épisodes disjoints de 60 échantillons ~72 s).
func ConfigPowerlogParDefaut() ConfigEvaluationPowerlog {
	return ConfigEvaluationPowerlog{
		TemperatureReposMilliC:  25_000,
		PlancherPuissanceMilliW: 35_000,
		PlancherChargeMilli:     1_000,
		FenetreEpisode:          60,
		MaxEcartEchantillonSec:  15,
	}
}

// ComparaisonMetriqueROC rapporte la performance hors-distribution complète
// d'une métrique ou d'un quotient invariant avec contextualisation obligatoire.
type ComparaisonMetriqueROC struct {
	NomMetrique            string  `json:"nom_metrique"`
	EffectifDegradePositif int     `json:"effectif_degrade_positif"`
	EffectifNominalNegatif int     `json:"effectif_nominal_negatif"`
	TauxClasseMajoritaire  float64 `json:"taux_classe_majoritaire"`
	MedianeDegrade         float64 `json:"mediane_degrade"`
	MADMDegrade            float64 `json:"madm_degrade"`
	MedianeNominale        float64 `json:"mediane_nominale"`
	MADMNominal            float64 `json:"madm_nominal"`
	AUCMannWhitney         float64 `json:"auc_mann_whitney"`
	RappelAFPRZero         float64 `json:"rappel_a_fpr_zero"`
	RappelAFPRUnPourcent   float64 `json:"rappel_a_fpr_un_pourcent"`
}

// BilanCampagnePowerlog consolide la lecture intégrale des journaux dégradé vs
// nominal et la comparaison exacte entre grandeurs brutes et quotients invariants.
type BilanCampagnePowerlog struct {
	JournalDegrade                  JournalPuissanceCharge   `json:"journal_degrade"`
	JournalNominal                  JournalPuissanceCharge   `json:"journal_nominal"`
	FenetreEpisode                  int                      `json:"fenetre_episode"`
	TemperatureReposCelsius         float64                  `json:"temperature_repos_celsius"`
	TemperatureReposEffectiveC      float64                  `json:"temperature_repos_effective_celsius"`
	CalibrationTempReposActive      bool                     `json:"calibration_temp_repos_active"`
	ComparaisonsEpisodes            []ComparaisonMetriqueROC `json:"comparaisons_episodes"`
	ComparaisonsPonctuelles         []ComparaisonMetriqueROC `json:"comparaisons_ponctuelles"`
	ComparaisonsIsoPuissance50a90W  []ComparaisonMetriqueROC `json:"comparaisons_iso_puissance_50_90w,omitempty"`
	EpreuveConfusionForteCharge     []ComparaisonMetriqueROC `json:"epreuve_confusion_forte_charge"`
	ControleAutoNominalModereVsFort []ComparaisonMetriqueROC `json:"controle_auto_nominal_modere_vs_fort,omitempty"`
}

// ChargerFichierPuissanceCSV ouvre et lit intégralement un fichier CSV powerlog.
func ChargerFichierPuissanceCSV(chemin string) (JournalPuissanceCharge, error) {
	fichier, err := os.Open(chemin)
	if err != nil {
		return JournalPuissanceCharge{}, fmt.Errorf("cinetique: ouverture %s: %w", chemin, err)
	}
	bilan, errLecture := LireJournalPuissanceCSV(fichier)
	errFermeture := fichier.Close()
	if errLecture != nil {
		return JournalPuissanceCharge{}, errLecture
	}
	if errFermeture != nil {
		return JournalPuissanceCharge{}, errFermeture
	}
	return bilan, nil
}

// LireJournalPuissanceCSV lit ligne à ligne l'intégralité d'un flux CSV powerlog
// (OBJET-INTEGRAL-001) en résolvant les colonnes par leur nom d'en-tête.
func LireJournalPuissanceCSV(flux io.Reader) (JournalPuissanceCharge, error) {
	var journal JournalPuissanceCharge
	lecteur := bufio.NewReaderSize(flux, 65536)

	ligneEnTete, errEnTete := lireLigneIntegrale(lecteur)
	if errEnTete != nil {
		return journal, fmt.Errorf("%w: %v", ErrEnTetePowerlogInvalide, errEnTete)
	}
	colonnes := strings.Split(strings.TrimRight(ligneEnTete, "\r\n"), ",")
	journal.NombreColonnesEnTete = len(colonnes)

	idxTS := -1
	idxPkgW := -1
	idxCoreW := -1
	idxPkgTemp := -1
	idxCoreMax := -1
	idxLoad1 := -1

	for i, nom := range colonnes {
		switch strings.TrimSpace(nom) {
		case "ts":
			idxTS = i
		case "cpu_pkg_w":
			idxPkgW = i
		case "cpu_core_w":
			idxCoreW = i
		case "cpu_pkg_temp_c":
			idxPkgTemp = i
		case "cpu_core_max_c":
			idxCoreMax = i
		case "load1":
			idxLoad1 = i
		}
	}
	if idxTS < 0 || idxPkgW < 0 || idxPkgTemp < 0 || idxLoad1 < 0 {
		return journal, ErrEnTetePowerlogInvalide
	}

	for {
		ligneBrute, errLigne := lireLigneIntegrale(lecteur)
		if errors.Is(errLigne, io.EOF) && len(ligneBrute) == 0 {
			break
		}
		if errLigne != nil && !errors.Is(errLigne, io.EOF) {
			return journal, errLigne
		}
		propre := strings.TrimRight(ligneBrute, "\r\n")
		if strings.TrimSpace(propre) == "" {
			if errors.Is(errLigne, io.EOF) {
				break
			}
			continue
		}
		journal.LignesTotales++
		champs := strings.Split(propre, ",")
		if len(champs) != journal.NombreColonnesEnTete {
			journal.LignesQuarantaineSchema++
			if errors.Is(errLigne, io.EOF) {
				break
			}
			continue
		}

		pkgMW, okW := parserMilliFlottant(champs[idxPkgW])
		tempMC, okT := parserMilliFlottant(champs[idxPkgTemp])
		loadMilli, okL := parserMilliFlottant(champs[idxLoad1])
		if !okW || !okT || !okL || pkgMW <= 0 {
			journal.LignesQuarantaineSchema++
			if errors.Is(errLigne, io.EOF) {
				break
			}
			continue
		}

		var coreMW, coreMaxMC int64
		if idxCoreW >= 0 {
			if v, ok := parserMilliFlottant(champs[idxCoreW]); ok {
				coreMW = v
			}
		}
		if idxCoreMax >= 0 {
			if v, ok := parserMilliFlottant(champs[idxCoreMax]); ok {
				coreMaxMC = v
			}
		}

		horodatage := strings.TrimSpace(champs[idxTS])
		unixMs, errTS := parserHorodatagePowerlogMs(horodatage)
		if errTS != nil {
			journal.LignesQuarantaineSchema++
			if errors.Is(errLigne, io.EOF) {
				break
			}
			continue
		}
		if journal.LignesValides == 0 {
			journal.PremierHorodatage = horodatage
		}
		journal.DernierHorodatage = horodatage
		journal.LignesValides++
		journal.Mesures = append(journal.Mesures, MesurePowerlog{
			HorodatageISO:      horodatage,
			HorodatageUnixMs:   unixMs,
			HorodatageValide:   true,
			PuissancePkgMilliW: pkgMW,
			PuissanceCoreMW:    coreMW,
			TempPkgMilliC:      tempMC,
			TempCoreMaxMilliC:  coreMaxMC,
			Charge1Milli:       loadMilli,
		})

		if errors.Is(errLigne, io.EOF) {
			break
		}
	}

	return journal, nil
}

func lireLigneIntegrale(lecteur *bufio.Reader) (string, error) {
	var constructeur strings.Builder
	for {
		fragment, err := lecteur.ReadString('\n')
		constructeur.WriteString(fragment)
		if err == nil {
			return constructeur.String(), nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return constructeur.String(), err
	}
}

func parserMilliFlottant(texte string) (int64, bool) {
	propre := strings.TrimSpace(texte)
	if propre == "" {
		return 0, false
	}
	flottant, err := strconv.ParseFloat(propre, 64)
	if err != nil || math.IsNaN(flottant) || math.IsInf(flottant, 0) {
		return 0, false
	}
	return int64(math.Round(flottant * 1000.0)), true
}

func parserHorodatagePowerlogMs(texte string) (int64, error) {
	if texte == "" {
		return 0, ErrEnTetePowerlogInvalide
	}
	format := time.RFC3339Nano
	if !strings.Contains(texte, "T") {
		format = "2006-01-02 15:04:05"
	}
	inst, errParse := time.Parse(format, texte)
	if errParse != nil {
		return 0, errParse
	}
	return inst.UnixMilli(), nil
}

// estimerTemperatureReposNominalMilliC ajuste sur le seul journal nominal l'ordonnée à
// l'origine affine T(P) = T_0 + R_th * P par médianes des quartiles inférieur et supérieur
// de puissance active. Zéro information du journal dégradé n'est consultée. Si l'excursion
// de puissance nominale est inférieure à 20 W (pente non identifiable), la fonction rend
// false et l'évaluation conserve TemperatureReposMilliC configurée.
func estimerTemperatureReposNominalMilliC(mesuresNominales []MesurePowerlog, plancherPuissanceMW int64) (int64, bool) {
	actives := make([]MesurePowerlog, 0, len(mesuresNominales))
	for _, m := range mesuresNominales {
		if m.PuissancePkgMilliW >= plancherPuissanceMW {
			actives = append(actives, m)
		}
	}
	if len(actives) < 8 {
		return 0, false
	}
	sort.Slice(actives, func(i, j int) bool {
		if actives[i].PuissancePkgMilliW != actives[j].PuissancePkgMilliW {
			return actives[i].PuissancePkgMilliW < actives[j].PuissancePkgMilliW
		}
		return actives[i].TempPkgMilliC < actives[j].TempPkgMilliC
	})
	tailleQuartile := len(actives) / 4
	if tailleQuartile < 1 {
		return 0, false
	}
	pBasMW, tBasMC := medianesPuissanceEtTemp(actives[:tailleQuartile])
	pHautMW, tHautMC := medianesPuissanceEtTemp(actives[len(actives)-tailleQuartile:])
	deltaPMW := pHautMW - pBasMW
	deltaTMC := tHautMC - tBasMC
	if deltaPMW < 20_000 || deltaTMC <= 0 {
		return 0, false
	}
	penteCParW := float64(deltaTMC) / float64(deltaPMW)
	t0MC := int64(math.Round(float64(tBasMC) - penteCParW*float64(pBasMW)))
	if t0MC < 15_000 {
		t0MC = 15_000
	} else if t0MC > 55_000 {
		t0MC = 55_000
	}
	return t0MC, true
}

func medianesPuissanceEtTemp(tranche []MesurePowerlog) (int64, int64) {
	puissances := make([]float64, len(tranche))
	temperatures := make([]float64, len(tranche))
	for i, m := range tranche {
		puissances[i] = float64(m.PuissancePkgMilliW)
		temperatures[i] = float64(m.TempPkgMilliC)
	}
	sort.Float64s(puissances)
	sort.Float64s(temperatures)
	return int64(math.Round(medianeFlottantsTries(puissances))), int64(math.Round(medianeFlottantsTries(temperatures)))
}

type episodeThermique struct {
	puissanceMoyenneW   float64
	temperatureMoyenneC float64
	resistanceCParW     float64
	chargeParKilowatt   float64
}

func construireEpisodesDisjoints(mesures []MesurePowerlog, cfg ConfigEvaluationPowerlog, tempReposEffectiveMC int64) []episodeThermique {
	fenetre := cfg.FenetreEpisode
	if fenetre <= 0 {
		fenetre = 1
	}
	maxEcartMs := cfg.MaxEcartEchantillonSec * 1000
	if cfg.MaxEcartEchantillonSec == 0 {
		maxEcartMs = 15_000
	}
	var episodes []episodeThermique
	debut := 0
	for debut+fenetre <= len(mesures) {
		var sommePkgMW, sommeTempMC, sommeSurchauffeMC, sommeChargeMilli int64
		ruptureHorodatage := -1
		for i := debut; i < debut+fenetre; i++ {
			if i > debut && maxEcartMs > 0 && mesures[i].HorodatageValide && mesures[i-1].HorodatageValide {
				ecartMs := mesures[i].HorodatageUnixMs - mesures[i-1].HorodatageUnixMs
				if ecartMs < 0 || ecartMs > maxEcartMs {
					ruptureHorodatage = i
					break
				}
			}
			m := mesures[i]
			sommePkgMW += m.PuissancePkgMilliW
			sommeTempMC += m.TempPkgMilliC
			ecartTemp := m.TempPkgMilliC - tempReposEffectiveMC
			if ecartTemp > 0 {
				sommeSurchauffeMC += ecartTemp
			}
			sommeChargeMilli += m.Charge1Milli
		}
		if ruptureHorodatage >= 0 {
			debut = ruptureHorodatage
			continue
		}
		debut += fenetre
		moyPkgMW := sommePkgMW / int64(fenetre)
		moyChargeMilli := sommeChargeMilli / int64(fenetre)
		if moyPkgMW < cfg.PlancherPuissanceMilliW || moyChargeMilli < cfg.PlancherChargeMilli || sommePkgMW <= 0 {
			continue
		}
		episodes = append(episodes, episodeThermique{
			puissanceMoyenneW:   float64(moyPkgMW) / 1000.0,
			temperatureMoyenneC: float64(sommeTempMC) / (1000.0 * float64(fenetre)),
			resistanceCParW:     float64(sommeSurchauffeMC) / float64(sommePkgMW),
			chargeParKilowatt:   1000.0 * float64(sommeChargeMilli) / float64(sommePkgMW),
		})
	}
	return episodes
}

// EvaluerCampagnePowerlog compare sans aucun sous-échantillonnage les journaux
// dégradé (ex. 2026-10-28) et nominal (ex. 2026-10-29) en rapportant les effectifs,
// le taux de classe majoritaire et l'AUC exacte de Mann-Whitney.
func EvaluerCampagnePowerlog(
	degrade JournalPuissanceCharge,
	nominal JournalPuissanceCharge,
	cfg ConfigEvaluationPowerlog,
) (BilanCampagnePowerlog, error) {
	var bilan BilanCampagnePowerlog
	bilan.JournalDegrade = degrade
	bilan.JournalNominal = nominal
	bilan.FenetreEpisode = cfg.FenetreEpisode
	bilan.TemperatureReposCelsius = float64(cfg.TemperatureReposMilliC) / 1000.0

	tempReposEffectiveMC := cfg.TemperatureReposMilliC
	if !cfg.DesactiverCalibrationTempRepos {
		if tEstimeeMC, okCalib := estimerTemperatureReposNominalMilliC(nominal.Mesures, cfg.PlancherPuissanceMilliW); okCalib {
			tempReposEffectiveMC = tEstimeeMC
			bilan.CalibrationTempReposActive = true
		}
	}
	bilan.TemperatureReposEffectiveC = float64(tempReposEffectiveMC) / 1000.0

	epDeg := construireEpisodesDisjoints(degrade.Mesures, cfg, tempReposEffectiveMC)
	epNom := construireEpisodesDisjoints(nominal.Mesures, cfg, tempReposEffectiveMC)
	if len(epDeg) == 0 || len(epNom) == 0 {
		return bilan, ErrEchantillonVide
	}

	bilan.ComparaisonsEpisodes = []ComparaisonMetriqueROC{
		calculerROC("episode_puissance_brute_w", extraireChampEpisode(epDeg, 0), extraireChampEpisode(epNom, 0)),
		calculerROC("episode_temperature_brute_c", extraireChampEpisode(epDeg, 1), extraireChampEpisode(epNom, 1)),
		calculerROC("episode_resistance_thermique_c_par_w", extraireChampEpisode(epDeg, 2), extraireChampEpisode(epNom, 2)),
		calculerROC("episode_charge_par_kw", extraireChampEpisode(epDeg, 3), extraireChampEpisode(epNom, 3)),
	}

	cfgPonctuel := cfg
	cfgPonctuel.FenetreEpisode = 1
	ptDeg := construireEpisodesDisjoints(degrade.Mesures, cfgPonctuel, tempReposEffectiveMC)
	ptNom := construireEpisodesDisjoints(nominal.Mesures, cfgPonctuel, tempReposEffectiveMC)
	if len(ptDeg) > 0 && len(ptNom) > 0 {
		bilan.ComparaisonsPonctuelles = []ComparaisonMetriqueROC{
			calculerROC("ponctuel_puissance_brute_w", extraireChampEpisode(ptDeg, 0), extraireChampEpisode(ptNom, 0)),
			calculerROC("ponctuel_temperature_brute_c", extraireChampEpisode(ptDeg, 1), extraireChampEpisode(ptNom, 1)),
			calculerROC("ponctuel_resistance_thermique_c_par_w", extraireChampEpisode(ptDeg, 2), extraireChampEpisode(ptNom, 2)),
			calculerROC("ponctuel_charge_par_kw", extraireChampEpisode(ptDeg, 3), extraireChampEpisode(ptNom, 3)),
		}
	}

	// Tranches de puissance pour :
	// 1. Comparaison iso-puissance [50 W .. 90 W] dégradé vs [50 W .. 90 W] nominal (sans biais de levier P).
	// 2. Épreuve de confusion inter-charge : dégradé [50 W .. 90 W] vs nominal forte charge [>= 110 W].
	// 3. Contrôle négatif auto-nominal : nominal [50 W .. 90 W] vs nominal forte charge [>= 110 W].
	var tempDegMod, resDegMod []float64
	for _, m := range degrade.Mesures {
		if m.PuissancePkgMilliW >= 50_000 && m.PuissancePkgMilliW <= 90_000 {
			tempDegMod = append(tempDegMod, float64(m.TempPkgMilliC)/1000.0)
			ecart := math.Max(0, float64(m.TempPkgMilliC-tempReposEffectiveMC))
			resDegMod = append(resDegMod, ecart/float64(m.PuissancePkgMilliW))
		}
	}
	var tempNomMod, resNomMod []float64
	var tempNomFort, resNomFort []float64
	for _, m := range nominal.Mesures {
		if m.PuissancePkgMilliW >= 50_000 && m.PuissancePkgMilliW <= 90_000 {
			tempNomMod = append(tempNomMod, float64(m.TempPkgMilliC)/1000.0)
			ecart := math.Max(0, float64(m.TempPkgMilliC-tempReposEffectiveMC))
			resNomMod = append(resNomMod, ecart/float64(m.PuissancePkgMilliW))
		}
		if m.PuissancePkgMilliW >= 110_000 {
			tempNomFort = append(tempNomFort, float64(m.TempPkgMilliC)/1000.0)
			ecart := math.Max(0, float64(m.TempPkgMilliC-tempReposEffectiveMC))
			resNomFort = append(resNomFort, ecart/float64(m.PuissancePkgMilliW))
		}
	}
	if len(tempDegMod) > 0 && len(tempNomMod) > 0 {
		bilan.ComparaisonsIsoPuissance50a90W = []ComparaisonMetriqueROC{
			calculerROC("iso_50_90w_temperature_brute_c", tempDegMod, tempNomMod),
			calculerROC("iso_50_90w_resistance_thermique_c_par_w", resDegMod, resNomMod),
		}
	}
	if len(tempDegMod) > 0 && len(tempNomFort) > 0 {
		bilan.EpreuveConfusionForteCharge = []ComparaisonMetriqueROC{
			calculerROC("stress_temperature_brute_c", tempDegMod, tempNomFort),
			calculerROC("stress_resistance_thermique_c_par_w", resDegMod, resNomFort),
		}
	}
	if len(tempNomMod) > 0 && len(tempNomFort) > 0 {
		bilan.ControleAutoNominalModereVsFort = []ComparaisonMetriqueROC{
			calculerROC("controle_nominal_50_90w_vs_110w_temperature_brute_c", tempNomMod, tempNomFort),
			calculerROC("controle_nominal_50_90w_vs_110w_resistance_thermique_c_par_w", resNomMod, resNomFort),
		}
	}

	return bilan, nil
}

func extraireChampEpisode(episodes []episodeThermique, indiceChamp int) []float64 {
	sortie := make([]float64, len(episodes))
	for i, ep := range episodes {
		switch indiceChamp {
		case 0:
			sortie[i] = ep.puissanceMoyenneW
		case 1:
			sortie[i] = ep.temperatureMoyenneC
		case 2:
			sortie[i] = ep.resistanceCParW
		default:
			sortie[i] = ep.chargeParKilowatt
		}
	}
	return sortie
}

type pointEtiquete struct {
	score   float64
	positif bool
}

func calculerROC(nom string, positifs, negatifs []float64) ComparaisonMetriqueROC {
	nPos := len(positifs)
	nNeg := len(negatifs)
	total := nPos + nNeg
	var tauxMaj float64
	if total > 0 {
		if nPos >= nNeg {
			tauxMaj = float64(nPos) / float64(total)
		} else {
			tauxMaj = float64(nNeg) / float64(total)
		}
	}
	medPos, madmPos := medianeEtMADMFlottant(positifs)
	medNeg, madmNeg := medianeEtMADMFlottant(negatifs)
	if nPos == 0 || nNeg == 0 {
		return ComparaisonMetriqueROC{
			NomMetrique:            nom,
			EffectifDegradePositif: nPos,
			EffectifNominalNegatif: nNeg,
			TauxClasseMajoritaire:  tauxMaj,
			MedianeDegrade:         medPos,
			MADMDegrade:            madmPos,
			MedianeNominale:        medNeg,
			MADMNominal:            madmNeg,
		}
	}

	fusion := make([]pointEtiquete, 0, total)
	for _, s := range positifs {
		fusion = append(fusion, pointEtiquete{score: s, positif: true})
	}
	for _, s := range negatifs {
		fusion = append(fusion, pointEtiquete{score: s, positif: false})
	}
	sort.Slice(fusion, func(i, j int) bool {
		return fusion[i].score < fusion[j].score
	})

	// Mann-Whitney U exact avec rang moyen sur les groupes d'ex-aequo.
	sommeRangsPos := 0.0
	curseur := 0
	for curseur < len(fusion) {
		fin := curseur + 1
		for fin < len(fusion) && fusion[fin].score == fusion[curseur].score {
			fin++
		}
		rangMoyen := float64(curseur+1+fin) / 2.0
		posDansGroupe := 0
		for k := curseur; k < fin; k++ {
			if fusion[k].positif {
				posDansGroupe++
			}
		}
		sommeRangsPos += float64(posDansGroupe) * rangMoyen
		curseur = fin
	}
	statU := sommeRangsPos - float64(nPos)*float64(nPos+1)/2.0
	auc := statU / (float64(nPos) * float64(nNeg))

	// Balayage décroissant par seuils distincts pour TPR @ FPR==0 et TPR @ FPR<=1%.
	tpCumul := 0
	fpCumul := 0
	rappelFPRZero := 0.0
	rappelFPRUnPct := 0.0
	idx := len(fusion) - 1
	for idx >= 0 {
		debutGroupe := idx
		for debutGroupe > 0 && fusion[debutGroupe-1].score == fusion[idx].score {
			debutGroupe--
		}
		for k := debutGroupe; k <= idx; k++ {
			if fusion[k].positif {
				tpCumul++
			} else {
				fpCumul++
			}
		}
		tpr := float64(tpCumul) / float64(nPos)
		fpr := float64(fpCumul) / float64(nNeg)
		if fpCumul == 0 && tpr > rappelFPRZero {
			rappelFPRZero = tpr
		}
		if fpr <= 0.01 && tpr > rappelFPRUnPct {
			rappelFPRUnPct = tpr
		}
		idx = debutGroupe - 1
	}

	return ComparaisonMetriqueROC{
		NomMetrique:            nom,
		EffectifDegradePositif: nPos,
		EffectifNominalNegatif: nNeg,
		TauxClasseMajoritaire:  tauxMaj,
		MedianeDegrade:         medPos,
		MADMDegrade:            madmPos,
		MedianeNominale:        medNeg,
		MADMNominal:            madmNeg,
		AUCMannWhitney:         auc,
		RappelAFPRZero:         rappelFPRZero,
		RappelAFPRUnPourcent:   rappelFPRUnPct,
	}
}

func medianeEtMADMFlottant(echantillons []float64) (float64, float64) {
	if len(echantillons) == 0 {
		return 0, 0
	}
	copie := make([]float64, len(echantillons))
	copy(copie, echantillons)
	sort.Float64s(copie)
	mediane := medianeFlottantsTries(copie)

	ecarts := make([]float64, len(copie))
	for i, x := range copie {
		ecarts[i] = math.Abs(x - mediane)
	}
	sort.Float64s(ecarts)
	return mediane, medianeFlottantsTries(ecarts)
}

func medianeFlottantsTries(tries []float64) float64 {
	n := len(tries)
	if n == 0 {
		return 0
	}
	if n%2 == 1 {
		return tries[n/2]
	}
	return 0.5 * (tries[n/2-1] + tries[n/2])
}
