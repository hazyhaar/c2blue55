package cinetique

import (
	"os"
	"strings"
	"testing"
)

// Strate V8 : l'arbitre causal devient un consommateur du formulaire c2slm
// (form.Compiler / form.RemplirDepuis, préfixe calculé une fois et conservé
// dans le cache KV) au lieu de piloter le moteur directement. Même brief,
// même amorce `{"cause":"`, mêmes quatre jetons (storage, network, memory,
// normal), même calibration à vide sur les sondes, même veto physique. Deux
// modèles : Qwen2.5-0.5B (ligne de base) et Qwen3-0.6B (base cible, bloc
// <think> vide dans l'amorce). Oracle : les cinq cas de référence de
// TestRevueQwenQuatreClassesSansVetoEtPlafondContexte, 5/5, sans veto.

const (
	v8CheminQwen25 = "/data/models/qwen2.5-0.5b-gguf/qwen2.5-0.5b-instruct-q4_k_m.gguf"
	v8CheminQwen3  = "/data/models/qwen3-0.6b-gguf/Qwen3-0.6B-Q8_0.gguf"
)

func v8CasReference(t *testing.T) []struct {
	nom     string
	diag    DiagnosticEpisodeCinetique
	attendu string
} {
	t.Helper()
	epStorage := construireEpisodeReference(t, 0, 8_000_000, 100_000, 45_000_000, 30_000, 100, CompteursReseauEpisode{})
	diagStorage := DiagnosticEpisodeCinetique{Orientation: OrientationDegradationES, Episode: epStorage}
	diagStorage.VariationsPct[IndiceDilatationHorsCPU] = 480
	epNetwork := construireEpisodeReference(t, 0, 24_000_000, 100_000, 300_000, 32_000, 100, CompteursReseauEpisode{OctetsSortants: 32_768, ConnexionsSortantes: 1, ResolutionsDNS: 4, PortSuspect: 53, ProtocoleSuspectUDP: true, CodeRaisonDNS: 5})
	diagNetwork := DiagnosticEpisodeCinetique{Orientation: OrientationCompromissionReseau, Episode: epNetwork}
	diagNetwork.VariationsPct[IndiceNsCPUParKioLogique] = 220
	epMemory := construireEpisodeReference(t, 0, 8_000_000, 100_000, 300_000, 38_000, 100, CompteursReseauEpisode{})
	diagMemory := DiagnosticEpisodeCinetique{Orientation: OrientationDeriveOrganique, PasDeriveMonotoneRSS: 6, Episode: epMemory}
	diagMemory.VariationsPct[IndiceKioPicRSSParFil] = 26
	epMemoryPSI := construireEpisodeReference(t, 0, 8_000_000, 100_000, 300_000, 38_000, 15_000, CompteursReseauEpisode{})
	diagMemoryPSI := DiagnosticEpisodeCinetique{Orientation: OrientationDeriveOrganique, PasDeriveMonotoneRSS: 6, Episode: epMemoryPSI}
	diagMemoryPSI.VariationsPct[IndiceKioPicRSSParFil] = 26
	debutIdle := InstantaneTache{PID: 88, DebutTacheTicks: 444, HorodatageNs: 1_000_000}
	finIdle := InstantaneTache{PID: 88, DebutTacheTicks: 444, HorodatageNs: 31_000_000, TempsExecutionNs: 2_000_000, AttenteFileNs: 8_000_000, CommutationsVolontaires: 10, CommutationsSubies: 20, VmRSSKio: 20_000, NombreFils: 1}
	epNormal, err := EvaluerEpisodeCinetique(debutIdle, finIdle, InstantanePressionPSI{HorodatageNs: 1_000_000}, InstantanePressionPSI{HorodatageNs: 31_000_000, CPUSomeTotalUs: 12_000}, CompteursReseauEpisode{OctetsSortants: 200, ConnexionsSortantes: 1, ResolutionsDNS: 1}, TopologieHybride{}, ConfigPlanchersParDefaut())
	if err != nil {
		t.Fatalf("epNormal: %v", err)
	}
	diagNormal := DiagnosticEpisodeCinetique{Orientation: OrientationEcartStructurel, Episode: epNormal}
	diagNormal.VariationsPct[IndiceDilatationHorsCPU] = 310
	return []struct {
		nom     string
		diag    DiagnosticEpisodeCinetique
		attendu string
	}{
		{"daemon_alpha", diagStorage, VerdictSLMDegradationMaterielle},
		{"daemon_beta", diagNetwork, VerdictSLMCompromissionExfil},
		{"storage_sync_ trompeur", diagMemory, VerdictSLMDeriveOrganique},
		{"daemon_gamma_psi", diagMemoryPSI, VerdictSLMDeriveOrganique},
		{"daemon_delta", diagNormal, VerdictSLMContentionOuInsuff},
	}
}

func v8Jouer(t *testing.T, chemin, etiquette string) {
	t.Helper()
	if _, err := os.Stat(chemin); err != nil {
		t.Skipf("modèle absent : %v", err)
	}
	arbitre, err := NouvelArbitreFormulaireCinetique(chemin)
	if err != nil {
		t.Fatalf("NouvelArbitreFormulaireCinetique(%s): %v", etiquette, err)
	}
	defer func() { _ = arbitre.Fermer() }()
	var _ ArbitreCausalCinetique = arbitre
	longueurPrefixe := arbitre.longueurPrefixe
	if longueurPrefixe <= 0 || arbitre.moteur.KVCache.SeqLen != longueurPrefixe {
		t.Fatalf("%s : préfixe non résident (longueur %d, SeqLen %d)", etiquette, longueurPrefixe, arbitre.moteur.KVCache.SeqLen)
	}
	bons := 0
	for _, c := range v8CasReference(t) {
		dec, err := arbitre.ArbitrerEpisode(t.Context(), c.nom, c.diag)
		if err != nil {
			t.Fatalf("%s %s : %v", etiquette, c.nom, err)
		}
		if !dec.ModeleInvoque || !strings.HasPrefix(dec.MoteurArbitre, "Formulaire:") || dec.DureeInferenceUs == 0 {
			t.Errorf("%s %s : décision mal renseignée %+v", etiquette, c.nom, dec)
		}
		if dec.VetoPhysiqueApplique {
			t.Errorf("%s %s : veto appliqué (%s) sur un cas de référence", etiquette, c.nom, dec.MotifVeto)
		}
		if dec.BiaisNeutreModele == [nombreVerdictsCausaux]float32{} {
			t.Errorf("%s %s : biais neutre absent (calibration à vide)", etiquette, c.nom)
		}
		for i := range dec.DeltaLogitsModele {
			if dec.DeltaLogitsModele[i] != dec.LogitsBrutsModele[i]-dec.BiaisNeutreModele[i] {
				t.Errorf("%s %s : delta[%d] ≠ brut − biais", etiquette, c.nom, i)
			}
		}
		if dec.VerdictBrutModele == c.attendu {
			bons++
		}
		t.Logf("%s %-24s brut=%s calibré=%s final=%s delta=%v %d µs", etiquette, c.nom, dec.VerdictBrutNonCalibre, dec.VerdictBrutModele, dec.VerdictFinal, dec.DeltaLogitsModele, dec.DureeInferenceUs)
		if arbitre.moteur.KVCache.SeqLen < longueurPrefixe {
			t.Fatalf("%s : préfixe perdu après %s", etiquette, c.nom)
		}
	}
	if bons != 5 {
		t.Errorf("%s : %d/5 cas de référence corrects", etiquette, bons)
	}
}

func TestArbitreFormulaire_CinqCasQwen25(t *testing.T) { v8Jouer(t, v8CheminQwen25, "qwen2.5-0.5b") }
func TestArbitreFormulaire_CinqCasQwen3(t *testing.T)  { v8Jouer(t, v8CheminQwen3, "qwen3-0.6b") }
