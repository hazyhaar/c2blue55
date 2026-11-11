package main

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55/internal/dnslive"
)

// TestDNSLiveContratL1S7 exerce les deux déclarations prescrites de la strate
// L1-S7 : resolveLanguage pour l'arbitrage de langue et runService pour le
// refus sous contrat et l'arrêt à l'annulation du contexte reçu.
func TestDNSLiveContratL1S7(t *testing.T) {
	t.Run("C01", func(t *testing.T) {
		delaiFermeture := delaiFermetureService()
		if delaiFermeture != 10*time.Second {
			t.Errorf("delaiFermetureService() = %v ; attendu 10s", delaiFermeture)
		}
		t.Setenv("C2BLUE_LANG", "en")
		languageDepuisEnvironnement, errEnvironnement := resolveLanguage("")
		if errEnvironnement != nil {
			t.Fatalf(`resolveLanguage("") avec C2BLUE_LANG=en : erreur inattendue : %v`, errEnvironnement)
		}
		if languageDepuisEnvironnement != "en" {
			t.Errorf(`resolveLanguage("") avec C2BLUE_LANG=en : langue rendue %q, attendu "en"`, languageDepuisEnvironnement)
		}
		languageDepuisDrapeau, errDrapeau := resolveLanguage("fr")
		if errDrapeau != nil {
			t.Fatalf(`resolveLanguage("fr") avec C2BLUE_LANG=en : erreur inattendue : %v`, errDrapeau)
		}
		if languageDepuisDrapeau != "fr" {
			t.Errorf(`resolveLanguage("fr") avec C2BLUE_LANG=en : langue rendue %q, attendu "fr" (le drapeau l'emporte sur C2BLUE_LANG)`, languageDepuisDrapeau)
		}
		t.Setenv("C2BLUE_LANG", "")
		languageVide, errVide := resolveLanguage("")
		if errVide != nil {
			t.Fatalf(`resolveLanguage("") avec C2BLUE_LANG vide : erreur inattendue : %v`, errVide)
		}
		if languageVide != "" {
			t.Errorf(`resolveLanguage("") avec C2BLUE_LANG vide : langue rendue %q, attendu vide`, languageVide)
		}
		t.Setenv("C2BLUE_DASHBOARD_TOKEN", "jeton")
		repertoirePreuvesValide := t.TempDir()
		ctxDemarrageValide, annuleDemarrageValide := context.WithTimeout(t.Context(), 300*time.Millisecond)
		defer annuleDemarrageValide()
		instantDemarrageValide := time.Now()
		errDemarrageValide := runService(ctxDemarrageValide, "127.0.0.1:0", "127.0.0.1:0", repertoirePreuvesValide, "fr")
		dureeDemarrageValide := time.Since(instantDemarrageValide)
		if errDemarrageValide != nil {
			t.Fatalf("runService avec jeton et langue fr : erreur inattendue : %v", errDemarrageValide)
		}
		if dureeDemarrageValide < 250*time.Millisecond {
			t.Errorf("runService avec jeton et langue fr : durée %v, attendu au moins 250 ms (arrêt à l'annulation du contexte)", dureeDemarrageValide)
		}
		if dureeDemarrageValide >= 10*time.Second {
			t.Errorf("runService avec jeton et langue fr : durée %v, attendu strictement inférieure à 10 s", dureeDemarrageValide)
		}
	})
	t.Run("C02", func(t *testing.T) {
		t.Setenv("C2BLUE_LANG", "")
		languageAllemande, errAllemande := resolveLanguage("de")
		if errAllemande == nil {
			t.Fatalf(`resolveLanguage("de") : succès inattendu, attendu une erreur`)
		}
		if languageAllemande != "" {
			t.Errorf(`resolveLanguage("de") : langue rendue %q, attendu vide`, languageAllemande)
		}
		if !strings.Contains(errAllemande.Error(), "non reconnue") {
			t.Errorf(`resolveLanguage("de") : erreur %q ne contient pas "non reconnue"`, errAllemande.Error())
		}
		t.Setenv("C2BLUE_LANG", "es")
		languageEspagnole, errEspagnole := resolveLanguage("")
		if errEspagnole == nil {
			t.Fatalf(`resolveLanguage("") avec C2BLUE_LANG=es : succès inattendu, attendu une erreur`)
		}
		if languageEspagnole != "" {
			t.Errorf(`resolveLanguage("") avec C2BLUE_LANG=es : langue rendue %q, attendu vide`, languageEspagnole)
		}
		if !strings.Contains(errEspagnole.Error(), "non reconnue") {
			t.Errorf(`resolveLanguage("") avec C2BLUE_LANG=es : erreur %q ne contient pas "non reconnue"`, errEspagnole.Error())
		}
		t.Setenv("C2BLUE_LANG", "")
		t.Setenv("C2BLUE_DASHBOARD_TOKEN", "")
		repertoireSansJeton := t.TempDir()
		ctxSansJeton, annuleSansJeton := context.WithTimeout(t.Context(), 2*time.Second)
		defer annuleSansJeton()
		instantSansJeton := time.Now()
		errSansJeton := runService(ctxSansJeton, "127.0.0.1:0", "127.0.0.1:0", repertoireSansJeton, "")
		dureeSansJeton := time.Since(instantSansJeton)
		if errSansJeton == nil {
			t.Fatalf(`runService sans C2BLUE_DASHBOARD_TOKEN : succès inattendu, attendu un refus immédiat`)
		}
		if errSansJeton.Error() != "C2BLUE_DASHBOARD_TOKEN est requis" {
			t.Errorf(`runService sans C2BLUE_DASHBOARD_TOKEN : erreur %q, attendu exactement "C2BLUE_DASHBOARD_TOKEN est requis"`, errSansJeton.Error())
		}
		if dureeSansJeton >= time.Second {
			t.Errorf("runService sans C2BLUE_DASHBOARD_TOKEN : durée %v, attendu strictement inférieure à 1 s (refus immédiat)", dureeSansJeton)
		}
		t.Setenv("C2BLUE_DASHBOARD_TOKEN", "jeton")
		repertoireLangueForgée := t.TempDir()
		ctxLangueForgée, annuleLangueForgée := context.WithTimeout(t.Context(), 2*time.Second)
		defer annuleLangueForgée()
		instantLangueForgée := time.Now()
		errLangueForgée := runService(ctxLangueForgée, "127.0.0.1:0", "127.0.0.1:0", repertoireLangueForgée, "de")
		dureeLangueForgée := time.Since(instantLangueForgée)
		if errLangueForgée == nil {
			t.Fatalf(`runService avec langue "de" : succès inattendu, attendu une erreur`)
		}
		if !strings.Contains(errLangueForgée.Error(), "non reconnue") {
			t.Errorf(`runService avec langue "de" : erreur %q ne contient pas "non reconnue"`, errLangueForgée.Error())
		}
		if dureeLangueForgée >= time.Second {
			t.Errorf(`runService avec langue "de" : durée %v, attendu strictement inférieure à 1 s (refus immédiat)`, dureeLangueForgée)
		}
		repertoireVide := ""
		ctxRepertoireVide, annuleRepertoireVide := context.WithTimeout(t.Context(), 2*time.Second)
		defer annuleRepertoireVide()
		instantRepertoireVide := time.Now()
		errRepertoireVide := runService(ctxRepertoireVide, "127.0.0.1:0", "127.0.0.1:0", repertoireVide, "fr")
		dureeRepertoireVide := time.Since(instantRepertoireVide)
		if errRepertoireVide == nil {
			t.Fatalf("runService avec répertoire de preuves vide : succès inattendu, attendu une erreur")
		}
		if !errors.Is(errRepertoireVide, dnslive.ErrLiveConfig) {
			t.Errorf("runService avec répertoire de preuves vide : erreur %v, attendu ErrLiveConfig via errors.Is", errRepertoireVide)
		}
		if dureeRepertoireVide >= time.Second {
			t.Errorf("runService avec répertoire de preuves vide : durée %v, attendu strictement inférieure à 1 s (refus immédiat)", dureeRepertoireVide)
		}
		var configurationEcoute net.ListenConfig
		connexionUDPOccupée, errÉcouteOccupée := configurationEcoute.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
		if errÉcouteOccupée != nil {
			t.Fatalf("préparation de l'écoute UDP de test : %v", errÉcouteOccupée)
		}
		defer func() {
			if errFermetureÉcoute := connexionUDPOccupée.Close(); errFermetureÉcoute != nil {
				t.Errorf("fermeture de l'écoute UDP de test : %v", errFermetureÉcoute)
			}
		}()
		adresseUDPOccupée := connexionUDPOccupée.LocalAddr().String()
		repertoirePortOccupé := t.TempDir()
		ctxPortOccupé, annulePortOccupé := context.WithTimeout(t.Context(), 2*time.Second)
		defer annulePortOccupé()
		instantPortOccupé := time.Now()
		errPortOccupé := runService(ctxPortOccupé, adresseUDPOccupée, "127.0.0.1:0", repertoirePortOccupé, "fr")
		dureePortOccupé := time.Since(instantPortOccupé)
		if errPortOccupé == nil {
			t.Fatalf("runService sur une adresse UDP déjà occupée : succès inattendu, attendu une erreur")
		}
		if dureePortOccupé >= time.Second {
			t.Errorf("runService sur une adresse UDP déjà occupée : durée %v, attendu strictement inférieure à 1 s (échec d'écoute immédiat)", dureePortOccupé)
		}
	})
}
