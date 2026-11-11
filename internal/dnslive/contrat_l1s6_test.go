package dnslive_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55/internal/dnslive"
)

// TestServiceLiveContratL1S6 porte les cas prescrits C01 et C02 de la strate
// L1-S6. Chaque appel prescrit est écrit en ligne droite au niveau du
// sous-test, une variable par départ, et chaque valeur rendue est comparée
// juste après l'appel.
func TestServiceLiveContratL1S6(t *testing.T) {
	clientContrat := &http.Client{Timeout: 5 * time.Second}

	t.Run("C01", func(t *testing.T) {
		repertoirePreuves := t.TempDir()
		serviceDemarre, erreurNew := dnslive.New(dnslive.Config{
			UDPListen:      "127.0.0.1:0",
			HTTPListen:     "127.0.0.1:0",
			EvidenceDir:    repertoirePreuves,
			DashboardToken: "jeton-l1s6",
		})
		if erreurNew != nil {
			t.Fatalf("New: erreur = %v, attendu nil", erreurNew)
		}
		if serviceDemarre == nil {
			t.Fatalf("New: service nul, attendu une instance")
		}
		erreurStart := serviceDemarre.Start()
		if erreurStart != nil {
			t.Fatalf("Start: erreur = %v, attendu nil", erreurStart)
		}
		adresseUDP := serviceDemarre.UDPAddr()
		_, portUDP, erreurSplitUDP := net.SplitHostPort(adresseUDP)
		if erreurSplitUDP != nil {
			t.Fatalf("UDPAddr %q non analysable: %v", adresseUDP, erreurSplitUDP)
		}
		if portUDP == "0" {
			t.Errorf("UDPAddr %q: port nul, attendu un port alloué", adresseUDP)
		}
		adresseHTTP := serviceDemarre.HTTPAddr()
		_, portHTTP, erreurSplitHTTP := net.SplitHostPort(adresseHTTP)
		if erreurSplitHTTP != nil {
			t.Fatalf("HTTPAddr %q non analysable: %v", adresseHTTP, erreurSplitHTTP)
		}
		if portHTTP == "0" {
			t.Errorf("HTTPAddr %q: port nul, attendu un port alloué", adresseHTTP)
		}
		requeteSante, erreurRequete := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+adresseHTTP+"/healthz", nil)
		if erreurRequete != nil {
			t.Fatalf("requête healthz: %v", erreurRequete)
		}
		reponseSante, erreurAppel := clientContrat.Do(requeteSante)
		if erreurAppel != nil {
			t.Fatalf("healthz: %v", erreurAppel)
		}
		if reponseSante.StatusCode != http.StatusOK {
			t.Errorf("healthz: code %d, attendu 200", reponseSante.StatusCode)
		}
		_, erreurLecture := io.Copy(io.Discard, io.LimitReader(reponseSante.Body, 1<<20))
		if erreurLecture != nil {
			t.Errorf("healthz: lecture du corps: %v", erreurLecture)
		}
		if erreurFermeture := reponseSante.Body.Close(); erreurFermeture != nil {
			t.Errorf("healthz: fermeture du corps: %v", erreurFermeture)
		}
		contexteCloture, annuleCloture := context.WithTimeout(t.Context(), 5*time.Second)
		erreurCloture := serviceDemarre.Close(contexteCloture)
		annuleCloture()
		if erreurCloture != nil {
			t.Errorf("Close: erreur = %v, attendu nil", erreurCloture)
		}
	})

	t.Run("C02", func(t *testing.T) {
		repertoirePreuves := t.TempDir()
		serviceUDPVide, erreurUDPVide := dnslive.New(dnslive.Config{
			UDPListen:      "",
			HTTPListen:     "127.0.0.1:0",
			EvidenceDir:    repertoirePreuves,
			DashboardToken: "jeton-l1s6",
		})
		if erreurUDPVide == nil {
			t.Fatalf("New sans UDPListen: erreur nulle, attendu ErrLiveConfig")
		}
		if !errors.Is(erreurUDPVide, dnslive.ErrLiveConfig) {
			t.Errorf("New sans UDPListen: erreur = %v, attendu ErrLiveConfig", erreurUDPVide)
		}
		if serviceUDPVide != nil {
			t.Errorf("New sans UDPListen: service = %v, attendu nil", serviceUDPVide)
		}
		serviceJetonVide, erreurJetonVide := dnslive.New(dnslive.Config{
			UDPListen:      "127.0.0.1:0",
			HTTPListen:     "127.0.0.1:0",
			EvidenceDir:    repertoirePreuves,
			DashboardToken: "",
		})
		if erreurJetonVide == nil {
			t.Fatalf("New sans DashboardToken: erreur nulle, attendu ErrLiveConfig")
		}
		if !errors.Is(erreurJetonVide, dnslive.ErrLiveConfig) {
			t.Errorf("New sans DashboardToken: erreur = %v, attendu ErrLiveConfig", erreurJetonVide)
		}
		if serviceJetonVide != nil {
			t.Errorf("New sans DashboardToken: service = %v, attendu nil", serviceJetonVide)
		}
		serviceRedemarre, erreurNewRedemarre := dnslive.New(dnslive.Config{
			UDPListen:      "127.0.0.1:0",
			HTTPListen:     "127.0.0.1:0",
			EvidenceDir:    repertoirePreuves,
			DashboardToken: "jeton-l1s6",
		})
		if erreurNewRedemarre != nil {
			t.Fatalf("New du service à redémarrer: %v", erreurNewRedemarre)
		}
		if serviceRedemarre == nil {
			t.Fatalf("New du service à redémarrer: service nul")
		}
		erreurPremierDepart := serviceRedemarre.Start()
		if erreurPremierDepart != nil {
			t.Fatalf("premier Start: erreur = %v, attendu nil", erreurPremierDepart)
		}
		erreurSecondDepart := serviceRedemarre.Start()
		if !errors.Is(erreurSecondDepart, dnslive.ErrLiveStarted) {
			t.Errorf("second Start: erreur = %v, attendu ErrLiveStarted", erreurSecondDepart)
		}
		contexteClotureRedemarre, annuleRedemarre := context.WithTimeout(t.Context(), 5*time.Second)
		erreurClotureRedemarre := serviceRedemarre.Close(contexteClotureRedemarre)
		annuleRedemarre()
		if erreurClotureRedemarre != nil {
			t.Errorf("Close du service à redémarrer: erreur = %v, attendu nil", erreurClotureRedemarre)
		}
		serviceApresCloture, erreurNewApresCloture := dnslive.New(dnslive.Config{
			UDPListen:      "127.0.0.1:0",
			HTTPListen:     "127.0.0.1:0",
			EvidenceDir:    repertoirePreuves,
			DashboardToken: "jeton-l1s6",
		})
		if erreurNewApresCloture != nil {
			t.Fatalf("New du service à clore: %v", erreurNewApresCloture)
		}
		if serviceApresCloture == nil {
			t.Fatalf("New du service à clore: service nul")
		}
		erreurDepartApresCloture := serviceApresCloture.Start()
		if erreurDepartApresCloture != nil {
			t.Fatalf("Start du service à clore: erreur = %v, attendu nil", erreurDepartApresCloture)
		}
		adresseHTTPApresCloture := serviceApresCloture.HTTPAddr()
		if _, _, erreurSplit := net.SplitHostPort(adresseHTTPApresCloture); erreurSplit != nil {
			t.Fatalf("HTTPAddr %q avant clôture non analysable: %v", adresseHTTPApresCloture, erreurSplit)
		}
		contexteClotureApresCloture, annuleApresCloture := context.WithTimeout(t.Context(), 5*time.Second)
		erreurClotureApresCloture := serviceApresCloture.Close(contexteClotureApresCloture)
		annuleApresCloture()
		if erreurClotureApresCloture != nil {
			t.Errorf("Close avant requête healthz: erreur = %v, attendu nil", erreurClotureApresCloture)
		}
		requeteApresCloture, erreurRequeteApresCloture := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+adresseHTTPApresCloture+"/healthz", nil)
		if erreurRequeteApresCloture != nil {
			t.Fatalf("requête healthz après clôture: %v", erreurRequeteApresCloture)
		}
		reponseApresCloture, erreurAppelApresCloture := clientContrat.Do(requeteApresCloture)
		if erreurAppelApresCloture == nil {
			_ = reponseApresCloture.Body.Close()
			t.Errorf("healthz après Close: réponse %d, attendu un échec de connexion", reponseApresCloture.StatusCode)
		}
		serviceJamaisDemarre, erreurNewJamais := dnslive.New(dnslive.Config{
			UDPListen:      "127.0.0.1:0",
			HTTPListen:     "127.0.0.1:0",
			EvidenceDir:    repertoirePreuves,
			DashboardToken: "jeton-l1s6",
		})
		if erreurNewJamais != nil {
			t.Fatalf("New du service jamais démarré: %v", erreurNewJamais)
		}
		if serviceJamaisDemarre == nil {
			t.Fatalf("New du service jamais démarré: service nul")
		}
		adresseUDPJamais := serviceJamaisDemarre.UDPAddr()
		if adresseUDPJamais != "" {
			t.Errorf("UDPAddr sans démarrage: %q, attendu chaîne vide", adresseUDPJamais)
		}
		adresseHTTPJamais := serviceJamaisDemarre.HTTPAddr()
		if adresseHTTPJamais != "" {
			t.Errorf("HTTPAddr sans démarrage: %q, attendu chaîne vide", adresseHTTPJamais)
		}
	})

	t.Run("C03", func(t *testing.T) {
		serviceAcces, erreurNewAcces := dnslive.New(dnslive.Config{
			UDPListen:      "127.0.0.1:0",
			HTTPListen:     "127.0.0.1:0",
			EvidenceDir:    t.TempDir(),
			DashboardToken: fixtureDashboardToken,
		})
		if erreurNewAcces != nil {
			t.Fatalf("New du service d'accès: %v", erreurNewAcces)
		}
		if serviceAcces == nil {
			t.Fatalf("New du service d'accès: service nul sans erreur")
		}
		erreurStartAcces := serviceAcces.Start()
		if erreurStartAcces != nil {
			t.Fatalf("Start du service d'accès: %v", erreurStartAcces)
		}
		transportAcces := &http.Transport{DisableKeepAlives: true}
		banc := &liveHarness{
			serviceLive: serviceAcces,
			httpBase:    "http://" + serviceAcces.HTTPAddr(),
			transport:   transportAcces,
			client:      &http.Client{Transport: transportAcces, Timeout: 3 * time.Second},
		}
		statutTableauMauvaisJeton, _, _ := banc.request(t, http.MethodGet, "/", nil, fixtureBasicAuth, "mauvais-jeton")
		if statutTableauMauvaisJeton != http.StatusUnauthorized {
			t.Errorf("tableau de bord avec un mot de passe faux: statut %d, attendu 401", statutTableauMauvaisJeton)
		}
		statutTableauBonJeton, _, _ := banc.request(t, http.MethodGet, "/", nil, fixtureBasicAuth, fixtureDashboardToken)
		if statutTableauBonJeton != http.StatusOK {
			t.Errorf("tableau de bord avec le bon mot de passe: statut %d, attendu 200", statutTableauBonJeton)
		}
		statutEvenementsSansJeton, _, _ := banc.request(t, http.MethodGet, "/api/v1/events", nil, fixtureNoAuth, "")
		if statutEvenementsSansJeton != http.StatusUnauthorized {
			t.Errorf("événements sans jeton porteur: statut %d, attendu 401", statutEvenementsSansJeton)
		}
		statutEvenementsBonJeton, _, _ := banc.request(t, http.MethodGet, "/api/v1/events", nil, fixtureBearerAuth, fixtureDashboardToken)
		if statutEvenementsBonJeton != http.StatusOK {
			t.Errorf("événements avec le jeton porteur: statut %d, attendu 200", statutEvenementsBonJeton)
		}
		adresseSource := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40053}
		statutIdentifiantInvalide, _, _ := banc.request(t, http.MethodPost, "/api/v1/registrations", fixtureRegistrationBody(t, "run invalide!", "P3", adresseSource), fixtureBearerAuth, fixtureDashboardToken)
		if statutIdentifiantInvalide != http.StatusBadRequest {
			t.Errorf("enregistrement à identifiant de run invalide: statut %d, attendu 400", statutIdentifiantInvalide)
		}
		statutEnregistrementValide, _, _ := banc.request(t, http.MethodPost, "/api/v1/registrations", fixtureRegistrationBody(t, "run-l1s6-contrat", "P3", adresseSource), fixtureBearerAuth, fixtureDashboardToken)
		if statutEnregistrementValide != http.StatusCreated {
			t.Errorf("enregistrement valide: statut %d, attendu 201", statutEnregistrementValide)
		}
		contexteClotureAcces, annuleClotureAcces := context.WithTimeout(context.Background(), 5*time.Second)
		defer annuleClotureAcces()
		erreurClotureAcces := serviceAcces.Close(contexteClotureAcces)
		if erreurClotureAcces != nil {
			t.Errorf("Close après un enregistrement valide: %v, attendu nil", erreurClotureAcces)
		}

		serviceOccupe, erreurNewOccupe := dnslive.New(dnslive.Config{
			UDPListen:      "127.0.0.1:0",
			HTTPListen:     "127.0.0.1:0",
			EvidenceDir:    t.TempDir(),
			DashboardToken: fixtureDashboardToken,
		})
		if erreurNewOccupe != nil {
			t.Fatalf("New du service occupé: %v", erreurNewOccupe)
		}
		if serviceOccupe == nil {
			t.Fatalf("New du service occupé: service nul sans erreur")
		}
		erreurStartOccupe := serviceOccupe.Start()
		if erreurStartOccupe != nil {
			t.Fatalf("Start du service occupé: %v", erreurStartOccupe)
		}
		var composeur net.Dialer
		connexionOuverte, erreurConnexion := composeur.DialContext(t.Context(), "tcp", serviceOccupe.HTTPAddr())
		if erreurConnexion != nil {
			t.Fatalf("connexion au service occupé: %v", erreurConnexion)
		}
		defer func() { _ = connexionOuverte.Close() }()
		// La requête annonce un corps qu'elle n'envoie pas : la réponse
		// intermédiaire 100 Continue prouve que le gestionnaire est entré en
		// lecture du corps, donc que la connexion est active côté serveur.
		enteteInacheve := "POST /api/v1/registrations HTTP/1.1\r\nHost: contrat\r\nAuthorization: Bearer " + fixtureDashboardToken +
			"\r\nContent-Type: application/json\r\nContent-Length: 64\r\nExpect: 100-continue\r\n\r\n"
		if _, erreurEcriture := connexionOuverte.Write([]byte(enteteInacheve)); erreurEcriture != nil {
			t.Fatalf("écriture d'une requête au corps inachevé: %v", erreurEcriture)
		}
		if erreurEcheance := connexionOuverte.SetReadDeadline(time.Now().Add(3 * time.Second)); erreurEcheance != nil {
			t.Fatalf("échéance de lecture: %v", erreurEcheance)
		}
		ligneIntermediaire, erreurLecture := bufio.NewReader(connexionOuverte).ReadString('\n')
		if erreurLecture != nil {
			t.Fatalf("lecture de la réponse intermédiaire: %v", erreurLecture)
		}
		if !strings.HasPrefix(ligneIntermediaire, "HTTP/1.1 100") {
			t.Fatalf("réponse intermédiaire = %q, attendu 100 Continue", ligneIntermediaire)
		}
		contexteEchu, annuleEchu := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer annuleEchu()
		erreurClotureOccupe := serviceOccupe.Close(contexteEchu)
		if erreurClotureOccupe == nil {
			t.Fatalf("Close sur contexte échu avec une connexion en cours: nil, attendu l'erreur d'arrêt HTTP")
		}
		if !strings.Contains(erreurClotureOccupe.Error(), "arrêt HTTP") {
			t.Errorf("Close sur contexte échu: %v, attendu une erreur d'arrêt HTTP", erreurClotureOccupe)
		}
		if strings.Contains(erreurClotureOccupe.Error(), "forcer l'arrêt HTTP") {
			t.Errorf("Close sur contexte échu: %v, la fermeture forcée a réussi et ne doit pas être rapportée en erreur", erreurClotureOccupe)
		}
	})
}
