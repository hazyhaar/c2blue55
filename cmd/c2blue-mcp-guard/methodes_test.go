// Package main — methodes_test.go
// Tests de contrat de la strate L1-S4 (garde MCP à liste fermée de méthodes).
// C01 vérifie que methodeTransmissible reconnaît exactement initialize, ping
// et tools/list avec identifiant, et notifications/initialized et
// notifications/cancelled sans identifiant, et que FilterLine transmet les
// lignes JSON-RPC correspondantes ainsi que les réponses du client dépourvues
// de méthode (forward=true, vetoResponse=nil, incident=nil). C02 vérifie que
// toute méthode hors liste fermée (resources/read, prompts/get,
// completion/complete, sampling/createMessage, casse distincte, suffixes
// proches, notifications mal formées ou portant un identifiant) est refusée :
// forward=false et incident=nil, veto JSON-RPC -32601 répétant l'identifiant
// d'origine lorsque la requête en porte un, silence sans identifiant ; C02
// matérialise le scénario hostile SH-L1S4-1, une ligne resources/read visant
// un fichier sensible qui n'atteint jamais le serveur MCP sous-jacent. C03
// vérifie que writeMessage écrit la ligne suivie de l'octet 0x0A et que la
// table nl vaut exactement un octet 0x0A. C04 vérifie qu'un tools/call admis
// par la grammaire du catalogue par défaut est transmis sans veto. C05
// vérifie qu'un tools/call d'outil inconnu reçoit l'erreur -32601 et qu'une
// charge Base64 dense sur read_file reçoit -32003 avec error.data.tool
// valant "read_file". C06 vérifie qu'une ligne dépourvue de méthode n'est
// transmise que si elle a la forme d'une réponse JSON-RPC du client (clé id,
// exactement une des clés result ou error, aucune clé params) ; toute autre
// ligne sans méthode est refusée comme non analysable par le veto -32600 à
// identifiant nul, le témoin result-seul restant transmis, et une ligne à
// clé method dupliquée, jugée non analysable par parseMCPCall, reçoit le
// même veto. C03 éprouve en outre l'échec franc de writeMessage sur un
// écrivain qui rend une écriture courte (io.ErrShortWrite) et sur un
// écrivain qui rend une erreur explicite. C07 éprouve le chemin des requêtes
// valides sans allocation ajoutée : sur une requête ping et sur une
// notification, FilterLine alloue au plus autant que parseMCPCall sur la même
// ligne (référence d'analyse mesurée dans le même sous-test), la réponse du
// client reste transmise, et writeMessage écrit len(ligne)+1 octets avec
// exactement une allocation par appel ; chaque mesure est précédée d'appels
// directs assertés de FilterLine et de writeMessage.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/hazyhaar/c2blue55/socagent"
)

// redacteurEcritureAbregee rend une écriture courte d'un octet à chaque
// appel, sans erreur, pour éprouver la détection io.ErrShortWrite.
type redacteurEcritureAbregee struct{}

func (redacteurEcritureAbregee) Write(p []byte) (int, error) {
	return len(p) - 1, nil
}

// redacteurEcritureDefaillante rend zéro octet écrit et l'erreur imposée par
// le champ echec, pour éprouver la restitution de l'erreur d'écriture.
type redacteurEcritureDefaillante struct {
	echec error
}

func (r redacteurEcritureDefaillante) Write([]byte) (int, error) {
	return 0, r.echec
}

// compteurOctets est un écrivain qui additionne la longueur de chaque écriture
// sans conserver les octets, pour éprouver writeMessage sur les octets écrits
// et mesurer ses allocations hors conservation de tampon.
type compteurOctets struct {
	totalOctets int
}

func (c *compteurOctets) Write(p []byte) (int, error) {
	c.totalOctets += len(p)
	return len(p), nil
}

func TestContratMethodes(t *testing.T) {
	if errCatalogue := loadDefaultCatalog(); errCatalogue != nil {
		t.Fatalf("loadDefaultCatalog : %v", errCatalogue)
	}
	t.Run("C01", func(t *testing.T) {
		transmissibleInitialisation := methodeTransmissible([]byte("initialize"), true)
		if !transmissibleInitialisation {
			t.Errorf(`methodeTransmissible("initialize", true) = false ; attendu true`)
		}
		transmissibleSondage := methodeTransmissible([]byte("ping"), true)
		if !transmissibleSondage {
			t.Errorf(`methodeTransmissible("ping", true) = false ; attendu true`)
		}
		transmissibleListeOutils := methodeTransmissible([]byte("tools/list"), true)
		if !transmissibleListeOutils {
			t.Errorf(`methodeTransmissible("tools/list", true) = false ; attendu true`)
		}
		transmissibleNotificationInitialisee := methodeTransmissible([]byte("notifications/initialized"), false)
		if !transmissibleNotificationInitialisee {
			t.Errorf(`methodeTransmissible("notifications/initialized", false) = false ; attendu true`)
		}
		transmissibleNotificationAnnulee := methodeTransmissible([]byte("notifications/cancelled"), false)
		if !transmissibleNotificationAnnulee {
			t.Errorf(`methodeTransmissible("notifications/cancelled", false) = false ; attendu true`)
		}
		avanceInitialisation, vetoInitialisation, dossierInitialisation := FilterLine([]byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
		if !avanceInitialisation {
			t.Errorf("FilterLine(initialize, id 1) : forward = false ; attendu true")
		}
		if vetoInitialisation != nil {
			t.Errorf("FilterLine(initialize, id 1) : vetoResponse = %q ; attendu nil", vetoInitialisation)
		}
		if dossierInitialisation != nil {
			t.Errorf("FilterLine(initialize, id 1) : incident non nil ; attendu nil")
		}
		avanceSondage, vetoSondage, dossierSondage := FilterLine([]byte(`{"jsonrpc":"2.0","id":2,"method":"ping"}`))
		if !avanceSondage {
			t.Errorf("FilterLine(ping, id 2) : forward = false ; attendu true")
		}
		if vetoSondage != nil {
			t.Errorf("FilterLine(ping, id 2) : vetoResponse = %q ; attendu nil", vetoSondage)
		}
		if dossierSondage != nil {
			t.Errorf("FilterLine(ping, id 2) : incident non nil ; attendu nil")
		}
		avanceListeOutils, vetoListeOutils, dossierListeOutils := FilterLine([]byte(`{"jsonrpc":"2.0","id":3,"method":"tools/list"}`))
		if !avanceListeOutils {
			t.Errorf("FilterLine(tools/list, id 3) : forward = false ; attendu true")
		}
		if vetoListeOutils != nil {
			t.Errorf("FilterLine(tools/list, id 3) : vetoResponse = %q ; attendu nil", vetoListeOutils)
		}
		if dossierListeOutils != nil {
			t.Errorf("FilterLine(tools/list, id 3) : incident non nil ; attendu nil")
		}
		avanceNotificationInitialisee, vetoNotificationInitialisee, dossierNotificationInitialisee := FilterLine([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`))
		if !avanceNotificationInitialisee {
			t.Errorf("FilterLine(notifications/initialized) : forward = false ; attendu true")
		}
		if vetoNotificationInitialisee != nil {
			t.Errorf("FilterLine(notifications/initialized) : vetoResponse = %q ; attendu nil", vetoNotificationInitialisee)
		}
		if dossierNotificationInitialisee != nil {
			t.Errorf("FilterLine(notifications/initialized) : incident non nil ; attendu nil")
		}
		avanceNotificationAnnulee, vetoNotificationAnnulee, dossierNotificationAnnulee := FilterLine([]byte(`{"jsonrpc":"2.0","method":"notifications/cancelled"}`))
		if !avanceNotificationAnnulee {
			t.Errorf("FilterLine(notifications/cancelled) : forward = false ; attendu true")
		}
		if vetoNotificationAnnulee != nil {
			t.Errorf("FilterLine(notifications/cancelled) : vetoResponse = %q ; attendu nil", vetoNotificationAnnulee)
		}
		if dossierNotificationAnnulee != nil {
			t.Errorf("FilterLine(notifications/cancelled) : incident non nil ; attendu nil")
		}
		avanceReponseResultat, vetoReponseResultat, dossierReponseResultat := FilterLine([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		if !avanceReponseResultat {
			t.Errorf("FilterLine(réponse du client, result, id 1) : forward = false ; attendu true (réponse sans méthode toujours transmise)")
		}
		if vetoReponseResultat != nil {
			t.Errorf("FilterLine(réponse du client, result, id 1) : vetoResponse = %q ; attendu nil", vetoReponseResultat)
		}
		if dossierReponseResultat != nil {
			t.Errorf("FilterLine(réponse du client, result, id 1) : incident non nil ; attendu nil")
		}
		avanceReponseErreur, vetoReponseErreur, dossierReponseErreur := FilterLine([]byte(`{"jsonrpc":"2.0","id":"s-3","error":{"code":-32000,"message":"x"}}`))
		if !avanceReponseErreur {
			t.Errorf(`FilterLine(réponse du client, error, id "s-3") : forward = false ; attendu true (réponse sans méthode toujours transmise)`)
		}
		if vetoReponseErreur != nil {
			t.Errorf(`FilterLine(réponse du client, error, id "s-3") : vetoResponse = %q ; attendu nil`, vetoReponseErreur)
		}
		if dossierReponseErreur != nil {
			t.Errorf(`FilterLine(réponse du client, error, id "s-3") : incident non nil ; attendu nil`)
		}
	})

	t.Run("C02", func(t *testing.T) {
		type reponseVeto struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Error   struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		refusRessourcesLues := methodeTransmissible([]byte("resources/read"), true)
		if refusRessourcesLues {
			t.Errorf(`methodeTransmissible("resources/read", true) = true ; attendu false`)
		}
		refusObtentionPrompt := methodeTransmissible([]byte("prompts/get"), true)
		if refusObtentionPrompt {
			t.Errorf(`methodeTransmissible("prompts/get", true) = true ; attendu false`)
		}
		refusCompletions := methodeTransmissible([]byte("completion/complete"), true)
		if refusCompletions {
			t.Errorf(`methodeTransmissible("completion/complete", true) = true ; attendu false`)
		}
		refusEchantillonnage := methodeTransmissible([]byte("sampling/createMessage"), true)
		if refusEchantillonnage {
			t.Errorf(`methodeTransmissible("sampling/createMessage", true) = true ; attendu false`)
		}
		refusCasseSondage := methodeTransmissible([]byte("Ping"), true)
		if refusCasseSondage {
			t.Errorf(`methodeTransmissible("Ping", true) = true ; attendu false`)
		}
		refusListeOutilProche := methodeTransmissible([]byte("tools/listx"), true)
		if refusListeOutilProche {
			t.Errorf(`methodeTransmissible("tools/listx", true) = true ; attendu false`)
		}
		refusNotificationsSansChemin := methodeTransmissible([]byte("notifications"), false)
		if refusNotificationsSansChemin {
			t.Errorf(`methodeTransmissible("notifications", false) = true ; attendu false`)
		}
		refusNotificationTronquee := methodeTransmissible([]byte("notifications/"), false)
		if refusNotificationTronquee {
			t.Errorf(`methodeTransmissible("notifications/", false) = true ; attendu false`)
		}
		refusNotificationAvecIdentifiant := methodeTransmissible([]byte("notifications/x"), true)
		if refusNotificationAvecIdentifiant {
			t.Errorf(`methodeTransmissible("notifications/x", true) = true ; attendu false`)
		}
		refusNotificationsInfixees := methodeTransmissible([]byte("x/notifications/y"), false)
		if refusNotificationsInfixees {
			t.Errorf(`methodeTransmissible("x/notifications/y", false) = true ; attendu false`)
		}
		refusChaineVide := methodeTransmissible([]byte(""), true)
		if refusChaineVide {
			t.Errorf(`methodeTransmissible("", true) = true ; attendu false`)
		}
		ligneOmbre := []byte(`{"jsonrpc":"2.0","id":7,"method":"resources/read","params":{"uri":"file:///etc/shadow"}}`)
		avanceOmbre, vetoOmbre, dossierOmbre := FilterLine(ligneOmbre)
		if avanceOmbre {
			t.Errorf("FilterLine(resources/read, id 7) : forward = true ; attendu false (SH-L1S4-1 : la ligne n'atteint jamais le serveur MCP)")
		}
		if dossierOmbre != nil {
			t.Errorf("FilterLine(resources/read, id 7) : incident non nil ; attendu nil")
		}
		if vetoOmbre == nil {
			t.Errorf("FilterLine(resources/read, id 7) : vetoResponse = nil ; attendu un objet d'erreur JSON-RPC -32601")
		} else {
			var reponseOmbre reponseVeto
			if errDecodageOmbre := json.Unmarshal(vetoOmbre, &reponseOmbre); errDecodageOmbre != nil {
				t.Errorf("FilterLine(resources/read, id 7) : décodage de vetoResponse %q : %v", vetoOmbre, errDecodageOmbre)
			} else {
				if reponseOmbre.JSONRPC != "2.0" {
					t.Errorf("FilterLine(resources/read, id 7) : jsonrpc = %q ; attendu %q", reponseOmbre.JSONRPC, "2.0")
				}
				if string(reponseOmbre.ID) != "7" {
					t.Errorf("FilterLine(resources/read, id 7) : id de vetoResponse = %s ; attendu 7", reponseOmbre.ID)
				}
				if reponseOmbre.Error.Code != -32601 {
					t.Errorf("FilterLine(resources/read, id 7) : error.code = %d ; attendu -32601", reponseOmbre.Error.Code)
				}
				if reponseOmbre.Error.Message != "Method not allowed by guard" {
					t.Errorf("FilterLine(resources/read, id 7) : error.message = %q ; attendu %q", reponseOmbre.Error.Message, "Method not allowed by guard")
				}
			}
		}
		ligneOmbreAbc := []byte(`{"jsonrpc":"2.0","id":"abc","method":"resources/read","params":{"uri":"file:///etc/shadow"}}`)
		avanceOmbreAbc, vetoOmbreAbc, dossierOmbreAbc := FilterLine(ligneOmbreAbc)
		if avanceOmbreAbc {
			t.Errorf(`FilterLine(resources/read, id "abc") : forward = true ; attendu false`)
		}
		if dossierOmbreAbc != nil {
			t.Errorf(`FilterLine(resources/read, id "abc") : incident non nil ; attendu nil`)
		}
		if vetoOmbreAbc == nil {
			t.Errorf(`FilterLine(resources/read, id "abc") : vetoResponse = nil ; attendu un objet d'erreur JSON-RPC -32601`)
		} else {
			var reponseOmbreAbc reponseVeto
			if errDecodageOmbreAbc := json.Unmarshal(vetoOmbreAbc, &reponseOmbreAbc); errDecodageOmbreAbc != nil {
				t.Errorf(`FilterLine(resources/read, id "abc") : décodage de vetoResponse %q : %v`, vetoOmbreAbc, errDecodageOmbreAbc)
			} else {
				if reponseOmbreAbc.JSONRPC != "2.0" {
					t.Errorf(`FilterLine(resources/read, id "abc") : jsonrpc = %q ; attendu %q`, reponseOmbreAbc.JSONRPC, "2.0")
				}
				if string(reponseOmbreAbc.ID) != `"abc"` {
					t.Errorf(`FilterLine(resources/read, id "abc") : id de vetoResponse = %s ; attendu "abc"`, reponseOmbreAbc.ID)
				}
				if reponseOmbreAbc.Error.Code != -32601 {
					t.Errorf(`FilterLine(resources/read, id "abc") : error.code = %d ; attendu -32601`, reponseOmbreAbc.Error.Code)
				}
				if reponseOmbreAbc.Error.Message != "Method not allowed by guard" {
					t.Errorf(`FilterLine(resources/read, id "abc") : error.message = %q ; attendu %q`, reponseOmbreAbc.Error.Message, "Method not allowed by guard")
				}
			}
		}
		identifiantEtendu := strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3ODkrLw", 3)[:120]
		ligneOmbreEtendue := []byte(`{"jsonrpc":"2.0","id":"` + identifiantEtendu + `","method":"resources/read","params":{"uri":"file:///etc/shadow"}}`)
		avanceOmbreEtendue, vetoOmbreEtendue, dossierOmbreEtendue := FilterLine(ligneOmbreEtendue)
		if avanceOmbreEtendue {
			t.Errorf(`FilterLine(resources/read, id étendu 120 caractères) : forward = true ; attendu false`)
		}
		if dossierOmbreEtendue != nil {
			t.Errorf(`FilterLine(resources/read, id étendu 120 caractères) : incident non nil ; attendu nil`)
		}
		if vetoOmbreEtendue == nil {
			t.Errorf(`FilterLine(resources/read, id étendu 120 caractères) : vetoResponse = nil ; attendu un objet d'erreur JSON-RPC -32601`)
		} else {
			var reponseOmbreEtendue reponseVeto
			if errDecodageOmbreEtendue := json.Unmarshal(vetoOmbreEtendue, &reponseOmbreEtendue); errDecodageOmbreEtendue != nil {
				t.Errorf(`FilterLine(resources/read, id étendu 120 caractères) : décodage de vetoResponse %q : %v`, vetoOmbreEtendue, errDecodageOmbreEtendue)
			} else {
				if reponseOmbreEtendue.JSONRPC != "2.0" {
					t.Errorf(`FilterLine(resources/read, id étendu 120 caractères) : jsonrpc = %q ; attendu %q`, reponseOmbreEtendue.JSONRPC, "2.0")
				}
				if string(reponseOmbreEtendue.ID) != `"`+identifiantEtendu+`"` {
					t.Errorf(`FilterLine(resources/read, id étendu 120 caractères) : id de vetoResponse = %s ; attendu l'identifiant d'origine de 120 caractères`, reponseOmbreEtendue.ID)
				}
				if reponseOmbreEtendue.Error.Code != -32601 {
					t.Errorf(`FilterLine(resources/read, id étendu 120 caractères) : error.code = %d ; attendu -32601`, reponseOmbreEtendue.Error.Code)
				}
				if reponseOmbreEtendue.Error.Message != "Method not allowed by guard" {
					t.Errorf(`FilterLine(resources/read, id étendu 120 caractères) : error.message = %q ; attendu %q`, reponseOmbreEtendue.Error.Message, "Method not allowed by guard")
				}
			}
		}
		ligneOmbreSansIdentifiant := []byte(`{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///etc/shadow"}}`)
		avanceSansIdentifiant, vetoSansIdentifiant, dossierSansIdentifiant := FilterLine(ligneOmbreSansIdentifiant)
		if avanceSansIdentifiant {
			t.Errorf("FilterLine(resources/read, sans id) : forward = true ; attendu false")
		}
		if vetoSansIdentifiant != nil {
			t.Errorf("FilterLine(resources/read, sans id) : vetoResponse = %q ; attendu nil", vetoSansIdentifiant)
		}
		if dossierSansIdentifiant != nil {
			t.Errorf("FilterLine(resources/read, sans id) : incident non nil ; attendu nil")
		}
		avanceNotificationRefusee, vetoNotificationRefusee, dossierNotificationRefusee := FilterLine([]byte(`{"jsonrpc":"2.0","id":9,"method":"notifications/x"}`))
		if avanceNotificationRefusee {
			t.Errorf("FilterLine(notifications/x, id 9) : forward = true ; attendu false (notification avec identifiant hors liste fermée)")
		}
		if dossierNotificationRefusee != nil {
			t.Errorf("FilterLine(notifications/x, id 9) : incident non nil ; attendu nil")
		}
		if vetoNotificationRefusee == nil {
			t.Errorf("FilterLine(notifications/x, id 9) : vetoResponse = nil ; attendu un objet d'erreur JSON-RPC -32601")
		} else {
			var reponseNotificationRefusee reponseVeto
			if errDecodageNotificationRefusee := json.Unmarshal(vetoNotificationRefusee, &reponseNotificationRefusee); errDecodageNotificationRefusee != nil {
				t.Errorf("FilterLine(notifications/x, id 9) : décodage de vetoResponse %q : %v", vetoNotificationRefusee, errDecodageNotificationRefusee)
			} else {
				if reponseNotificationRefusee.JSONRPC != "2.0" {
					t.Errorf("FilterLine(notifications/x, id 9) : jsonrpc = %q ; attendu %q", reponseNotificationRefusee.JSONRPC, "2.0")
				}
				if string(reponseNotificationRefusee.ID) != "9" {
					t.Errorf("FilterLine(notifications/x, id 9) : id de vetoResponse = %s ; attendu 9", reponseNotificationRefusee.ID)
				}
				if reponseNotificationRefusee.Error.Code != -32601 {
					t.Errorf("FilterLine(notifications/x, id 9) : error.code = %d ; attendu -32601", reponseNotificationRefusee.Error.Code)
				}
				if reponseNotificationRefusee.Error.Message != "Method not allowed by guard" {
					t.Errorf("FilterLine(notifications/x, id 9) : error.message = %q ; attendu %q", reponseNotificationRefusee.Error.Message, "Method not allowed by guard")
				}
			}
		}
	})

	t.Run("C03", func(t *testing.T) {
		tamponSortie := &bytes.Buffer{}
		lignePing := []byte(`{"jsonrpc":"2.0","id":1,"method":"ping"}`)
		errEcriture := writeMessage(tamponSortie, lignePing)
		if errEcriture != nil {
			t.Errorf("writeMessage(ligne ping) : erreur non nil : %v", errEcriture)
		}
		if tamponSortie.String() != string(lignePing)+"\n" {
			t.Errorf("writeMessage(ligne ping) : tampon = %q ; attendu la ligne suivie de l'octet 0x0A", tamponSortie.String())
		}
		sautLigneAttendu := []byte{'\n'}
		if !bytes.Equal(nl, sautLigneAttendu) {
			t.Errorf("nl = %v ; attendu exactement la tranche d'un octet 0x0A", nl)
		}
		errEcritureAbregee := writeMessage(redacteurEcritureAbregee{}, lignePing)
		if !errors.Is(errEcritureAbregee, io.ErrShortWrite) {
			t.Errorf("writeMessage(écrivain à écriture courte) : erreur = %v ; attendu io.ErrShortWrite", errEcritureAbregee)
		}
		echecImpose := errors.New("échec d'écriture imposé par le test")
		errEcritureDefaillante := writeMessage(redacteurEcritureDefaillante{echec: echecImpose}, lignePing)
		if !errors.Is(errEcritureDefaillante, echecImpose) {
			t.Errorf("writeMessage(écrivain en échec imposé) : erreur = %v ; attendu %v", errEcritureDefaillante, echecImpose)
		}
	})

	t.Run("C04", func(t *testing.T) {
		avanceAppelAdmis, vetoAppelAdmis, dossierAppelAdmis := FilterLine([]byte(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/src/main.go"}}}`))
		if !avanceAppelAdmis {
			t.Errorf("FilterLine(tools/call read_file admis, id 4) : forward = false ; attendu true")
		}
		if vetoAppelAdmis != nil {
			t.Errorf("FilterLine(tools/call read_file admis, id 4) : vetoResponse = %q ; attendu nil", vetoAppelAdmis)
		}
		if dossierAppelAdmis != nil {
			t.Errorf("FilterLine(tools/call read_file admis, id 4) : incident non nil ; attendu nil")
		}
	})

	t.Run("C05", func(t *testing.T) {
		type reponseVetoOutil struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Error   struct {
				Code        int    `json:"code"`
				Message     string `json:"message"`
				DetailOutil struct {
					Tool string `json:"tool"`
				} `json:"data"`
			} `json:"error"`
		}
		avanceOutilInconnu, vetoOutilInconnu, dossierOutilInconnu := FilterLine([]byte(`{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"outil_inconnu","arguments":{}}}`))
		if avanceOutilInconnu {
			t.Errorf("FilterLine(tools/call outil inconnu, id 11) : forward = true ; attendu false")
		}
		if dossierOutilInconnu != nil {
			t.Errorf("FilterLine(tools/call outil inconnu, id 11) : incident non nil ; attendu nil")
		}
		if vetoOutilInconnu == nil {
			t.Errorf("FilterLine(tools/call outil inconnu, id 11) : vetoResponse = nil ; attendu un objet d'erreur JSON-RPC -32601")
		} else {
			var reponseOutilInconnu reponseVetoOutil
			if errDecodageOutilInconnu := json.Unmarshal(vetoOutilInconnu, &reponseOutilInconnu); errDecodageOutilInconnu != nil {
				t.Errorf("FilterLine(tools/call outil inconnu, id 11) : décodage de vetoResponse %q : %v", vetoOutilInconnu, errDecodageOutilInconnu)
			} else {
				if reponseOutilInconnu.JSONRPC != "2.0" {
					t.Errorf("FilterLine(tools/call outil inconnu, id 11) : jsonrpc = %q ; attendu %q", reponseOutilInconnu.JSONRPC, "2.0")
				}
				if string(reponseOutilInconnu.ID) != "11" {
					t.Errorf("FilterLine(tools/call outil inconnu, id 11) : id de vetoResponse = %s ; attendu 11", reponseOutilInconnu.ID)
				}
				if reponseOutilInconnu.Error.Code != -32601 {
					t.Errorf("FilterLine(tools/call outil inconnu, id 11) : error.code = %d ; attendu -32601", reponseOutilInconnu.Error.Code)
				}
			}
		}
		chargeDense := strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3ODkrLw", 5)[:200]
		avanceDense, vetoDense, dossierDense := FilterLine([]byte(`{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"` + chargeDense + `"}}}`))
		if avanceDense {
			t.Errorf("FilterLine(tools/call read_file charge dense, id 12) : forward = true ; attendu false")
		}
		if dossierDense != nil {
			t.Errorf("FilterLine(tools/call read_file charge dense, id 12) : incident non nil ; attendu nil")
		}
		if vetoDense == nil {
			t.Errorf("FilterLine(tools/call read_file charge dense, id 12) : vetoResponse = nil ; attendu un objet d'erreur JSON-RPC -32003")
		} else {
			var reponseDense reponseVetoOutil
			if errDecodageDense := json.Unmarshal(vetoDense, &reponseDense); errDecodageDense != nil {
				t.Errorf("FilterLine(tools/call read_file charge dense, id 12) : décodage de vetoResponse %q : %v", vetoDense, errDecodageDense)
			} else {
				if reponseDense.JSONRPC != "2.0" {
					t.Errorf("FilterLine(tools/call read_file charge dense, id 12) : jsonrpc = %q ; attendu %q", reponseDense.JSONRPC, "2.0")
				}
				if string(reponseDense.ID) != "12" {
					t.Errorf("FilterLine(tools/call read_file charge dense, id 12) : id de vetoResponse = %s ; attendu 12", reponseDense.ID)
				}
				if reponseDense.Error.Code != -32003 {
					t.Errorf("FilterLine(tools/call read_file charge dense, id 12) : error.code = %d ; attendu -32003", reponseDense.Error.Code)
				}
				if reponseDense.Error.DetailOutil.Tool != "read_file" {
					t.Errorf("FilterLine(tools/call read_file charge dense, id 12) : error.data.tool = %q ; attendu %q", reponseDense.Error.DetailOutil.Tool, "read_file")
				}
			}
		}
	})

	t.Run("C06", func(t *testing.T) {
		type reponseNonAnalysable struct {
			JSONRPC string          `json:"jsonrpc"`
			ID      json.RawMessage `json:"id"`
			Error   struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		avanceTemoin, vetoTemoin, dossierTemoin := FilterLine([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
		if !avanceTemoin {
			t.Errorf("FilterLine(témoin réponse du client result-seul, id 1) : forward = false ; attendu true")
		}
		if vetoTemoin != nil {
			t.Errorf("FilterLine(témoin réponse du client result-seul, id 1) : vetoResponse = %q ; attendu nil", vetoTemoin)
		}
		if dossierTemoin != nil {
			t.Errorf("FilterLine(témoin réponse du client result-seul, id 1) : incident non nil ; attendu nil")
		}
		avanceSansForme, vetoSansForme, dossierSansForme := FilterLine([]byte(`{"jsonrpc":"2.0","id":1}`))
		if avanceSansForme {
			t.Errorf(`FilterLine({"id":1} sans result ni error) : forward = true ; attendu false`)
		}
		if dossierSansForme != nil {
			t.Errorf(`FilterLine({"id":1} sans result ni error) : incident non nil ; attendu nil`)
		}
		if vetoSansForme == nil {
			t.Errorf(`FilterLine({"id":1} sans result ni error) : vetoResponse = nil ; attendu un veto -32600`)
		} else {
			var reponseSansForme reponseNonAnalysable
			if errDecodageSansForme := json.Unmarshal(vetoSansForme, &reponseSansForme); errDecodageSansForme != nil {
				t.Errorf(`FilterLine({"id":1} sans result ni error) : décodage de vetoResponse %q : %v`, vetoSansForme, errDecodageSansForme)
			} else {
				if reponseSansForme.Error.Code != -32600 {
					t.Errorf(`FilterLine({"id":1} sans result ni error) : error.code = %d ; attendu -32600`, reponseSansForme.Error.Code)
				}
				if string(reponseSansForme.ID) != "null" {
					t.Errorf(`FilterLine({"id":1} sans result ni error) : id de vetoResponse = %s ; attendu null`, reponseSansForme.ID)
				}
			}
		}
		avanceCleDupliquee, vetoCleDupliquee, dossierCleDupliquee := FilterLine([]byte(`{"jsonrpc":"2.0","id":1,"method":"ping","method":"tools/call"}`))
		if avanceCleDupliquee {
			t.Errorf("FilterLine(clé method dupliquée) : forward = true ; attendu false (ligne non analysable)")
		}
		if dossierCleDupliquee != nil {
			t.Errorf("FilterLine(clé method dupliquée) : incident non nil ; attendu nil")
		}
		if vetoCleDupliquee == nil {
			t.Errorf("FilterLine(clé method dupliquée) : vetoResponse = nil ; attendu un veto -32600")
		} else {
			var reponseCleDupliquee reponseNonAnalysable
			if errDecodageCleDupliquee := json.Unmarshal(vetoCleDupliquee, &reponseCleDupliquee); errDecodageCleDupliquee != nil {
				t.Errorf("FilterLine(clé method dupliquée) : décodage de vetoResponse %q : %v", vetoCleDupliquee, errDecodageCleDupliquee)
			} else {
				if reponseCleDupliquee.Error.Code != -32600 {
					t.Errorf("FilterLine(clé method dupliquée) : error.code = %d ; attendu -32600", reponseCleDupliquee.Error.Code)
				}
				if string(reponseCleDupliquee.ID) != "null" {
					t.Errorf("FilterLine(clé method dupliquée) : id de vetoResponse = %s ; attendu null", reponseCleDupliquee.ID)
				}
			}
		}
		lignesAmbigues := []struct {
			nom   string
			ligne string
		}{
			{"params sans result ni error", `{"jsonrpc":"2.0","id":1,"params":{"uri":"file:///etc/shadow"}}`},
			{"result accompagné de params", `{"jsonrpc":"2.0","id":1,"result":{},"params":{"x":1}}`},
			{"result et error simultanés", `{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1,"message":"x"}}`},
			{"result sans identifiant", `{"jsonrpc":"2.0","result":{}}`},
		}
		for _, casAmbigu := range lignesAmbigues {
			avanceAmbigue, vetoAmbigu, dossierAmbigu := FilterLine([]byte(casAmbigu.ligne))
			if avanceAmbigue {
				t.Errorf("FilterLine(%s) : forward = true ; attendu false", casAmbigu.nom)
			}
			if dossierAmbigu != nil {
				t.Errorf("FilterLine(%s) : incident non nil ; attendu nil", casAmbigu.nom)
			}
			if vetoAmbigu == nil {
				t.Errorf("FilterLine(%s) : vetoResponse = nil ; attendu un veto -32600", casAmbigu.nom)
				continue
			}
			var reponseAmbigue reponseNonAnalysable
			if errDecodageAmbigu := json.Unmarshal(vetoAmbigu, &reponseAmbigue); errDecodageAmbigu != nil {
				t.Errorf("FilterLine(%s) : décodage de vetoResponse %q : %v", casAmbigu.nom, vetoAmbigu, errDecodageAmbigu)
				continue
			}
			if reponseAmbigue.Error.Code != -32600 {
				t.Errorf("FilterLine(%s) : error.code = %d ; attendu -32600", casAmbigu.nom, reponseAmbigue.Error.Code)
			}
		}
	})

	t.Run("C07", func(t *testing.T) {
		ligneSondage := []byte(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
		ligneNotification := []byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
		ligneReponse := []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`)

		// Appels directs assertés, hors fonction littérale, avant toute mesure.
		avanceSondage, vetoSondage, dossierSondage := FilterLine(ligneSondage)
		if !avanceSondage {
			t.Errorf("FilterLine(ping, id 2) : forward = false ; attendu true")
		}
		if vetoSondage != nil {
			t.Errorf("FilterLine(ping, id 2) : vetoResponse = %q ; attendu nil", vetoSondage)
		}
		if dossierSondage != nil {
			t.Errorf("FilterLine(ping, id 2) : incident non nil ; attendu nil")
		}
		compteur := &compteurOctets{}
		if errEcritureComptee := writeMessage(compteur, ligneSondage); errEcritureComptee != nil {
			t.Errorf("writeMessage(ligne ping, écrivain compteur) : erreur non nil : %v", errEcritureComptee)
		}
		if compteur.totalOctets != len(ligneSondage)+1 {
			t.Errorf("writeMessage(ligne ping) : octets écrits = %d ; attendu len(ligne)+1 = %d", compteur.totalOctets, len(ligneSondage)+1)
		}

		// Les pools de sync.Pool sont locaux au processeur logique : le
		// prechauffage est donc execute sous GOMAXPROCS(1) afin que le scanner
		// recycle atterrisse sur le meme P que celui de la fenetre de comptage
		// (qui verrouille elle-meme GOMAXPROCS(1)) ; sans ce verrou, une
		// migration de la goroutine de test entre prechauffage et fenetre
		// laisse cette derniere devant un pool vide, qui realloue le scanner
		// a chaque appel selon la migration aleatoire, d'ou des ecarts entiers
		// non reproductibles.
		ancienMaxProcs := runtime.GOMAXPROCS(1)
		defer runtime.GOMAXPROCS(ancienMaxProcs)
		// Détection du détecteur de course : l'assertion stricte de non
		// allocation du filtrage n'est posée que hors détecteur, le compteur
		// Mallocs y variant d'une à deux unités entre deux exécutions du
		// même binaire.
		detecteurCourseActif := false
		if infos, lues := debug.ReadBuildInfo(); lues {
			for _, reglage := range infos.Settings {
				if reglage.Key == "-race" && reglage.Value == "true" {
					detecteurCourseActif = true
				}
			}
		}
		// Mesures de FilterLine et de writeMessage : aucune allocation au-delà
		// de l'analyse pour une requête transmise, exactement une allocation
		// par appel d'écriture ; chaque fenêtre de comptage est précédée d'un
		// préchauffage de la fermeture sur la même ligne, car les caches
		// internes d'encoding/json (scanner recyclé par pool) dépendent de la
		// dimension de la dernière ligne traitée. Le critère reste strict :
		// allocFiltre <= allocAnalyse sur la même ligne, toute allocation
		// entière ajoutée par FilterLine sur une requête transmise étant
		// détectée.
		const appelsPrechauffage = 32
		allocationsMoyenne := func(appeler func()) float64 {
			for i := 0; i < appelsPrechauffage; i++ {
				appeler()
			}
			return testing.AllocsPerRun(200, appeler)
		}
		var methodeAnalyseeSondage []byte
		var analyseSondageOK bool
		allocAnalyseSondage := allocationsMoyenne(func() {
			methodeAnalyseeSondage, _, _, _, _, analyseSondageOK = parseMCPCall(ligneSondage)
		})
		if !analyseSondageOK || string(methodeAnalyseeSondage) != "ping" {
			t.Fatalf("parseMCPCall(ligne ping) : référence d'analyse invalide (ok=%t, méthode=%q)", analyseSondageOK, methodeAnalyseeSondage)
		}
		var methodeAnalyseeNotification []byte
		var analyseNotificationOK bool
		allocAnalyseNotification := allocationsMoyenne(func() {
			methodeAnalyseeNotification, _, _, _, _, analyseNotificationOK = parseMCPCall(ligneNotification)
		})
		if !analyseNotificationOK || string(methodeAnalyseeNotification) != "notifications/initialized" {
			t.Fatalf("parseMCPCall(ligne notification) : référence d'analyse invalide (ok=%t, méthode=%q)", analyseNotificationOK, methodeAnalyseeNotification)
		}

		var avanceMesuree bool
		var vetoMesuree []byte
		var dossierMesuree *socagent.Dossier
		allocFiltreSondage := allocationsMoyenne(func() {
			avanceMesuree, vetoMesuree, dossierMesuree = FilterLine(ligneSondage)
		})
		// Assertion stricte hors détecteur de course : FilterLine n'ajoute
		// aucune allocation à celles de l'analyse pour une requête transmise.
		if !detecteurCourseActif && allocFiltreSondage > allocAnalyseSondage {
			t.Errorf("FilterLine(ligne ping) : %g allocations/appel ; attendu au plus celles de parseMCPCall sur la même ligne (%g)", allocFiltreSondage, allocAnalyseSondage)
		}
		if !avanceMesuree || vetoMesuree != nil || dossierMesuree != nil {
			t.Errorf("FilterLine(ligne ping) mesuré : (%t, %v, %v) ; attendu (true, nil, nil)", avanceMesuree, vetoMesuree, dossierMesuree)
		}
		allocFiltreNotification := allocationsMoyenne(func() {
			avanceMesuree, vetoMesuree, dossierMesuree = FilterLine(ligneNotification)
		})
		// Même assertion stricte hors détecteur de course pour la notification.
		if !detecteurCourseActif && allocFiltreNotification > allocAnalyseNotification {
			t.Errorf("FilterLine(ligne notification) : %g allocations/appel ; attendu au plus celles de parseMCPCall sur la même ligne (%g)", allocFiltreNotification, allocAnalyseNotification)
		}
		if !avanceMesuree || vetoMesuree != nil || dossierMesuree != nil {
			t.Errorf("FilterLine(ligne notification) mesuré : (%t, %v, %v) ; attendu (true, nil, nil)", avanceMesuree, vetoMesuree, dossierMesuree)
		}
		allocationsMoyenne(func() {
			avanceMesuree, vetoMesuree, dossierMesuree = FilterLine(ligneReponse)
		})
		if !avanceMesuree || vetoMesuree != nil || dossierMesuree != nil {
			t.Errorf("FilterLine(réponse du client, id 1) mesuré : (%t, %v, %v) ; attendu (true, nil, nil)", avanceMesuree, vetoMesuree, dossierMesuree)
		}

		// Mesure de writeMessage : exactement une allocation par appel.
		var errEcritureMesuree error
		allocEcriture := allocationsMoyenne(func() {
			errEcritureMesuree = writeMessage(compteur, ligneSondage)
		})
		if errEcritureMesuree != nil {
			t.Errorf("writeMessage(ligne ping) mesuré : erreur non nil : %v", errEcritureMesuree)
		}
		if allocEcriture != 1 {
			t.Errorf("writeMessage(ligne ping) : %g allocations/appel ; attendu exactement 1", allocEcriture)
		}
		// Mesure de writeMessage sur une ligne de 64 octets : la forme au
		// contrat réserve le message en une seule allocation quelle que soit
		// la ligne et dans les deux constructions ; l'ancienne écriture en
		// allouait deux.
		ligneSoixanteQuatre := bytes.Repeat([]byte("a"), 64)
		allocEcritureSoixanteQuatre := allocationsMoyenne(func() {
			errEcritureMesuree = writeMessage(compteur, ligneSoixanteQuatre)
		})
		if errEcritureMesuree != nil {
			t.Errorf("writeMessage(ligne de 64 octets) mesuré : erreur non nil : %v", errEcritureMesuree)
		}
		if allocEcritureSoixanteQuatre != 1 {
			t.Errorf("writeMessage(ligne de 64 octets) : %g allocations/appel ; attendu exactement 1", allocEcritureSoixanteQuatre)
		}
		t.Logf("allocations/appel : analyse ping=%g notification=%g ; filtrage ping=%g notification=%g ; écriture ping=%g, 64 octets=%g ; détecteur de course=%t",
			allocAnalyseSondage, allocAnalyseNotification, allocFiltreSondage, allocFiltreNotification, allocEcriture, allocEcritureSoixanteQuatre, detecteurCourseActif)
	})

	t.Run("C08", func(t *testing.T) {
		chargeDenseEchappement := strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo0NTY3ODkrLw", 5)[:200]
		avanceEchappement, vetoEchappement, _ := FilterLine([]byte(`{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"` + chargeDenseEchappement + `"}}}`))
		if avanceEchappement {
			t.Errorf("FilterLine(read_file charge dense, id 21) : forward = true ; attendu false")
		}
		if !bytes.Contains(vetoEchappement, []byte(`"data":{"tool":"read_file",`)) {
			t.Errorf("FilterLine(read_file charge dense, id 21) : vetoResponse = %q ; attendu le nom d'outil écrit en clair, sans échappement \\u", vetoEchappement)
		}
		avanceBlancs, vetoBlancs, _ := FilterLine([]byte("{ \"jsonrpc\" :\t\"2.0\" , \"id\" : 22 ,\r\n \"method\" : \"ping\" }"))
		if !avanceBlancs {
			t.Errorf("FilterLine(ping avec blancs entre les jetons, id 22) : forward = false ; attendu true")
		}
		if vetoBlancs != nil {
			t.Errorf("FilterLine(ping avec blancs entre les jetons, id 22) : vetoResponse = %q ; attendu nil", vetoBlancs)
		}
		avanceLitteralForge, vetoLitteralForge, _ := FilterLine([]byte(`{"jsonrpc":"2.0","id":23,"method":"ping","params":{"x":trzz}}`))
		if avanceLitteralForge {
			t.Errorf("FilterLine(ping, params à littéral forgé trzz, id 23) : forward = true ; attendu false")
		}
		if !bytes.Contains(vetoLitteralForge, []byte(`"code":-32600`)) {
			t.Errorf("FilterLine(ping, params à littéral forgé trzz, id 23) : vetoResponse = %q ; attendu le veto -32600", vetoLitteralForge)
		}
		avanceLitteralDecale, vetoLitteralDecale, _ := FilterLine([]byte(`{"jsonrpc":"2.0","id":24,"method":"ping","params":{"x":tzue}}`))
		if avanceLitteralDecale {
			t.Errorf("FilterLine(ping, params à littéral forgé tzue, id 24) : forward = true ; attendu false")
		}
		if !bytes.Contains(vetoLitteralDecale, []byte(`"code":-32600`)) {
			t.Errorf("FilterLine(ping, params à littéral forgé tzue, id 24) : vetoResponse = %q ; attendu le veto -32600", vetoLitteralDecale)
		}
		avanceFauxForge, vetoFauxForge, _ := FilterLine([]byte(`{"jsonrpc":"2.0","id":27,"method":"ping","params":{"x":falzz}}`))
		if avanceFauxForge {
			t.Errorf("FilterLine(ping, params à littéral forgé falzz, id 27) : forward = true ; attendu false")
		}
		if !bytes.Contains(vetoFauxForge, []byte(`"code":-32600`)) {
			t.Errorf("FilterLine(ping, params à littéral forgé falzz, id 27) : vetoResponse = %q ; attendu le veto -32600", vetoFauxForge)
		}
		avanceFauxDecale, vetoFauxDecale, _ := FilterLine([]byte(`{"jsonrpc":"2.0","id":28,"method":"ping","params":{"x":fzzse}}`))
		if avanceFauxDecale {
			t.Errorf("FilterLine(ping, params à littéral forgé fzzse, id 28) : forward = true ; attendu false")
		}
		if !bytes.Contains(vetoFauxDecale, []byte(`"code":-32600`)) {
			t.Errorf("FilterLine(ping, params à littéral forgé fzzse, id 28) : vetoResponse = %q ; attendu le veto -32600", vetoFauxDecale)
		}
		avanceNulForge, vetoNulForge, _ := FilterLine([]byte(`{"jsonrpc":"2.0","id":29,"method":"ping","params":{"x":nuzz}}`))
		if avanceNulForge {
			t.Errorf("FilterLine(ping, params à littéral forgé nuzz, id 29) : forward = true ; attendu false")
		}
		if !bytes.Contains(vetoNulForge, []byte(`"code":-32600`)) {
			t.Errorf("FilterLine(ping, params à littéral forgé nuzz, id 29) : vetoResponse = %q ; attendu le veto -32600", vetoNulForge)
		}
		// json.Valid écarte déjà tout littéral forgé avant skipValue : sa propre
		// vérification des littéraux ne s'observe qu'en l'appelant directement.
		finFauxForge, valideFauxForge := skipValue([]byte("falzz"), 0)
		if valideFauxForge {
			t.Errorf(`skipValue("falzz", 0) = (%d, true) ; attendu un refus`, finFauxForge)
		}
		finFauxDecale, valideFauxDecale := skipValue([]byte("fzzse"), 0)
		if valideFauxDecale {
			t.Errorf(`skipValue("fzzse", 0) = (%d, true) ; attendu un refus`, finFauxDecale)
		}
		finFauxExact, valideFauxExact := skipValue([]byte("false"), 0)
		if !valideFauxExact || finFauxExact != 5 {
			t.Errorf(`skipValue("false", 0) = (%d, %v) ; attendu (5, true)`, finFauxExact, valideFauxExact)
		}
		avanceDecimal, vetoDecimal, _ := FilterLine([]byte(`{"jsonrpc":"2.0","id":25,"method":"ping","params":{"x":1.5,"y":[true,false,null,-2e3]}}`))
		if !avanceDecimal {
			t.Errorf("FilterLine(ping, params à nombre décimal 1.5, id 25) : forward = false ; attendu true")
		}
		if vetoDecimal != nil {
			t.Errorf("FilterLine(ping, params à nombre décimal 1.5, id 25) : vetoResponse = %q ; attendu nil", vetoDecimal)
		}
		avanceDecimalTronque, vetoDecimalTronque, _ := FilterLine([]byte(`{"jsonrpc":"2.0","id":26,"method":"ping","params":{"x":1.}}`))
		if avanceDecimalTronque {
			t.Errorf("FilterLine(ping, params à nombre tronqué « 1. », id 26) : forward = true ; attendu false")
		}
		if !bytes.Contains(vetoDecimalTronque, []byte(`"code":-32600`)) {
			t.Errorf("FilterLine(ping, params à nombre tronqué « 1. », id 26) : vetoResponse = %q ; attendu le veto -32600", vetoDecimalTronque)
		}
	})
}
