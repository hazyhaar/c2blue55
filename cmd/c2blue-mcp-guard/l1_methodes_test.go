// Package main — l1_methodes_test.go
// Test d'acceptation de la ligne L-1 (EXG-21) sur la garde MCP à liste fermée
// de méthodes : les méthodes de cycle de vie et de découverte (initialize,
// ping, tools/list, notifications/initialized) sont relayées sans veto, et les
// méthodes hors liste fermée (resources/read, prompts/get, completion/complete,
// sampling/createMessage) sont refusées par le mécanisme exact : veto JSON-RPC
// -32601 portant le même identifiant, ou absence de réponse pour une notification.
package main

import (
	"encoding/json"
	"testing"
)

// TestL1_GardeMCPMethodes applique FilterLine à des lignes JSON-RPC représentatives.
func TestL1_GardeMCPMethodes(t *testing.T) {
	t.Run("L1-01", func(t *testing.T) {
		lignes := []struct {
			nom  string
			line string
		}{
			{"initialize", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`},
			{"ping", `{"jsonrpc":"2.0","id":2,"method":"ping"}`},
			{"tools/list", `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`},
			{"notifications/initialized", `{"jsonrpc":"2.0","method":"notifications/initialized"}`},
		}
		for _, l := range lignes {
			forward, veto, _ := FilterLine([]byte(l.line))
			if forward != true {
				t.Errorf("%s : forward = %t ; attendu true", l.nom, forward)
			}
			if veto != nil {
				t.Errorf("%s : vetoResponse = %q ; attendu nil", l.nom, veto)
			}
		}
	})

	t.Run("L1-02", func(t *testing.T) {
		type reponseVeto struct {
			ID    json.RawMessage `json:"id"`
			Error struct {
				Code int `json:"code"`
			} `json:"error"`
		}

		avecId := []struct {
			nom  string
			id   string
			line string
		}{
			{"resources/read", "4", `{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"file:///x"}}`},
			{"prompts/get", "5", `{"jsonrpc":"2.0","id":5,"method":"prompts/get","params":{"name":"p"}}`},
			{"completion/complete", "6", `{"jsonrpc":"2.0","id":6,"method":"completion/complete","params":{}}`},
			{"sampling/createMessage", "7", `{"jsonrpc":"2.0","id":7,"method":"sampling/createMessage","params":{}}`},
		}
		for _, l := range avecId {
			forward, veto, _ := FilterLine([]byte(l.line))
			if forward != false {
				t.Errorf("%s : forward = %t ; attendu false", l.nom, forward)
			}
			if veto == nil || !json.Valid(veto) {
				t.Errorf("%s : vetoResponse = %q ; attendu un JSON valide", l.nom, veto)
				continue
			}
			var rep reponseVeto
			if err := json.Unmarshal(veto, &rep); err != nil {
				t.Errorf("%s : décodage de vetoResponse : %v", l.nom, err)
				continue
			}
			if string(rep.ID) != l.id {
				t.Errorf("%s : id de vetoResponse = %s ; attendu %s", l.nom, rep.ID, l.id)
			}
			if rep.Error.Code != -32601 {
				t.Errorf("%s : error.code = %d ; attendu -32601", l.nom, rep.Error.Code)
			}
		}

		// Notification sans identifiant : refus sans réponse.
		forward, veto, _ := FilterLine([]byte(`{"jsonrpc":"2.0","method":"resources/read","params":{"uri":"file:///x"}}`))
		if forward != false {
			t.Errorf("resources/read sans id : forward = %t ; attendu false", forward)
		}
		if veto != nil {
			t.Errorf("resources/read sans id : vetoResponse = %q ; attendu nil", veto)
		}
	})
}
