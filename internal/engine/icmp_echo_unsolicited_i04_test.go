package engine

import "testing"

// Strate I-04 : règle complémentaire « Echo Reply sans Echo Request vue ».
// Mesuré sur ptunnel-ng le 2026-10-29 : le mandataire pousse ses données
// descendantes dans des Echo Replies qui ne répondent à aucune requête (même
// identifiant que les requêtes du tunnel, séquence inconnue). Règle : une
// réponse dont la clé (src, dst, ID, seq) n'a pas de requête mémorisée, mais
// dont l'identifiant (src, dst, ID) a reçu au moins une requête dans les 60 s,
// lève REASON_IC02_ICMP_ECHO_UNSOLICITED. Une réponse d'un identifiant jamais
// vu en requête reste ignorée (capture commencée en cours de session).

func TestICMPEchoParityTracker_UnsolicitedReplyOnKnownIDFires(t *testing.T) {
	var tr ICMPEchoParityTracker
	payload := []byte("c2il-data-chunk")
	// Requête seq 0 vue, réponse identique : rien.
	tr.ObserveIPv4(1e9, i02Frame(i02Emitter, i02Responder, 8, 23475, 0, payload))
	if f, _ := tr.ObserveIPv4(1e9+100000, i02Frame(i02Responder, i02Emitter, 0, 23475, 0, payload)); f {
		t.Fatal("réponse identique : feu interdit")
	}
	// Réponse seq 2 sans requête, même identifiant : feu « non sollicitée ».
	f, r := tr.ObserveIPv4(2e9, i02Frame(i02Responder, i02Emitter, 0, 23475, 2, make([]byte, 228)))
	if !f || r != ReasonIC02ICMPEchoUnsolicited {
		t.Fatalf("réponse orpheline sur identifiant connu : fired=%v reason=%q, attendu %q", f, r, ReasonIC02ICMPEchoUnsolicited)
	}
	// Identifiant jamais vu en requête : ignorée.
	if f, _ := tr.ObserveIPv4(3e9, i02Frame(i02Responder, i02Emitter, 0, 9999, 5, payload)); f {
		t.Error("réponse d'un identifiant jamais vu : feu interdit")
	}
	// Identifiant connu mais dont la dernière requête date de plus de 60 s : ignorée.
	if f, _ := tr.ObserveIPv4(70e9, i02Frame(i02Responder, i02Emitter, 0, 23475, 7, payload)); f {
		t.Error("identifiant expiré : feu interdit")
	}
}

func TestICMPEchoParityTracker_PingNeverUnsolicited(t *testing.T) {
	var tr ICMPEchoParityTracker
	payload := make([]byte, 56)
	for seq := uint16(1); seq <= 30; seq++ {
		tr.ObserveIPv4(int64(seq)*2e8, i02Frame(i02Emitter, i02Responder, 8, 14, seq, payload))
		if f, r := tr.ObserveIPv4(int64(seq)*2e8+400000, i02Frame(i02Responder, i02Emitter, 0, 14, seq, payload)); f || r != ReasonNone {
			t.Fatalf("ping seq %d : fired=%v reason=%q", seq, f, r)
		}
	}
}
