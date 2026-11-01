package icmplab_test

import (
	"testing"

	"github.com/hazyhaar/c2blue55/internal/icmplab"
)

// Strate I-01b : le répondeur ne répond qu'aux sources du laboratoire
// (10.55.0.0/24) ; la règle est une fonction pure du paquet icmplab, utilisée
// par cmd/c2icmplab-respond avant toute réponse.
func TestSourceAutoriseeLaboratoire(t *testing.T) {
	cas := []struct {
		ip     [4]byte
		admise bool
	}{
		{[4]byte{10, 55, 0, 2}, true},
		{[4]byte{10, 55, 0, 254}, true},
		{[4]byte{10, 55, 1, 2}, false},
		{[4]byte{127, 0, 0, 1}, false},
		{[4]byte{8, 8, 8, 8}, false},
		{[4]byte{0, 0, 0, 0}, false},
	}
	for _, c := range cas {
		if got := icmplab.SourceAutoriseeLaboratoire(c.ip); got != c.admise {
			t.Errorf("%v : %v, attendu %v", c.ip, got, c.admise)
		}
	}
}
