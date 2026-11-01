package icmplab

import "testing"

func TestAuditTransformPayloadLongueurEcrite(t *testing.T) {
	entree := make([]byte, 10)
	for i := range entree {
		entree[i] = byte(i + 1)
	}
	sortie := make([]byte, 2)
	nbEcrits := TransformPayload(42, entree, sortie)
	if nbEcrits != len(sortie) {
		t.Fatalf("TransformPayload a ecrit au plus %d octets dans sortie mais annonce %d", len(sortie), nbEcrits)
	}
}
