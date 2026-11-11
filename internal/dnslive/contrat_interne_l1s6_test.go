package dnslive

import (
	"errors"
	"net"
	"testing"
)

// TestServiceLiveContratInterneL1S6 porte le cas prescrit C04 de la strate
// L1-S6 : l'enregistrement d'une erreur asynchrone, qui ne s'observe que de
// l'intérieur du paquet.
func TestServiceLiveContratInterneL1S6(t *testing.T) {
	t.Run("C04", func(t *testing.T) {
		serviceInterne, erreurNewInterne := New(Config{
			UDPListen:      "127.0.0.1:0",
			HTTPListen:     "127.0.0.1:0",
			EvidenceDir:    t.TempDir(),
			DashboardToken: t.Name(),
		})
		if erreurNewInterne != nil {
			t.Fatalf("New: %v", erreurNewInterne)
		}
		if serviceInterne == nil {
			t.Fatalf("New: service nul sans erreur")
		}
		serviceInterne.recordAsynchronousError(net.ErrClosed)
		if !errors.Is(serviceInterne.asynchronousErr, net.ErrClosed) {
			t.Errorf("hors fermeture, net.ErrClosed doit être consignée: erreur asynchrone = %v", serviceInterne.asynchronousErr)
		}
		serviceInterne.mu.Lock()
		serviceInterne.closing = true
		serviceInterne.asynchronousErr = nil
		serviceInterne.mu.Unlock()
		erreurTemoin := errors.New("erreur asynchrone de contrat")
		serviceInterne.recordAsynchronousError(erreurTemoin)
		if !errors.Is(serviceInterne.asynchronousErr, erreurTemoin) {
			t.Errorf("en fermeture, une erreur autre que net.ErrClosed doit être consignée: erreur asynchrone = %v", serviceInterne.asynchronousErr)
		}
		serviceInterne.recordAsynchronousError(net.ErrClosed)
		if errors.Is(serviceInterne.asynchronousErr, net.ErrClosed) {
			t.Errorf("en fermeture, net.ErrClosed ne doit pas être consignée: erreur asynchrone = %v", serviceInterne.asynchronousErr)
		}
	})
}
