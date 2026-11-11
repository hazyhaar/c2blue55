// Nom de fichier historique : ce fichier est compilé dans tous les modes ;
// son renommage est dû dans une ligne ultérieure, une fois le fichier
// présent sur main.
package c2blue55

import (
	"runtime"
	"syscall"
	"testing"
	"time"
)

// usageRessourcesDuFil est RUSAGE_THREAD : getrusage restreint au fil
// appelant (Linux).
const usageRessourcesDuFil = 1

func TestRouter_ThroughputExceedsMillion(t *testing.T) {
	// Le débit se mesure en temps processeur du fil, pas en temps d'horloge :
	// sur une machine saturée le fil attend son tour sans consommer de
	// processeur, et l'horloge mesurerait alors la charge de la machine au
	// lieu du routeur.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	rt := NewRouter()
	var batch [dispatchBatch]Event
	for i := range batch {
		batch[i].Subsystem = uint16(i&3) + SubProc
	}
	var drain [routerRingCount][dispatchBatch]Event
	const lotsMesures = 20000
	var usageAvant, usageApres syscall.Rusage
	if err := syscall.Getrusage(usageRessourcesDuFil, &usageAvant); err != nil {
		t.Fatalf("getrusage du fil avant la mesure: %v", err)
	}
	for range lotsMesures {
		rt.DispatchBatch(batch[:])
		rt.RingProc().PopBatch(drain[0][:], consumeBatch)
		rt.RingFile().PopBatch(drain[1][:], consumeBatch)
		rt.RingNet().PopBatch(drain[2][:], consumeBatch)
		rt.RingMem().PopBatch(drain[3][:], consumeBatch)
	}
	if err := syscall.Getrusage(usageRessourcesDuFil, &usageApres); err != nil {
		t.Fatalf("getrusage du fil après la mesure: %v", err)
	}
	tempsProcesseur := time.Duration(usageApres.Utime.Nano()-usageAvant.Utime.Nano()) +
		time.Duration(usageApres.Stime.Nano()-usageAvant.Stime.Nano())
	if tempsProcesseur <= 0 {
		t.Fatalf("temps processeur du fil non mesurable: %v", tempsProcesseur)
	}
	rate := float64(lotsMesures*dispatchBatch) / tempsProcesseur.Seconds()
	if rate < 1_000_000 {
		t.Errorf("débit = %.0f ev/s en temps processeur, attendu > 1000000", rate)
	}
	t.Logf("débit routage = %.0f ev/s en temps processeur (%v pour %d lots)",
		rate, tempsProcesseur, lotsMesures)
}
