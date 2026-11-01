//go:build linux

package cinetique_test

import (
	"context"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55/internal/cinetique"
	"golang.org/x/sys/unix"
)

func TestAttributionSocketInetDiagUDPConnecteeNonConnecteeEtTCP(t *testing.T) {
	resolveur, errOpen := cinetique.OuvrirResolveurSocketProcessus()
	if errOpen != nil {
		t.Fatalf("OuvrirResolveurSocketProcessus: %v", errOpen)
	}
	defer func() { _ = resolveur.Fermer() }()

	pidAttendu := os.Getpid()

	// 1. Socket UDP non connectée (cas sendto/WriteToUDP d'un résolveur DNS standard, DstPort=0 dans le noyau).
	udpNonConnectee, errU1 := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if errU1 != nil {
		t.Fatalf("ListenUDP: %v", errU1)
	}
	defer func() { _ = udpNonConnectee.Close() }()
	portUDP1 := uint16(udpNonConnectee.LocalAddr().(*net.UDPAddr).Port)

	identU1, errRes1 := resolveur.ResoudreTupleIPv4(unix.IPPROTO_UDP, portUDP1, 53, 0)
	if errRes1 != nil {
		t.Fatalf("ResoudreTupleIPv4 UDP non connectee: %v", errRes1)
	}
	if identU1.PID != pidAttendu || identU1.InodeSocket == 0 || identU1.DebutTacheTicks == 0 || identU1.NomExecutable == "" {
		t.Fatalf("attribution UDP non connectee invalide: %+v", identU1)
	}

	// 2. Socket UDP connectée (DialUDP) + vérification du hit de cache d'inode revalidé par starttime.
	udpConnectee, errU2 := net.DialUDP("udp4", nil, udpNonConnectee.LocalAddr().(*net.UDPAddr))
	if errU2 != nil {
		t.Fatalf("DialUDP: %v", errU2)
	}
	defer func() { _ = udpConnectee.Close() }()
	portUDP2 := uint16(udpConnectee.LocalAddr().(*net.UDPAddr).Port)

	identU2, errRes2 := resolveur.ResoudreTupleIPv4(unix.IPPROTO_UDP, portUDP2, portUDP1, 0)
	if errRes2 != nil {
		t.Fatalf("ResoudreTupleIPv4 UDP connectee: %v", errRes2)
	}
	if identU2.PID != pidAttendu || identU2.InodeSocket == identU1.InodeSocket {
		t.Fatalf("attribution UDP connectee incoherente: %+v vs %+v", identU2, identU1)
	}
	identU2Cache, errCache := resolveur.ResoudreTupleIPv4(unix.IPPROTO_UDP, portUDP2, portUDP1, 0)
	if errCache != nil || identU2Cache.InodeSocket != identU2.InodeSocket {
		t.Fatalf("relecture cache inode en echec: %+v err=%v", identU2Cache, errCache)
	}

	// 3. Connexion TCP établie réelle.
	ecouteTCP, errL := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if errL != nil {
		t.Fatalf("ListenTCP: %v", errL)
	}
	defer func() { _ = ecouteTCP.Close() }()

	canalSrv := make(chan *net.TCPConn, 1)
	go func() {
		conn, errAcc := ecouteTCP.AcceptTCP()
		if errAcc == nil {
			canalSrv <- conn
		}
	}()
	adrEcoute := ecouteTCP.Addr().(*net.TCPAddr)
	clientTCP, errDial := net.DialTCP("tcp4", nil, adrEcoute)
	if errDial != nil {
		t.Fatalf("DialTCP: %v", errDial)
	}
	defer func() { _ = clientTCP.Close() }()
	connAcceptee := <-canalSrv
	defer func() { _ = connAcceptee.Close() }()

	portClientTCP := uint16(clientTCP.LocalAddr().(*net.TCPAddr).Port)
	identTCP, errResTCP := resolveur.ResoudreTupleIPv4(unix.IPPROTO_TCP, portClientTCP, uint16(adrEcoute.Port), 0)
	if errResTCP != nil {
		t.Fatalf("ResoudreTupleIPv4 TCP etablie: %v", errResTCP)
	}
	if identTCP.PID != pidAttendu || identTCP.InodeSocket == 0 {
		t.Fatalf("attribution TCP invalide: %+v", identTCP)
	}

	// 4. Jumeau négatif : tuple inexistant.
	_ = clientTCP.Close()
	_ = connAcceptee.Close()
	if _, errAbs := resolveur.ResoudreInodeSocket(0, 0, 0); !errors.Is(errAbs, cinetique.ErrProprietaireIntrouvable) {
		t.Fatalf("attendu ErrProprietaireIntrouvable sur inode 0, obtenu %v", errAbs)
	}

	// 5. Zéro allocation sur CollecteurReseauParProcessus.
	collecteur := cinetique.NouveauCollecteurReseauParProcessus()
	allocsCollecteur := testing.AllocsPerRun(1000, func() {
		collecteur.EnregistrerObservationReseau(pidAttendu, identU1.DebutTacheTicks, 512, 128, true, true, 53, true, 2)
		_ = collecteur.RecolterEtPurger(pidAttendu, identU1.DebutTacheTicks)
	})
	if allocsCollecteur != 0 {
		t.Fatalf("CollecteurReseauParProcessus doit etre 0 B/op, mesure %.2f allocs/op", allocsCollecteur)
	}
}

func TestArbitreEncodeurZeroAllocEtVetoPhysiqueSouverain(t *testing.T) {
	arbitre := cinetique.NouvelArbitreEncodeurCinetique()
	defer func() { _ = arbitre.Fermer() }()

	// Cas 1 : Dégradation stockage pure (0 activité réseau) -> même si un modèle proposait B, le veto force A.
	epDisque, err1 := construireEpisodeReference(55_000_000, 8_000_000, 200_000, 30_000, 2, 2, 80, cinetique.CompteursReseauEpisode{})
	if err1 != nil {
		t.Fatalf("epDisque: %v", err1)
	}
	diagDisque := cinetique.DiagnosticEpisodeCinetique{
		Orientation: cinetique.OrientationDegradationES,
		Episode:     epDisque,
	}
	diagDisque.VariationsPct[cinetique.IndiceDilatationHorsCPU] = 520

	verdictVeto1, veto1, motif1 := cinetique.AppliquerVetoPhysiqueCinetique(diagDisque, cinetique.VerdictSLMCompromissionExfil)
	if !veto1 || verdictVeto1 != cinetique.VerdictSLMDegradationMaterielle || motif1 != "VETO_ZERO_NETWORK_STORAGE_STALL" {
		t.Fatalf("veto panne disque mal applique: verdict=%s veto=%v motif=%s", verdictVeto1, veto1, motif1)
	}

	// Cas 2 : Exfiltration réseau/DNS convergente -> impossible à blanchir en C ou D.
	epHostile, err2 := construireEpisodeReference(
		30_000_000, 24_000_000, 200_000, 44_000, 2, 2, 100,
		cinetique.CompteursReseauEpisode{
			OctetsSortants:      32_768,
			ConnexionsSortantes: 1,
			ResolutionsDNS:      10,
			PortSuspect:         53,
			ProtocoleSuspectUDP: true,
			CodeRaisonDNS:       5,
		},
	)
	if err2 != nil {
		t.Fatalf("epHostile: %v", err2)
	}
	diagHostile := cinetique.DiagnosticEpisodeCinetique{
		Orientation: cinetique.OrientationCompromissionReseau,
		Episode:     epHostile,
	}
	diagHostile.VariationsPct[cinetique.IndiceNsCPUParKioLogique] = 210
	diagHostile.VariationsPct[cinetique.IndiceKioPicRSSParFil] = 46

	verdictVeto2, veto2, _ := cinetique.AppliquerVetoPhysiqueCinetique(diagHostile, cinetique.VerdictSLMContentionOuInsuff)
	if !veto2 || verdictVeto2 != cinetique.VerdictSLMCompromissionExfil {
		t.Fatalf("veto anti-blanchiment en echec: verdict=%s veto=%v", verdictVeto2, veto2)
	}

	// Cas 3 : Dérive mémoire monotone avec gigue hors-CPU sub-unitaire (+600% sur <1ms,
	// Valeurs[IndiceDilatationHorsCPU] < 1000 permille) -> doit rester ORGANIC_RESOURCE_DRIFT.
	epDeriveGigue, err3 := construireEpisodeReference(10_500_000, 8_000_000, 200_000, 36_000, 2, 2, 0, cinetique.CompteursReseauEpisode{})
	if err3 != nil {
		t.Fatalf("epDeriveGigue: %v", err3)
	}
	diagDeriveGigue := cinetique.DiagnosticEpisodeCinetique{
		Orientation:          cinetique.OrientationDeriveOrganique,
		PasDeriveMonotoneRSS: 6,
		Episode:              epDeriveGigue,
	}
	diagDeriveGigue.VariationsPct[cinetique.IndiceDilatationHorsCPU] = 620
	diagDeriveGigue.VariationsPct[cinetique.IndiceKioPicRSSParFil] = 20
	if vDerive, _, _ := arbitre.EvaluerZeroAlloc(diagDeriveGigue); vDerive != cinetique.VerdictSLMDeriveOrganique {
		t.Fatalf("gigue hors-CPU sub-unitaire ne doit pas masquer ORGANIC_RESOURCE_DRIFT, obtenu %s", vDerive)
	}

	// Preuve 0 B/op sur EvaluerZeroAlloc (DecisionHead SIMD + veto) et FormaterBriefCausalSLM.
	var tamponBrief [512]byte
	allocsEncodeur := testing.AllocsPerRun(1000, func() {
		brief, errB := cinetique.FormaterBriefCausalSLM(tamponBrief[:0], "backup_job", diagHostile)
		if errB != nil || len(brief) == 0 {
			t.Fatalf("FormaterBriefCausalSLM: %v", errB)
		}
		v, conf, _ := arbitre.EvaluerZeroAlloc(diagHostile)
		if v != cinetique.VerdictSLMCompromissionExfil || conf <= 0 {
			t.Fatalf("verdict inattendu: %s (%f)", v, conf)
		}
	})
	if allocsEncodeur != 0 {
		t.Fatalf("EvaluerZeroAlloc + FormaterBriefCausalSLM doivent etre 0 B/op, mesure %.2f allocs/op", allocsEncodeur)
	}
	var tamponCourt [16]byte
	if _, errCourt := cinetique.FormaterBriefCausalSLM(tamponCourt[:0], "backup_job", diagHostile); !errors.Is(errCourt, cinetique.ErrTamponTropCourt) {
		t.Fatalf("attendu ErrTamponTropCourt, obtenu %v", errCourt)
	}

	// Vérification de la file asynchrone bornée hors chemin chaud.
	var compteurRecus atomic.Uint64
	canalTermine := make(chan struct{}, 4)
	file := cinetique.NouvelleFileArbitrageCinetique(arbitre, 2, func(_ cinetique.DossierEscaladeCinetique, dec cinetique.DecisionArbitrageCinetique) {
		if dec.ModeleInvoque {
			compteurRecus.Add(1)
			select {
			case canalTermine <- struct{}{}:
			default:
			}
		}
	})
	diagNominal := cinetique.DiagnosticEpisodeCinetique{Orientation: cinetique.OrientationNominale}
	if err := file.SoumettreNonBloquant("cron_sain", diagNominal); err != nil {
		t.Fatalf("soumission nominale: %v", err)
	}
	if file.TotalIgnoresNominal.Load() != 1 {
		t.Fatalf("attendu 1 episode nominal ignore, obtenu %d", file.TotalIgnoresNominal.Load())
	}
	if err := file.SoumettreNonBloquant("backup_job", diagDisque); err != nil {
		t.Fatalf("soumission disque: %v", err)
	}
	if err := file.SoumettreNonBloquant("backup_job", diagHostile); err != nil {
		t.Fatalf("soumission hostile: %v", err)
	}
	<-canalTermine
	file.Fermer()
	if compteurRecus.Load() != 2 || file.TotalArbitres.Load() != 2 {
		t.Fatalf("attendu 2 dossiers arbitres apres drain, obtenu recus=%d arbitres=%d",
			compteurRecus.Load(), file.TotalArbitres.Load())
	}
	// Jumeau négatif : soumission après fermeture -> ErrArbitreFerme.
	if errFerme := file.SoumettreNonBloquant("backup_job", diagHostile); !errors.Is(errFerme, cinetique.ErrArbitreFerme) {
		t.Fatalf("attendu ErrArbitreFerme apres Fermer, obtenu %v", errFerme)
	}
}

func TestBancChaineCompleteBoutEnBout(t *testing.T) {
	ctx, annuler := context.WithTimeout(context.Background(), 45*time.Second)
	defer annuler()

	cheminModele := os.Getenv("C2_TEST_QWEN_GGUF")
	rapport, err := cinetique.ExecuterBancChaineComplete(ctx, t.TempDir(), cheminModele)
	if err != nil {
		t.Fatalf("ExecuterBancChaineComplete: %v", err)
	}
	if rapport.PIDProcessus != os.Getpid() || rapport.DebutTacheTicks == 0 {
		t.Fatalf("identite processus invalide: %+v", rapport)
	}
	if len(rapport.Chaines) < 4 {
		t.Fatalf("attendu au moins 4 chaines, obtenu %d", len(rapport.Chaines))
	}

	parNom := make(map[string]cinetique.EtapeChaineDetection, len(rapport.Chaines))
	for _, ch := range rapport.Chaines {
		parNom[ch.NomChaine] = ch
	}

	if ch0, ok := parNom["0_controle_nominal"]; !ok || ch0.EscaladeSLM || ch0.DecisionEncodeur.ModeleInvoque {
		t.Fatalf("chaine 0 nominale ne doit pas escalader: %+v", ch0)
	}
	if ch1, ok := parNom["1_abstention_migration_hybride"]; ok {
		if ch1.EscaladeSLM || ch1.DecisionEncodeur.ModeleInvoque || ch1.OrientationMoteur != cinetique.OrientationAbstention.String() {
			t.Fatalf("chaine 1 migration hybride doit s'abstenir sans escalader: %+v", ch1)
		}
	}
	if ch2, ok := parNom["2_degradation_stockage_nvme"]; !ok {
		t.Fatal("chaine 2 degradation stockage absente")
	} else if ch2.EscaladeSLM {
		if ch2.DecisionEncodeur.VerdictFinal != cinetique.VerdictSLMDegradationMaterielle {
			t.Fatalf("chaine 2 degradation stockage mal arbitree (encodeur): %+v", ch2)
		}
		if ch2.DecisionQwen != nil {
			if ch2.DecisionQwen.VerdictFinal != cinetique.VerdictSLMDegradationMaterielle ||
				ch2.DecisionQwen.VerdictBrutModele != cinetique.VerdictSLMDegradationMaterielle ||
				ch2.DecisionQwen.VetoPhysiqueApplique {
				t.Fatalf("chaine 2 degradation stockage mal arbitree ou sauvee par veto (Qwen): %+v", ch2.DecisionQwen)
			}
		}
	} else if ch2.OrientationMoteur != cinetique.OrientationAbstention.String() ||
		(!ch2.MigrationHybride && ch2.PressionCPUPermille <= 200) {
		t.Fatalf("chaine 2 non escaladee sans cause physique d'abstention: %+v", ch2)
	}
	if ch3, ok := parNom["3_exfiltration_udp_attribuee_inet_diag"]; !ok ||
		!ch3.EscaladeSLM ||
		ch3.AttributionSocket == nil ||
		ch3.AttributionSocket.PID != os.Getpid() ||
		ch3.CodeRaisonDNS == 0 ||
		ch3.DecisionEncodeur.VerdictFinal != cinetique.VerdictSLMCompromissionExfil ||
		(ch3.DecisionQwen != nil && (ch3.DecisionQwen.VerdictFinal != cinetique.VerdictSLMCompromissionExfil ||
			ch3.DecisionQwen.VerdictBrutModele != cinetique.VerdictSLMCompromissionExfil ||
			ch3.DecisionQwen.VetoPhysiqueApplique)) {
		t.Fatalf("chaine 3 exfiltration attribuee invalide: ch3=%+v qwen=%+v", ch3, ch3.DecisionQwen)
	}
	if ch4, ok := parNom["4_derive_organique_monotone"]; !ok ||
		!ch4.EscaladeSLM ||
		ch4.DecisionEncodeur.VerdictFinal != cinetique.VerdictSLMDeriveOrganique ||
		(ch4.DecisionQwen != nil && (ch4.DecisionQwen.VerdictFinal != cinetique.VerdictSLMDeriveOrganique ||
			ch4.DecisionQwen.VerdictBrutModele != cinetique.VerdictSLMDeriveOrganique ||
			ch4.DecisionQwen.VetoPhysiqueApplique)) {
		t.Fatalf("chaine 4 derive organique invalide: ch4=%+v qwen=%+v", ch4, ch4.DecisionQwen)
	}
}
