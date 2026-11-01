package c2blue55

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/engine"
)

func construireRDataTXTSegmentee(taillesSegments []int) []byte {
	var rdata []byte
	motif := byte(0)
	for _, tailleSegment := range taillesSegments {
		rdata = append(rdata, byte(tailleSegment))
		for range tailleSegment {
			rdata = append(rdata, 'A'+byte(motif%26))
			motif++
		}
	}
	return rdata
}

func construireReponseDNSBrute(nbReponses int, typeRR uint16, rdata []byte) []byte {
	trameDNS := make([]byte, 12)
	binary.BigEndian.PutUint16(trameDNS[0:2], 0x4242)
	binary.BigEndian.PutUint16(trameDNS[2:4], 0x8180)
	binary.BigEndian.PutUint16(trameDNS[4:6], 1)
	binary.BigEndian.PutUint16(trameDNS[6:8], uint16(nbReponses))
	trameDNS = append(trameDNS, 3, 'l', 'a', 'b', 4, 't', 'e', 's', 't', 0)
	trameDNS = binary.BigEndian.AppendUint16(trameDNS, typeRR)
	trameDNS = binary.BigEndian.AppendUint16(trameDNS, 1)
	for range nbReponses {
		trameDNS = append(trameDNS, 0xc0, 0x0c)
		trameDNS = binary.BigEndian.AppendUint16(trameDNS, typeRR)
		trameDNS = binary.BigEndian.AppendUint16(trameDNS, 1)
		trameDNS = binary.BigEndian.AppendUint32(trameDNS, 60)
		trameDNS = binary.BigEndian.AppendUint16(trameDNS, uint16(len(rdata)))
		trameDNS = append(trameDNS, rdata...)
	}
	return trameDNS
}

func TestAuditDNSRejetDixSeptReponses(t *testing.T) {
	var message DNSMessage
	paquet := construireReponseDNSBrute(17, 1, []byte{192, 0, 2, 10})
	if err := ParseDNSMessage(paquet, &message); err == nil {
		t.Fatalf("17 reponses DNS A acceptees apres reduction muette a %d", message.AnswerCount)
	}
}

func TestAuditDNSRDataIntegraleEtRejetDepassement(t *testing.T) {
	// 1. Reponse TXT de 385 octets (segments [255] + [128] -> (1+255)+(1+128) = 385).
	rdata385 := construireRDataTXTSegmentee([]int{255, 128})
	if len(rdata385) != 385 {
		t.Fatalf("fixture RDATA 385 invalide: len=%d", len(rdata385))
	}
	var message385 DNSMessage
	if err := ParseDNSMessage(construireReponseDNSBrute(1, 16, rdata385), &message385); err != nil {
		t.Errorf("ParseDNSMessage RDATA=385 octets a echoue: %v", err)
	} else {
		longueurRestituee := int(message385.Answers[0].RDataLen)
		if longueurRestituee != 385 {
			t.Errorf("ParseDNSMessage RDATA=385 tronquee a %d octets", longueurRestituee)
		} else {
			octetsRestitues := message385.Answers[0].RData[:longueurRestituee]
			if !bytes.Equal(octetsRestitues, rdata385) {
				t.Errorf("ParseDNSMessage RDATA=385 alteree (dernier octet obtenu=%#x, attendu=%#x)", octetsRestitues[384], rdata385[384])
			}
		}
	}

	// 2. Reponse TXT EDNS0 de 1139 octets (4 segments [255] + 1 segment [114] -> 4*256 + 115 = 1139).
	rdata1139 := construireRDataTXTSegmentee([]int{255, 255, 255, 255, 114})
	if len(rdata1139) != 1139 {
		t.Fatalf("fixture RDATA 1139 invalide: len=%d", len(rdata1139))
	}
	var message1139 DNSMessage
	if err := ParseDNSMessage(construireReponseDNSBrute(1, 16, rdata1139), &message1139); err != nil {
		t.Errorf("ParseDNSMessage RDATA=1139 octets a echoue: %v", err)
	} else {
		longueurRestituee := int(message1139.Answers[0].RDataLen)
		if longueurRestituee != 1139 {
			t.Errorf("ParseDNSMessage RDATA=1139 tronquee a %d octets", longueurRestituee)
		} else {
			octetsRestitues := message1139.Answers[0].RData[:longueurRestituee]
			if !bytes.Equal(octetsRestitues, rdata1139) {
				t.Errorf("ParseDNSMessage RDATA=1139 alteree")
			}
		}
	}

	// 3. Reponse TXT de 2048 octets au-dela du plafond Ethernet/EDNS0 : rejet explicite obligatoire.
	rdata2048 := construireRDataTXTSegmentee([]int{255, 255, 255, 255, 255, 255, 255, 255})
	if len(rdata2048) != 2048 {
		t.Fatalf("fixture RDATA 2048 invalide: len=%d", len(rdata2048))
	}
	var message2048 DNSMessage
	if err := ParseDNSMessage(construireReponseDNSBrute(1, 16, rdata2048), &message2048); err == nil {
		t.Errorf("ParseDNSMessage RDATA=2048 octets acceptee silencieusement (RDataLen=%d)", message2048.Answers[0].RDataLen)
	}
}

func TestAuditLongueurUDPInvalide(t *testing.T) {
	trameEthernet := make([]byte, 14+20+8+12)
	binary.BigEndian.PutUint16(trameEthernet[12:14], 0x0800)
	enteteIP := trameEthernet[14:]
	enteteIP[0] = 0x45
	binary.BigEndian.PutUint16(enteteIP[2:4], uint16(20+8+12))
	enteteIP[9] = 17
	enteteUDP := enteteIP[20:]
	binary.BigEndian.PutUint16(enteteUDP[0:2], 51000)
	binary.BigEndian.PutUint16(enteteUDP[2:4], 53)
	binary.BigEndian.PutUint16(enteteUDP[4:6], 7) // Longueur UDP < 8 octets d'en-tête !

	if _, _, ok := extractDNSPayload(pcapLinkEthernet, trameEthernet); ok {
		t.Fatal("extractDNSPayload(Ethernet) accepte une longueur UDP invalide de 7 octets")
	}
	if _, _, ok := extractDNSPayload(pcapLinkRawIP, trameEthernet[14:]); ok {
		t.Fatal("extractDNSPayload(RawIP) accepte une longueur UDP invalide de 7 octets")
	}
}

func TestAuditSiloRefuseTrancheCouranteNonAuthentifiee(t *testing.T) {
	repertoire := t.TempDir()
	const machine = uint64(0x1122334455667788)
	const instant = uint64(1789732800)
	jour := uint32(instant / 86400)
	entrees := []engine.OracleVectorEntry{{RelativeSec: 1, Subsystem: engine.OracleSubKernel, HealthScore: 990}}
	entete := engine.OracleDailyHeader{
		EpochDay: jour, StartTsSec: instant - 60, EndTsSec: instant,
		VectorCount: 1, AverageScore: 990, Flags: engine.OracleFlagSealed, MachineID: machine,
	}
	chemin := filepath.Join(repertoire, oracleDayFileName(machine, jour))
	if err := writeOracleDayAtomic(chemin, &entete, entrees, nil); err != nil {
		t.Fatal(err)
	}
	cle := bytes.Repeat([]byte{0x5a}, 32)
	silo, err := NewDailyOracleSilo(SiloConfig{StorageDir: repertoire, MachineID: machine, HMACKey: cle})
	if err != nil {
		t.Fatal(err)
	}
	instantane := engine.ServerHealthSnapshot{
		TimestampSec: instant + 30,
		Subsystem:    engine.OracleSubKernel,
		HealthScore:  990,
		Severity:     engine.SeverityLow,
	}
	if err := silo.IngestSnapshot(&instantane); err != nil {
		t.Fatal(err)
	}
	if err := silo.SealDay(instant + 120); err == nil {
		_, fusionnees, erreurLecture := loadOracleDayFile(chemin, cle)
		t.Fatalf("la tranche non authentifiee a ete re-scellee: entrees=%d lecture=%v", len(fusionnees), erreurLecture)
	}
}

func TestAuditBaselineVideSurCorruption(t *testing.T) {
	repertoire := t.TempDir()
	const machine = uint64(0x1122334455667788)
	chemin := filepath.Join(repertoire, oracleDayFileName(machine, 20000))
	if err := os.WriteFile(chemin, []byte("synth-corrompu"), 0o600); err != nil {
		t.Fatal(err)
	}
	silo, err := NewDailyOracleSilo(SiloConfig{StorageDir: repertoire, MachineID: machine})
	if err != nil {
		t.Fatal(err)
	}
	oracle, err := silo.BuildServerBaseline(7)
	if err == nil {
		t.Fatalf("toutes les tranches sont corrompues mais la baseline vide est acceptee: %d entrees", oracle.Len())
	}
}

func verifierPreuveOOSNonCodageEnDur(t *testing.T, contexteSuite string, rapportSuite any) {
	t.Helper()
	valeurRapport := reflect.ValueOf(rapportSuite)
	champPreuve := valeurRapport.FieldByName("OOSProof")
	if !champPreuve.IsValid() {
		t.Errorf("%s: champ OOSProof absent du rapport (aucune preuve OOS reelle exposee)", contexteSuite)
		return
	}
	preuveOOS, ok := champPreuve.Interface().(engine.OOSPatternProof)
	if !ok {
		t.Errorf("%s: champ OOSProof de type inattendu %T", contexteSuite, champPreuve.Interface())
		return
	}
	if len(preuveOOS.Families) < 4 {
		t.Errorf("%s: len(OOSProof.Families)=%d, attendu >= 4", contexteSuite, len(preuveOOS.Families))
		return
	}
	if !preuveOOS.AllPass {
		t.Errorf("%s: OOSProof.AllPass=false, attendu true", contexteSuite)
	}
	for _, idFamille := range []string{"P1", "P2", "P3", "P4"} {
		metriques, presente := preuveOOS.Families[idFamille]
		if !presente {
			t.Errorf("%s: famille %s absente de OOSProof.Families", contexteSuite, idFamille)
			continue
		}
		if metriques.MaxSphereRad <= 0 {
			t.Errorf("%s: famille %s MaxSphereRad=%.6f <= 0 (preuve OOS non calibree par ProvePatternOutOfSample)", contexteSuite, idFamille, metriques.MaxSphereRad)
		}
	}
	famP3 := preuveOOS.Families["P3"]
	famP4 := preuveOOS.Families["P4"]
	paireLitterale9896 := math.Abs(famP3.AUC-0.98) < 1e-9 &&
		math.Abs(famP3.LODO_AUC-0.96) < 1e-9 &&
		math.Abs(famP4.AUC-0.99) < 1e-9 &&
		math.Abs(famP4.LODO_AUC-0.97) < 1e-9
	if paireLitterale9896 {
		t.Errorf("%s: quadruple (AUC, LODO_AUC) litteral code en dur detecte P3=(%.2f, %.2f) P4=(%.2f, %.2f)",
			contexteSuite, famP3.AUC, famP3.LODO_AUC, famP4.AUC, famP4.LODO_AUC)
	}
}

func TestAuditIRLThesaurusSansFuiteVeriteTerrain(t *testing.T) {
	_, corpus, _, err := executeAndRecordDilutedRun(t.TempDir(), "audit-irl-a", "a.test", 0xCAFE1234)
	if err != nil {
		t.Fatalf("executeAndRecordDilutedRun: %v", err)
	}
	if corpus == nil || len(corpus.Samples) == 0 {
		t.Fatal("corpus vide retourne par executeAndRecordDilutedRun")
	}

	vecteurBeninCodeEnDur := [8]float32{0.1, 0.2, 0.0, 0.05, 0.1, 0.0, 0.0, 0.0}
	var vecteursBeninsDistincts [][8]float32
	nbBenins, nbBeninsCodeEnDur := 0, 0
	nbP1, nbP1DrapeauConstant := 0, 0
	nbP2, nbP2DrapeauConstant := 0, 0
	nbP3, nbP3DrapeauConstant := 0, 0

	for _, echantillon := range corpus.Samples {
		switch echantillon.Family {
		case "BENIGN":
			nbBenins++
			if echantillon.Features == vecteurBeninCodeEnDur {
				nbBeninsCodeEnDur++
			}
			if !slices.Contains(vecteursBeninsDistincts, echantillon.Features) {
				vecteursBeninsDistincts = append(vecteursBeninsDistincts, echantillon.Features)
			}
		case "P1":
			nbP1++
			if echantillon.Features[2] == 1.0 && echantillon.Features[3] == 0 && echantillon.Features[4] == 0 {
				nbP1DrapeauConstant++
			}
		case "P2":
			nbP2++
			if echantillon.Features[5] == 1.0 && echantillon.Features[0] == 0 && echantillon.Features[1] == 0 {
				nbP2DrapeauConstant++
			}
		case "P3":
			nbP3++
			if echantillon.Features[7] == 1.0 && echantillon.Features[0] == 0 && echantillon.Features[1] == 0 && echantillon.Features[2] == 0 {
				nbP3DrapeauConstant++
			}
		}
	}

	if nbBeninsCodeEnDur > 0 {
		t.Errorf("fuite de verite terrain sur BENIGN: %d/%d echantillons portent le vecteur litteral code en dur %v",
			nbBeninsCodeEnDur, nbBenins, vecteurBeninCodeEnDur)
	}
	if len(vecteursBeninsDistincts) < 2 {
		t.Errorf("les echantillons BENIGN ne produisent que %d vecteur(s) distinct(s) sur le fil (attendu >= 2)", len(vecteursBeninsDistincts))
	}
	if nbP1 > 0 && nbP1DrapeauConstant == nbP1 {
		t.Errorf("fuite de verite terrain sur P1: %d/%d echantillons portent le drapeau constant Features[2]==1.0 && Features[3..4]==0", nbP1DrapeauConstant, nbP1)
	}
	if nbP2 > 0 && nbP2DrapeauConstant == nbP2 {
		t.Errorf("fuite de verite terrain sur P2: %d/%d echantillons portent le drapeau constant Features[5]==1.0 && Features[0..1]==0", nbP2DrapeauConstant, nbP2)
	}
	if nbP3 > 0 && nbP3DrapeauConstant == nbP3 {
		t.Errorf("fuite de verite terrain sur P3: %d/%d echantillons portent le drapeau constant Features[7]==1.0 && Features[0..2]==0", nbP3DrapeauConstant, nbP3)
	}

	rapport8, err := RunIRL8MotifsFullSuite(t.TempDir(), 0x11112222, 0x33334444)
	if err != nil {
		t.Fatalf("RunIRL8MotifsFullSuite: %v", err)
	}
	verifierPreuveOOSNonCodageEnDur(t, "RunIRL8MotifsFullSuite", rapport8)

	rapport17, err := RunIRL17MotifsFullSuite(t.TempDir(), 0x55556666, 0x77778888)
	if err != nil {
		t.Fatalf("RunIRL17MotifsFullSuite: %v", err)
	}
	verifierPreuveOOSNonCodageEnDur(t, "RunIRL17MotifsFullSuite", rapport17)
}
