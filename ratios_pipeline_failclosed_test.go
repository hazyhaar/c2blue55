package c2blue55

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/engine"
)

func rat02aEncoderNomDNS(nomDomaine string) []byte {
	var filaire []byte
	for etiquette := range strings.SplitSeq(nomDomaine, ".") {
		if len(etiquette) == 0 {
			continue
		}
		filaire = append(filaire, byte(len(etiquette)))
		filaire = append(filaire, etiquette...)
	}
	return append(filaire, 0)
}

func rat02aAjouterRR(tampon []byte, nomFilaire []byte, typeRR uint16, ttl uint32, rdata []byte) []byte {
	tampon = append(tampon, nomFilaire...)
	tampon = binary.BigEndian.AppendUint16(tampon, typeRR)
	tampon = binary.BigEndian.AppendUint16(tampon, 1)
	tampon = binary.BigEndian.AppendUint32(tampon, ttl)
	tampon = binary.BigEndian.AppendUint16(tampon, uint16(len(rdata)))
	return append(tampon, rdata...)
}

func rat02aConstruireMessageAdditionalA(identifiantTx uint16, estReponse bool, nomQuestion string, nbAdditionnels int) []byte {
	drapeaux := uint16(0x0100)
	var nbReponses uint16
	if estReponse {
		drapeaux = 0x8180
		nbReponses = 1
	}
	paquet := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(paquet[0:2], identifiantTx)
	binary.BigEndian.PutUint16(paquet[2:4], drapeaux)
	binary.BigEndian.PutUint16(paquet[4:6], 1)
	binary.BigEndian.PutUint16(paquet[6:8], nbReponses)
	binary.BigEndian.PutUint16(paquet[8:10], 0)
	binary.BigEndian.PutUint16(paquet[10:12], uint16(nbAdditionnels))

	paquet = append(paquet, rat02aEncoderNomDNS(nomQuestion)...)
	paquet = binary.BigEndian.AppendUint16(paquet, 1)
	paquet = binary.BigEndian.AppendUint16(paquet, 1)

	pointeurQuestion := []byte{0xC0, 0x0C}
	if estReponse {
		paquet = rat02aAjouterRR(paquet, pointeurQuestion, 1, 300, []byte{192, 0, 2, 1})
	}
	for indice := range nbAdditionnels {
		paquet = rat02aAjouterRR(paquet, pointeurQuestion, 1, 300, []byte{192, 0, 2, byte(10 + indice)})
	}
	return paquet
}

func rat02aConstruireMessageRDataDepassement(identifiantTx uint16, longueurRData int) []byte {
	paquet := make([]byte, 12, 64+longueurRData)
	binary.BigEndian.PutUint16(paquet[0:2], identifiantTx)
	binary.BigEndian.PutUint16(paquet[2:4], 0x8180)
	binary.BigEndian.PutUint16(paquet[4:6], 1)
	binary.BigEndian.PutUint16(paquet[6:8], 1)
	paquet = append(paquet, rat02aEncoderNomDNS("api.hazyhaar.fr")...)
	paquet = binary.BigEndian.AppendUint16(paquet, 16)
	paquet = binary.BigEndian.AppendUint16(paquet, 1)

	chargeRData := make([]byte, longueurRData)
	restant := longueurRData
	curseur := 0
	for restant > 0 {
		segment := max(min(restant-1, 255), 0)
		chargeRData[curseur] = byte(segment)
		curseur++
		restant--
		for indice := range segment {
			chargeRData[curseur+indice] = 'a' + byte(indice%26)
		}
		curseur += segment
		restant -= segment
	}
	return rat02aAjouterRR(paquet, []byte{0xC0, 0x0C}, 16, 60, chargeRData)
}

func rat02aConstruireNXDOMAINConformeDNSSEC() ([]byte, []byte) {
	nomQuestion := rat02aEncoderNomDNS("alias.zone.hazyhaar.fr")

	requete := make([]byte, 12, 128)
	binary.BigEndian.PutUint16(requete[0:2], 0x5101)
	binary.BigEndian.PutUint16(requete[2:4], 0x0100)
	binary.BigEndian.PutUint16(requete[4:6], 1)
	requete = append(requete, nomQuestion...)
	requete = binary.BigEndian.AppendUint16(requete, 1)
	requete = binary.BigEndian.AppendUint16(requete, 1)

	reponse := make([]byte, 12, 512)
	binary.BigEndian.PutUint16(reponse[0:2], 0x5101)
	binary.BigEndian.PutUint16(reponse[2:4], 0x8503) // QR=1, AA=1, RD=1, RCODE=3 (NXDOMAIN)
	binary.BigEndian.PutUint16(reponse[4:6], 1)
	binary.BigEndian.PutUint16(reponse[6:8], 3)  // CNAME + RRSIG + DNAME
	binary.BigEndian.PutUint16(reponse[8:10], 1) // SOA en Authority
	reponse = append(reponse, nomQuestion...)
	reponse = binary.BigEndian.AppendUint16(reponse, 1)
	reponse = binary.BigEndian.AppendUint16(reponse, 1)

	// Answer 1 : CNAME (type 5)
	rdataCNAME := rat02aEncoderNomDNS("alias.deleguee.hazyhaar.fr")
	reponse = rat02aAjouterRR(reponse, nomQuestion, 5, 300, rdataCNAME)

	// Answer 2 : RRSIG (type 46) couvrant CNAME
	rdataRRSIG := make([]byte, 18)
	binary.BigEndian.PutUint16(rdataRRSIG[0:2], 5)
	rdataRRSIG[2] = 13
	rdataRRSIG[3] = 4
	binary.BigEndian.PutUint32(rdataRRSIG[4:8], 300)
	binary.BigEndian.PutUint32(rdataRRSIG[8:12], 1_893_456_000)
	binary.BigEndian.PutUint32(rdataRRSIG[12:16], 1_793_456_000)
	binary.BigEndian.PutUint16(rdataRRSIG[16:18], 12345)
	rdataRRSIG = append(rdataRRSIG, rat02aEncoderNomDNS("zone.hazyhaar.fr")...)
	rdataRRSIG = append(rdataRRSIG, make([]byte, 64)...)
	reponse = rat02aAjouterRR(reponse, nomQuestion, 46, 300, rdataRRSIG)

	// Answer 3 : DNAME (type 39)
	nomZone := rat02aEncoderNomDNS("zone.hazyhaar.fr")
	rdataDNAME := rat02aEncoderNomDNS("deleguee.hazyhaar.fr")
	reponse = rat02aAjouterRR(reponse, nomZone, 39, 300, rdataDNAME)

	// Authority 1 : SOA (type 6)
	var rdataSOA []byte
	rdataSOA = append(rdataSOA, rat02aEncoderNomDNS("ns1.hazyhaar.fr")...)
	rdataSOA = append(rdataSOA, rat02aEncoderNomDNS("hostmaster.hazyhaar.fr")...)
	rdataSOA = binary.BigEndian.AppendUint32(rdataSOA, 2026110101)
	rdataSOA = binary.BigEndian.AppendUint32(rdataSOA, 3600)
	rdataSOA = binary.BigEndian.AppendUint32(rdataSOA, 900)
	rdataSOA = binary.BigEndian.AppendUint32(rdataSOA, 604800)
	rdataSOA = binary.BigEndian.AppendUint32(rdataSOA, 60)
	reponse = rat02aAjouterRR(reponse, rat02aEncoderNomDNS("hazyhaar.fr"), 6, 300, rdataSOA)

	return requete, reponse
}

func rat02aTrameIPv4BruteUDP(adrSource, adrDest [4]byte, portSource, portDest uint16, chargeDNS []byte) []byte {
	longueurTotale := 20 + 8 + len(chargeDNS)
	trame := make([]byte, longueurTotale)
	trame[0] = 0x45
	binary.BigEndian.PutUint16(trame[2:4], uint16(longueurTotale))
	trame[8] = 64
	trame[9] = 17
	copy(trame[12:16], adrSource[:])
	copy(trame[16:20], adrDest[:])
	binary.BigEndian.PutUint16(trame[20:22], portSource)
	binary.BigEndian.PutUint16(trame[22:24], portDest)
	binary.BigEndian.PutUint16(trame[24:26], uint16(8+len(chargeDNS)))
	copy(trame[28:], chargeDNS)
	return trame
}

func rat02aEcrirePCAPRawIP(t *testing.T, chemin string, trames [][]byte, horodatagesUs []uint64) {
	t.Helper()
	octetsPCAP := make([]byte, 24)
	binary.LittleEndian.PutUint32(octetsPCAP[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(octetsPCAP[4:6], 2)
	binary.LittleEndian.PutUint16(octetsPCAP[6:8], 4)
	binary.LittleEndian.PutUint32(octetsPCAP[16:20], 65535)
	binary.LittleEndian.PutUint32(octetsPCAP[20:24], 101)
	for indice, trame := range trames {
		var enteteEnregistrement [16]byte
		binary.LittleEndian.PutUint32(enteteEnregistrement[0:4], uint32(horodatagesUs[indice]/1_000_000))
		binary.LittleEndian.PutUint32(enteteEnregistrement[4:8], uint32(horodatagesUs[indice]%1_000_000))
		binary.LittleEndian.PutUint32(enteteEnregistrement[8:12], uint32(len(trame)))
		binary.LittleEndian.PutUint32(enteteEnregistrement[12:16], uint32(len(trame)))
		octetsPCAP = append(octetsPCAP, enteteEnregistrement[:]...)
		octetsPCAP = append(octetsPCAP, trame...)
	}
	if err := os.WriteFile(chemin, octetsPCAP, 0o600); err != nil {
		t.Fatalf("écriture PCAP temporaire %s : %v", chemin, err)
	}
}

func TestRatiosPipeline_FailClosedParseErrors(t *testing.T) {
	if ReasonDNSParseError != "REASON_DNS_PARSE_ERROR" {
		t.Fatalf("ReasonDNSParseError = %q, attendu %q", ReasonDNSParseError, "REASON_DNS_PARSE_ERROR")
	}

	pipe, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline : %v", err)
	}
	defer pipe.Close()

	var adrClient, adrServeur [16]byte
	adrClient[15] = 2
	adrServeur[15] = 1
	const instantBaseNs = int64(1_793_500_000_000_000_000)

	trame17RR := rat02aConstruireMessageAdditionalA(0x3101, true, "api.hazyhaar.fr", 17)
	trameTronquee5 := []byte{0x31, 0x02, 0x01, 0x00, 0x00}
	trameRDataLong := rat02aConstruireMessageRDataDepassement(0x3103, MaxDNSRDataBytes+64)

	casHostiles := []struct {
		nom            string
		trame          []byte
		erreurAttendue error
	}{
		{nom: "Additional_17_RR_ErrTooManyRRs", trame: trame17RR, erreurAttendue: ErrTooManyRRs},
		{nom: "Tronquee_5_octets_ErrPacketTooShort", trame: trameTronquee5, erreurAttendue: ErrPacketTooShort},
		{nom: "RDATA_1600_octets_ErrRDataTooLong", trame: trameRDataLong, erreurAttendue: ErrRDataTooLong},
	}

	for indice, cas := range casHostiles {
		t.Run(cas.nom, func(t *testing.T) {
			var messageDecode DNSMessage
			errParse := ParseDNSMessage(cas.trame, &messageDecode)
			if !errors.Is(errParse, cas.erreurAttendue) {
				t.Fatalf("précondition ParseDNSMessage : err=%v, attendu %v", errParse, cas.erreurAttendue)
			}

			horodatage := instantBaseNs + int64(indice)*1_000_000
			verdictRaison, classe, motif, errEval := pipe.EvaluateDNSMessageWithReason(cas.trame, horodatage, adrServeur, adrClient)
			if errEval == nil {
				t.Fatalf("EvaluateDNSMessageWithReason : err == nil sur trame invalide (%s)", cas.nom)
			}
			if !errors.Is(errEval, cas.erreurAttendue) {
				t.Errorf("EvaluateDNSMessageWithReason : err = %v, attendu errors.Is(%v)", errEval, cas.erreurAttendue)
			}
			if verdictRaison.Decision == DecisionFastPass {
				t.Errorf("EvaluateDNSMessageWithReason : DecisionFastPass interdit en fail-closed sur erreur de décodage")
			}
			if verdictRaison.Decision != DecisionEscalateSLM {
				t.Errorf("EvaluateDNSMessageWithReason : Decision = %v, attendu DecisionEscalateSLM (%v)", verdictRaison.Decision, DecisionEscalateSLM)
			}
			if classe == "BENIGN" || classe != "PARSE_ERR" {
				t.Errorf("EvaluateDNSMessageWithReason : classe = %q, attendu %q (jamais BENIGN)", classe, "PARSE_ERR")
			}
			if motif != ReasonDNSParseError {
				t.Errorf("EvaluateDNSMessageWithReason : motif = %q, attendu %q", motif, ReasonDNSParseError)
			}

			verdictSimple, errSimple := pipe.EvaluateDNSMessage(cas.trame, horodatage+500, adrServeur, adrClient)
			if errSimple == nil || !errors.Is(errSimple, cas.erreurAttendue) {
				t.Errorf("EvaluateDNSMessage : err = %v, attendu errors.Is(%v)", errSimple, cas.erreurAttendue)
			}
			if verdictSimple.Decision != DecisionEscalateSLM {
				t.Errorf("EvaluateDNSMessage : Decision = %v, attendu DecisionEscalateSLM (%v)", verdictSimple.Decision, DecisionEscalateSLM)
			}
		})
	}

	// Jumeau négatif : 16 RR en Additional (borne exacte MaxDNSMessageRRs) passe sans ReasonDNSParseError.
	trame16RR := rat02aConstruireMessageAdditionalA(0x3110, true, "api.hazyhaar.fr", 16)
	var messageValide16 DNSMessage
	if err := ParseDNSMessage(trame16RR, &messageValide16); err != nil || messageValide16.AdditionalCount != 16 {
		t.Fatalf("jumeau négatif 16 RR refusé par ParseDNSMessage : err=%v additionalCount=%d", err, messageValide16.AdditionalCount)
	}
	verdict16, classe16, motif16, err16 := pipe.EvaluateDNSMessageWithReason(trame16RR, instantBaseNs+10_000_000, adrServeur, adrClient)
	if err16 != nil {
		t.Fatalf("jumeau négatif 16 RR : erreur inattendue %v", err16)
	}
	if motif16 == ReasonDNSParseError || motif16 != engine.ReasonNone {
		t.Errorf("jumeau négatif 16 RR : motif = %q, attendu %q", motif16, engine.ReasonNone)
	}
	if classe16 != "BENIGN" {
		t.Errorf("jumeau négatif 16 RR : classe = %q, attendu BENIGN", classe16)
	}
	if verdict16.Decision != DecisionFastPass {
		t.Errorf("jumeau négatif 16 RR : Decision = %v, attendu DecisionFastPass (%v)", verdict16.Decision, DecisionFastPass)
	}
}

func TestRatiosPipeline_RecordSessionFailClosedSansCorruption(t *testing.T) {
	repertoire := t.TempDir()
	pipe, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline : %v", err)
	}
	defer pipe.Close()

	session, err := NewRecordSession(repertoire, "rat02a-session", pipe)
	if err != nil {
		t.Fatalf("NewRecordSession : %v", err)
	}

	adrClient := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 55, 0, 2}
	adrServeur := [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 55, 0, 1}
	const instantNs = int64(1_793_500_100_000_000_000)

	requeteValideAvant := rat02aConstruireMessageAdditionalA(0x4101, false, "api.hazyhaar.fr", 0)
	paquetHostile17RR := rat02aConstruireMessageAdditionalA(0x4102, true, "api.hazyhaar.fr", 17)
	reponseValideApres := rat02aConstruireMessageAdditionalA(0x4101, true, "api.hazyhaar.fr", 16)

	verdictAvant, errAvant := session.RecordDNSMessage(requeteValideAvant, instantNs, adrClient, adrServeur)
	if errAvant != nil || verdictAvant.Decision != DecisionFastPass {
		t.Fatalf("RecordDNSMessage valide avant : decision=%v err=%v", verdictAvant.Decision, errAvant)
	}

	verdictHostile, errHostile := session.RecordDNSMessage(paquetHostile17RR, instantNs+1_000_000, adrServeur, adrClient)
	if errHostile == nil || !errors.Is(errHostile, ErrTooManyRRs) {
		t.Fatalf("RecordDNSMessage 17 RR : err=%v, attendu errors.Is(ErrTooManyRRs)", errHostile)
	}
	if verdictHostile.Decision != DecisionEscalateSLM {
		t.Fatalf("RecordDNSMessage 17 RR : Decision=%v, attendu DecisionEscalateSLM (%v)", verdictHostile.Decision, DecisionEscalateSLM)
	}

	verdictApres, errApres := session.RecordDNSMessage(reponseValideApres, instantNs+2_000_000, adrServeur, adrClient)
	if errApres != nil || verdictApres.Decision != DecisionFastPass {
		t.Fatalf("RecordDNSMessage valide après 17 RR : decision=%v err=%v", verdictApres.Decision, errApres)
	}

	if err := session.Close(); err != nil {
		t.Fatalf("Close session : %v", err)
	}

	bilanPCAP, errPCAP := ReadPCAPDNSMessages(session.PCAPPath(), nil)
	if errPCAP != nil {
		t.Fatalf("ReadPCAPDNSMessages : %v", errPCAP)
	}
	if bilanPCAP.TotalPackets != 2 || bilanPCAP.DecodedQueries != 1 || bilanPCAP.DecodedReplies != 1 || bilanPCAP.MalformedCount != 0 {
		t.Fatalf("PCAP corrompu ou désynchronisé après rejet 17 RR : %+v", bilanPCAP)
	}

	fichierJSONL, errOuverture := os.Open(session.JSONLPath())
	if errOuverture != nil {
		t.Fatalf("ouverture JSONL : %v", errOuverture)
	}
	defer fichierJSONL.Close()

	var lignes []RecordedEpisodeLine
	lecteurLignes := bufio.NewScanner(io.LimitReader(fichierJSONL, 1<<20))
	for lecteurLignes.Scan() {
		var entree RecordedEpisodeLine
		if errJSON := json.Unmarshal(lecteurLignes.Bytes(), &entree); errJSON != nil {
			t.Fatalf("décodage JSONL : %v", errJSON)
		}
		lignes = append(lignes, entree)
	}
	if errScan := lecteurLignes.Err(); errScan != nil {
		t.Fatalf("lecture JSONL : %v", errScan)
	}
	if len(lignes) != 2 {
		t.Fatalf("nombre de lignes JSONL = %d, attendu 2", len(lignes))
	}
	empreinteApres := sha256.Sum256(reponseValideApres)
	attenduSHA256 := hex.EncodeToString(empreinteApres[:])
	if lignes[0].FrameIndex != 0 || lignes[1].FrameIndex != 1 || !lignes[1].IsResponse || lignes[1].PacketSHA256 != attenduSHA256 {
		t.Fatalf("entrée JSONL post-rejet incohérente : %+v (attendu sha256=%s)", lignes[1], attenduSHA256)
	}
}

func TestRatiosPipeline_ZeroAllocCheminErreurEtNominal(t *testing.T) {
	pipe, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline : %v", err)
	}
	defer pipe.Close()

	var adrClient, adrServeur [16]byte
	adrClient[15] = 2
	adrServeur[15] = 1
	trame17RR := rat02aConstruireMessageAdditionalA(0x6101, true, "api.hazyhaar.fr", 17)
	trame16RR := rat02aConstruireMessageAdditionalA(0x6102, true, "api.hazyhaar.fr", 16)

	allocsErreur := testing.AllocsPerRun(500, func() {
		verdict, _, motif, errEval := pipe.EvaluateDNSMessageWithReason(trame17RR, 1_793_500_200_000_000_000, adrServeur, adrClient)
		if errEval == nil || verdict.Decision != DecisionEscalateSLM || motif != ReasonDNSParseError {
			t.Fatalf("contrat fail-closed rompu sous mesure d'allocations : verdict=%v motif=%q err=%v", verdict.Decision, motif, errEval)
		}
	})
	if allocsErreur != 0 {
		t.Errorf("EvaluateDNSMessageWithReason (ErrTooManyRRs) : %v allocs/op, attendu 0", allocsErreur)
	}

	allocsNominal := testing.AllocsPerRun(500, func() {
		_, _, _, errEval := pipe.EvaluateDNSMessageWithReason(trame16RR, 1_793_500_200_001_000_000, adrServeur, adrClient)
		if errEval != nil {
			t.Fatalf("erreur nominale inattendue : %v", errEval)
		}
	})
	if allocsNominal != 0 {
		t.Errorf("EvaluateDNSMessageWithReason (16 RR valide) : %v allocs/op, attendu 0", allocsNominal)
	}
}

func TestRatiosPipeline_SOANegativeWithAnswerPayload(t *testing.T) {
	cheminSoar := filepath.Join("testdata", "rat-20261101", "soar-signed-nxdomain-cache-auth.pcap")
	rapportSoar, err := EvaluateSOANegativePCAP(cheminSoar)
	if err != nil {
		t.Fatalf("EvaluateSOANegativePCAP(%s) : %v", cheminSoar, err)
	}
	if rapportSoar.Responses != 40 {
		t.Errorf("soar Responses = %d, attendu 40", rapportSoar.Responses)
	}
	if got := NegativeAnswerPayloadPackets(rapportSoar); got != 40 {
		t.Errorf("soar NegativeAnswerPayloadPackets = %d, attendu 40", got)
	}
	if rapportSoar.NegativeWithSOA != 0 {
		t.Errorf("soar NegativeWithSOA = %d, attendu 0", rapportSoar.NegativeWithSOA)
	}

	// Jumeau négatif 1 : capture réelle bénigne multi-types (200 réponses).
	cheminBenin := filepath.Join("testdata", "rat-20261101", "benign-rrtypes-clear.pcap")
	rapportBenin, err := EvaluateSOANegativePCAP(cheminBenin)
	if err != nil {
		t.Fatalf("EvaluateSOANegativePCAP(%s) : %v", cheminBenin, err)
	}
	if rapportBenin.Responses != 200 {
		t.Errorf("benign-rrtypes Responses = %d, attendu 200", rapportBenin.Responses)
	}
	if got := NegativeAnswerPayloadPackets(rapportBenin); got != 0 {
		t.Errorf("benign-rrtypes NegativeAnswerPayloadPackets = %d, attendu 0", got)
	}

	// Jumeau négatif 2 : NXDOMAIN conforme RFC 2308 / RFC 4035 avec CNAME + RRSIG + DNAME en Answer et SOA en Authority.
	requeteDNSSEC, reponseDNSSEC := rat02aConstruireNXDOMAINConformeDNSSEC()
	var controleMsg DNSMessage
	if errParse := ParseDNSMessage(reponseDNSSEC, &controleMsg); errParse != nil || controleMsg.AnswerCount != 3 || controleMsg.AuthorityCount != 1 {
		t.Fatalf("fixture NXDOMAIN RFC 2308/4035 invalide : err=%v answers=%d authorities=%d", errParse, controleMsg.AnswerCount, controleMsg.AuthorityCount)
	}

	adrClient := [4]byte{10, 55, 0, 2}
	adrResolveur := [4]byte{10, 55, 0, 1}
	trames := [][]byte{
		rat02aTrameIPv4BruteUDP(adrClient, adrResolveur, 51200, 53, requeteDNSSEC),
		rat02aTrameIPv4BruteUDP(adrResolveur, adrClient, 53, 51200, reponseDNSSEC),
	}
	horodatagesUs := []uint64{1_793_500_000_000_000, 1_793_500_000_015_000}
	cheminDNSSEC := filepath.Join(t.TempDir(), "nxdomain-cname-rrsig-dname.pcap")
	rat02aEcrirePCAPRawIP(t, cheminDNSSEC, trames, horodatagesUs)

	rapportDNSSEC, err := EvaluateSOANegativePCAP(cheminDNSSEC)
	if err != nil {
		t.Fatalf("EvaluateSOANegativePCAP(nxdomain RFC 2308/4035) : %v", err)
	}
	if rapportDNSSEC.Responses != 1 {
		t.Errorf("nxdomain RFC 2308/4035 Responses = %d, attendu 1", rapportDNSSEC.Responses)
	}
	if got := NegativeAnswerPayloadPackets(rapportDNSSEC); got != 0 {
		t.Errorf("nxdomain RFC 2308/4035 NegativeAnswerPayloadPackets = %d, attendu 0", got)
	}
	if rapportDNSSEC.NegativeWithSOA != 0 {
		t.Errorf("nxdomain RFC 2308/4035 NegativeWithSOA = %d, attendu 0 (ANCOUNT > 0)", rapportDNSSEC.NegativeWithSOA)
	}
}
