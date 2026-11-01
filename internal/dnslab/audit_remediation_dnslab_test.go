package dnslab

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAuditSOAIntegraliteApexMaximale(t *testing.T) {
	defer func() {
		if panique := recover(); panique != nil {
			t.Logf("panique interceptee dans BuildResponse: %v", panique)
			t.Fatalf("BuildResponse panique sur une apex DNS legale de 253 octets: %v", panique)
		}
	}()

	// Apex légale de 253 octets commençant par "nx-" (63 + 1 + 63 + 1 + 63 + 1 + 61 = 253) pour déclencher NegativeSOA.
	apexMax := "nx-" + strings.Repeat("a", 60) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(apexMax) != 253 {
		t.Fatalf("fixture apexMax invalide: len=%d", len(apexMax))
	}

	zone, err := NewZone(apexMax, [4]byte{192, 0, 2, 1}, "", 60)
	if err != nil {
		t.Fatalf("NewZone(253 octets): %v", err)
	}
	zone.Negative = NegativeSOA

	var question, reponse [512]byte
	longueurQuestion, err := BuildQuery(1, zone.Apex, 16, question[:])
	if err != nil {
		t.Fatalf("BuildQuery: %v", err)
	}
	_, decision, err := BuildResponse(question[:longueurQuestion], &zone, reponse[:])
	if err != nil {
		t.Fatalf("BuildResponse: %v", err)
	}
	if decision.Verdict != VerdictRefused {
		t.Fatalf("une reponse SOA superieure a 512 octets DNS UDP standard doit rendre VerdictRefused, obtenu=%v", decision.Verdict)
	}
}

func TestAuditJournalJSONOctetsArbitraires(t *testing.T) {
	ligne := JournalLine{
		Source:  "127.0.0.1",
		QName:   "a\x01b.example",
		Verdict: "nxdomain",
	}
	encodee, err := EncodeJournalLine(&ligne, make([]byte, 0, 256))
	if err != nil {
		t.Fatalf("EncodeJournalLine: %v", err)
	}
	if !json.Valid(encodee) {
		t.Fatalf("EncodeJournalLine produit un JSON invalide pour QName avec octet de controle: %q", encodee)
	}
}
