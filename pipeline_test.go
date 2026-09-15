package c2blue55

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These wire packets and policy entries are local fixtures, not captured attacks.
func TestPipeline_EndToEndEvaluation(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "c2_events.jsonl")

	p, err := NewPipeline(PipelineConfig{
		LogPath:            logPath,
		EntropyThresholdQ8: 1024, // 4.0 bits/byte
		BeaconJitterMax:    20,
		UniqueSubThreshold: 5,
	}, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	defer p.Close()

	// 1. Échelon 1 : Fast Pass sur éditeur certifié DNSAML (Sophos)
	// "cloudtelemetry.sophosxl.com"
	wireSophosHex := "4a1201000001000000000000" +
		"0e636c6f756474656c656d65747279" +
		"08736f70686f73786c" +
		"03636f6d00" +
		"00010001"
	wireSophos, _ := hex.DecodeString(wireSophosHex)

	res1, err := p.EvaluatePacket(wireSophos, 1700000000)
	if err != nil {
		t.Fatalf("EvaluatePacket Sophos: %v", err)
	}
	if res1.Decision != DecisionFastPass {
		t.Errorf("Sophos: Decision = %d, attendu DecisionFastPass (%d)", res1.Decision, DecisionFastPass)
	}
	if res1.MatchedCategory != RepClassAllowVendor {
		t.Errorf("Sophos: MatchedCategory = %d, attendu %d", res1.MatchedCategory, RepClassAllowVendor)
	}

	// 2. Échelon 1 : Fast Drop sur domaine C2 connu de la blocklist (dnscat2.net)
	// "c2.tunnel.dnscat2.net"
	wireC2Hex := "889901000001000000000000" +
		"026332" +
		"0674756e6e656c" +
		"07646e7363617432" +
		"036e657400" +
		"00010001"
	wireC2, _ := hex.DecodeString(wireC2Hex)

	res2, err := p.EvaluatePacket(wireC2, 1700000001)
	if err != nil {
		t.Fatalf("EvaluatePacket C2: %v", err)
	}
	if res2.Decision != DecisionFastDrop {
		t.Errorf("C2: Decision = %d, attendu DecisionFastDrop (%d)", res2.Decision, DecisionFastDrop)
	}

	// 3. Échelon 2 : Fast Pass sur clé DKIM légitime à haute entropie
	// "k1._domainkey.company.org"
	wireDKIMHex := "556601000001000000000000" +
		"026b31" +
		"0a5f646f6d61696e6b6579" +
		"07636f6d70616e79" +
		"036f726700" +
		"00100001"
	wireDKIM, _ := hex.DecodeString(wireDKIMHex)

	res3, err := p.EvaluatePacket(wireDKIM, 1700000002)
	if err != nil {
		t.Fatalf("EvaluatePacket DKIM: %v", err)
	}
	if res3.Decision != DecisionFastPass {
		t.Errorf("DKIM: Decision = %d, attendu DecisionFastPass", res3.Decision)
	}

	// 4. Échelon 5 : Escalade vers le SLM (Grey Zone) pour exfiltration suspecte à haute entropie
	// Domaine inconnu "exfil-node-99.org" avec charge Base64/Hex dense en sous-domaine
	// FQDN: "9f8a7b6c5d4e3f2a1b0c.exfil-node-99.org"
	wireExfilHex := "334401000001000000000000" +
		"143966386137623663356434653366326131623063" + // 20 octets hex pseudo-random
		"0d657866696c2d6e6f64652d3939" + // 13 "exfil-node-99"
		"036f726700" +
		"00010001"
	wireExfil, _ := hex.DecodeString(wireExfilHex)

	res4, err := p.EvaluatePacket(wireExfil, 1700000010)
	if err != nil {
		t.Fatalf("EvaluatePacket Exfil: %v", err)
	}
	if res4.Decision != DecisionEscalateSLM {
		t.Errorf("Exfil: Decision = %d, attendu DecisionEscalateSLM (%d)", res4.Decision, DecisionEscalateSLM)
	}
	if res4.Incident == nil {
		t.Fatalf("Exfil: incident transmis est nil")
	}

	// Vérification que le dossier médico-légal est bien arrivé dans la file d'arbitrage SLM
	select {
	case inc := <-p.SLMQueue():
		if inc.FQDN != "9f8a7b6c5d4e3f2a1b0c.exfil-node-99.org" {
			t.Errorf("FQDN dans la file SLM = %q", inc.FQDN)
		}
	default:
		t.Errorf("SLMQueue vide, incident non recu")
	}

	// 5. Test du Veto Déterministe Go contre l'hallucination du modèle
	// Local incident fixture: vendor reputation must not override suspicious metrics.
	sophosIncident := &SLMIncident{
		FQDN:         "cloudtelemetry.sophosxl.com",
		ParentDomain: "sophosxl.com",
		Subdomain:    "cloudtelemetry",
		QueryCount:   10,
		EntropyBits:  4.5,
	}

	verdict, conf, reason := p.ApplyDeterministicVeto(sophosIncident, "DNS_TUNNEL_CONFIRMED")
	if verdict != "DNS_TUNNEL_CONFIRMED" {
		t.Errorf("vendor policy must not override inspection: %q", verdict)
	}
	if conf != 0 {
		t.Errorf("deterministic rule invented statistical confidence: %.2f", conf)
	}
	if reason == "" {
		t.Errorf("Motif de veto vide")
	}
}

// TestPipeline_ZeroAllocation vérifie formellement 0 allocation sur le chemin chaud d'évaluation.
func TestPipeline_ZeroAllocation(t *testing.T) {
	p, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	defer p.Close()

	wireSophosHex := "4a1201000001000000000000" +
		"0e636c6f756474656c656d65747279" +
		"08736f70686f73786c" +
		"03636f6d00" +
		"00010001"
	wireSophos, _ := hex.DecodeString(wireSophosHex)

	allocs := testing.AllocsPerRun(1000, func() {
		_, _ = p.EvaluatePacket(wireSophos, 1700000000)
	})

	if allocs != 0 {
		t.Errorf("EvaluatePacket AllocsPerRun = %.2f, attendu 0.0 (0 B/op)", allocs)
	}
}

// TestPipeline_AuditLogWritten vérifie la persistance du journal d'audit append-only JSONL.
func TestPipeline_AuditLogWritten(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.jsonl")

	p, err := NewPipeline(PipelineConfig{LogPath: logPath}, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}

	p.logEvent("bad-c2.net", "TEST_ALERT", "REPUTATION_MATCH", 0.99)
	_ = p.Close()

	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Lecture du journal: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("Journal d'audit vide")
	}
}

// concreteArbitrator is a test double, not a model inference or accuracy oracle.
type concreteArbitrator struct {
	verdict string
}

func (c *concreteArbitrator) Arbitrate(ctx context.Context, incident *SLMIncident) (SLMArbitrationResponse, error) {
	return SLMArbitrationResponse{
		Verdict:    c.verdict,
		Confidence: 0.95,
		Thought:    "Analyse forensique SLM",
	}, nil
}

// TestPipeline_ArbitratorWorker teste la supervision asynchrone et le veto Go.
func TestPipeline_ArbitratorWorker(t *testing.T) {
	p, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Arbitre configuré pour halluciner un verdict agressif DNS_TUNNEL_CONFIRMED
	arb := &concreteArbitrator{verdict: "DNS_TUNNEL_CONFIRMED"}

	verdictReceived := make(chan string, 1)
	reasonReceived := make(chan string, 1)

	p.StartArbitratorWorker(ctx, arb, func(inc SLMIncident, finalVerdict string, conf float64, reason string) {
		verdictReceived <- finalVerdict
		reasonReceived <- reason
	})

	// Injection d'un incident sur éditeur Sophos dans la file
	p.slmQueue <- SLMIncident{
		FQDN:         "cloudtelemetry.sophosxl.com",
		ParentDomain: "sophosxl.com",
		Subdomain:    "cloudtelemetry",
		QueryCount:   10,
	}

	select {
	case verdict := <-verdictReceived:
		if verdict != "DNS_TUNNEL_CONFIRMED" {
			t.Errorf("vendor policy must not override inspection: %q", verdict)
		}
		reason := <-reasonReceived
		if reason == "" {
			t.Errorf("Raison du veto vide")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Timeout en attente du verdict du worker SLM")
	}
}

// TestPipeline_ProtocolPrefixBoundary vérifie que seuls les labels réservés complets
// (_domainkey, _dmarc, _acme-challenge) sont reconnus, jamais un préfixe partiel.
func TestPipeline_ProtocolPrefixBoundary(t *testing.T) {
	cases := []struct {
		sub  string
		want bool
	}{
		{"_domainkey", true},
		{"google._domainkey", true},
		{"k1._domainkey", true},
		{"_domainkeyevil", false},
		{"_domainkeyevil.attacker-c2", false},
		{"evil_domainkey", false},
		{"_dmarc", true},
		{"sub._dmarc", true},
		{"_dmarc-evil", false},
		{"_dmarcx", false},
		{"_acme-challenge", true},
		{"sub._acme-challenge", true},
		{"_acme-challengeevil", false},
		{"cloudtelemetry", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isLegitimateProtocolPrefix(c.sub, 0); got != c.want {
			t.Errorf("isLegitimateProtocolPrefix(%q, 0) = %v, attendu %v", c.sub, got, c.want)
		}
	}
}

// TestPipeline_ProtocolPrefixBounds vérifie que la reconnaissance protocolaire est bornée
// à un sélecteur court et de faible entropie. Un préfixe réservé dépassant 45 octets ou
// porté par une entropie >= 4.0 bits/octet est refusé, indépendamment de la syntaxe.
func TestPipeline_ProtocolPrefixBounds(t *testing.T) {
	short := "k1._domainkey"
	oversized := "_domainkey." + strings.Repeat("a", 50)

	if !isLegitimateProtocolPrefix(short, 0) {
		t.Errorf("sélecteur court de faible entropie refusé à tort: %q", short)
	}
	if isLegitimateProtocolPrefix(oversized, 0) {
		t.Errorf("préfixe de %d octets (> %d) accepté à tort: %q", len(oversized), MaxProtocolPrefixLen, oversized)
	}
	if isLegitimateProtocolPrefix(short, MinTunnelEntropyQ8) {
		t.Errorf("sélecteur court à entropie >= 4.0 bits/octet accepté à tort: %q", short)
	}
	if !isLegitimateProtocolPrefix(short, MinTunnelEntropyQ8-1) {
		t.Errorf("sélecteur court juste sous le seuil d'entropie refusé à tort: %q", short)
	}
}

// TestPipeline_DomainKeyEvilNoFastPass est le test de non-régression de la faille d'évasion :
// un label partiel _domainkeyevil ne doit PAS bénéficier du FastPass protocolaire, tandis
// qu'un label complet _domainkey en TXT reste légitimement exempté.
func TestPipeline_DomainKeyEvilNoFastPass(t *testing.T) {
	p, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	defer p.Close()

	// Vecteur hostile : "_domainkeyevil.9f8a7b6c5d4e3f2a1b0c.exfil-node-99.org" en TXT.
	// Le sous-domaine commence par "_domainkeyevil" : avant correctif, le préfixe partiel
	// accordait un FastPass et court-circuitait l'entropie et le suivi temporel.
	evil := buildDNSQueryWire("_domainkeyevil.9f8a7b6c5d4e3f2a1b0c.exfil-node-99.org", TypeTXT)
	res, err := p.EvaluatePacket(evil, 1700000100)
	if err != nil {
		t.Fatalf("EvaluatePacket _domainkeyevil: %v", err)
	}
	if res.Decision == DecisionFastPass {
		t.Errorf("_domainkeyevil a obtenu un FastPass : évasion protocolaire non corrigée")
	}
	if res.Decision != DecisionEscalateSLM {
		t.Errorf("_domainkeyevil: Decision = %d, attendu EscalateSLM (%d)", res.Decision, DecisionEscalateSLM)
	}

	// Vecteur témoin légitime : label _domainkey complet en TXT.
	legit := buildDNSQueryWire("k1._domainkey.company.org", TypeTXT)
	resLegit, err := p.EvaluatePacket(legit, 1700000101)
	if err != nil {
		t.Fatalf("EvaluatePacket _domainkey légitime: %v", err)
	}
	if resLegit.Decision != DecisionFastPass {
		t.Errorf("_domainkey légitime: Decision = %d, attendu FastPass (%d)", resLegit.Decision, DecisionFastPass)
	}
}

// TestPipeline_QueryTypeGateProtocolPrefix vérifie que l'exemption protocolaire est
// strictement conditionnée au type TXT. Un label réservé complet (ici _domainkey) porté
// par des requêtes A ne bénéficie d'aucun FastPass : le suivi temporel s'active et la
// prolifération de sous-domaines finit par escalader vers le SLM.
func TestPipeline_QueryTypeGateProtocolPrefix(t *testing.T) {
	p, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	defer p.Close()

	var res EvaluationResult
	for i := 1; i <= 8; i++ {
		fqdn := "s" + strconv.Itoa(i) + "._domainkey.evil-dom.invalid"
		wire := buildDNSQueryWire(fqdn, TypeA)
		res, err = p.EvaluatePacket(wire, 1700000200)
		if err != nil {
			t.Fatalf("EvaluatePacket %s: %v", fqdn, err)
		}
	}
	if res.Decision != DecisionEscalateSLM {
		t.Errorf("label _domainkey en A: Decision = %d, attendu EscalateSLM (%d) (garde QType==TXT absente)", res.Decision, DecisionEscalateSLM)
	}
}

// TestPipeline_ProtocolPrefixUnknownParentNoFastPass est le test de non-régression de
// l'exemption protocolaire sur domaine parent inconnu. Un enregistrement TXT portant un
// label réservé (_domainkey) sous un parent non certifié ne doit pas court-circuiter la
// métrologie d'entropie et le suivi temporel : la prolifération de sous-domaines escalade.
func TestPipeline_ProtocolPrefixUnknownParentNoFastPass(t *testing.T) {
	p, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	defer p.Close()

	var res EvaluationResult
	for i := 1; i <= 8; i++ {
		fqdn := "k" + strconv.Itoa(i) + "._domainkey.unknown-corp.org"
		wire := buildDNSQueryWire(fqdn, TypeTXT)
		res, err = p.EvaluatePacket(wire, 1700000300)
		if err != nil {
			t.Fatalf("EvaluatePacket %s: %v", fqdn, err)
		}
	}
	if res.Decision != DecisionEscalateSLM {
		t.Errorf("parent inconnu: Decision = %d, attendu EscalateSLM (%d) (FastPass protocolaire non borné)", res.Decision, DecisionEscalateSLM)
	}
	if res.Incident == nil || res.Incident.SuspectedIndicator != "SUBDOMAIN_EXFIL_FLOOD" {
		t.Errorf("parent inconnu: incident inattendu: %+v", res.Incident)
	}
}

// TestPipeline_ProtocolPrefixCertifiedParentFastPass vérifie le témoin légitime : le
// label réservé porté par un domaine parent certifié Tranco conserve son FastPass.
func TestPipeline_ProtocolPrefixCertifiedParentFastPass(t *testing.T) {
	p, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	defer p.Close()

	wire := buildDNSQueryWire("k1._domainkey.google.com", TypeTXT)
	res, err := p.EvaluatePacket(wire, 1700000310)
	if err != nil {
		t.Fatalf("EvaluatePacket: %v", err)
	}
	if res.Decision != DecisionFastPass {
		t.Errorf("parent certifié: Decision = %d, attendu FastPass (%d)", res.Decision, DecisionFastPass)
	}
}

// TestPipeline_VetoCryptoKeyBounded éprouve le bornage du veto protocolaire. Un parent
// inconnu à fort volume et à sous-domaines multiples ne peut être blanchi en BENIGN_CRYPTO_KEY,
// tandis qu'un volume faible et une faible cardinalité conservent l'exemption légitime.
func TestPipeline_VetoCryptoKeyBounded(t *testing.T) {
	p, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	defer p.Close()

	// 1. Parent inconnu, volume élevé, prolifération : le veto protocolaire est refusé.
	hostile := &SLMIncident{
		FQDN:             "k1._domainkey.evil-exfil.net",
		ParentDomain:     "evil-exfil.net",
		Subdomain:        "k1._domainkey",
		QType:            TypeTXT,
		QueryCount:       50,
		UniqueSubdomains: 12,
		EntropyBits:      4.8,
	}
	verdict, _, _ := p.ApplyDeterministicVeto(hostile, "DNS_TUNNEL_CONFIRMED")
	if verdict == "BENIGN_CRYPTO_KEY" {
		t.Errorf("parent inconnu à fort volume blanchi à tort en BENIGN_CRYPTO_KEY")
	}
	if verdict != "DNS_TUNNEL_CONFIRMED" {
		t.Errorf("verdict = %q, attendu DNS_TUNNEL_CONFIRMED", verdict)
	}

	// 2. Parent inconnu, volume faible sans prolifération : exemption légitime maintenue.
	benignEdge := &SLMIncident{
		FQDN:             "k1._domainkey.unknown-corp.org",
		ParentDomain:     "unknown-corp.org",
		Subdomain:        "k1._domainkey",
		QType:            TypeTXT,
		QueryCount:       2,
		UniqueSubdomains: 1,
		EntropyBits:      3.0,
	}
	if v, _, _ := p.ApplyDeterministicVeto(benignEdge, "INSUFFICIENT_EVIDENCE"); v != "BENIGN_CRYPTO_KEY" {
		t.Errorf("volume faible: verdict = %q, attendu BENIGN_CRYPTO_KEY", v)
	}

	// 3. An allowed parent cannot exempt high volume or proliferation.
	certified := &SLMIncident{
		FQDN:             "k1._domainkey.google.com",
		ParentDomain:     "google.com",
		Subdomain:        "k1._domainkey",
		QType:            TypeTXT,
		QueryCount:       50,
		UniqueSubdomains: 12,
		EntropyBits:      3.5,
	}
	if v, _, _ := p.ApplyDeterministicVeto(certified, "DNS_TUNNEL_CONFIRMED"); v == "BENIGN_CRYPTO_KEY" {
		t.Errorf("high volume exempted by parent reputation: %q", v)
	}

	// 4. Parent certifié mais sélecteur à entropie >= 4.0 bits/octet : le préfixe
	// protocolaire ne blanchit plus, la charge utile escalade vers le tunnel confirmé.
	certifiedHighEntropy := &SLMIncident{
		FQDN:             "9f8a7b6c5d4e3f2a1b0c._domainkey.google.com",
		ParentDomain:     "google.com",
		Subdomain:        "9f8a7b6c5d4e3f2a1b0c._domainkey",
		QType:            TypeTXT,
		QueryCount:       50,
		UniqueSubdomains: 12,
		EntropyBits:      4.48,
	}
	if v, _, _ := p.ApplyDeterministicVeto(certifiedHighEntropy, "DNS_TUNNEL_CONFIRMED"); v == "BENIGN_CRYPTO_KEY" {
		t.Errorf("parent certifié à haute entropie blanchi à tort en BENIGN_CRYPTO_KEY")
	}

	// 5. Parent certifié mais sélecteur débordant (> 45 octets) : même refus d'exemption.
	certifiedOversized := &SLMIncident{
		FQDN:             strings.Repeat("a", 50) + "._domainkey.google.com",
		ParentDomain:     "google.com",
		Subdomain:        strings.Repeat("a", 50) + "._domainkey",
		QType:            TypeTXT,
		QueryCount:       50,
		UniqueSubdomains: 12,
		EntropyBits:      2.5,
	}
	if v, _, _ := p.ApplyDeterministicVeto(certifiedOversized, "DNS_TUNNEL_CONFIRMED"); v == "BENIGN_CRYPTO_KEY" {
		t.Errorf("parent certifié à préfixe débordant blanchi à tort en BENIGN_CRYPTO_KEY")
	}
}

// TestPipeline_DeepMultilabelEscalation vérifie la détection d'évasion par dictionnaire :
// un FQDN à profondeur multi-labels (>= 5 labels) sous un parent inconnu escalade en
// Grey Zone sous l'indicateur DEEP_MULTILABEL_SUBDOMAIN, même à faible entropie.
func TestPipeline_DeepMultilabelEscalation(t *testing.T) {
	p, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	defer p.Close()

	wire := buildDNSQueryWire("a.b.c.d.e.org", TypeA)
	res, err := p.EvaluatePacket(wire, 1700000400)
	if err != nil {
		t.Fatalf("EvaluatePacket: %v", err)
	}
	if res.Decision != DecisionEscalateSLM {
		t.Fatalf("profondeur multi-labels: Decision = %d, attendu EscalateSLM (%d)", res.Decision, DecisionEscalateSLM)
	}
	if res.Incident == nil || res.Incident.SuspectedIndicator != "DEEP_MULTILABEL_SUBDOMAIN" {
		t.Errorf("indicateur = %+v, attendu DEEP_MULTILABEL_SUBDOMAIN", res.Incident)
	}
}

// newPipelineWithExactCertifiedParent construit un pipeline dont la table de réputation
// certifie bénin "trusted-org.test" en correspondance EXACTE seulement. Ce montage isole
// l'exemption protocolaire : le FQDN sous ce parent ne bénéficie pas du FastPass de
// réputation par sous-arbre, seule la garde protocolaire bornée peut le blanchir.
func newPipelineWithExactCertifiedParent(t *testing.T) *Pipeline {
	t.Helper()
	snap, err := CompileReputationSnapshot([]BuildEntry{
		{Domain: "trusted-org.test", Classification: RepClassAllowTranco, MatchKind: MatchExact},
	})
	if err != nil {
		t.Fatalf("CompileReputationSnapshot: %v", err)
	}
	tbl, err := NewReputationTable(snap)
	if err != nil {
		t.Fatalf("NewReputationTable: %v", err)
	}
	p, err := NewPipeline(PipelineConfig{}, tbl)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	return p
}

// TestPipeline_ProtocolPrefixOversizedCertifiedParent est le test de non-régression de
// l'évasion par injection volumineuse ou à haute entropie sous un préfixe protocolaire,
// même sur un domaine parent certifié. Un sélecteur _domainkey débordant (> 45 octets)
// ou à entropie >= 4.0 bits/octet ne doit bénéficier NI du FastPass NI du veto
// BENIGN_CRYPTO_KEY : il escalade vers le SLM. Le témoin court conserve son FastPass.
func TestPipeline_ProtocolPrefixOversizedCertifiedParent(t *testing.T) {
	// 1. Témoin légitime : sélecteur court et de faible entropie sous parent certifié.
	p := newPipelineWithExactCertifiedParent(t)
	defer p.Close()

	legit := buildDNSQueryWire("k1._domainkey.trusted-org.test", TypeTXT)
	resLegit, err := p.EvaluatePacket(legit, 1700000500)
	if err != nil {
		t.Fatalf("EvaluatePacket légitime: %v", err)
	}
	if resLegit.Decision != DecisionFastPass {
		t.Errorf("sélecteur court: Decision = %d, attendu FastPass (%d)", resLegit.Decision, DecisionFastPass)
	}

	// 2. Préfixe protocolaire débordant (> 45 octets) sous le même parent certifié.
	pOver := newPipelineWithExactCertifiedParent(t)
	defer pOver.Close()

	oversizedSub := strings.Repeat("a", 50) + "._domainkey"
	oversized := buildDNSQueryWire(oversizedSub+".trusted-org.test", TypeTXT)
	resOver, err := pOver.EvaluatePacket(oversized, 1700000510)
	if err != nil {
		t.Fatalf("EvaluatePacket débordant: %v", err)
	}
	if resOver.Decision == DecisionFastPass {
		t.Errorf("préfixe débordant: FastPass accordé à tort (évasion non corrigée)")
	}
	if resOver.Decision != DecisionEscalateSLM {
		t.Errorf("préfixe débordant: Decision = %d, attendu EscalateSLM (%d)", resOver.Decision, DecisionEscalateSLM)
	}
	if resOver.Incident == nil || resOver.Incident.SuspectedIndicator != "DNS_TUNNEL_RECORD_TYPE" {
		t.Errorf("préfixe débordant: indicateur = %+v, attendu DNS_TUNNEL_RECORD_TYPE", resOver.Incident)
	}
	// Le veto déterministe ne doit pas blanchir ce même incident.
	if v, _, _ := pOver.ApplyDeterministicVeto(resOver.Incident, "DNS_TUNNEL_CONFIRMED"); v == "BENIGN_CRYPTO_KEY" {
		t.Errorf("préfixe débordant blanchi à tort en BENIGN_CRYPTO_KEY")
	}

	// 3. Préfixe protocolaire présent mais charge à entropie >= 4.0 bits/octet,
	// sous parent certifié, sélecteur court (<= 45 octets).
	pEnt := newPipelineWithExactCertifiedParent(t)
	defer pEnt.Close()

	entropySub := "9f8a7b6c5d4e3f2a1b0c._domainkey"
	entropyWire := buildDNSQueryWire(entropySub+".trusted-org.test", TypeTXT)
	resEnt, err := pEnt.EvaluatePacket(entropyWire, 1700000520)
	if err != nil {
		t.Fatalf("EvaluatePacket haute entropie: %v", err)
	}
	if resEnt.Decision == DecisionFastPass {
		t.Errorf("préfixe à haute entropie: FastPass accordé à tort")
	}
	if resEnt.Decision != DecisionEscalateSLM {
		t.Errorf("préfixe à haute entropie: Decision = %d, attendu EscalateSLM (%d)", resEnt.Decision, DecisionEscalateSLM)
	}
	if resEnt.Incident == nil || resEnt.Incident.SuspectedIndicator != "HEX_BASE64_PAYLOAD_DENSE" {
		t.Errorf("préfixe à haute entropie: indicateur = %+v, attendu HEX_BASE64_PAYLOAD_DENSE", resEnt.Incident)
	}
	if resEnt.EntropyQ8 < MinTunnelEntropyQ8 {
		t.Fatalf("pré-condition de test non satisfaite: EntropyQ8 = %d, attendu >= %d", resEnt.EntropyQ8, MinTunnelEntropyQ8)
	}
	if v, _, _ := pEnt.ApplyDeterministicVeto(resEnt.Incident, "DNS_TUNNEL_CONFIRMED"); v == "BENIGN_CRYPTO_KEY" {
		t.Errorf("préfixe à haute entropie blanchi à tort en BENIGN_CRYPTO_KEY")
	}
}

// TestPipeline_ConsonantDroughtDetection éprouve D01 : un sous-domaine purement
// consonantique (au moins 15 lettres, moins de 10% de voyelles) escalade en Grey Zone
// sous l'indicateur CONSONANT_DROUGHT_PAYLOAD, sans dépendre du seuil d'entropie Shannon.
// Un domaine anglais normal reste en FastPass.
func TestPipeline_ConsonantDroughtDetection(t *testing.T) {
	p, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	defer p.Close()

	// Vecteur hostile : 18 consonnes consécutives, aucune voyelle.
	drought := buildDNSQueryWire("bcdfghjklmnpqrstvw.unknown-corp.invalid", TypeA)
	res, err := p.EvaluatePacket(drought, 1700000600)
	if err != nil {
		t.Fatalf("EvaluatePacket sécheresse: %v", err)
	}
	if res.Decision != DecisionEscalateSLM {
		t.Fatalf("sécheresse de voyelles: Decision = %d, attendu EscalateSLM (%d)", res.Decision, DecisionEscalateSLM)
	}
	if res.Incident == nil || res.Incident.SuspectedIndicator != "CONSONANT_DROUGHT_PAYLOAD" {
		t.Errorf("sécheresse de voyelles: indicateur = %+v, attendu CONSONANT_DROUGHT_PAYLOAD", res.Incident)
	}

	// Témoin nominal : domaine anglais normal, largement pourvu en voyelles.
	normal := buildDNSQueryWire("telemetry-service-update.unknown-corp.invalid", TypeA)
	resNormal, err := p.EvaluatePacket(normal, 1700000601)
	if err != nil {
		t.Fatalf("EvaluatePacket témoin: %v", err)
	}
	if resNormal.Decision != DecisionFastPass {
		t.Errorf("témoin anglais: Decision = %d, attendu FastPass (%d)", resNormal.Decision, DecisionFastPass)
	}
}

// TestPipeline_ExoticTypesDetection éprouve D02 : les types DNS exotiques volumineux
// (TypeNULL >= 25 octets, TypeCNAME >= 45 octets) escaladent avec les indicateurs
// respectifs, indépendamment de l'entropie mesurée.
func TestPipeline_ExoticTypesDetection(t *testing.T) {
	p, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	defer p.Close()

	// TypeNULL : nom total >= 25 octets sans atteindre le seuil tunnel classique (40).
	nullWire := buildDNSQueryWire("0123456789abcdef0123.tunnel.invalid", TypeNULL)
	resNull, err := p.EvaluatePacket(nullWire, 1700000700)
	if err != nil {
		t.Fatalf("EvaluatePacket TypeNULL: %v", err)
	}
	if resNull.Decision != DecisionEscalateSLM {
		t.Fatalf("TypeNULL: Decision = %d, attendu EscalateSLM (%d)", resNull.Decision, DecisionEscalateSLM)
	}
	if resNull.Incident == nil || resNull.Incident.SuspectedIndicator != "DNS_TUNNEL_RECORD_TYPE" {
		t.Errorf("TypeNULL: indicateur = %+v, attendu DNS_TUNNEL_RECORD_TYPE", resNull.Incident)
	}

	// TypeCNAME : nom total >= 45 octets.
	cnameWire := buildDNSQueryWire(strings.Repeat("ab", 20)+".tunnel.invalid", TypeCNAME)
	resCNAME, err := p.EvaluatePacket(cnameWire, 1700000701)
	if err != nil {
		t.Fatalf("EvaluatePacket TypeCNAME: %v", err)
	}
	if resCNAME.Decision != DecisionEscalateSLM {
		t.Fatalf("TypeCNAME: Decision = %d, attendu EscalateSLM (%d)", resCNAME.Decision, DecisionEscalateSLM)
	}
	if resCNAME.Incident == nil || resCNAME.Incident.SuspectedIndicator != "CNAME_QUESTION_LONG" {
		t.Errorf("TypeCNAME: indicateur = %+v, attendu CNAME_QUESTION_LONG", resCNAME.Incident)
	}
}

// TestPipeline_VetoEnrichesIncidentHITL éprouve D03 : le veto déterministe enrichit
// le dossier d'incident de la fiche médico-légale HITL (résumé et action recommandée)
// calibrée sur le verdict final.
func TestPipeline_VetoEnrichesIncidentHITL(t *testing.T) {
	p, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	defer p.Close()

	hostile := &SLMIncident{
		FQDN:               "c2.01636c69656e742d696e666f.c2.evil-exfil.net",
		ParentDomain:       "evil-exfil.net",
		Subdomain:          "c2.01636c69656e742d696e666f.c2",
		QType:              TypeTXT,
		EntropyBits:        4.8,
		UniqueSubdomains:   8,
		QueryCount:         15,
		SuspectedIndicator: "HEX_BASE64_PAYLOAD_DENSE",
	}
	verdict, _, _ := p.ApplyDeterministicVeto(hostile, "DNS_TUNNEL_CONFIRMED")
	if verdict != "DNS_TUNNEL_CONFIRMED" {
		t.Fatalf("verdict = %q, attendu DNS_TUNNEL_CONFIRMED", verdict)
	}
	if hostile.RecommendedAction != "BLOCK_IMMEDIATE" {
		t.Errorf("action = %q, attendu BLOCK_IMMEDIATE", hostile.RecommendedAction)
	}
	if hostile.HumanSummary == "" || !strings.Contains(hostile.HumanSummary, hostile.FQDN) {
		t.Errorf("résumé HITL incomplet: %q", hostile.HumanSummary)
	}
	if !strings.Contains(hostile.HumanSummary, hostile.SuspectedIndicator) {
		t.Errorf("résumé HITL sans indicateur suspect: %q", hostile.HumanSummary)
	}

	benign := &SLMIncident{
		FQDN:               "cloudtelemetry.sophosxl.com",
		ParentDomain:       "sophosxl.com",
		Subdomain:          "cloudtelemetry",
		QueryCount:         10,
		EntropyBits:        4.5,
		SuspectedIndicator: "HIGH_ENTROPY",
	}
	if v, _, _ := p.ApplyDeterministicVeto(benign, "DNS_TUNNEL_CONFIRMED"); v != "DNS_TUNNEL_CONFIRMED" {
		t.Fatalf("vendor policy overrides model proposal: %q", v)
	}
	if benign.RecommendedAction != "BLOCK_IMMEDIATE" {
		t.Errorf("action = %q, attendu BLOCK_IMMEDIATE", benign.RecommendedAction)
	}

	weak := &SLMIncident{
		FQDN:               "a.example.invalid",
		ParentDomain:       "example.invalid",
		Subdomain:          "a",
		QueryCount:         1,
		EntropyBits:        2.0,
		SuspectedIndicator: "HIGH_ENTROPY",
	}
	if v, _, _ := p.ApplyDeterministicVeto(weak, "DNS_TUNNEL_CONFIRMED"); v != "INSUFFICIENT_EVIDENCE" {
		t.Fatalf("veto = %q, attendu INSUFFICIENT_EVIDENCE", v)
	}
	if weak.RecommendedAction != "MONITOR_ONLY" {
		t.Errorf("action = %q, attendu MONITOR_ONLY", weak.RecommendedAction)
	}
}
