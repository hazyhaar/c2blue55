// Package engine — dns_agent_test.go
// Tests d'acceptation de l'agent DNS (#24) :
//   - TestForgeDNSFloppies_NoCorpusDomainLeak (EXG-DNS-04) ;
//   - TestDNSAgentCascade_DualFloppyRouting (EXG-DNS-05, SH-DNS-04, 0 B/op) ;
//   - TestDNSAgent_ColdFamilyGeneralization (EXG-DNS-06) ;
//   - TestRedhostPatternDiscoveryAndCompile (EXG-DNS-07) ;
//   - TestDNSAgent_HostileRejections (EXG-DNS-08, SH-DNS-03).
package engine

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// buildTestDecisionHead construit une tête de décision INT8 à deux classes
// orientée empiriquement entre un vecteur bénin et un vecteur hostile.
func buildTestDecisionHead(benign, hostile [EmbeddingDim]float32) []DecisionClass {
	head := make([]DecisionClass, 2)
	for d := range EmbeddingDim {
		diff := (benign[d] - hostile[d]) * 127.0
		if diff > 127 {
			diff = 127
		} else if diff < -127 {
			diff = -127
		}
		head[0].Weights[d] = int8(diff)
		head[1].Weights[d] = -int8(diff)
	}
	head[0].QHat = 0.01
	head[1].QHat = 0.01
	return head
}

// TestForgeDNSFloppies_NoCorpusDomainLeak vérifie EXG-DNS-04 :
// compilation sur données réelles des deux disquettes scellées HMAC-SHA256
// floppy_dns_tunnel.c2book et floppy_dns_dga.c2book, sans aucun nom de domaine
// du corpus en mot-clé L0.
func TestForgeDNSFloppies_NoCorpusDomainLeak(t *testing.T) {
	dataDir := testWittgensteinDataDir(t)
	outDir := t.TempDir()
	hmacKey := WittgensteinFloppyKey(FloppyFamilyDNSC2)

	if err := BuildDNSFloppiesColdSplit(dataDir, outDir, hmacKey); err != nil {
		t.Fatalf("BuildDNSFloppiesColdSplit a échoué: %v", err)
	}

	tunnelPath := filepath.Join(outDir, "floppy_dns_tunnel.c2book")
	dgaPath := filepath.Join(outDir, "floppy_dns_dga.c2book")

	tunnelDisk, err := LoadFloppyMmap(tunnelPath, hmacKey)
	if err != nil {
		t.Fatalf("LoadFloppyMmap(floppy_dns_tunnel.c2book): %v", err)
	}
	t.Cleanup(func() { _ = tunnelDisk.Close() })

	dgaDisk, err := LoadFloppyMmap(dgaPath, hmacKey)
	if err != nil {
		t.Fatalf("LoadFloppyMmap(floppy_dns_dga.c2book): %v", err)
	}
	t.Cleanup(func() { _ = dgaDisk.Close() })

	if tunnelDisk.Header.FamilyID != FloppyFamilyDNSTunnel {
		t.Errorf("tunnelDisk FamilyID = %d, attendu %d", tunnelDisk.Header.FamilyID, FloppyFamilyDNSTunnel)
	}
	if dgaDisk.Header.FamilyID != FloppyFamilyDNSDGA {
		t.Errorf("dgaDisk FamilyID = %d, attendu %d", dgaDisk.Header.FamilyID, FloppyFamilyDNSDGA)
	}
	if tunnelDisk.Header.Flags&FloppyFlagSealed == 0 || dgaDisk.Header.Flags&FloppyFlagSealed == 0 {
		t.Errorf("les deux disquettes doivent porter FloppyFlagSealed")
	}
	if tunnelDisk.Header.EntryCount == 0 || dgaDisk.Header.EntryCount == 0 {
		t.Errorf("EntryCount vide: tunnel=%d dga=%d", tunnelDisk.Header.EntryCount, dgaDisk.Header.EntryCount)
	}
	if len(tunnelDisk.Head) < 2 || len(dgaDisk.Head) < 2 {
		t.Errorf("DecisionHead incomplète: tunnel=%d dga=%d", len(tunnelDisk.Head), len(dgaDisk.Head))
	}
	if tunnelDisk.Probe() == nil || dgaDisk.Probe() == nil {
		t.Errorf("sonde conforme L1a absente: tunnel=%v dga=%v", tunnelDisk.Probe() != nil, dgaDisk.Probe() != nil)
	}

	// Aucun nom de domaine du corpus d'entraînement ou d'évaluation ne peut
	// figurer en mot-clé L0.
	bannedCorpusDomains := []string{
		"hidemyself", "tuns.org", "example.org", "fedoraproject", "datacenter.by",
	}
	for _, kw := range append(append([]string{}, tunnelDisk.Keywords...), dgaDisk.Keywords...) {
		lower := strings.ToLower(kw)
		for _, banned := range bannedCorpusDomains {
			if strings.Contains(lower, banned) {
				t.Errorf("fuite lexicale de domaine du corpus dans les mots-clés L0: %q contient %q", kw, banned)
			}
		}
	}

	// Jumeau négatif : refus avec mauvaise clé HMAC
	if bad, err := LoadFloppyMmap(tunnelPath, []byte("cle-hmac-invalide")); err == nil {
		_ = bad.Close()
		t.Errorf("LoadFloppyMmap(tunnelPath) a accepté une clé HMAC erronée")
	} else if !errors.Is(err, ErrFloppySeal) {
		t.Errorf("LoadFloppyMmap(tunnelPath) mauvaise clé: attendu ErrFloppySeal, obtenu %v", err)
	}
}

// TestDNSAgentCascade_DualFloppyRouting vérifie EXG-DNS-05 et SH-DNS-04 :
// aiguillage sans allocation (0 B/op) de Subdomain vers floppy_dns_tunnel.c2book
// dès que len(Subdomain) > 0, évaluation de SLD contre floppy_dns_dga.c2book
// y compris sur domaine apex sans neutralisation par isApexDomain (SH-DNS-04),
// et monotonie défensive L0 -> L1a -> L1b.
func TestDNSAgentCascade_DualFloppyRouting(t *testing.T) {
	tmpDir := t.TempDir()
	hmacKey := []byte("test-hmac-key-dual-routing")

	var vecTunnelHostile, vecTunnelBenign [EmbeddingDim]float32
	if !ExtractDNSTunnel512([]byte("4a6f686e446f653132333435367890ab.0.b.1"), 16, 6, 32, 64, vecTunnelHostile[:]) {
		t.Errorf("ExtractDNSTunnel512(hostile) a échoué")
	}
	if !ExtractDNSTunnel512([]byte("www"), 1, 3, 3, 1, vecTunnelBenign[:]) {
		t.Errorf("ExtractDNSTunnel512(benign) a échoué")
	}
	var codeTunnel [codebookWords]uint64
	QuantizeFHT512(vecTunnelHostile[:], &codeTunnel)
	tunnelEntries := []CodebookEntry{{Bitcode: codeTunnel, ThreatID: 2101, Subsystem: 3, Severity: SeverityHigh}}
	tunnelHead := buildTestDecisionHead(vecTunnelBenign, vecTunnelHostile)
	tunnelProtos := []FloppyPrototype{
		{Class: 0, Vector: vecTunnelBenign},
		{Class: 1, Vector: vecTunnelHostile},
	}
	tunnelPath := filepath.Join(tmpDir, "floppy_dns_tunnel.c2book")
	if err := SaveFloppyFile(tunnelPath, FloppyFamilyDNSTunnel, nil, tunnelEntries, tunnelHead, tunnelProtos, 12, hmacKey); err != nil {
		t.Fatalf("SaveFloppyFile(tunnel): %v", err)
	}
	tunnelDisk, err := LoadFloppyMmap(tunnelPath, hmacKey)
	if err != nil {
		t.Fatalf("LoadFloppyMmap(tunnel): %v", err)
	}
	t.Cleanup(func() { _ = tunnelDisk.Close() })

	var vecDGAHostile, vecDGABenign [EmbeddingDim]float32
	if !ExtractDNSDGA512([]byte("qx7v9k2m4p8w1z9x8c"), []byte("com"), vecDGAHostile[:]) {
		t.Errorf("ExtractDNSDGA512(hostile) a échoué")
	}
	if !ExtractDNSDGA512([]byte("forbesmiddleeast"), []byte("com"), vecDGABenign[:]) {
		t.Errorf("ExtractDNSDGA512(benign) a échoué")
	}
	var codeDGA [codebookWords]uint64
	QuantizeFHT512(vecDGAHostile[:], &codeDGA)
	dgaEntries := []CodebookEntry{{Bitcode: codeDGA, ThreatID: 4101, Subsystem: 3, Severity: SeverityHigh}}
	dgaHead := buildTestDecisionHead(vecDGABenign, vecDGAHostile)
	dgaProtos := []FloppyPrototype{
		{Class: 0, Vector: vecDGABenign},
		{Class: 1, Vector: vecDGAHostile},
	}
	dgaPath := filepath.Join(tmpDir, "floppy_dns_dga.c2book")
	if err := SaveFloppyFile(dgaPath, FloppyFamilyDNSDGA, nil, dgaEntries, dgaHead, dgaProtos, 12, hmacKey); err != nil {
		t.Fatalf("SaveFloppyFile(dga): %v", err)
	}
	dgaDisk, err := LoadFloppyMmap(dgaPath, hmacKey)
	if err != nil {
		t.Fatalf("LoadFloppyMmap(dga): %v", err)
	}
	t.Cleanup(func() { _ = dgaDisk.Close() })

	// 1. Veto réflexe L0 sur caractère d'encodage Base64
	encView := DNSQueryView{
		FQDN:            []byte("aaa+bbb==.0.b.1.forbesmiddleeast.com"),
		Subdomain:       []byte("aaa+bbb==.0.b.1"),
		SLD:             []byte("forbesmiddleeast"),
		TLD:             []byte("com"),
		QType:           16,
		LabelCount:      6,
		MaxLabelLen:     9,
		HasEncodingChar: true,
		SubCardinality:  8,
	}
	vEnc := EvaluateDNSView(encView, tunnelDisk, dgaDisk)
	if vEnc.Stage != StageL0 || vEnc.Action != VerdictBlock {
		t.Errorf("L0 Base64: Stage=%d Action=%d, attendu StageL0(0) VerdictBlock(2)", vEnc.Stage, vEnc.Action)
	}

	// 2. Tunnel sous un SLD bénin : routé vers tunnelDisk et bloqué sans être adouci par dgaDisk
	tunnelView := DNSQueryView{
		FQDN:           []byte("4a6f686e446f653132333435367890ab.0.b.1.forbesmiddleeast.com"),
		Subdomain:      []byte("4a6f686e446f653132333435367890ab.0.b.1"),
		SLD:            []byte("forbesmiddleeast"),
		TLD:            []byte("com"),
		QType:          16,
		LabelCount:     6,
		MaxLabelLen:    32,
		SubCardinality: 64,
	}
	vTunnel := EvaluateDNSView(tunnelView, tunnelDisk, dgaDisk)
	if vTunnel.Action != VerdictBlock {
		t.Errorf("Tunnel sous SLD bénin: Action=%d Stage=%d, attendu VerdictBlock(2)", vTunnel.Action, vTunnel.Stage)
	}

	// 3. SH-DNS-04 : Domaine DGA apex (sans sous-domaine) évalué par dgaDisk et bloqué
	apexDGAView := DNSQueryView{
		FQDN:        []byte("qx7v9k2m4p8w1z9x8c.com"),
		Subdomain:   nil,
		SLD:         []byte("qx7v9k2m4p8w1z9x8c"),
		TLD:         []byte("com"),
		QType:       1,
		LabelCount:  2,
		MaxLabelLen: 18,
	}
	vApexDGA := EvaluateDNSView(apexDGAView, tunnelDisk, dgaDisk)
	if vApexDGA.Action != VerdictBlock {
		t.Errorf("SH-DNS-04 Apex DGA: Action=%d Stage=%d, attendu VerdictBlock(2)", vApexDGA.Action, vApexDGA.Stage)
	}

	// 4. Domaine bénin (avec ou sans sous-domaine court) : VerdictPass
	benignView := DNSQueryView{
		FQDN:           []byte("www.forbesmiddleeast.com"),
		Subdomain:      []byte("www"),
		SLD:            []byte("forbesmiddleeast"),
		TLD:            []byte("com"),
		QType:          1,
		LabelCount:     3,
		MaxLabelLen:    16,
		SubCardinality: 1,
	}
	vBenign := EvaluateDNSView(benignView, tunnelDisk, dgaDisk)
	if vBenign.Action != VerdictPass {
		t.Errorf("Domaine bénin: Action=%d Stage=%d, attendu VerdictPass(1)", vBenign.Action, vBenign.Stage)
	}

	// 5. Preuve 0 B/op sur le chemin chaud d'aiguillage bi-tête
	allocs := testing.AllocsPerRun(1000, func() {
		_ = EvaluateDNSView(tunnelView, tunnelDisk, dgaDisk)
		_ = EvaluateDNSView(apexDGAView, tunnelDisk, dgaDisk)
		_ = EvaluateDNSView(benignView, tunnelDisk, dgaDisk)
	})
	if allocs != 0 {
		t.Errorf("EvaluateDNSView AllocsPerRun = %.2f, attendu 0 (0 B/op)", allocs)
	}
}

// TestDNSAgent_ColdFamilyGeneralization vérifie EXG-DNS-06 :
// généralisation hors-distribution (Cold-Family Split) sur la famille tuns.org
// exclue de l'entraînement (netrack_dns/test.csv) et sur les familles DGA tenues
// à l'écart (abusayed_dga_full.csv), avec comptes bruts, taux de la classe
// majoritaire et AUC >= 0.90.
func TestDNSAgent_ColdFamilyGeneralization(t *testing.T) {
	dataDir := testWittgensteinDataDir(t)
	floppyDir := t.TempDir()
	hmacKey := WittgensteinFloppyKey(FloppyFamilyDNSC2)

	if err := BuildDNSFloppiesColdSplit(dataDir, floppyDir, hmacKey); err != nil {
		t.Fatalf("BuildDNSFloppiesColdSplit: %v", err)
	}

	tunnelMetrics, dgaMetrics, err := EvaluateDNSColdSplit(dataDir, floppyDir, hmacKey)
	if err != nil {
		t.Fatalf("EvaluateDNSColdSplit: %v", err)
	}

	t.Logf("[Cold-Family Split Tunnel (tuns.org tenu à l'écart)] Total=%d MajorityClassRate=%.4f TP=%d FP=%d TN=%d FN=%d QuarHostile=%d QuarBenign=%d L0=%d L1a=%d L1b=%d AUC=%.4f",
		tunnelMetrics.Total, tunnelMetrics.MajorityClassRate,
		tunnelMetrics.TP, tunnelMetrics.FP, tunnelMetrics.TN, tunnelMetrics.FN,
		tunnelMetrics.QuarantineHostile, tunnelMetrics.QuarantineBenign,
		tunnelMetrics.L0Blocks, tunnelMetrics.L1aPasses, tunnelMetrics.L1bBlocks, tunnelMetrics.AUC)

	t.Logf("[Cold-Family Split DGA (familles tenues à l'écart)] Total=%d MajorityClassRate=%.4f TP=%d FP=%d TN=%d FN=%d QuarHostile=%d QuarBenign=%d L0=%d L1a=%d L1b=%d AUC=%.4f",
		dgaMetrics.Total, dgaMetrics.MajorityClassRate,
		dgaMetrics.TP, dgaMetrics.FP, dgaMetrics.TN, dgaMetrics.FN,
		dgaMetrics.QuarantineHostile, dgaMetrics.QuarantineBenign,
		dgaMetrics.L0Blocks, dgaMetrics.L1aPasses, dgaMetrics.L1bBlocks, dgaMetrics.AUC)

	for _, check := range []struct {
		name string
		m    ColdSplitMetrics
	}{
		{"tunnel_cold_tuns_org", tunnelMetrics},
		{"dga_cold_families", dgaMetrics},
	} {
		m := check.m
		if m.Total <= 0 {
			t.Errorf("[%s] Total = %d, attendu > 0", check.name, m.Total)
		}
		if m.MajorityClassRate <= 0 || m.MajorityClassRate >= 1.0 {
			t.Errorf("[%s] MajorityClassRate = %.4f, attendu dans ]0, 1[", check.name, m.MajorityClassRate)
		}
		if m.TP <= 0 {
			t.Errorf("[%s] TP = %d, attendu > 0", check.name, m.TP)
		}
		if m.TN <= 0 {
			t.Errorf("[%s] TN = %d, attendu > 0", check.name, m.TN)
		}
		sum := m.TP + m.FP + m.TN + m.FN + m.QuarantineHostile + m.QuarantineBenign
		if sum != m.Total {
			t.Errorf("[%s] somme des comptes bruts (%d) != Total (%d)", check.name, sum, m.Total)
		}
		if m.AUC < 0.90 {
			t.Errorf("[%s] AUC hors-distribution = %.4f, attendu >= 0.90", check.name, m.AUC)
		}
	}
}

// TestRedhostPatternDiscoveryAndCompile vérifie EXG-DNS-07 :
// découverte de nouveaux centroïdes hors-distribution sur un flux issu du faux
// serveur DNS redhost (mythos) et recompilation d'une disquette .c2book vérifiée.
func TestRedhostPatternDiscoveryAndCompile(t *testing.T) {
	tmpDir := t.TempDir()
	hmacKey := []byte("test-hmac-key-redhost")

	var vecBenignSub, vecBenignSLD [EmbeddingDim]float32
	_ = ExtractDNSTunnel512([]byte("www"), 1, 3, 3, 1, vecBenignSub[:])
	_ = ExtractDNSDGA512([]byte("forbesmiddleeast"), []byte("com"), vecBenignSLD[:])

	tunnelPath := filepath.Join(tmpDir, "tunnel_init.c2book")
	dgaPath := filepath.Join(tmpDir, "dga_init.c2book")
	if err := SaveFloppyFile(tunnelPath, FloppyFamilyDNSTunnel, nil, nil, buildTestDecisionHead(vecBenignSub, vecBenignSub), nil, 12, hmacKey); err != nil {
		t.Fatalf("SaveFloppyFile(tunnel_init): %v", err)
	}
	if err := SaveFloppyFile(dgaPath, FloppyFamilyDNSDGA, nil, nil, buildTestDecisionHead(vecBenignSLD, vecBenignSLD), nil, 12, hmacKey); err != nil {
		t.Fatalf("SaveFloppyFile(dga_init): %v", err)
	}

	tunnelDisk, err := LoadFloppyMmap(tunnelPath, hmacKey)
	if err != nil {
		t.Fatalf("LoadFloppyMmap(tunnel_init): %v", err)
	}
	t.Cleanup(func() { _ = tunnelDisk.Close() })

	dgaDisk, err := LoadFloppyMmap(dgaPath, hmacKey)
	if err != nil {
		t.Fatalf("LoadFloppyMmap(dga_init): %v", err)
	}
	t.Cleanup(func() { _ = dgaDisk.Close() })

	novelRedhostView := DNSQueryView{
		FQDN:           []byte("f8e7d6c5b4a39281706f5e4d3c2b1a09.seq1.redhost.lan"),
		Subdomain:      []byte("f8e7d6c5b4a39281706f5e4d3c2b1a09.seq1"),
		SLD:            []byte("redhost"),
		TLD:            []byte("lan"),
		QType:          10, // TypeNULL
		LabelCount:     4,
		MaxLabelLen:    32,
		SubCardinality: 96,
	}
	benignView := DNSQueryView{
		FQDN:           []byte("www.forbesmiddleeast.com"),
		Subdomain:      []byte("www"),
		SLD:            []byte("forbesmiddleeast"),
		TLD:            []byte("com"),
		QType:          1,
		LabelCount:     3,
		MaxLabelLen:    16,
		SubCardinality: 1,
	}

	candidates, err := DiscoverRedhostPatterns([]DNSQueryView{benignView, novelRedhostView}, tunnelDisk, dgaDisk)
	if err != nil {
		t.Fatalf("DiscoverRedhostPatterns a échoué: %v", err)
	}
	if len(candidates) == 0 {
		t.Fatalf("DiscoverRedhostPatterns n'a extrait aucun nouveau centroïde sur le flux redhost")
	}

	// Recompilation de la disquette tunnel avec les nouveaux centroïdes découverts
	updatedTunnelPath := filepath.Join(tmpDir, "tunnel_updated.c2book")
	if err := SaveFloppyFile(updatedTunnelPath, FloppyFamilyDNSTunnel, nil, candidates, tunnelDisk.Head, nil, 12, hmacKey); err != nil {
		t.Fatalf("SaveFloppyFile(tunnel_updated): %v", err)
	}
	updatedTunnelDisk, err := LoadFloppyMmap(updatedTunnelPath, hmacKey)
	if err != nil {
		t.Fatalf("LoadFloppyMmap(tunnel_updated): %v", err)
	}
	t.Cleanup(func() { _ = updatedTunnelDisk.Close() })

	vAfter := EvaluateDNSView(novelRedhostView, updatedTunnelDisk, dgaDisk)
	if vAfter.Action != VerdictBlock {
		t.Errorf("après recompilation redhost, novelRedhostView Action = %d, attendu VerdictBlock(2)", vAfter.Action)
	}

	// Jumeau négatif : un flux uniquement bénin ne génère aucun centroïde hostile
	benignCandidates, err := DiscoverRedhostPatterns([]DNSQueryView{benignView}, updatedTunnelDisk, dgaDisk)
	if err != nil {
		t.Errorf("DiscoverRedhostPatterns(bénin seul) erreur inattendue: %v", err)
	}
	if len(benignCandidates) != 0 {
		t.Errorf("DiscoverRedhostPatterns(bénin seul) a produit %d centroïdes, attendu 0", len(benignCandidates))
	}
}

// TestDNSAgent_HostileRejections vérifie EXG-DNS-08 et SH-DNS-03 :
// rejet immédiat avec ErrFloppySeal de toute altération de BlockRadius ou
// FamilyID dans l'en-tête binaire d'une disquette scellée, et rejet par
// ErrFloppyTruncated sans pré-allocation OOM d'un KwCount géant sur une
// disquette non scellée.
func TestDNSAgent_HostileRejections(t *testing.T) {
	tmpDir := t.TempDir()
	hmacKey := []byte("test-hmac-key-hostile-rejections")

	validPath := filepath.Join(tmpDir, "valid_sealed.c2book")
	entries := []CodebookEntry{{ThreatID: 2001, Subsystem: 3, Severity: SeverityHigh}}
	if err := SaveFloppyFile(validPath, FloppyFamilyDNSTunnel, []string{"tunnel-marker"}, entries, nil, nil, 10, hmacKey); err != nil {
		t.Fatalf("SaveFloppyFile(valid): %v", err)
	}

	raw, err := os.ReadFile(validPath)
	if err != nil {
		t.Fatalf("ReadFile(valid): %v", err)
	}

	// 1. SH-DNS-03a : Altération d'un octet de BlockRadius (offset 15 dans FloppyHeader)
	corruptRadius := append([]byte(nil), raw...)
	corruptRadius[15] ^= 0x01
	radiusPath := filepath.Join(tmpDir, "corrupt_radius.c2book")
	if err := os.WriteFile(radiusPath, corruptRadius, 0o600); err != nil {
		t.Fatalf("WriteFile(corrupt_radius): %v", err)
	}
	if d, err := LoadFloppyMmap(radiusPath, hmacKey); err == nil {
		_ = d.Close()
		t.Errorf("SH-DNS-03: LoadFloppyMmap a accepté une disquette avec BlockRadius altéré")
	} else if !errors.Is(err, ErrFloppySeal) {
		t.Errorf("SH-DNS-03 BlockRadius altéré: attendu ErrFloppySeal, obtenu %v", err)
	}

	// 2. SH-DNS-03b : Altération d'un octet de FamilyID (offset 10..12 dans FloppyHeader)
	corruptFamily := append([]byte(nil), raw...)
	corruptFamily[10] ^= 0x01
	familyPath := filepath.Join(tmpDir, "corrupt_family.c2book")
	if err := os.WriteFile(familyPath, corruptFamily, 0o600); err != nil {
		t.Fatalf("WriteFile(corrupt_family): %v", err)
	}
	if d, err := LoadFloppyMmap(familyPath, hmacKey); err == nil {
		_ = d.Close()
		t.Errorf("SH-DNS-03: LoadFloppyMmap a accepté une disquette avec FamilyID altéré")
	} else if !errors.Is(err, ErrFloppySeal) {
		t.Errorf("SH-DNS-03 FamilyID altéré: attendu ErrFloppySeal, obtenu %v", err)
	}

	// 3. EXG-DNS-08 : KwCount géant sur une disquette non scellée de 64 octets
	// doit être rejeté par ErrFloppyTruncated AVANT toute allocation de la tranche Keywords.
	unsealedPath := filepath.Join(tmpDir, "unsealed_huge_kw.c2book")
	if err := SaveFloppyFile(unsealedPath, FloppyFamilyDNSTunnel, nil, nil, nil, nil, 10, nil); err != nil {
		t.Fatalf("SaveFloppyFile(unsealed): %v", err)
	}
	unsealedRaw, err := os.ReadFile(unsealedPath)
	if err != nil {
		t.Fatalf("ReadFile(unsealed): %v", err)
	}
	// Injecter KwCount = 1 << 22 (4 194 304 chaînes annoncées sur un corps de 0 octet)
	// tout en conservant un CRC32C valide sur le corps vide.
	binary.LittleEndian.PutUint32(unsealedRaw[20:24], 1<<22)
	bodyCRC := crc32.Checksum(unsealedRaw[FloppyHeaderSize:], crc32.MakeTable(crc32.Castagnoli))
	binary.LittleEndian.PutUint32(unsealedRaw[24:28], bodyCRC)
	if err := os.WriteFile(unsealedPath, unsealedRaw, 0o600); err != nil {
		t.Fatalf("WriteFile(unsealed_huge_kw): %v", err)
	}

	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	d, err := LoadFloppyMmap(unsealedPath, nil)
	runtime.ReadMemStats(&m1)
	if d != nil {
		_ = d.Close()
	}
	if !errors.Is(err, ErrFloppyTruncated) {
		t.Errorf("KwCount géant sur corps vide: attendu ErrFloppyTruncated, obtenu %v", err)
	}
	deltaAlloc := m1.TotalAlloc - m0.TotalAlloc
	if deltaAlloc > 64*1024 {
		t.Errorf("KwCount géant sur fichier de 64 octets a alloué %d octets avant vérification de troncature (attendu <= 65536 octets sans pré-allocation OOM)", deltaAlloc)
	}
}
