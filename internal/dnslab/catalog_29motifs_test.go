package dnslab

import (
	"strings"
	"testing"
)

func TestA06A07_Catalog23RectificationsRFC(t *testing.T) {
	p16, ok := LookupPatternSpec23("P16")
	if !ok {
		t.Fatal("P16 introuvable")
	}
	if !strings.Contains(p16.PhysicalInvariant, "CNAME") && !strings.Contains(p16.OrthogonalGuard, "CNAME") {
		t.Errorf("P16 doit exclure explicitement une chaîne CNAME légitime: %+v", p16)
	}

	p17, ok := LookupPatternSpec23("P17")
	if !ok {
		t.Fatal("P17 introuvable")
	}
	if !strings.Contains(p17.PhysicalInvariant, "68") || strings.Contains(p17.PhysicalInvariant, "184") {
		t.Errorf("P17 doit spécifier >= 68 octets (4 en-tête + 64 P-256) et retirer 184: %q", p17.PhysicalInvariant)
	}

	p18, ok := LookupPatternSpec23("P18")
	if !ok {
		t.Fatal("P18 introuvable")
	}
	if !strings.Contains(strings.ToUpper(p18.PhysicalInvariant), "OPCODE == 4") || strings.Contains(p18.PhysicalInvariant, "QType == 64") {
		t.Errorf("P18 (A-06) doit cibler OPCODE == 4 (NOTIFY) et non QType == 64 (SVCB): %q", p18.PhysicalInvariant)
	}

	p19, ok := LookupPatternSpec23("P19")
	if !ok {
		t.Fatal("P19 introuvable")
	}
	for _, jeton := range []string{"24", "SIG(0)", "249", "TKEY", "250", "TSIG"} {
		if !strings.Contains(p19.PhysicalInvariant, jeton) {
			t.Errorf("P19 (A-07) incomplet, jeton %q absent de %q", jeton, p19.PhysicalInvariant)
		}
	}
}

func TestPatternCatalog29Motifs(t *testing.T) {
	catalogue := PatternCatalog29()
	if len(catalogue) != 29 {
		t.Fatalf("len(PatternCatalog29()) = %d, attendu 29 (M-01..M-04 + P1..P25)", len(catalogue))
	}

	attendusP20P25 := map[string]string{
		"P20": "GHSA_P20_QUIC_INITIAL_REASSEMBLY",
		"P21": "GHSA_P21_ENCRYPTED_DNS_TRANSPORT",
		"P22": "GHSA_P22_MIGRATION_BEACON_REASSEMBLY",
		"P23": "GHSA_P23_PADDED_DNS_TURN_EXCHANGE",
		"P24": "GHSA_P24_QUIC_DATAGRAM_COVER_CHANNEL",
		"P25": "GHSA_P25_RELAY_LOOPBACK_QUIC_CORRELATION",
	}

	identifiantsVus := make(map[string]bool, len(catalogue))
	raisonsVues := make(map[string]bool, len(catalogue))
	for _, motif := range catalogue {
		if motif.ID == "" || motif.Code != motif.ID {
			t.Errorf("motif ID/Code incohérent: %+v", motif)
		}
		if motif.ReasonCode == "" || motif.ExpectedReasonCode != motif.ReasonCode {
			t.Errorf("motif %s ReasonCode/ExpectedReasonCode incohérent: %+v", motif.ID, motif)
		}
		if motif.OrthogonalGuard == "" || motif.OrthogonalityGuard != motif.OrthogonalGuard {
			t.Errorf("motif %s OrthogonalGuard/OrthogonalityGuard incohérent: %+v", motif.ID, motif)
		}
		if motif.PhysicalInvariant == "" || motif.Name == "" {
			t.Errorf("motif %s incomplet: %+v", motif.ID, motif)
		}
		if identifiantsVus[motif.ID] {
			t.Errorf("ID dupliqué dans PatternCatalog29: %s", motif.ID)
		}
		identifiantsVus[motif.ID] = true
		if raisonsVues[motif.ReasonCode] {
			t.Errorf("ReasonCode dupliqué dans PatternCatalog29: %s", motif.ReasonCode)
		}
		raisonsVues[motif.ReasonCode] = true
	}

	for identifiant, raisonAttendue := range attendusP20P25 {
		motif, ok := LookupPatternSpec29(identifiant)
		if !ok {
			t.Fatalf("LookupPatternSpec29(%q) introuvable", identifiant)
		}
		if motif.ReasonCode != raisonAttendue || motif.Category != CategoryNewGHSA {
			t.Errorf("motif %s: ReasonCode=%q Category=%q, attendu %q / %q",
				identifiant, motif.ReasonCode, motif.Category, raisonAttendue, CategoryNewGHSA)
		}
	}

	// Jumeaux négatifs : identifiant hors catalogue ou vide.
	for _, inconnu := range []string{"", "P0", "P26", "M-05", "INCONNU"} {
		if motif, ok := LookupPatternSpec29(inconnu); ok || motif.ID != "" {
			t.Errorf("LookupPatternSpec29(%q) = (%+v, %t), attendu vide/false", inconnu, motif, ok)
		}
	}
}
