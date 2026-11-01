package engine

import (
	"encoding/binary"
	"strings"
	"testing"
)

func construireRequeteDNSFilaireA18(sousDomaine, apex string, qtype uint16) []byte {
	paquet := []byte{0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	complet := apex
	if sousDomaine != "" {
		complet = sousDomaine + "." + apex
	}
	for label := range strings.SplitSeq(complet, ".") {
		paquet = append(paquet, byte(len(label)))
		paquet = append(paquet, label...)
	}
	paquet = append(paquet, 0, 0, 0, 0, 1)
	binary.BigEndian.PutUint16(paquet[len(paquet)-4:], qtype)
	return paquet
}

func TestA18_IsRFCUnderscoreSubdomain_LabelAnchored(t *testing.T) {
	exemptes := []string{
		"_dmarc",
		"_DMARC",
		"_spf",
		"_acme-challenge",
		"_acme-challenge.www",
		"selector1._domainkey",
		"default._domainkey.mail",
		"_mta-sts",
		"_dane",
		"_sip._tls",
		"_xmpp._tcp",
		"_kerberos._udp",
		"_http._quic",
		"_ldap._tcp",
		"_ldap._tcp.dc",
	}
	for _, sousDomaine := range exemptes {
		if !IsRFCUnderscoreSubdomain(sousDomaine) {
			t.Errorf("IsRFCUnderscoreSubdomain(%q) = false, attendu true", sousDomaine)
		}
		if !isRFCUnderscoreBytes([]byte(sousDomaine)) {
			t.Errorf("isRFCUnderscoreBytes(%q) = false, attendu true", sousDomaine)
		}
	}

	charge48 := strings.Repeat("a", 48)
	charge33 := strings.Repeat("b", 33)
	rejetes := []string{
		"",
		".",
		"_dmarc.",
		"._dmarc",
		"_dmarc..mail",
		charge48 + "._dmarc",
		charge33 + "._domainkey",
		"_dmarc." + charge33,
		"foo_dmarc_bar",
		"prefix_domainkey",
		"exfil_acme-challenge_payload",
		"_dmarc_tunnel",
		"_spf2",
		"_evil",
		"_evil._dmarc",
		"_c2ctl._tcp.node00",
	}
	for _, sousDomaine := range rejetes {
		if IsRFCUnderscoreSubdomain(sousDomaine) {
			t.Errorf("IsRFCUnderscoreSubdomain(%q) = true, attendu false (contournement A-18)", sousDomaine)
		}
		if isRFCUnderscoreBytes([]byte(sousDomaine)) {
			t.Errorf("isRFCUnderscoreBytes(%q) = true, attendu false (contournement A-18)", sousDomaine)
		}
	}
}

func TestA18_StreamingDNS18_RejectsOversizedPayloadWithUnderscoreSuffix(t *testing.T) {
	var etat StreamingDNS18State
	adresseClient := [16]byte{10, 55, 0, 9}
	apex := []byte("example.org")

	// 1. Sous-domaine DKIM légitime : fast-pass BENIGN.
	sousLegitime := "selector1._domainkey"
	trameLegitime := construireRequeteDNSFilaireA18(sousLegitime, "example.org", 16)
	classe, raison, consomme := etat.ObserveAndClassify18(
		trameLegitime, 1_000_000, adresseClient, []byte(sousLegitime), apex, 16, DNSEpisodeSnapshot{}, EpisodeP3Features{},
	)
	if classe != "BENIGN" || raison != ReasonNone || !consomme {
		t.Fatalf("DKIM légitime: classe=%q raison=%q consomme=%t", classe, raison, consomme)
	}

	// 2. Jumeau hostile A-18 : charge utile de 48 octets préfixant ._dmarc -> ne doit JAMAIS être exempté, classé M-01.
	sousHostile := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6._dmarc"
	trameHostile := construireRequeteDNSFilaireA18(sousHostile, "example.org", 16)
	classe, raison, consomme = etat.ObserveAndClassify18(
		trameHostile, 2_000_000, adresseClient, []byte(sousHostile), apex, 16, DNSEpisodeSnapshot{}, EpisodeP3Features{},
	)
	if classe != "M-01" || raison != ReasonM01LongLabel || !consomme {
		t.Fatalf("contournement A-18 non bloqué: classe=%q raison=%q consomme=%t, attendu M-01 / %s", classe, raison, consomme, ReasonM01LongLabel)
	}

	// 3. Zéro allocation tas sur le chemin chaud.
	sousOctets := []byte(sousHostile)
	allocations := testing.AllocsPerRun(500, func() {
		etat.ObserveAndClassify18(trameHostile, 3_000_000, adresseClient, sousOctets, apex, 16, DNSEpisodeSnapshot{}, EpisodeP3Features{})
	})
	if allocations != 0 {
		t.Fatalf("allocations=%v, attendu 0", allocations)
	}
}
