package dnslab_test

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

func zoneNames(t *testing.T) []string {
	t.Helper()
	questions := loadRealQuestions(t)
	seen := make(map[string]struct{})
	names := make([]string, 0, 8)
	for _, question := range questions {
		if !inLabZone(question.qname) {
			continue
		}
		if _, ok := seen[question.qname]; ok {
			continue
		}
		seen[question.qname] = struct{}{}
		names = append(names, question.qname)
	}
	if len(names) == 0 {
		t.Fatal("aucun nom réel en zone dans la capture")
	}
	return names
}

func wireNameLen(name string) int {
	if before, ok := strings.CutSuffix(name, "."); ok {
		name = before
	}
	if name == "" {
		return 1
	}
	return len(name) + 2
}

func nameOfLen(n int) string {
	labels := []int{63, 63, 63, 62}
	parts := make([]string, 0, len(labels))
	for _, labelLen := range labels {
		parts = append(parts, strings.Repeat("a", labelLen))
	}
	joined := strings.Join(parts, ".")
	if len(joined) != n {
		return joined
	}
	return joined
}

func TestBuildQuery_RoundTripWithParseDNSQuery(t *testing.T) {
	names := zoneNames(t)
	qtypes := []uint16{1, 16, 10}
	query := make([]byte, 512)
	for nameIdx, name := range names {
		qname := []byte(name)
		encoded := wireNameLen(name)
		wantLen := 12 + encoded + 4
		for typeIdx, qtype := range qtypes {
			id := uint16(0x1000 + nameIdx*8 + typeIdx)
			for i := range query {
				query[i] = 0xA5
			}
			n, err := dnslab.BuildQuery(id, qname, qtype, query)
			if err != nil || n != wantLen {
				t.Fatalf("%s qtype %d: n=%d err=%v, attendu %d octets et aucune erreur", name, qtype, n, err, wantLen)
			}
			if binary.BigEndian.Uint16(query[0:2]) != id {
				t.Fatalf("%s qtype %d: ID fil %#x, attendu %#x", name, qtype, binary.BigEndian.Uint16(query[0:2]), id)
			}
			flags := binary.BigEndian.Uint16(query[2:4])
			if flags&0x8000 != 0 || flags&0x0100 != 0 {
				t.Fatalf("%s qtype %d: Flags fil %#x, RD et QR doivent être nuls", name, qtype, flags)
			}
			if binary.BigEndian.Uint16(query[4:6]) != 1 || binary.BigEndian.Uint16(query[6:8]) != 0 || binary.BigEndian.Uint16(query[8:10]) != 0 || binary.BigEndian.Uint16(query[10:12]) != 0 {
				t.Fatalf("%s qtype %d: comptes QD/AN/NS/AR = %d/%d/%d/%d, attendu 1/0/0/0 (aucun OPT)", name, qtype, binary.BigEndian.Uint16(query[4:6]), binary.BigEndian.Uint16(query[6:8]), binary.BigEndian.Uint16(query[8:10]), binary.BigEndian.Uint16(query[10:12]))
			}
			for i := n; i < len(query); i++ {
				if query[i] != 0xA5 {
					t.Fatalf("%s qtype %d: octet %d modifié au-delà de la question", name, qtype, i)
				}
			}
			var ev c2blue55.DNSEvent
			if err := c2blue55.ParseDNSQuery(query[:n], &ev); err != nil {
				t.Fatalf("%s qtype %d: ParseDNSQuery: %v", name, qtype, err)
			}
			if ev.FQDN() != name || ev.QType != qtype || ev.ID != id || ev.Flags&0x8000 != 0 || ev.Flags&0x0100 != 0 {
				t.Fatalf("%s qtype %d: relu FQDN=%q QType=%d ID=%#x Flags=%#x", name, qtype, ev.FQDN(), ev.QType, ev.ID, ev.Flags)
			}
			allocs := testing.AllocsPerRun(20, func() {
				_, _ = dnslab.BuildQuery(id, qname, qtype, query)
			})
			if allocs != 0 {
				t.Fatalf("%s qtype %d: AllocsPerRun=%v, attendu 0", name, qtype, allocs)
			}
		}
	}
}

func TestBuildQuery_Refusals(t *testing.T) {
	names := zoneNames(t)
	longName := nameOfLen(254)
	if len(longName) != 254 {
		t.Fatalf("oracle de nom long: %d octets, attendu 254", len(longName))
	}
	label64 := strings.Repeat("b", 64)
	if len(label64) != 64 {
		t.Fatalf("oracle de label: %d octets, attendu 64", len(label64))
	}
	cases := []struct {
		name  string
		qname []byte
		space int
	}{
		{"nom_vide", nil, 512},
		{"nom_vide_tranche", []byte{}, 512},
		{"nom_254", []byte(longName), 512},
		{"label_64", []byte(label64), 512},
		{"tampon_511", []byte(names[0]), 511},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			query := make([]byte, tc.space)
			n, err := dnslab.BuildQuery(0x1357, tc.qname, 1, query)
			if !errors.Is(err, dnslab.ErrQueryContract) || n != 0 {
				t.Fatalf("n=%d err=%v, attendu 0 et ErrQueryContract", n, err)
			}
		})
	}
	t.Run("nom_reel_tampon_512", func(t *testing.T) {
		query := make([]byte, 512)
		n, err := dnslab.BuildQuery(0x1357, []byte(names[0]), 1, query)
		wantLen := 12 + wireNameLen(names[0]) + 4
		if err != nil || n != wantLen {
			t.Fatalf("nom réel %s refusé: n=%d err=%v, attendu %d et aucune erreur", names[0], n, err, wantLen)
		}
	})
}
