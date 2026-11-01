package c2blue55

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func dnsHeader(flags, qd, an uint16) []byte {
	h := make([]byte, 12)
	binary.BigEndian.PutUint16(h[0:], 0x1234)
	binary.BigEndian.PutUint16(h[2:], flags)
	binary.BigEndian.PutUint16(h[4:], qd)
	binary.BigEndian.PutUint16(h[6:], an)
	return h
}

func question(name []byte, qtype uint16) []byte {
	q := binary.BigEndian.AppendUint16(append([]byte{}, name...), qtype)
	return binary.BigEndian.AppendUint16(q, 1)
}

func checkField(t *testing.T, name string, got []byte, want string) {
	t.Helper()
	if string(got) != want {
		t.Errorf("%s = %q, veut %q", name, got, want)
	}
}

var apiName = []byte("\x03api\x08hazyhaar\x02fr\x00")

func TestParseDNSMessage(t *testing.T) {
	query := append(dnsHeader(0x0100, 1, 0), question(apiName, TypeA)...)

	rdata := bytes.Repeat(append([]byte{99}, bytes.Repeat([]byte{'a'}, 99)...), 3)
	answer := binary.BigEndian.AppendUint16([]byte{0xC0, 0x0C}, TypeTXT)
	answer = binary.BigEndian.AppendUint16(answer, 1)
	answer = binary.BigEndian.AppendUint32(answer, 60)
	answer = binary.BigEndian.AppendUint16(answer, uint16(len(rdata)))
	answer = append(answer, rdata...)
	response := append(dnsHeader(0x8180, 1, 1), question(apiName, TypeTXT)...)
	response = append(response, answer...)

	t.Run("requete_A", func(t *testing.T) {
		var msg DNSMessage
		if err := ParseDNSMessage(query, &msg); err != nil {
			t.Fatalf("erreur inattendue : %v", err)
		}
		if msg.IsResponse {
			t.Error("IsResponse = true, veut false")
		}
		checkField(t, "QName", msg.QName[:msg.QNameLen], "api.hazyhaar.fr")
		checkField(t, "Subdomain", msg.Subdomain[:msg.SubdomainLen], "api")
		checkField(t, "ParentDomain", msg.ParentDomain[:msg.ParentDomainLen], "hazyhaar.fr")
		checkField(t, "SLD", msg.SLD[:msg.SLDLen], "hazyhaar")
		checkField(t, "TLD", msg.TLD[:msg.TLDLen], "fr")
	})

	t.Run("reponse_TXT", func(t *testing.T) {
		var msg DNSMessage
		if err := ParseDNSMessage(response, &msg); err != nil {
			t.Fatalf("erreur inattendue : %v", err)
		}
		if !msg.IsResponse {
			t.Error("IsResponse = false, veut true")
		}
		if msg.AnswerCount != 1 {
			t.Errorf("AnswerCount = %d, veut 1", msg.AnswerCount)
		}
		if msg.Answers[0].Type != TypeTXT {
			t.Errorf("Answers[0].Type = %d, veut %d", msg.Answers[0].Type, TypeTXT)
		}
		if msg.Answers[0].RDataLen != 300 {
			t.Errorf("Answers[0].RDataLen = %d, veut 300", msg.Answers[0].RDataLen)
		}
	})

	t.Run("boucle_pointeur", func(t *testing.T) {
		cases := []struct {
			name string
			raw  []byte
		}{
			{"auto_reference", append(dnsHeader(0x0100, 1, 0), 0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01)},
			{"saut_avant", append(dnsHeader(0x0100, 1, 0), 0xC0, 0x0E, 0x00, 0x01, 0x00, 0x01)},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				var msg DNSMessage
				err := ParseDNSMessage(tc.raw, &msg)
				if !errors.Is(err, ErrLoopPointer) {
					t.Errorf("err = %v, veut ErrLoopPointer", err)
				}
			})
		}
	})

	t.Run("label_8bit_rfc2181", func(t *testing.T) {
		name := []byte("\x02\x80\xfe\x01t\x07example\x03com\x00")
		raw := append(dnsHeader(0x0100, 1, 0), question(name, TypeA)...)
		var msg DNSMessage
		if err := ParseDNSMessage(raw, &msg); err != nil {
			t.Fatalf("erreur inattendue : %v", err)
		}
		if !msg.HasNonLDH {
			t.Error("HasNonLDH = false, veut true")
		}
	})

	t.Run("zero_alloc_reponse", func(t *testing.T) {
		var msg DNSMessage
		var err error
		allocs := testing.AllocsPerRun(100, func() {
			err = ParseDNSMessage(response, &msg)
		})
		if err != nil {
			t.Fatalf("erreur inattendue : %v", err)
		}
		if allocs != 0 {
			t.Errorf("allocations = %v par décodage, veut 0", allocs)
		}
	})

	t.Run("base58_wire_metrics_SH_S22a_01", func(t *testing.T) {
		// Sous-domaine Base58 (26 octets : majuscules + minuscules + chiffres [1-9], sans 0/O/I/l/-)
		b58Label := "5HueCGU8rMjxEXxiPuD5BDku4Mk"
		qNameWire := append([]byte{byte(len(b58Label))}, []byte(b58Label)...)
		qNameWire = append(qNameWire, []byte("\x07example\x03com\x00")...)
		rawB58 := append(dnsHeader(0x0100, 1, 0), question(qNameWire, TypeA)...)

		var msg DNSMessage
		if err := ParseDNSMessage(rawB58, &msg); err != nil {
			t.Fatalf("ParseDNSMessage(Base58) : %v", err)
		}
		if msg.FirstLabelUpper == 0 || msg.FirstLabelLower == 0 || msg.FirstLabelDigits == 0 {
			t.Errorf("Base58 FirstLabel counts = upper:%d lower:%d digits:%d, attendu > 0 sur les 3",
				msg.FirstLabelUpper, msg.FirstLabelLower, msg.FirstLabelDigits)
		}
		if msg.FirstLabelHasZeroOIl || msg.FirstLabelHasHyphen {
			t.Errorf("Base58 FirstLabelHasZeroOIl=%v FirstLabelHasHyphen=%v, attendu false/false",
				msg.FirstLabelHasZeroOIl, msg.FirstLabelHasHyphen)
		}

		// Jumeau bénin DNS-0x20 avec tiret et '0'/'O'
		d0x20Label := "WwW-01OIl"
		q0x20 := append([]byte{byte(len(d0x20Label))}, []byte(d0x20Label)...)
		q0x20 = append(q0x20, []byte("\x07example\x03com\x00")...)
		raw0x20 := append(dnsHeader(0x0100, 1, 0), question(q0x20, TypeA)...)
		if err := ParseDNSMessage(raw0x20, &msg); err != nil {
			t.Fatalf("ParseDNSMessage(0x20) : %v", err)
		}
		if !msg.FirstLabelHasZeroOIl || !msg.FirstLabelHasHyphen {
			t.Errorf("DNS-0x20 FirstLabelHasZeroOIl=%v FirstLabelHasHyphen=%v, attendu true/true",
				msg.FirstLabelHasZeroOIl, msg.FirstLabelHasHyphen)
		}
	})
}
