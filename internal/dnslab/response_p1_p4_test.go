package dnslab

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestBuildLabResponseP1P4(t *testing.T) {
	var resp [512]byte

	// 1. Entrées hostiles : paquet trop court, QR=1, tampon trop petit (SH-S15a-01).
	if _, _, err := BuildLabResponseP1P4([]byte{1, 2, 3}, 42, resp[:]); !errors.Is(err, ErrQueryTooShort) {
		t.Fatalf("attendu ErrQueryTooShort, obtenu %v", err)
	}
	var qr1 [16]byte
	qr1[2] = 0x80
	if _, _, err := BuildLabResponseP1P4(qr1[:], 42, resp[:]); !errors.Is(err, ErrNotAQuery) {
		t.Fatalf("attendu ErrNotAQuery sur QR=1, obtenu %v", err)
	}
	var validQ [512]byte
	qLen, err := BuildQuery(0x1234, []byte("v01.tun.test"), 10, validQ[:])
	if err != nil {
		t.Fatalf("BuildQuery: %v", err)
	}
	if _, _, err := BuildLabResponseP1P4(validQ[:qLen], 42, resp[:100]); !errors.Is(err, ErrResponseBufferTooSmall) {
		t.Fatalf("attendu ErrResponseBufferTooSmall, obtenu %v", err)
	}

	// 2. Poignée de main iodine NULL sans état dérivée du 1er caractère QName (V, L, I, Z, p).
	prefixes := []string{"v01.iodine.test", "l01.iodine.test", "i01.iodine.test", "z01.iodine.test", "p01.iodine.test"}
	seenRData := make(map[string]bool)
	for _, qname := range prefixes {
		qn, err := BuildQuery(0x2233, []byte(qname), 10, validQ[:])
		if err != nil {
			t.Fatalf("BuildQuery(%s): %v", qname, err)
		}
		n, dec, err := BuildLabResponseP1P4(validQ[:qn], 0xCAFE55, resp[:])
		if err != nil {
			t.Fatalf("BuildLabResponseP1P4(%s): %v", qname, err)
		}
		if dec.RCode != 0 || dec.QType != 10 {
			t.Fatalf("iodine NULL(%s): RCode=%d QType=%d", qname, dec.RCode, dec.QType)
		}
		if resp[7] != 1 {
			t.Fatalf("iodine NULL(%s): ANCOUNT=%d != 1", qname, resp[7])
		}
		rdLen := int(binary.BigEndian.Uint16(resp[qn+10 : qn+12]))
		if qname[0] == 'p' && rdLen < 200 {
			t.Fatalf("iodine data NULL(%s): rdLen=%d < 200", qname, rdLen)
		}
		if n != qn+12+rdLen {
			t.Fatalf("iodine NULL(%s): n=%d attendu=%d", qname, n, qn+12+rdLen)
		}
		rdata := string(resp[qn+12 : n])
		if seenRData[rdata] {
			t.Fatalf("iodine NULL(%s): RDATA identique à une étape précédente", qname)
		}
		seenRData[rdata] = true
	}

	// 3. Réponse P1 TXT descendante >= 200 octets vs TXT bénin _domainkey.
	qnP1, _ := BuildQuery(0x3344, []byte("p1a01.runa-p1-01.test"), 16, validQ[:])
	nP1, decP1, err := BuildLabResponseP1P4(validQ[:qnP1], 0xBEEF, resp[:])
	if err != nil || decP1.Verdict != VerdictAnswerTXT || decP1.RCode != 0 {
		t.Fatalf("P1 TXT: err=%v verdict=%v rcode=%d", err, decP1.Verdict, decP1.RCode)
	}
	rdLenP1 := int(binary.BigEndian.Uint16(resp[qnP1+10 : qnP1+12]))
	if rdLenP1 < 200 || nP1 != qnP1+12+rdLenP1 {
		t.Fatalf("P1 TXT: rdLen=%d (<200) nP1=%d", rdLenP1, nP1)
	}

	qnDKIM, _ := BuildQuery(0x3345, []byte("default._domainkey.mail-org.com"), 16, validQ[:])
	nDKIM, decDKIM, err := BuildLabResponseP1P4(validQ[:qnDKIM], 0xBEEF, resp[:])
	if err != nil || decDKIM.Verdict != VerdictAnswerTXT {
		t.Fatalf("DKIM TXT: err=%v verdict=%v", err, decDKIM.Verdict)
	}
	if !bytes.Contains(resp[qnDKIM+12:nDKIM], []byte("v=")) {
		t.Fatalf("DKIM TXT bénin attendu avec marqueur 'v=', obtenu %q", resp[qnDKIM+12:nDKIM])
	}

	// 4. Réponses A (QType=1) et AAAA (QType=28) et garantie 0 B/op.
	qnA, _ := BuildQuery(0x4455, []byte("www.cdn-edge.org"), 1, validQ[:])
	if _, decA, err := BuildLabResponseP1P4(validQ[:qnA], 99, resp[:]); err != nil || decA.RCode != 0 || resp[7] != 1 {
		t.Fatalf("A query: err=%v rcode=%d ancount=%d", err, decA.RCode, resp[7])
	}
	qnAAAA, _ := BuildQuery(0x4456, []byte("www.cdn-edge.org"), 28, validQ[:])
	if _, decAAAA, err := BuildLabResponseP1P4(validQ[:qnAAAA], 99, resp[:]); err != nil || decAAAA.RCode != 0 || resp[7] != 1 {
		t.Fatalf("AAAA query: err=%v rcode=%d ancount=%d", err, decAAAA.RCode, resp[7])
	}

	allocs := testing.AllocsPerRun(100, func() {
		_, _, _ = BuildLabResponseP1P4(validQ[:qnP1], 0xBEEF, resp[:])
	})
	if allocs > 0 {
		t.Fatalf("BuildLabResponseP1P4 a alloué %.2f allocs/op (attendu 0 B/op)", allocs)
	}
}
