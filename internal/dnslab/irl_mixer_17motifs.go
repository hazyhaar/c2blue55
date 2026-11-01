package dnslab

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

var base58Payloads = [...]string{
	"5HueCGU8rMjxEXxiPuD5BDku4Mk",
	"9AjdFGH3kLmNpQrStUvWxYz2BcD",
	"3J98t1WpEZ73CNmQviecrnyiWrnq",
	"7K4mPqRsTuVwXyZ123456789AbCd",
	"2B8nQrStUvWxYz3456789AbCdEfG",
	"4H6kLmNpQrStUvWxYz56789AbCdE",
	"6M9pQrStUvWxYz23456789AbCdEf",
	"8N2qRsTuVwXyZ456789AbCdEfGhJ",
}

var p11CleanLengthTuples = [...]string{
	"cat.alpha.node.sync",
	"beta.dog.cache.host",
	"edge.router.api.data",
	"auth.gateway.srv.logs",
	"mail.app.cluster.flow",
	"cdn.storage.dev.mesh",
	"hub.network.core.gate",
	"dns.proxy.system.time",
}

// encodeWireDomainNoAlloc encode un nom de domaine ASCII en labels wire DNS dans dst sans allocation.
func encodeWireDomainNoAlloc(domain string, dst []byte) int {
	pos := 0
	start := 0
	for i := 0; i <= len(domain); i++ {
		if i == len(domain) || domain[i] == '.' {
			l := i - start
			if l > 0 && l <= 63 && pos+1+l < len(dst) {
				dst[pos] = byte(l)
				pos++
				copy(dst[pos:], domain[start:i])
				pos += l
			}
			start = i + 1
		}
	}
	if pos < len(dst) {
		dst[pos] = 0
		pos++
	}
	return pos
}

// buildCustomRequestWire construit une requête DNS wire en conservant la casse exacte du QNAME
// (indispensable pour P12 Base58 et le piège bénin DNS-0x20) et en supportant Opcode=5 (P6 UPDATE).
func buildCustomRequestWire(txid uint16, qname string, qtype uint16, motifID string) []byte {
	var buf [512]byte
	flags := uint16(0x0100)
	qdCount := uint16(1)
	nsCount := uint16(0)
	if motifID == "P6" {
		flags = 0x2800 // Opcode = 5 (UPDATE)
		nsCount = 1
	}
	binary.BigEndian.PutUint16(buf[0:2], txid)
	binary.BigEndian.PutUint16(buf[2:4], flags)
	binary.BigEndian.PutUint16(buf[4:6], qdCount)
	binary.BigEndian.PutUint16(buf[6:8], 0)
	binary.BigEndian.PutUint16(buf[8:10], nsCount)
	binary.BigEndian.PutUint16(buf[10:12], 0)

	off := 12
	off += encodeWireDomainNoAlloc(qname, buf[off:])
	binary.BigEndian.PutUint16(buf[off:off+2], qtype)
	binary.BigEndian.PutUint16(buf[off+2:off+4], 1)
	off += 4

	if motifID == "P6" {
		// Section Update (Authority) : 1 RR TXT ajoutant une charge C2
		buf[off] = 0xC0
		buf[off+1] = 0x0C
		binary.BigEndian.PutUint16(buf[off+2:off+4], 16) // TXT
		binary.BigEndian.PutUint16(buf[off+4:off+6], 1)  // IN
		binary.BigEndian.PutUint32(buf[off+6:off+10], 60)
		payload := "upd-c2-cmd-exec-payload"
		binary.BigEndian.PutUint16(buf[off+10:off+12], uint16(1+len(payload)))
		buf[off+12] = byte(len(payload))
		copy(buf[off+13:], payload)
		off += 13 + len(payload)
	}

	out := make([]byte, off)
	copy(out, buf[:off])
	return out
}

func appendRRPtr(dst []byte, off int, rrType uint16, ttl uint32, rdata []byte) int {
	if off+12+len(rdata) > len(dst) {
		return off
	}
	dst[off] = 0xC0
	dst[off+1] = 0x0C
	binary.BigEndian.PutUint16(dst[off+2:off+4], rrType)
	binary.BigEndian.PutUint16(dst[off+4:off+6], 1)
	binary.BigEndian.PutUint32(dst[off+6:off+10], ttl)
	binary.BigEndian.PutUint16(dst[off+10:off+12], uint16(len(rdata)))
	copy(dst[off+12:], rdata)
	return off + 12 + len(rdata)
}

// BuildLabResponse17Motifs construit en 0 B/op la réponse wire DNS correspondant à l'une des
// 17 familles hostiles ou aux profils bénins IRL (dont CNAME CDN, EDNS0 OPT, SRV AD, CNAME+A).
func BuildLabResponse17Motifs(reqWire []byte, motifID string, dst []byte) (int, error) {
	if len(reqWire) < 17 || len(dst) < 512 {
		return 0, ErrLiveRateContract
	}
	// Trouver la fin de la première question (QNAME + QTYPE + QCLASS)
	qEnd := 12
	for qEnd < len(reqWire) {
		l := int(reqWire[qEnd])
		qEnd++
		if l == 0 {
			break
		}
		if (l & 0xC0) == 0xC0 {
			qEnd++
			break
		}
		qEnd += l
	}
	qEnd += 4
	if qEnd > len(reqWire) || qEnd > 280 {
		return 0, ErrLiveRateContract
	}

	copy(dst[:qEnd], reqWire[:qEnd])
	binary.BigEndian.PutUint16(dst[2:4], 0x8180) // QR=1, AA=0, RD=1, RA=1, RCode=0
	binary.BigEndian.PutUint16(dst[4:6], 1)      // QDCount=1
	binary.BigEndian.PutUint16(dst[6:8], 0)      // ANCount
	binary.BigEndian.PutUint16(dst[8:10], 0)     // NSCount
	binary.BigEndian.PutUint16(dst[10:12], 0)    // ARCount
	off := qEnd

	switch motifID {
	case "M-04", "BENIGN_TYPO_NX":
		binary.BigEndian.PutUint16(dst[2:4], 0x8403) // RCode=3 NXDOMAIN
		return off, nil

	case "P1":
		binary.BigEndian.PutUint16(dst[6:8], 1)
		qtype := binary.BigEndian.Uint16(reqWire[qEnd-4 : qEnd-2])
		if qtype != 10 && qtype != 16 {
			qtype = 16
		}
		dst[off] = 0xC0
		dst[off+1] = 0x0C
		binary.BigEndian.PutUint16(dst[off+2:off+4], qtype)
		binary.BigEndian.PutUint16(dst[off+4:off+6], 1)
		binary.BigEndian.PutUint32(dst[off+6:off+10], 60)
		const rLen = 220
		binary.BigEndian.PutUint16(dst[off+10:off+12], rLen)
		for i := range rLen {
			dst[off+12+i] = byte((i*73 + 19) & 0xFF)
		}
		return off + 12 + rLen, nil

	case "P5":
		// AXFR/IXFR C2 : 3 RR en section Answer avec charge TXT d'exfiltration en lot (>= 32 octets)
		binary.BigEndian.PutUint16(dst[6:8], 3)
		var rdataA = [4]byte{10, 55, 5, 1}
		var rdataTXT = [32]byte{31, 'a', 'x', 'f', 'r', '-', 'z', 'o', 'n', 'e', '-', 'd', 'u', 'm', 'p', '-', 's', 'e', 'c', 'r', 'e', 't', '-', 'b', 'l', 'o', 'c', 'k', '-', '0', '0', '1'}
		var rdataA2 = [4]byte{10, 55, 5, 2}
		off = appendRRPtr(dst, off, 1, 300, rdataA[:])
		off = appendRRPtr(dst, off, 16, 300, rdataTXT[:])
		off = appendRRPtr(dst, off, 1, 300, rdataA2[:])
		return off, nil

	case "BENIGN_AXFR_AUTH":
		// Transfert de zone secondaire légitime vers un apex autoritaire : 2 RR A courts (8 octets RDATA au total)
		binary.BigEndian.PutUint16(dst[6:8], 2)
		ip1 := [4]byte{198, 51, 100, 10}
		ip2 := [4]byte{198, 51, 100, 11}
		off = appendRRPtr(dst, off, 1, 3600, ip1[:])
		off = appendRRPtr(dst, off, 1, 3600, ip2[:])
		return off, nil

	case "BENIGN_MULTI_A_TTL":
		// RRset multi-A round-robin légitime RFC 2181 §5.2 : 4 RR A avec TTL=300 strictement uniforme
		binary.BigEndian.PutUint16(dst[6:8], 4)
		for idx := range 4 {
			ip := [4]byte{198, 51, 100, byte(20 + idx)}
			off = appendRRPtr(dst, off, 1, 300, ip[:])
		}
		return off, nil

	case "BENIGN_ANY_DIAG":
		// Requête ANY de diagnostic légitime : 1 A + 1 AAAA (2 types standards sans TXT/NULL porteur)
		binary.BigEndian.PutUint16(dst[6:8], 2)
		ip4 := [4]byte{198, 51, 100, 30}
		ip6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		off = appendRRPtr(dst, off, 1, 3600, ip4[:])
		off = appendRRPtr(dst, off, 28, 3600, ip6[:])
		return off, nil

	case "P6":
		// Dynamic DNS UPDATE (Opcode=5) avec 1 RR en section Authority (Update)
		binary.BigEndian.PutUint16(dst[2:4], 0xA800) // QR=1, Opcode=5, RCode=0
		binary.BigEndian.PutUint16(dst[8:10], 1)     // NSCount = 1
		var updData = [20]byte{19, 'u', 'p', 'd', '-', 'a', 'c', 'k', '-', 'c', '2', '-', 's', 'y', 'n', 'c', '-', 'o', 'k', '!'}
		off = appendRRPtr(dst, off, 16, 60, updData[:])
		return off, nil

	case "P7":
		// SRV C2 (Type=33) : Priority=10, Weight=5, Port=4444 (non-standard), Target encodée
		binary.BigEndian.PutUint16(dst[6:8], 1)
		var srvRData [64]byte
		binary.BigEndian.PutUint16(srvRData[0:2], 10)
		binary.BigEndian.PutUint16(srvRData[2:4], 5)
		binary.BigEndian.PutUint16(srvRData[4:6], 4444)
		n := encodeWireDomainNoAlloc("c2target9f8e7d6c5b4a39281726.srv-c2.org", srvRData[6:])
		off = appendRRPtr(dst, off, 33, 60, srvRData[:6+n])
		return off, nil

	case "BENIGN_SRV_AD":
		// SRV Active Directory légitime : Port=389 (LDAP), Target courte dc01.corp.example.com
		binary.BigEndian.PutUint16(dst[6:8], 1)
		var srvRData [64]byte
		binary.BigEndian.PutUint16(srvRData[0:2], 0)
		binary.BigEndian.PutUint16(srvRData[2:4], 100)
		binary.BigEndian.PutUint16(srvRData[4:6], 389)
		n := encodeWireDomainNoAlloc("dc01.corp.example.com", srvRData[6:])
		off = appendRRPtr(dst, off, 33, 600, srvRData[:6+n])
		return off, nil

	case "P8":
		// Chaîne CNAME (2 CNAME + 1 A = 3 RR) avec cible CNAME porteuse (label >= 24 octets)
		binary.BigEndian.PutUint16(dst[6:8], 3)
		var cname1, cname2 [64]byte
		n1 := encodeWireDomainNoAlloc("hop1c2payload8f7e6d5c4b3a2918.cname-c2.org", cname1[:])
		n2 := encodeWireDomainNoAlloc("hop2c2payload1a2b3c4d5e6f7a8b.cname-c2.org", cname2[:])
		var ipA = [4]byte{10, 55, 8, 1}
		off = appendRRPtr(dst, off, 5, 120, cname1[:n1])
		off = appendRRPtr(dst, off, 5, 120, cname2[:n2])
		off = appendRRPtr(dst, off, 1, 120, ipA[:])
		return off, nil

	case "BENIGN_CDN_CNAME":
		// Chaîne CNAME CDN bénigne (2 CNAME à labels courts + 1 A = 3 RR)
		binary.BigEndian.PutUint16(dst[6:8], 3)
		var cname1, cname2 [64]byte
		n1 := encodeWireDomainNoAlloc("edge.akamai.net", cname1[:])
		n2 := encodeWireDomainNoAlloc("pop1.akadns.net", cname2[:])
		var ipA = [4]byte{93, 184, 216, 10}
		off = appendRRPtr(dst, off, 5, 300, cname1[:n1])
		off = appendRRPtr(dst, off, 5, 300, cname2[:n2])
		off = appendRRPtr(dst, off, 1, 60, ipA[:])
		return off, nil

	case "P9":
		// EDNS0 / OPT (Type=41 en section Additional) avec OptionCode privé 65001 (28 octets)
		binary.BigEndian.PutUint16(dst[6:8], 1)
		binary.BigEndian.PutUint16(dst[10:12], 1)
		var ipA = [4]byte{10, 55, 9, 1}
		off = appendRRPtr(dst, off, 1, 60, ipA[:])
		// Enregistrement OPT (Name = 0x00 root, Type = 41, Class = 4096)
		dst[off] = 0x00
		binary.BigEndian.PutUint16(dst[off+1:off+3], 41)
		binary.BigEndian.PutUint16(dst[off+3:off+5], 4096)
		binary.BigEndian.PutUint32(dst[off+5:off+9], 0)
		const optPayloadLen = 28
		binary.BigEndian.PutUint16(dst[off+9:off+11], 4+optPayloadLen)
		binary.BigEndian.PutUint16(dst[off+11:off+13], 65001) // OptionCode privé C2
		binary.BigEndian.PutUint16(dst[off+13:off+15], optPayloadLen)
		for i := range optPayloadLen {
			dst[off+15+i] = byte(0xA0 + i)
		}
		return off + 15 + optPayloadLen, nil

	case "BENIGN_EDNS0_STD":
		// EDNS0 / OPT bénin avec ECS (OptionCode=8, 8B) + Padding RFC 7830 (OptionCode=12, 24B) -> RDLength = 40B
		binary.BigEndian.PutUint16(dst[6:8], 1)
		binary.BigEndian.PutUint16(dst[10:12], 1)
		var ipA = [4]byte{93, 184, 216, 11}
		off = appendRRPtr(dst, off, 1, 300, ipA[:])
		dst[off] = 0x00
		binary.BigEndian.PutUint16(dst[off+1:off+3], 41)
		binary.BigEndian.PutUint16(dst[off+3:off+5], 4096)
		binary.BigEndian.PutUint32(dst[off+5:off+9], 0)
		binary.BigEndian.PutUint16(dst[off+9:off+11], 40) // RDLength = 40 (>= 24, mais options 8 et 12 bénignes)
		// Option 8 (ECS) : 8 octets
		binary.BigEndian.PutUint16(dst[off+11:off+13], 8)
		binary.BigEndian.PutUint16(dst[off+13:off+15], 8)
		for i := range 8 {
			dst[off+15+i] = byte(i + 1)
		}
		// Option 12 (Padding) : 24 octets de zéros
		binary.BigEndian.PutUint16(dst[off+23:off+25], 12)
		binary.BigEndian.PutUint16(dst[off+25:off+27], 24)
		for i := range 24 {
			dst[off+27+i] = 0
		}
		return off + 51, nil

	case "P10":
		// Stéganographie TTL : 4 RR Type=1 (A, RDLength=4) partageant le même nom mais avec 4 TTL distincts (61, 65, 71, 74)
		binary.BigEndian.PutUint16(dst[6:8], 4)
		ttls := [4]uint32{61, 65, 71, 74}
		for idx, ttl := range ttls {
			ip := [4]byte{10, 55, 10, byte(idx + 1)}
			off = appendRRPtr(dst, off, 1, ttl, ip[:])
		}
		return off, nil

	case "BENIGN_CNAME_A_TTL":
		// Piège bénin : 1 CNAME (TTL=3600) + 2 A (TTL=60, TTL=60 uniformes sur Type=1)
		binary.BigEndian.PutUint16(dst[6:8], 3)
		var cnameTarget [32]byte
		n := encodeWireDomainNoAlloc("cdn.example.com", cnameTarget[:])
		ip1 := [4]byte{93, 184, 216, 20}
		ip2 := [4]byte{93, 184, 216, 21}
		off = appendRRPtr(dst, off, 5, 3600, cnameTarget[:n])
		off = appendRRPtr(dst, off, 1, 60, ip1[:])
		off = appendRRPtr(dst, off, 1, 60, ip2[:])
		return off, nil

	case "P13":
		// Requête ANY (QType=255) : 3 RR de 3 types distincts (A=1, TXT=16, MX=15)
		binary.BigEndian.PutUint16(dst[6:8], 3)
		ip := [4]byte{10, 55, 13, 1}
		txt := [12]byte{11, 'w', 'i', 'l', 'd', 'c', 'a', 'r', 'd', '-', 'c', '2'}
		var mx [24]byte
		binary.BigEndian.PutUint16(mx[0:2], 10)
		nMx := encodeWireDomainNoAlloc("mx.any-c2.org", mx[2:])
		off = appendRRPtr(dst, off, 1, 120, ip[:])
		off = appendRRPtr(dst, off, 16, 120, txt[:])
		off = appendRRPtr(dst, off, 15, 120, mx[:2+nMx])
		return off, nil

	default:
		binary.BigEndian.PutUint16(dst[6:8], 1)
		ip := [4]byte{93, 184, 216, 34}
		off = appendRRPtr(dst, off, 1, 300, ip[:])
		return off, nil
	}
}

// BuildIRLDilutedStream17Motifs génère un flux DNS dilué mêlant les 17 familles hostiles
// (M-01..M-04 + P1..P13) et un trafic bénin IRL enrichi des pièges d'orthogonalité.
func BuildIRLDilutedStream17Motifs(seed uint64, benignRatio float64, totalExchanges int) ([]GeneratedExchange, []GroundTruthPacket, error) {
	if benignRatio < 0.70 || benignRatio > 0.90 || totalExchanges < 240 || totalExchanges > 800 {
		return nil, nil, ErrLiveRateContract
	}

	families := []string{
		"M-01", "M-02", "M-03", "M-04",
		"P1", "P2", "P3", "P4",
		"P5", "P6", "P7", "P8", "P9", "P10", "P11", "P12", "P13",
	}

	// Garantir des quotas suffisants pour les motifs à seuil d'agrégation (M-03 >= 15, P4 >= 16, P3 >= 6, P11 >= 6)
	quotas := map[string]int{
		"M-01": 5, "M-02": 5, "M-03": 16, "M-04": 5,
		"P1": 5, "P2": 5, "P3": 6, "P4": 16,
		"P5": 5, "P6": 5, "P7": 5, "P8": 5, "P9": 5, "P10": 5, "P11": 6, "P12": 5, "P13": 5,
	}
	hostileTotal := 0
	for _, q := range quotas {
		hostileTotal += q
	}
	benignTotal := totalExchanges - hostileTotal
	if benignTotal <= 0 {
		return nil, nil, ErrLiveRateContract
	}

	byFamily := make([][]GeneratedExchange, len(families))
	for fIdx, fam := range families {
		familyQuota := quotas[fam]
		for i := range familyQuota {
			var ex GeneratedExchange
			ex.Family = fam
			switch fam {
			case "M-01":
				ex.DomainApex = "m01-volumetric.org"
				ex.Subdomain = fmt.Sprintf("chunk1a%02dabcdef0123456789.chunk2b%02dabcdef0123456789abcdef", i, i)
				ex.QType = 16
			case "M-02":
				ex.DomainApex = "m02-shannon.net"
				ex.Subdomain = strings.ToLower(m02HighShannonTokens[i%len(m02HighShannonTokens)])
				ex.QType = 1
			case "M-03":
				ex.DomainApex = "m03-burst.org"
				ex.Subdomain = fmt.Sprintf("bst-%03d", i)
				ex.QType = 1
			case "M-04":
				ex.DomainApex = fmt.Sprintf("dga-%02d.org", i%6+1)
				ex.Subdomain = dgaConsonantSeeds[i%len(dgaConsonantSeeds)]
				ex.QType = 1
			case "P1":
				ex.DomainApex = fmt.Sprintf("irl-p1-%02d.org", i%4+1)
				ex.Subdomain = fmt.Sprintf("p1dl%02d", i)
				ex.QType = 16
				if i%2 == 1 {
					ex.QType = 10
				}
			case "P2":
				ex.DomainApex = fmt.Sprintf("irl-p2-%02d.net", i%3+1)
				ex.Subdomain = hex28Payloads[i%len(hex28Payloads)]
				ex.QType = 1
			case "P3":
				ex.DomainApex = "irl-beacon-sync.com"
				ex.Subdomain = fmt.Sprintf("hb%03d", i)
				ex.QType = p3QTypes[i%len(p3QTypes)]
			case "P4":
				ex.DomainApex = fmt.Sprintf("irl-p4-shard-%02d.org", i)
				ex.Subdomain = fmt.Sprintf("s%d9f8e7d6c5b4a39", i%10)
				ex.QType = 1
			case "P5":
				ex.DomainApex = fmt.Sprintf("axfr-c2-%02d.org", i%3+1)
				ex.Subdomain = "zone"
				ex.QType = 252
				if i%2 == 1 {
					ex.QType = 251
				}
			case "P6":
				ex.DomainApex = "dyn-update-c2.org"
				ex.Subdomain = fmt.Sprintf("upd%02d", i)
				ex.QType = 6 // SOA Zone Type in RFC 2136 UPDATE
			case "P7":
				ex.DomainApex = "srv-c2-control.org"
				ex.Subdomain = fmt.Sprintf("_c2ctl._tcp.node%02d", i)
				ex.QType = 33
				ex.HasNonLDH = true
			case "P8":
				ex.DomainApex = "cname-chain-c2.org"
				ex.Subdomain = fmt.Sprintf("alias%02d", i)
				ex.QType = 5
			case "P9":
				ex.DomainApex = "edns-opt-c2.org"
				ex.Subdomain = fmt.Sprintf("opt%02d", i)
				ex.QType = 1
			case "P10":
				ex.DomainApex = "ttl-stego-c2.org"
				ex.Subdomain = fmt.Sprintf("rr%02d", i)
				ex.QType = 1
			case "P11":
				ex.DomainApex = "len-stego-c2.org"
				ex.Subdomain = p11CleanLengthTuples[i%len(p11CleanLengthTuples)]
				ex.QType = 1
			case "P12":
				ex.DomainApex = "b58-stego-c2.org"
				ex.Subdomain = base58Payloads[i%len(base58Payloads)]
				ex.QType = 1
			case "P13":
				ex.DomainApex = "any-wildcard-c2.org"
				ex.Subdomain = fmt.Sprintf("wild%02d", i)
				ex.QType = 255
			}
			byFamily[fIdx] = append(byFamily[fIdx], ex)
		}
	}

	var hostile []GeneratedExchange
	for j := 0; len(hostile) < hostileTotal; j++ {
		for fIdx := range byFamily {
			if j < len(byFamily[fIdx]) {
				hostile = append(hostile, byFamily[fIdx][j])
			}
		}
	}

	// Construction des échanges bénins IRL incluant tous les pièges d'orthogonalité :
	// - Happy Eyeballs A+AAAA (dt = 5ms)
	// - Chaînes CNAME CDN de profondeur 3 à cibles bénignes (piège P8)
	// - EDNS0 OPT avec ECS (8) + Padding RFC 7830 (12) >= 40 octets (piège P9)
	// - SRV Active Directory port 389 (_ldap._tcp.dc._msdcs) (piège P7)
	// - CNAME (TTL=3600) + A (TTL=60) dans la même réponse (piège P10)
	// - DNS-0x20 bit-encoding avec tiret et 0/O/I/l (piège P12)
	// - Pods Kubernetes avec tirets et chiffres (piège P11)
	// - 6 retransmissions NXDOMAIN sur la même faute de frappe (piège M-04)
	type benignTrap struct {
		ex       GeneratedExchange
		respKind string
	}
	var benignList []benignTrap
	cdnSubs := []string{"www", "assets", "static", "img", "api"}
	txtSubs := []string{"default._domainkey", "_spf", "_acme-challenge", "_dmarc"}

	for k := range benignTotal {
		switch {
		case k < 16:
			// Happy Eyeballs A+AAAA
			qt := uint16(1)
			if k%2 == 1 {
				qt = 28
			}
			benignList = append(benignList, benignTrap{
				ex: GeneratedExchange{
					Family:     "BENIGN",
					DomainApex: fmt.Sprintf("cdn-edge-%02d.com", (k/2)%4+1),
					Subdomain:  "www",
					QType:      qt,
				},
				respKind: "BENIGN",
			})
		case k < 24:
			// Piège P8 : Chaîne CNAME CDN de profondeur 3 à cibles bénignes
			benignList = append(benignList, benignTrap{
				ex: GeneratedExchange{
					Family:     "BENIGN",
					DomainApex: "shop-akamai.com",
					Subdomain:  "www",
					QType:      1,
				},
				respKind: "BENIGN_CDN_CNAME",
			})
		case k < 32:
			// Piège P9 : EDNS0 OPT standard (ECS Option 8 + Padding Option 12 >= 40 octets)
			benignList = append(benignList, benignTrap{
				ex: GeneratedExchange{
					Family:     "BENIGN",
					DomainApex: "cloudflare-dns.com",
					Subdomain:  "resolver",
					QType:      1,
				},
				respKind: "BENIGN_EDNS0_STD",
			})
		case k < 40:
			// Piège P7 : SRV Active Directory port 389 légitime
			benignList = append(benignList, benignTrap{
				ex: GeneratedExchange{
					Family:     "BENIGN",
					DomainApex: "corp-ad.internal",
					Subdomain:  "_ldap._tcp.dc._msdcs",
					QType:      33,
					HasNonLDH:  true,
				},
				respKind: "BENIGN_SRV_AD",
			})
		case k < 48:
			// Piège P10 : Réponse contenant CNAME (TTL=3600) + A (TTL=60)
			benignList = append(benignList, benignTrap{
				ex: GeneratedExchange{
					Family:     "BENIGN",
					DomainApex: "fastly-cdn.net",
					Subdomain:  "media",
					QType:      1,
				},
				respKind: "BENIGN_CNAME_A_TTL",
			})
		case k < 56:
			// Piège P12 : DNS-0x20 bit-encoding avec tiret et 0/O/I/l
			benignList = append(benignList, benignTrap{
				ex: GeneratedExchange{
					Family:     "BENIGN",
					DomainApex: "example-corp.com",
					Subdomain:  "WwW-01OIl",
					QType:      1,
				},
				respKind: "BENIGN",
			})
		case k < 64:
			// Piège P11 : Sous-domaines Kubernetes à 4 labels contenant chiffres et tirets
			benignList = append(benignList, benignTrap{
				ex: GeneratedExchange{
					Family:     "BENIGN",
					DomainApex: "k8s-cluster.local",
					Subdomain:  fmt.Sprintf("pod-%02d.svc-1.ns-2.app", k),
					QType:      1,
				},
				respKind: "BENIGN",
			})
		case k < 70:
			// Piège M-04 : 6 retransmissions sur une faute de frappe unique en NXDOMAIN
			qt := uint16(1)
			if k%2 == 1 {
				qt = 28
			}
			benignList = append(benignList, benignTrap{
				ex: GeneratedExchange{
					Family:     "BENIGN",
					DomainApex: "corp-intra.org",
					Subdomain:  "typo-intranet-local",
					QType:      qt,
				},
				respKind: "BENIGN_TYPO_NX",
			})
		case k < 80:
			// Préfixes RFC _domainkey, _spf, _acme-challenge, _dmarc
			sub := txtSubs[k%len(txtSubs)]
			benignList = append(benignList, benignTrap{
				ex: GeneratedExchange{
					Family:     "BENIGN",
					DomainApex: "mail-corp.org",
					Subdomain:  sub,
					QType:      16,
					HasNonLDH:  true,
				},
				respKind: "BENIGN",
			})
		case k < 86:
			// Baseline bénigne même canal P5 : transfert AXFR/IXFR secondaire légitime vers un apex autoritaire
			qt := uint16(252)
			if k%2 == 1 {
				qt = 251
			}
			benignList = append(benignList, benignTrap{
				ex: GeneratedExchange{
					Family:     "BENIGN",
					DomainApex: "ns-sync-auth.org",
					Subdomain:  "zone-sec",
					QType:      qt,
				},
				respKind: "BENIGN_AXFR_AUTH",
			})
		case k < 92:
			// Baseline bénigne même canal P10 : RRset multi-A round-robin à TTL=300 uniforme (RFC 2181 §5.2)
			benignList = append(benignList, benignTrap{
				ex: GeneratedExchange{
					Family:     "BENIGN",
					DomainApex: "cdn-rr-pool.org",
					Subdomain:  "edge",
					QType:      1,
				},
				respKind: "BENIGN_MULTI_A_TTL",
			})
		case k < 98:
			// Baseline bénigne même canal P13 : requête ANY de diagnostic court (A + AAAA)
			benignList = append(benignList, benignTrap{
				ex: GeneratedExchange{
					Family:     "BENIGN",
					DomainApex: "diag-net.org",
					Subdomain:  "probe",
					QType:      255,
				},
				respKind: "BENIGN_ANY_DIAG",
			})
		default:
			benignList = append(benignList, benignTrap{
				ex: GeneratedExchange{
					Family:     "BENIGN",
					DomainApex: fmt.Sprintf("benign-cdn-%02d.com", k%5+1),
					Subdomain:  cdnSubs[k%len(cdnSubs)],
					QType:      1,
				},
				respKind: "BENIGN",
			})
		}
	}

	exchanges := make([]GeneratedExchange, 0, totalExchanges)
	bi, hi := 0, 0
	ts := int64(1_785_000_000_000_000_000)
	m03Clock := int64(1_785_100_000_000_000_000)
	p3Clock := int64(1_785_200_000_000_000_000)

	var respBuf [512]byte
	for bi < len(benignList) || hi < len(hostile) {
		takeBenign := hi >= len(hostile) || (bi < len(benignList) && bi*len(hostile) <= hi*len(benignList))
		var ex GeneratedExchange
		var respKind string
		if takeBenign {
			ex = benignList[bi].ex
			respKind = benignList[bi].respKind
			bi++
		} else {
			ex = hostile[hi]
			respKind = ex.Family
			hi++
		}

		idx := len(exchanges)
		switch ex.Family {
		case "M-03":
			m03Clock += 15_000_000 // 15 ms (Burst >= 15 req / 2s)
			ex.TimestampNs = m03Clock
		case "P3":
			p3Clock += 60_000_000_000 // 60 s exact (CV < 0.12)
			ex.TimestampNs = p3Clock
		default:
			if idx > 0 {
				if ex.Family == "BENIGN" && ex.QType == 28 && exchanges[idx-1].Family == "BENIGN" {
					ts += 5_000_000 // Happy Eyeballs 5 ms
				} else {
					w := irlHumanJitterWeights[(idx*7+int(seed&0x1f))%len(irlHumanJitterWeights)]
					ts += w * 1_000_000
				}
			}
			ex.TimestampNs = ts
		}

		qname := ex.Subdomain + "." + ex.DomainApex
		txid := uint16(0x5000 + idx)
		ex.RequestWire = buildCustomRequestWire(txid, qname, ex.QType, respKind)
		rLen, err := BuildLabResponse17Motifs(ex.RequestWire, respKind, respBuf[:])
		if err != nil {
			return nil, nil, err
		}
		ex.ResponseWire = make([]byte, rLen)
		copy(ex.ResponseWire, respBuf[:rLen])

		exchanges = append(exchanges, ex)
	}

	truth := make([]GroundTruthPacket, len(exchanges))
	for i, ex := range exchanges {
		sum := sha256.Sum256(ex.RequestWire)
		truth[i] = GroundTruthPacket{
			FrameIndex:   i,
			TimestampNs:  ex.TimestampNs,
			Family:       ex.Family,
			MotifFamily:  ex.Family,
			IsHostile:    ex.Family != "BENIGN",
			DomainApex:   ex.DomainApex,
			Subdomain:    ex.Subdomain,
			QType:        ex.QType,
			PacketSHA256: hex.EncodeToString(sum[:]),
		}
	}
	return exchanges, truth, nil
}
