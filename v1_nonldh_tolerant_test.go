package c2blue55

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/engine"
)

// questionFilaire construit une requête standard IN à partir de labels bruts.
func questionFilaire(qtype uint16, labels ...[]byte) []byte {
	paquet := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range labels {
		paquet = append(paquet, byte(len(label)))
		paquet = append(paquet, label...)
	}
	paquet = append(paquet, 0, 0, 0, 0, 1)
	binary.BigEndian.PutUint16(paquet[len(paquet)-4:], qtype)
	return paquet
}

func labelsTextuels(nom string) [][]byte {
	var labels [][]byte
	for label := range strings.SplitSeq(nom, ".") {
		labels = append(labels, []byte(label))
	}
	return labels
}

func labelBase128(longueur int, graine byte) []byte {
	label := make([]byte, longueur)
	for indice := range label {
		label[indice] = 0x80 | byte(indice*37+int(graine)*11)&0x3f // octets de continuation seuls : UTF-8 invalide
	}
	return label
}

func ecrirePCAPQuestionsUDP53(t *testing.T, questions [][]byte, instantsUs []uint64) []byte {
	t.Helper()
	var tampon bytes.Buffer
	var entete [24]byte
	binary.LittleEndian.PutUint32(entete[0:], 0xa1b2c3d4) // microsecondes, petit-boutiste
	binary.LittleEndian.PutUint16(entete[4:], 2)
	binary.LittleEndian.PutUint16(entete[6:], 4)
	binary.LittleEndian.PutUint32(entete[16:], 65535)
	binary.LittleEndian.PutUint32(entete[20:], 1) // Ethernet
	tampon.Write(entete[:])

	for indice, question := range questions {
		trame := make([]byte, 14+20+8+len(question))
		binary.BigEndian.PutUint16(trame[12:14], 0x0800)
		ip := trame[14:]
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+len(question)))
		ip[8] = 64
		ip[9] = 17 // UDP
		copy(ip[12:16], []byte{10, 55, 0, 2})
		copy(ip[16:20], []byte{10, 55, 0, 53})
		udp := ip[20:]
		binary.BigEndian.PutUint16(udp[0:2], 51000+uint16(indice))
		binary.BigEndian.PutUint16(udp[2:4], 53)
		binary.BigEndian.PutUint16(udp[4:6], uint16(8+len(question)))
		copy(udp[8:], question)

		horodatage := uint64(indice+1) * 1_000_000
		if indice < len(instantsUs) {
			horodatage = instantsUs[indice]
		}
		var enregistrement [16]byte
		binary.LittleEndian.PutUint32(enregistrement[0:4], uint32(horodatage/1_000_000))
		binary.LittleEndian.PutUint32(enregistrement[4:8], uint32(horodatage%1_000_000))
		binary.LittleEndian.PutUint32(enregistrement[8:12], uint32(len(trame)))
		binary.LittleEndian.PutUint32(enregistrement[12:16], uint32(len(trame)))
		tampon.Write(enregistrement[:])
		tampon.Write(trame)
	}
	return tampon.Bytes()
}

func trouverRepertoiresWittgensteinV1(t *testing.T) (corpusDir, labDir string) {
	t.Helper()
	repertoire, err := os.Getwd()
	if err != nil {
		t.Fatalf("répertoire courant illisible: %v", err)
	}
	for {
		if _, errStat := os.Lstat(filepath.Join(repertoire, ".git")); errStat == nil {
			break
		}
		parent := filepath.Dir(repertoire)
		if parent == repertoire {
			t.Fatalf("aucun .git au-dessus de %s", repertoire)
		}
		repertoire = parent
	}
	candidats := []string{
		filepath.Join(repertoire, "wittgenstein"),
		filepath.Join(repertoire, "..", "wittgenstein"),
		filepath.Join(repertoire, "..", "..", "..", "wittgenstein"),
	}
	for _, candidat := range candidats {
		cheminLab := filepath.Join(candidat, "redhost_lab")
		etat, errStat := os.Stat(cheminLab)
		if errStat == nil && etat.IsDir() {
			return candidat, cheminLab
		}
	}
	t.Fatalf("wittgenstein/redhost_lab introuvable depuis %s", repertoire)
	return "", ""
}

func copierFichierBorneV1(t *testing.T, source, destination string) {
	t.Helper()
	fichierSource, err := os.Open(source)
	if err != nil {
		t.Fatalf("ouverture %s: %v", source, err)
	}
	contenu, errLecture := io.ReadAll(io.LimitReader(fichierSource, 64<<20))
	errFermeture := fichierSource.Close()
	if errLecture != nil || errFermeture != nil {
		t.Fatalf("lecture %s: %v / %v", source, errLecture, errFermeture)
	}
	if err := os.WriteFile(destination, contenu, 0o600); err != nil {
		t.Fatalf("écriture %s: %v", destination, err)
	}
}

func TestParseDNSQueryTolerant_Base128NullIngested(t *testing.T) {
	paquet := questionFilaire(TypeNULL, labelBase128(48, 1), []byte("t"), []byte("example"), []byte("com"))
	var ev DNSEvent
	if err := ParseDNSQueryTolerant(paquet, &ev); err != nil {
		t.Fatalf("tolérant: %v", err)
	}
	if ev.Grammar.Classe != QNameGrammarBinary || ev.Grammar.OctetsHautBit != 48 || ev.Parent() != "example.com" || ev.QType != TypeNULL {
		t.Fatalf("grammaire=%+v parent=%q", ev.Grammar, ev.Parent())
	}
	if !bytes.Equal(ev.Name[:48], labelBase128(48, 1)) {
		t.Fatal("les octets haut-bit doivent être recopiés intégralement, sans repli ni troncature")
	}
	var strict DNSEvent
	if err := ParseDNSQuery(paquet, &strict); err != ErrInvalidLabel {
		t.Fatalf("strict: err=%v, attendu exactement ErrInvalidLabel", err)
	}
}

func TestParseDNSQueryTolerant_StructuralRejectsUnchanged(t *testing.T) {
	label64 := bytes.Repeat([]byte{'a'}, 64)
	nomLong := make([][]byte, 0, 5)
	for range 5 {
		nomLong = append(nomLong, bytes.Repeat([]byte{0xc3}, 60))
	}
	pointeurBoucle := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1}
	pointeurBas := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x02, 0, 1, 0, 1}
	debordement := []byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0x20, 0x80, 0x81}
	cas := []struct {
		nom     string
		paquet  []byte
		attendu error
	}{
		{"moins_de_12_octets", []byte{1, 2, 3}, ErrPacketTooShort},
		{"label_64_octets", questionFilaire(TypeA, label64, []byte("com")), ErrInvalidLabel},
		{"nom_superieur_253_haut_bit", questionFilaire(TypeA, nomLong...), ErrNameTooLong},
		{"pointeur_sur_lui_meme", pointeurBoucle, ErrLoopPointer},
		{"pointeur_dans_en_tete", pointeurBas, ErrInvalidLabel},
		{"label_hors_tampon", debordement, ErrPacketTooShort},
	}
	for _, scenario := range cas {
		t.Run(scenario.nom, func(t *testing.T) {
			var tolerant, strict DNSEvent
			errTolerant := ParseDNSQueryTolerant(scenario.paquet, &tolerant)
			errStrict := ParseDNSQuery(scenario.paquet, &strict)
			if !errors.Is(errTolerant, scenario.attendu) {
				t.Fatalf("tolérant: err=%v, attendu %v", errTolerant, scenario.attendu)
			}
			if errStrict == nil {
				t.Fatal("strict: rejet attendu")
			}
			if tolerant.NameLen != 0 || tolerant.Grammar != (QNameGrammarProfile{}) {
				t.Fatal("un rejet doit remettre l'événement à zéro")
			}
		})
	}
}

func TestQNameGrammar_ClassesSansFauxPositif(t *testing.T) {
	cas := []struct {
		nom     string
		labels  [][]byte
		attendu QNameGrammar
		jeton   string
	}{
		{"acme", labelsTextuels("_acme-challenge.www.example.com"), QNameGrammarLDH, "LDH"},
		{"dmarc", labelsTextuels("_dmarc.example.com"), QNameGrammarLDH, "LDH"},
		{"dkim", labelsTextuels("sel1._domainkey.example.com"), QNameGrammarLDH, "LDH"},
		{"srv_ldap_kerberos", labelsTextuels("_ldap._tcp.dc._msdcs.corp.example"), QNameGrammarLDH, "LDH"},
		{"srv_sip_tls", labelsTextuels("_sip._tls.example.com"), QNameGrammarLDH, "LDH"},
		{"punycode", labelsTextuels("xn--mnchen-3ya.de"), QNameGrammarLDH, "LDH"},
		{"utf8_local", labelsTextuels("münchen.de"), QNameGrammarUTF8Local, "UTF8_LOCAL"},
		{"instance_dns_sd", [][]byte{[]byte("Imprimante Étage.2"), []byte("_ipp"), []byte("_tcp"), []byte("example"), []byte("com")}, QNameGrammarDNSSDInstance, "DNSSD_INSTANCE"},
		{"ascii_espace", labelsTextuels("a b.example.com"), QNameGrammarASCIIOutsideLDH, "ASCII_HORS_LDH"},
		{"octet_nul", [][]byte{{'a', 0, 'b'}, []byte("example"), []byte("com")}, QNameGrammarBinary, "BINAIRE"},
		{"point_interne_hors_dns_sd", [][]byte{[]byte("a.b"), []byte("example"), []byte("com")}, QNameGrammarBinary, "BINAIRE"},
		{"base128", [][]byte{labelBase128(30, 2), []byte("example"), []byte("com")}, QNameGrammarBinary, "BINAIRE"},
	}
	for _, scenario := range cas {
		t.Run(scenario.nom, func(t *testing.T) {
			var ev DNSEvent
			if err := ParseDNSQueryTolerant(questionFilaire(TypeA, scenario.labels...), &ev); err != nil {
				t.Fatal(err)
			}
			if ev.Grammar.Classe != scenario.attendu || ev.Grammar.Classe.String() != scenario.jeton {
				t.Fatalf("classe=%s (%q), attendu %s (%q)", ev.Grammar.Classe, ev.Grammar.Classe.String(), scenario.attendu, scenario.jeton)
			}
		})
	}
}

func TestParseDNSQueryTolerant_ZeroAlloc(t *testing.T) {
	paquet := questionFilaire(TypeNULL, labelBase128(60, 3), []byte("example"), []byte("com"))
	var ev DNSEvent
	if allocations := testing.AllocsPerRun(1000, func() {
		if err := ParseDNSQueryTolerant(paquet, &ev); err != nil {
			t.Fatal(err)
		}
	}); allocations != 0 {
		t.Fatalf("allocations=%v, attendu 0", allocations)
	}
}

func FuzzParseDNSQueryTolerant_DifferentialStrict(f *testing.F) {
	f.Add(questionFilaire(TypeA, labelsTextuels("www.example.com")...))
	f.Add(questionFilaire(TypeNULL, labelBase128(40, 4), []byte("example"), []byte("com")))
	f.Fuzz(func(t *testing.T, paquet []byte) {
		var strict, tolerant DNSEvent
		errStrict := ParseDNSQuery(paquet, &strict)
		errTolerant := ParseDNSQueryTolerant(paquet, &tolerant)
		if errStrict == nil {
			if errTolerant != nil || tolerant.Grammar.Classe != QNameGrammarLDH {
				t.Fatalf("accepté en strict mais tolérant err=%v classe=%s", errTolerant, tolerant.Grammar.Classe)
			}
			tolerant.Grammar = QNameGrammarProfile{}
			if strict != tolerant {
				t.Fatal("un QNAME LDH doit produire un événement identique dans les deux modes")
			}
		}
		if errTolerant == nil && errStrict != nil && !errors.Is(errStrict, ErrInvalidLabel) {
			t.Fatalf("seule la grammaire peut séparer les modes ; strict=%v", errStrict)
		}
		if errTolerant == nil && tolerant.NameLen > 253 {
			t.Fatalf("NameLen=%d", tolerant.NameLen)
		}
	})
}

func TestNonLDHBurstGuard_SalveEtJumeaux(t *testing.T) {
	binaire := QNameGrammarProfile{Classe: QNameGrammarBinary}
	asciiHorsLDH := QNameGrammarProfile{Classe: QNameGrammarASCIIOutsideLDH}
	utf8Local := QNameGrammarProfile{Classe: QNameGrammarUTF8Local}
	parent := []byte("evil-c2.net")

	t.Run("salve_binaire_et_ascii_hors_ldh_condamnee_a_la_troisieme", func(t *testing.T) {
		var garde NonLDHBurstGuard
		for rang := range 3 {
			decision := garde.Observe(parent, []byte{0x80, byte(rang)}, binaire, 1, int64(rang)*1e9)
			if decision.Hostile != (rang == 2) {
				t.Fatalf("question %d: hostile=%t", rang+1, decision.Hostile)
			}
		}
		garde.Reset()
		for rang := range 3 {
			decision := garde.Observe(parent, []byte{'a', ' ', byte('0' + rang)}, asciiHorsLDH, 1, int64(rang)*1e9)
			if decision.Hostile != (rang == 2) || (rang == 2 && decision.Indicator != IndicatorNonLDHBinaryBurst) {
				t.Fatalf("ascii hors LDH %d: %+v", rang+1, decision)
			}
		}
	})
	t.Run("deux_null_ou_qtype_prive_binaires", func(t *testing.T) {
		var garde NonLDHBurstGuard
		if garde.Observe(parent, []byte{0x81}, binaire, TypeNULL, 0).Hostile {
			t.Fatal("une question NULL isolée ne suffit pas")
		}
		if decision := garde.Observe(parent, []byte{0x82}, binaire, 65280, 1e9); !decision.Hostile || decision.Indicator != IndicatorNonLDHTunnelQType {
			t.Fatalf("décision=%+v", decision)
		}
	})
	t.Run("utf8_isole_ou_repete_jamais_condamne", func(t *testing.T) {
		var garde NonLDHBurstGuard
		for rang := range 40 {
			sous := [][]byte{[]byte("café"), []byte("crèche")}[rang%2]
			if garde.Observe([]byte("example.fr"), sous, utf8Local, 1, int64(rang)*1e9).Hostile {
				t.Fatalf("question UTF-8 répétée %d condamnée", rang+1)
			}
		}
	})
	t.Run("fenetre_expiree", func(t *testing.T) {
		var garde NonLDHBurstGuard
		garde.Observe(parent, []byte{1}, binaire, 1, 0)
		garde.Observe(parent, []byte{2}, binaire, 1, 1e9)
		if garde.Observe(parent, []byte{3}, binaire, 1, FenetreGardeNonLDHNs+2e9).Hostile {
			t.Fatal("une question hors fenêtre ouvre un nouvel épisode")
		}
	})
	t.Run("ldh_et_dns_sd_ignores", func(t *testing.T) {
		var garde NonLDHBurstGuard
		for rang := range 10 {
			if garde.Observe(parent, []byte{byte(rang)}, QNameGrammarProfile{Classe: QNameGrammarDNSSDInstance}, TypeNULL, 0).Hostile {
				t.Fatal("instance DNS-SD condamnée")
			}
		}
	})
	t.Run("zero_alloc", func(t *testing.T) {
		var garde NonLDHBurstGuard
		instant := int64(0)
		if allocations := testing.AllocsPerRun(1000, func() {
			instant++
			garde.Observe(parent, []byte("x"), binaire, 1, instant)
		}); allocations != 0 {
			t.Fatalf("allocations=%v", allocations)
		}
	})
	t.Run("saturation_comptee", func(t *testing.T) {
		var garde NonLDHBurstGuard
		for rang := range 3 * capaciteGardeNonLDH {
			garde.Observe([]byte{byte(rang), byte(rang >> 8), 'x'}, []byte{1}, binaire, 1, 0)
		}
		if garde.Evictions() == 0 {
			t.Fatal("l'éviction de parents vivants doit être comptée")
		}
	})
}

func TestV1_A17_ParseDNSMessage_SplitWireQNameWithInternalDot(t *testing.T) {
	labelB128Point := []byte{0x85, '.', 0x90, '.', 0xaa}
	cas := []struct {
		nom           string
		labels        [][]byte
		attenduParent string
		attenduSLD    string
		attenduTLD    string
		attenduSub    string
	}{
		{
			nom:           "iodine_t0_lab_pound2pound_fr",
			labels:        [][]byte{labelB128Point, []byte("t0"), []byte("lab"), []byte("pound2pound"), []byte("fr")},
			attenduParent: "pound2pound.fr",
			attenduSLD:    "pound2pound",
			attenduTLD:    "fr",
			attenduSub:    string(labelB128Point) + ".t0.lab",
		},
		{
			nom:           "iodine_hidemyself_org",
			labels:        [][]byte{labelB128Point, []byte("hidemyself"), []byte("org")},
			attenduParent: "hidemyself.org",
			attenduSLD:    "hidemyself",
			attenduTLD:    "org",
			attenduSub:    string(labelB128Point),
		},
		{
			nom:           "suffixe_deux_niveaux_co_uk",
			labels:        [][]byte{labelB128Point, []byte("bbc"), []byte("co"), []byte("uk")},
			attenduParent: "bbc.co.uk",
			attenduSLD:    "bbc",
			attenduTLD:    "co.uk",
			attenduSub:    string(labelB128Point),
		},
		{
			nom:           "deux_labels_seulement_avec_points_internes",
			labels:        [][]byte{labelB128Point, []byte("org")},
			attenduParent: string(labelB128Point) + ".org",
			attenduSLD:    string(labelB128Point),
			attenduTLD:    "org",
			attenduSub:    "",
		},
	}
	for _, scenario := range cas {
		t.Run(scenario.nom, func(t *testing.T) {
			trame := questionFilaire(TypeNULL, scenario.labels...)
			var message DNSMessage
			if err := ParseDNSMessage(trame, &message); err != nil {
				t.Fatalf("ParseDNSMessage: %v", err)
			}
			if !message.HasNonLDH {
				t.Fatal("HasNonLDH attendu à vrai")
			}
			if got := string(message.ParentDomain[:message.ParentDomainLen]); got != scenario.attenduParent {
				t.Errorf("ParentDomain=%q, attendu %q", got, scenario.attenduParent)
			}
			if got := string(message.SLD[:message.SLDLen]); got != scenario.attenduSLD {
				t.Errorf("SLD=%q, attendu %q", got, scenario.attenduSLD)
			}
			if got := string(message.TLD[:message.TLDLen]); got != scenario.attenduTLD {
				t.Errorf("TLD=%q, attendu %q", got, scenario.attenduTLD)
			}
			if got := string(message.Subdomain[:message.SubdomainLen]); got != scenario.attenduSub {
				t.Errorf("Subdomain=%q, attendu %q", got, scenario.attenduSub)
			}
			allocations := testing.AllocsPerRun(200, func() {
				if err := ParseDNSMessage(trame, &message); err != nil {
					t.Fatal(err)
				}
			})
			if allocations != 0 {
				t.Errorf("allocations=%v, attendu 0", allocations)
			}
		})
	}
}

func TestV1_PCAPAndLabEvalTolerant_RealIodineAndBenignTwins(t *testing.T) {
	corpusDir, labSourceDir := trouverRepertoiresWittgensteinV1(t)
	labTemp := t.TempDir()
	entrees, err := os.ReadDir(labSourceDir)
	if err != nil {
		t.Fatalf("lecture %s: %v", labSourceDir, err)
	}
	for _, entree := range entrees {
		if entree.IsDir() {
			continue
		}
		nom := entree.Name()
		if strings.HasSuffix(nom, ".manifest.json") || strings.HasSuffix(nom, ".pcap") {
			copierFichierBorneV1(t, filepath.Join(labSourceDir, nom), filepath.Join(labTemp, nom))
		}
	}

	// Ajout d'un run bénin hors-LDH légitime (DNS-SD RFC 6763, punycode, UTF-8 local isolé)
	// pour éprouver l'absence de faux positifs sous EvaluateDNSLabFamiliesTolerant.
	questionsBenignes := [][]byte{
		questionFilaire(TypePTR, [][]byte{[]byte("Imprimante Salle.2"), []byte("_ipp"), []byte("_tcp"), []byte("hazyhaar"), []byte("fr")}...),
		questionFilaire(TypeSRV, [][]byte{[]byte("Poste Équipe"), []byte("_airplay"), []byte("_tcp"), []byte("hazyhaar"), []byte("fr")}...),
		questionFilaire(TypeA, labelsTextuels("xn--mnchen-3ya.hazyhaar.fr")...),
		questionFilaire(TypeA, labelsTextuels("café.hazyhaar.fr")...),
		questionFilaire(TypeA, labelsTextuels("café.hazyhaar.fr")...),
	}
	cheminPCAPBenin := filepath.Join(labTemp, "benign-dnssd-v1.pcap")
	if err := os.WriteFile(cheminPCAPBenin, ecrirePCAPQuestionsUDP53(t, questionsBenignes, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	manifesteBenin, err := json.Marshal(RedhostLabManifest{
		RunID:     "benign-dnssd-v1",
		Host:      "fixture-host",
		Interface: "lo",
		Filter:    "udp port 53",
		Resolver:  "10.55.0.53",
		Start:     "2026-10-31T10:00:00Z",
		End:       "2026-10-31T10:01:00Z",
		Label:     "benign-dnssd",
		Family:    "benign-dnssd",
		Note:      "jumeau négatif DNS-SD / punycode / UTF-8 isolé",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(labTemp, "benign-dnssd-v1.manifest.json"), manifesteBenin, 0o600); err != nil {
		t.Fatal(err)
	}

	// Ajout d'un run hostile Base128/NULL à labels courts contenant des octets >= 0x80 et '.' interne
	// (rejeté à 100 % en mode strict, ingéré et condamné par NonLDHBurstGuard en mode tolérant).
	var questionsB128 [][]byte
	for indice := range 8 {
		sous := []byte{0x85, '.', 0x90, byte(0xa0 + indice)}
		questionsB128 = append(questionsB128, questionFilaire(TypeNULL, sous, []byte("t0"), []byte("lab"), []byte("pound2pound"), []byte("fr")))
	}
	cheminPCAPB128 := filepath.Join(labTemp, "iodine-b128-v1.pcap")
	if err := os.WriteFile(cheminPCAPB128, ecrirePCAPQuestionsUDP53(t, questionsB128, nil), 0o600); err != nil {
		t.Fatal(err)
	}
	manifesteB128 := filepath.Join(labTemp, "iodine-b128-v1.manifest.json")
	encodageB128, err := json.Marshal(RedhostLabManifest{
		RunID:     "iodine-b128-v1",
		Host:      "redhost",
		Interface: "eth0",
		Filter:    "udp port 53",
		Resolver:  "10.55.0.53",
		Start:     "2026-10-31T10:02:00Z",
		End:       "2026-10-31T10:03:00Z",
		Label:     "redhost-iodine-b128",
		Family:    "redhost-iodine-b128",
		Note:      "salve Base128 >= 0x80 et QType NULL",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifesteB128, encodageB128, 0o600); err != nil {
		t.Fatal(err)
	}

	runStrict, err := IngestRedhostLabRun(cheminPCAPB128, manifesteB128)
	if err != nil {
		t.Fatalf("IngestRedhostLabRun: %v", err)
	}
	if runStrict.Stats.Accepted != 0 || runStrict.Stats.RejectedInvalidLabel != 8 {
		t.Fatalf("mode strict altéré: Accepted=%d RejectedInvalidLabel=%d, attendu 0 et 8", runStrict.Stats.Accepted, runStrict.Stats.RejectedInvalidLabel)
	}

	runTolerant, err := IngestRedhostLabRunTolerant(cheminPCAPB128, manifesteB128)
	if err != nil {
		t.Fatalf("IngestRedhostLabRunTolerant: %v", err)
	}
	if runTolerant.Stats.Accepted != 8 || len(runTolerant.Views) != 8 {
		t.Fatalf("mode tolérant: Accepted=%d Views=%d, attendu 8", runTolerant.Stats.Accepted, len(runTolerant.Views))
	}

	// Vérification sur la capture réelle iodine-20261027T151046Z : le mode strict reste figé à 5.
	iodineStrict, err := IngestRedhostLabRun(
		filepath.Join(labSourceDir, "iodine-20261027T151046Z.pcap"),
		filepath.Join(labSourceDir, "iodine-20261027T151046Z.manifest.json"),
	)
	if err != nil {
		t.Fatalf("IngestRedhostLabRun iodine réel: %v", err)
	}
	if iodineStrict.Stats.Accepted != 5 {
		t.Fatalf("compteur épinglé iodine strict=%d, attendu 5", iodineStrict.Stats.Accepted)
	}
	iodineTolerant, err := IngestRedhostLabRunTolerant(
		filepath.Join(labSourceDir, "iodine-20261027T151046Z.pcap"),
		filepath.Join(labSourceDir, "iodine-20261027T151046Z.manifest.json"),
	)
	if err != nil {
		t.Fatalf("IngestRedhostLabRunTolerant iodine réel: %v", err)
	}
	if iodineTolerant.Stats.Accepted < iodineStrict.Stats.Accepted {
		t.Fatalf("iodine tolérant Accepted=%d < strict=%d", iodineTolerant.Stats.Accepted, iodineStrict.Stats.Accepted)
	}

	cleHMAC := engine.WittgensteinFloppyKey(engine.FloppyFamilyDNSC2)
	bilanStrictBase, err := EvaluateDNSLabFamilies(corpusDir, labSourceDir, t.TempDir(), cleHMAC)
	if err != nil {
		t.Fatalf("EvaluateDNSLabFamilies base: %v", err)
	}
	if len(bilanStrictBase) == 0 {
		t.Fatal("aucune famille hostile de référence dans redhost_lab")
	}
	fpStrictBase := bilanStrictBase[0].Metrics.FP
	tnStrictBase := bilanStrictBase[0].Metrics.TN

	bilanTolerant, err := EvaluateDNSLabFamiliesTolerant(corpusDir, labTemp, t.TempDir(), cleHMAC)
	if err != nil {
		t.Fatalf("EvaluateDNSLabFamiliesTolerant: %v", err)
	}
	trouveB128 := false
	for _, ligne := range bilanTolerant {
		if ligne.Family == "redhost-iodine-b128" {
			trouveB128 = true
			if ligne.Questions != 8 || ligne.Metrics.TP < 7 || ligne.Metrics.L0Blocks < 7 {
				t.Errorf("redhost-iodine-b128 mal détecté: %+v", ligne)
			}
			// Les 5 questions bénignes hors LDH (DNS-SD RFC 6763, punycode, UTF-8 local)
			// doivent produire exactement 0 faux positif additionnel et +5 vrais négatifs.
			if ligne.Metrics.FP != fpStrictBase || ligne.Metrics.TN != tnStrictBase+5 {
				t.Errorf("bénin/DNS-SD/punycode: FP=%d (base=%d) TN=%d (base+5=%d)",
					ligne.Metrics.FP, fpStrictBase, ligne.Metrics.TN, tnStrictBase+5)
			}
		}
	}
	if !trouveB128 {
		t.Fatal("famille redhost-iodine-b128 absente du bilan tolérant")
	}
}

func TestA09_EvaluateDNSMessageWithReason_ResponseClientIP(t *testing.T) {
	pipeline, err := NewPipeline(PipelineConfig{}, nil)
	if err != nil {
		t.Fatalf("NewPipeline: %v", err)
	}
	defer pipeline.Close()

	adresseClientA := [16]byte{10, 55, 1, 10}
	adresseResolveur := [16]byte{10, 55, 1, 53}

	// 4 échanges bidirectionnels réalistes : requête TXT courte (client -> résolveur)
	// puis réponse TXT lourde >= 220 octets haute entropie (résolveur -> client, dstIP = adresseClientA).
	// Grâce à A-09, les réponses sont rattachées à adresseClientA et déclenchent P1.
	var verdict EvaluationResult
	var classe, raison string
	var derniereReponse []byte
	for echange := range 4 {
		identifiantTx := uint16(0x4100 + echange)
		requete := questionFilaire(TypeTXT, []byte("dl"), []byte("tunnel-a09"), []byte("org"))
		binary.BigEndian.PutUint16(requete[0:2], identifiantTx)

		reponse := make([]byte, 0, len(requete)+260)
		reponse = append(reponse, requete...)
		binary.BigEndian.PutUint16(reponse[2:4], 0x8180) // QR=1, RCode=0
		binary.BigEndian.PutUint16(reponse[6:8], 1)      // ANCount=1
		reponse = append(reponse, 0xc0, 0x0c)
		var enteteRR [10]byte
		binary.BigEndian.PutUint16(enteteRR[0:2], TypeTXT)
		binary.BigEndian.PutUint16(enteteRR[2:4], 1)
		binary.BigEndian.PutUint32(enteteRR[4:8], 60)
		const tailleCharge = 240
		binary.BigEndian.PutUint16(enteteRR[8:10], tailleCharge)
		reponse = append(reponse, enteteRR[:]...)
		for indice := range tailleCharge {
			reponse = append(reponse, byte((indice*73+echange*29+19)&0xff))
		}
		derniereReponse = reponse

		horodatage := int64(1_000_000 + echange*10_000)
		if _, _, _, errReq := pipeline.EvaluateDNSMessageWithReason(requete, horodatage, adresseClientA, adresseResolveur); errReq != nil {
			t.Fatalf("requête %d: %v", echange, errReq)
		}
		verdict, classe, raison, err = pipeline.EvaluateDNSMessageWithReason(reponse, horodatage+1_000, adresseResolveur, adresseClientA)
		if err != nil {
			t.Fatalf("réponse %d: %v", echange, err)
		}
	}
	if verdict.Decision != DecisionEscalateSLM || classe != "P1" || raison != engine.ReasonP1DownlinkExfil {
		t.Fatalf("verdict=%+v classe=%q raison=%q, attendu P1 / %s", verdict, classe, raison, engine.ReasonP1DownlinkExfil)
	}

	// Repli rétrocompatible : dstIP nul sur réponse utilise srcIP sans panique ni allocation.
	allocations := testing.AllocsPerRun(200, func() {
		_, _, _, errEval := pipeline.EvaluateDNSMessageWithReason(derniereReponse, 9_000_000, adresseClientA, [16]byte{})
		if errEval != nil {
			t.Fatal(errEval)
		}
	})
	if allocations != 0 {
		t.Fatalf("allocations=%v, attendu 0", allocations)
	}
}
