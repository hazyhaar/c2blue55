package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hazyhaar/c2blue55"
)

func construireFixturePCAPForge(t *testing.T, portServeur uint16, chargesMontantes, chargesDescendantes []int, pasNs uint64) []byte {
	t.Helper()
	var tampon bytes.Buffer
	var entete [24]byte
	binary.LittleEndian.PutUint32(entete[0:4], 0xa1b23c4d)
	binary.LittleEndian.PutUint16(entete[4:6], 2)
	binary.LittleEndian.PutUint16(entete[6:8], 4)
	binary.LittleEndian.PutUint32(entete[16:20], 65535)
	binary.LittleEndian.PutUint32(entete[20:24], 1)
	tampon.Write(entete[:])

	instant := uint64(1_000_000_000)
	ecrireTrame := func(montant bool, taille int, horodatage uint64) {
		trame := make([]byte, 14+20+8+taille)
		binary.BigEndian.PutUint16(trame[12:14], 0x0800)
		ip := trame[14:]
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(20+8+taille))
		ip[8] = 64
		ip[9] = 17
		udp := ip[20:]
		if montant {
			copy(ip[12:16], []byte{10, 0, 0, 2})
			copy(ip[16:20], []byte{192, 0, 2, 53})
			binary.BigEndian.PutUint16(udp[0:2], 52000)
			binary.BigEndian.PutUint16(udp[2:4], portServeur)
		} else {
			copy(ip[12:16], []byte{192, 0, 2, 53})
			copy(ip[16:20], []byte{10, 0, 0, 2})
			binary.BigEndian.PutUint16(udp[0:2], portServeur)
			binary.BigEndian.PutUint16(udp[2:4], 52000)
		}
		binary.BigEndian.PutUint16(udp[4:6], uint16(8+taille))
		if taille > 0 {
			udp[8] = 0x40
		}
		var enregistrement [16]byte
		binary.LittleEndian.PutUint32(enregistrement[0:4], uint32(horodatage/1e9))
		binary.LittleEndian.PutUint32(enregistrement[4:8], uint32(horodatage%1e9))
		binary.LittleEndian.PutUint32(enregistrement[8:12], uint32(len(trame)))
		binary.LittleEndian.PutUint32(enregistrement[12:16], uint32(len(trame)))
		tampon.Write(enregistrement[:])
		tampon.Write(trame)
	}

	tours := min(len(chargesMontantes), len(chargesDescendantes))
	for indice := range tours {
		ecrireTrame(true, chargesMontantes[indice], instant)
		ecrireTrame(false, chargesDescendantes[indice], instant+15_000_000)
		instant += pasNs
	}
	return tampon.Bytes()
}

func lireFichierJSONBorne(t *testing.T, chemin string) []byte {
	t.Helper()
	fichier, err := os.Open(chemin)
	if err != nil {
		t.Fatalf("ouverture %s: %v", chemin, err)
	}
	contenu, errLecture := io.ReadAll(io.LimitReader(fichier, 8<<20))
	errFermeture := fichier.Close()
	if errLecture != nil || errFermeture != nil {
		t.Fatalf("lecture %s: %v / %v", chemin, errLecture, errFermeture)
	}
	return contenu
}

func TestRunEncryptedEval_SinglePCAPAndOut(t *testing.T) {
	repertoire := t.TempDir()
	cheminCapture := filepath.Join(repertoire, "fixture-doq-r0a.pcap")
	montants := []int{110, 120, 95, 130}
	descendants := []int{220, 260, 180, 240}
	if err := os.WriteFile(cheminCapture, construireFixturePCAPForge(t, 853, montants, descendants, 2_000_000_000), 0o600); err != nil {
		t.Fatal(err)
	}

	// 1. Sortie directe JSON sur output sans -out (via dispatchSubcommand).
	var sortieDirecte bytes.Buffer
	prisEnCharge, code, err := dispatchSubcommand("encrypted-eval", []string{"-pcap", cheminCapture}, &sortieDirecte)
	if !prisEnCharge || code != 0 || err != nil {
		t.Fatalf("dispatchSubcommand: prisEnCharge=%t code=%d err=%v", prisEnCharge, code, err)
	}
	var constatDirect c2blue55.EncryptedWireCapture
	if err := json.Unmarshal(sortieDirecte.Bytes(), &constatDirect); err != nil {
		t.Fatalf("JSON direct invalide: %v\n%s", err, sortieDirecte.String())
	}
	if len(constatDirect.Conversations) != 1 || constatDirect.Conversations[0].RegimeLabel != "R0a" || constatDirect.SHA256 == "" {
		t.Fatalf("constat direct inattendu: %+v", constatDirect)
	}

	// 2. Écriture atomique via -out.
	cheminSortie := filepath.Join(repertoire, "rapport-pcap.json")
	var sortieResume bytes.Buffer
	code, err = runEncryptedEval([]string{"-pcap", cheminCapture, "-out", cheminSortie}, &sortieResume)
	if code != 0 || err != nil {
		t.Fatalf("runEncryptedEval -out: code=%d err=%v", code, err)
	}
	var constatFichier c2blue55.EncryptedWireCapture
	if err := json.Unmarshal(lireFichierJSONBorne(t, cheminSortie), &constatFichier); err != nil {
		t.Fatalf("JSON fichier invalide: %v", err)
	}
	if constatFichier.SHA256 != constatDirect.SHA256 || constatFichier.Conversations[0].RegimeLabel != "R0a" {
		t.Fatalf("constat fichier divergent: %+v", constatFichier)
	}
}

func TestRunEncryptedEval_ManifestLOFOAndRejects(t *testing.T) {
	repertoire := t.TempDir()
	type entreeManifeste struct {
		Path           string `json:"path"`
		Family         string `json:"family"`
		RunID          string `json:"run_id"`
		Hostile        bool   `json:"hostile"`
		ExpectedRegime string `json:"expected_regime,omitempty"`
	}

	var entrees []entreeManifeste
	generateur := rand.New(rand.NewPCG(19, 73))

	// Famille bénigne 1 : R0a sporadique (12 captures)
	for indice := range 12 {
		chemin := filepath.Join(repertoire, "fixture-b1-"+string(rune('a'+indice))+".pcap")
		montants := []int{100 + generateur.IntN(30), 110 + generateur.IntN(30), 95 + generateur.IntN(30), 105 + generateur.IntN(30)}
		descendants := []int{200 + generateur.IntN(60), 240 + generateur.IntN(60), 190 + generateur.IntN(60), 210 + generateur.IntN(60)}
		if err := os.WriteFile(chemin, construireFixturePCAPForge(t, 853, montants, descendants, 3_000_000_000), 0o600); err != nil {
			t.Fatal(err)
		}
		entrees = append(entrees, entreeManifeste{Path: chemin, Family: "fixture-benign-r0a", RunID: filepath.Base(chemin), Hostile: false, ExpectedRegime: "R0a"})
	}
	// Famille bénigne 2 : keepalive court 45 octets (12 captures, total bénin = 24 >= 20)
	for indice := range 12 {
		chemin := filepath.Join(repertoire, "fixture-b2-"+string(rune('a'+indice))+".pcap")
		montants := []int{45, 45, 45, 45, 45, 45}
		descendants := []int{45, 45, 45, 45, 45, 45}
		if err := os.WriteFile(chemin, construireFixturePCAPForge(t, 853, montants, descendants, 15_000_000_000), 0o600); err != nil {
			t.Fatal(err)
		}
		entrees = append(entrees, entreeManifeste{Path: chemin, Family: "fixture-benign-keepalive", RunID: filepath.Base(chemin), Hostile: false, ExpectedRegime: "R0a"})
	}
	// Famille hostile : R1b balise régulière toutes les 60 s sur >= 7 rafales porteuses (20 captures)
	for indice := range 20 {
		chemin := filepath.Join(repertoire, "fixture-h1-"+string(rune('a'+indice))+".pcap")
		montants := make([]int, 8)
		descendants := make([]int, 8)
		for tour := range 8 {
			montants[tour] = 320 + generateur.IntN(10)
			descendants[tour] = 380 + generateur.IntN(15)
		}
		if err := os.WriteFile(chemin, construireFixturePCAPForge(t, 443, montants, descendants, 60_000_000_000), 0o600); err != nil {
			t.Fatal(err)
		}
		entrees = append(entrees, entreeManifeste{Path: chemin, Family: "fixture-redhost-balise", RunID: filepath.Base(chemin), Hostile: true, ExpectedRegime: "R1b"})
	}

	cheminManifeste := filepath.Join(repertoire, "manifest.json")
	octetsManifeste, err := json.MarshalIndent(entrees, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cheminManifeste, octetsManifeste, 0o600); err != nil {
		t.Fatal(err)
	}
	cheminRapport := filepath.Join(repertoire, "lofo-report.json")
	var sortie bytes.Buffer
	code, err := runEncryptedEval([]string{"-manifest", cheminManifeste, "-report", cheminRapport}, &sortie)
	if code != 0 || err != nil {
		t.Fatalf("runEncryptedEval -manifest: code=%d err=%v", code, err)
	}

	var rapport c2blue55.EncryptedWireLabReport
	if err := json.Unmarshal(lireFichierJSONBorne(t, cheminRapport), &rapport); err != nil {
		t.Fatalf("rapport LOFO invalide: %v", err)
	}
	if len(rapport.FamillesHostiles) != 1 || len(rapport.FamillesBenignes) != 2 {
		t.Fatalf("familles=%d/%d, attendu 1 hostile et 2 bénignes", len(rapport.FamillesHostiles), len(rapport.FamillesBenignes))
	}
	bilanHostile := rapport.FamillesHostiles[0]
	if bilanHostile.ROCAUC != 1 || bilanHostile.TPR != 1 || bilanHostile.FPR != 0 || bilanHostile.MajorityClassRate <= 0 {
		t.Fatalf("bilan hostile inattendu: %+v", bilanHostile)
	}
	if rapport.MatriceRegimes[0][0] != 24 || rapport.MatriceRegimes[3][3] != 20 {
		t.Fatalf("MatriceRegimes=%v, attendu 24 en [0][0] et 20 en [3][3]", rapport.MatriceRegimes)
	}

	// Jumeaux négatifs CLI : drapeaux incohérents et manifeste corrompu refusés en fail-closed.
	if codeErr, errInvalide := runEncryptedEval([]string{"-pcap", entrees[0].Path, "-manifest", cheminManifeste}, &sortie); codeErr == 0 || errInvalide == nil {
		t.Fatal("combinaison -pcap et -manifest aurait dû échouer")
	}
	cheminManifesteInvalide := filepath.Join(repertoire, "manifest-invalide.json")
	if err := os.WriteFile(cheminManifesteInvalide, []byte(`[{"path":"","family":"x","run_id":"r1","hostile":true}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	cheminRapportAbsent := filepath.Join(repertoire, "ne-doit-pas-exister.json")
	if codeErr, errInvalide := runEncryptedEval([]string{"-manifest", cheminManifesteInvalide, "-report", cheminRapportAbsent}, &sortie); codeErr == 0 || errInvalide == nil {
		t.Fatal("manifeste à chemin vide aurait dû échouer")
	}
	if _, errStat := os.Stat(cheminRapportAbsent); !os.IsNotExist(errStat) {
		t.Fatal("aucun rapport ne doit être écrit en cas d'échec")
	}
}

func TestRunLabEval_TolerantFlag(t *testing.T) {
	repertoireCourant, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	racineGit := repertoireCourant
	for {
		if _, errStat := os.Lstat(filepath.Join(racineGit, ".git")); errStat == nil {
			break
		}
		parent := filepath.Dir(racineGit)
		if parent == racineGit {
			t.Fatalf("aucun .git au-dessus de %s", repertoireCourant)
		}
		racineGit = parent
	}
	var corpusDir, labSourceDir string
	for _, candidat := range []string{
		filepath.Join(racineGit, "wittgenstein"),
		filepath.Join(racineGit, "..", "wittgenstein"),
		filepath.Join(racineGit, "..", "..", "..", "wittgenstein"),
	} {
		testLab := filepath.Join(candidat, "redhost_lab")
		if etat, errStat := os.Stat(testLab); errStat == nil && etat.IsDir() {
			corpusDir, labSourceDir = candidat, testLab
			break
		}
	}
	if labSourceDir == "" {
		t.Fatalf("wittgenstein/redhost_lab introuvable depuis %s", racineGit)
	}

	labTemp := t.TempDir()
	entrees, err := os.ReadDir(labSourceDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entree := range entrees {
		if !entree.IsDir() && (strings.HasSuffix(entree.Name(), ".manifest.json") || strings.HasSuffix(entree.Name(), ".pcap")) {
			octets := lireFichierJSONBorne(t, filepath.Join(labSourceDir, entree.Name()))
			if err := os.WriteFile(filepath.Join(labTemp, entree.Name()), octets, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	cheminRapport := filepath.Join(t.TempDir(), "lab-tolerant.json")
	var sortie bytes.Buffer
	code, err := runLabEval([]string{
		"-tolerant",
		"-data", corpusDir,
		"-lab", labTemp,
		"-out", t.TempDir(),
		"-report", cheminRapport,
	}, &sortie)
	if code != 0 || err != nil {
		t.Fatalf("runLabEval -tolerant: code=%d err=%v", code, err)
	}
	if !strings.Contains(sortie.String(), "redhost-iodine") {
		t.Fatalf("sortie lab-eval -tolerant inattendue: %s", sortie.String())
	}
}
