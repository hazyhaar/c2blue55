package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55"
	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

// TestMain relance le binaire de test comme c2forge quand C2FORGE_E2E vaut 1 :
// les tests de bout en bout exercent ainsi le vrai main, drapeaux compris.
func TestMain(m *testing.M) {
	if os.Getenv("C2FORGE_E2E") == "1" {
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// forge exécute c2forge avec args et rend sa sortie standard, sa sortie
// d'erreur et son code de retour.
func forge(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], args...)
	cmd.Env = append(os.Environ(), "C2FORGE_E2E=1")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("c2forge %v: %v", args, err)
	}
	return out.String(), errb.String(), code
}

func forgeOK(t *testing.T, args ...string) string {
	t.Helper()
	out, errOut, code := forge(t, args...)
	if code != 0 {
		t.Fatalf("c2forge %v: code %d\n%s%s", args, code, out, errOut)
	}
	return out
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

const e2eKey = "phrase-secrete-hote-phase5"

// e2eDelta est une fenêtre de maintenance apt de 02:00 à 05:00 UTC, du 27
// septembre au 5 octobre 2026, sur les cinq échelles journalières.
const e2eDelta = `{"rules": [{
  "id": 1, "label": "apt-nuit", "preset": "apt-maintenance",
  "not_before": "2026-09-27T00:00:00Z", "not_after": "2026-10-05T00:00:00Z",
  "hours": "02:00-05:00"
}]}`

// De bout en bout : ingestion de huit jours de journal dpkg, condensation en
// pyramides scellées HMAC, compilation d'une fenêtre de maintenance, puis
// évaluation d'une trace qui contient un état nominal, un état dévié dispensé
// par la fenêtre et le même état hors fenêtre, qui reste une anomalie.
func TestForge_PyramidDeltaEndToEnd(t *testing.T) {
	silo := t.TempDir()
	logs := t.TempDir()
	var train strings.Builder
	for d := 20; d <= 27; d++ {
		for m := range 30 {
			fmt.Fprintf(&train, "2026-09-%02d 09:%02d:00 status installed libc6:amd64 2.40-1\n", d, m)
		}
	}
	trainLog := filepath.Join(logs, "dpkg.log")
	writeFile(t, trainLog, train.String())
	out := forgeOK(t, "-oracle-ingest", trainLog, "-out-dir", silo, "-hmac-key", e2eKey)
	if !strings.Contains(out, "240 evenements") || !strings.Contains(out, "sceau HMAC-SHA256") {
		t.Fatalf("ingestion: %s", out)
	}
	// Les huit tranches forment une chaîne de sceaux intacte sous la clé.
	if out = forgeOK(t, "-oracle-verify-chain", "-out-dir", silo, "-hmac-key", e2eKey); !strings.Contains(out, "chaine des tranches .c2oracle intacte") {
		t.Fatalf("chaine: %s", out)
	}
	// Sans la clé, aucune tranche n'entre dans la baseline.
	if out = forgeOK(t, "-oracle-baseline", "-out-dir", silo); !strings.Contains(out, ": 0 etats") {
		t.Fatalf("baseline sans cle: %s", out)
	}
	if out = forgeOK(t, "-oracle-baseline", "-out-dir", silo, "-hmac-key", e2eKey); !strings.Contains(out, ": 240 etats") {
		t.Fatalf("baseline sous cle: %s", out)
	}

	out = forgeOK(t, "-oracle-condense", "-out-dir", silo, "-hmac-key", e2eKey)
	machine := c2blue55.DefaultSiloConfig(silo).MachineID
	for _, h := range []string{"24h", "7d", "30d", "120d", "365d"} {
		name := fmt.Sprintf("pyramid_%016x_%s.c2pyramid", machine, h)
		if _, err := os.Stat(filepath.Join(silo, name)); err != nil {
			t.Fatalf("pyramide %s absente: %v\n%s", h, err, out)
		}
	}
	if !strings.Contains(out, "HMAC-SHA256") {
		t.Fatalf("condensation sans sceau HMAC: %s", out)
	}
	// La pyramide produite se relit sous la clé, et seulement sous elle.
	p24 := filepath.Join(silo, fmt.Sprintf("pyramid_%016x_24h.c2pyramid", machine))
	data, err := os.ReadFile(p24)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := engine.LoadPyramidHMAC(bytes.NewReader(data), machine, []byte(e2eKey)); err != nil || p.Len() != 1 || p.Header().EpochEnd != p.Header().EpochStart {
		t.Fatalf("pyramide 24h: %v", err)
	}
	if _, err := engine.LoadPyramid(bytes.NewReader(data), machine); err == nil {
		t.Fatal("pyramide HMAC chargee sans cle")
	}

	desc := filepath.Join(logs, "delta.json")
	writeFile(t, desc, e2eDelta)
	catalog := filepath.Join(silo, "maintenance.c2delta")
	out = forgeOK(t, "-delta-compile", desc, "-delta-catalog", catalog, "-out-dir", silo, "-hmac-key", e2eKey)
	if !strings.Contains(out, "1 regles de dispense") || !strings.Contains(out, "creneaux 5..13") {
		t.Fatalf("compilation: %s", out)
	}

	evalDir := t.TempDir()
	trace := filepath.Join(evalDir, "dpkg.log")
	writeFile(t, trace, strings.Join([]string{
		"2026-09-28 09:10:00 status installed libc6:amd64 2.40-1",
		"2026-09-28 03:00:00 status half-installed libc6:amd64 2.40-1",
		"2026-09-28 15:00:00 status half-installed libc6:amd64 2.40-1",
	}, "\n")+"\n")
	out = forgeOK(t, "-oracle-eval", trace, "-out-dir", silo, "-delta-catalog", catalog, "-hmac-key", e2eKey)
	for _, want := range []string{
		"pyramides : 24h 7d 30d 120d 365d",
		"catalogue : 1 regles, HMAC-SHA256",
		"synthese : 3 evenements | base 30d : nominal 1, dispense 1, anomalie 1",
		"2026-09-28T03:00:00Z sub=5 act=6 sev=2 score=800 | base:DISPENSE#1",
		" 24h:D#1(", " 365d:D#1(",
		"2026-09-28T15:00:00Z sub=5 act=6 sev=2 score=800 | base:ANOMALIE",
		" 24h:A(",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("evaluation: %q absent\n%s", want, out)
		}
	}
	for _, h := range []string{"24h", "7d", "30d", "120d", "365d"} {
		if !strings.Contains(out, fmt.Sprintf("  %-5s : nominal 1, dispense 1, anomalie 1", h)) {
			t.Fatalf("evaluation, echelle %s:\n%s", h, out)
		}
	}
	if strings.Contains(out, "09:10:00Z") {
		t.Fatalf("etat nominal detaille sans -eval-verbose:\n%s", out)
	}
	if out = forgeOK(t, "-oracle-eval", trace, "-out-dir", silo, "-delta-catalog", catalog, "-hmac-key", e2eKey, "-eval-verbose"); !strings.Contains(out, "09:10:00Z sub=5 act=6 sev=1 score=980 | base:NOMINAL") {
		t.Fatalf("-eval-verbose:\n%s", out)
	}

	// Un échec d'authentification (High) n'est dispensé par aucune règle Medium.
	auth := filepath.Join(evalDir, "auth.log")
	writeFile(t, auth, "2026-09-28 03:10:00 sshd[42]: Failed password for root from 203.0.113.9 port 22\n")
	out = forgeOK(t, "-oracle-eval", auth, "-out-dir", silo, "-delta-catalog", catalog, "-hmac-key", e2eKey)
	if !strings.Contains(out, "base 30d : nominal 0, dispense 0, anomalie 1") || !strings.Contains(out, "  365d  : nominal 0, dispense 0, anomalie 1") {
		t.Fatalf("auth:\n%s", out)
	}
}

// Sans la bonne clé, ou sur un fichier altéré, -oracle-eval échoue au lieu
// d'évaluer contre une norme ou des dispenses non authentifiées.
func TestForge_EvalRefusesUnauthenticated(t *testing.T) {
	silo := t.TempDir()
	logs := t.TempDir()
	var train strings.Builder
	for m := range 20 {
		fmt.Fprintf(&train, "2026-09-27 09:%02d:00 status installed libc6:amd64 2.40-1\n", m)
	}
	trainLog := filepath.Join(logs, "dpkg.log")
	writeFile(t, trainLog, train.String())
	forgeOK(t, "-oracle-ingest", trainLog, "-out-dir", silo, "-hmac-key", "hex:00112233445566778899aabbccddeeff")
	forgeOK(t, "-oracle-condense", "-out-dir", silo, "-hmac-key", "hex:00112233445566778899aabbccddeeff", "-condense-scales", "24h,7d")
	desc := filepath.Join(logs, "delta.json")
	writeFile(t, desc, e2eDelta)
	catalog := filepath.Join(silo, "m.c2delta")
	forgeOK(t, "-delta-compile", desc, "-delta-catalog", catalog, "-out-dir", silo, "-hmac-key", "hex:00112233445566778899aabbccddeeff")

	trace := filepath.Join(logs, "trace-dpkg.log")
	writeFile(t, trace, "2026-09-28 09:10:00 status installed libc6:amd64 2.40-1\n")
	good := []string{"-oracle-eval", trace, "-out-dir", silo, "-delta-catalog", catalog, "-hmac-key", "hex:00112233445566778899aabbccddeeff"}
	if out := forgeOK(t, good...); !strings.Contains(out, "pyramides : 24h 7d |") {
		t.Fatalf("echelles choisies:\n%s", out)
	}
	keyFile := filepath.Join(logs, "cle")
	writeFile(t, keyFile, "phrase-secrete-hote-phase5\n")
	for name, key := range map[string]string{
		"sans cle":    "",
		"autre cle":   "hex:ffeeddccbbaa99887766554433221100",
		"cle fichier": "file:" + keyFile,
	} {
		out, errOut, code := forge(t, "-oracle-eval", trace, "-out-dir", silo, "-delta-catalog", catalog, "-hmac-key", key)
		if code == 0 || !strings.Contains(errOut, "HMAC-SHA256 invalide") {
			t.Fatalf("%s: code %d\n%s%s", name, code, out, errOut)
		}
	}
	if _, errOut, code := forge(t, "-oracle-eval", trace, "-out-dir", silo, "-hmac-key", "court"); code == 0 || !strings.Contains(errOut, "cle HMAC de moins de") {
		t.Fatalf("cle courte: code %d %s", code, errOut)
	}
	// Un octet de prototype altéré dans une pyramide fait échouer le chargement entier.
	machine := c2blue55.DefaultSiloConfig(silo).MachineID
	p7 := filepath.Join(silo, fmt.Sprintf("pyramid_%016x_7d.c2pyramid", machine))
	data, err := os.ReadFile(p7)
	if err != nil {
		t.Fatal(err)
	}
	data[engine.PyramidHeaderSize+64] ^= 1 // rayon du premier prototype
	writeFile(t, p7, string(data))
	if _, errOut, code := forge(t, good...); code == 0 || !strings.Contains(errOut, p7) {
		t.Fatalf("pyramide alteree: code %d %s", code, errOut)
	}
}

// Descriptions refusées : champ inconnu, préréglage inconnu, règle éternelle,
// et absence de -delta-catalog.
func TestForge_DeltaCompileRefuses(t *testing.T) {
	dir := t.TempDir()
	for name, desc := range map[string]string{
		"champ inconnu": `{"rules":[{"id":1,"label":"x","preset":"apt-maintenance","not_before":"2026-09-27T00:00:00Z","not_after":"2026-10-05T00:00:00Z","radis":3}]}`,
		"preset":        `{"rules":[{"id":1,"label":"x","preset":"tout-dispenser","not_before":"2026-09-27T00:00:00Z","not_after":"2026-10-05T00:00:00Z"}]}`,
		"eternelle":     `{"rules":[{"id":1,"label":"x","preset":"apt-maintenance","not_before":"2026-10-05T00:00:00Z","not_after":"2026-09-27T00:00:00Z"}]}`,
		"minuit":        `{"rules":[{"id":1,"label":"x","preset":"apt-maintenance","not_before":"2026-09-27T00:00:00Z","not_after":"2026-10-05T00:00:00Z","hours":"23:00-01:00"}]}`,
	} {
		path := filepath.Join(dir, "d.json")
		writeFile(t, path, desc)
		if _, errOut, code := forge(t, "-delta-compile", path, "-delta-catalog", filepath.Join(dir, "c.c2delta"), "-out-dir", dir); code != 1 {
			t.Fatalf("%s: code %d %s", name, code, errOut)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "c.c2delta")); err == nil {
		t.Fatal("catalogue ecrit malgre le refus")
	}
	path := filepath.Join(dir, "ok.json")
	writeFile(t, path, e2eDelta)
	if _, errOut, code := forge(t, "-delta-compile", path, "-out-dir", dir); code != 1 || !strings.Contains(errOut, "-delta-catalog") {
		t.Fatalf("sans -delta-catalog: code %d %s", code, errOut)
	}
}

// TestForge_HMACKeyRefusesEmptySpec vérifie que hex: vide ou file: vide sont rejetés
// avec une erreur explicite pour empêcher tout déclassement silencieux vers SHA-256.
func TestForge_HMACKeyRefusesEmptySpec(t *testing.T) {
	dir := t.TempDir()
	emptyFile := filepath.Join(dir, "empty.key")
	writeFile(t, emptyFile, "\n\r\n")

	for name, keyFlag := range map[string]string{
		"hex vide":  "hex:",
		"file vide": "file:" + emptyFile,
	} {
		_, errOut, code := forge(t, "-oracle-condense", "-out-dir", dir, "-hmac-key", keyFlag)
		if code == 0 || (!strings.Contains(errOut, "vide") && !strings.Contains(errOut, "ErrSealKey")) {
			t.Fatalf("%s: attendu échec avec mention 'vide', obtenu code %d: %s", name, code, errOut)
		}
	}
}
