package c2blue55

import (
	"archive/zip"
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/engine"
)

const (
	cheminMonographieMD   = "docs/why_micro_optimization_is_a_security_choice.md"
	cheminMonographieDOCX = "docs/why_micro_optimization_is_a_security_choice.docx"
	borneLectureDocOctets = 16 << 20
)

type contenuDocxExtrait struct {
	paragraphes    []string
	lignesParTable []int
	texteComplet   string
}

func lireFichierEntierBorne(chemin string) ([]byte, error) {
	f, err := os.Open(chemin)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	donnees, err := io.ReadAll(io.LimitReader(f, borneLectureDocOctets+1))
	if err != nil {
		return nil, err
	}
	if len(donnees) > borneLectureDocOctets {
		return nil, fmt.Errorf("%s depasse la borne de %d octets", chemin, borneLectureDocOctets)
	}
	return donnees, nil
}

func extraireDocxComplet(octetsZip []byte) (contenuDocxExtrait, error) {
	var resultat contenuDocxExtrait
	zr, err := zip.NewReader(bytes.NewReader(octetsZip), int64(len(octetsZip)))
	if err != nil {
		return resultat, err
	}

	var xmlDoc []byte
	for _, entree := range zr.File {
		if entree.Name != "word/document.xml" {
			continue
		}
		rc, errOpen := entree.Open()
		if errOpen != nil {
			return resultat, errOpen
		}
		lu, errRead := io.ReadAll(io.LimitReader(rc, borneLectureDocOctets+1))
		_ = rc.Close()
		if errRead != nil {
			return resultat, errRead
		}
		if len(lu) > borneLectureDocOctets {
			return resultat, errors.New("word/document.xml depasse 16 Mio")
		}
		xmlDoc = lu
		break
	}
	if len(xmlDoc) == 0 {
		return resultat, errors.New("word/document.xml introuvable")
	}

	decodeur := xml.NewDecoder(bytes.NewReader(xmlDoc))
	var paraCourant strings.Builder
	dansParagraphe := false
	dansTexte := false
	profondeurTable := 0
	lignesTableCourante := 0
	var toutTexte strings.Builder

	for {
		jeton, errTok := decodeur.Token()
		if errors.Is(errTok, io.EOF) {
			break
		}
		if errTok != nil {
			return resultat, errTok
		}
		switch elem := jeton.(type) {
		case xml.StartElement:
			switch elem.Name.Local {
			case "tbl":
				profondeurTable++
				if profondeurTable == 1 {
					lignesTableCourante = 0
				}
			case "tr":
				if profondeurTable == 1 {
					lignesTableCourante++
				}
			case "p":
				dansParagraphe = true
				paraCourant.Reset()
			case "t":
				dansTexte = true
			case "br", "tab":
				if dansParagraphe {
					paraCourant.WriteByte(' ')
				}
			}
		case xml.EndElement:
			switch elem.Name.Local {
			case "t":
				dansTexte = false
			case "p":
				if dansParagraphe {
					textePara := strings.Join(strings.Fields(paraCourant.String()), " ")
					if textePara != "" {
						resultat.paragraphes = append(resultat.paragraphes, textePara)
						toutTexte.WriteString(textePara)
						toutTexte.WriteByte('\n')
					}
					dansParagraphe = false
				}
			case "tbl":
				if profondeurTable == 1 {
					resultat.lignesParTable = append(resultat.lignesParTable, lignesTableCourante)
				}
				if profondeurTable > 0 {
					profondeurTable--
				}
			}
		case xml.CharData:
			if dansTexte && dansParagraphe {
				paraCourant.Write(elem)
			}
		}
	}
	resultat.texteComplet = toutTexte.String()
	return resultat, nil
}

func nettoyerTitreMarkdown(ligne string) string {
	sansHashes := strings.TrimSpace(strings.TrimLeft(ligne, "#"))
	sansCode := strings.ReplaceAll(sansHashes, "`", "")
	sansGras := strings.ReplaceAll(sansCode, "**", "")
	sansItal := strings.ReplaceAll(sansGras, "*", "")
	return strings.Join(strings.Fields(sansItal), " ")
}

func extraireStructureMarkdown(texteMD string) (titres []string, lignesParTable []int) {
	lignes := strings.Split(texteMD, "\n")
	dansBlocCode := false
	lignesTableCourante := 0
	dansTable := false

	for _, brute := range lignes {
		trim := strings.TrimSpace(brute)
		if strings.HasPrefix(trim, "```") {
			dansBlocCode = !dansBlocCode
			if dansTable {
				lignesParTable = append(lignesParTable, lignesTableCourante)
				dansTable = false
				lignesTableCourante = 0
			}
			continue
		}
		if dansBlocCode {
			continue
		}
		if strings.HasPrefix(trim, "# ") || strings.HasPrefix(trim, "## ") || strings.HasPrefix(trim, "### ") {
			if dansTable {
				lignesParTable = append(lignesParTable, lignesTableCourante)
				dansTable = false
				lignesTableCourante = 0
			}
			titre := nettoyerTitreMarkdown(trim)
			if titre != "" {
				titres = append(titres, titre)
			}
			continue
		}
		if strings.HasPrefix(trim, "|") && strings.HasSuffix(trim, "|") {
			sansBarres := strings.Trim(trim, "| ")
			estSeparateur := sansBarres != ""
			for _, r := range sansBarres {
				if r != '-' && r != ':' && r != '|' && r != ' ' {
					estSeparateur = false
					break
				}
			}
			if !dansTable {
				dansTable = true
				lignesTableCourante = 0
			}
			if !estSeparateur {
				lignesTableCourante++
			}
			continue
		}
		if dansTable && trim == "" {
			lignesParTable = append(lignesParTable, lignesTableCourante)
			dansTable = false
			lignesTableCourante = 0
		}
	}
	if dansTable && lignesTableCourante > 0 {
		lignesParTable = append(lignesParTable, lignesTableCourante)
	}
	return titres, lignesParTable
}

func formaterMilliersAnglais(n int) string {
	if n < 1000 {
		return strconv.Itoa(n)
	}
	return fmt.Sprintf("%d,%03d", n/1000, n%1000)
}

func verifierContenuMonographie(
	texteMD string,
	docx contenuDocxExtrait,
	jetonsAttendus []string,
	jetonsInterdits []string,
) []string {
	var anomalies []string

	for _, interdit := range jetonsInterdits {
		if strings.Contains(texteMD, interdit) {
			anomalies = append(anomalies, fmt.Sprintf("%s contient encore l'affirmation obsolete/fausse %q", cheminMonographieMD, interdit))
		}
		if strings.Contains(docx.texteComplet, interdit) {
			anomalies = append(anomalies, fmt.Sprintf("%s contient encore l'affirmation obsolete/fausse %q", cheminMonographieDOCX, interdit))
		}
	}

	for _, attendu := range jetonsAttendus {
		if !strings.Contains(texteMD, attendu) {
			anomalies = append(anomalies, fmt.Sprintf("%s omet le fait verifie %q", cheminMonographieMD, attendu))
		}
		if !strings.Contains(docx.texteComplet, attendu) {
			anomalies = append(anomalies, fmt.Sprintf("%s omet le fait verifie %q", cheminMonographieDOCX, attendu))
		}
	}

	titresMD, tablesMD := extraireStructureMarkdown(texteMD)
	if len(titresMD) < 18 {
		anomalies = append(anomalies, fmt.Sprintf("%s compte trop peu de sections structurees (%d)", cheminMonographieMD, len(titresMD)))
	}

	curseurPara := 0
	for _, titre := range titresMD {
		trouve := false
		for curseurPara < len(docx.paragraphes) {
			if docx.paragraphes[curseurPara] == titre {
				trouve = true
				curseurPara++
				break
			}
			curseurPara++
		}
		if !trouve {
			anomalies = append(anomalies, fmt.Sprintf("%s desaligne de %s : titre absent ou hors ordre %q", cheminMonographieDOCX, cheminMonographieMD, titre))
			curseurPara = 0
		}
	}

	if len(tablesMD) < 2 {
		anomalies = append(anomalies, fmt.Sprintf("%s doit comporter au moins 2 tables empiriques, obtenu %d", cheminMonographieMD, len(tablesMD)))
	}
	if len(docx.lignesParTable) != len(tablesMD) {
		anomalies = append(anomalies, fmt.Sprintf("%s compte %d tables Word contre %d tables dans %s",
			cheminMonographieDOCX, len(docx.lignesParTable), len(tablesMD), cheminMonographieMD))
	} else {
		for idx := range tablesMD {
			if docx.lignesParTable[idx] != tablesMD[idx] {
				anomalies = append(anomalies, fmt.Sprintf("%s table %d compte %d lignes contre %d dans %s",
					cheminMonographieDOCX, idx+1, docx.lignesParTable[idx], tablesMD[idx], cheminMonographieMD))
			}
		}
	}

	return anomalies
}

func TestMonographTruthfulnessAndDocxParity(t *testing.T) {
	// 1. Mesure directe sur le moteur réel (fenêtre 4 096 octets) pour dériver les attendus.
	if engine.PageSize != 4096 {
		t.Fatalf("%s : PageSize inattendu %d", cheminMonographieMD, engine.PageSize)
	}

	dataDir := resolveWittgensteinDataDir(t)
	cascade, _, _ := setupWittgensteinEngine(t)
	arena := engine.DefaultArenaPool()
	seq := uint64(1)
	evaluer := func(sub, act uint16, charge []byte) (engine.Probe_event_t, engine.CascadeVerdict) {
		var ev engine.Probe_event_t
		ev.Ts_ns = 1727630000000000000 + seq
		ev.Subsystem = sub
		ev.Action = act
		arena.StorePayload(&ev, charge)
		seq++
		return ev, cascade.EvaluateEvent(&ev)
	}

	shells, errShells := engine.LoadReverseShellPayloads(filepath.Join(dataDir, "reverse_shells.jsonl"))
	if errShells != nil {
		t.Fatalf("%s : lecture reverse_shells.jsonl : %v", cheminMonographieMD, errShells)
	}
	nTrain := engine.ReverseShellTrainCount(len(shells))
	holdout := shells[nTrain:]

	var bilanHoldout, bilanVariantes verdictTally
	variantes := []struct{ ip, port string }{
		{"172.16.99.23", "9001"},
		{"192.168.56.101", "8443"},
		{"198.51.100.7", "53"},
	}
	for _, s := range holdout {
		_, v := evaluer(SubProc, ActExec, []byte(s))
		bilanHoldout.add(v)
		for _, vr := range variantes {
			mutee := ipPortVariant(s, vr.ip, vr.port)
			if mutee == s {
				continue
			}
			_, vm := evaluer(SubProc, ActExec, []byte(mutee))
			bilanVariantes.add(vm)
		}
	}

	var bilanAdminBrut, bilanAdminTrain, bilanAdminTTY verdictTally
	ctxTTY := engine.DeriveCascadeContext(engine.ProcessProvenance{
		PID: 4242, UID: 1000, EUID: 1000, LoginSession: true, HasTTY: true, ExeTarget: []byte("/usr/bin/bash"),
	})
	for idx, cmd := range engine.BenignAdminCommands() {
		ev, v := evaluer(SubProc, ActExec, []byte(cmd))
		if engine.IsBenignTrainIndex(idx) {
			bilanAdminTrain.add(v)
			continue
		}
		bilanAdminBrut.add(v)
		bilanAdminTTY.add(cascade.EvaluateEventCtx(&ev, ctxTTY))
	}

	fDNS, errDNS := os.Open(filepath.Join(dataDir, "netrack_dns", "validate.csv"))
	if errDNS != nil {
		t.Fatalf("%s : lecture validate.csv : %v", cheminMonographieMD, errDNS)
	}
	defer fDNS.Close()
	lecteurCSV := csv.NewReader(fDNS)
	var bilanDNSC2, bilanDNSBenin verdictTally
	for {
		ligne, errLigne := lecteurCSV.Read()
		if errors.Is(errLigne, io.EOF) {
			break
		}
		if errLigne != nil || len(ligne) < 2 {
			continue
		}
		_, v := evaluer(SubNet, ActConnect, []byte(strings.TrimSpace(ligne[1])))
		switch strings.TrimSpace(ligne[0]) {
		case "1":
			bilanDNSC2.add(v)
		case "0":
			bilanDNSBenin.add(v)
		}
	}

	jetonsAttendus := []string{
		formaterMilliersAnglais(engine.PageSize),
		"GOEXPERIMENT=simd",
		fmt.Sprintf("%d/%d", bilanHoldout.block, bilanHoldout.n),
		fmt.Sprintf("%.2f%%", pct(bilanHoldout.block, bilanHoldout.n)),
		fmt.Sprintf("%d/%d", bilanHoldout.quarantine, bilanHoldout.n),
		fmt.Sprintf("%.2f%%", pct(bilanHoldout.quarantine, bilanHoldout.n)),
		fmt.Sprintf("%d/%d", bilanVariantes.block, bilanVariantes.n),
		fmt.Sprintf("%.2f%%", pct(bilanVariantes.block, bilanVariantes.n)),
		fmt.Sprintf("%d/%d", bilanVariantes.quarantine, bilanVariantes.n),
		fmt.Sprintf("%.2f%%", pct(bilanVariantes.quarantine, bilanVariantes.n)),
		fmt.Sprintf("%d/%d", bilanAdminBrut.quarantine, bilanAdminBrut.n),
		fmt.Sprintf("%.2f%%", pct(bilanAdminBrut.quarantine, bilanAdminBrut.n)),
		fmt.Sprintf("%d/%d", bilanAdminBrut.pass, bilanAdminBrut.n),
		fmt.Sprintf("%.2f%%", pct(bilanAdminBrut.pass, bilanAdminBrut.n)),
		fmt.Sprintf("%d/%d", bilanAdminTrain.quarantine, bilanAdminTrain.n),
		fmt.Sprintf("%.2f%%", pct(bilanAdminTrain.quarantine, bilanAdminTrain.n)),
		fmt.Sprintf("%d/%d", bilanAdminTrain.block, bilanAdminTrain.n),
		fmt.Sprintf("%.2f%%", pct(bilanAdminTrain.block, bilanAdminTrain.n)),
		fmt.Sprintf("%s/%s", formaterMilliersAnglais(bilanDNSC2.block), formaterMilliersAnglais(bilanDNSC2.n)),
		fmt.Sprintf("%.2f%%", pct(bilanDNSC2.block, bilanDNSC2.n)),
		fmt.Sprintf("%d/%s", bilanDNSC2.quarantine, formaterMilliersAnglais(bilanDNSC2.n)),
		fmt.Sprintf("%.2f%%", pct(bilanDNSC2.quarantine, bilanDNSC2.n)),
		strconv.Itoa(bilanDNSBenin.byStage[engine.StageL1a][engine.VerdictPass]),
		strconv.Itoa(bilanDNSBenin.byStage[engine.StageL1b][engine.VerdictPass]),
		engine.ReasonP14NegativeAnswerPayload,
		engine.ReasonP15RDataRenewal,
		ReasonDNSParseError,
		"part_resolveur_permille",
		"FinalizeWithHosts",
		"StripLeadingRFCUnderscoreLabels",
		"27.6%",
		"doh3-shared-conn-vaydns-transit",
	}

	jetonsInterdits := []string{
		"91.43%",
		"96.65%",
		"99.90%",
		"21.43%",
		"14.56%",
		"78.57%",
		"L0 Reflex (20) / L1b INT8 (21)",
		"L0 Reflex (2,957) / L1b Centroid (1,043)",
		"no caller outside test suites loads floppy disks",
	}

	// 2. Jumeau négatif : le validateur doit rejeter un document falsifié ou désaligné.
	fauxDocx := contenuDocxExtrait{
		paragraphes:    []string{"# Titre Orphelin"},
		lignesParTable: []int{2},
		texteComplet:   "Reverse Shell Payloads 100.00% [91.43%, 100.00%] 21.43%",
	}
	rejetsJumeau := verifierContenuMonographie("# Autre Titre\n\n| A | B |\n|---|---|\n| 1 | 21.43% |\n", fauxDocx, jetonsAttendus, jetonsInterdits)
	if len(rejetsJumeau) == 0 {
		t.Fatalf("%s : le jumeau negatif falsifie n'a declenche aucun rejet", cheminMonographieMD)
	}

	// 3. Lecture intégrale sans troncature des deux fichiers cibles.
	octetsMD, errMD := lireFichierEntierBorne(cheminMonographieMD)
	if errMD != nil {
		t.Fatalf("lecture %s : %v", cheminMonographieMD, errMD)
	}
	octetsDOCX, errDOCX := lireFichierEntierBorne(cheminMonographieDOCX)
	if errDOCX != nil {
		t.Fatalf("lecture %s : %v", cheminMonographieDOCX, errDOCX)
	}

	docxExtrait, errXML := extraireDocxComplet(octetsDOCX)
	if errXML != nil {
		t.Fatalf("decodage OOXML %s : %v", cheminMonographieDOCX, errXML)
	}

	anomalies := verifierContenuMonographie(string(octetsMD), docxExtrait, jetonsAttendus, jetonsInterdits)
	for _, anomalie := range anomalies {
		t.Errorf("%s", anomalie)
	}
}
