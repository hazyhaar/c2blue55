// Package c2blue55 — wittgenstein_bench_test.go
// Bancs d'homologation du concours Wittgenstein Security, sur données réelles
// (/devhoros/data/wittgenstein/) strictement disjointes de l'apprentissage :
//   - LOLBAS : uniquement les reverse shells distincts tenus à l'écart par
//     c2forge (engine.ReverseShellTrainCount), puis leurs variantes d'adresse
//     IP et de port ;
//   - bénin : la partition d'évaluation des commandes d'administration
//     (engine.IsBenignTrainIndex faux), jamais vue par la forgerie ;
//   - DNS : l'intégralité de netrack_dns/validate.csv, famille par famille.
//
// Chaque taux distingue le blocage et la quarantaine, côté détection comme
// côté faux positifs, ainsi que l'étage qui a tranché (L0 mot-clé ou axiome,
// L1a sonde conforme, L1b disquette).
package c2blue55

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

const wittgensteinDataDir = "/devhoros/data/wittgenstein"

func setupWittgensteinEngine(t testing.TB) (*engine.CascadeEngine, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	cb := engine.NewCodebook(nil)
	gz := engine.NewGrayZoneDecider(engine.DefaultGrayZoneConfig())
	cascade := engine.NewCascadeEngine(cb, gz)

	files := []struct {
		family   uint16
		filename string
	}{
		{engine.FloppyFamilyLOLBAS, "floppy_lolbas.c2book"},
		{engine.FloppyFamilyDNSC2, "floppy_dns_c2.c2book"},
		{engine.FloppyFamilyAgentMCP, "floppy_agent_mcp.c2book"},
	}
	for _, f := range files {
		disk, err := engine.LoadFloppyMmap(filepath.Join(wittgensteinDataDir, "floppies", f.filename), engine.WittgensteinFloppyKey(f.family))
		if err != nil {
			t.Fatalf("Impossible de monter la disquette %s: %v", f.filename, err)
		}
		if disk.Probe() == nil {
			t.Fatalf("La disquette %s n'embarque pas de sonde conforme L1a", f.filename)
		}
		t.Cleanup(func() { disk.Close() })
		// Le montage active la sonde conforme L1a embarquée dans la disquette.
		cascade.MountFloppy(f.family, disk)
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Erreur génération paire Ed25519: %v", err)
	}
	return cascade, pubKey, privKey
}

// verdictTally compte les verdicts d'une population, par action et par étage.
type verdictTally struct {
	n, block, quarantine, pass int
	byStage                    [3][4]int // [étage][action]
}

func (c *verdictTally) add(v engine.CascadeVerdict) {
	c.n++
	switch v.Action {
	case engine.VerdictBlock:
		c.block++
	case engine.VerdictQuarantine:
		c.quarantine++
	default:
		c.pass++
	}
	if int(v.Stage) < len(c.byStage) && int(v.Action) < 4 {
		c.byStage[v.Stage][v.Action]++
	}
}

func pct(k, n int) float64 {
	if n == 0 {
		return 0
	}
	return 100 * float64(k) / float64(n)
}

func (c *verdictTally) String() string {
	return fmt.Sprintf("n=%d | Block=%d (%.2f%%) | Quarantaine=%d (%.2f%%) | Pass=%d (%.2f%%) | par étage L0/L1a/L1b : Block=%d/%d/%d Quarantaine=%d/%d/%d Pass=%d/%d/%d",
		c.n, c.block, pct(c.block, c.n), c.quarantine, pct(c.quarantine, c.n), c.pass, pct(c.pass, c.n),
		c.byStage[engine.StageL0][engine.VerdictBlock], c.byStage[engine.StageL1a][engine.VerdictBlock], c.byStage[engine.StageL1b][engine.VerdictBlock],
		c.byStage[engine.StageL0][engine.VerdictQuarantine], c.byStage[engine.StageL1a][engine.VerdictQuarantine], c.byStage[engine.StageL1b][engine.VerdictQuarantine],
		c.byStage[engine.StageL0][engine.VerdictPass], c.byStage[engine.StageL1a][engine.VerdictPass], c.byStage[engine.StageL1b][engine.VerdictPass])
}

// ipv4Port repère l'adresse de l'attaquant et le port qui la suit dans les
// reverse shells du corpus (« IP/port », « IP',port », « IP:port », « IP port »,
// « $i="IP";$p=port »).
var ipv4Port = regexp.MustCompile(`((?:\d{1,3}\.){3}\d{1,3})(\D{1,8}?)(\d{2,5})\b`)

// ipPortVariant remplace chaque adresse IPv4 et le port qui la suit. La charge
// réelle est conservée à l'identique hors de ces deux champs.
func ipPortVariant(payload, ip, port string) string {
	out := ipv4Port.ReplaceAllString(payload, ip+"${2}"+port)
	return strings.ReplaceAll(out, "4444", port)
}

func TestWittgenstein_Evaluation_RealData(t *testing.T) {
	cascade, pubKey, privKey := setupWittgensteinEngine(t)
	arena := engine.DefaultArenaPool()
	seq := uint64(1)

	eval := func(sub, act uint16, payload []byte) (engine.Probe_event_t, engine.CascadeVerdict) {
		var ev engine.Probe_event_t
		ev.Ts_ns = 1727630000000000000 + seq
		ev.Subsystem = sub
		ev.Action = act
		arena.StorePayload(&ev, payload)
		seq++
		return ev, cascade.EvaluateEvent(&ev)
	}

	// =========================================================================
	// 1. LOLBAS : reverse shells distincts tenus à l'écart (hors apprentissage)
	// =========================================================================
	shells, err := engine.LoadReverseShellPayloads(filepath.Join(wittgensteinDataDir, "reverse_shells.jsonl"))
	if err != nil {
		t.Fatalf("reverse_shells.jsonl: %v", err)
	}
	nTrain := engine.ReverseShellTrainCount(len(shells))
	train := map[string]bool{}
	for _, s := range shells[:nTrain] {
		train[s] = true
	}
	holdout := shells[nTrain:]
	if len(holdout) == 0 {
		t.Fatal("Partition tenue à l'écart vide")
	}

	var witnessProof *engine.ForensicProof
	var witnessEvent engine.Probe_event_t
	var holdoutTally verdictTally
	for _, s := range holdout {
		if train[s] {
			t.Fatalf("Fuite d'apprentissage : charge tenue à l'écart présente dans l'apprentissage : %.60q", s)
		}
		payload := []byte(s)
		ev, v := eval(SubProc, ActExec, payload)
		holdoutTally.add(v)
		// Preuve témoin : un veto sur charge longue, qui passe par l'arène 4 Ko.
		if witnessProof == nil && v.Action == engine.VerdictBlock && len(payload) > 96 {
			disk := cascade.GetFloppy(engine.FloppyFamilyLOLBAS)
			proof, err := engine.SignForensicProof(privKey, seq, &ev, payload, v, disk.Header.FamilyID, disk.Header.CRC32C)
			if err != nil {
				t.Fatalf("SignForensicProof: %v", err)
			}
			witnessProof, witnessEvent = proof, ev
		}
	}
	t.Logf("[LOLBAS tenu à l'écart] %d charges distinctes jamais vues (apprentissage : %d) | %s", len(holdout), nTrain, &holdoutTally)

	variants := []struct{ ip, port string }{
		{"172.16.99.23", "9001"}, {"192.168.56.101", "8443"}, {"198.51.100.7", "53"},
	}
	var variantTally verdictTally
	for _, s := range holdout {
		for _, vr := range variants {
			mutated := ipPortVariant(s, vr.ip, vr.port)
			if mutated == s {
				continue // charge sans adresse en clair (encodée) : aucune variante réelle
			}
			_, v := eval(SubProc, ActExec, []byte(mutated))
			variantTally.add(v)
		}
	}
	t.Logf("[LOLBAS variantes IP/port] %s", &variantTally)

	// =========================================================================
	// 2. Bénin : commandes d'administration de la partition d'évaluation
	// =========================================================================
	var benignTally, benignTrainTally, benignTTYTally verdictTally
	tty := engine.DeriveCascadeContext(engine.ProcessProvenance{
		PID: 4242, UID: 1000, EUID: 1000, LoginSession: true, HasTTY: true, ExeTarget: []byte("/usr/bin/bash"),
	})
	for i, cmd := range engine.BenignAdminCommands() {
		ev, v := eval(SubProc, ActExec, []byte(cmd))
		if engine.IsBenignTrainIndex(i) {
			benignTrainTally.add(v)
			continue
		}
		benignTally.add(v)
		if v.Action == engine.VerdictBlock {
			t.Logf("  faux positif Block L%d : %q", v.Stage, cmd)
		}
		benignTTYTally.add(cascade.EvaluateEventCtx(&ev, tty))
	}
	t.Logf("[Bénin tenu à l'écart] FPR_block=%.2f%% FPR_quarantine=%.2f%% | %s",
		pct(benignTally.block, benignTally.n), pct(benignTally.quarantine, benignTally.n), &benignTally)
	t.Logf("[Bénin tenu à l'écart, session TTY établie] FPR_block=%.2f%% FPR_quarantine=%.2f%% | %s",
		pct(benignTTYTally.block, benignTTYTally.n), pct(benignTTYTally.quarantine, benignTTYTally.n), &benignTTYTally)
	t.Logf("[Bénin d'apprentissage, pour comparaison seulement] %s", &benignTrainTally)

	// =========================================================================
	// 3. DNS : validate.csv intégral, par famille
	// =========================================================================
	dnsFile, err := os.Open(filepath.Join(wittgensteinDataDir, "netrack_dns", "validate.csv"))
	if err != nil {
		t.Fatalf("validate.csv: %v", err)
	}
	defer dnsFile.Close()
	r := csv.NewReader(dnsFile)
	c2ByFamily := map[string]*verdictTally{}
	var c2All, benignDNS verdictTally
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(row) < 2 {
			continue
		}
		label := strings.TrimSpace(row[0])
		domain := strings.TrimSpace(row[1])
		_, v := eval(SubNet, ActConnect, []byte(domain))
		switch label {
		case "1":
			labels := strings.Split(strings.TrimSuffix(domain, "."), ".")
			fam := strings.Join(labels[max(0, len(labels)-2):], ".")
			if c2ByFamily[fam] == nil {
				c2ByFamily[fam] = &verdictTally{}
			}
			c2ByFamily[fam].add(v)
			c2All.add(v)
		case "0":
			benignDNS.add(v)
		}
	}
	fams := make([]string, 0, len(c2ByFamily))
	for f := range c2ByFamily {
		fams = append(fams, f)
	}
	sort.Strings(fams)
	for _, f := range fams {
		c := c2ByFamily[f]
		t.Logf("[DNS C2 %-16s] TPR_block=%.2f%% TPR_quarantine=%.2f%% | %s", f, pct(c.block, c.n), pct(c.quarantine, c.n), c)
	}
	t.Logf("[DNS C2 toutes familles] TPR_block=%.2f%% TPR_quarantine=%.2f%% | %s", pct(c2All.block, c2All.n), pct(c2All.quarantine, c2All.n), &c2All)
	t.Logf("[DNS bénin] FPR_block=%.2f%% FPR_quarantine=%.2f%% | %s", pct(benignDNS.block, benignDNS.n), pct(benignDNS.quarantine, benignDNS.n), &benignDNS)
	if len(fams) < 3 || benignDNS.n == 0 {
		t.Fatalf("validate.csv incomplet : %d familles C2, %d domaines bénins", len(fams), benignDNS.n)
	}

	// Seuils de non-régression. Ils portent sur le blocage et sur la détection
	// (blocage ou quarantaine) hors apprentissage ; les taux de quarantaine
	// bénigne et la couverture par famille DNS sont rapportés ci-dessus sans
	// seuil, leur niveau actuel n'étant pas un objectif atteint.
	if got := pct(holdoutTally.block+holdoutTally.quarantine, holdoutTally.n); got < 95 {
		t.Errorf("Détection LOLBAS hors apprentissage : %.2f%% (seuil 95%%)", got)
	}
	if got := pct(variantTally.block+variantTally.quarantine, variantTally.n); got < 95 {
		t.Errorf("Détection des variantes IP/port : %.2f%% (seuil 95%%)", got)
	}
	if got := pct(benignTally.block, benignTally.n); got > 1 {
		t.Errorf("FPR_block des commandes d'administration tenues à l'écart : %.2f%% (seuil 1%%)", got)
	}
	if got := pct(benignDNS.block, benignDNS.n); got > 1 {
		t.Errorf("FPR_block DNS : %.2f%% (seuil 1%%)", got)
	}

	// =========================================================================
	// 4. Dossier forensique scellé Ed25519 pour le jury
	// =========================================================================
	if witnessProof == nil {
		t.Fatal("Aucune preuve témoin n'a pu être scellée (aucun veto sur charge longue tenue à l'écart)")
	}
	if !engine.VerifyForensicProof(pubKey, witnessProof) {
		t.Fatal("La signature Ed25519 du dossier témoin est invalide contre la clé hôte")
	}
	fakePubKey, _, _ := ed25519.GenerateKey(rand.Reader)
	if engine.VerifyForensicProof(fakePubKey, witnessProof) {
		t.Fatal("VerifyForensicProof a validé la preuve contre une clé racine forgée")
	}
	if engine.VerifyForensicProof(nil, witnessProof) {
		t.Fatal("VerifyForensicProof a validé la preuve sans clé racine")
	}

	// Recyclage complet de l'arène par un trafic long réel (commandes
	// d'administration longues) : la page du témoin est réécrite, l'événement
	// seul n'est plus évaluable (fail-closed) mais la preuve se rejoue sur sa
	// charge scellée.
	var longBenign [][]byte
	for _, cmd := range engine.BenignAdminCommands() {
		if len(cmd) > 96 {
			longBenign = append(longBenign, []byte(cmd))
		}
	}
	if len(longBenign) == 0 {
		t.Fatal("aucune commande bénigne longue pour recycler l'arène")
	}
	for i := 0; i < engine.ArenaCapacity; i++ {
		var w engine.Probe_event_t
		arena.StorePayload(&w, longBenign[i%len(longBenign)])
	}
	if v := cascade.EvaluateEvent(&witnessEvent); v.Action == engine.VerdictPass {
		t.Fatalf("Événement témoin à page recyclée évalué Pass (fail-open), drapeaux=0x%X", v.Flags)
	}
	reproduced, reason := engine.ReplayForensicProof(pubKey, witnessProof, cascade)
	if !reproduced {
		t.Fatalf("Le rejeu forensique a échoué: %s", reason)
	}
	t.Logf("[FORENSIQUE JURY] Dossier témoin SeqID=%d (%d octets de charge) vérifié et rejoué après recyclage de l'arène : %s",
		witnessProof.SeqID, len(witnessProof.Payload), reason)
}

// BenchmarkWittgenstein_L0_Reflex_Throughput mesure la cadence de la Couche 0 réflexe (mot-clé malveillant explicite).
func BenchmarkWittgenstein_L0_Reflex_Throughput(b *testing.B) {
	cascade, _, _ := setupWittgensteinEngine(b)

	var ev engine.Probe_event_t
	ev.Subsystem = SubProc
	ev.Action = ActExec
	copy(ev.Payload[:], "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA=")

	b.ReportAllocs()
	for b.Loop() {
		_ = cascade.EvaluateEvent(&ev)
	}
}

func stageName(s uint8) string {
	switch s {
	case engine.StageL0:
		return "L0"
	case engine.StageL1a:
		return "L1a"
	case engine.StageL1b:
		return "L1b"
	default:
		return fmt.Sprintf("L%d", s)
	}
}

// BenchmarkWittgenstein_Full_Cascade_Throughput mesure la cascade complète
// (L0 -> L1a -> L1b) sur une commande nominale sans mot-clé, avec la sonde
// conforme L1a embarquée par la disquette réellement consultée.
func BenchmarkWittgenstein_Full_Cascade_Throughput(b *testing.B) {
	cascade, _, _ := setupWittgensteinEngine(b)

	var ev engine.Probe_event_t
	ev.Subsystem = SubProc
	ev.Action = ActExec
	copy(ev.Payload[:], "git status --porcelain")
	v := cascade.EvaluateEvent(&ev)
	b.Logf("verdict de référence : action=%d étage=%s", v.Action, stageName(v.Stage))

	b.ReportAllocs()
	for b.Loop() {
		_ = cascade.EvaluateEvent(&ev)
	}
}

// BenchmarkWittgenstein_Full_Cascade_LongPayload mesure la cascade complète
// sur une charge longue lue dans l'arène 4 Ko (copie vérifiée par CRC32-C).
func BenchmarkWittgenstein_Full_Cascade_LongPayload(b *testing.B) {
	cascade, _, _ := setupWittgensteinEngine(b)

	var ev engine.Probe_event_t
	ev.Subsystem = SubProc
	ev.Action = ActExec
	engine.DefaultArenaPool().StorePayload(&ev, []byte("Get-ChildItem -Path C:\\Windows\\Temp -Recurse | Measure-Object -Property Length -Sum | Select-Object Count,Sum"))
	v := cascade.EvaluateEvent(&ev)
	b.Logf("verdict de référence : action=%d étage=%s drapeaux=0x%X", v.Action, stageName(v.Stage), v.Flags)

	b.ReportAllocs()
	for b.Loop() {
		_ = cascade.EvaluateEvent(&ev)
	}
}

// BenchmarkWittgenstein_DNS_Cascade mesure la cascade sur un domaine bénin
// réel de validate.csv, sonde L1a DNS embarquée consultée.
func BenchmarkWittgenstein_DNS_Cascade(b *testing.B) {
	cascade, _, _ := setupWittgensteinEngine(b)

	var ev engine.Probe_event_t
	ev.Subsystem = SubNet
	ev.Action = ActConnect
	copy(ev.Payload[:], "businessinsider.my.")
	v := cascade.EvaluateEvent(&ev)
	b.Logf("verdict de référence : action=%d étage=%s", v.Action, stageName(v.Stage))

	b.ReportAllocs()
	for b.Loop() {
		_ = cascade.EvaluateEvent(&ev)
	}
}
