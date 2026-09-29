// Package engine - ontology_test.go
package engine

import (
	"path/filepath"
	"testing"
)

func TestOntoKeyPacking(t *testing.T) {
	k := PackOntoKey(SubjRootSystemd, ActWriteFile, TgtFIMEtc, CtxSystemdUnit)
	s, a, tg, c := k.Unpack()

	if s != SubjRootSystemd {
		t.Fatalf("Sujet unpack = %d, attendu %d", s, SubjRootSystemd)
	}
	if a != ActWriteFile {
		t.Fatalf("Action unpack = %d, attendu %d", a, ActWriteFile)
	}
	if tg != TgtFIMEtc {
		t.Fatalf("Cible unpack = %d, attendu %d", tg, TgtFIMEtc)
	}
	if c != CtxSystemdUnit {
		t.Fatalf("Contexte unpack = %d, attendu %d", c, CtxSystemdUnit)
	}
}

func TestOntoAxiomsInvariance(t *testing.T) {
	// Test 1 : Invariance FIM - Root systemd autorisé
	kNominal := PackOntoKey(SubjRootSystemd, ActWriteFile, TgtFIMEtc, CtxSystemdUnit)
	if v := EvaluateOntology(kNominal); v != OntoVerdictAllow {
		t.Fatalf("kNominal attendu OntoVerdictAllow, obtenu %d", v)
	}

	// Test 2 : Invariance FIM - Service non privilégié tentant d'écrire dans /etc/cron -> VIOLATION
	kAttackFIM := PackOntoKey(SubjServiceUnpriv, ActWriteFile, TgtFIMEtc, CtxDefault)
	if v := EvaluateOntology(kAttackFIM); v != OntoVerdictDeny {
		t.Fatalf("kAttackFIM attendu OntoVerdictDeny, obtenu %d", v)
	}

	// Test 3 : Invariance FIM - Altération SSH authorized_keys par utilisateur non root -> VIOLATION
	kAttackSSH := PackOntoKey(SubjUserInteractive, ActWriteFile, TgtFIMSsh, CtxInteractiveTTY)
	if v := EvaluateOntology(kAttackSSH); v != OntoVerdictDeny {
		t.Fatalf("kAttackSSH attendu OntoVerdictDeny, obtenu %d", v)
	}

	// Test 4 : Évasion mémoire - Connexion réseau depuis binaire supprimé -> VIOLATION
	kAttackDeleted := PackOntoKey(SubjDeletedBinary, ActConnectNet, TgtNetExternal, CtxDefault)
	if v := EvaluateOntology(kAttackDeleted); v != OntoVerdictDeny {
		t.Fatalf("kAttackDeleted attendu OntoVerdictDeny, obtenu %d", v)
	}

	// Test 5 : Exécution depuis /memfd anonyme -> VIOLATION
	kAttackMemfd := PackOntoKey(SubjMemfdAnon, ActExecve, TgtTmpExec, CtxDefault)
	if v := EvaluateOntology(kAttackMemfd); v != OntoVerdictDeny {
		t.Fatalf("kAttackMemfd attendu OntoVerdictDeny, obtenu %d", v)
	}

	// Test 6 : Masquage de processus kworker par processus non kernel -> VIOLATION
	kAttackMasq := PackOntoKey(SubjUserInteractive, ActPrctlMasq, TgtUnknown, CtxDefault)
	if v := EvaluateOntology(kAttackMasq); v != OntoVerdictDeny {
		t.Fatalf("kAttackMasq attendu OntoVerdictDeny, obtenu %d", v)
	}

	// Test 7 : Tube vers interpréteur de commandes -> VIOLATION
	kAttackPipe := PackOntoKey(SubjServiceUnpriv, ActExecve, TgtPipeInterpreter, CtxDefault)
	if v := EvaluateOntology(kAttackPipe); v != OntoVerdictDeny {
		t.Fatalf("kAttackPipe attendu OntoVerdictDeny, obtenu %d", v)
	}

	// Test 8 : Cas ambigu nécessitant analyse vectorielle
	kAmbiguous := PackOntoKey(SubjUserInteractive, ActConnectNet, TgtNetExternal, CtxInteractiveTTY)
	if v := EvaluateOntology(kAmbiguous); v != OntoVerdictAmbiguous {
		t.Fatalf("kAmbiguous attendu OntoVerdictAmbiguous, obtenu %d", v)
	}
}

func TestOntoZeroAllocation(t *testing.T) {
	k := PackOntoKey(SubjServiceUnpriv, ActWriteFile, TgtFIMEtc, CtxDefault)

	allocs := testing.AllocsPerRun(500, func() {
		_ = EvaluateOntology(k)
	})
	if allocs != 0 {
		t.Fatalf("EvaluateOntology a alloué %.2f fois, attendu 0", allocs)
	}
}

func TestGrayZoneDeciderCascade(t *testing.T) {
	cfg := DefaultGrayZoneConfig()
	cfg.DistStrict = 16
	cfg.DistFar = 64
	decider := NewGrayZoneDecider(cfg)

	// Prépare un codebook synthétique avec un motif hostile
	var hostileCode [codebookWords]uint64
	hostileCode[0] = 0xAAAAAAAAAAAAAAAA
	cb := NewCodebook([]CodebookEntry{
		{
			Bitcode:   hostileCode,
			ThreatID:  0xDEAD,
			Subsystem: 1,
			Severity:  SeverityCritical,
		},
	})

	// Cas 1 : Veto ontologique direct (prime sur la distance)
	kDeny := PackOntoKey(SubjMemfdAnon, ActConnectNet, TgtNetExternal, CtxDefault)
	var benignQuery [codebookWords]uint64 // Très loin du motif hostile
	res1 := decider.Decide(&benignQuery, cb, kDeny)
	if res1.Verdict != CascadeFastDrop {
		t.Fatalf("res1 attendu CascadeFastDrop, obtenu %d", res1.Verdict)
	}

	// Cas 2 : Signature hostile évidente (distance Hamming <= 16)
	kAmbiguous := PackOntoKey(SubjUserInteractive, ActConnectNet, TgtNetExternal, CtxInteractiveTTY)
	res2 := decider.Decide(&hostileCode, cb, kAmbiguous)
	if res2.Verdict != CascadeFastDrop {
		t.Fatalf("res2 attendu CascadeFastDrop, obtenu %d", res2.Verdict)
	}
	if res2.HammingDist != 0 {
		t.Fatalf("res2 HammingDist = %d, attendu 0", res2.HammingDist)
	}

	// Cas 3 : Bénignité certifiée des deux côtés (distance > DistFar et OntoVerdictAllow)
	var farQuery [codebookWords]uint64
	farQuery[1] = 0xFFFFFFFFFFFFFFFF
	farQuery[2] = 0xFFFFFFFFFFFFFFFF // Distance de Hamming > 128 bits
	kAllow := PackOntoKey(SubjRootSystemd, ActExecve, TgtBinSystem, CtxSystemdUnit)
	res3 := decider.Decide(&farQuery, cb, kAllow)
	if res3.Verdict != CascadeFastPass {
		t.Fatalf("res3 attendu CascadeFastPass, obtenu %d (dist=%d)", res3.Verdict, res3.HammingDist)
	}

	// Cas 4 : Zone grise -> Escalade vers Slow Path
	// Crée une requête à distance 32 (zone intermédiaire [16, 64])
	var grayQuery [codebookWords]uint64
	grayQuery = hostileCode
	grayQuery[0] ^= 0x00000000FFFFFFFF // 32 bits inversés
	res4 := decider.Decide(&grayQuery, cb, kAmbiguous)
	if res4.Verdict != CascadeEscalate {
		t.Fatalf("res4 attendu CascadeEscalate, obtenu %d", res4.Verdict)
	}
	if !res4.RequiresSlowPath {
		t.Fatalf("res4 RequiresSlowPath attendu true")
	}
	if res4.HammingDist != 32 {
		t.Fatalf("res4 HammingDist = %d, attendu 32", res4.HammingDist)
	}
}

func TestQuarantineChamberAndHoldout(t *testing.T) {
	qc := NewQuarantineChamber(100)

	var bitcode [codebookWords]uint64
	bitcode[0] = 0xCAFEBABE12345678
	key := PackOntoKey(SubjMemfdAnon, ActExecve, TgtTmpExec, CtxDefault)

	fp, err := qc.EnqueueIncident(bitcode, key, CascadeFastDrop, 0xBEEF, 1, SeverityHigh)
	if err != nil {
		t.Fatalf("EnqueueIncident: %v", err)
	}
	if fp == "" {
		t.Fatalf("Empreinte SHA-256 vide")
	}
	if qc.Len() != 1 {
		t.Fatalf("qc.Len() = %d, attendu 1", qc.Len())
	}

	// Validation de non-régression
	approved, err := qc.ValidateAgainstHoldoutSet(nil, 0.0)
	if err != nil {
		t.Fatalf("ValidateAgainstHoldoutSet: %v", err)
	}
	if len(approved) != 1 {
		t.Fatalf("len(approved) = %d, attendu 1", len(approved))
	}
	if qc.Len() != 0 {
		t.Fatalf("qc.Len() apres validation = %d, attendu 0", qc.Len())
	}

	// Promotion et rechargement atomique sans verrou
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "quarantine_test.c2book")
	initCB := NewCodebook([]CodebookEntry{
		{ThreatID: 1, Subsystem: 1, Severity: 1},
	})
	if err := SaveCodebook(targetPath, initCB.Entries()); err != nil {
		t.Fatalf("SaveCodebook: %v", err)
	}

	ac, err := LoadAtomicCodebook(targetPath)
	if err != nil {
		t.Fatalf("LoadAtomicCodebook: %v", err)
	}
	if ac.Len() != 1 {
		t.Fatalf("ac.Len() initial = %d, attendu 1", ac.Len())
	}

	if err := PromoteAndReload(targetPath, ac, approved); err != nil {
		t.Fatalf("PromoteAndReload: %v", err)
	}
	if ac.Len() != 2 {
		t.Fatalf("ac.Len() apres promotion = %d, attendu 2", ac.Len())
	}
}

func TestGrayZoneDualTokenBucket_Isolation(t *testing.T) {
	cfg := DefaultGrayZoneConfig()
	cfg.DistStrict = 10
	cfg.DistFar = 60
	cfg.MaxBurst = 100
	cfg.RefillPerSec = 1
	cfg.SourceMaxBurst = 5
	cfg.SourceRefillPerSec = 1

	decider := NewGrayZoneDecider(cfg)

	// Codebook et clé ambiguë pour forcer l'évaluation en zone grise
	cb := NewCodebook([]CodebookEntry{{ThreatID: 1}})
	var grayQuery [codebookWords]uint64
	grayQuery[0] = 0x00000000FFFFFFFF // 32 bits inversés -> distance 32 dans [10, 60]
	kAmbiguous := PackOntoKey(SubjUserInteractive, ActConnectNet, TgtNetExternal, CtxInteractiveTTY)

	sourceNoisy := uint64(1001)
	sourceVictim := uint64(2002)

	// La source bruyante consomme ses 5 jetons unitaires
	for i := 0; i < 5; i++ {
		res := decider.DecideWithSource(&grayQuery, cb, kAmbiguous, sourceNoisy)
		if res.Verdict != CascadeEscalate {
			t.Fatalf("iter %d source bruyante: attendu CascadeEscalate, obtenu %d", i, res.Verdict)
		}
	}

	// La 6e requête de la source bruyante est bloquée par dépassement de quota unitaire
	resThrottled := decider.DecideWithSource(&grayQuery, cb, kAmbiguous, sourceNoisy)
	if resThrottled.Verdict != CascadeSourceThrottled {
		t.Fatalf("source bruyante: attendu CascadeSourceThrottled, obtenu %d (%s)", resThrottled.Verdict, resThrottled.Diagnostic)
	}

	// ISOLATION ANTI-DOS : La source légitime conserve son quota intact et obtient CascadeEscalate
	resVictim := decider.DecideWithSource(&grayQuery, cb, kAmbiguous, sourceVictim)
	if resVictim.Verdict != CascadeEscalate {
		t.Fatalf("source victime indûment bloquée par le voisin bruyant: attendu CascadeEscalate, obtenu %d", resVictim.Verdict)
	}

	esc, gThrottled, sThrottled := decider.Stats()
	if esc != 6 || sThrottled != 1 || gThrottled != 0 {
		t.Fatalf("stats incohérentes: esc=%d, sThrottled=%d, gThrottled=%d", esc, sThrottled, gThrottled)
	}
}

func TestDeriveOntoContext_AntiSpoofing(t *testing.T) {
	// 1. Usurpation de kworker par un binaire applicatif
	ctx1 := DeriveOntoContext([]byte("/tmp/evil_worker"), false, false, false, []byte("kworker/u:0"), 4242)
	if ctx1 != CtxKworkerSpoof {
		t.Fatalf("usurpation kworker attendue CtxKworkerSpoof, obtenu %d", ctx1)
	}
	// Veto immédiat garanti par l'Axiome A8
	k1 := PackOntoKey(SubjUserInteractive, ActExecve, TgtBinSystem, ctx1)
	if v := EvaluateOntology(k1); v != OntoVerdictDeny {
		t.Fatalf("k1 attendu OntoVerdictDeny, obtenu %d", v)
	}

	// 2. Évasion memfd
	ctx2 := DeriveOntoContext([]byte("/memfd:payload (deleted)"), true, false, false, []byte("bash"), 100)
	if ctx2 != CtxMemfdSpoof {
		t.Fatalf("memfd attendu CtxMemfdSpoof, obtenu %d", ctx2)
	}
	k2 := PackOntoKey(SubjUserInteractive, ActExecve, TgtTmpExec, ctx2)
	if v := EvaluateOntology(k2); v != OntoVerdictDeny {
		t.Fatalf("k2 attendu OntoVerdictDeny, obtenu %d", v)
	}

	// 3. Image supprimée du disque
	ctx3 := DeriveOntoContext([]byte("/usr/bin/python (deleted)"), false, true, false, []byte("python"), 200)
	if ctx3 != CtxDeletedExe {
		t.Fatalf("deleted attendu CtxDeletedExe, obtenu %d", ctx3)
	}
	k3 := PackOntoKey(SubjUserInteractive, ActConnectNet, TgtNetExternal, ctx3)
	if v := EvaluateOntology(k3); v != OntoVerdictDeny {
		t.Fatalf("k3 attendu OntoVerdictDeny, obtenu %d", v)
	}

	// 4. Régions inscriptibles et exécutables anonymes
	ctx4 := DeriveOntoContext([]byte("/usr/bin/custom_c"), false, false, true, []byte("custom"), 300)
	if ctx4 != CtxAnonWX {
		t.Fatalf("anon WX attendu CtxAnonWX, obtenu %d", ctx4)
	}
	k4 := PackOntoKey(SubjUserInteractive, ActExecve, TgtTmpExec, ctx4)
	if v := EvaluateOntology(k4); v != OntoVerdictDeny {
		t.Fatalf("k4 attendu OntoVerdictDeny, obtenu %d", v)
	}

	// 5. Exécution depuis /tmp
	ctx5 := DeriveOntoContext([]byte("/tmp/dropped_script.sh"), false, false, false, []byte("sh"), 400)
	if ctx5 != CtxTmpResidence {
		t.Fatalf("/tmp attendu CtxTmpResidence, obtenu %d", ctx5)
	}
	k5 := PackOntoKey(SubjUserInteractive, ActExecve, TgtTmpExec, ctx5)
	if v := EvaluateOntology(k5); v != OntoVerdictDeny {
		t.Fatalf("k5 attendu OntoVerdictDeny, obtenu %d", v)
	}

	// 6. Processus nominal sain
	ctxNominal := DeriveOntoContext([]byte("/usr/bin/node"), false, false, false, []byte("node"), 500)
	if ctxNominal != CtxDefault {
		t.Fatalf("nominal attendu CtxDefault, obtenu %d", ctxNominal)
	}
}

func TestSealedHoldoutIntegrityVerification(t *testing.T) {
	qc := NewQuarantineChamber(10)
	var bitcode [codebookWords]uint64
	key := PackOntoKey(SubjMemfdAnon, ActExecve, TgtTmpExec, CtxDefault)
	_, _ = qc.EnqueueIncident(bitcode, key, CascadeFastDrop, 0x1234, 1, SeverityHigh)

	// Construit un hold-out set de référence
	refEntries := []CodebookEntry{
		{ThreatID: 10, Subsystem: 1, Severity: 1},
		{ThreatID: 20, Subsystem: 1, Severity: 2},
	}
	holdoutCB := NewCodebook(refEntries)

	// Calcule le sceau canonique authentique
	validSeal := ComputeHoldoutSeal(refEntries)
	if validSeal == (HoldoutSeal{}) {
		t.Fatal("sceau vide inattendu")
	}

	// Test A : Validation avec sceau authentique -> Succès
	approved, err := qc.ValidateAgainstSealedHoldout(holdoutCB, validSeal, 0.0)
	if err != nil {
		t.Fatalf("validation avec sceau valide: %v", err)
	}
	if len(approved) != 1 {
		t.Fatalf("len(approved) = %d, attendu 1", len(approved))
	}

	// Test B : Tentative d'empoisonnement avec un faux sceau altéré
	_, _ = qc.EnqueueIncident(bitcode, key, CascadeFastDrop, 0x5678, 1, SeverityHigh)
	var fakeSeal HoldoutSeal
	fakeSeal[0] = 0xDE
	fakeSeal[1] = 0xAD

	_, errFake := qc.ValidateAgainstSealedHoldout(holdoutCB, fakeSeal, 0.0)
	if errFake != ErrHoldoutSealMismatch {
		t.Fatalf("empoisonnement de sceau: attendu ErrHoldoutSealMismatch, obtenu %v", errFake)
	}
}

func BenchmarkEvaluateOntology(b *testing.B) {
	k := PackOntoKey(SubjServiceUnpriv, ActWriteFile, TgtFIMEtc, CtxDefault)
	b.ReportAllocs()
	b.ResetTimer()
	var v uint8
	for i := 0; i < b.N; i++ {
		v = EvaluateOntology(k)
	}
	_ = v
}

func BenchmarkGrayZoneFastDrop(b *testing.B) {
	cfg := DefaultGrayZoneConfig()
	decider := NewGrayZoneDecider(cfg)
	var q [codebookWords]uint64
	cb := NewCodebook(synthCorpus(0x777, 256))
	kDeny := PackOntoKey(SubjMemfdAnon, ActConnectNet, TgtNetExternal, CtxDefault)

	b.ReportAllocs()
	b.ResetTimer()
	var res CascadeResult
	for i := 0; i < b.N; i++ {
		res = decider.Decide(&q, cb, kDeny)
	}
	_ = res
}

func BenchmarkGrayZoneDecideEscalate(b *testing.B) {
	cfg := DefaultGrayZoneConfig()
	decider := NewGrayZoneDecider(cfg)
	var q [codebookWords]uint64
	cb := NewCodebook(synthCorpus(0x777, 256))
	k := PackOntoKey(SubjUserInteractive, ActConnectNet, TgtNetExternal, CtxInteractiveTTY)

	b.ReportAllocs()
	b.ResetTimer()
	var res CascadeResult
	for i := 0; i < b.N; i++ {
		res = decider.Decide(&q, cb, k)
	}
	_ = res
}


