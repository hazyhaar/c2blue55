package c2blue55

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// TestReputationSyncer_SyncOnce exercises a local fixture, not authenticated IOCs.
func TestReputationSyncer_SyncOnce(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Local policy fixture.
	threatFile := filepath.Join(tmpDir, "threatfox_iocs.txt")
	threatContent := `# Local fixture, not a ThreatFox feed
0.0.0.0 cobalt-c2-active.net
127.0.0.1 drop-zone-exfil.biz
# Commentaire
sliver-beacon-real.cc
`
	if err := os.WriteFile(threatFile, []byte(threatContent), 0644); err != nil {
		t.Fatalf("WriteFile threat: %v", err)
	}

	// 2. Initialisation du réceptacle atomique
	initSnap, _ := CompileReputationSnapshot(DefaultBuildEntries)
	initTbl, _ := NewReputationTable(initSnap)
	ar := NewAtomicReputation(initTbl)

	var successCount int64
	syncer := NewReputationSyncer(SyncerConfig{
		Sources: []ReputationSource{
			{
				Name:           "ThreatFox-Local",
				URI:            "file://" + threatFile,
				Classification: RepClassBlockC2,
				MatchKind:      MatchSubtree,
			},
		},
		OnSyncSuccess: func(n int) {
			atomic.AddInt64(&successCount, 1)
		},
	}, ar)

	ctx := context.Background()
	numEntries, err := syncer.SyncOnce(ctx)
	if err != nil {
		t.Fatalf("SyncOnce: %v", err)
	}

	if numEntries < len(DefaultBuildEntries)+3 {
		t.Errorf("numEntries = %d, attendu >= %d", numEntries, len(DefaultBuildEntries)+3)
	}
	if atomic.LoadInt64(&successCount) != 1 {
		t.Errorf("successCount = %d, attendu 1", successCount)
	}

	// Vérification que les nouveaux IOCs sont maintenant bloqués
	if res, ok := ar.Match("sub.cobalt-c2-active.net"); !ok || res.Classification != RepClassBlockC2 {
		t.Errorf("IOC cobalt-c2 non trouve ou mauvais type: %+v", res)
	}
	if res, ok := ar.Match("drop-zone-exfil.biz"); !ok || res.Classification != RepClassBlockC2 {
		t.Errorf("IOC drop-zone non trouve: %+v", res)
	}

	// Vérification que les seeds d'origine sont toujours présents
	if res, ok := ar.Match("cloudtelemetry.sophosxl.com"); !ok || res.Classification != RepClassAllowVendor {
		t.Errorf("Seed Sophos perdu apres synchro: %+v", res)
	}
}

// TestReputationSyncer_FallbackOnError vérifie la résilience en cas d'indisponibilité d'une source.
func TestReputationSyncer_FallbackOnError(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing-source.txt")
	initSnap, _ := CompileReputationSnapshot(DefaultBuildEntries)
	initTbl, _ := NewReputationTable(initSnap)
	ar := NewAtomicReputation(initTbl)

	var reportedErr error
	syncer := NewReputationSyncer(SyncerConfig{
		Sources: []ReputationSource{
			{
				Name:           "NonExistentSource",
				URI:            "file://" + missing,
				Classification: RepClassBlockC2,
				MatchKind:      MatchSubtree,
			},
		},
		OnSyncError: func(err error) {
			reportedErr = err
		},
	}, ar)

	ctx := context.Background()
	num, err := syncer.SyncOnce(ctx)
	if err == nil {
		t.Fatal("source failure must remain visible despite retained seeds")
	}
	if num != len(DefaultBuildEntries) {
		t.Errorf("num = %d, attendu len(seeds) = %d", num, len(DefaultBuildEntries))
	}
	if reportedErr == nil {
		t.Errorf("OnSyncError aurait du être appelé")
	}
	if err := os.WriteFile(missing, []byte("recovered.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := syncer.SyncOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if res, ok := ar.Match("recovered.test"); !ok || res.Classification != RepClassBlockC2 {
		t.Fatal("source recovery failed")
	}
}

// TestReputationSyncer_PreservesDynamicIOCsOnSourceFailure vérifie qu'un échec
// transitoire de source ne vide pas de la mémoire vive les IOCs précédemment appris.
// Le scénario reproduit une perte réelle d'information : la table active contient
// des IOCs dynamiques, puis la source unique devient indisponible.
func TestReputationSyncer_PreservesDynamicIOCsOnSourceFailure(t *testing.T) {
	tmpDir := t.TempDir()

	threatFile := filepath.Join(tmpDir, "threatfox_iocs.txt")
	threatContent := `# Local fixture, not a ThreatFox feed
learned-dynamic-c2.net
learned-exfil.biz
`
	if err := os.WriteFile(threatFile, []byte(threatContent), 0644); err != nil {
		t.Fatalf("WriteFile threat: %v", err)
	}

	initSnap, _ := CompileReputationSnapshot(DefaultBuildEntries)
	initTbl, _ := NewReputationTable(initSnap)
	ar := NewAtomicReputation(initTbl)

	// Nominal loading from the private fixture.
	good := NewReputationSyncer(SyncerConfig{
		Sources: []ReputationSource{{
			Name:           "ThreatFox-Local",
			URI:            "file://" + threatFile,
			Classification: RepClassBlockC2,
			MatchKind:      MatchSubtree,
		}},
	}, ar)

	if _, err := good.SyncOnce(context.Background()); err != nil {
		t.Fatalf("SyncOnce nominal: %v", err)
	}
	if _, ok := ar.Match("sub.learned-dynamic-c2.net"); !ok {
		t.Fatalf("IOC dynamique absent après la passe nominale")
	}

	// Passe dégradée : la source a disparu du disque (erreur transitoire).
	missing := filepath.Join(tmpDir, "source-devenue-indisponible.txt")
	bad := NewReputationSyncer(SyncerConfig{
		Sources: []ReputationSource{{
			Name:           "ThreatFox-Local",
			URI:            "file://" + missing,
			Classification: RepClassBlockC2,
			MatchKind:      MatchSubtree,
		}},
	}, ar)

	if _, err := bad.SyncOnce(context.Background()); err == nil {
		t.Fatal("degraded synchronization must return its source error")
	}

	if res, ok := ar.Match("sub.learned-dynamic-c2.net"); !ok || res.Classification != RepClassBlockC2 {
		t.Fatalf("IOC dynamique perdu après échec de source: %+v ok=%v", res, ok)
	}
	if res, ok := ar.Match("learned-exfil.biz"); !ok || res.Classification != RepClassBlockC2 {
		t.Fatalf("IOC dynamique perdu après échec de source: %+v ok=%v", res, ok)
	}
	if res, ok := ar.Match("cloudtelemetry.sophosxl.com"); !ok || res.Classification != RepClassAllowVendor {
		t.Fatalf("Seed Sophos perdu après échec de source: %+v", res)
	}
	if _, err := good.SyncOnce(context.Background()); err != nil {
		t.Fatalf("recovery: %v", err)
	}
	if res, ok := ar.Match("learned-exfil.biz"); !ok || res.Classification != RepClassBlockC2 {
		t.Fatal("recovery lost policy")
	}
}

// TestReputationSyncer_PeriodicCancellation teste l'arrêt propre de la goroutine de synchronisation périodique.
func TestReputationSyncer_PeriodicCancellation(t *testing.T) {
	initSnap, _ := CompileReputationSnapshot(DefaultBuildEntries)
	initTbl, _ := NewReputationTable(initSnap)
	ar := NewAtomicReputation(initTbl)

	syncer := NewReputationSyncer(SyncerConfig{
		SyncInterval: 10 * time.Millisecond,
	}, ar)

	ctx, cancel := context.WithCancel(context.Background())
	syncer.StartPeriodic(ctx)
	time.Sleep(25 * time.Millisecond)
	cancel()
	time.Sleep(10 * time.Millisecond)
}
