// Package c2blue55 — l1_remise_en_etat_test.go
// Tests d'acceptation de bout en bout de la ligne L-1 (EXG-21), remise en état
// après l'audit du 2026-11-10 :
//   - vecteur d'évaluation indépendant du PID et de la source (cas L1-01 a) ;
//   - réputation par remontée des suffixes, avec frontières de labels DNS
//     (cas L1-01 b et L1-02 a).
//
// Ces tests sont écrits en boîte noire à partir de la spécification de la
// ligne. Ils doivent compiler sur la tête de base a74747e et échouer par
// assertion tant que la remise en état n'est pas réalisée.
package c2blue55

import (
	"path/filepath"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/engine"
)

// TestL1_VecteurIndependantDuPIDEtDeLaSource vérifie que la cascade rend le même
// couple (Action, Stage) pour une même charge, que le PID et la source soient
// nuls ou renseignés, et que les charges tenues à l'écart restent bloquées à
// l'étage L1b sous un PID non nul.
func TestL1_VecteurIndependantDuPIDEtDeLaSource(t *testing.T) {
	t.Run("L1-01", func(t *testing.T) {
		cascade, _, _ := setupWittgensteinEngine(t)
		arena := engine.DefaultArenaPool()
		dataDir := resolveWittgensteinDataDir(t)

		shells, err := engine.LoadReverseShellPayloads(filepath.Join(dataDir, "reverse_shells.jsonl"))
		if err != nil {
			t.Fatalf("chargement des reverse shells : %v", err)
		}
		nTrain := engine.ReverseShellTrainCount(len(shells))
		holdout := shells[nTrain:]
		if len(holdout) == 0 {
			t.Fatal("partition tenue à l'écart vide : précondition du cas L1-01 non satisfaite")
		}

		const (
			pidSans, srcSans        = uint32(0), uint64(0)
			pidAvec                 = uint32(4242)
			srcAvec                 = uint64(1)<<32 | 0xC0A80117
			seqDepart        uint64 = 1727630000000000000
		)

		// evalue charge une fois avec un couple (PID, Src) donné et renvoie le verdict.
		evalue := func(payload string, pid uint32, src uint64, seq uint64) engine.CascadeVerdict {
			var ev engine.Probe_event_t
			ev.Ts_ns = seq
			ev.Pid = pid
			ev.Src = src
			ev.Subsystem = SubProc
			ev.Action = ActExec
			arena.StorePayload(&ev, []byte(payload))
			return cascade.EvaluateEvent(&ev)
		}

		var seq uint64 = seqDepart
		nonConformes := 0
		veto := 0
		for _, charge := range holdout {
			seq++
			a := evalue(charge, pidSans, srcSans, seq)
			seq++
			b := evalue(charge, pidAvec, srcAvec, seq)
			if a.Action != b.Action || a.Stage != b.Stage {
				nonConformes++
				if nonConformes <= 3 {
					t.Errorf("reverse shell %.60q : verdict dépend du PID/source : sans=(Action %d, Stage %d) avec=(Action %d, Stage %d)",
						charge, a.Action, a.Stage, b.Action, b.Stage)
				}
			}
			if b.Action == engine.VerdictBlock && b.Stage == engine.StageL1b {
				veto++
			}
		}
		if nonConformes != 0 {
			t.Errorf("écarts (Action, Stage) entre les deux en-têtes : obtenu %d, attendu 0", nonConformes)
		}
		if veto == 0 {
			t.Errorf("aucune charge tenue à l'écart n'est VerdictBlock à l'étage StageL1b sous Pid=4242 : obtenu 0, attendu au moins 1")
		}

		for _, cmd := range engine.BenignAdminCommands() {
			seq++
			a := evalue(cmd, pidSans, srcSans, seq)
			seq++
			b := evalue(cmd, pidAvec, srcAvec, seq)
			if a.Action != b.Action || a.Stage != b.Stage {
				t.Errorf("commande bénigne %.60q : verdict dépend du PID/source : sans=(Action %d, Stage %d) avec=(Action %d, Stage %d)",
					cmd, a.Action, a.Stage, b.Action, b.Stage)
				break
			}
		}
	})
}

// TestL1_ReputationRemonteLesSuffixes vérifie la remontée des suffixes d'un
// FQDN dans la table de réputation, avec les frontières de labels DNS.
func TestL1_ReputationRemonteLesSuffixes(t *testing.T) {
	t.Run("L1-01", func(t *testing.T) {
		raw, err := CompileReputationSnapshot([]BuildEntry{
			{Domain: "evil-l1.example", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
		})
		if err != nil {
			t.Fatalf("compilation de l'instantané : %v", err)
		}
		table, err := NewReputationTable(raw)
		if err != nil {
			t.Fatalf("ouverture de la table : %v", err)
		}

		for _, fqdn := range []string{
			"-a.evil-l1.example",
			"a-.evil-l1.example",
			"ab=.evil-l1.example",
			"x.y.evil-l1.example",
		} {
			res, ok := table.Match(fqdn)
			if res.MatchedDomain != "evil-l1.example" || res.Classification != RepClassBlockC2 || ok != true {
				t.Errorf("Match(%q) = (%q, %d, %t) ; attendu (%q, %d, %t)",
					fqdn, res.MatchedDomain, res.Classification, ok, "evil-l1.example", RepClassBlockC2, true)
			}
		}
	})

	t.Run("L1-02", func(t *testing.T) {
		raw, err := CompileReputationSnapshot([]BuildEntry{
			{Domain: "evil-l1.example", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
			{Domain: "exact-l1.example", Classification: RepClassBlockC2, MatchKind: MatchExact},
		})
		if err != nil {
			t.Fatalf("compilation de l'instantané : %v", err)
		}
		table, err := NewReputationTable(raw)
		if err != nil {
			t.Fatalf("ouverture de la table : %v", err)
		}

		for _, fqdn := range []string{
			"-a.absent-l1.example",
			"a..evil-l1.example",
			"-x.exact-l1.example",
		} {
			if _, ok := table.Match(fqdn); ok != false {
				t.Errorf("Match(%q) = %t ; attendu false", fqdn, ok)
			}
		}
	})
}
