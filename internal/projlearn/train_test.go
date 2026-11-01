package projlearn_test

import (
	"bytes"
	"cmp"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/hazyhaar/c2blue55/internal/projlearn"
	"github.com/hazyhaar/c2pkg/c2projlearn"
)

func wittgensteinDir(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("répertoire du paquet illisible: %v", err)
	}
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("aucun .git au-dessus du répertoire du paquet")
		}
		dir = parent
	}
	candidates := []string{
		filepath.Join(dir, "wittgenstein"),
		filepath.Join(dir, "..", "wittgenstein"),
		filepath.Join(dir, "..", "..", "..", "wittgenstein"),
	}
	for _, cand := range candidates {
		trainCSV := filepath.Join(cand, "netrack_dns", "train.csv")
		dgaCSV := filepath.Join(cand, "abusayed_dga_full.csv")
		if _, err := os.Stat(trainCSV); err != nil {
			continue
		}
		if _, err := os.Stat(dgaCSV); err != nil {
			continue
		}
		return cand
	}
	t.Fatalf("wittgenstein/netrack_dns introuvable depuis la racine %s", dir)
	return ""
}

func labelsMatchDots(name []byte, bounds []int) bool {
	if len(name) == 0 || len(bounds) < 2 || len(bounds)%2 != 0 {
		return false
	}
	if bounds[0] != 0 || bounds[len(bounds)-1] != len(name) {
		return false
	}
	for i := 0; i < len(bounds); i += 2 {
		start, end := bounds[i], bounds[i+1]
		if start < 0 || end > len(name) || start >= end {
			return false
		}
		for j := start; j < end; j++ {
			if name[j] == '.' {
				return false
			}
		}
		if i+2 < len(bounds) {
			next := bounds[i+2]
			if next != end+1 || end >= len(name) || name[end] != '.' {
				return false
			}
		}
	}
	return true
}

func requireCorpusContract(t *testing.T, train, heldOut []projlearn.Example) {
	t.Helper()
	if len(train) == 0 {
		t.Fatal("train vide")
	}
	if len(heldOut) == 0 {
		t.Fatal("heldOut vide")
	}
	families := make(map[string]struct{}, len(train))
	for i := range train {
		checkExample(t, "train", i, &train[i])
		families[train[i].Family] = struct{}{}
	}
	if len(families) < 2 {
		t.Fatalf("train: %d famille, attendu au moins 2", len(families))
	}
	for i := range heldOut {
		checkExample(t, "heldOut", i, &heldOut[i])
		if _, overlap := families[heldOut[i].Family]; overlap {
			t.Fatalf("famille %q présente dans train et heldOut", heldOut[i].Family)
		}
	}
}

func checkExample(t *testing.T, side string, index int, ex *projlearn.Example) {
	t.Helper()
	if len(ex.Name) == 0 || len(ex.Name) > 253 {
		t.Fatalf("%s[%d]: longueur de nom %d hors 1..253", side, index, len(ex.Name))
	}
	for _, b := range ex.Name {
		if b >= 'A' && b <= 'Z' {
			t.Fatalf("%s[%d]: nom non minuscule", side, index)
		}
	}
	if ex.Label != 1 && ex.Label != -1 {
		t.Fatalf("%s[%d]: Label=%g, attendu +1 ou -1", side, index, ex.Label)
	}
	if !labelsMatchDots(ex.Name, ex.Labels) {
		t.Fatalf("%s[%d]: bornes %v incohérentes avec les points de %q", side, index, ex.Labels, ex.Name)
	}
}

func sortExamples(examples []projlearn.Example) {
	slices.SortFunc(examples, func(a, b projlearn.Example) int {
		if c := strings.Compare(a.Family, b.Family); c != 0 {
			return c
		}
		if c := bytes.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return cmp.Compare(a.Label, b.Label)
	})
}

func splitClasses(examples []projlearn.Example) (positive, negative []projlearn.Example) {
	for i := range examples {
		switch examples[i].Label {
		case 1:
			positive = append(positive, examples[i])
		case -1:
			negative = append(negative, examples[i])
		}
	}
	return positive, negative
}

func stridePick(examples []projlearn.Example, n int) []projlearn.Example {
	out := make([]projlearn.Example, n)
	for i := range n {
		out[i] = examples[i*len(examples)/n]
	}
	return out
}

func balancedSubsample(t *testing.T, examples []projlearn.Example, half int) []projlearn.Example {
	t.Helper()
	positive, negative := splitClasses(examples)
	if len(positive) < half || len(negative) < half {
		t.Fatalf("échantillon insuffisant pour %d équilibrés: +1=%d -1=%d", half*2, len(positive), len(negative))
	}
	sortExamples(positive)
	sortExamples(negative)
	out := append(stridePick(positive, half), stridePick(negative, half)...)
	sortExamples(out)
	return out
}

func heldOutSample(t *testing.T, examples []projlearn.Example, n int) []projlearn.Example {
	t.Helper()
	positive, negative := splitClasses(examples)
	if len(positive) == 0 || len(negative) == 0 {
		t.Fatalf("heldOut sans les deux classes: +1=%d -1=%d", len(positive), len(negative))
	}
	if len(positive)+len(negative) < n {
		t.Fatalf("heldOut trop court pour %d exemples: +1=%d -1=%d", n, len(positive), len(negative))
	}
	sortExamples(positive)
	sortExamples(negative)
	nPos := n / 2
	nNeg := n - nPos
	if len(positive) < nPos {
		nPos = len(positive)
		nNeg = n - nPos
	}
	if len(negative) < nNeg {
		nNeg = len(negative)
		nPos = n - nNeg
	}
	if nPos == 0 || nNeg == 0 || nPos > len(positive) || nNeg > len(negative) {
		t.Fatalf("heldOut non répartissable en %d: +1=%d -1=%d", n, len(positive), len(negative))
	}
	out := append(stridePick(positive, nPos), stridePick(negative, nNeg)...)
	sortExamples(out)
	return out
}

func buildTriplets(examples []projlearn.Example, limit int) [][3]int {
	byFamily := make(map[string][]int)
	var order []string
	for i := range examples {
		fam := examples[i].Family
		if _, ok := byFamily[fam]; !ok {
			order = append(order, fam)
		}
		byFamily[fam] = append(byFamily[fam], i)
	}
	var triplets [][3]int
	for _, fam := range order {
		members := byFamily[fam]
		if len(members) < 2 {
			continue
		}
		neg := -1
		for _, other := range order {
			if other != fam && len(byFamily[other]) > 0 {
				neg = byFamily[other][0]
				break
			}
		}
		if neg < 0 {
			continue
		}
		for i := 0; i < len(members)-1 && len(triplets) < limit; i++ {
			triplets = append(triplets, [3]int{members[i], members[i+1], neg})
		}
	}
	return triplets
}

func separationLoss(scores, labels []float32, margin float32) float64 {
	n := len(scores)
	if n == 0 {
		return 0
	}
	inv := 1 / float64(n)
	var loss float64
	for i := range scores {
		hinge := float64(margin) - float64(labels[i])*float64(scores[i])
		if hinge > 0 {
			loss += (hinge * hinge) * inv
		}
	}
	return loss
}

func tripletLoss(anchor, positive, negative []float32, margin float32) float64 {
	var posDist, negDist float64
	for i := range anchor {
		ap := float64(anchor[i]) - float64(positive[i])
		an := float64(anchor[i]) - float64(negative[i])
		posDist += ap * ap
		negDist += an * an
	}
	loss := (posDist - negDist) + float64(margin)
	if loss <= 0 {
		return 0
	}
	return loss
}

func bitBalanceLoss(hidden []float32, batch, dim int) float64 {
	inv := 1 / float64(batch)
	var loss float64
	for d := range dim {
		var sum float64
		for b := range batch {
			sum += float64(hidden[b*dim+d])
		}
		mu := sum * inv
		loss += mu * mu
	}
	return loss
}

func acceptanceWeights() projlearn.LossWeights {
	return projlearn.LossWeights{Separation: 1, Triplet: 0.1, BitBalance: 0.01, Margin: 1, TripletMargin: 1}
}

func acceptanceAdam() c2projlearn.AdamWConfig {
	return c2projlearn.AdamWConfig{
		LearningRate: 1e-3,
		Beta1:        0.9,
		Beta2:        0.999,
		Epsilon:      1e-8,
		WeightDecay:  0.01,
	}
}

func cloneBatch(src []projlearn.Example) []projlearn.Example {
	dst := make([]projlearn.Example, len(src))
	copy(dst, src)
	return dst
}

type epochRun struct {
	stats  []projlearn.TrainStats
	params *projlearn.Params
	cfg    projlearn.Config
	step   int
}

func trainEpochs(t *testing.T, sample []projlearn.Example, triplets [][3]int, epochs int, seed uint64) epochRun {
	t.Helper()
	cfg := projlearn.DefaultConfig()
	params := projlearn.NewParams(cfg, seed)
	requireShapes(t, params, cfg)
	ws := projlearn.NewWorkspace(cfg, 253, 64)
	if ws == nil {
		t.Fatal("NewWorkspace a rendu nil")
	}
	rng := projlearn.NewPCG64(seed)
	if rng == nil {
		t.Fatal("NewPCG64 a rendu nil")
	}
	grads := zeroLike(params)
	momentsM := zeroLike(params)
	momentsV := zeroLike(params)
	batch := cloneBatch(sample)
	trips := append([][3]int(nil), triplets...)
	weights := acceptanceWeights()
	adam := acceptanceAdam()
	step := 1
	stats := make([]projlearn.TrainStats, 0, epochs)
	for epoch := 1; epoch <= epochs; epoch++ {
		got, err := projlearn.TrainEpoch(params, grads, momentsM, momentsV, cfg, ws, batch, trips, weights, adam, step, rng)
		if err != nil {
			t.Fatalf("TrainEpoch époque %d: %v", epoch, err)
		}
		if got.Steps <= 0 {
			t.Fatalf("TrainEpoch époque %d: Steps=%d, attendu un pas par lot de 64", epoch, got.Steps)
		}
		step += got.Steps
		stats = append(stats, got)
	}
	return epochRun{stats: stats, params: params, cfg: cfg, step: step}
}

func measureReferenceLosses(t *testing.T, params *projlearn.Params, cfg projlearn.Config, ws *projlearn.Workspace, sample []projlearn.Example, triplets [][3]int) {
	t.Helper()
	scores := make([]float32, len(sample))
	labels := make([]float32, len(sample))
	hiddenRows := make([][]float32, len(sample))
	flat := make([]float32, 0, len(sample)*cfg.CodeBits)
	for i := range sample {
		_, hidden, score := projlearn.Forward(params, cfg, &sample[i], ws)
		if len(hidden) != cfg.CodeBits {
			t.Fatalf("Forward exemple %d: len(h)=%d, attendu %d", i, len(hidden), cfg.CodeBits)
		}
		row := append([]float32(nil), hidden...)
		hiddenRows[i] = row
		flat = append(flat, row...)
		scores[i] = score
		labels[i] = sample[i].Label
	}
	sep := separationLoss(scores, labels, 1)
	var triSum float64
	for _, tri := range triplets {
		triSum += tripletLoss(hiddenRows[tri[0]], hiddenRows[tri[1]], hiddenRows[tri[2]], 1)
	}
	triMean := 0.0
	if len(triplets) > 0 {
		triMean = triSum / float64(len(triplets))
	}
	var balSum float64
	lots := 0
	for start := 0; start+64 <= len(sample); start += 64 {
		balSum += bitBalanceLoss(flat[start*cfg.CodeBits:(start+64)*cfg.CodeBits], 64, cfg.CodeBits)
		lots++
	}
	balMean := 0.0
	if lots > 0 {
		balMean = balSum / float64(lots)
	}
	if math.IsNaN(sep) || math.IsInf(sep, 0) {
		t.Fatalf("perte de séparation initiale non finie: %g", sep)
	}
	t.Logf("pertes initiales référence: séparation=%g triplet_moyenne=%g équilibre_bits_moyenne=%g lots=%d triplets=%d", sep, triMean, balMean, lots, len(triplets))
}

func scoreAUC(scores, labels []float32) (auc float64, nPos, nNeg, wins, ties, losses, tp, fp, tn, fn int) {
	type scored struct {
		score   float64
		hostile bool
	}
	ranked := make([]scored, len(scores))
	for i := range scores {
		hostile := labels[i] > 0
		ranked[i] = scored{score: float64(scores[i]), hostile: hostile}
		if hostile {
			nPos++
			if scores[i] >= 0 {
				tp++
			} else {
				fn++
			}
		} else {
			nNeg++
			if scores[i] >= 0 {
				fp++
			} else {
				tn++
			}
		}
	}
	if nPos == 0 || nNeg == 0 {
		return 0, nPos, nNeg, 0, 0, 0, tp, fp, tn, fn
	}
	slices.SortFunc(ranked, func(a, b scored) int {
		return cmp.Compare(a.score, b.score)
	})
	var rankSumPos float64
	i := 0
	for i < len(ranked) {
		j := i + 1
		for j < len(ranked) && ranked[j].score == ranked[i].score {
			j++
		}
		avgRank := float64(i+1+j) * 0.5
		posInTie := 0
		for k := i; k < j; k++ {
			if ranked[k].hostile {
				posInTie++
			}
		}
		rankSumPos += float64(posInTie) * avgRank
		i = j
	}
	uStat := rankSumPos - float64(nPos)*float64(nPos+1)*0.5
	auc = uStat / (float64(nPos) * float64(nNeg))
	for _, pos := range ranked {
		if !pos.hostile {
			continue
		}
		for _, neg := range ranked {
			if neg.hostile {
				continue
			}
			switch {
			case pos.score > neg.score:
				wins++
			case pos.score == neg.score:
				ties++
			default:
				losses++
			}
		}
	}
	return auc, nPos, nNeg, wins, ties, losses, tp, fp, tn, fn
}

func TestTrainEpoch_LossDecreasesOnRealCorpus(t *testing.T) {
	corpusDir := wittgensteinDir(t)
	train, heldOut, err := projlearn.LoadColdSplitCorpus(corpusDir, 100)
	if err != nil {
		t.Fatalf("LoadColdSplitCorpus: %v", err)
	}
	requireCorpusContract(t, train, heldOut)
	sample := balancedSubsample(t, train, 256)
	if len(sample) != 512 {
		t.Fatalf("sous-échantillon %d, attendu 512", len(sample))
	}
	triplets := buildTriplets(sample, 64)
	if len(triplets) == 0 {
		t.Fatal("aucun triplet constructible sur le sous-échantillon")
	}
	cfg := projlearn.DefaultConfig()
	params := projlearn.NewParams(cfg, 7)
	requireShapes(t, params, cfg)
	ws := projlearn.NewWorkspace(cfg, 253, 64)
	if ws == nil {
		t.Fatal("NewWorkspace a rendu nil")
	}
	measureReferenceLosses(t, params, cfg, ws, sample, triplets)
	run := trainEpochs(t, sample, triplets, 3, 7)
	epoch1 := run.stats[0]
	epoch3 := run.stats[2]
	t.Logf("époque 1: séparation=%g triplet=%g équilibre=%g exemples=%d lots=%d pas=%d", epoch1.SeparationLoss, epoch1.TripletLoss, epoch1.BitBalanceLoss, epoch1.Examples, epoch1.Batches, epoch1.Steps)
	t.Logf("époque 3: séparation=%g triplet=%g équilibre=%g exemples=%d lots=%d pas=%d", epoch3.SeparationLoss, epoch3.TripletLoss, epoch3.BitBalanceLoss, epoch3.Examples, epoch3.Batches, epoch3.Steps)
	if math.IsNaN(epoch1.SeparationLoss) || math.IsNaN(epoch3.SeparationLoss) || epoch1.SeparationLoss <= 0 {
		t.Fatalf("SeparationLoss inutilisable: époque 1 = %g, époque 3 = %g", epoch1.SeparationLoss, epoch3.SeparationLoss)
	}
	if !(epoch3.SeparationLoss < 0.9*epoch1.SeparationLoss) {
		t.Fatalf("SeparationLoss époque 3 = %g, époque 1 = %g, attendu < 0,9 ×", epoch3.SeparationLoss, epoch1.SeparationLoss)
	}
	evalSet := heldOutSample(t, heldOut, 256)
	scores := make([]float32, len(evalSet))
	labels := make([]float32, len(evalSet))
	for i := range evalSet {
		_, hidden, score := projlearn.Forward(run.params, run.cfg, &evalSet[i], ws)
		if len(hidden) != run.cfg.CodeBits {
			t.Fatalf("Forward heldOut %d: len(h)=%d, attendu %d", i, len(hidden), run.cfg.CodeBits)
		}
		scores[i] = score
		labels[i] = evalSet[i].Label
	}
	auc, nPos, nNeg, wins, ties, losses, tp, fp, tn, fn := scoreAUC(scores, labels)
	t.Logf("AUC heldOut n=%d nPos=%d nNeg=%d paires_pos_sup=%d paires_egales=%d paires_pos_inf=%d AUC=%.4f seuil0 TP=%d FP=%d TN=%d FN=%d", len(evalSet), nPos, nNeg, wins, ties, losses, auc, tp, fp, tn, fn)
	if nPos == 0 || nNeg == 0 || !(auc > 0.5) {
		t.Fatalf("AUC=%g sur nPos=%d nNeg=%d, attendu > 0,5", auc, nPos, nNeg)
	}
}

func TestTrainEpoch_BitExactReplay(t *testing.T) {
	corpusDir := wittgensteinDir(t)
	train, _, err := projlearn.LoadColdSplitCorpus(corpusDir, 100)
	if err != nil {
		t.Fatalf("LoadColdSplitCorpus: %v", err)
	}
	if len(train) == 0 {
		t.Fatal("train vide")
	}
	sample := balancedSubsample(t, train, 256)
	triplets := buildTriplets(sample, 64)
	dir := t.TempDir()
	pathA := filepath.Join(dir, "run-a.c2pl")
	pathB := filepath.Join(dir, "run-b.c2pl")
	runA := trainEpochs(t, sample, triplets, 2, 7)
	if err := projlearn.SaveCheckpoint(pathA, runA.params, runA.cfg, runA.step); err != nil {
		t.Fatalf("SaveCheckpoint A: %v", err)
	}
	runB := trainEpochs(t, sample, triplets, 2, 7)
	if err := projlearn.SaveCheckpoint(pathB, runB.params, runB.cfg, runB.step); err != nil {
		t.Fatalf("SaveCheckpoint B: %v", err)
	}
	left, err := os.ReadFile(pathA)
	if err != nil {
		t.Fatalf("lecture A: %v", err)
	}
	right, err := os.ReadFile(pathB)
	if err != nil {
		t.Fatalf("lecture B: %v", err)
	}
	if len(left) == 0 || len(right) == 0 {
		t.Fatalf("point de contrôle vide: %d et %d octets", len(left), len(right))
	}
	if !bytes.Equal(left, right) {
		t.Fatalf("rejouabilité: fichiers différents (%d et %d octets)", len(left), len(right))
	}
}
