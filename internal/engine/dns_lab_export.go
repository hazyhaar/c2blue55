package engine

// AccumulateVerdict ajoute un verdict aux comptes de la partition tenue à l'écart.
func AccumulateVerdict(m *ColdSplitMetrics, v CascadeVerdict, hostile bool) {
	accumulateVerdictMetrics(m, v, hostile)
}

// ThreatScore calcule le score continu de la tête tunnel.
func ThreatScore(features *[EmbeddingDim]float32, disk *FloppyDisk) float64 {
	return continuousFloppyThreatScore(features, disk)
}

// FinalizeMetrics calcule le taux majoritaire et l'aire sous la courbe.
// Si les scores et leurs étiquettes diffèrent en nombre, les métriques restent
// inchangées (notamment AUC à zéro pour une métrique initialement vide).
func FinalizeMetrics(m *ColdSplitMetrics, posCount, negCount int, scores []float64, hostile []bool) {
	if len(scores) != len(hostile) {
		return
	}
	samples := make([]scoredSample, 0, len(scores))
	for index, score := range scores {
		samples = append(samples, scoredSample{score: score, hostile: hostile[index]})
	}
	finalizeColdSplitMetrics(m, posCount, negCount, samples)
}

// TunnelFeatures extrait les mêmes traits tunnel que EvaluateDNSView.
func TunnelFeatures(view DNSQueryView, dst *[EmbeddingDim]float32) {
	ExtractDNSTunnel512(view.Subdomain, view.QType, view.LabelCount, view.MaxLabelLen, view.SubCardinality, dst[:])
}
