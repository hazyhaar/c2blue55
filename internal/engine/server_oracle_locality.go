// Package engine — server_oracle_locality.go
// Encodage 512 bits à préservation de distance pour l'oracle serveur, et sa
// comparaison par groupes de mots. Contrairement à VectorizeServerHealth, une
// petite variation d'une métrique scalaire produit une petite distance de Hamming.
// Le silo stocke encore le code historique : y substituer ce code impose un
// changement de version du format .c2oracle.
package engine

import "math/bits"

// Agencement des 8 mots de 64 bits de VectorizeServerHealthLocality.
//
//	mot 0 : sous-système, code catégoriel pseudo-aléatoire (écart attendu 32 bits entre valeurs)
//	mot 1 : action, code catégoriel pseudo-aléatoire
//	mot 2 : bits 0..31 sévérité en thermomètre (8 bits par niveau), bits 32..63 log2(CorrelatedCount) en thermomètre (2 bits par octave)
//	mot 3 : HealthScore 0..1000 en thermomètre de 64 bits (1 bit ≈ 15,6 points)
//	mot 4 : EntropyQ8 0..2048 en thermomètre de 64 bits (1 bit = 0,125 bit d'entropie)
//	mot 5 : heure de la journée en code circulaire (fenêtre de 32 bits tournant sur 64, pas de 22,5 min ;
//	        un écart de k pas coûte 2k bits jusqu'à douze heures)
//	mot 6 : EntityID, code catégoriel par mélange bijectif (deux entités distinctes diffèrent toujours)
//	mot 7 : SimHash des trigrammes d'octets de la charge (similarité de Jaccard approchée)
const (
	localityScoreMax    = 1000
	localityEntropyMax  = 2048
	localitySlotsPerDay = 64
)

// thermo64 rend un mot dont les n bits de poids faible valent 1 (n borné à 64).
func thermo64(n uint) uint64 {
	if n >= 64 {
		return ^uint64(0)
	}
	return (uint64(1) << n) - 1
}

// VectorizeServerHealthLocality projette un instantané sans allocation tas ;
// la distance de Hamming entre deux codes est la somme des écarts de chaque champ.
func VectorizeServerHealthLocality(s *ServerHealthSnapshot, out *[8]uint64) {
	if s == nil || out == nil {
		return
	}
	out[0] = mixSpatial64(uint64(s.Subsystem) ^ 0x5B5B000000000001)
	out[1] = mixSpatial64(uint64(s.Action) ^ 0x5B5B000000000002)

	sev := uint(min(s.Severity, SeverityCritical)) * 8
	corr := uint(bits.Len16(s.CorrelatedCount)) * 2
	out[2] = thermo64(sev) | thermo64(corr)<<32

	score := uint(min(uint32(s.HealthScore), localityScoreMax)) * 64 / localityScoreMax
	out[3] = thermo64(score)
	ent := uint(min(s.EntropyQ8, localityEntropyMax)) * 64 / localityEntropyMax
	out[4] = thermo64(ent)

	slot := int(s.TimestampSec % 86400 * localitySlotsPerDay / 86400)
	out[5] = bits.RotateLeft64(0x00000000FFFFFFFF, slot)

	out[6] = mixSpatial64(s.EntityID ^ 0x5B5B000000000006)
	out[7] = payloadSimHash64(&s.RawPayload)
}

// payloadSimHash64 calcule un SimHash 64 bits des trigrammes d'octets de la charge,
// arrêtée au premier octet nul ; compteurs sur la pile, aucune allocation.
func payloadSimHash64(p *[FeaturePayloadBytes]byte) uint64 {
	n := 0
	for n < len(p) && p[n] != 0 {
		n++
	}
	if n < 3 {
		return 0
	}
	var acc [64]int16
	for i := 0; i+3 <= n; i++ {
		h := mixSpatial64(uint64(p[i]) | uint64(p[i+1])<<8 | uint64(p[i+2])<<16)
		for b := range 64 {
			acc[b] += int16(h>>b&1)*2 - 1
		}
	}
	var out uint64
	for b := range 64 {
		if acc[b] > 0 {
			out |= 1 << b
		}
	}
	return out
}

// LocalityDistance décompose l'écart entre deux codes de VectorizeServerHealthLocality
// par groupe de mots. Un seuil unique sur la distance totale est inopérant : un
// changement de catégorie coûte environ 32 bits, autant qu'une forte dérive scalaire.
type LocalityDistance struct {
	Categorical  int // mots 0 et 1 : sous-système et action, doivent être identiques
	SeverityRise int // niveaux de sévérité gagnés par la cible sur la référence (négatif si baisse)
	Scalar       int // mots 2 à 5 : sévérité, corrélation, score, entropie, heure
	Entity       int // mot 6 : entité ; 0 si et seulement si même EntityID
	Content      int // mot 7 : SimHash de la charge
}

// LocalityThresholds fixe la tolérance de chaque groupe de LocalityDistance.
type LocalityThresholds struct {
	MaxSeverityRise int // hausse de sévérité admise, en niveaux ; 0 refuse toute aggravation
	MaxScalar       int // bits admis sur les mots 2 à 5
	MaxEntity       int // bits admis sur le mot 6 ; 0 exige la même entité
	MaxContent      int // bits admis sur le mot 7
	// MaxContentSurpriseBits, s'il est positif, remplace dans
	// ServerBaselineOracle.QueryStateLocality le test MaxContent par un seuil
	// sur la surprise -log2 P(gabarit | créneau) du mot 7 (voir TemplateRarity).
	// Within et EvaluateLocalityMatch, qui comparent deux codes sans baseline,
	// l'ignorent.
	MaxContentSurpriseBits int
}

// MaxEntityToleranceBits borne MaxEntity. Deux entités distinctes diffèrent sur
// le mot 6 d'une loi binomiale B(64, 1/2) : une tolérance de 24 bits confond
// deux entités dans 3,0 % des cas, une tolérance de 16 bits dans 3,9·10⁻⁵ des cas.
const MaxEntityToleranceBits = 16

// DefaultLocalityThresholds admet une dérive scalaire de 24 bits, soit par
// exemple un score en baisse de 160 points avec 0,5 bit d'entropie et une
// demi-heure, ou l'heure seule décalée de 4 h 30 (12 pas de 22,5 min à 2 bits
// par pas). Elle admet une dérive de charge de 24 bits, mais aucune différence
// d'entité : le mot 6 est un code catégoriel bijectif, si bien que la même
// entité donne 0 bit et que toute tolérance ne ferait qu'admettre des entités
// étrangères. Toute aggravation de sévérité est refusée. Face à une
// baseline, le contenu est jugé par sa rareté : un gabarit dont la surprise
// dans son créneau dépasse DefaultMaxContentSurpriseBits n'est pas nominal.
func DefaultLocalityThresholds() LocalityThresholds {
	return LocalityThresholds{MaxSeverityRise: 0, MaxScalar: 24, MaxEntity: 0, MaxContent: 24,
		MaxContentSurpriseBits: DefaultMaxContentSurpriseBits}
}

// localitySeverityMask isole le thermomètre de sévérité (8 bits par niveau) du mot 2.
const localitySeverityMask = 0x00000000FFFFFFFF

// LocalityDistanceOf mesure l'écart par groupe entre la cible observée et une
// référence ; aucune allocation tas.
func LocalityDistanceOf(target, reference *[8]uint64) LocalityDistance {
	var d LocalityDistance
	d.Categorical = bits.OnesCount64(target[0]^reference[0]) + bits.OnesCount64(target[1]^reference[1])
	d.SeverityRise = (bits.OnesCount64(target[2]&localitySeverityMask) - bits.OnesCount64(reference[2]&localitySeverityMask)) / 8
	for w := 2; w <= 5; w++ {
		d.Scalar += bits.OnesCount64(target[w] ^ reference[w])
	}
	d.Entity = bits.OnesCount64(target[6] ^ reference[6])
	d.Content = bits.OnesCount64(target[7] ^ reference[7])
	return d
}

// Within dit si l'écart respecte les seuils : identité catégorielle stricte,
// aggravation de sévérité bornée, tolérances de Hamming par groupe. La
// tolérance d'entité est plafonnée à MaxEntityToleranceBits quelle que soit la
// configuration.
func (d LocalityDistance) Within(cfg LocalityThresholds) bool {
	return d.Categorical == 0 &&
		d.SeverityRise <= cfg.MaxSeverityRise &&
		d.Scalar <= cfg.MaxScalar &&
		d.Entity <= min(cfg.MaxEntity, MaxEntityToleranceBits) &&
		d.Content <= cfg.MaxContent
}

// EvaluateLocalityMatch dit si la cible observée est un voisin nominal de la
// référence candidate ; un code nil n'est jamais voisin.
func EvaluateLocalityMatch(target, candidate *[8]uint64, cfg LocalityThresholds) bool {
	if target == nil || candidate == nil {
		return false
	}
	return LocalityDistanceOf(target, candidate).Within(cfg)
}
