// Package engine — template_rarity.go
// Mesure de rareté probabiliste du gabarit de journal par créneau horaire.
//
// Le test de Hamming sur le mot 7 (SimHash de la charge) accepte une cible dès
// qu'une seule référence en est proche : avec N références et une probabilité p
// qu'une charge quelconque tombe dans la boule de l'une d'elles, la
// probabilité qu'elle tombe dans l'union vaut 1 - (1-p)^N, qui tend vers 1
// quand la baseline grossit. Une ligne injectée finit donc toujours par avoir
// un voisin de contenu. Le modèle ci-dessous remplace ce test booléen par la
// surprise -log2 P(gabarit | créneau) : le silo place dans la charge le
// gabarit normalisé de la ligne (PID, adresses, nombres, chemins volatils
// masqués), si bien que le mot 7 est une empreinte du gabarit, et le modèle
// compte ces empreintes par créneau.
package engine

import (
	"math"
	"math/bits"
)

// TemplateRaritySlots est le nombre de créneaux du modèle : 16 créneaux de
// 90 minutes, soit quatre des 64 créneaux du mot 5 de VectorizeServerHealthLocality.
const TemplateRaritySlots = 16

// templateUniverseBits fixe la probabilité a priori d'un gabarit jamais vu à
// 2^-32 : sa surprise dépasse toujours 32 bits, quelle que soit la taille de la
// baseline, ce qui la sépare d'un gabarit déjà observé.
const templateUniverseBits = 32

// DefaultMaxContentSurpriseBits est le seuil de surprise de DefaultLocalityThresholds.
// Un gabarit vu une fois parmi n événements du même créneau coûte environ
// log2(n+1) bits (13,3 bits pour n = 10 000) ; un gabarit vu ailleurs dans la
// journée mais jamais dans ce créneau coûte environ log2(n_créneau) + log2(n_total),
// soit 26,6 bits pour 10 000 événements de chaque côté ; un gabarit inédit
// coûte au moins 32 bits.
const DefaultMaxContentSurpriseBits = 24

// TemplateRarity compte les empreintes de gabarit (mot 7) par créneau. Les
// comptes sont pondérés : une tranche échantillonnée compte pour le nombre
// d'événements qu'elle représente. Les lectures n'allouent pas ; le modèle
// n'est pas protégé contre l'accès concurrent, son propriétaire le verrouille.
type TemplateRarity struct {
	slot       map[uint64]float64 // (empreinte, créneau) → poids
	global     map[uint64]float64 // empreinte → poids
	slotTotal  [TemplateRaritySlots]float64
	totalCount float64
}

// NewTemplateRarity rend un modèle vide.
func NewTemplateRarity() *TemplateRarity {
	return &TemplateRarity{slot: make(map[uint64]float64), global: make(map[uint64]float64)}
}

// LocalitySlotOf décode le créneau (0..63) du mot 5 d'un code de
// VectorizeServerHealthLocality : la fenêtre de 32 bits à 1 commence au bit
// dont le prédécesseur circulaire vaut 0. Un mot hors de cette forme rend 0.
func LocalitySlotOf(w5 uint64) int {
	starts := w5 &^ bits.RotateLeft64(w5, 1)
	if starts == 0 {
		return 0
	}
	return bits.TrailingZeros64(starts)
}

// TemplateSlotOf rend le créneau du modèle pour un code de localité.
func TemplateSlotOf(code *[8]uint64) int {
	return LocalitySlotOf(code[5]) * TemplateRaritySlots / localitySlotsPerDay
}

func templateSlotKey(fp uint64, slot int) uint64 {
	return mixSpatial64(fp ^ uint64(slot+1)*0x9E3779B97F4A7C15)
}

// Observe ajoute weight observations du gabarit du code. Un mot 7 nul (charge
// de moins de trois octets) n'a pas de gabarit et n'est pas compté.
func (m *TemplateRarity) Observe(code *[8]uint64, weight float64) {
	fp := code[7]
	if fp == 0 || weight <= 0 {
		return
	}
	s := TemplateSlotOf(code)
	m.slot[templateSlotKey(fp, s)] += weight
	m.global[fp] += weight
	m.slotTotal[s] += weight
	m.totalCount += weight
}

// Total rend le poids total observé.
func (m *TemplateRarity) Total() float64 { return m.totalCount }

// Surprise rend -log2 P(gabarit | créneau) en bits, par lissage hiérarchique :
//
//	P_global(g) = (c(g) + 2^-32) / (n + 1)
//	P(g | s)   = (c(g, s) + P_global(g)) / (n_s + 1)
//
// Un gabarit fréquent dans le créneau est peu surprenant ; un gabarit vu
// seulement à d'autres heures l'est davantage ; un gabarit jamais vu l'est au
// moins de 32 bits. Un code sans gabarit (mot 7 nul) rend 0. Aucune allocation.
func (m *TemplateRarity) Surprise(code *[8]uint64) float64 {
	fp := code[7]
	if fp == 0 {
		return 0
	}
	s := TemplateSlotOf(code)
	pg := (m.global[fp] + math.Ldexp(1, -templateUniverseBits)) / (m.totalCount + 1)
	p := (m.slot[templateSlotKey(fp, s)] + pg) / (m.slotTotal[s] + 1)
	return -math.Log2(p)
}
