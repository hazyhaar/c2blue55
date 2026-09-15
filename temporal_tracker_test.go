package c2blue55

import (
	"fmt"
	"testing"
)

// TestTemporalTracker_BeaconDetection teste la détection mathématique de périodicité (jitter de beaconing).
// Zéro mock : intervalles réguliers réels (cadence Cobalt Strike standard avec jitter 10% vs trafic humain).
func TestTemporalTracker_BeaconDetection(t *testing.T) {
	tracker := NewTemporalTracker()
	domain := "c2-beacon.attacker.net"

	// 1. Simulation d'un beaconing régulier C2 (intervalle fixe de 60s +/- 3s, soit jitter ~5%)
	// Données d'intervalles documentées de balises réelles Cobalt Strike.
	baseTime := uint32(1700000000)
	c2Timestamps := []uint32{
		baseTime,
		baseTime + 60,
		baseTime + 119,
		baseTime + 181,
		baseTime + 240,
		baseTime + 301,
		baseTime + 359,
		baseTime + 420,
	}

	var lastJitter uint16
	var lastCount uint16
	for _, ts := range c2Timestamps {
		jitter, _, count := tracker.RecordQuery(domain, "sync", ts)
		lastJitter = jitter
		lastCount = count
	}

	if lastCount != 8 {
		t.Errorf("lastCount = %d, attendu 8", lastCount)
	}
	// Jitter attendu très bas (< 10%) en raison de la régularité du beaconing
	if lastJitter > 15 {
		t.Errorf("Jitter de beaconing = %d%%, attendu <= 15%%", lastJitter)
	}

	// 2. Trafic humain / poissonnien légitime sur un autre domaine
	// Intervalles erratiques (1s, 45s, 3s, 500s, 12s)
	legitDomain := "browse.example.org"
	legitTimestamps := []uint32{
		baseTime,
		baseTime + 1,
		baseTime + 46,
		baseTime + 49,
		baseTime + 549,
		baseTime + 561,
	}

	var legitJitter uint16
	for _, ts := range legitTimestamps {
		jitter, _, _ := tracker.RecordQuery(legitDomain, "page", ts)
		legitJitter = jitter
	}

	// Jitter erratique attendu élevé (> 40%)
	if legitJitter < 40 {
		t.Errorf("Jitter de trafic humain = %d%%, attendu >= 40%%", legitJitter)
	}
}

// TestTemporalTracker_UniqueSubdomainsBloom teste le comptage compact des sous-domaines uniques via Bloom filter.
func TestTemporalTracker_UniqueSubdomainsBloom(t *testing.T) {
	tracker := NewTemporalTracker()
	domain := "exfil.tunnel.org"
	baseTime := uint32(1700000000)

	// Envoi de 10 requêtes avec des sous-domaines différents (exfiltration fragmentée DNS réelles).
	// Le filtre 256 bits à deux fonctions de hachage ne doit produire aucune collision : le
	// comptage des sous-domaines uniques doit être exact, et non plus sous-estimé comme avec
	// l'ancien filtre 64 bits saturé dès 6 à 8 entrées.
	for i := 0; i < 10; i++ {
		sub := fmt.Sprintf("chunk%d.payload", i)
		_, uniqueSubs, _ := tracker.RecordQuery(domain, sub, baseTime+uint32(i*10))
		if uniqueSubs != uint16(i+1) {
			t.Fatalf("uniqueSubs = %d, attendu exactement %d à l'itération %d", uniqueSubs, i+1, i)
		}
	}

	// Une répétition du même sous-domaine ne doit pas incrémenter le compteur.
	_, uniqueSubs, _ := tracker.RecordQuery(domain, "chunk0.payload", baseTime+1000)
	if uniqueSubs != 10 {
		t.Errorf("uniqueSubs = %d après répétition, attendu 10", uniqueSubs)
	}
}

// findSameSlotDomains retourne deux domaines distincts qui se projettent sur le même
// slot (même hash modulo MaxTrackedDomains). La recherche est déterministe : sur 2049
// candidats, le principe des tiroirs garantit une collision de slot.
func findSameSlotDomains(t *testing.T) (string, string) {
	t.Helper()
	seen := make(map[uint64]string, MaxTrackedDomains)
	for i := 0; i < MaxTrackedDomains+8; i++ {
		d := fmt.Sprintf("same-slot-candidate-%d.attacker.net", i)
		idx := FNV1a64String(d) % MaxTrackedDomains
		if prev, ok := seen[idx]; ok {
			return prev, d
		}
		seen[idx] = d
	}
	t.Fatal("aucune paire de collision de slot trouvée")
	return "", ""
}

// TestTemporalTracker_SameSecondSlotCollision vérifie que deux domaines distincts
// partageant un slot et interrogés dans la même seconde ne s'écrasent plus mutuellement.
func TestTemporalTracker_SameSecondSlotCollision(t *testing.T) {
	tracker := NewTemporalTracker()
	domA, domB := findSameSlotDomains(t)
	base := uint32(1700000000)

	// Domaine A une première fois.
	_, _, countA := tracker.RecordQuery(domA, "a", base)
	if countA != 1 {
		t.Fatalf("countA = %d, attendu 1", countA)
	}

	// Domaine B à la même seconde sur le même slot : il doit obtenir un slot voisin propre.
	_, _, countB := tracker.RecordQuery(domB, "b", base)
	if countB != 1 {
		t.Fatalf("countB = %d, attendu 1", countB)
	}

	// Retour de A à la même seconde : son compteur doit continuer, pas repartir de zéro.
	_, _, countA = tracker.RecordQuery(domA, "a", base)
	if countA != 2 {
		t.Errorf("countA = %d après ré-interrogation, attendu 2 (écrasement par collision)", countA)
	}
	_, _, countB = tracker.RecordQuery(domB, "b", base)
	if countB != 2 {
		t.Errorf("countB = %d après ré-interrogation, attendu 2 (écrasement par collision)", countB)
	}
}

// TestTemporalTracker_WindowExpiration vérifie la purge de la fenêtre temporelle après
// plus d'une heure d'inactivité, afin de ne pas fausser le jitter avec des deltas périmés.
func TestTemporalTracker_WindowExpiration(t *testing.T) {
	tracker := NewTemporalTracker()
	domain := "dormant-beacon.attacker.net"
	base := uint32(1700000000)

	for i := 0; i < 6; i++ {
		tracker.RecordQuery(domain, "sync", base+uint32(i*60))
	}

	// Réapparition après 3601 secondes d'inactivité : la fenêtre est purgée.
	lastSeen := base + uint32(5*60)
	_, _, count := tracker.RecordQuery(domain, "sync", lastSeen+3601)
	if count != 1 {
		t.Errorf("count = %d après péremption, attendu 1 (fenêtre non purgée)", count)
	}

	// À l'inverse, une réapparition sous le seuil conserve l'historique.
	tracker2 := NewTemporalTracker()
	for i := 0; i < 3; i++ {
		tracker2.RecordQuery("keep-window.net", "sync", base+uint32(i*60))
	}
	_, _, count2 := tracker2.RecordQuery("keep-window.net", "sync", base+3600)
	if count2 != 4 {
		t.Errorf("count2 = %d sous le seuil d'inactivité, attendu 4", count2)
	}
}

// TestTemporalTracker_ZeroAllocation prouve formellement 0 allocation tas lors du suivi temporel.
func TestTemporalTracker_ZeroAllocation(t *testing.T) {
	tracker := NewTemporalTracker()
	domain := "beacon.test.net"
	sub := "telemetry01"
	var ts uint32 = 1700000000

	allocs := testing.AllocsPerRun(1000, func() {
		ts += 10
		_, _, _ = tracker.RecordQuery(domain, sub, ts)
	})

	if allocs != 0 {
		t.Errorf("RecordQuery AllocsPerRun = %.2f, attendu 0.0 (0 B/op)", allocs)
	}
}

// findCollidingDomainsWithStep retourne deux domaines distincts partageant le même slot
// d'ancrage et un pas de sondage mix64 différent de 1, afin d'éprouver la dispersion.
func findCollidingDomainsWithStep(t *testing.T) (domA, domB string, homeIdx uint64, step int) {
	t.Helper()
	seen := make(map[uint64]string)
	for i := 0; i < 500000; i++ {
		d := fmt.Sprintf("disperse-%d.attacker.net", i)
		h := FNV1a64String(d)
		idx := h % MaxTrackedDomains
		prev, ok := seen[idx]
		if ok && prev != d {
			s := int((mix64(h) & 0x7) | 1)
			if s != 1 {
				return prev, d, idx, s
			}
		}
		seen[idx] = d
	}
	t.Fatal("aucune paire de collision avec pas dispersé trouvée")
	return "", "", 0, 0
}

// TestTemporalTracker_CollisionProbingDispersed vérifie que la résolution de collision
// s'effectue par un pas dérivé de mix64(h) et non par un sondage linéaire consécutif.
// Un attaquant ne peut donc plus saturer des slots voisins immédiats par collision FNV-1a.
func TestTemporalTracker_CollisionProbingDispersed(t *testing.T) {
	tracker := NewTemporalTracker()
	domA, domB, homeIdx, step := findCollidingDomainsWithStep(t)
	hB := FNV1a64String(domB)
	base := uint32(1700000000)

	tracker.RecordQuery(domA, "a", base)

	// Le pas doit être impair (donc premier avec 8192) et borné à [1,7].
	if step%2 == 0 || step < 1 || step > 7 {
		t.Fatalf("pas de sondage invalide: %d", step)
	}

	tracker.RecordQuery(domB, "b", base)
	altIdx := (homeIdx + uint64(step)) % MaxTrackedDomains
	if tracker.slots[altIdx].DomainHash != hB {
		t.Fatalf("dispersion mix64 non appliquée: D1 attendu au slot %d (pas %d)", altIdx, step)
	}

	// Les deux historiques restent indépendants et progressent.
	_, _, countA := tracker.RecordQuery(domA, "a", base+1)
	_, _, countB := tracker.RecordQuery(domB, "b", base+1)
	if countA != 2 || countB != 2 {
		t.Errorf("compteurs = (%d,%d), attendu (2,2) après dispersion", countA, countB)
	}
}

// TestTemporalTracker_Capacity8192 vérifie que la table contiguë absorbe 8192 domaines
// simultanément sans écrasement de slot. Chaque domaine est placé sur un slot d'ancrage
// distinct (permutation de slots), remplissant intégralement la capacité, puis relu pour
// prouver la persistance de son historique. Une table de 2048 slots perdrait ce test.
func TestTemporalTracker_Capacity8192(t *testing.T) {
	if MaxTrackedDomains != 8192 {
		t.Fatalf("MaxTrackedDomains = %d, attendu 8192", MaxTrackedDomains)
	}

	seen := make(map[uint64]struct{}, MaxTrackedDomains)
	domains := make([]string, 0, MaxTrackedDomains)
	for i := 0; len(domains) < MaxTrackedDomains; i++ {
		d := fmt.Sprintf("capacity-%d.test", i)
		idx := FNV1a64String(d) % MaxTrackedDomains
		if _, ok := seen[idx]; ok {
			continue
		}
		seen[idx] = struct{}{}
		domains = append(domains, d)
	}

	tracker := NewTemporalTracker()
	base := uint32(1700000000)

	for i, d := range domains {
		if _, _, c := tracker.RecordQuery(d, "s", base); c != 1 {
			t.Fatalf("insertion %d (%s): count = %d, attendu 1", i, d, c)
		}
	}

	for i, d := range domains {
		if _, _, c := tracker.RecordQuery(d, "s", base+1); c != 2 {
			t.Fatalf("relecture %d (%s): count = %d, attendu 2 (slot écrasé)", i, d, c)
		}
	}
}
