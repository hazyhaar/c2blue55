package c2blue55

import (
	"encoding/binary"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestCompactReputation_ExactAndSubtree teste les correspondances exactes et par sous-arbre.
// These entries are local policy fixtures, not authenticated threat intelligence.
func TestCompactReputation_ExactAndSubtree(t *testing.T) {
	entries := []BuildEntry{
		{Domain: "sophosxl.com", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
		{Domain: "login.microsoft.com", Classification: RepClassAllowTranco, MatchKind: MatchExact},
		{Domain: "tunnel.dnscat2.org", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
	}

	snap, err := CompileReputationSnapshot(entries)
	if err != nil {
		t.Fatalf("CompileReputationSnapshot: %v", err)
	}

	tbl, err := NewReputationTable(snap)
	if err != nil {
		t.Fatalf("NewReputationTable: %v", err)
	}

	// 1. MatchSubtree : doit matcher le domaine parent et tous les sous-domaines
	casesSubtree := []struct {
		fqdn     string
		expected bool
	}{
		{"sophosxl.com", true},
		{"cloudtelemetry.sophosxl.com", true},
		{"a.b.c.sophosxl.com", true},
		{"SOPHOSXL.COM", true},                 // Casse insensible
		{"cloudtelemetry.sophosxl.com.", true}, // Point final ignoré
	}
	for _, tc := range casesSubtree {
		res, ok := tbl.Match(tc.fqdn)
		if ok != tc.expected {
			t.Errorf("Match(%q) = %v, attendu %v", tc.fqdn, ok, tc.expected)
		}
		if ok && (res.Classification != RepClassAllowVendor || res.MatchedDomain != "sophosxl.com") {
			t.Errorf("Match(%q) resultat inattendu: %+v", tc.fqdn, res)
		}
	}

	// 2. Strict label boundary : ne doit PAS matcher si ce n'est pas une frontière de label '.'
	casesStrict := []string{
		"notsophosxl.com",
		"fake-sophosxl.com",
		"sophosxl.com.attacker.net",
		"sophosxl.comm",
	}
	for _, fqdn := range casesStrict {
		if res, ok := tbl.Match(fqdn); ok {
			t.Errorf("Frontiere de label violee: Match(%q) = true (%+v), attendu false", fqdn, res)
		}
	}

	// 3. MatchExact : doit matcher uniquement le FQDN exact, pas les sous-domaines
	if res, ok := tbl.Match("login.microsoft.com"); !ok || res.Classification != RepClassAllowTranco {
		t.Errorf("MatchExact 'login.microsoft.com' a echoue: %+v", res)
	}
	if _, ok := tbl.Match("sub.login.microsoft.com"); ok {
		t.Errorf("MatchExact a matche un sous-domaine par erreur")
	}

	// 4. Blocklist C2
	if res, ok := tbl.Match("c2.data.tunnel.dnscat2.org"); !ok || res.Classification != RepClassBlockC2 {
		t.Errorf("Match dnscat2 a echoue: %+v", res)
	}
}

// TestCompactReputation_ParseDomainList tests a local text fixture.
func TestCompactReputation_ParseDomainList(t *testing.T) {
	rawList := `
# Local test fixture, not threat intelligence
0.0.0.0 bad-c2-node.xyz
127.0.0.1 malware-c2.cc
# Commentaire
legit-service.net
`
	entries, err := ParseDomainList(strings.NewReader(rawList), RepClassBlockC2, MatchSubtree)
	if err != nil {
		t.Fatalf("ParseDomainList: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("Attendu 3 entrees, obtenu %d", len(entries))
	}
	if entries[0].Domain != "bad-c2-node.xyz" || entries[1].Domain != "malware-c2.cc" || entries[2].Domain != "legit-service.net" {
		t.Fatalf("Parsing incorrect: %+v", entries)
	}
}

// TestAtomicReputation_ConcurrentHotReload vérifie le remplacement atomique en mémoire sans verrou (lock-free).
// Les lecteurs concurrents continuent d'interroger la table à pleine vitesse pendant le rechargement.
func TestAtomicReputation_ConcurrentHotReload(t *testing.T) {
	initialEntries := []BuildEntry{
		{Domain: "sophosxl.com", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
	}
	snap, _ := CompileReputationSnapshot(initialEntries)
	tbl, _ := NewReputationTable(snap)
	ar := NewAtomicReputation(tbl)

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// 4 goroutines de lecture intensive
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_, _ = ar.Match("cloudtelemetry.sophosxl.com")
					_, _ = ar.Match("random.domain.net")
				}
			}
		}()
	}

	// Rechargement atomique de la table avec une nouvelle liste
	newEntries := []BuildEntry{
		{Domain: "sophosxl.com", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
		{Domain: "threatfox-c2.biz", Classification: RepClassBlockC2, MatchKind: MatchSubtree},
	}
	time.Sleep(10 * time.Millisecond)

	if err := ar.ReloadFromEntries(newEntries); err != nil {
		t.Fatalf("ReloadFromEntries: %v", err)
	}

	// Vérification immédiate de la présence de la nouvelle entrée
	if res, ok := ar.Match("beacon.threatfox-c2.biz"); !ok || res.Classification != RepClassBlockC2 {
		t.Errorf("Nouvelle entree non visible apres rechargement: %+v", res)
	}

	close(stop)
	wg.Wait()
}

// TestCompactReputation_CorruptEntryOffsetRejected est le test de non-régression de la
// validation des bornes d'index. Toute entrée dont l'intervalle [Offset, Offset+Length)
// déborde du bloc de chaînes — y compris par repli d'entier — doit être rejetée.
func TestCompactReputation_CorruptEntryOffsetRejected(t *testing.T) {
	entries := []BuildEntry{
		{Domain: "sophosxl.com", Classification: RepClassAllowVendor, MatchKind: MatchSubtree},
	}
	snap, err := CompileReputationSnapshot(entries)
	if err != nil {
		t.Fatalf("CompileReputationSnapshot: %v", err)
	}

	// L'offset de la première entrée se situe aux octets 24+8..24+12.
	offsetField := snap[24+8 : 24+12]

	// 1. Offset franc au-delà du bloc de chaînes.
	binary.LittleEndian.PutUint32(offsetField, 0xFFFF)
	if _, err := NewReputationTable(snap); err != ErrCorruptSnapshot {
		t.Fatalf("offset 0xFFFF: attendu ErrCorruptSnapshot, obtenu %v", err)
	}

	// 2. Offset maximal : Offset+Length déborderait l'arithmétique uint32.
	binary.LittleEndian.PutUint32(offsetField, 0xFFFFFFFF)
	if _, err := NewReputationTable(snap); err != ErrCorruptSnapshot {
		t.Fatalf("offset 0xFFFFFFFF: attendu ErrCorruptSnapshot (anti-wrap-around), obtenu %v", err)
	}
}

// BenchmarkCompactReputation_Match mesure le temps de lookup dichotomique dans la table compacte.
func BenchmarkCompactReputation_Match(b *testing.B) {
	tbl, err := GetDefaultReputationTable()
	if err != nil {
		b.Fatalf("GetDefaultReputationTable: %v", err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = tbl.Match("cloudtelemetry.sophosxl.com")
	}
}

// TestCompactReputation_ZeroAllocation prouve formellement 0 allocation tas lors d'un match de réputation.
func TestCompactReputation_ZeroAllocation(t *testing.T) {
	tbl, err := GetDefaultReputationTable()
	if err != nil {
		t.Fatalf("GetDefaultReputationTable: %v", err)
	}

	fqdn := "cloudtelemetry.sophosxl.com"
	allocs := testing.AllocsPerRun(1000, func() {
		_, _ = tbl.Match(fqdn)
	})

	if allocs != 0 {
		t.Errorf("tbl.Match AllocsPerRun = %.2f, attendu 0.0 (0 B/op)", allocs)
	}
}
