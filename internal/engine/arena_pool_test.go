// Package engine — arena_pool_test.go
// Validation unitaire de l'arène 4 Ko et de l'extraction sur charge longue (> 96 octets).
package engine

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"

	"github.com/hazyhaar/c2pkg/c2archtsim"
)

func TestArenaPool_StoreAndResolve(t *testing.T) {
	pool := NewArenaPool()
	var page [PageSize]byte

	// 1. Charge courte (<= 96 octets)
	shortData := []byte("powershell.exe -NoProfile -Command Write-Host 'Hello'")
	var evShort Probe_event_t
	nShort := pool.StorePayload(&evShort, shortData)
	if nShort != len(shortData) {
		t.Fatalf("StorePayload courte a écrit %d octets, attendu %d", nShort, len(shortData))
	}
	if evShort.Flags&FlagLongPayload != 0 {
		t.Fatalf("FlagLongPayload positionné à tort sur charge courte")
	}
	resolvedShort, err := pool.ResolvePayload(&evShort, &page)
	if err != nil || !bytes.Equal(resolvedShort, shortData) {
		t.Fatalf("ResolvePayload courte corrompu : %q vs %q (err=%v)", resolvedShort, shortData, err)
	}

	// 2. Charge longue (> 96 octets, ex: 512 octets de script obfusqué)
	longData := make([]byte, 512)
	for i := range longData {
		longData[i] = byte(32 + (i % 95)) // caractères imprimables variés
	}
	var evLong Probe_event_t
	nLong := pool.StorePayload(&evLong, longData)
	if nLong != 512 {
		t.Fatalf("StorePayload longue a écrit %d octets, attendu 512", nLong)
	}
	if evLong.Flags&FlagLongPayload == 0 {
		t.Fatalf("FlagLongPayload absent sur charge longue")
	}
	resolvedLong, err := pool.ResolvePayload(&evLong, &page)
	if err != nil {
		t.Fatalf("ResolvePayload longue : %v", err)
	}
	if !bytes.Equal(resolvedLong, longData) {
		t.Fatalf("ResolvePayload longue divergent de l'original")
	}

	// 3. Préfixe réflexe préservé dans ev.Payload[0..80]
	if !bytes.Equal(evLong.Payload[:80], longData[:80]) {
		t.Fatalf("Préfixe réflexe non préservé dans evLong.Payload[:80]")
	}

	// 4. Une charge plus courte déposée ensuite sur une page déjà utilisée
	// doit se relire exactement, sans les octets résiduels de la précédente.
	for i := 0; i < ArenaCapacity-1; i++ {
		var filler Probe_event_t
		pool.StorePayload(&filler, bytes.Repeat([]byte{'#'}, PageSize))
	}
	shorter := bytes.Repeat([]byte("abc"), 40)
	var evReuse Probe_event_t
	pool.StorePayload(&evReuse, shorter)
	got, err := pool.ResolvePayload(&evReuse, &page)
	if err != nil || !bytes.Equal(got, shorter) {
		t.Fatalf("page réutilisée : err=%v, égalité=%v", err, bytes.Equal(got, shorter))
	}
}

// Une page recyclée après le dépôt doit être refusée, jamais remplacée par le
// préfixe de 80 octets.
func TestArenaPool_StaleAfterRotation(t *testing.T) {
	pool := NewArenaPool()
	var page [PageSize]byte
	var ev Probe_event_t
	pool.StorePayload(&ev, bytes.Repeat([]byte{'Q'}, 300))
	for i := 0; i < ArenaCapacity; i++ {
		var w Probe_event_t
		pool.StorePayload(&w, bytes.Repeat([]byte{'W'}, 300))
	}
	got, err := pool.ResolvePayload(&ev, &page)
	if !errors.Is(err, ErrArenaStale) || got != nil {
		t.Fatalf("page recyclée : err=%v, tranche=%d octets ; attendu ErrArenaStale et aucune tranche", err, len(got))
	}
}

// Un descripteur dont le CRC ne correspond plus à la page doit être refusé,
// y compris quand le CRC scellé vaut zéro (plus d'exemption).
func TestArenaPool_CorruptDescriptorRejected(t *testing.T) {
	pool := NewArenaPool()
	var page [PageSize]byte
	for _, crc := range []uint32{0, 0xDEADBEEF} {
		var ev Probe_event_t
		pool.StorePayload(&ev, bytes.Repeat([]byte{'C'}, 200))
		binary.LittleEndian.PutUint32(ev.Payload[metaOffsetCRC:metaOffsetEpoch], crc)
		if _, err := pool.ResolvePayload(&ev, &page); !errors.Is(err, ErrArenaCorrupt) {
			t.Fatalf("CRC scellé 0x%08X : err=%v, attendu ErrArenaCorrupt", crc, err)
		}
	}
	var ev Probe_event_t
	pool.StorePayload(&ev, bytes.Repeat([]byte{'C'}, 200))
	binary.LittleEndian.PutUint32(ev.Payload[metaOffsetPageIdx:metaOffsetLen], ArenaCapacity)
	if _, err := pool.ResolvePayload(&ev, &page); !errors.Is(err, ErrArenaDescriptor) {
		t.Fatalf("index hors bornes : err=%v, attendu ErrArenaDescriptor", err)
	}
}

// Sous -race, des écrivains qui recyclent la page d'un lecteur ne doivent
// provoquer ni course de données ni lecture déchirée : toute tranche rendue
// sans erreur est bit-à-bit la charge déposée.
func TestArenaPool_ConcurrentWritersNoTornRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := NewArenaPool()
		payload := bytes.Repeat([]byte{'A', 'B', 'C', 'D'}, PageSize/4)
		var ev Probe_event_t
		pool.StorePayload(&ev, payload)

		var wg sync.WaitGroup
		var writersDone atomic.Bool
		for w := 0; w < 2; w++ {
			wg.Go(func() {
				other := bytes.Repeat([]byte{byte('a' + w)}, PageSize)
				for i := 0; i < 3*ArenaCapacity; i++ {
					var e Probe_event_t
					pool.StorePayload(&e, other)
				}
			})
		}
		go func() { wg.Wait(); writersDone.Store(true) }()

		var page [PageSize]byte
		ok, refused := 0, 0
		for !writersDone.Load() {
			got, err := pool.ResolvePayload(&ev, &page)
			if err != nil {
				refused++
				continue
			}
			if !bytes.Equal(got, payload) {
				t.Fatal("lecture acceptée mais divergente de la charge déposée")
			}
			ok++
		}
		t.Logf("résolutions exactes=%d refusées=%d", ok, refused)
	})
}

func TestArenaPool_FeatureExtraction_LongPayload(t *testing.T) {
	pool := DefaultArenaPool()

	// Création d'une charge longue de 1024 octets
	data := make([]byte, 1024)
	for i := range data {
		data[i] = byte('A' + (i % 26))
	}

	var ev Probe_event_t
	ev.Subsystem = 4 // MCP
	ev.Action = 4    // ToolCall
	pool.StorePayload(&ev, data)

	var dst [EmbeddingDim]float32
	extractor := NewFeatureExtractor()
	if !extractor.ExtractTo(&ev, dst[:]) {
		t.Fatal("ExtractTo a échoué sur charge longue d'arène")
	}

	// Vérifier que le vecteur n'est pas tout nul
	hasNonZero := false
	for _, v := range dst {
		if v != 0 {
			hasNonZero = true
			break
		}
	}
	if !hasNonZero {
		t.Fatal("La projection d'arène 4 Ko est intégralement nulle")
	}

	// Descripteur altéré : l'extraction doit refuser au lieu de projeter le préfixe.
	bad := ev
	binary.LittleEndian.PutUint32(bad.Payload[metaOffsetCRC:metaOffsetEpoch], 0)
	if extractor.ExtractTo(&bad, dst[:]) {
		t.Fatal("ExtractTo a projeté une charge longue au descripteur altéré")
	}
}

func TestArenaPool_ZeroAlloc(t *testing.T) {
	pool := DefaultArenaPool()
	var ev Probe_event_t
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	var page [PageSize]byte

	allocs := testing.AllocsPerRun(1000, func() {
		pool.StorePayload(&ev, data)
		_, _ = pool.ResolvePayload(&ev, &page)
	})
	if allocs != 0 {
		t.Fatalf("AllocsPerRun = %.2f, attendu 0 (0 B/op)", allocs)
	}
}

// Le CRC calculé en flux par l'écrivain doit égaler celui du noyau c2archtsim
// sur la page complétée de zéros, que le rejeu forensique recalcule.
func TestArenaPool_PageCRCMatchesKernel(t *testing.T) {
	for _, n := range []int{97, 120, 1000, 4095, PageSize} {
		data := make([]byte, n)
		for i := range data {
			data[i] = byte(i*31 + 7)
		}
		var img [PageSize]byte
		copy(img[:], data)
		if got, want := arenaPageCRC32C(data), c2archtsim.C2archtsim_page4k_crc32c(img[:]); got != want {
			t.Fatalf("n=%d : CRC en flux 0x%08X, noyau 0x%08X", n, got, want)
		}
	}
}
