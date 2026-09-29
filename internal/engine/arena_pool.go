// Package engine — arena_pool.go
// Réservoir d'arènes de pages 4 Ko pré-allouées (alignées sur 4096 octets),
// permettant à c2blue55 d'analyser des charges utiles jusqu'à 4096 octets
// (commandes LOLBAS obfusquées, messages MCP JSON-RPC d'agents IA) sans aucune allocation tas.
// Le CRC32-C de page est celui du noyau c2archtsim.C2archtsim_page4k_crc32c,
// calculé en flux (arenaPageCRC32C) ; l'équivalence est vérifiée par test.
package engine

import (
	"encoding/binary"
	"errors"
	"hash/crc32"
	"runtime"
	"sync/atomic"
)

const (
	// PageSize est la taille standard d'une page mémoire (4096 octets).
	PageSize = 4096

	// ArenaCapacity fixe le nombre de pages 4 Ko dans le réservoir tournant (1024 pages = 4 Mio).
	ArenaCapacity = 1024
	arenaMask     = ArenaCapacity - 1

	// FlagLongPayload indique que l'événement détient une charge longue dans l'arène 4 Ko.
	FlagLongPayload uint32 = 0x1000

	// Offset des métadonnées d'arène logées dans ev.Payload[80..96].
	metaOffsetPageIdx = 80
	metaOffsetLen     = 84
	metaOffsetCRC     = 86
	metaOffsetEpoch   = 90
	metaOffsetRes     = 94

	// arenaWords est le nombre de mots de 64 bits d'une page.
	arenaWords = PageSize / 8
)

// castagnoliTable est la table CRC32-C, identique à celle du noyau
// c2archtsim.C2archtsim_page4k_crc32c (hash/crc32, accélération matérielle).
var castagnoliTable = crc32.MakeTable(crc32.Castagnoli)

// zeroPage fournit la traîne de zéros d'une page partiellement remplie.
var zeroPage [PageSize]byte

// arenaPageCRC32C calcule le CRC32-C de la page [data ‖ zéros] de PageSize
// octets, c'est-à-dire exactement ce que c2archtsim.C2archtsim_page4k_crc32c
// rend sur la page complétée, mais en flux et sans image locale de 4 Ko :
// hash/crc32 appelle son noyau par une variable de fonction, ce qui ferait
// échapper vers le tas toute image tenue sur la pile.
func arenaPageCRC32C(data []byte) uint32 {
	crc := crc32.Update(0, castagnoliTable, data)
	return crc32.Update(crc, castagnoliTable, zeroPage[:PageSize-len(data)])
}

// Erreurs de résolution d'une charge longue. Toutes signifient que les octets
// de l'arène ne sont plus ceux que le descripteur de l'événement a scellés ;
// l'appelant doit alors refuser d'évaluer la charge comme bénigne.
var (
	// ErrArenaDescriptor signale un descripteur d'arène hors bornes (index ou longueur).
	ErrArenaDescriptor = errors.New("c2arena: descripteur de charge longue invalide")
	// ErrArenaStale signale une page recyclée depuis le dépôt ou en cours d'écriture.
	ErrArenaStale = errors.New("c2arena: page d'arène recyclée ou en cours d'écriture")
	// ErrArenaTorn signale une écriture commencée pendant la copie de la page.
	ErrArenaTorn = errors.New("c2arena: lecture déchirée par une écriture concurrente")
	// ErrArenaCorrupt signale une page dont la longueur ou le CRC32-C scellés
	// diffèrent du descripteur de l'événement.
	ErrArenaCorrupt = errors.New("c2arena: longueur ou CRC32-C de la charge discordant")
)

// ArenaPage représente un bloc physique de 4096 octets contigus, protégé par
// un seqlock à écrivain exclusif.
//
// seq est pair quand la page est stable et impair pendant une écriture ; un
// écrivain l'acquiert par CompareAndSwap, si bien que deux dépôts qui tombent
// sur la même page après un tour complet de l'arène s'exécutent l'un après
// l'autre et ne mêlent jamais leurs octets. Les octets sont stockés en mots de
// 64 bits accédés exclusivement par opérations atomiques : un seqlock Go
// n'établit de relation « arrivé avant » entre écrivain et lecteur que si les
// données elles-mêmes transitent par des atomiques ; un tableau d'octets
// ordinaire lu pendant une réécriture est une course de données au sens du
// modèle mémoire, même quand l'incohérence est détectée ensuite.
type ArenaPage struct {
	words [arenaWords]atomic.Uint64
	seq   atomic.Uint32
	Epoch atomic.Uint32
	Len   atomic.Uint32
	CRC32 atomic.Uint32
}

// ArenaPool gère un réservoir statique de pages 4 Ko sans allocation sur le chemin chaud.
type ArenaPool struct {
	pages [ArenaCapacity]ArenaPage
	alloc atomic.Uint64
}

// defaultArenaPool est le pool global partagé du moteur.
var defaultArenaPool = NewArenaPool()

// DefaultArenaPool retourne le pool d'arène singleton standard.
func DefaultArenaPool() *ArenaPool {
	return defaultArenaPool
}

// NewArenaPool alloue et initialise un réservoir de 1024 pages.
func NewArenaPool() *ArenaPool {
	return &ArenaPool{}
}

// StorePayload inspecte la longueur de la charge :
//   - Si len(data) <= 96, la charge est copiée directement dans ev.Payload.
//   - Si len(data) > 96, les 80 premiers octets sont copiés dans ev.Payload[0..80],
//     la totalité (jusqu'à 4096 octets) est déposée dans une page d'arène, et le descripteur
//     est scellé dans ev.Payload[80..96] avec le drapeau FlagLongPayload.
//
// Retourne la longueur effective écrite dans l'arène ou dans l'événement.
func (p *ArenaPool) StorePayload(ev *Probe_event_t, data []byte) int {
	if ev == nil || len(data) == 0 {
		return 0
	}
	clear(ev.Payload[:])

	if len(data) <= 96 {
		copy(ev.Payload[:], data)
		ev.Flags &^= FlagLongPayload
		return len(data)
	}

	// Charge longue : plafonnement à 4096 octets
	length := len(data)
	if length > PageSize {
		length = PageSize
	}

	// 1. Copie du préfixe réflexe (80 octets)
	copy(ev.Payload[:metaOffsetPageIdx], data[:metaOffsetPageIdx])

	// 2. CRC32-C Castagnoli de la page [charge ‖ zéros], tel que le noyau
	// c2archtsim le rend sur la page complétée.
	crc := arenaPageCRC32C(data[:length])

	// 3. Allocation atomique de page tournante
	slotIdx := p.alloc.Add(1) - 1
	pageIdx := uint32(slotIdx & arenaMask)
	page := &p.pages[pageIdx]
	epoch := uint32(slotIdx / ArenaCapacity)

	// 4. Section critique du seqlock : acquisition exclusive (seq impair),
	// écriture atomique des mots utiles, métadonnées, puis libération (seq
	// pair). Les mots au-delà de length ne sont jamais lus par un lecteur de ce
	// descripteur, qui les remplace par des zéros.
	var seq uint32
	for {
		seq = page.seq.Load()
		if seq&1 == 0 && page.seq.CompareAndSwap(seq, seq+1) {
			break
		}
		runtime.Gosched()
	}
	words := (length + 7) / 8
	for w := 0; w < words; w++ {
		var buf [8]byte
		copy(buf[:], data[w*8:min(w*8+8, length)])
		page.words[w].Store(binary.LittleEndian.Uint64(buf[:]))
	}
	page.Len.Store(uint32(length))
	page.CRC32.Store(crc)
	page.Epoch.Store(epoch)
	page.seq.Store(seq + 2)

	// 5. Scellement du descripteur dans ev.Payload[80..96]
	binary.LittleEndian.PutUint32(ev.Payload[metaOffsetPageIdx:metaOffsetLen], pageIdx)
	binary.LittleEndian.PutUint16(ev.Payload[metaOffsetLen:metaOffsetCRC], uint16(length))
	binary.LittleEndian.PutUint32(ev.Payload[metaOffsetCRC:metaOffsetEpoch], crc)
	binary.LittleEndian.PutUint32(ev.Payload[metaOffsetEpoch:metaOffsetRes], epoch)
	binary.LittleEndian.PutUint16(ev.Payload[metaOffsetRes:96], 0)

	ev.Flags |= FlagLongPayload
	return length
}

// ResolvePayload extrait la charge utile exacte de l'événement dans dst.
//
// Une charge courte est rendue telle qu'elle figure dans ev.Payload, qui
// appartient à l'appelant. Une charge longue est lue sous le seqlock de sa
// page : la page doit être stable (seq pair), porter l'époque, la longueur et
// le CRC32-C scellés dans le descripteur, et aucune écriture ne doit avoir
// commencé pendant la copie mot à mot. Les octets rendus sont donc exactement
// ceux du dépôt que le descripteur désigne, jamais une page recyclée ni une
// écriture en cours. En cas d'échec, la fonction rend une erreur et aucune
// tranche : il n'existe plus de repli silencieux sur le préfixe de 80 octets.
// La tranche rendue pointe dans dst ou dans ev.Payload ; elle ne référence
// jamais la page partagée.
func (p *ArenaPool) ResolvePayload(ev *Probe_event_t, dst *[PageSize]byte) ([]byte, error) {
	if ev == nil {
		return nil, nil
	}
	if ev.Flags&FlagLongPayload == 0 {
		return ev.Payload[:payloadUsed(ev.Payload[:])], nil
	}
	if dst == nil {
		return nil, ErrArenaDescriptor
	}

	pageIdx := binary.LittleEndian.Uint32(ev.Payload[metaOffsetPageIdx:metaOffsetLen])
	length := int(binary.LittleEndian.Uint16(ev.Payload[metaOffsetLen:metaOffsetCRC]))
	if pageIdx >= ArenaCapacity || length <= 96 || length > PageSize {
		return nil, ErrArenaDescriptor
	}
	expectedCRC := binary.LittleEndian.Uint32(ev.Payload[metaOffsetCRC:metaOffsetEpoch])
	expectedEpoch := binary.LittleEndian.Uint32(ev.Payload[metaOffsetEpoch:metaOffsetRes])
	page := &p.pages[pageIdx]

	// 1. Ouverture du seqlock : page stable et de la bonne époque.
	seq := page.seq.Load()
	if seq&1 != 0 || page.Epoch.Load() != expectedEpoch {
		return nil, ErrArenaStale
	}
	// 2. Le dépôt présent doit être celui que le descripteur a scellé.
	if page.Len.Load() != uint32(length) || page.CRC32.Load() != expectedCRC {
		return nil, ErrArenaCorrupt
	}

	// 3. Copie atomique des mots utiles, traîne remise à zéro.
	words := (length + 7) / 8
	for w := 0; w < words; w++ {
		binary.LittleEndian.PutUint64(dst[w*8:], page.words[w].Load())
	}
	clear(dst[length:])

	// 4. Fermeture du seqlock : aucune écriture n'a commencé pendant la copie.
	if page.seq.Load() != seq {
		return nil, ErrArenaTorn
	}
	return dst[:length], nil
}

// ResolvePayloadGlobal extrait la charge au moyen de l'arène globale par défaut.
func ResolvePayloadGlobal(ev *Probe_event_t, dst *[PageSize]byte) ([]byte, error) {
	return defaultArenaPool.ResolvePayload(ev, dst)
}
