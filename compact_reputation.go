// Package c2blue55 — Référentiel de réputation binaire compact (GC-friendly, sans pointeurs).
// Format immuable mappable en mémoire (rodata) avec recherche dichotomique en O(log N).
package c2blue55

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"sort"
	"strings"
	"sync/atomic"
)

var (
	ErrCorruptSnapshot = errors.New("c2blue55: instantane de reputation corrompu ou invalide")
	ErrInvalidMagic    = errors.New("c2blue55: magic binaire invalide (attendu C2DB)")
)

// Catégories de réputation
const (
	RepClassUnknown        uint8 = 0
	RepClassAllowVendor    uint8 = 1 // Local vendor allow policy, not certification.
	RepClassAllowTranco    uint8 = 2 // Local popularity allow policy, not certification.
	RepClassBlockC2        uint8 = 3 // Local deny policy; source provenance is external.
	RepClassProtocolCrypto uint8 = 4 // Protocoles bénins normalisés (DKIM, DMARC, ACME)
)

// Modes de correspondance
const (
	MatchExact   uint8 = 1 // Correspondance exacte du FQDN uniquement
	MatchSubtree uint8 = 2 // Couvre le domaine et tous ses sous-domaines (*.example.com)
)

// Magic 4 octets pour l'en-tête du format binaire compact
const CompactMagic uint32 = 0x42443243 // "C2DB" en Little Endian

// CompactEntry représente un enregistrement d'index compact fixe de 16 octets (zéro pointeur).
type CompactEntry struct {
	DomainHash     uint64 // Hash FNV-1a 64 bits du domaine en minuscules
	Offset         uint32 // Offset du nom texte dans le bloc de chaînes
	Length         uint8  // Longueur du nom en octets (<= 255)
	Classification uint8  // RepClass*
	MatchKind      uint8  // MatchExact ou MatchSubtree
	Flags          uint8  // Réservé
}

// CompactHeader représente l'en-tête de 24 octets du fichier binaire.
type CompactHeader struct {
	Magic            uint32
	Version          uint16
	NumEntries       uint32
	StringBlockStart uint32
	StringBlockLen   uint32
	Reserved         uint32
}

// ReputationTable encapsule un instantané binaire compact en mémoire contiguë.
type ReputationTable struct {
	data        []byte
	numEntries  int
	entriesData []byte
	stringBlock []byte
	stringPool  string
}

// MatchResult contient le fait typé résultant d'une correspondance.
type MatchResult struct {
	MatchedDomain  string
	Classification uint8
	MatchKind      uint8
}

// FNV1a64 calcule le hachage FNV-1a 64 bits d'une tranche d'octets.
func FNV1a64(data []byte) uint64 {
	var h uint64 = 14695981039346656037
	for _, b := range data {
		h ^= uint64(b)
		h *= 1099511628211
	}
	return h
}

// FNV1a64String calcule le hachage FNV-1a 64 bits d'une chaîne.
func FNV1a64String(s string) uint64 {
	var h uint64 = 14695981039346656037
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// NewReputationTable validates and owns a private copy. Callers must not mutate raw
// during this call; mutations after return cannot alter the published table.
func NewReputationTable(raw []byte) (*ReputationTable, error) {
	if len(raw) < 24 {
		return nil, ErrCorruptSnapshot
	}

	magic := binary.LittleEndian.Uint32(raw[0:4])
	if magic != CompactMagic {
		return nil, ErrInvalidMagic
	}
	if binary.LittleEndian.Uint16(raw[4:6]) != 1 || !bytes.Equal(raw[18:24], make([]byte, 6)) {
		return nil, ErrCorruptSnapshot
	}
	raw = bytes.Clone(raw)

	count64 := uint64(binary.LittleEndian.Uint32(raw[6:10]))
	start64 := uint64(binary.LittleEndian.Uint32(raw[10:14]))
	length64 := uint64(binary.LittleEndian.Uint32(raw[14:18]))
	if count64 > uint64((len(raw)-24)/16) || start64 != 24+count64*16 || start64 > uint64(len(raw)) || length64 != uint64(len(raw))-start64 {
		return nil, ErrCorruptSnapshot
	}
	numEntries, stringStart, stringLen := int(count64), int(start64), int(length64)
	entriesLen := numEntries * 16

	entriesData := raw[24 : 24+entriesLen]
	stringBlock := raw[stringStart : stringStart+stringLen]

	// Validation stricte des offsets : chaque entrée doit désigner un intervalle
	// intégralement contenu dans le bloc de chaînes. L'arithmétique est menée en
	// uint64 pour interdire tout repli (wrap-around) lors de la somme Offset+Length.
	var previousHash uint64
	for i := 0; i < numEntries; i++ {
		off := i * 16
		entryOffset := binary.LittleEndian.Uint32(entriesData[off+8 : off+12])
		entryLength := entriesData[off+12]
		if uint64(entryOffset) > uint64(len(stringBlock)) || uint64(entryLength) > uint64(len(stringBlock))-uint64(entryOffset) {
			return nil, ErrCorruptSnapshot
		}
		name := string(stringBlock[entryOffset : uint64(entryOffset)+uint64(entryLength)])
		hash := binary.LittleEndian.Uint64(entriesData[off : off+8])
		if !validReputationDomain(name) || name != cleanDomain(name) || hash != FNV1a64String(name) ||
			(i > 0 && hash < previousHash) || !validReputationClass(entriesData[off+13]) ||
			(entriesData[off+14] != MatchExact && entriesData[off+14] != MatchSubtree) || entriesData[off+15] != 0 {
			return nil, ErrCorruptSnapshot
		}
		previousHash = hash
	}

	return &ReputationTable{
		data:        raw,
		numEntries:  numEntries,
		entriesData: entriesData,
		stringBlock: stringBlock,
		stringPool:  string(stringBlock),
	}, nil
}

// getEntry lit la i-ème entrée directement depuis le slice d'octets sans allouer d'objet sur le tas.
func (t *ReputationTable) getEntry(idx int, out *CompactEntry) {
	off := idx * 16
	out.DomainHash = binary.LittleEndian.Uint64(t.entriesData[off : off+8])
	out.Offset = binary.LittleEndian.Uint32(t.entriesData[off+8 : off+12])
	out.Length = t.entriesData[off+12]
	out.Classification = t.entriesData[off+13]
	out.MatchKind = t.entriesData[off+14]
	out.Flags = t.entriesData[off+15]
}

func cleanDomain(fqdn string) string {
	if len(fqdn) == 0 {
		return ""
	}
	hasUpper := false
	for i := 0; i < len(fqdn); i++ {
		if fqdn[i] >= 'A' && fqdn[i] <= 'Z' {
			hasUpper = true
			break
		}
	}
	s := fqdn
	if hasUpper {
		s = strings.ToLower(fqdn)
	}
	if strings.HasSuffix(s, ".") {
		s = s[:len(s)-1]
	}
	return s
}

func stringEqualBytes(s string, b []byte) bool {
	if len(s) != len(b) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != b[i] {
			return false
		}
	}
	return true
}

// Match inspecte un FQDN et remonte les labels de droite à gauche.
// Respect strict des frontières de labels DNS (le point '.').
// Zéro allocation tas si fqdn est déjà en minuscules (0 B/op).
func (t *ReputationTable) Match(fqdn string) (MatchResult, bool) {
	var res MatchResult
	if t == nil || len(fqdn) == 0 || t.numEntries == 0 {
		return res, false
	}
	fqdnClean := cleanDomain(fqdn)
	if !validReputationDomain(fqdnClean) {
		return res, false
	}
	curr := fqdnClean
	for {
		candidate, ok := t.matchHash(curr, FNV1a64String(curr), curr == fqdnClean)
		if ok && (res.Classification == 0 || reputationRank(candidate.Classification) > reputationRank(res.Classification)) {
			res = candidate
		}
		dotIdx := strings.IndexByte(curr, '.')
		if dotIdx == -1 || dotIdx+1 >= len(curr) {
			break
		}
		curr = curr[dotIdx+1:]
	}
	return res, res.Classification != 0
}

// Scan the complete equal-hash range; text equality remains authoritative.
func (t *ReputationTable) matchHash(name string, hash uint64, exact bool) (MatchResult, bool) {
	low, high := 0, t.numEntries
	for low < high {
		mid := low + (high-low)/2
		if binary.LittleEndian.Uint64(t.entriesData[mid*16:]) < hash {
			low = mid + 1
		} else {
			high = mid
		}
	}
	var res MatchResult
	for i := low; i < t.numEntries; i++ {
		var entry CompactEntry
		t.getEntry(i, &entry)
		if entry.DomainHash != hash {
			break
		}
		stored := t.stringPool[entry.Offset : entry.Offset+uint32(entry.Length)]
		if stored != name || !exact && (entry.MatchKind != MatchSubtree || isSharedHostingDomain(stored) && entry.Classification != RepClassBlockC2) {
			continue
		}
		if res.Classification == 0 || reputationRank(entry.Classification) > reputationRank(res.Classification) || entry.Classification == res.Classification && entry.MatchKind < res.MatchKind {
			res = MatchResult{stored, entry.Classification, entry.MatchKind}
		}
	}
	return res, res.Classification != 0
}

func validReputationClass(class uint8) bool {
	return class >= RepClassAllowVendor && class <= RepClassProtocolCrypto
}

// Block wins across exact/subtree entries. Remaining classes have a fixed order.
func reputationRank(class uint8) uint8 {
	if class == RepClassBlockC2 {
		return 10
	}
	return class
}

func validReputationDomain(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	labelLen := 0
	for i := 0; i < len(name); i++ {
		b := name[i]
		if b == '.' {
			if labelLen == 0 || labelLen > 63 || name[i-1] == '-' {
				return false
			}
			labelLen = 0
			continue
		}
		if !dnsLabelByte(b) || b == '-' && labelLen == 0 {
			return false
		}
		labelLen++
	}
	return labelLen > 0 && labelLen <= 63 && name[len(name)-1] != '-'
}

// Deliberately bounded list, not a public suffix database. Unknown hosting
// platforms still require an explicit policy review before granting a subtree.
func isSharedHostingDomain(name string) bool {
	switch name {
	case "amazonaws.com", "cloudfront.net", "trafficmanager.net", "azure.com", "githubusercontent.com", "github.io", "appspot.com", "googleapis.com", "akamai.net", "akamaiedge.net":
		return true
	}
	return false
}

// BuildEntry définit une entrée source pour le compilateur de snapshot.
type BuildEntry struct {
	Domain         string
	Classification uint8
	MatchKind      uint8
}

// Entries reconstruit les entrées de la table active sous forme de BuildEntry.
// Cette énumération sert au synchroniseur pour préserver les IOCs déjà appris lors
// d'un incident transitoire de source ; elle est hors du chemin chaud d'inspection.
func (t *ReputationTable) Entries() []BuildEntry {
	out := make([]BuildEntry, 0, t.numEntries)
	var e CompactEntry
	for i := 0; i < t.numEntries; i++ {
		t.getEntry(i, &e)
		if int(e.Offset)+int(e.Length) > len(t.stringPool) {
			continue
		}
		out = append(out, BuildEntry{
			Domain:         t.stringPool[e.Offset : e.Offset+uint32(e.Length)],
			Classification: e.Classification,
			MatchKind:      e.MatchKind,
		})
	}
	return out
}

// CompileReputationSnapshot compile une liste d'entrées en un instantané binaire compact immuable.
func CompileReputationSnapshot(entries []BuildEntry) ([]byte, error) {
	// Tri déterministe par Hash FNV-1a croissant
	type item struct {
		hash  uint64
		entry BuildEntry
	}

	if uint64(len(entries)) > (uint64(^uint32(0))-24)/16 {
		return nil, ErrCorruptSnapshot
	}
	items := make([]item, len(entries))
	bytesRequired := uint64(24) + uint64(len(entries))*16
	for i, e := range entries {
		nameClean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(e.Domain)), ".")
		if !validReputationDomain(nameClean) || !validReputationClass(e.Classification) || (e.MatchKind != MatchExact && e.MatchKind != MatchSubtree) {
			return nil, ErrCorruptSnapshot
		}
		bytesRequired += uint64(len(nameClean))
		if bytesRequired > uint64(^uint32(0)) {
			return nil, ErrCorruptSnapshot
		}
		if isSharedHostingDomain(nameClean) && e.Classification != RepClassBlockC2 {
			e.MatchKind = MatchExact
		}
		items[i] = item{
			hash: FNV1a64String(nameClean),
			entry: BuildEntry{
				Domain:         nameClean,
				Classification: e.Classification,
				MatchKind:      e.MatchKind,
			},
		}
	}

	sort.Slice(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.hash != b.hash {
			return a.hash < b.hash
		}
		if a.entry.Domain != b.entry.Domain {
			return a.entry.Domain < b.entry.Domain
		}
		if a.entry.MatchKind != b.entry.MatchKind {
			return a.entry.MatchKind < b.entry.MatchKind
		}
		return reputationRank(a.entry.Classification) > reputationRank(b.entry.Classification)
	})
	merged := items[:0]
	for _, it := range items {
		if len(merged) > 0 {
			last := merged[len(merged)-1]
			if last.entry.Domain == it.entry.Domain && last.entry.MatchKind == it.entry.MatchKind {
				continue
			}
		}
		merged = append(merged, it)
	}
	items = merged

	var buf bytes.Buffer
	var strBuf bytes.Buffer

	// En-tête provisoire de 24 octets
	header := make([]byte, 24)
	buf.Write(header)

	// Écriture de la table d'index
	for _, it := range items {
		off := uint32(strBuf.Len())
		strBytes := []byte(it.entry.Domain)
		strBuf.Write(strBytes)

		var entBytes [16]byte
		binary.LittleEndian.PutUint64(entBytes[0:8], it.hash)
		binary.LittleEndian.PutUint32(entBytes[8:12], off)
		entBytes[12] = uint8(len(strBytes))
		entBytes[13] = it.entry.Classification
		entBytes[14] = it.entry.MatchKind
		entBytes[15] = 0

		buf.Write(entBytes[:])
	}

	stringBlockStart := uint32(buf.Len())
	stringBlockLen := uint32(strBuf.Len())
	buf.Write(strBuf.Bytes())

	// Écriture de l'en-tête final
	res := buf.Bytes()
	binary.LittleEndian.PutUint32(res[0:4], CompactMagic)
	binary.LittleEndian.PutUint16(res[4:6], 1) // Version 1
	binary.LittleEndian.PutUint32(res[6:10], uint32(len(items)))
	binary.LittleEndian.PutUint32(res[10:14], stringBlockStart)
	binary.LittleEndian.PutUint32(res[14:18], stringBlockLen)
	binary.LittleEndian.PutUint32(res[18:22], 0)

	return res, nil
}

// AtomicReputation encapsule une ReputationTable échangeable de manière atomique (lock-free).
// Les lectures de réputation sur le chemin chaud wire-speed sont 100% non-bloquantes (0 B/op).
// Les mises à jour s'effectuent par remplacement atomique de pointeur (atomic.Pointer).
type AtomicReputation struct {
	ptr atomic.Pointer[ReputationTable]
}

// NewAtomicReputation initialise un conteneur de réputation atomique.
func NewAtomicReputation(initial *ReputationTable) *AtomicReputation {
	ar := &AtomicReputation{}
	if initial != nil {
		ar.ptr.Store(initial)
	}
	return ar
}

// Load retourne la table actuelle de façon lock-free.
func (ar *AtomicReputation) Load() *ReputationTable {
	return ar.ptr.Load()
}

// Store remplace atomiquement la table de réputation.
func (ar *AtomicReputation) Store(table *ReputationTable) {
	ar.ptr.Store(table)
}

// Match effectue une recherche de réputation lock-free.
func (ar *AtomicReputation) Match(fqdn string) (MatchResult, bool) {
	tbl := ar.ptr.Load()
	if tbl == nil {
		return MatchResult{}, false
	}
	return tbl.Match(fqdn)
}

// ParseDomainList extrait des BuildEntry à partir d'un flux texte (1 domaine par ligne ou format hosts, ignorant les commentaires #).
func ParseDomainList(r io.Reader, classification uint8, matchKind uint8) ([]BuildEntry, error) {
	if !validReputationClass(classification) || (matchKind != MatchExact && matchKind != MatchSubtree) {
		return nil, ErrCorruptSnapshot
	}
	scanner := bufio.NewScanner(r)
	var entries []BuildEntry
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		domain := fields[0]
		expectedFields := 1
		if len(fields) >= 2 && (domain == "0.0.0.0" || domain == "127.0.0.1") {
			domain = fields[1]
			expectedFields = 2
		}
		domain = strings.TrimSuffix(strings.ToLower(domain), ".")
		if len(fields) != expectedFields || !validReputationDomain(domain) {
			return nil, ErrCorruptSnapshot
		}
		if len(domain) > 0 {
			entries = append(entries, BuildEntry{
				Domain:         domain,
				Classification: classification,
				MatchKind:      matchKind,
			})
		}
	}
	return entries, scanner.Err()
}

// ReloadFromEntries recompile et échange atomiquement la table en mémoire vive sans bloquer les lectures.
func (ar *AtomicReputation) ReloadFromEntries(entries []BuildEntry) error {
	snap, err := CompileReputationSnapshot(entries)
	if err != nil {
		return err
	}
	newTbl, err := NewReputationTable(snap)
	if err != nil {
		return err
	}
	ar.Store(newTbl)
	return nil
}
