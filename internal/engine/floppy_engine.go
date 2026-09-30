// Package engine — floppy_engine.go
// Moteur de disquettes de vecteurs spécialisées (.c2book étendu, C2FLOP1).
// Projeté en mémoire vive en lecture seule via mmap (PROT_READ, MADV_WILLNEED),
// avec commutation atomique O(1) sans verrou via RCU (atomic.Pointer).
package engine

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"unsafe"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/goclassifier"
)

const (
	// FloppyHeaderSize est la taille exacte de l'en-tête (64 octets).
	FloppyHeaderSize = 64

	// FloppyVersion définit la révision binaire active.
	FloppyVersion uint16 = 1

	// Familles de disquettes spécialisées.
	FloppyFamilyLOLBAS   uint16 = 1 // Processus, LOLBAS et élévations APT
	FloppyFamilyDNSC2    uint16 = 2 // Balisages réseau, tunnels DNS et exfiltration
	FloppyFamilyAgentMCP uint16 = 3 // Agents IA, injections de prompt et usurpations MCP

	// Drapeaux de disquette.
	FloppyFlagSealed uint8 = 0x01 // Sceau HMAC-SHA256 validé

	// FloppyDefaultBlockRadius est le rayon de veto L1b (distance de Hamming
	// sur 512 bits) d'une disquette qui n'en déclare pas.
	FloppyDefaultBlockRadius uint8 = 12
)

// FloppyMagic identifie canoniquement une disquette de vecteurs C2FLOP1.
var FloppyMagic = [8]byte{'C', '2', 'F', 'L', 'O', 'P', '1', 0}

// FloppyHeader structure l'en-tête binaire de 64 octets.
type FloppyHeader struct {
	Magic       [8]byte  // 0..8
	Version     uint16   // 8..10
	FamilyID    uint16   // 10..12
	VectorDim   uint16   // 12..14 (512)
	Flags       uint8    // 14 (FloppyFlag*)
	BlockRadius uint8    // 15 (rayon de veto L1b calibré à la forgerie ; 0 = FloppyDefaultBlockRadius)
	EntryCount  uint32   // 16..20 (nombre de centroïdes RaBitQ)
	KwCount     uint32   // 20..24 (nombre de mots-clés exacts)
	CRC32C      uint32   // 24..28 (Castagnoli sur les données)
	HeadClasses uint16   // 28..30 (nombre de classes de décision)
	ProtoCount  uint16   // 30..32 (prototypes d'étalonnage de la sonde conforme L1a ; 0 sur les disquettes antérieures)
	Seal        [32]byte // 32..64 (Sceau cryptographique)
}

var _ = [1]struct{}{}[unsafe.Sizeof(FloppyHeader{})-FloppyHeaderSize]

// DecisionClass INT8 représente les poids d'une classe pour projection ultra-rapide.
type DecisionClass struct {
	Weights [EmbeddingDim]int8
	Bias    int32
	QHat    float32 // Seuil conforme calibré (1 - alpha)
}

// floppyProtoRecSize est la taille d'un prototype sérialisé : classe (uint16),
// réserve (uint16), puis EmbeddingDim composantes float32 little-endian.
const floppyProtoRecSize = 4 + EmbeddingDim*4

// FloppyPrototype est un vecteur de référence réel, tiré du corpus
// d'apprentissage de la disquette, qui étalonne la sonde conforme L1a
// (0 = bénin, 1 = hostile).
type FloppyPrototype struct {
	Class  uint16
	Vector [EmbeddingDim]float32
}

// Erreurs d'ouverture d'une disquette.
var (
	// ErrFloppyUnsealed signale une discordance de sceau : soit la disquette est
	// scellée et aucune clé HMAC n'est fournie, soit une clé est fournie alors
	// que la disquette n'est pas scellée.
	ErrFloppyUnsealed = errors.New("c2flop: clé HMAC requise pour une disquette scellée, ou disquette non scellée")
	// ErrFloppySeal signale un sceau HMAC-SHA256 discordant.
	ErrFloppySeal = errors.New("c2flop: sceau HMAC-SHA256 discordant")
	// ErrFloppyTruncated signale un corps dont les sections ne tombent pas juste.
	ErrFloppyTruncated = errors.New("c2flop: sections tronquées ou octets excédentaires")
)

// FloppyDisk représente une disquette projetée en mémoire vive via mmap.
type FloppyDisk struct {
	Header     FloppyHeader
	Keywords   []string
	Entries    []CodebookEntry
	Head       []DecisionClass
	Prototypes []FloppyPrototype
	// probe est la sonde conforme L1a construite une fois au chargement à
	// partir des prototypes ; elle n'est plus modifiée ensuite, ce qui la rend
	// sûre en lecture concurrente et la fait commuter avec la disquette.
	probe    *goclassifier.RabitqProbe
	mmapData []byte
	file     *os.File
}

// Probe retourne la sonde conforme L1a embarquée, ou nil si la disquette ne
// porte pas de prototypes des deux classes.
func (d *FloppyDisk) Probe() *goclassifier.RabitqProbe {
	if d == nil {
		return nil
	}
	return d.probe
}

// FloppySlot assure la commutation atomique O(1) sans blocage d'une disquette active.
type FloppySlot struct {
	current atomic.Pointer[FloppyDisk]
	epoch   atomic.Uint64
}

// NewFloppySlot initialise un emplacement de disquette.
func NewFloppySlot() *FloppySlot {
	return &FloppySlot{}
}

// Current retourne la disquette active en temps constant O(1).
func (s *FloppySlot) Current() *FloppyDisk {
	if s == nil {
		return nil
	}
	return s.current.Load()
}

// Swap commute atomiquement la disquette active et incrémente l'époque RCU.
func (s *FloppySlot) Swap(newDisk *FloppyDisk) *FloppyDisk {
	if s == nil {
		return nil
	}
	s.epoch.Add(1)
	return s.current.Swap(newDisk)
}

// Epoch retourne la révision d'époque active.
func (s *FloppySlot) Epoch() uint64 {
	if s == nil {
		return 0
	}
	return s.epoch.Load()
}

// LoadFloppyMmap projette un fichier .c2book étendu en mémoire vive en lecture seule via mmap.
//
// Si hmacKey est non vide, la disquette doit porter le drapeau FloppyFlagSealed
// et un sceau HMAC-SHA256 égal, en temps constant, à celui du corps : une
// disquette non scellée ou au sceau discordant est refusée. Le CRC32-C est
// toujours contrôlé, sans exemption pour une valeur nulle, et les sections
// doivent couvrir le corps exactement.
func LoadFloppyMmap(path string, hmacKey []byte) (*FloppyDisk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	size := fi.Size()
	if size < FloppyHeaderSize {
		f.Close()
		return nil, errors.New("c2flop: fichier trop court pour en-tête")
	}

	// Projection mmap en lecture seule partagée
	data, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("c2flop mmap failed: %w", err)
	}

	disk, err := decodeFloppy(data, hmacKey)
	if err != nil {
		syscall.Munmap(data)
		f.Close()
		return nil, err
	}
	disk.mmapData = data
	disk.file = f
	return disk, nil
}

// decodeFloppy valide et décode l'image complète d'une disquette.
func decodeFloppy(data []byte, hmacKey []byte) (*FloppyDisk, error) {
	var hdr FloppyHeader
	copy((*[FloppyHeaderSize]byte)(unsafe.Pointer(&hdr))[:], data[:FloppyHeaderSize])

	if hdr.Magic != FloppyMagic {
		return nil, errors.New("c2flop: magie invalide")
	}
	if hdr.Version != FloppyVersion {
		return nil, fmt.Errorf("c2flop: version %d non supportée", hdr.Version)
	}
	if hdr.VectorDim != EmbeddingDim {
		return nil, fmt.Errorf("c2flop: dimension %d incompatible", hdr.VectorDim)
	}

	body := data[FloppyHeaderSize:]

	// Contrôle d'intégrité HMAC-SHA256 :
	// - En mode strict (C2BLUE_REQUIRE_SECURE_KEYS=1 ou C2BLUE_PRODUCTION=1), toute disquette
	//   non scellée est catégoriquement refusée avec ErrFloppyUnsealed, interdisant
	//   l'acceptation d'une image dont le drapeau de sceau aurait été effacé.
	// - Si la disquette est scellée (FloppyFlagSealed), la fourniture d'une clé HMAC
	//   est strictement obligatoire ; un chargement sans clé est refusé avec ErrFloppyUnsealed.
	// - Si une clé est fournie alors que la disquette n'est pas scellée, elle est refusée avec ErrFloppyUnsealed.
	// - Le HMAC couvre les 32 premiers octets de l'en-tête (Magic, Version,
	//   FamilyID, VectorDim, Flags, BlockRadius, EntryCount, KwCount, CRC32C,
	//   HeadClasses, ProtoCount) ainsi que l'intégralité du corps, interdisant
	//   toute altération non détectée des paramètres de décision ou de veto.
	isStrict := os.Getenv("C2BLUE_REQUIRE_SECURE_KEYS") == "1" || os.Getenv("C2BLUE_PRODUCTION") == "1"
	if isStrict && (hdr.Flags&FloppyFlagSealed == 0) {
		return nil, ErrFloppyUnsealed
	}
	if hdr.Flags&FloppyFlagSealed != 0 {
		if len(hmacKey) == 0 {
			return nil, ErrFloppyUnsealed
		}
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write(data[:32])
		mac.Write(body)
		if !hmac.Equal(mac.Sum(nil), hdr.Seal[:]) {
			return nil, ErrFloppySeal
		}
	} else if len(hmacKey) > 0 {
		return nil, ErrFloppyUnsealed
	}

	// Contrôle CRC32C Castagnoli
	if crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli)) != hdr.CRC32C {
		return nil, errors.New("c2flop: somme de contrôle CRC32C discordante")
	}

	disk := &FloppyDisk{Header: hdr}
	offset := FloppyHeaderSize

	// 1. Mots-clés (KwCount chaînes préfixées par uint16 de longueur)
	disk.Keywords = make([]string, hdr.KwCount)
	for i := uint32(0); i < hdr.KwCount; i++ {
		if offset+2 > len(data) {
			return nil, ErrFloppyTruncated
		}
		kwLen := int(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if offset+kwLen > len(data) {
			return nil, ErrFloppyTruncated
		}
		disk.Keywords[i] = string(data[offset : offset+kwLen])
		offset += kwLen
	}

	// 2. Centroïdes RaBitQ (EntryCount * 72 octets)
	entryBytes := int(hdr.EntryCount) * codebookEntrySize
	if offset+entryBytes > len(data) {
		return nil, ErrFloppyTruncated
	}
	disk.Entries = make([]CodebookEntry, hdr.EntryCount)
	for i := uint32(0); i < hdr.EntryCount; i++ {
		entryData := data[offset+int(i)*codebookEntrySize : offset+(int(i)+1)*codebookEntrySize]
		decodeCodebookEntry((*[codebookEntrySize]byte)(entryData), &disk.Entries[i])
	}
	offset += entryBytes

	// 3. Tête de décision INT8 (HeadClasses * (512 + 4 + 4) = 520 octets)
	const classRecSize = EmbeddingDim + 4 + 4
	headBytes := int(hdr.HeadClasses) * classRecSize
	if offset+headBytes > len(data) {
		return nil, ErrFloppyTruncated
	}
	disk.Head = make([]DecisionClass, hdr.HeadClasses)
	for i := uint16(0); i < hdr.HeadClasses; i++ {
		base := offset + int(i)*classRecSize
		for d := 0; d < EmbeddingDim; d++ {
			disk.Head[i].Weights[d] = int8(data[base+d])
		}
		disk.Head[i].Bias = int32(binary.LittleEndian.Uint32(data[base+EmbeddingDim : base+EmbeddingDim+4]))
		disk.Head[i].QHat = math.Float32frombits(binary.LittleEndian.Uint32(data[base+EmbeddingDim+4 : base+classRecSize]))
	}
	offset += headBytes

	// 4. Prototypes d'étalonnage de la sonde conforme L1a
	protoBytes := int(hdr.ProtoCount) * floppyProtoRecSize
	if offset+protoBytes > len(data) {
		return nil, ErrFloppyTruncated
	}
	disk.Prototypes = make([]FloppyPrototype, hdr.ProtoCount)
	for i := range disk.Prototypes {
		base := offset + i*floppyProtoRecSize
		pr := &disk.Prototypes[i]
		pr.Class = binary.LittleEndian.Uint16(data[base : base+2])
		if pr.Class > 1 {
			return nil, fmt.Errorf("c2flop: classe de prototype %d hors {0,1}", pr.Class)
		}
		for d := 0; d < EmbeddingDim; d++ {
			o := base + 4 + d*4
			v := math.Float32frombits(binary.LittleEndian.Uint32(data[o : o+4]))
			if math.IsNaN(float64(v)) || math.IsInf(float64(v), 0) {
				return nil, fmt.Errorf("c2flop: prototype %d non fini", i)
			}
			pr.Vector[d] = v
		}
	}
	offset += protoBytes

	if offset != len(data) {
		return nil, ErrFloppyTruncated
	}

	probe, err := buildFloppyProbe(disk.Prototypes)
	if err != nil {
		return nil, err
	}
	disk.probe = probe
	return disk, nil
}

// buildFloppyProbe construit la sonde conforme à deux classes à partir des
// prototypes. Elle rend nil, sans erreur, quand l'une des deux classes est vide :
// la cascade saute alors L1a plutôt que de trancher sur une classe absente.
func buildFloppyProbe(protos []FloppyPrototype) (*goclassifier.RabitqProbe, error) {
	var n [2]int
	for i := range protos {
		n[protos[i].Class]++
	}
	if n[0] == 0 || n[1] == 0 {
		return nil, nil
	}
	probe, err := goclassifier.NewRabitqProbe(2)
	if err != nil {
		return nil, err
	}
	for i := range protos {
		if err := probe.AddPrototype(int(protos[i].Class), protos[i].Vector[:]); err != nil {
			return nil, err
		}
	}
	return probe, nil
}

// Close libère la projection mémoire de la disquette.
func (d *FloppyDisk) Close() error {
	if d == nil {
		return nil
	}
	var err error
	if d.mmapData != nil {
		err = syscall.Munmap(d.mmapData)
		d.mmapData = nil
	}
	if d.file != nil {
		d.file.Close()
		d.file = nil
	}
	return err
}

func containsSubsliceFold(haystack, needle []byte) bool {
	if len(needle) == 0 {
		return true
	}
	if len(haystack) < len(needle) {
		return false
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			c1 := haystack[i+j]
			c2 := needle[j]
			if c1 != c2 {
				if c1 >= 'A' && c1 <= 'Z' {
					c1 += 'a' - 'A'
				}
				if c2 >= 'A' && c2 <= 'Z' {
					c2 += 'a' - 'A'
				}
				if c1 != c2 {
					match = false
					break
				}
			}
		}
		if match {
			return true
		}
	}
	return false
}

// MatchKeyword vérifie en O(K) sur une table courte si un mot-clé hostile est présent (insensible à la casse).
func (d *FloppyDisk) MatchKeyword(payload []byte) (string, bool) {
	if d == nil || len(payload) == 0 {
		return "", false
	}
	for _, kw := range d.Keywords {
		if len(kw) > 0 && len(payload) >= len(kw) {
			if containsSubsliceFold(payload, []byte(kw)) {
				return kw, true
			}
		}
	}
	return "", false
}

// SearchCentroid trouve le centroïde le plus proche au sens de la distance de Hamming.
func (d *FloppyDisk) SearchCentroid(query *[codebookWords]uint64, maxHamming int) (CodebookEntry, int, bool) {
	if d == nil || query == nil || len(d.Entries) == 0 {
		return CodebookEntry{}, 0, false
	}
	best := maxHamming + 1
	var match CodebookEntry
	found := false
	for i := range d.Entries {
		e := &d.Entries[i]
		dist := codebookHammingBounded(query, e, maxHamming)
		if dist <= maxHamming && dist < best {
			best = dist
			match = *e
			found = true
		}
	}
	return match, best, found
}

// BlockRadius retourne le rayon de Hamming (sur 512 bits) en deçà duquel la
// proximité d'un centroïde d'attaque réelle vaut veto en L1b. Il est calibré à
// la forgerie sur la partition d'apprentissage bénigne de la disquette.
func (d *FloppyDisk) BlockRadius() int {
	if d == nil || d.Header.BlockRadius == 0 {
		return int(FloppyDefaultBlockRadius)
	}
	return int(d.Header.BlockRadius)
}

// nearThreat dit si un centroïde d'attaque de la disquette se trouve dans le
// rayon de veto. La recherche bornée abandonne chaque centroïde dès que la
// distance dépasse le rayon.
func (d *FloppyDisk) nearThreat(query *[codebookWords]uint64) bool {
	r := d.BlockRadius()
	_, dist, found := d.SearchCentroid(query, r)
	return found && dist <= r
}

// CalibrateBlockRadius retourne le plus grand rayon r <= FloppyDefaultBlockRadius
// tel que la part des vecteurs bénins d'apprentissage dont le centroïde
// d'attaque le plus proche est à distance <= r ne dépasse pas maxRate. Il
// s'applique à la forgerie, sur la seule partition d'apprentissage.
func CalibrateBlockRadius(entries []CodebookEntry, benign [][EmbeddingDim]float32, maxRate float64) uint8 {
	if len(benign) == 0 {
		return FloppyDefaultBlockRadius
	}
	d := &FloppyDisk{Entries: entries}
	var hits [int(FloppyDefaultBlockRadius) + 1]int
	for i := range benign {
		var code [codebookWords]uint64
		QuantizeFHT512(benign[i][:], &code)
		if _, dist, found := d.SearchCentroid(&code, int(FloppyDefaultBlockRadius)); found {
			hits[dist]++
		}
	}
	best := uint8(0)
	cum := 0
	for r := 0; r <= int(FloppyDefaultBlockRadius); r++ {
		cum += hits[r]
		if float64(cum) > maxRate*float64(len(benign)) {
			break
		}
		best = uint8(r)
	}
	if best == 0 {
		best = 1 // 0 est réservé à « non déclaré » ; un rayon de 1 bit reste un quasi-doublon
	}
	return best
}

// PredictINT8 calcule le produit scalaire entier saturé de la tête de décision (Zero-Alloc, 0 B/op).
func (d *FloppyDisk) PredictINT8(features []float32) (predictedClass int, maxScore int32, conforms bool) {
	if d == nil || len(d.Head) == 0 || len(features) < EmbeddingDim {
		return -1, 0, false
	}

	maxScore = math.MinInt32
	predictedClass = -1

	for c := range d.Head {
		cls := &d.Head[c]
		var acc int32 = cls.Bias
		for i := 0; i < EmbeddingDim; i++ {
			f := features[i]
			if math.IsNaN(float64(f)) || math.IsInf(float64(f), 0) {
				return -1, 0, false
			}
			var q int32
			if f > 1.0 {
				q = 127
			} else if f < -1.0 {
				q = -127
			} else {
				q = int32(f * 127.0)
			}
			acc += q * int32(cls.Weights[i])
		}

		if acc > maxScore {
			maxScore = acc
			predictedClass = c
		}
	}

	if predictedClass >= 0 {
		// Vérification conforme : si le score normalisé dépasse le seuil QHat
		cls := &d.Head[predictedClass]
		normScore := float32(maxScore) / (127.0 * float32(EmbeddingDim))
		conforms = normScore >= cls.QHat
	}

	return predictedClass, maxScore, conforms
}

// SaveFloppyFile sérialise une disquette dans un fichier binaire .c2book étendu.
func SaveFloppyFile(path string, familyID uint16, keywords []string, entries []CodebookEntry, head []DecisionClass, protos []FloppyPrototype, blockRadius uint8, hmacKey []byte) error {
	if len(protos) > math.MaxUint16 {
		return fmt.Errorf("c2flop: %d prototypes, maximum %d", len(protos), math.MaxUint16)
	}
	for i := range protos {
		if protos[i].Class > 1 {
			return fmt.Errorf("c2flop: classe de prototype %d hors {0,1}", protos[i].Class)
		}
	}
	// Écriture dans un fichier temporaire du même répertoire puis renommage
	// atomique : un lecteur concurrent voit l'ancienne disquette ou la
	// nouvelle, jamais une disquette à moitié écrite.
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	committed := false
	defer func() {
		if !committed {
			f.Close()
			os.Remove(tmpPath)
		}
	}()

	hdr := FloppyHeader{
		Magic:       FloppyMagic,
		Version:     FloppyVersion,
		FamilyID:    familyID,
		VectorDim:   EmbeddingDim,
		EntryCount:  uint32(len(entries)),
		KwCount:     uint32(len(keywords)),
		HeadClasses: uint16(len(head)),
		ProtoCount:  uint16(len(protos)),
		BlockRadius: blockRadius,
	}

	// Sérialisation du corps pour calcul CRC32C et HMAC
	var body []byte

	// 1. Mots-clés
	for _, kw := range keywords {
		kwBytes := []byte(kw)
		var lenBuf [2]byte
		binary.LittleEndian.PutUint16(lenBuf[:], uint16(len(kwBytes)))
		body = append(body, lenBuf[:]...)
		body = append(body, kwBytes...)
	}

	// 2. Centroïdes
	var eb [codebookEntrySize]byte
	for i := range entries {
		encodeCodebookEntry(&eb, &entries[i])
		body = append(body, eb[:]...)
	}

	// 3. Tête de décision
	const classRecSize = EmbeddingDim + 4 + 4
	for i := range head {
		var rec [classRecSize]byte
		for d := 0; d < EmbeddingDim; d++ {
			rec[d] = byte(head[i].Weights[d])
		}
		binary.LittleEndian.PutUint32(rec[EmbeddingDim:EmbeddingDim+4], uint32(head[i].Bias))
		binary.LittleEndian.PutUint32(rec[EmbeddingDim+4:classRecSize], math.Float32bits(head[i].QHat))
		body = append(body, rec[:]...)
	}

	// 4. Prototypes d'étalonnage L1a
	for i := range protos {
		var rec [floppyProtoRecSize]byte
		binary.LittleEndian.PutUint16(rec[0:2], protos[i].Class)
		for d := 0; d < EmbeddingDim; d++ {
			binary.LittleEndian.PutUint32(rec[4+d*4:], math.Float32bits(protos[i].Vector[d]))
		}
		body = append(body, rec[:]...)
	}

	// CRC32C Castagnoli
	hdr.CRC32C = crc32.Checksum(body, crc32.MakeTable(crc32.Castagnoli))

	var hBuf [FloppyHeaderSize]byte

	// HMAC-SHA256 si clé fournie : couvre les 32 premiers octets de l'en-tête
	// (dont BlockRadius et FamilyID) ainsi que le corps.
	if len(hmacKey) > 0 {
		hdr.Flags |= FloppyFlagSealed
		copy(hBuf[:FloppyHeaderSize], (*[FloppyHeaderSize]byte)(unsafe.Pointer(&hdr))[:])
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write(hBuf[:32])
		mac.Write(body)
		copy(hdr.Seal[:], mac.Sum(nil))
	}

	// Écriture de l'en-tête de 64 octets
	copy(hBuf[:FloppyHeaderSize], (*[FloppyHeaderSize]byte)(unsafe.Pointer(&hdr))[:])
	if _, err := f.Write(hBuf[:]); err != nil {
		return err
	}

	// Écriture du corps
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}
