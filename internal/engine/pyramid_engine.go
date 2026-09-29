// Package engine — pyramid_engine.go
// Pyramide temporelle multi-échelle (.c2pyramid) : pour chaque horizon glissant
// (4 h, 12 h, 24 h, 7 j, 30 j, 120 j, 365 j), la norme comportementale de la
// machine est condensée en prototypes 512 bits de la géométrie
// VectorizeServerHealthLocality, chacun muni d'un rayon de normalité. Un état
// observé est évalué à chaque échelle : il est nominal s'il tombe dans le rayon
// d'un prototype admissible, sinon il est soumis au catalogue .c2delta, qui le
// dispense ou le laisse en anomalie active.
package engine

import (
	"bufio"
	"cmp"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"slices"
	"sync"
	"unsafe"
)

const (
	// PyramidHeaderSize est la taille exacte de l'en-tête d'un fichier .c2pyramid.
	PyramidHeaderSize = 64
	// PyramidPrototypeSize est la taille exacte d'un prototype.
	PyramidPrototypeSize = 96
	// PyramidVersion est la version de schéma de la pyramide.
	PyramidVersion uint16 = 1
	// PyramidMaxRadius borne le rayon de normalité d'un prototype, en bits de Hamming.
	PyramidMaxRadius = 16
	// PyramidMaxPrototypes borne le nombre de prototypes d'une échelle.
	PyramidMaxPrototypes = 1 << 16
	// pyramidLoadInitialCap borne la préallocation au chargement.
	pyramidLoadInitialCap = 1024
)

// PyramidMagic identifie une pyramide temporelle.
var PyramidMagic = [8]byte{'C', '2', 'P', 'Y', 'R', 'A', 'M', '1'}

// Agencement de PyramidPrototype.TemporalPattern : bits 0..23 = heures UTC où
// le prototype a été observé, bits 24..30 = jours de la semaine UTC (dimanche =
// 24), bit 31 réservé à zéro.
const (
	PyramidHoursMask uint32 = 1<<24 - 1
	PyramidDaysShift        = 24
	PyramidDaysMask  uint32 = uint32(DeltaAllDays) << PyramidDaysShift
)

// Erreurs contractuelles des fichiers .c2pyramid.
var (
	ErrPyramidMagic     = errors.New("c2pyramid: signature magique invalide")
	ErrPyramidVersion   = errors.New("c2pyramid: version non supportee")
	ErrPyramidCorrupt   = errors.New("c2pyramid: fichier tronque ou incomplet")
	ErrPyramidSeal      = errors.New("c2pyramid: empreinte SHA-256 ou HMAC-SHA256 invalide")
	ErrPyramidTooLarge  = errors.New("c2pyramid: nombre de prototypes superieur a PyramidMaxPrototypes")
	ErrPyramidMachine   = errors.New("c2pyramid: pyramide d'une autre machine")
	ErrPyramidScale     = errors.New("c2pyramid: echelle invalide (un seul bit de DeltaScaleAll attendu)")
	ErrPyramidEpoch     = errors.New("c2pyramid: horizon invalide (EpochEnd < EpochStart)")
	ErrPyramidPrototype = errors.New("c2pyramid: prototype invalide")
	// ErrCondenseNoDays refuse une condensation hiérarchique sans tranche.
	ErrCondenseNoDays = errors.New("c2pyramid: aucune tranche a condenser")
)

// PyramidHeader structure l'en-tête de 64 octets.
type PyramidHeader struct {
	Magic          [8]byte  // 'C2PYRAM1' (0..8)
	Version        uint16   // PyramidVersion (8..10)
	Scale          uint16   // Échelle représentée, un seul bit DeltaScale* (10..12)
	PrototypeCount uint32   // Nombre de prototypes (12..16)
	EpochStart     uint32   // Premier jour calendaire Unix couvert (16..20)
	EpochEnd       uint32   // Dernier jour calendaire Unix couvert (20..24)
	MachineID      uint64   // Machine décrite (24..32)
	Seal           [32]byte // SHA-256 de l'en-tête (Seal à zéro) et des prototypes (32..64)
}

// PyramidPrototype structure un prototype de 96 octets.
type PyramidPrototype struct {
	Bitcode         [8]uint64 // Centroïde 512 bits (0..64)
	Radius          uint16    // Rayon de normalité, distance de Hamming (64..66)
	Subsystem       uint16    // Sous-système (66..68)
	AverageScore    uint16    // Score de santé moyen des observations (68..70)
	MinScore        uint16    // Score de santé minimal observé (70..72)
	HitCount        uint32    // Nombre d'observations consolidées (72..76)
	TemporalPattern uint32    // Heures et jours de récurrence (PyramidHoursMask, PyramidDaysMask) (76..80)
	Reserved        [16]byte  // Alignement sur 96 octets (80..96)
}

var (
	_ = [1]struct{}{}[unsafe.Sizeof(PyramidHeader{})-PyramidHeaderSize]
	_ = [1]struct{}{}[unsafe.Sizeof(PyramidPrototype{})-PyramidPrototypeSize]
)

// EncodePyramidHeader écrit l'en-tête en little-endian.
func EncodePyramidHeader(dst *[PyramidHeaderSize]byte, h *PyramidHeader) {
	copy(dst[0:8], h.Magic[:])
	binary.LittleEndian.PutUint16(dst[8:10], h.Version)
	binary.LittleEndian.PutUint16(dst[10:12], h.Scale)
	binary.LittleEndian.PutUint32(dst[12:16], h.PrototypeCount)
	binary.LittleEndian.PutUint32(dst[16:20], h.EpochStart)
	binary.LittleEndian.PutUint32(dst[20:24], h.EpochEnd)
	binary.LittleEndian.PutUint64(dst[24:32], h.MachineID)
	copy(dst[32:64], h.Seal[:])
}

// DecodePyramidHeader lit l'en-tête little-endian.
func DecodePyramidHeader(src *[PyramidHeaderSize]byte, h *PyramidHeader) {
	copy(h.Magic[:], src[0:8])
	h.Version = binary.LittleEndian.Uint16(src[8:10])
	h.Scale = binary.LittleEndian.Uint16(src[10:12])
	h.PrototypeCount = binary.LittleEndian.Uint32(src[12:16])
	h.EpochStart = binary.LittleEndian.Uint32(src[16:20])
	h.EpochEnd = binary.LittleEndian.Uint32(src[20:24])
	h.MachineID = binary.LittleEndian.Uint64(src[24:32])
	copy(h.Seal[:], src[32:64])
}

// EncodePyramidPrototype écrit un prototype en little-endian.
func EncodePyramidPrototype(dst *[PyramidPrototypeSize]byte, p *PyramidPrototype) {
	for i := range 8 {
		binary.LittleEndian.PutUint64(dst[i*8:], p.Bitcode[i])
	}
	binary.LittleEndian.PutUint16(dst[64:66], p.Radius)
	binary.LittleEndian.PutUint16(dst[66:68], p.Subsystem)
	binary.LittleEndian.PutUint16(dst[68:70], p.AverageScore)
	binary.LittleEndian.PutUint16(dst[70:72], p.MinScore)
	binary.LittleEndian.PutUint32(dst[72:76], p.HitCount)
	binary.LittleEndian.PutUint32(dst[76:80], p.TemporalPattern)
	copy(dst[80:96], p.Reserved[:])
}

// DecodePyramidPrototype lit un prototype little-endian.
func DecodePyramidPrototype(src *[PyramidPrototypeSize]byte, p *PyramidPrototype) {
	for i := range 8 {
		p.Bitcode[i] = binary.LittleEndian.Uint64(src[i*8:])
	}
	p.Radius = binary.LittleEndian.Uint16(src[64:66])
	p.Subsystem = binary.LittleEndian.Uint16(src[66:68])
	p.AverageScore = binary.LittleEndian.Uint16(src[68:70])
	p.MinScore = binary.LittleEndian.Uint16(src[70:72])
	p.HitCount = binary.LittleEndian.Uint32(src[72:76])
	p.TemporalPattern = binary.LittleEndian.Uint32(src[76:80])
	copy(p.Reserved[:], src[80:96])
}

// ComputePyramidSeal calcule le SHA-256 de l'en-tête encodé, Seal remis à zéro,
// suivi des prototypes encodés dans l'ordre.
func ComputePyramidSeal(hdr *PyramidHeader, protos []PyramidPrototype) [32]byte {
	return ComputePyramidSealHMAC(hdr, protos, nil)
}

// ComputePyramidSealHMAC calcule le sceau sur les mêmes octets que
// ComputePyramidSeal, par HMAC-SHA256 sous la clé key ; une clé vide rend le
// SHA-256 simple. Sans la clé, une pyramide qui élargirait la norme de la
// machine ne peut pas être forgée.
func ComputePyramidSealHMAC(hdr *PyramidHeader, protos []PyramidPrototype, key []byte) [32]byte {
	h := newSealHash(key)
	unsealed := *hdr
	unsealed.Seal = [32]byte{}
	var hb [PyramidHeaderSize]byte
	EncodePyramidHeader(&hb, &unsealed)
	h.Write(hb[:])
	var pb [PyramidPrototypeSize]byte
	for i := range protos {
		EncodePyramidPrototype(&pb, &protos[i])
		h.Write(pb[:])
	}
	var seal [32]byte
	copy(seal[:], h.Sum(nil))
	return seal
}

// pyramidScaleIndex rend le rang 0..6 d'une échelle à un seul bit, faux sinon.
func pyramidScaleIndex(scale uint16) (int, bool) {
	if scale == 0 || scale&^DeltaScaleAll != 0 || scale&(scale-1) != 0 {
		return 0, false
	}
	return bits.TrailingZeros16(scale), true
}

// ValidatePyramidPrototype applique les gardes de référence à un prototype :
//   - rayon au plus PyramidMaxRadius ;
//   - champ de sévérité du centroïde codé en thermomètre entier, de niveau
//     inférieur à High : un état High ou Critical ne devient jamais une norme ;
//   - DegradedHealthScore <= MinScore <= AverageScore <= 1000 : un état dégradé
//     ne devient pas davantage une norme ;
//   - HitCount non nul ;
//   - au moins une heure et un jour dans TemporalPattern, bit 31 nul.
func ValidatePyramidPrototype(p *PyramidPrototype) error {
	if p.Radius > PyramidMaxRadius {
		return fmt.Errorf("%w: rayon %d > %d", ErrPyramidPrototype, p.Radius, PyramidMaxRadius)
	}
	level, ok := deltaSeverityLevel(p.Bitcode[2])
	if !ok || level >= SeverityHigh {
		return fmt.Errorf("%w: severite du centroide hors thermometre ou >= High", ErrPyramidPrototype)
	}
	if p.MinScore < DegradedHealthScore || p.MinScore > p.AverageScore || p.AverageScore > localityScoreMax {
		return fmt.Errorf("%w: scores min %d, moyen %d", ErrPyramidPrototype, p.MinScore, p.AverageScore)
	}
	if p.HitCount == 0 {
		return fmt.Errorf("%w: aucune observation", ErrPyramidPrototype)
	}
	if p.TemporalPattern&PyramidHoursMask == 0 || p.TemporalPattern&PyramidDaysMask == 0 ||
		p.TemporalPattern&^(PyramidHoursMask|PyramidDaysMask) != 0 {
		return fmt.Errorf("%w: motif temporel 0x%08x", ErrPyramidPrototype, p.TemporalPattern)
	}
	return nil
}

// validatePyramid valide l'échelle, l'horizon et chaque prototype.
func validatePyramid(scale uint16, epochStart, epochEnd uint32, protos []PyramidPrototype) error {
	if _, ok := pyramidScaleIndex(scale); !ok {
		return fmt.Errorf("%w: 0x%04x", ErrPyramidScale, scale)
	}
	if epochEnd < epochStart {
		return fmt.Errorf("%w: %d..%d", ErrPyramidEpoch, epochStart, epochEnd)
	}
	for i := range protos {
		if err := ValidatePyramidPrototype(&protos[i]); err != nil {
			return fmt.Errorf("prototype %d: %w", i, err)
		}
	}
	return nil
}

// SavePyramid valide puis écrit une pyramide scellée d'une échelle.
func SavePyramid(w io.Writer, machineID uint64, scale uint16, epochStart, epochEnd uint32, protos []PyramidPrototype) error {
	return SavePyramidHMAC(w, machineID, scale, epochStart, epochEnd, protos, nil)
}

// SavePyramidHMAC valide puis écrit une pyramide dont le sceau est un
// HMAC-SHA256 sous key ; une clé vide écrit le sceau SHA-256 de SavePyramid.
func SavePyramidHMAC(w io.Writer, machineID uint64, scale uint16, epochStart, epochEnd uint32, protos []PyramidPrototype, key []byte) error {
	if err := checkSealKey(key); err != nil {
		return err
	}
	if len(protos) > PyramidMaxPrototypes {
		return ErrPyramidTooLarge
	}
	if err := validatePyramid(scale, epochStart, epochEnd, protos); err != nil {
		return err
	}
	hdr := PyramidHeader{
		Magic:          PyramidMagic,
		Version:        PyramidVersion,
		Scale:          scale,
		PrototypeCount: uint32(len(protos)),
		EpochStart:     epochStart,
		EpochEnd:       epochEnd,
		MachineID:      machineID,
	}
	hdr.Seal = ComputePyramidSealHMAC(&hdr, protos, key)

	bw := bufio.NewWriterSize(w, 1<<16)
	var hb [PyramidHeaderSize]byte
	EncodePyramidHeader(&hb, &hdr)
	if _, err := bw.Write(hb[:]); err != nil {
		return err
	}
	var pb [PyramidPrototypeSize]byte
	for i := range protos {
		EncodePyramidPrototype(&pb, &protos[i])
		if _, err := bw.Write(pb[:]); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// Pyramid est le niveau chargé et validé d'une échelle ; immuable, il se lit
// sans verrou depuis plusieurs goroutines.
type Pyramid struct {
	hdr    PyramidHeader
	protos []PyramidPrototype
}

// NewPyramid valide des prototypes et rend la pyramide d'une échelle, sans
// passer par un fichier ; son en-tête porte le sceau SHA-256.
func NewPyramid(machineID uint64, scale uint16, epochStart, epochEnd uint32, protos []PyramidPrototype) (*Pyramid, error) {
	if len(protos) > PyramidMaxPrototypes {
		return nil, ErrPyramidTooLarge
	}
	if err := validatePyramid(scale, epochStart, epochEnd, protos); err != nil {
		return nil, err
	}
	hdr := PyramidHeader{
		Magic:          PyramidMagic,
		Version:        PyramidVersion,
		Scale:          scale,
		PrototypeCount: uint32(len(protos)),
		EpochStart:     epochStart,
		EpochEnd:       epochEnd,
		MachineID:      machineID,
	}
	hdr.Seal = ComputePyramidSeal(&hdr, protos)
	return &Pyramid{hdr: hdr, protos: protos}, nil
}

// SaveHMAC écrit la pyramide, scellée sous key (SHA-256 si key est vide).
func (p *Pyramid) SaveHMAC(w io.Writer, key []byte) error {
	return SavePyramidHMAC(w, p.hdr.MachineID, p.hdr.Scale, p.hdr.EpochStart, p.hdr.EpochEnd, p.protos, key)
}

// LoadPyramid lit une pyramide, vérifie sa signature, son sceau et sa machine,
// puis la refuse entière si l'échelle, l'horizon ou un prototype viole une garde.
func LoadPyramid(r io.Reader, machineID uint64) (*Pyramid, error) {
	return LoadPyramidHMAC(r, machineID, nil)
}

// LoadPyramidHMAC charge comme LoadPyramid, mais exige un sceau HMAC-SHA256
// sous key. Sous une clé non vide, une pyramide scellée en SHA-256 simple ou
// sous une autre clé est refusée par ErrPyramidSeal ; la comparaison du sceau
// se fait en temps constant.
func LoadPyramidHMAC(r io.Reader, machineID uint64, key []byte) (*Pyramid, error) {
	if err := checkSealKey(key); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(r, 1<<16)
	var hb [PyramidHeaderSize]byte
	if _, err := io.ReadFull(br, hb[:]); err != nil {
		return nil, ErrPyramidCorrupt
	}
	var hdr PyramidHeader
	DecodePyramidHeader(&hb, &hdr)
	if hdr.Magic != PyramidMagic {
		return nil, ErrPyramidMagic
	}
	if hdr.Version != PyramidVersion {
		return nil, ErrPyramidVersion
	}
	if hdr.PrototypeCount > PyramidMaxPrototypes {
		return nil, ErrPyramidTooLarge
	}
	protos := make([]PyramidPrototype, 0, min(hdr.PrototypeCount, pyramidLoadInitialCap))
	var pb [PyramidPrototypeSize]byte
	for i := uint32(0); i < hdr.PrototypeCount; i++ {
		if _, err := io.ReadFull(br, pb[:]); err != nil {
			return nil, ErrPyramidCorrupt
		}
		var p PyramidPrototype
		DecodePyramidPrototype(&pb, &p)
		protos = append(protos, p)
	}
	if seal := ComputePyramidSealHMAC(&hdr, protos, key); !hmac.Equal(seal[:], hdr.Seal[:]) {
		return nil, ErrPyramidSeal
	}
	if hdr.MachineID != machineID {
		return nil, ErrPyramidMachine
	}
	if err := validatePyramid(hdr.Scale, hdr.EpochStart, hdr.EpochEnd, protos); err != nil {
		return nil, err
	}
	return &Pyramid{hdr: hdr, protos: protos}, nil
}

// Header rend une copie de l'en-tête.
func (p *Pyramid) Header() PyramidHeader { return p.hdr }

// Len rend le nombre de prototypes.
func (p *Pyramid) Len() int {
	if p == nil {
		return 0
	}
	return len(p.protos)
}

// pyramidTemporalGate rend les bits de TemporalPattern qu'un prototype doit
// porter pour s'appliquer à l'instant tsSec à cette échelle :
//   - 4 h et 12 h : aucun, ces horizons ne couvrent pas une journée entière et
//     l'heure est déjà comparée par le mot 5 du bitcode ;
//   - 24 h et au-delà : l'heure de l'observation ou l'une de ses deux voisines,
//     la voisine de minuit étant 23 h (repli circulaire) ;
//   - 7 j et au-delà : en plus, le jour de la semaine de l'observation.
//
// hoursNeed et daysNeed valent zéro quand le critère ne s'applique pas.
func pyramidTemporalGate(scaleIdx int, tsSec uint64) (hoursNeed, daysNeed uint32) {
	if scaleIdx >= 2 {
		h := uint32(tsSec % 86400 / 3600)
		hoursNeed = 1<<h | 1<<((h+1)%24) | 1<<((h+23)%24)
	}
	if scaleIdx >= 3 {
		dow := uint32((tsSec/86400 + 4) % 7)
		daysNeed = 1 << (PyramidDaysShift + dow)
	}
	return hoursNeed, daysNeed
}

// ScaleDisparity est le verdict d'une échelle pour un état observé.
type ScaleDisparity struct {
	Scale          uint16 // bit DeltaScale* de l'échelle
	Loaded         bool   // une pyramide est installée à cette échelle ; sinon aucun verdict
	Nominal        bool   // l'état tombe dans le rayon d'un prototype admissible
	Dispensed      bool   // l'état dévie mais une règle .c2delta le dispense
	RuleID         uint32 // règle qui dispense, 0 sinon
	DisparityBits  uint16 // distance de Hamming au prototype admissible le plus proche, 512 s'il n'y en a pas
	PrototypeIndex int32  // rang de ce prototype, -1 s'il n'y en a pas
}

// Anomaly dit si l'échelle, chargée, porte une anomalie active.
func (d ScaleDisparity) Anomaly() bool {
	return d.Loaded && !d.Nominal && !d.Dispensed
}

// MultiScaleDisparityReport réunit les verdicts des sept échelles, rangés dans
// l'ordre de DeltaScale4h à DeltaScale365d, et leurs masques de synthèse.
type MultiScaleDisparityReport struct {
	Levels        [DeltaScaleCount]ScaleDisparity
	LoadedMask    uint16 // échelles évaluées
	NominalMask   uint16 // échelles où l'état est nominal
	DispensedMask uint16 // échelles où l'état est dispensé par le catalogue
	AnomalyMask   uint16 // échelles en anomalie active
}

// MultiScalePyramid tient une pyramide par échelle. Un sync.RWMutex sérialise
// Install et Remove face aux évaluations ; une pyramide installée est immuable.
type MultiScalePyramid struct {
	mu        sync.RWMutex
	machineID uint64
	levels    [DeltaScaleCount]*Pyramid
}

// NewMultiScalePyramid crée un moteur vide pour machineID.
func NewMultiScalePyramid(machineID uint64) *MultiScalePyramid {
	return &MultiScalePyramid{machineID: machineID}
}

// Install place p à son échelle, en remplaçant la pyramide précédente.
func (m *MultiScalePyramid) Install(p *Pyramid) error {
	if p == nil {
		return fmt.Errorf("%w: pyramide nil", ErrPyramidCorrupt)
	}
	if p.hdr.MachineID != m.machineID {
		return ErrPyramidMachine
	}
	idx, ok := pyramidScaleIndex(p.hdr.Scale)
	if !ok {
		return fmt.Errorf("%w: 0x%04x", ErrPyramidScale, p.hdr.Scale)
	}
	m.mu.Lock()
	m.levels[idx] = p
	m.mu.Unlock()
	return nil
}

// Remove retire la pyramide d'une échelle.
func (m *MultiScalePyramid) Remove(scale uint16) error {
	idx, ok := pyramidScaleIndex(scale)
	if !ok {
		return fmt.Errorf("%w: 0x%04x", ErrPyramidScale, scale)
	}
	m.mu.Lock()
	m.levels[idx] = nil
	m.mu.Unlock()
	return nil
}

// Scales rend le masque des échelles installées.
func (m *MultiScalePyramid) Scales() uint16 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var mask uint16
	for i, p := range m.levels {
		if p != nil {
			mask |= 1 << i
		}
	}
	return mask
}

// EvaluateInstantaneous évalue l'état observé à l'instant tsSec contre chaque
// échelle installée. À une échelle, un prototype est admissible si son motif
// temporel couvre l'instant (pyramidTemporalGate) et si la sévérité observée
// ne dépasse pas celle de son centroïde : un rayon de 16 bits absorberait
// sinon deux niveaux d'aggravation. L'état est nominal s'il se trouve à une
// distance de Hamming au plus égale au rayon d'un prototype admissible ; sinon
// catalog.EvaluateDelta est interrogé pour cette échelle, et l'écart est soit
// dispensé, soit une anomalie active. Un catalogue nil ne dispense rien.
// 0 allocation tas (0 B/op).
func (m *MultiScalePyramid) EvaluateInstantaneous(observed *[8]uint64, tsSec uint64, catalog *DeltaCatalog) MultiScaleDisparityReport {
	var rep MultiScaleDisparityReport
	for i := range rep.Levels {
		rep.Levels[i] = ScaleDisparity{Scale: 1 << i, DisparityBits: 512, PrototypeIndex: -1}
	}
	if m == nil || observed == nil {
		return rep
	}
	obsLevel := deltaSeverityCeil(observed[2])
	q0, q1, q2, q3 := observed[0], observed[1], observed[2], observed[3]
	q4, q5, q6, q7 := observed[4], observed[5], observed[6], observed[7]

	m.mu.RLock()
	defer m.mu.RUnlock()
	for idx, p := range m.levels {
		if p == nil {
			continue
		}
		lv := &rep.Levels[idx]
		lv.Loaded = true
		rep.LoadedMask |= lv.Scale
		hoursNeed, daysNeed := pyramidTemporalGate(idx, tsSec)
		best := 513
		for j := range p.protos {
			pr := &p.protos[j]
			if (hoursNeed != 0 && pr.TemporalPattern&hoursNeed == 0) ||
				(daysNeed != 0 && pr.TemporalPattern&daysNeed == 0) ||
				obsLevel > deltaSeverityCeil(pr.Bitcode[2]) {
				continue
			}
			d := bits.OnesCount64(pr.Bitcode[0]^q0) +
				bits.OnesCount64(pr.Bitcode[1]^q1) +
				bits.OnesCount64(pr.Bitcode[2]^q2) +
				bits.OnesCount64(pr.Bitcode[3]^q3) +
				bits.OnesCount64(pr.Bitcode[4]^q4) +
				bits.OnesCount64(pr.Bitcode[5]^q5) +
				bits.OnesCount64(pr.Bitcode[6]^q6) +
				bits.OnesCount64(pr.Bitcode[7]^q7)
			if d <= int(pr.Radius) {
				// Un prototype qui contient l'état l'emporte sur un plus proche qui ne le contient pas.
				if !lv.Nominal || d < best {
					lv.Nominal, best, lv.PrototypeIndex = true, d, int32(j)
				}
				continue
			}
			if !lv.Nominal && d < best {
				best, lv.PrototypeIndex = d, int32(j)
			}
		}
		if best <= 512 {
			lv.DisparityBits = uint16(best)
		}
		if lv.Nominal {
			rep.NominalMask |= lv.Scale
			continue
		}
		lv.Dispensed, lv.RuleID = catalog.EvaluateDelta(observed, tsSec, lv.Scale)
		if lv.Dispensed {
			rep.DispensedMask |= lv.Scale
		} else {
			rep.AnomalyMask |= lv.Scale
		}
	}
	return rep
}

// CondenseDay est une tranche journalière soumise à la condensation.
type CondenseDay struct {
	EpochDay uint32              // jour calendaire Unix de la tranche
	Entries  []OracleVectorEntry // entrées de la tranche, bitcodes VectorizeServerHealthLocality
}

// Plafond des groupes intermédiaires de la condensation (finding N3). Chaque
// groupe tient 512 compteurs de 32 bits, soit plus de 2 Kio : sans plafond, une
// rétention de 365 jours d'états tous distincts en ferait autant que d'entrées.
const (
	// CondenseDefaultIntermediateClusters est le plafond appliqué quand CondenseConfig n'en fixe pas.
	CondenseDefaultIntermediateClusters = 4096
	// CondenseMaxIntermediateClusters borne le plafond configurable.
	CondenseMaxIntermediateClusters = 16384
)

// CondenseHierarchyDefaultScales sont les échelles que CondensePyramidHierarchy
// produit quand CondenseConfig.Scales est nul.
const CondenseHierarchyDefaultScales = DeltaScale24h | DeltaScale7d | DeltaScale30d | DeltaScale120d | DeltaScale365d

// pyramidScaleDays est l'horizon en jours calendaires de chaque échelle ; 4 h
// et 12 h valent zéro, faute de pouvoir se déduire de tranches journalières.
var pyramidScaleDays = [DeltaScaleCount]uint32{0, 0, 1, 7, 30, 120, 365}

// CondenseConfig règle la condensation.
type CondenseConfig struct {
	Radius        uint16 // rayon de regroupement, 1..PyramidMaxRadius ; 0 vaut PyramidMaxRadius
	MaxPrototypes int    // nombre maximal de prototypes gardés ; 0 vaut PyramidMaxPrototypes
	MinHits       uint32 // observations minimales d'un prototype gardé ; 0 vaut 1
	// MaxIntermediateClusters plafonne les groupes vivants pendant
	// l'accumulation ; 0 ou négatif vaut CondenseDefaultIntermediateClusters,
	// au-delà de CondenseMaxIntermediateClusters il est ramené à ce maximum.
	MaxIntermediateClusters int
	// Scales choisit les échelles de CondensePyramidHierarchy ; 0 vaut
	// CondenseHierarchyDefaultScales. CondensePrototypes l'ignore.
	Scales uint16
}

// CondenseStats décrit ce que la condensation a retenu et écarté.
type CondenseStats struct {
	Admitted        int    // entrées admises comme référence
	Excluded        int    // entrées écartées : High/Critical, dégradées, marquées, ou sévérité du bitcode hors thermomètre
	Clusters        int    // groupes formés avant sélection
	DroppedClusters int    // groupes écartés par MinHits ou MaxPrototypes
	DroppedHits     uint64 // observations de ces groupes
	EvictedClusters int    // groupes évincés pendant l'accumulation pour tenir MaxIntermediateClusters
	EvictedHits     uint64 // observations de ces groupes
	PeakClusters    int    // nombre maximal de groupes vivants atteint pendant l'accumulation
	EpochStart      uint32 // premier jour vu parmi les tranches fournies
	EpochEnd        uint32 // dernier jour vu
}

// condenseCluster accumule un groupe pendant la condensation.
type condenseCluster struct {
	leader   [8]uint64
	sub      uint16
	level    uint16
	ones     [512]uint32
	sumScore uint64
	minScore uint16
	hits     uint32
	pattern  uint32
	order    int
}

// condenseKey regroupe les meneurs par sous-système et niveau de sévérité :
// deux états de catégories ou de sévérités distinctes ne fusionnent jamais.
type condenseKey struct {
	sub   uint16
	level uint16
}

// CondensePrototypes condense des tranches journalières en prototypes par
// regroupement à meneur (leader clustering) déterministe :
//  1. les tranches sont parcourues par jour croissant (à jour égal, dans l'ordre
//     fourni), les entrées dans leur ordre de scellement ;
//  2. une entrée High/Critical, dégradée (score < DegradedHealthScore), marquée
//     anomalie ou dégradation, ou dont le champ de sévérité du bitcode n'est pas
//     un thermomètre de niveau < High, est écartée ;
//  3. une entrée admise rejoint le premier meneur, parmi ceux de même
//     sous-système et de même niveau, qui est à la distance minimale et au plus
//     égale à Radius ; sinon elle fonde un nouveau groupe dont elle est le meneur ;
//  4. si fonder ce groupe porterait les groupes vivants au-delà de
//     MaxIntermediateClusters, le quart le moins fourni des groupes vivants est
//     d'abord évincé (à égalité, le plus ancien) : leurs observations sont
//     perdues et comptées dans EvictedHits. L'éviction garde intact le lien
//     de chaque membre à son meneur, ce que ne ferait pas une fusion de deux
//     meneurs voisins, dont les membres pourraient s'écarter du centroïde
//     fusionné au-delà de Radius, voire de PyramidMaxRadius ;
//  5. le centroïde d'un groupe est le vote majoritaire bit à bit de ses membres
//     (égalité tranchée par le bit du meneur) ; si un membre en est à plus de
//     Radius, le centroïde retombe sur le meneur, à qui tous les membres sont
//     liés par construction. Le rayon du prototype est la distance maximale
//     entre le centroïde et ses membres ;
//  6. les groupes de moins de MinHits observations sont écartés, puis les
//     MaxPrototypes groupes les plus fournis sont gardés (à égalité, le plus
//     ancien), rangés par ordre de création.
//
// La mémoire de travail est bornée par MaxIntermediateClusters groupes, plus
// quatre octets par entrée admise et douze par groupe fondé, en sus des
// tranches fournies. Le résultat passe ValidatePyramidPrototype.
func CondensePrototypes(days []CondenseDay, cfg CondenseConfig) ([]PyramidPrototype, CondenseStats) {
	radius := int(cfg.Radius)
	if radius == 0 || radius > PyramidMaxRadius {
		radius = PyramidMaxRadius
	}
	maxProtos := cfg.MaxPrototypes
	if maxProtos <= 0 || maxProtos > PyramidMaxPrototypes {
		maxProtos = PyramidMaxPrototypes
	}
	minHits := max(cfg.MinHits, 1)
	budget := condenseBudget(cfg.MaxIntermediateClusters)

	var st CondenseStats
	order := make([]int, len(days))
	for i := range order {
		order[i] = i
	}
	slices.SortStableFunc(order, func(a, b int) int { return cmp.Compare(days[a].EpochDay, days[b].EpochDay) })
	if len(days) > 0 {
		st.EpochStart, st.EpochEnd = days[order[0]].EpochDay, days[order[len(order)-1]].EpochDay
	}

	// clusters[ci] est le groupe fondé en ci-ème, nil une fois évincé.
	var clusters []*condenseCluster
	live := 0
	buckets := make(map[condenseKey][]int)
	// assign[k] est le groupe de la k-ième entrée admise, dans l'ordre de parcours.
	var assign []int32

	for _, di := range order {
		day := &days[di]
		dow := (day.EpochDay + 4) % 7
		for ei := range day.Entries {
			e := &day.Entries[ei]
			level, ok := condenseAdmit(e)
			if !ok {
				st.Excluded++
				continue
			}
			st.Admitted++
			key := condenseKey{sub: e.Subsystem, level: level}
			target, bestD := -1, radius+1
			for _, ci := range buckets[key] {
				if d := HammingDistance512(&e.Bitcode, &clusters[ci].leader); d < bestD {
					target, bestD = ci, d
				}
			}
			if target < 0 {
				if live >= budget {
					live -= condenseEvict(clusters, buckets, live-budget*3/4, &st)
				}
				target = len(clusters)
				clusters = append(clusters, &condenseCluster{
					leader: e.Bitcode, sub: e.Subsystem, level: level, minScore: e.HealthScore, order: target,
				})
				buckets[key] = append(buckets[key], target)
				live++
				st.PeakClusters = max(st.PeakClusters, live)
			}
			c := clusters[target]
			for w := range 8 {
				for x := e.Bitcode[w]; x != 0; x &= x - 1 {
					c.ones[w*64+bits.TrailingZeros64(x)]++
				}
			}
			c.sumScore += uint64(e.HealthScore)
			c.minScore = min(c.minScore, e.HealthScore)
			c.hits++
			hour := min(e.RelativeSec, 86399) / 3600
			c.pattern |= 1<<hour | 1<<(PyramidDaysShift+dow)
			assign = append(assign, int32(target))
		}
	}
	st.Clusters = len(clusters)

	// slot[ci] est le rang compact du groupe ci parmi les groupes vivants, -1
	// s'il a été évincé ; centroïdes et rayons ne se tiennent que pour ceux-là.
	slot := make([]int32, len(clusters))
	survivors := make([]*condenseCluster, 0, live)
	for ci, c := range clusters {
		slot[ci] = -1
		if c != nil {
			slot[ci] = int32(len(survivors))
			survivors = append(survivors, c)
		}
	}

	// memberRadii rend, pour chaque groupe vivant retenu par only (tous si only
	// est nil), la distance maximale entre son centroïde et ses membres ; la
	// seconde passe rejoue le parcours et le filtre de la première.
	memberRadii := func(centroids [][8]uint64, radii []int, only []bool) {
		k := 0
		for _, di := range order {
			for ei := range days[di].Entries {
				e := &days[di].Entries[ei]
				if _, ok := condenseAdmit(e); !ok {
					continue
				}
				si := slot[assign[k]]
				k++
				if si >= 0 && (only == nil || only[si]) {
					radii[si] = max(radii[si], HammingDistance512(&e.Bitcode, &centroids[si]))
				}
			}
		}
	}

	centroids := make([][8]uint64, len(survivors))
	radii := make([]int, len(survivors))
	for si, c := range survivors {
		for b := range 512 {
			w, s := b/64, uint(b%64)
			twice := 2 * c.ones[b]
			if twice > c.hits || (twice == c.hits && c.leader[w]>>s&1 == 1) {
				centroids[si][w] |= 1 << s
			}
		}
	}
	memberRadii(centroids, radii, nil)
	if slices.ContainsFunc(radii, func(r int) bool { return r > radius }) {
		// Seuls les groupes dont le vote déborde retombent sur leur meneur.
		over := make([]bool, len(survivors))
		for si := range survivors {
			if radii[si] > radius {
				over[si], centroids[si], radii[si] = true, survivors[si].leader, 0
			}
		}
		memberRadii(centroids, radii, over)
	}

	kept := make([]*condenseCluster, 0, len(survivors))
	for _, c := range survivors {
		if c.hits < minHits {
			st.DroppedClusters++
			st.DroppedHits += uint64(c.hits)
			continue
		}
		kept = append(kept, c)
	}
	if len(kept) > maxProtos {
		slices.SortStableFunc(kept, func(a, b *condenseCluster) int { return cmp.Compare(b.hits, a.hits) })
		for _, c := range kept[maxProtos:] {
			st.DroppedClusters++
			st.DroppedHits += uint64(c.hits)
		}
		kept = kept[:maxProtos]
		slices.SortFunc(kept, func(a, b *condenseCluster) int { return cmp.Compare(a.order, b.order) })
	}

	protos := make([]PyramidPrototype, len(kept))
	for i, c := range kept {
		si := slot[c.order]
		protos[i] = PyramidPrototype{
			Bitcode:         centroids[si],
			Radius:          uint16(radii[si]),
			Subsystem:       c.sub,
			AverageScore:    uint16(c.sumScore / uint64(c.hits)),
			MinScore:        c.minScore,
			HitCount:        c.hits,
			TemporalPattern: c.pattern,
		}
	}
	return protos, st
}

// condenseBudget rend le plafond effectif des groupes vivants.
func condenseBudget(n int) int {
	if n <= 0 {
		return CondenseDefaultIntermediateClusters
	}
	return min(n, CondenseMaxIntermediateClusters)
}

// condenseEvict évince au moins n groupes vivants (au moins un), les moins
// fournis d'abord et, à égalité, les plus anciens, puis retire leurs meneurs
// des seaux sans changer l'ordre des autres. Rend le nombre de groupes évincés.
func condenseEvict(clusters []*condenseCluster, buckets map[condenseKey][]int, n int, st *CondenseStats) int {
	victims := make([]*condenseCluster, 0, len(clusters))
	for _, c := range clusters {
		if c != nil {
			victims = append(victims, c)
		}
	}
	slices.SortFunc(victims, func(a, b *condenseCluster) int {
		return cmp.Or(cmp.Compare(a.hits, b.hits), cmp.Compare(a.order, b.order))
	})
	n = min(max(n, 1), len(victims))
	for _, c := range victims[:n] {
		clusters[c.order] = nil
		st.EvictedClusters++
		st.EvictedHits += uint64(c.hits)
	}
	for k, idx := range buckets {
		idx = slices.DeleteFunc(idx, func(ci int) bool { return clusters[ci] == nil })
		if len(idx) == 0 {
			delete(buckets, k)
		} else {
			buckets[k] = idx
		}
	}
	return n
}

// CondensePyramidHierarchy produit une pyramide par échelle de cfg.Scales
// (CondenseHierarchyDefaultScales si nul), par horizons croissants ancrés sur
// le dernier jour fourni : l'échelle de h jours condense, par
// CondensePrototypes et sous le même plafond de groupes, les tranches des h
// derniers jours calendaires. Les horizons étant emboîtés, deux échelles dont
// l'horizon couvre les mêmes tranches partagent la même condensation. Chaque
// niveau se condense depuis les entrées de son horizon, jamais depuis les
// prototypes du niveau inférieur : le rayon d'un prototype de prototypes ne
// borne plus ses membres. EpochStart et EpochEnd de chaque pyramide sont les
// jours effectivement vus, si bien qu'une pyramide de 365 jours nourrie de dix
// jours le montre dans son en-tête. Les échelles de 4 h et 12 h sont refusées :
// une tranche journalière ne dit pas à quel instant ancrer un horizon plus
// court qu'une journée.
func CondensePyramidHierarchy(days []CondenseDay, cfg CondenseConfig, machineID uint64) (map[uint16]*Pyramid, error) {
	pyr, _, err := CondensePyramidHierarchyStats(days, cfg, machineID)
	return pyr, err
}

// CondensePyramidHierarchyStats fait comme CondensePyramidHierarchy et rend en
// plus les statistiques de condensation de chaque échelle.
func CondensePyramidHierarchyStats(days []CondenseDay, cfg CondenseConfig, machineID uint64) (map[uint16]*Pyramid, map[uint16]CondenseStats, error) {
	scales := cfg.Scales
	if scales == 0 {
		scales = CondenseHierarchyDefaultScales
	}
	if scales&^DeltaScaleAll != 0 {
		return nil, nil, fmt.Errorf("%w: 0x%04x", ErrPyramidScale, scales)
	}
	for idx := range DeltaScaleCount {
		if scales&(1<<idx) != 0 && pyramidScaleDays[idx] == 0 {
			return nil, nil, fmt.Errorf("%w: echelle 0x%04x plus courte qu'une tranche journaliere", ErrPyramidScale, uint16(1)<<idx)
		}
	}
	if len(days) == 0 {
		return nil, nil, ErrCondenseNoDays
	}
	sorted := slices.Clone(days)
	slices.SortStableFunc(sorted, func(a, b CondenseDay) int { return cmp.Compare(a.EpochDay, b.EpochDay) })
	end := sorted[len(sorted)-1].EpochDay

	pyr := make(map[uint16]*Pyramid)
	stats := make(map[uint16]CondenseStats)
	prevFrom := -1
	var prevProtos []PyramidPrototype
	var prevStats CondenseStats
	for idx := range DeltaScaleCount {
		scale := uint16(1) << idx
		if scales&scale == 0 {
			continue
		}
		var first uint32
		if h := pyramidScaleDays[idx]; end >= h-1 {
			first = end - (h - 1)
		}
		from, _ := slices.BinarySearchFunc(sorted, first, func(d CondenseDay, day uint32) int { return cmp.Compare(d.EpochDay, day) })
		if from != prevFrom {
			prevProtos, prevStats = CondensePrototypes(sorted[from:], cfg)
			prevFrom = from
		}
		p, err := NewPyramid(machineID, scale, prevStats.EpochStart, prevStats.EpochEnd, prevProtos)
		if err != nil {
			return nil, nil, fmt.Errorf("echelle 0x%04x: %w", scale, err)
		}
		pyr[scale], stats[scale] = p, prevStats
	}
	return pyr, stats, nil
}

// condenseAdmit dit si une entrée peut servir de référence et rend le niveau de
// sévérité de son bitcode : sont écartées les entrées High/Critical (champ
// Severity ou bitcode), dégradées, hors échelle de score, marquées anomalie ou
// dégradation, et celles dont le champ de sévérité n'est pas un thermomètre.
func condenseAdmit(e *OracleVectorEntry) (uint16, bool) {
	level, ok := deltaSeverityLevel(e.Bitcode[2])
	if !ok || level >= SeverityHigh || e.Severity >= SeverityHigh ||
		e.HealthScore < DegradedHealthScore || e.HealthScore > localityScoreMax ||
		e.Flags&(OracleFlagAnomalies|OracleFlagDegraded) != 0 {
		return 0, false
	}
	return level, true
}
