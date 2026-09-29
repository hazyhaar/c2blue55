// Package engine — delta_catalog.go
// Méta-catalogue scellé des disparités autorisées (.c2delta) : chaque règle
// dispense, dans une fenêtre de temps bornée, les états observés voisins d'un
// motif 512 bits de la géométrie VectorizeServerHealthLocality. Le chargement
// refuse toute règle qui blanchirait une aggravation (règle éternelle, masque
// vide, rayon couvrant tout le masque, sévérité non verrouillée).
package engine

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/bits"
	"unsafe"
)

const (
	// DeltaHeaderSize est la taille exacte de l'en-tête d'un fichier .c2delta.
	DeltaHeaderSize = 64
	// DeltaRuleSize est la taille exacte d'une règle de dispense.
	DeltaRuleSize = 192
	// DeltaVersion est la version de schéma du catalogue.
	DeltaVersion uint16 = 1
	// DeltaDim est la dimension des motifs (512 bits, géométrie de l'oracle v3).
	DeltaDim uint16 = 512
	// DeltaMaxRuleCount borne le nombre de règles d'un catalogue.
	DeltaMaxRuleCount = 1 << 16
	// deltaLoadInitialCap borne la préallocation au chargement.
	deltaLoadInitialCap = 256
	// DeltaSlotsPerDay est le nombre de créneaux horaires (22,5 min), aligné sur le mot 5 de l'oracle.
	DeltaSlotsPerDay = localitySlotsPerDay
)

// DeltaMagic identifie un catalogue de disparités autorisées.
var DeltaMagic = [8]byte{'C', '2', 'D', 'E', 'L', 'T', 'A', '1'}

// Échelles d'agrégation auxquelles une règle s'applique (DeltaRule.ScaleMask).
// Ce sont aussi les niveaux de la pyramide temporelle (.c2pyramid) : un bit
// par horizon glissant, du plus court au plus long.
const (
	DeltaScale4h   uint16 = 1 << 0
	DeltaScale12h  uint16 = 1 << 1
	DeltaScale24h  uint16 = 1 << 2
	DeltaScale7d   uint16 = 1 << 3
	DeltaScale30d  uint16 = 1 << 4
	DeltaScale120d uint16 = 1 << 5
	DeltaScale365d uint16 = 1 << 6
	// DeltaScaleAll réunit toutes les échelles connues ; un bit au-delà est refusé.
	DeltaScaleAll uint16 = (1 << 7) - 1
	// DeltaScaleCount est le nombre d'échelles connues.
	DeltaScaleCount = 7
)

// DeltaCriticalMaxRadius plafonne le rayon d'une règle qui vise Critical : la
// sévérité ne peut plus s'aggraver, mais un rayon plus large dispenserait des
// états étrangers au motif (autre score, autre entité, autre charge).
const DeltaCriticalMaxRadius = 8

// DeltaAllDays couvre les sept jours de la semaine (bit 0 = dimanche).
const DeltaAllDays uint8 = 0x7F

// Erreurs contractuelles des fichiers .c2delta.
var (
	ErrDeltaMagic    = errors.New("c2delta: signature magique invalide")
	ErrDeltaVersion  = errors.New("c2delta: version de catalogue non supportee")
	ErrDeltaDim      = errors.New("c2delta: dimension non conforme (512 attendu)")
	ErrDeltaCorrupt  = errors.New("c2delta: fichier tronque ou incomplet")
	ErrDeltaSeal     = errors.New("c2delta: empreinte SHA-256 ou HMAC-SHA256 invalide")
	ErrDeltaTooLarge = errors.New("c2delta: nombre de regles superieur a DeltaMaxRuleCount")
	ErrDeltaMachine  = errors.New("c2delta: catalogue d'une autre machine")
	// ErrDeltaEternal refuse une règle sans expiration ou à fenêtre vide.
	ErrDeltaEternal = errors.New("c2delta: regle sans expiration (NotAfterSec nul ou <= NotBeforeSec)")
	// ErrDeltaSeverity refuse une règle qui laisserait une sévérité basse atteindre High.
	ErrDeltaSeverity = errors.New("c2delta: garde de severite violee")
	// ErrDeltaRule refuse une règle mal formée (masque, rayon, calendrier, identité).
	ErrDeltaRule = errors.New("c2delta: regle invalide")
)

// SealKeyMinLen est la longueur minimale d'une clé d'authentification des
// fichiers .c2delta et .c2pyramid. Une clé vide garde le sceau SHA-256 simple ;
// une clé non vide plus courte est refusée, car elle donnerait l'apparence
// d'une authentification sans en offrir la résistance.
const SealKeyMinLen = 16

// ErrSealKey refuse une clé d'authentification non vide trop courte.
var ErrSealKey = fmt.Errorf("c2seal: cle HMAC de moins de %d octets", SealKeyMinLen)

// checkSealKey admet une clé vide (sceau SHA-256) ou d'au moins SealKeyMinLen octets.
func checkSealKey(key []byte) error {
	if len(key) != 0 && len(key) < SealKeyMinLen {
		return ErrSealKey
	}
	return nil
}

// newSealHash rend SHA-256 pour une clé vide, HMAC-SHA256 sinon.
func newSealHash(key []byte) hash.Hash {
	if len(key) == 0 {
		return sha256.New()
	}
	return hmac.New(sha256.New, key)
}

// DeltaHeader structure l'en-tête de 64 octets.
type DeltaHeader struct {
	Magic     [8]byte  // 'C2DELTA1' (0..8)
	Version   uint16   // DeltaVersion (8..10)
	Dimension uint16   // DeltaDim (10..12)
	RuleCount uint32   // Nombre de règles (12..16)
	MachineID uint64   // Machine à laquelle le catalogue s'applique (16..24)
	Seal      [32]byte // SHA-256 de l'en-tête (Seal à zéro) et des règles (24..56)
	Reserved  [8]byte  // Alignement sur 64 octets (56..64)
}

// DeltaRule structure une règle de dispense de 192 octets. L'ordre des champs
// suit leur alignement naturel, si bien que la structure Go et l'encodage
// disque ont la même taille sans remplissage implicite.
type DeltaRule struct {
	Pattern        [8]uint64 // Motif 512 bits (0..64)
	Mask           [8]uint64 // Bits significatifs du motif (64..128)
	NotBeforeSec   uint64    // Début de validité, secondes Unix incluses (128..136)
	NotAfterSec    uint64    // Fin de validité, secondes Unix incluses (136..144)
	RuleID         uint32    // Identifiant non nul, unique dans le catalogue (144..148)
	MaxRadius      uint16    // Distance de Hamming admise sur les bits masqués (148..150)
	ScaleMask      uint16    // Échelles applicables (DeltaScale*) (150..152)
	DaysOfWeekMask uint8     // Bits 0..6 = dimanche..samedi, UTC (152)
	TimeSlotMin    uint8     // Premier créneau admis, 0..63, UTC (153)
	TimeSlotMax    uint8     // Dernier créneau admis, 0..63, UTC (154)
	Label          [32]byte  // Nom descriptif, complété par des octets nuls (155..187)
	Reserved       [5]byte   // Alignement sur 192 octets (187..192)
}

var (
	_ = [1]struct{}{}[unsafe.Sizeof(DeltaHeader{})-DeltaHeaderSize]
	_ = [1]struct{}{}[unsafe.Sizeof(DeltaRule{})-DeltaRuleSize]
)

// EncodeDeltaHeader écrit l'en-tête en little-endian.
func EncodeDeltaHeader(dst *[DeltaHeaderSize]byte, h *DeltaHeader) {
	copy(dst[0:8], h.Magic[:])
	binary.LittleEndian.PutUint16(dst[8:10], h.Version)
	binary.LittleEndian.PutUint16(dst[10:12], h.Dimension)
	binary.LittleEndian.PutUint32(dst[12:16], h.RuleCount)
	binary.LittleEndian.PutUint64(dst[16:24], h.MachineID)
	copy(dst[24:56], h.Seal[:])
	copy(dst[56:64], h.Reserved[:])
}

// DecodeDeltaHeader lit l'en-tête little-endian.
func DecodeDeltaHeader(src *[DeltaHeaderSize]byte, h *DeltaHeader) {
	copy(h.Magic[:], src[0:8])
	h.Version = binary.LittleEndian.Uint16(src[8:10])
	h.Dimension = binary.LittleEndian.Uint16(src[10:12])
	h.RuleCount = binary.LittleEndian.Uint32(src[12:16])
	h.MachineID = binary.LittleEndian.Uint64(src[16:24])
	copy(h.Seal[:], src[24:56])
	copy(h.Reserved[:], src[56:64])
}

// EncodeDeltaRule écrit une règle en little-endian.
func EncodeDeltaRule(dst *[DeltaRuleSize]byte, r *DeltaRule) {
	for i := range 8 {
		binary.LittleEndian.PutUint64(dst[i*8:], r.Pattern[i])
		binary.LittleEndian.PutUint64(dst[64+i*8:], r.Mask[i])
	}
	binary.LittleEndian.PutUint64(dst[128:136], r.NotBeforeSec)
	binary.LittleEndian.PutUint64(dst[136:144], r.NotAfterSec)
	binary.LittleEndian.PutUint32(dst[144:148], r.RuleID)
	binary.LittleEndian.PutUint16(dst[148:150], r.MaxRadius)
	binary.LittleEndian.PutUint16(dst[150:152], r.ScaleMask)
	dst[152] = r.DaysOfWeekMask
	dst[153] = r.TimeSlotMin
	dst[154] = r.TimeSlotMax
	copy(dst[155:187], r.Label[:])
	copy(dst[187:192], r.Reserved[:])
}

// DecodeDeltaRule lit une règle little-endian.
func DecodeDeltaRule(src *[DeltaRuleSize]byte, r *DeltaRule) {
	for i := range 8 {
		r.Pattern[i] = binary.LittleEndian.Uint64(src[i*8:])
		r.Mask[i] = binary.LittleEndian.Uint64(src[64+i*8:])
	}
	r.NotBeforeSec = binary.LittleEndian.Uint64(src[128:136])
	r.NotAfterSec = binary.LittleEndian.Uint64(src[136:144])
	r.RuleID = binary.LittleEndian.Uint32(src[144:148])
	r.MaxRadius = binary.LittleEndian.Uint16(src[148:150])
	r.ScaleMask = binary.LittleEndian.Uint16(src[150:152])
	r.DaysOfWeekMask = src[152]
	r.TimeSlotMin = src[153]
	r.TimeSlotMax = src[154]
	copy(r.Label[:], src[155:187])
	copy(r.Reserved[:], src[187:192])
}

// ComputeDeltaSeal calcule le SHA-256 de l'en-tête encodé, Seal remis à zéro,
// suivi des règles encodées dans l'ordre.
func ComputeDeltaSeal(hdr *DeltaHeader, rules []DeltaRule) [32]byte {
	return ComputeDeltaSealHMAC(hdr, rules, nil)
}

// ComputeDeltaSealHMAC calcule le sceau sur les mêmes octets que
// ComputeDeltaSeal, par HMAC-SHA256 sous la clé key. Une clé vide rend le
// SHA-256 simple : ce sceau ne détecte qu'une corruption, alors que le sceau
// HMAC interdit à qui ignore la clé de forger ou d'altérer un catalogue.
func ComputeDeltaSealHMAC(hdr *DeltaHeader, rules []DeltaRule, key []byte) [32]byte {
	h := newSealHash(key)
	unsealed := *hdr
	unsealed.Seal = [32]byte{}
	var hb [DeltaHeaderSize]byte
	EncodeDeltaHeader(&hb, &unsealed)
	h.Write(hb[:])
	var rb [DeltaRuleSize]byte
	for i := range rules {
		EncodeDeltaRule(&rb, &rules[i])
		h.Write(rb[:])
	}
	var seal [32]byte
	copy(seal[:], h.Sum(nil))
	return seal
}

// DeltaMatchField désigne un champ de la géométrie VectorizeServerHealthLocality
// qu'une règle fixe dans son masque.
type DeltaMatchField uint16

// Champs qu'une règle peut fixer ; la sévérité l'est toujours.
const (
	DeltaMatchSubsystem  DeltaMatchField = 1 << iota // mot 0
	DeltaMatchAction                                 // mot 1
	DeltaMatchCorrelated                             // mot 2, 32 bits hauts
	DeltaMatchScore                                  // mot 3
	DeltaMatchEntropy                                // mot 4
	DeltaMatchSlot                                   // mot 5
	DeltaMatchEntity                                 // mot 6
	DeltaMatchPayload                                // mot 7
	// DeltaMatchAll réunit tous les champs.
	DeltaMatchAll DeltaMatchField = 1<<8 - 1
)

// DeltaPatternFromSnapshot rend le motif d'une règle, soit le bitcode
// VectorizeServerHealthLocality de s, et son masque : les mots des champs
// demandés, plus le champ de sévérité, que ValidateDeltaRule exige toujours.
func DeltaPatternFromSnapshot(s *ServerHealthSnapshot, fields DeltaMatchField) (pattern, mask [8]uint64) {
	VectorizeServerHealthLocality(s, &pattern)
	mask[2] = localitySeverityMask
	words := [8]DeltaMatchField{DeltaMatchSubsystem, DeltaMatchAction, 0, DeltaMatchScore, DeltaMatchEntropy, DeltaMatchSlot, DeltaMatchEntity, DeltaMatchPayload}
	for w, f := range words {
		if f != 0 && fields&f != 0 {
			mask[w] = ^uint64(0)
		}
	}
	if fields&DeltaMatchCorrelated != 0 {
		mask[2] |= ^uint64(localitySeverityMask)
	}
	return pattern, mask
}

// deltaSeverityLevel rend le niveau de sévérité codé en thermomètre dans les
// 32 bits bas d'un mot 2, et faux si ces bits ne forment pas un thermomètre
// entier (8 bits par niveau, de 0 à SeverityCritical).
func deltaSeverityLevel(word2 uint64) (uint16, bool) {
	field := word2 & localitySeverityMask
	n := bits.OnesCount64(field)
	if n%8 != 0 || field != thermo64(uint(n)) {
		return 0, false
	}
	return uint16(n / 8), true
}

// deltaSeverityCeil rend le niveau de sévérité d'un mot 2 par son bit de
// sévérité le plus haut, arrondi au niveau supérieur. Pour un thermomètre
// entier, c'est le niveau exact ; pour un champ troué ou forgé, c'est le plus
// haut niveau que le champ atteint, si bien qu'un état malformé n'est jamais
// jugé moins grave qu'il n'y paraît.
func deltaSeverityCeil(word2 uint64) int {
	return (bits.Len64(word2&localitySeverityMask) + 7) / 8
}

// ValidateDeltaRule applique les gardes anti-blanchiment à une règle :
//   - fenêtre temporelle bornée : NotAfterSec non nul et strictement postérieur à NotBeforeSec ;
//   - RuleID non nul, libellé non vide, échelles et jours non vides, jours dans 0x7F ;
//   - créneaux 0 <= TimeSlotMin <= TimeSlotMax <= 63 ;
//   - masque non vide et rayon strictement inférieur au nombre de bits masqués,
//     sans quoi la règle dispenserait tout état ;
//   - champ de sévérité (32 bits bas du mot 2) entièrement masqué et codé en
//     thermomètre entier : une règle qui ne fixe pas la sévérité dispenserait
//     aussi High et Critical ;
//   - échelles non vides et comprises dans DeltaScaleAll (finding F_DS_10) ;
//   - si la sévérité visée est inférieure à Critical, MaxRadius < 8 : monter
//     d'un niveau coûte 8 bits sur ce champ, la règle ne peut donc jamais
//     absorber une aggravation, de Medium vers High comme de High vers
//     Critical (findings F8 et F_DS_01) ;
//   - si la sévérité visée vaut Critical, MaxRadius <= DeltaCriticalMaxRadius.
func ValidateDeltaRule(r *DeltaRule) error {
	if r.NotAfterSec == 0 || r.NotAfterSec <= r.NotBeforeSec {
		return fmt.Errorf("%w: regle %d", ErrDeltaEternal, r.RuleID)
	}
	if r.RuleID == 0 {
		return fmt.Errorf("%w: RuleID nul", ErrDeltaRule)
	}
	if r.Label[0] == 0 {
		return fmt.Errorf("%w: regle %d sans libelle", ErrDeltaRule, r.RuleID)
	}
	if r.ScaleMask == 0 || r.ScaleMask&^DeltaScaleAll != 0 {
		return fmt.Errorf("%w: regle %d, echelles 0x%04x", ErrDeltaRule, r.RuleID, r.ScaleMask)
	}
	if r.DaysOfWeekMask == 0 || r.DaysOfWeekMask&^DeltaAllDays != 0 {
		return fmt.Errorf("%w: regle %d, jours 0x%02x", ErrDeltaRule, r.RuleID, r.DaysOfWeekMask)
	}
	if r.TimeSlotMin > r.TimeSlotMax || r.TimeSlotMax >= DeltaSlotsPerDay {
		return fmt.Errorf("%w: regle %d, creneaux %d..%d", ErrDeltaRule, r.RuleID, r.TimeSlotMin, r.TimeSlotMax)
	}
	masked := 0
	for i := range 8 {
		masked += bits.OnesCount64(r.Mask[i])
	}
	if masked == 0 || int(r.MaxRadius) >= masked {
		return fmt.Errorf("%w: regle %d, rayon %d pour %d bits masques", ErrDeltaRule, r.RuleID, r.MaxRadius, masked)
	}
	if r.Mask[2]&localitySeverityMask != localitySeverityMask {
		return fmt.Errorf("%w: regle %d, champ de severite non entierement masque", ErrDeltaSeverity, r.RuleID)
	}
	level, ok := deltaSeverityLevel(r.Pattern[2])
	if !ok {
		return fmt.Errorf("%w: regle %d, motif de severite hors thermometre", ErrDeltaSeverity, r.RuleID)
	}
	if level < SeverityCritical && r.MaxRadius >= 8 {
		return fmt.Errorf("%w: regle %d, rayon %d >= 8 sur une severite < Critical", ErrDeltaSeverity, r.RuleID, r.MaxRadius)
	}
	if level == SeverityCritical && r.MaxRadius > DeltaCriticalMaxRadius {
		return fmt.Errorf("%w: regle %d, rayon %d > %d sur Critical", ErrDeltaSeverity, r.RuleID, r.MaxRadius, DeltaCriticalMaxRadius)
	}
	return nil
}

// validateDeltaRules valide chaque règle et l'unicité des RuleID.
func validateDeltaRules(rules []DeltaRule) error {
	seen := make(map[uint32]struct{}, len(rules))
	for i := range rules {
		if err := ValidateDeltaRule(&rules[i]); err != nil {
			return err
		}
		if _, dup := seen[rules[i].RuleID]; dup {
			return fmt.Errorf("%w: RuleID %d en double", ErrDeltaRule, rules[i].RuleID)
		}
		seen[rules[i].RuleID] = struct{}{}
	}
	return nil
}

// SaveDeltaCatalog valide puis écrit un catalogue scellé pour machineID.
func SaveDeltaCatalog(w io.Writer, machineID uint64, rules []DeltaRule) error {
	return SaveDeltaCatalogHMAC(w, machineID, rules, nil)
}

// SaveDeltaCatalogHMAC valide puis écrit un catalogue dont le sceau est un
// HMAC-SHA256 sous key ; une clé vide écrit le sceau SHA-256 de SaveDeltaCatalog.
func SaveDeltaCatalogHMAC(w io.Writer, machineID uint64, rules []DeltaRule, key []byte) error {
	if err := checkSealKey(key); err != nil {
		return err
	}
	if len(rules) > DeltaMaxRuleCount {
		return ErrDeltaTooLarge
	}
	if err := validateDeltaRules(rules); err != nil {
		return err
	}
	hdr := DeltaHeader{
		Magic:     DeltaMagic,
		Version:   DeltaVersion,
		Dimension: DeltaDim,
		RuleCount: uint32(len(rules)),
		MachineID: machineID,
	}
	hdr.Seal = ComputeDeltaSealHMAC(&hdr, rules, key)

	bw := bufio.NewWriterSize(w, 1<<16)
	var hb [DeltaHeaderSize]byte
	EncodeDeltaHeader(&hb, &hdr)
	if _, err := bw.Write(hb[:]); err != nil {
		return err
	}
	var rb [DeltaRuleSize]byte
	for i := range rules {
		EncodeDeltaRule(&rb, &rules[i])
		if _, err := bw.Write(rb[:]); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// DeltaCatalog est un catalogue chargé et validé ; immuable, il se lit sans
// verrou depuis plusieurs goroutines.
type DeltaCatalog struct {
	machineID uint64
	rules     []DeltaRule
}

// LoadDeltaCatalog lit un catalogue, vérifie sa signature, son sceau et sa
// machine, puis refuse le catalogue entier si une seule règle viole une garde.
func LoadDeltaCatalog(r io.Reader, machineID uint64) (*DeltaCatalog, error) {
	return LoadDeltaCatalogHMAC(r, machineID, nil)
}

// LoadDeltaCatalogHMAC charge comme LoadDeltaCatalog, mais exige un sceau
// HMAC-SHA256 sous key. Sous une clé non vide, un catalogue scellé en SHA-256
// simple ou sous une autre clé est refusé par ErrDeltaSeal : l'hôte qui
// configure une clé n'accepte que des catalogues authentifiés. La comparaison
// du sceau se fait en temps constant.
func LoadDeltaCatalogHMAC(r io.Reader, machineID uint64, key []byte) (*DeltaCatalog, error) {
	if err := checkSealKey(key); err != nil {
		return nil, err
	}
	br := bufio.NewReaderSize(r, 1<<16)
	var hb [DeltaHeaderSize]byte
	if _, err := io.ReadFull(br, hb[:]); err != nil {
		return nil, ErrDeltaCorrupt
	}
	var hdr DeltaHeader
	DecodeDeltaHeader(&hb, &hdr)
	if hdr.Magic != DeltaMagic {
		return nil, ErrDeltaMagic
	}
	if hdr.Version != DeltaVersion {
		return nil, ErrDeltaVersion
	}
	if hdr.Dimension != DeltaDim {
		return nil, ErrDeltaDim
	}
	if hdr.RuleCount > DeltaMaxRuleCount {
		return nil, ErrDeltaTooLarge
	}
	rules := make([]DeltaRule, 0, min(hdr.RuleCount, deltaLoadInitialCap))
	var rb [DeltaRuleSize]byte
	for i := uint32(0); i < hdr.RuleCount; i++ {
		if _, err := io.ReadFull(br, rb[:]); err != nil {
			return nil, ErrDeltaCorrupt
		}
		var rule DeltaRule
		DecodeDeltaRule(&rb, &rule)
		rules = append(rules, rule)
	}
	if seal := ComputeDeltaSealHMAC(&hdr, rules, key); !hmac.Equal(seal[:], hdr.Seal[:]) {
		return nil, ErrDeltaSeal
	}
	if hdr.MachineID != machineID {
		return nil, ErrDeltaMachine
	}
	if err := validateDeltaRules(rules); err != nil {
		return nil, err
	}
	return &DeltaCatalog{machineID: machineID, rules: rules}, nil
}

// Len rend le nombre de règles du catalogue.
func (c *DeltaCatalog) Len() int {
	if c == nil {
		return 0
	}
	return len(c.rules)
}

// EvaluateDelta cherche, dans l'ordre du catalogue, la première règle qui
// dispense l'état observé à l'instant tsSec pour l'échelle scale : tsSec dans
// [NotBeforeSec, NotAfterSec], jour de la semaine et créneau UTC admis, échelle
// couverte, sévérité observée au plus égale à celle du motif, et
// popcount((observed XOR Pattern) AND Mask) <= MaxRadius.
// La garde de sévérité double celle de ValidateDeltaRule au moment de
// l'évaluation : aucune règle, même admise par erreur, ne dispense un état plus
// grave que son motif (finding F_DS_01).
// scale désigne une seule échelle : une échelle composée de plusieurs bits est
// refusée (finding N4), faute de quoi une règle d'une seule de ces échelles
// dispenserait l'état pour toutes les autres.
// 0 allocation tas (0 B/op).
func (c *DeltaCatalog) EvaluateDelta(observed *[8]uint64, tsSec uint64, scale uint16) (matched bool, ruleID uint32) {
	if c == nil || observed == nil || bits.OnesCount16(scale) != 1 {
		return false, 0
	}
	// Le 1er janvier 1970 était un jeudi (4, dimanche = 0).
	dow := uint8((tsSec/86400 + 4) % 7)
	slot := uint8(tsSec % 86400 * DeltaSlotsPerDay / 86400)
	obsLevel := deltaSeverityCeil(observed[2])
	for i := range c.rules {
		r := &c.rules[i]
		if tsSec < r.NotBeforeSec || tsSec > r.NotAfterSec ||
			r.ScaleMask&scale == 0 ||
			r.DaysOfWeekMask&(1<<dow) == 0 ||
			slot < r.TimeSlotMin || slot > r.TimeSlotMax ||
			obsLevel > deltaSeverityCeil(r.Pattern[2]) {
			continue
		}
		d := bits.OnesCount64((observed[0]^r.Pattern[0])&r.Mask[0]) +
			bits.OnesCount64((observed[1]^r.Pattern[1])&r.Mask[1]) +
			bits.OnesCount64((observed[2]^r.Pattern[2])&r.Mask[2]) +
			bits.OnesCount64((observed[3]^r.Pattern[3])&r.Mask[3]) +
			bits.OnesCount64((observed[4]^r.Pattern[4])&r.Mask[4]) +
			bits.OnesCount64((observed[5]^r.Pattern[5])&r.Mask[5]) +
			bits.OnesCount64((observed[6]^r.Pattern[6])&r.Mask[6]) +
			bits.OnesCount64((observed[7]^r.Pattern[7])&r.Mask[7])
		if d <= int(r.MaxRadius) {
			return true, r.RuleID
		}
	}
	return false, 0
}
