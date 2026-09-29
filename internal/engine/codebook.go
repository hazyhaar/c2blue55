// Codebook RaBitQ 512D (.c2book) : format binaire contigu et moteur de recherche
// par distance de Hamming. Le fichier porte un en-tête de 32 octets suivi
// d'entrées de 72 octets strictement contiguës, sans indirection ni champ
// variable. Le noyau de recherche s'appuie sur le popcount de math/bits, sans
// table ni allocation sur le chemin chaud.
package engine

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"os"
	"sync/atomic"
	"unsafe"
)

const (
	// codebookEntrySize est la taille sérialisée d'une entrée : huit mots de
	// 64 bits (64 octets), l'identifiant de menace (4), le sous-système (2) et
	// la sévérité (2).
	codebookEntrySize = 72
	// codebookHeaderSize est la taille de l'en-tête : magie (8), version (2),
	// dimension (2), nombre d'entrées (4) et réserve (16).
	codebookHeaderSize = 32
	// codebookVersion est la révision de format portée par le fichier.
	codebookVersion uint16 = 1
	// codebookVectorDim est la dimension RaBitQ traitée par ce codebook.
	codebookVectorDim uint16 = 512
	// codebookWords est le nombre de mots de 64 bits d'un bitcode de 512 bits.
	codebookWords = 512 / 64
	// codebookBits est le nombre total de bits d'un bitcode, borne maximale de
	// la distance de Hamming.
	codebookBits = codebookWords * 64
	// codebookMaxEntries borne l'allocation au chargement d'un fichier hostile.
	codebookMaxEntries = 1 << 24
)

// Sévérités normalisées d'une entrée de codebook.
const (
	SeverityLow      uint16 = 1
	SeverityMedium   uint16 = 2
	SeverityHigh     uint16 = 3
	SeverityCritical uint16 = 4
)

// codebookMagic identifie un fichier .c2book de première génération.
var codebookMagic = [8]byte{'C', '2', 'B', 'O', 'O', 'K', '1', 0}

// Erreurs de validation du format .c2book.
var (
	ErrCodebookMagic   = errors.New("c2book: magie invalide")
	ErrCodebookVersion = errors.New("c2book: version non supportée")
	ErrCodebookDim     = errors.New("c2book: dimension non supportée")
	ErrCodebookCorrupt = errors.New("c2book: fichier tronqué")
	ErrCodebookHuge    = errors.New("c2book: nombre d'entrées hors bornes")
)

// CodebookHeader décrit l'en-tête binaire de 32 octets. Les champs sont
// ordonnés et alignés pour que la structure occupe exactement la taille
// déclarée, sans remplissage implicite.
type CodebookHeader struct {
	Magic      [8]byte
	Version    uint16
	VectorDim  uint16
	EntryCount uint32
	Reserved   [16]byte
}

// CodebookEntry porte un vecteur RaBitQ 1-bit de 512 dimensions et ses
// métadonnées de menace. La structure est comparable et occupe 72 octets.
type CodebookEntry struct {
	Bitcode   [codebookWords]uint64
	ThreatID  uint32
	Subsystem uint16
	Severity  uint16
}

// CodebookMatch apparie une entrée retenue par la recherche à sa distance de
// Hamming envers la requête.
type CodebookMatch struct {
	Entry    CodebookEntry
	Distance int
}

// Codebook détient les entrées dans une tranche contiguë unique. Aucune
// structure par entrée n'est allouée séparément.
type Codebook struct {
	entries []CodebookEntry
}

// Assertions de compilation : les structures doivent coïncider au bit près avec
// le format imposé. L'indexation constante échoue à la compilation dans les deux
// sens d'un écart de taille.
var (
	_ = [1]struct{}{}[unsafe.Sizeof(CodebookEntry{})-codebookEntrySize]
	_ = [1]struct{}{}[unsafe.Sizeof(CodebookHeader{})-codebookHeaderSize]
)

// NewCodebook construit un codebook propriétaire des entrées fournies.
func NewCodebook(entries []CodebookEntry) *Codebook {
	return &Codebook{entries: entries}
}

// Len rend le nombre d'entrées détenues.
func (cb *Codebook) Len() int {
	if cb == nil {
		return 0
	}
	return len(cb.entries)
}

// Entries rend la tranche des entrées du codebook.
func (cb *Codebook) Entries() []CodebookEntry {
	if cb == nil {
		return nil
	}
	return cb.entries
}

// Save écrit le codebook dans un fichier .c2book.
func (cb *Codebook) Save(path string) error {
	if cb == nil {
		return errors.New("c2book: codebook nul")
	}
	return SaveCodebook(path, cb.entries)
}

// SaveCodebook écrit l'en-tête puis les entrées dans un fichier .c2book. La
// sérialisation est explicitement little-endian, ce qui garantit un
// aller-retour bit-exact indépendant de l'architecture.
func SaveCodebook(path string, entries []CodebookEntry) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	hdr := CodebookHeader{
		Magic:      codebookMagic,
		Version:    codebookVersion,
		VectorDim:  codebookVectorDim,
		EntryCount: uint32(len(entries)),
	}
	var hb [codebookHeaderSize]byte
	encodeCodebookHeader(&hb, &hdr)

	bw := bufio.NewWriterSize(f, 1<<16)
	if _, err := bw.Write(hb[:]); err != nil {
		return err
	}
	var eb [codebookEntrySize]byte
	for i := range entries {
		encodeCodebookEntry(&eb, &entries[i])
		if _, err := bw.Write(eb[:]); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// LoadCodebook lit un fichier .c2book en une tranche d'entrées contiguë. Une
// seule allocation de masse est consentie pour les entrées ; les lectures
// intermédiaires s'effectuent sur une pile d'octets fixe.
func LoadCodebook(path string) (*Codebook, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	br := bufio.NewReaderSize(f, 1<<16)
	var hb [codebookHeaderSize]byte
	if _, err := io.ReadFull(br, hb[:]); err != nil {
		return nil, ErrCodebookCorrupt
	}
	var hdr CodebookHeader
	decodeCodebookHeader(&hb, &hdr)

	if hdr.Magic != codebookMagic {
		return nil, ErrCodebookMagic
	}
	if hdr.Version != codebookVersion {
		return nil, fmt.Errorf("%w: %d", ErrCodebookVersion, hdr.Version)
	}
	if hdr.VectorDim != codebookVectorDim {
		return nil, fmt.Errorf("%w: %d", ErrCodebookDim, hdr.VectorDim)
	}
	if hdr.EntryCount > codebookMaxEntries {
		return nil, fmt.Errorf("%w: %d", ErrCodebookHuge, hdr.EntryCount)
	}

	entries := make([]CodebookEntry, hdr.EntryCount)
	var eb [codebookEntrySize]byte
	for i := range entries {
		if _, err := io.ReadFull(br, eb[:]); err != nil {
			return nil, ErrCodebookCorrupt
		}
		decodeCodebookEntry(&eb, &entries[i])
	}
	return &Codebook{entries: entries}, nil
}

// SearchNearest rend l'entrée la plus proche de la requête au sens de la
// distance de Hamming, pourvu qu'elle ne dépasse pas maxHamming. Le parcours
// s'interrompt par entrée dès que le seuil est franchi. Le chemin chaud
// n'alloue pas.
func (cb *Codebook) SearchNearest(query *[codebookWords]uint64, maxHamming int) (match CodebookEntry, dist int, found bool) {
	if cb == nil || query == nil {
		return CodebookEntry{}, 0, false
	}
	bounded := maxHamming < codebookBits
	best := maxHamming + 1
	for i := range cb.entries {
		e := &cb.entries[i]
		var d int
		if bounded {
			d = codebookHammingBounded(query, e, maxHamming)
		} else {
			d = codebookHamming(query, e)
		}
		if d <= maxHamming && d < best {
			best = d
			match = *e
			found = true
		}
	}
	if !found {
		return CodebookEntry{}, 0, false
	}
	return match, best, true
}

// SearchAll écrit dans outMatches toutes les entrées dont la distance de
// Hamming ne dépasse pas maxHamming, puis rend le nombre total de correspondances
// trouvées. Le tampon fourni par l'appelant borne l'écriture sans provoquer
// d'allocation : si sa capacité est insuffisante, le surplus est compté mais non
// recopié.
func (cb *Codebook) SearchAll(query *[codebookWords]uint64, maxHamming int, outMatches []CodebookMatch) int {
	if cb == nil || query == nil {
		return 0
	}
	bounded := maxHamming < codebookBits
	total := 0
	for i := range cb.entries {
		e := &cb.entries[i]
		var d int
		if bounded {
			d = codebookHammingBounded(query, e, maxHamming)
		} else {
			d = codebookHamming(query, e)
		}
		if d <= maxHamming {
			if total < len(outMatches) {
				outMatches[total] = CodebookMatch{Entry: *e, Distance: d}
			}
			total++
		}
	}
	return total
}

// codebookHamming rend la distance de Hamming exacte entre la requête et le
// bitcode, les huit comptages étant déroulés pour laisser le processeur
// enchaîner les popcounts sans dépendance de données.
func codebookHamming(query *[codebookWords]uint64, e *CodebookEntry) int {
	q, b := query, &e.Bitcode
	return bits.OnesCount64(q[0]^b[0]) + bits.OnesCount64(q[1]^b[1]) +
		bits.OnesCount64(q[2]^b[2]) + bits.OnesCount64(q[3]^b[3]) +
		bits.OnesCount64(q[4]^b[4]) + bits.OnesCount64(q[5]^b[5]) +
		bits.OnesCount64(q[6]^b[6]) + bits.OnesCount64(q[7]^b[7])
}

// codebookHammingBounded rend la distance de Hamming en s'interrompant dès que
// le seuil est franchi. La valeur rendue peut alors être partielle, ce qui suffit
// au rejet de l'entrée par l'appelant.
func codebookHammingBounded(query *[codebookWords]uint64, e *CodebookEntry, maxHamming int) int {
	q, b := query, &e.Bitcode
	d := bits.OnesCount64(q[0] ^ b[0])
	if d > maxHamming {
		return d
	}
	d += bits.OnesCount64(q[1] ^ b[1])
	if d > maxHamming {
		return d
	}
	d += bits.OnesCount64(q[2] ^ b[2])
	if d > maxHamming {
		return d
	}
	d += bits.OnesCount64(q[3] ^ b[3])
	if d > maxHamming {
		return d
	}
	d += bits.OnesCount64(q[4] ^ b[4])
	if d > maxHamming {
		return d
	}
	d += bits.OnesCount64(q[5] ^ b[5])
	if d > maxHamming {
		return d
	}
	d += bits.OnesCount64(q[6] ^ b[6])
	if d > maxHamming {
		return d
	}
	d += bits.OnesCount64(q[7] ^ b[7])
	return d
}

// encodeCodebookHeader sérialise l'en-tête en little-endian.
func encodeCodebookHeader(dst *[codebookHeaderSize]byte, hdr *CodebookHeader) {
	copy(dst[0:8], hdr.Magic[:])
	binary.LittleEndian.PutUint16(dst[8:10], hdr.Version)
	binary.LittleEndian.PutUint16(dst[10:12], hdr.VectorDim)
	binary.LittleEndian.PutUint32(dst[12:16], hdr.EntryCount)
	copy(dst[16:32], hdr.Reserved[:])
}

// decodeCodebookHeader reconstruit l'en-tête depuis sa forme little-endian.
func decodeCodebookHeader(src *[codebookHeaderSize]byte, hdr *CodebookHeader) {
	copy(hdr.Magic[:], src[0:8])
	hdr.Version = binary.LittleEndian.Uint16(src[8:10])
	hdr.VectorDim = binary.LittleEndian.Uint16(src[10:12])
	hdr.EntryCount = binary.LittleEndian.Uint32(src[12:16])
	copy(hdr.Reserved[:], src[16:32])
}

// encodeCodebookEntry sérialise le bitcode puis les trois métadonnées.
func encodeCodebookEntry(dst *[codebookEntrySize]byte, e *CodebookEntry) {
	for k := 0; k < codebookWords; k++ {
		binary.LittleEndian.PutUint64(dst[k*8:k*8+8], e.Bitcode[k])
	}
	binary.LittleEndian.PutUint32(dst[64:68], e.ThreatID)
	binary.LittleEndian.PutUint16(dst[68:70], e.Subsystem)
	binary.LittleEndian.PutUint16(dst[70:72], e.Severity)
}

// decodeCodebookEntry reconstruit l'entrée depuis sa forme little-endian.
func decodeCodebookEntry(src *[codebookEntrySize]byte, e *CodebookEntry) {
	for k := 0; k < codebookWords; k++ {
		e.Bitcode[k] = binary.LittleEndian.Uint64(src[k*8 : k*8+8])
	}
	e.ThreatID = binary.LittleEndian.Uint32(src[64:68])
	e.Subsystem = binary.LittleEndian.Uint16(src[68:70])
	e.Severity = binary.LittleEndian.Uint16(src[70:72])
}

// AtomicCodebook encapsule un *Codebook de manière atomique pour autoriser
// un remplacement à chaud (hot reload) sans verrou (lock-free) en production.
type AtomicCodebook struct {
	ptr atomic.Pointer[Codebook]
}

// NewAtomicCodebook initialise le conteneur atomique avec le codebook fourni.
func NewAtomicCodebook(cb *Codebook) *AtomicCodebook {
	ac := &AtomicCodebook{}
	ac.ptr.Store(cb)
	return ac
}

// LoadAtomicCodebook charge un fichier .c2book et l'encapsule dans un AtomicCodebook.
func LoadAtomicCodebook(path string) (*AtomicCodebook, error) {
	cb, err := LoadCodebook(path)
	if err != nil {
		return nil, err
	}
	return NewAtomicCodebook(cb), nil
}

// Swap remplace atomiquement le codebook actif par le nouveau.
func (ac *AtomicCodebook) Swap(cb *Codebook) {
	ac.ptr.Store(cb)
}

// ReloadFile charge un fichier .c2book puis l'échange atomiquement.
// En cas d'erreur de lecture ou de format corrompu, le codebook actif reste inchangé.
func (ac *AtomicCodebook) ReloadFile(path string) error {
	cb, err := LoadCodebook(path)
	if err != nil {
		return err
	}
	ac.Swap(cb)
	return nil
}

// Current rend le pointeur vers le Codebook actif au moment de l'appel.
func (ac *AtomicCodebook) Current() *Codebook {
	return ac.ptr.Load()
}

// SearchNearest délègue la recherche au codebook actif sans verrou.
func (ac *AtomicCodebook) SearchNearest(query *[codebookWords]uint64, maxHamming int) (CodebookEntry, int, bool) {
	cb := ac.Current()
	if cb == nil {
		return CodebookEntry{}, 0, false
	}
	return cb.SearchNearest(query, maxHamming)
}

// SearchAll délègue la recherche globale au codebook actif sans verrou.
func (ac *AtomicCodebook) SearchAll(query *[codebookWords]uint64, maxHamming int, outMatches []CodebookMatch) int {
	cb := ac.Current()
	if cb == nil {
		return 0
	}
	return cb.SearchAll(query, maxHamming, outMatches)
}

// Len rend le nombre d'entrées du codebook actif.
func (ac *AtomicCodebook) Len() int {
	cb := ac.Current()
	if cb == nil {
		return 0
	}
	return cb.Len()
}
