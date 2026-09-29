// Package engine — server_oracle.go
// Moteur d'oracle individuel et de dataset d'état de santé journalier (Zero-Alloc, 0 B/op).
// Transforme les flux d'événements et de journaux réels du serveur en un binaire
// de vecteurs RaBitQ 512D scellé par tranche de 24h (.c2oracle).
package engine

import (
	"bufio"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/bits"
	"sync"
	"unsafe"
)

const (
	// OracleHeaderSize est la taille exacte de l'en-tête binaire d'un fichier
	// .c2oracle de version 4 (128 octets).
	OracleHeaderSize = 128
	// OracleHeaderSizeV3 est la taille de l'en-tête des versions 2 et 3 (80 octets),
	// encore lues : leur sceau occupe les octets 48..80 et elles n'ont pas de
	// sceau de la veille.
	OracleHeaderSizeV3 = 80
	// OracleEntrySize est la taille exacte d'une entrée d'état de santé vectorisé (80 octets).
	OracleEntrySize = 80
	// OracleVersion représente la version de schéma écrite par SaveOracleDay.
	// La version 2 étend le sceau à l'en-tête ; un fichier de version 1 n'a
	// qu'un sceau des entrées et n'est plus accepté. La version 3 garde la
	// disposition binaire de la version 2 mais ses bitcodes sont produits par
	// VectorizeServerHealthLocality. La version 4 porte un en-tête de 128 octets
	// (sceau de la veille, nombre d'événements observés, sceau HMAC-SHA256
	// possible), et ses entrées ont pour entité l'acteur du journal et pour
	// charge le gabarit normalisé de la ligne : ses bitcodes ne se comparent
	// donc pas à ceux de la version 3.
	OracleVersion uint16 = 4
	// OracleVersionV3 est la version précédente, lisible : bitcodes de
	// VectorizeServerHealthLocality, entité tirée du nom du fichier journal.
	OracleVersionV3 uint16 = 3
	// OracleVersionLegacy est la plus ancienne version encore lisible : ses bitcodes
	// viennent de VectorizeServerHealth et ne se comparent pas à ceux des versions 3 et 4.
	OracleVersionLegacy uint16 = 2
	// OracleVectorDim est la dimensionnalité RaBitQ standard (512 bits / 64 octets).
	OracleVectorDim uint16 = 512
	// OracleMaxVectorCount borne le nombre d'entrées d'une tranche (524 288, soit
	// 40 Mio d'entrées de 80 octets, six entrées par seconde sur une journée) :
	// au-delà, SaveOracleDay et LoadOracleDay refusent la tranche, et le silo
	// n'en scelle qu'un échantillon (réservoir déterministe, événements High et
	// Critical prioritaires) en posant OracleFlagSaturated et OracleFlagSampled.
	OracleMaxVectorCount = 1 << 19
	// oracleLoadInitialCap borne la préallocation : un en-tête ne décide jamais seul de la mémoire engagée.
	oracleLoadInitialCap = 4096
)

// OracleMagic identifie canoniquement un binaire d'oracle d'état de santé journalier.
var OracleMagic = [8]byte{'C', '2', 'O', 'R', 'A', 'C', 'L', '1'}

// Erreurs contractuelles de validation des fichiers .c2oracle.
var (
	ErrOracleMagic    = errors.New("c2oracle: signature magique invalide")
	ErrOracleVersion  = errors.New("c2oracle: version d'oracle non supportee")
	ErrOracleDim      = errors.New("c2oracle: dimension vectorielle non conforme (512 attendu)")
	ErrOracleCorrupt  = errors.New("c2oracle: fichier tronque ou incomplet")
	ErrOracleSeal     = errors.New("c2oracle: empreinte SHA-256 ou HMAC-SHA256 invalide")
	ErrOracleTooLarge = errors.New("c2oracle: nombre d'entrees superieur a OracleMaxVectorCount")
	// ErrOracleUnkeyed refuse, sous une clé HMAC, une tranche de version 2 ou 3 :
	// son sceau SHA-256 simple ne l'authentifie pas, et l'admettre permettrait à
	// qui ignore la clé de forger une tranche en la déclarant ancienne.
	ErrOracleUnkeyed = errors.New("c2oracle: tranche de version anterieure a 4, non authentifiable sous cle HMAC")
)

// Sous-systèmes d'origine pour la qualification des événements serveur.
const (
	OracleSubKernel  uint16 = 1 // Noyau, dmesg, alertes matérielles
	OracleSubAuth    uint16 = 2 // Authentification, PAM, SSH, sudo
	OracleSubProc    uint16 = 3 // Processus, execve, fork, exits atypiques
	OracleSubNet     uint16 = 4 // Trafic réseau, sockets, DNS, iptables
	OracleSubStorage uint16 = 5 // Système de fichiers, FIM, dpkg, apt
	OracleSubService uint16 = 6 // Services système, systemd, crontab
	OracleSubAgent   uint16 = 7 // Télémétrie de supervision c2blue55 / MCP
)

// Actions élémentaires transcrites.
const (
	OracleActStateNominal uint16 = 1 // État opérationnel stable et nominal
	OracleActAuthFailure  uint16 = 2 // Échec d'authentification ou élévation
	OracleActAnomalyBurst uint16 = 3 // Rafale d'activité atypique
	OracleActProcessSpawn uint16 = 4 // Nouveau binaire ou processus inédit
	OracleActNetConnect   uint16 = 5 // Connexion sortante ou résolution DNS
	OracleActFileMutate   uint16 = 6 // Modification critique de fichier ou paquet
	OracleActErrorFault   uint16 = 7 // Panique, crash ou dégradation de service
)

// Drapeaux d'état d'oracle.
const (
	OracleFlagSealed      uint16 = 0x0001 // Tranche journalière finalisée et scellée
	OracleFlagDegraded    uint16 = 0x0002 // Présence d'états de santé dégradés (< DegradedHealthScore)
	OracleFlagAnomalies   uint16 = 0x0004 // Présence d'incidents de sévérité élevée
	OracleFlagMaintenance uint16 = 0x0008 // Tranche marquée en fenêtre de maintenance
	OracleFlagSaturated   uint16 = 0x0010 // Entrées écartées faute de place (OracleMaxVectorCount)
	OracleFlagKeyed       uint16 = 0x0020 // Sceau HMAC-SHA256 sous la clé de l'hôte (version 4)
	OracleFlagSampled     uint16 = 0x0040 // Entrées normales échantillonnées par réservoir, High/Critical toutes gardées (version 4)
)

// DegradedHealthScore est le score sous lequel un état de santé est dégradé.
const DegradedHealthScore uint16 = 700

// OracleDailyHeader structure l'en-tête de 128 octets d'une tranche de 24h
// (version 4). Les versions 2 et 3 n'en sérialisent que les 80 premiers octets
// utiles : les champs jusqu'à MachineID, puis Seal ; PrevDaySeal,
// ObservedCount et Reserved y restent nuls.
type OracleDailyHeader struct {
	Magic        [8]byte  // Signature 'C2ORACL1' (0..8)
	Version      uint16   // Révision du format (OracleVersion, OracleVersionV3 ou OracleVersionLegacy) (8..10)
	VectorDim    uint16   // Dimension (512) (10..12)
	EpochDay     uint32   // Jour calendaire Unix (ts / 86400) (12..16)
	StartTsSec   uint64   // Timestamp Unix de début de tranche (16..24)
	EndTsSec     uint64   // Timestamp Unix de fin de tranche (24..32)
	VectorCount  uint32   // Nombre d'entrées d'état vectorisées (32..36)
	AverageScore uint16   // Score de santé moyen sur la tranche (0..1000) (36..38)
	Flags        uint16   // Drapeaux (OracleFlag*) (38..40)
	MachineID    uint64   // Condensat identifiant la machine hôte (40..48)
	PrevDaySeal  [32]byte // Sceau de la tranche scellée précédente de la machine, chaînage (48..80)
	Seal         [32]byte // SHA-256, ou HMAC-SHA256 si OracleFlagKeyed, sur l'en-tête (Seal nul) et les entrées (80..112)
	// ObservedCount est le nombre d'événements distincts observés dans la
	// journée ; il dépasse VectorCount quand la tranche est échantillonnée, et
	// leur rapport pondère la tranche dans la baseline (112..116).
	ObservedCount uint32
	Reserved      [12]byte // Alignement strict sur 128 octets (116..128)
}

// OracleVectorEntry structure un état de santé instantané de 80 octets.
type OracleVectorEntry struct {
	Bitcode         [8]uint64 // Vecteur d'état quantifié RaBitQ 512D (64 octets, 0..64)
	RelativeSec     uint32    // Seconde relative dans la journée (0..86399) (64..68)
	Subsystem       uint16    // Sous-système d'origine (OracleSub*) (68..70)
	HealthScore     uint16    // Score de santé instantané (0..1000, 1000 = nominal) (70..72)
	Severity        uint16    // Sévérité (SeverityLow, Medium, High, Critical) (72..74)
	CorrelatedCount uint16    // Nombre d'événements élémentaires agrégés (74..76)
	Flags           uint16    // Drapeaux d'état (76..78)
	Reserved        uint16    // Alignement strict sur 80 octets (78..80)
}

// Assertions statiques d'alignement mémoire strict à la compilation.
var (
	_ = [1]struct{}{}[unsafe.Sizeof(OracleDailyHeader{})-OracleHeaderSize]
	_ = [1]struct{}{}[unsafe.Sizeof(OracleVectorEntry{})-OracleEntrySize]
)

// ServerHealthSnapshot capture l'état instantané d'une tranche d'activité serveur.
type ServerHealthSnapshot struct {
	TimestampSec    uint64
	Subsystem       uint16
	Action          uint16
	HealthScore     uint16
	Severity        uint16
	CorrelatedCount uint16
	EntropyQ8       uint32
	EntityID        uint64
	ContextFlags    uint32
	RawPayload      [FeaturePayloadBytes]byte
}

// VectorizeServerHealth projette sans aucune allocation tas un instantané d'état
// serveur dans l'espace binaire 512D de l'oracle individuel (0 B/op).
func VectorizeServerHealth(s *ServerHealthSnapshot, outBitcode *[8]uint64) {
	if s == nil || outBitcode == nil {
		return
	}

	// 1. Mots 0 et 1 (bits 0..127) : Sous-système, Action et Sévérité
	subActionKey := (uint64(s.Subsystem) << 48) | (uint64(s.Action) << 32) | (uint64(s.Severity) << 16) | (uint64(s.ContextFlags) & 0xFFFF)
	outBitcode[0] = mixSpatial64(subActionKey)
	outBitcode[1] = mixSpatial64(subActionKey ^ 0xAAAAAAAAAAAAAAAA)

	// 2. Mots 2 et 3 (bits 128..255) : Profil d'entropie et caractéristiques de charge
	entKey := (uint64(s.EntropyQ8) << 32) | (uint64(s.CorrelatedCount) << 16) | (uint64(s.HealthScore))
	outBitcode[2] = mixSpatial64(entKey ^ 0x5555555555555555)

	var payloadHash uint64 = 0xCBF29CE484222325
	for i := 0; i < len(s.RawPayload); i++ {
		b := s.RawPayload[i]
		if b == 0 {
			break
		}
		payloadHash ^= uint64(b)
		payloadHash *= 0x100000001B3
	}
	outBitcode[3] = mixSpatial64(payloadHash ^ entKey)

	// 3. Mots 4 et 5 (bits 256..383) : Composante temporelle cyclique (heure relative)
	// Découpe la journée de 86400s en 96 tranches de 15 minutes pour capturer le rythme circadien
	relSec := uint32(s.TimestampSec % 86400)
	timeSlot := relSec / 900 // Tranche de 15 minutes (0..95)
	timeKey := (uint64(timeSlot) << 48) | (uint64(s.HealthScore) << 32) | (uint64(s.Severity) << 16)
	outBitcode[4] = mixSpatial64(timeKey ^ 0x0F0F0F0F0F0F0F0F)
	outBitcode[5] = mixSpatial64(timeKey ^ 0xF0F0F0F0F0F0F0F0)

	// 4. Mots 6 et 7 (bits 384..511) : Identité de l'entité et contexte de provenance
	entityKey := s.EntityID ^ (uint64(s.ContextFlags) << 32)
	outBitcode[6] = mixSpatial64(entityKey ^ 0x3333333333333333)
	outBitcode[7] = mixSpatial64(entityKey ^ 0xCCCCCCCCCCCCCCCC)

	// Modulation binaire par le score de santé : si le score est inférieur au seuil
	// nominal (dégradation), inversion systématique d'un motif de parité sur les bits hauts
	if s.HealthScore < DegradedHealthScore {
		outBitcode[0] ^= 0xF000F000F000F000
		outBitcode[4] ^= 0x0F000F000F000F00
	}
	if s.Severity >= SeverityHigh {
		outBitcode[1] ^= 0x00FF00FF00FF00FF
		outBitcode[5] ^= 0xFF00FF00FF00FF00
	}
}

func mixSpatial64(x uint64) uint64 {
	x += 0x9E3779B97F4A7C15
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
	x = (x ^ (x >> 27)) * 0x94D049BB133111EB
	return x ^ (x >> 31)
}

// EncodeOracleDailyHeader écrit canoniquement l'en-tête little-endian de
// version 4 dans un tampon de 128 octets.
func EncodeOracleDailyHeader(dst *[OracleHeaderSize]byte, h *OracleDailyHeader) {
	encodeOracleHeaderCommon(dst[:OracleHeaderSizeV3], h)
	copy(dst[48:80], h.PrevDaySeal[:])
	copy(dst[80:112], h.Seal[:])
	binary.LittleEndian.PutUint32(dst[112:116], h.ObservedCount)
	copy(dst[116:128], h.Reserved[:])
}

// DecodeOracleDailyHeader désérialise un en-tête little-endian de version 4
// depuis un tampon de 128 octets.
func DecodeOracleDailyHeader(src *[OracleHeaderSize]byte, h *OracleDailyHeader) {
	decodeOracleHeaderCommon(src[:OracleHeaderSizeV3], h)
	copy(h.PrevDaySeal[:], src[48:80])
	copy(h.Seal[:], src[80:112])
	h.ObservedCount = binary.LittleEndian.Uint32(src[112:116])
	copy(h.Reserved[:], src[116:128])
}

// EncodeOracleDailyHeaderV3 écrit l'en-tête de 80 octets des versions 2 et 3 :
// champs communs puis Seal aux octets 48..80.
func EncodeOracleDailyHeaderV3(dst *[OracleHeaderSizeV3]byte, h *OracleDailyHeader) {
	encodeOracleHeaderCommon(dst[:], h)
	copy(dst[48:80], h.Seal[:])
}

// DecodeOracleDailyHeaderV3 lit l'en-tête de 80 octets des versions 2 et 3.
func DecodeOracleDailyHeaderV3(src *[OracleHeaderSizeV3]byte, h *OracleDailyHeader) {
	decodeOracleHeaderCommon(src[:], h)
	h.PrevDaySeal = [32]byte{}
	copy(h.Seal[:], src[48:80])
	h.ObservedCount = 0
	h.Reserved = [12]byte{}
}

// OracleHeaderSizeOf rend la taille d'en-tête de la version v.
func OracleHeaderSizeOf(v uint16) int {
	if v >= OracleVersion {
		return OracleHeaderSize
	}
	return OracleHeaderSizeV3
}

// AppendOracleDailyHeader ajoute à dst l'en-tête encodé selon sa version :
// 128 octets en version 4, 80 octets en version 2 ou 3.
func AppendOracleDailyHeader(dst []byte, h *OracleDailyHeader) []byte {
	if h.Version >= OracleVersion {
		var b [OracleHeaderSize]byte
		EncodeOracleDailyHeader(&b, h)
		return append(dst, b[:]...)
	}
	var b [OracleHeaderSizeV3]byte
	EncodeOracleDailyHeaderV3(&b, h)
	return append(dst, b[:]...)
}

// encodeOracleHeaderCommon écrit les 48 premiers octets, communs à toutes les versions.
func encodeOracleHeaderCommon(dst []byte, h *OracleDailyHeader) {
	copy(dst[0:8], h.Magic[:])
	binary.LittleEndian.PutUint16(dst[8:10], h.Version)
	binary.LittleEndian.PutUint16(dst[10:12], h.VectorDim)
	binary.LittleEndian.PutUint32(dst[12:16], h.EpochDay)
	binary.LittleEndian.PutUint64(dst[16:24], h.StartTsSec)
	binary.LittleEndian.PutUint64(dst[24:32], h.EndTsSec)
	binary.LittleEndian.PutUint32(dst[32:36], h.VectorCount)
	binary.LittleEndian.PutUint16(dst[36:38], h.AverageScore)
	binary.LittleEndian.PutUint16(dst[38:40], h.Flags)
	binary.LittleEndian.PutUint64(dst[40:48], h.MachineID)
}

// decodeOracleHeaderCommon lit les 48 premiers octets, communs à toutes les versions.
func decodeOracleHeaderCommon(src []byte, h *OracleDailyHeader) {
	copy(h.Magic[:], src[0:8])
	h.Version = binary.LittleEndian.Uint16(src[8:10])
	h.VectorDim = binary.LittleEndian.Uint16(src[10:12])
	h.EpochDay = binary.LittleEndian.Uint32(src[12:16])
	h.StartTsSec = binary.LittleEndian.Uint64(src[16:24])
	h.EndTsSec = binary.LittleEndian.Uint64(src[24:32])
	h.VectorCount = binary.LittleEndian.Uint32(src[32:36])
	h.AverageScore = binary.LittleEndian.Uint16(src[36:38])
	h.Flags = binary.LittleEndian.Uint16(src[38:40])
	h.MachineID = binary.LittleEndian.Uint64(src[40:48])
}

// EncodeOracleVectorEntry sérialise une entrée d'état vectorisé dans un tampon de 80 octets.
func EncodeOracleVectorEntry(dst *[OracleEntrySize]byte, e *OracleVectorEntry) {
	for i := 0; i < 8; i++ {
		binary.LittleEndian.PutUint64(dst[i*8:(i+1)*8], e.Bitcode[i])
	}
	binary.LittleEndian.PutUint32(dst[64:68], e.RelativeSec)
	binary.LittleEndian.PutUint16(dst[68:70], e.Subsystem)
	binary.LittleEndian.PutUint16(dst[70:72], e.HealthScore)
	binary.LittleEndian.PutUint16(dst[72:74], e.Severity)
	binary.LittleEndian.PutUint16(dst[74:76], e.CorrelatedCount)
	binary.LittleEndian.PutUint16(dst[76:78], e.Flags)
	binary.LittleEndian.PutUint16(dst[78:80], e.Reserved)
}

// DecodeOracleVectorEntry désérialise une entrée d'état vectorisé depuis un tampon de 80 octets.
func DecodeOracleVectorEntry(src *[OracleEntrySize]byte, e *OracleVectorEntry) {
	for i := 0; i < 8; i++ {
		e.Bitcode[i] = binary.LittleEndian.Uint64(src[i*8 : (i+1)*8])
	}
	e.RelativeSec = binary.LittleEndian.Uint32(src[64:68])
	e.Subsystem = binary.LittleEndian.Uint16(src[68:70])
	e.HealthScore = binary.LittleEndian.Uint16(src[70:72])
	e.Severity = binary.LittleEndian.Uint16(src[72:74])
	e.CorrelatedCount = binary.LittleEndian.Uint16(src[74:76])
	e.Flags = binary.LittleEndian.Uint16(src[76:78])
	e.Reserved = binary.LittleEndian.Uint16(src[78:80])
}

// ComputeOracleDaySeal calcule l'empreinte SHA-256 canonique sur l'en-tête
// encodé selon sa version, champ Seal remis à zéro, suivi de la suite contiguë
// des entrées vectorisées de la journée. En version 4 l'en-tête couvert
// comprend PrevDaySeal : altérer le chaînage invalide le sceau.
func ComputeOracleDaySeal(hdr *OracleDailyHeader, entries []OracleVectorEntry) [32]byte {
	return ComputeOracleDaySealHMAC(hdr, entries, nil)
}

// ComputeOracleDaySealHMAC calcule le sceau sur les mêmes octets que
// ComputeOracleDaySeal, par HMAC-SHA256 sous key ; une clé vide rend le
// sceau SHA-256.
func ComputeOracleDaySealHMAC(hdr *OracleDailyHeader, entries []OracleVectorEntry, key []byte) [32]byte {
	h := newSealHash(key)
	unsealed := *hdr
	unsealed.Seal = [32]byte{}
	var hb [OracleHeaderSize]byte
	h.Write(AppendOracleDailyHeader(hb[:0], &unsealed))
	var buf [OracleEntrySize]byte
	for i := range entries {
		EncodeOracleVectorEntry(&buf, &entries[i])
		h.Write(buf[:])
	}
	var seal [32]byte
	copy(seal[:], h.Sum(nil))
	return seal
}

// ValidateSealKey admet une clé vide (sceau SHA-256) ou d'au moins
// SealKeyMinLen octets ; elle s'applique aux fichiers .c2oracle, .c2delta et .c2pyramid.
func ValidateSealKey(key []byte) error { return checkSealKey(key) }

// SaveOracleDay sérialise une tranche journalière de version 4 scellée en SHA-256.
func SaveOracleDay(w io.Writer, hdr *OracleDailyHeader, entries []OracleVectorEntry) error {
	return SaveOracleDayHMAC(w, hdr, entries, nil)
}

// SaveOracleDayHMAC sérialise une tranche de version 4 scellée par HMAC-SHA256
// sous key (SHA-256 si key est vide) ; OracleFlagKeyed dit quel sceau porte le
// fichier. hdr.PrevDaySeal et hdr.ObservedCount sont écrits tels quels ; un
// ObservedCount nul ou inférieur au nombre d'entrées est relevé à ce nombre.
func SaveOracleDayHMAC(w io.Writer, hdr *OracleDailyHeader, entries []OracleVectorEntry, key []byte) error {
	if hdr == nil {
		return errors.New("c2oracle: en-tete nul")
	}
	if err := checkSealKey(key); err != nil {
		return err
	}
	if len(entries) > OracleMaxVectorCount {
		return ErrOracleTooLarge
	}

	// Le sceau se calcule après la fixation de tous les champs qu'il couvre.
	hdr.VectorCount = uint32(len(entries))
	hdr.ObservedCount = max(hdr.ObservedCount, hdr.VectorCount)
	hdr.Magic = OracleMagic
	hdr.Version = OracleVersion
	hdr.VectorDim = OracleVectorDim
	hdr.Reserved = [12]byte{}
	if len(key) != 0 {
		hdr.Flags |= OracleFlagKeyed
	} else {
		hdr.Flags &^= OracleFlagKeyed
	}
	hdr.Seal = ComputeOracleDaySealHMAC(hdr, entries, key)

	bw := bufio.NewWriterSize(w, 1<<16)
	var hb [OracleHeaderSize]byte
	EncodeOracleDailyHeader(&hb, hdr)
	if _, err := bw.Write(hb[:]); err != nil {
		return err
	}

	var eb [OracleEntrySize]byte
	for i := range entries {
		EncodeOracleVectorEntry(&eb, &entries[i])
		if _, err := bw.Write(eb[:]); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// LoadOracleDay lit une tranche journalière et valide sa signature et son sceau SHA-256.
// Les versions OracleVersionV3 et OracleVersionLegacy (en-tête de 80 octets)
// sont admises ; hdr.Version dit à l'appelant quel encodage ont produit ses
// bitcodes. Une tranche scellée en HMAC est refusée par ErrOracleSeal.
func LoadOracleDay(r io.Reader) (*OracleDailyHeader, []OracleVectorEntry, error) {
	return LoadOracleDayHMAC(r, nil)
}

// LoadOracleDayHMAC lit une tranche et exige, sous une clé non vide, un sceau
// HMAC-SHA256 sous cette clé, comparé en temps constant. Sous une clé non
// vide, une tranche de version 2 ou 3 est refusée par ErrOracleUnkeyed (son
// en-tête, déjà lu, est rendu pour que l'appelant puisse l'archiver) ; une
// tranche de version 4 scellée en SHA-256 simple ou sous une autre clé est
// refusée par ErrOracleSeal.
func LoadOracleDayHMAC(r io.Reader, key []byte) (*OracleDailyHeader, []OracleVectorEntry, error) {
	if err := checkSealKey(key); err != nil {
		return nil, nil, err
	}
	br := bufio.NewReaderSize(r, 1<<16)
	var hb [OracleHeaderSize]byte
	if _, err := io.ReadFull(br, hb[:OracleHeaderSizeV3]); err != nil {
		return nil, nil, ErrOracleCorrupt
	}

	var hdr OracleDailyHeader
	decodeOracleHeaderCommon(hb[:OracleHeaderSizeV3], &hdr)
	if hdr.Magic != OracleMagic {
		return nil, nil, ErrOracleMagic
	}
	switch hdr.Version {
	case OracleVersion:
		if _, err := io.ReadFull(br, hb[OracleHeaderSizeV3:]); err != nil {
			return nil, nil, ErrOracleCorrupt
		}
		DecodeOracleDailyHeader(&hb, &hdr)
	case OracleVersionV3, OracleVersionLegacy:
		DecodeOracleDailyHeaderV3((*[OracleHeaderSizeV3]byte)(hb[:OracleHeaderSizeV3]), &hdr)
		if len(key) != 0 {
			return &hdr, nil, ErrOracleUnkeyed
		}
	default:
		return nil, nil, ErrOracleVersion
	}
	if hdr.VectorDim != OracleVectorDim {
		return nil, nil, ErrOracleDim
	}

	if hdr.VectorCount > OracleMaxVectorCount {
		return nil, nil, ErrOracleTooLarge
	}

	// La capacité croît avec les octets effectivement lus, jamais avec le compte annoncé.
	entries := make([]OracleVectorEntry, 0, min(hdr.VectorCount, oracleLoadInitialCap))
	var eb [OracleEntrySize]byte
	for i := uint32(0); i < hdr.VectorCount; i++ {
		if _, err := io.ReadFull(br, eb[:]); err != nil {
			return nil, nil, ErrOracleCorrupt
		}
		var e OracleVectorEntry
		DecodeOracleVectorEntry(&eb, &e)
		entries = append(entries, e)
	}

	if seal := ComputeOracleDaySealHMAC(&hdr, entries, key); !hmac.Equal(seal[:], hdr.Seal[:]) {
		return nil, nil, ErrOracleSeal
	}

	return &hdr, entries, nil
}

// ServerBaselineOracle héberge l'ensemble des vecteurs de santé historiques du serveur
// pour agir comme oracle de référence déterministe. QueryState balaie toute la
// baseline par POPCNT ; QueryStateLocality n'interroge que le compartiment des
// références de même sous-système, même action et, sous tolérance d'entité
// nulle, même entité. Un sync.RWMutex sérialise IngestDailyEntries face aux
// requêtes et à Len.
type ServerBaselineOracle struct {
	mu          sync.RWMutex
	machineID   uint64
	entries     []OracleVectorEntry
	nominalDist int // Seuil de distance de Hamming pour considérer l'état comme nominal (ex: 45)
	// byCategory indexe les entrées par (sous-système, action), clé tirée des
	// mots 0 et 1 du code ; byEntity par (sous-système, action, entité), clé
	// tirée des mots 0, 1 et 6. Ces trois mots sont des codes catégoriels
	// bijectifs : deux références de même clé ont le même triplet, sauf
	// collision de la clé de 64 bits, que la comparaison exacte des mots écarte.
	byCategory map[uint64][]int32
	byEntity   map[uint64][]int32
	// rarity compte les gabarits de la baseline par créneau (surprise du contenu).
	rarity *TemplateRarity
}

// NewServerBaselineOracle instancie l'oracle à partir des tranches historiques.
func NewServerBaselineOracle(machineID uint64, nominalDist int) *ServerBaselineOracle {
	if nominalDist <= 0 {
		nominalDist = 45 // ~9% de divergence sur 512 bits
	}
	return &ServerBaselineOracle{
		machineID:   machineID,
		nominalDist: nominalDist,
		byCategory:  make(map[uint64][]int32),
		byEntity:    make(map[uint64][]int32),
		rarity:      NewTemplateRarity(),
	}
}

// localityCategoryKey rend la clé de compartiment (sous-système, action) d'un code de localité.
func localityCategoryKey(code *[8]uint64) uint64 {
	return mixSpatial64(code[0] ^ bits.RotateLeft64(code[1], 29))
}

// localityEntityKey rend la clé de compartiment (sous-système, action, entité) d'un code de localité.
func localityEntityKey(code *[8]uint64) uint64 {
	return mixSpatial64(localityCategoryKey(code) ^ bits.RotateLeft64(code[6], 13))
}

// IngestDailyEntries incorpore les entrées d'une tranche journalière dans la baseline.
func (o *ServerBaselineOracle) IngestDailyEntries(entries []OracleVectorEntry) {
	o.IngestDailyEntriesWeighted(entries, 1)
}

// IngestDailyEntriesWeighted incorpore les entrées et les indexe par
// compartiment ; weight est le nombre d'événements que représente chaque
// entrée pour le modèle de rareté (ObservedCount / VectorCount pour une
// tranche échantillonnée, 1 sinon). Au-delà de 2^31 entrées l'index
// saturerait : les entrées suivantes sont ignorées.
func (o *ServerBaselineOracle) IngestDailyEntriesWeighted(entries []OracleVectorEntry, weight float64) {
	if !(weight > 0) {
		weight = 1
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for i := range entries {
		idx := len(o.entries)
		if idx >= math.MaxInt32 {
			return
		}
		o.entries = append(o.entries, entries[i])
		code := &entries[i].Bitcode
		ck, ek := localityCategoryKey(code), localityEntityKey(code)
		o.byCategory[ck] = append(o.byCategory[ck], int32(idx))
		o.byEntity[ek] = append(o.byEntity[ek], int32(idx))
		o.rarity.Observe(code, weight)
	}
}

// ContentSurprise rend la surprise -log2 P(gabarit | créneau) du code au
// regard de la baseline, en bits ; 0 si le code n'a pas de gabarit.
// Aucune allocation.
func (o *ServerBaselineOracle) ContentSurprise(bitcode *[8]uint64) float64 {
	if bitcode == nil {
		return 0
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.rarity.Surprise(bitcode)
}

// Len rend le nombre d'états d'oracle en mémoire.
func (o *ServerBaselineOracle) Len() int {
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.entries)
}

// HammingDistance512 calcule la distance de Hamming exacte entre deux bitcodes de 512 bits.
// 0 allocation tas (0 B/op).
func HammingDistance512(a, b *[8]uint64) int {
	if a == nil || b == nil {
		return 512
	}
	return bits.OnesCount64(a[0]^b[0]) +
		bits.OnesCount64(a[1]^b[1]) +
		bits.OnesCount64(a[2]^b[2]) +
		bits.OnesCount64(a[3]^b[3]) +
		bits.OnesCount64(a[4]^b[4]) +
		bits.OnesCount64(a[5]^b[5]) +
		bits.OnesCount64(a[6]^b[6]) +
		bits.OnesCount64(a[7]^b[7])
}

// QueryState interroge l'oracle individuel contre un vecteur d'état observé.
// Calcule la distance de Hamming minimale par rapport à la baseline de ce serveur.
// 0 allocation tas (0 B/op).
func (o *ServerBaselineOracle) QueryState(bitcode *[8]uint64) (minDist int, isNominal bool, matchedSub uint16, matchedScore uint16) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if len(o.entries) == 0 || bitcode == nil {
		return 512, false, 0, 0
	}

	minDist = 513
	q0, q1, q2, q3 := bitcode[0], bitcode[1], bitcode[2], bitcode[3]
	q4, q5, q6, q7 := bitcode[4], bitcode[5], bitcode[6], bitcode[7]

	for i := range o.entries {
		e := &o.entries[i]
		d := bits.OnesCount64(e.Bitcode[0]^q0) +
			bits.OnesCount64(e.Bitcode[1]^q1) +
			bits.OnesCount64(e.Bitcode[2]^q2) +
			bits.OnesCount64(e.Bitcode[3]^q3) +
			bits.OnesCount64(e.Bitcode[4]^q4) +
			bits.OnesCount64(e.Bitcode[5]^q5) +
			bits.OnesCount64(e.Bitcode[6]^q6) +
			bits.OnesCount64(e.Bitcode[7]^q7)

		if d < minDist {
			minDist = d
			matchedSub = e.Subsystem
			matchedScore = e.HealthScore
			if d == 0 {
				break
			}
		}
	}

	isNominal = (minDist <= o.nominalDist)
	return minDist, isNominal, matchedSub, matchedScore
}

// localityDistanceNone est l'écart rendu quand aucune référence n'est comparable :
// chaque groupe porte sa valeur maximale.
var localityDistanceNone = LocalityDistance{Categorical: 128, SeverityRise: 4, Scalar: 256, Entity: 64, Content: 64}

// localityRankLess ordonne deux écarts non nominaux : d'abord l'écart
// catégoriel, puis l'aggravation de sévérité, puis la somme des autres groupes.
func localityRankLess(a, b LocalityDistance) bool {
	if a.Categorical != b.Categorical {
		return a.Categorical < b.Categorical
	}
	ra, rb := max(a.SeverityRise, 0), max(b.SeverityRise, 0)
	if ra != rb {
		return ra < rb
	}
	return a.Scalar+a.Entity+a.Content < b.Scalar+b.Entity+b.Content
}

// QueryStateLocality interroge la baseline par groupes de mots, selon la
// géométrie de VectorizeServerHealthLocality : l'état est nominal si au moins
// une référence est voisine au sens de EvaluateLocalityMatch, et, lorsque
// cfg.MaxContentSurpriseBits est positif et que la cible porte un gabarit
// (mot 7 non nul), si la surprise de ce gabarit dans son créneau ne dépasse
// pas ce seuil ; le test de Hamming sur le mot 7 est alors remplacé par ce
// test de rareté.
//
// Within exige l'identité catégorielle stricte : seules les références du
// compartiment (sous-système, action) de la cible sont examinées, et, sous une
// tolérance d'entité nulle, seulement celles du compartiment (sous-système,
// action, entité). Un compartiment vide rend aussitôt l'état non nominal, avec
// bestDist = localityDistanceNone et matchedSub = matchedScore = 0, sans
// balayer la baseline. Sinon, bestDist est l'écart de la référence voisine la
// plus proche (somme Scalar+Entity+Content minimale) ou, faute de voisine, de
// la référence du compartiment la mieux classée par localityRankLess ;
// matchedSub et matchedScore décrivent cette référence.
// Les références doivent venir d'une tranche de version OracleVersion.
// 0 allocation tas (0 B/op).
func (o *ServerBaselineOracle) QueryStateLocality(bitcode *[8]uint64, cfg LocalityThresholds) (isNominal bool, bestDist LocalityDistance, matchedSub uint16, matchedScore uint16) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	bestDist = localityDistanceNone
	if len(o.entries) == 0 || bitcode == nil {
		return false, bestDist, 0, 0
	}
	var bucket []int32
	if min(cfg.MaxEntity, MaxEntityToleranceBits) <= 0 {
		bucket = o.byEntity[localityEntityKey(bitcode)]
	} else {
		bucket = o.byCategory[localityCategoryKey(bitcode)]
	}
	if len(bucket) == 0 {
		return false, bestDist, 0, 0
	}
	contentOK := true
	if cfg.MaxContentSurpriseBits > 0 && bitcode[7] != 0 && o.rarity.Total() > 0 {
		contentOK = o.rarity.Surprise(bitcode) <= float64(cfg.MaxContentSurpriseBits)
		cfg.MaxContent = 64
	}
	bestSum := int(^uint(0) >> 1)
	found := false
	for _, idx := range bucket {
		e := &o.entries[idx]
		d := LocalityDistanceOf(bitcode, &e.Bitcode)
		if contentOK && d.Within(cfg) {
			sum := d.Scalar + d.Entity + d.Content
			if !isNominal || sum < bestSum {
				isNominal = true
				bestSum = sum
				bestDist, matchedSub, matchedScore = d, e.Subsystem, e.HealthScore
				if sum == 0 {
					break
				}
			}
			continue
		}
		if !isNominal && (!found || localityRankLess(d, bestDist)) {
			found = true
			bestDist, matchedSub, matchedScore = d, e.Subsystem, e.HealthScore
		}
	}
	return isNominal, bestDist, matchedSub, matchedScore
}

// StateDeltaVerdict est le verdict conjoint de la baseline et du catalogue de
// disparités autorisées pour un état observé.
type StateDeltaVerdict struct {
	Nominal      bool             // l'état a une référence voisine dans la baseline
	Dispensed    bool             // l'état dévie, mais une règle .c2delta le dispense
	RuleID       uint32           // règle qui dispense, 0 sinon
	Distance     LocalityDistance // écart à la référence retenue par QueryStateLocality
	MatchedSub   uint16           // sous-système de cette référence
	MatchedScore uint16           // score de santé de cette référence
	// ContentSurprise est la surprise -log2 P(gabarit | créneau) de l'état au
	// regard de la baseline, en bits (0 sans gabarit ou sans baseline).
	ContentSurprise float64
}

// Anomaly dit si l'état dévie de la baseline sans qu'aucune règle ne le dispense.
func (v StateDeltaVerdict) Anomaly() bool {
	return !v.Nominal && !v.Dispensed
}

// EvaluateStateWithDelta interroge d'abord la baseline par QueryStateLocality ;
// si l'état n'y a pas de voisin, il interroge le catalogue par EvaluateDelta à
// l'instant tsSec pour l'échelle scale. Un état nominal n'est jamais soumis au
// catalogue, et un oracle ou un catalogue nil ne dispense rien : l'état est
// alors une anomalie. 0 allocation tas (0 B/op).
func EvaluateStateWithDelta(oracle *ServerBaselineOracle, catalog *DeltaCatalog, observed *[8]uint64, tsSec uint64, scale uint16, cfg LocalityThresholds) StateDeltaVerdict {
	v := StateDeltaVerdict{Distance: localityDistanceNone}
	if observed == nil {
		return v
	}
	if oracle != nil {
		v.Nominal, v.Distance, v.MatchedSub, v.MatchedScore = oracle.QueryStateLocality(observed, cfg)
		v.ContentSurprise = oracle.ContentSurprise(observed)
		if v.Nominal {
			return v
		}
	}
	v.Dispensed, v.RuleID = catalog.EvaluateDelta(observed, tsSec, scale)
	return v
}
