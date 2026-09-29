// Package c2blue55 — server_oracle_silo.go
// Gestionnaire de tranches de 24h d'état de santé serveur (.c2oracle) et ingesteur de logs réels.
// Transforme les journaux et sondes du serveur en dataset personnalisé scellé quotidiennement.
package c2blue55

import (
	"bufio"
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/bits"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

// SiloConfig configure le collecteur journalier d'oracle serveur.
type SiloConfig struct {
	StorageDir      string // Répertoire où sont déposés les fichiers .c2oracle
	MachineID       uint64 // Condensat d'identité unique de la machine hôte
	NominalDist     int    // Distance de Hamming maximale pour qualifier un état nominal (ex: 45)
	MaxRetainedDays int    // Nombre de tranches quotidiennes conservées dans l'historique actif (ex: 30)
	// BaselineExcludeAnomalousDays écarte de la baseline toute tranche marquée
	// OracleFlagAnomalies, au lieu de n'écarter que ses entrées High/Critical.
	BaselineExcludeAnomalousDays bool
	// HMACKey, s'il n'est pas vide, scelle chaque tranche écrite par
	// HMAC-SHA256 sous cette clé partagée de l'hôte (au moins
	// engine.SealKeyMinLen octets) et exige ce sceau de toute tranche lue : une
	// tranche scellée en SHA-256 simple, sous une autre clé, ou de version
	// antérieure à 4 n'entre alors ni dans la baseline ni dans les pyramides.
	HMACKey []byte
}

// DefaultSiloConfig produit une configuration calibrée pour le serveur local.
func DefaultSiloConfig(storageDir string) SiloConfig {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "server-node-default"
	}
	machineID := FNV1a64String(hostname)

	return SiloConfig{
		StorageDir:      storageDir,
		MachineID:       machineID,
		NominalDist:     45,
		MaxRetainedDays: 30,
	}
}

// DailyOracleSilo administre la production continue des binaires d'oracle par tranches de 24h.
type DailyOracleSilo struct {
	cfg            SiloConfig
	mu             sync.RWMutex
	currentDay     uint32
	hasCurrentDay  bool
	currentStartTs uint64
	// currentEntries est le réservoir des entrées de sévérité inférieure à
	// High ; currentPriority garde toutes les entrées High et Critical. Leur
	// somme ne dépasse jamais engine.OracleMaxVectorCount.
	currentEntries  []engine.OracleVectorEntry
	currentPriority []engine.OracleVectorEntry
	// currentNormalSeen et currentPrioritySeen comptent les entrées offertes à
	// chaque canal depuis l'ouverture de la tranche (algorithme R) ;
	// currentObserved compte tous les événements ingérés dans la tranche.
	currentNormalSeen   uint64
	currentPrioritySeen uint64
	currentObserved     uint64
	// sampler tire les indices du réservoir ; il est réensemencé à chaque
	// ouverture de tranche par (MachineID, jour), si bien que le même flux
	// produit le même échantillon.
	sampler splitMix64
	// currentDroppedFlags cumule OracleFlagSaturated, OracleFlagSampled et les
	// drapeaux des entrées écartées de la tranche en cours, pour que le
	// scellement ne les perde pas.
	currentDroppedFlags uint16
	// chainDay et chainSeal mémorisent le sceau de la dernière tranche écrite
	// par ce silo, pour éviter de la relire au scellement suivant.
	chainDay       uint32
	chainSeal      [32]byte
	chainKnown     bool
	totalIngested  uint64
	totalRotations uint64
	totalDropped   uint64
}

// splitMix64 est un générateur pseudo-aléatoire déterministe de 64 bits.
type splitMix64 struct{ state uint64 }

func (g *splitMix64) next() uint64 {
	g.state += 0x9E3779B97F4A7C15
	z := g.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// below rend un entier uniforme dans [0, n) par réduction de Lemire ; n > 0.
func (g *splitMix64) below(n uint64) uint64 {
	hi, _ := bits.Mul64(g.next(), n)
	return hi
}

// samplerSeed rend la graine du réservoir d'une tranche.
func samplerSeed(machineID uint64, day uint32) uint64 {
	return machineID ^ uint64(day)*0xD1B54A32D192ED03
}

// NewDailyOracleSilo initialise le silo de stockage journalier.
func NewDailyOracleSilo(cfg SiloConfig) (*DailyOracleSilo, error) {
	if cfg.StorageDir == "" {
		cfg.StorageDir = "var/oracle"
	}
	if cfg.NominalDist <= 0 {
		cfg.NominalDist = 45
	}
	if cfg.MaxRetainedDays <= 0 {
		cfg.MaxRetainedDays = 30
	}
	if err := engine.ValidateSealKey(cfg.HMACKey); err != nil {
		return nil, err
	}

	if err := os.MkdirAll(cfg.StorageDir, 0755); err != nil {
		return nil, fmt.Errorf("c2oracle: creation du repertoire de stockage: %w", err)
	}

	return &DailyOracleSilo{
		cfg: cfg,
	}, nil
}

// openDayLocked ouvre la tranche du jour day.
func (s *DailyOracleSilo) openDayLocked(day uint32, startTs uint64) {
	s.currentDay = day
	s.hasCurrentDay = true
	s.currentStartTs = startTs
	s.currentEntries = nil
	s.currentPriority = nil
	s.currentNormalSeen, s.currentPrioritySeen, s.currentObserved = 0, 0, 0
	s.currentDroppedFlags = 0
	s.sampler = splitMix64{state: samplerSeed(s.cfg.MachineID, day)}
}

// IngestSnapshot incorpore un instantané d'état de santé du serveur.
// Si le franchissement d'une tranche de 24h calendaire est constaté, la tranche
// précédente est automatiquement scellée sur disque et une nouvelle tranche s'ouvre.
//
// Au-delà de engine.OracleMaxVectorCount entrées dans la journée, une alerte
// de sécurité est journalisée une fois (un flot d'événements peut chercher à
// noyer une intrusion), puis :
//   - une entrée High ou Critical est toujours gardée ; elle prend la place
//     d'une entrée normale tirée au hasard ;
//   - une entrée normale entre dans le réservoir par l'algorithme R : la
//     n-ième entrée normale remplace une entrée du réservoir avec la
//     probabilité k/n, si bien que le réservoir reste un échantillon uniforme
//     des entrées normales de la journée ;
//   - seul le cas où les entrées High et Critical remplissent à elles seules la
//     tranche les soumet à leur tour à l'algorithme R, faute de place, avec
//     une seconde alerte.
//
// Chaque entrée écartée ou remplacée est comptée par Dropped.
func (s *DailyOracleSilo) IngestSnapshot(snap *engine.ServerHealthSnapshot) error {
	if snap == nil {
		return errors.New("c2oracle: snapshot nul")
	}

	day := uint32(snap.TimestampSec / 86400)

	s.mu.Lock()
	defer s.mu.Unlock()

	// Initialisation de la première tranche
	if !s.hasCurrentDay {
		s.openDayLocked(day, snap.TimestampSec)
	} else if day != s.currentDay {
		// Rotation automatique au franchissement de la frontière de 24 heures
		if err := s.sealCurrentDayLocked(snap.TimestampSec); err != nil {
			return fmt.Errorf("c2oracle: echec de rotation journaliere: %w", err)
		}
		s.openDayLocked(day, snap.TimestampSec)
		s.totalRotations++
	}

	var entry engine.OracleVectorEntry
	engine.VectorizeServerHealthLocality(snap, &entry.Bitcode)
	entry.RelativeSec = uint32(snap.TimestampSec % 86400)
	entry.Subsystem = snap.Subsystem
	entry.HealthScore = snap.HealthScore
	entry.Severity = snap.Severity
	entry.CorrelatedCount = snap.CorrelatedCount
	if snap.HealthScore < engine.DegradedHealthScore {
		entry.Flags |= engine.OracleFlagDegraded
	}
	priority := snap.Severity >= engine.SeverityHigh
	if priority {
		entry.Flags |= engine.OracleFlagAnomalies
	}

	s.totalIngested++
	s.currentObserved++
	if priority {
		s.currentPrioritySeen++
	} else {
		s.currentNormalSeen++
	}
	if len(s.currentEntries)+len(s.currentPriority) < engine.OracleMaxVectorCount {
		if priority {
			s.currentPriority = append(s.currentPriority, entry)
		} else {
			s.currentEntries = append(s.currentEntries, entry)
		}
		return nil
	}

	// Tranche pleine : la mémoire ne grossit plus, une entrée est écartée.
	if s.currentDroppedFlags&engine.OracleFlagSaturated == 0 {
		slog.Error("c2oracle: ALERTE SECURITE, saturation de la tranche journaliere : "+
			"un flot d'evenements peut chercher a effacer une trace ; echantillonnage par reservoir, "+
			"evenements High et Critical gardes en priorite",
			"jour", s.currentDay, "plafond", engine.OracleMaxVectorCount, "machine", fmt.Sprintf("%016x", s.cfg.MachineID))
	}
	s.currentDroppedFlags |= engine.OracleFlagSaturated | engine.OracleFlagSampled | entry.Flags
	s.totalDropped++
	switch {
	case priority && len(s.currentEntries) > 0:
		j := s.sampler.below(uint64(len(s.currentEntries)))
		last := len(s.currentEntries) - 1
		s.currentEntries[j] = s.currentEntries[last]
		s.currentEntries = s.currentEntries[:last]
		s.currentPriority = append(s.currentPriority, entry)
	case priority:
		if s.currentPrioritySeen == uint64(len(s.currentPriority))+1 {
			slog.Error("c2oracle: ALERTE SECURITE, canal prioritaire sature : les evenements High et Critical "+
				"remplissent seuls la tranche et sont echantillonnes a leur tour",
				"jour", s.currentDay, "plafond", engine.OracleMaxVectorCount)
		}
		if j := s.sampler.below(s.currentPrioritySeen); j < uint64(len(s.currentPriority)) {
			s.currentPriority[j] = entry
		}
	default:
		if j := s.sampler.below(s.currentNormalSeen); j < uint64(len(s.currentEntries)) {
			s.currentEntries[j] = entry
		}
	}
	return nil
}

// SealDay scelle manuellement la tranche en cours et l'écrit sur disque.
func (s *DailyOracleSilo) SealDay(endTsSec uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sealCurrentDayLocked(endTsSec)
}

// sealCurrentDayLocked écrit la tranche en cours sans jamais détruire une tranche
// déjà scellée : si le fichier du jour existe, ses entrées sont conservées et
// seules les entrées nouvelles (encodage de 80 octets absent du fichier) y sont
// ajoutées. Un fichier existant illisible, d'une autre machine ou d'un autre jour
// fait échouer le scellement et reste intact. L'écriture passe par un fichier
// temporaire renommé, si bien qu'une interruption laisse l'ancienne tranche en place.
// Le verrou exclusif du répertoire couvre la relecture, la fusion et le renommage :
// deux processus qui scellent le même jour (démon et c2forge -oracle-ingest) se
// sérialisent, et le second fusionne ce que le premier vient d'écrire.
//
// Une fusion qui dépasse OracleMaxVectorCount n'est pas une erreur : les
// entrées High et Critical sont toutes gardées, les autres sont échantillonnées
// par un réservoir déterministe, le surplus est compté et journalisé, et
// l'en-tête porte OracleFlagSaturated, OracleFlagSampled et les drapeaux
// d'alerte des entrées écartées. Un dépassement ne bloque donc jamais la
// rotation vers le jour suivant.
//
// L'en-tête porte en PrevDaySeal le sceau de la tranche de version 4 la plus
// récente antérieure à ce jour (voir prevDaySealLocked), et la tranche est
// scellée sous cfg.HMACKey.
func (s *DailyOracleSilo) sealCurrentDayLocked(endTsSec uint64) error {
	if len(s.currentEntries)+len(s.currentPriority) == 0 {
		return nil
	}

	unlock, err := lockStorageDir(s.cfg.StorageDir)
	if err != nil {
		return err
	}
	defer unlock()

	if endTsSec <= s.currentStartTs {
		endTsSec = s.currentStartTs + 86400
	}

	filePath := filepath.Join(s.cfg.StorageDir, oracleDayFileName(s.cfg.MachineID, s.currentDay))

	startTs := s.currentStartTs
	var prevFlags uint16
	var prevObserved uint64
	merged, err := loadExistingDay(filePath, s.cfg.MachineID, s.currentDay, s.cfg.HMACKey)
	if err != nil {
		return err
	}
	if merged != nil && merged.hdr.Version != engine.OracleVersion {
		// Les bitcodes d'une tranche de version antérieure ne se comparent pas à
		// ceux de la version courante : la tranche est conservée à part et ses
		// entrées ne sont pas fusionnées. Ses bornes et drapeaux ne sont repris
		// que si son sceau a pu être vérifié (aucune clé HMAC exigée).
		if err := archiveLegacyDay(filePath, merged.hdr.Version); err != nil {
			return err
		}
		merged.entries = nil
		if merged.unauthenticated {
			merged = nil
		}
	}
	if merged != nil {
		startTs = min(startTs, merged.hdr.StartTsSec)
		endTsSec = max(endTsSec, merged.hdr.EndTsSec)
		prevFlags = merged.hdr.Flags & (engine.OracleFlagMaintenance | engine.OracleFlagSaturated |
			engine.OracleFlagSampled | engine.OracleFlagDegraded | engine.OracleFlagAnomalies)
		if merged.hdr.Version == engine.OracleVersion {
			prevObserved = uint64(merged.hdr.ObservedCount)
		}
	}
	fresh := make([]engine.OracleVectorEntry, 0, len(s.currentEntries)+len(s.currentPriority))
	fresh = append(append(fresh, s.currentEntries...), s.currentPriority...)
	entries, dupFresh := mergeOracleEntries(merged, fresh)

	// Les drapeaux d'alerte se calculent sur toutes les entrées, écartées comprises.
	flags := engine.OracleFlagSealed | prevFlags | s.currentDroppedFlags
	for i := range entries {
		if entries[i].HealthScore < engine.DegradedHealthScore {
			flags |= engine.OracleFlagDegraded
		}
		if entries[i].Severity >= engine.SeverityHigh {
			flags |= engine.OracleFlagAnomalies
		}
	}
	observed := max(uint64(len(entries)), prevObserved+s.currentObserved-uint64(dupFresh))
	var dropped int
	if len(entries) > engine.OracleMaxVectorCount {
		dropped = len(entries) - engine.OracleMaxVectorCount
		sampler := splitMix64{state: samplerSeed(s.cfg.MachineID, s.currentDay) ^ 0x5EA15EA15EA15EA1}
		entries = sampleOracleEntries(entries, engine.OracleMaxVectorCount, &sampler)
		flags |= engine.OracleFlagSaturated | engine.OracleFlagSampled
	}

	// Calcul du score de santé moyen des entrées scellées
	var sumScore uint64
	for i := range entries {
		sumScore += uint64(entries[i].HealthScore)
	}
	avgScore := uint16(sumScore / uint64(len(entries)))

	prevSeal, err := s.prevDaySealLocked(s.currentDay)
	if err != nil {
		return err
	}
	hdr := engine.OracleDailyHeader{
		EpochDay:      s.currentDay,
		StartTsSec:    startTs,
		EndTsSec:      endTsSec,
		VectorCount:   uint32(len(entries)),
		AverageScore:  avgScore,
		Flags:         flags,
		MachineID:     s.cfg.MachineID,
		PrevDaySeal:   prevSeal,
		ObservedCount: uint32(min(observed, math.MaxUint32)),
	}

	if err := writeOracleDayAtomic(filePath, &hdr, entries, s.cfg.HMACKey); err != nil {
		return err
	}
	s.chainDay, s.chainSeal, s.chainKnown = s.currentDay, hdr.Seal, true
	if dropped > 0 {
		slog.Warn("c2oracle: tranche saturee au scellement, surplus echantillonne",
			"jour", s.currentDay, "plafond", engine.OracleMaxVectorCount, "ecartees", dropped)
		s.totalDropped += uint64(dropped)
	}
	if err := s.relinkSuccessorsLocked(s.currentDay, hdr.Seal); err != nil {
		return err
	}
	// Les entrées sont désormais sur disque : un scellement ultérieur du même
	// jour n'ajoutera que ce qui aura été ingéré depuis.
	s.currentEntries = nil
	s.currentPriority = nil
	s.currentObserved = 0
	s.currentDroppedFlags = 0
	return nil
}

// sampleOracleEntries réduit entries à capacity entrées : toutes les entrées
// High et Critical d'abord (échantillonnées à leur tour seulement si elles
// dépassent seules la capacité), puis un échantillon uniforme des autres par
// l'algorithme R ; l'ordre d'origine des entrées gardées est conservé.
func sampleOracleEntries(entries []engine.OracleVectorEntry, capacity int, g *splitMix64) []engine.OracleVectorEntry {
	var prio, normal []int
	for i := range entries {
		if entries[i].Severity >= engine.SeverityHigh {
			prio = append(prio, i)
		} else {
			normal = append(normal, i)
		}
	}
	keep := reservoirIndices(prio, capacity, g)
	keep = append(keep, reservoirIndices(normal, capacity-len(keep), g)...)
	slices.Sort(keep)
	out := make([]engine.OracleVectorEntry, len(keep))
	for i, idx := range keep {
		out[i] = entries[idx]
	}
	return out
}

// reservoirIndices rend au plus k éléments de idx tirés par l'algorithme R.
func reservoirIndices(idx []int, k int, g *splitMix64) []int {
	if k <= 0 {
		return nil
	}
	if len(idx) <= k {
		return slices.Clone(idx)
	}
	res := slices.Clone(idx[:k])
	for n := k; n < len(idx); n++ {
		if j := g.below(uint64(n + 1)); j < uint64(k) {
			res[j] = idx[n]
		}
	}
	return res
}

// oracleDayFileName rend le nom de la tranche d'un jour.
func oracleDayFileName(machineID uint64, day uint32) string {
	return fmt.Sprintf("oracle_%016x_%d.c2oracle", machineID, day)
}

// storedDayFilesLocked liste les tranches du répertoire, par jour croissant.
func (s *DailyOracleSilo) storedDayFilesLocked() []oracleDayFile {
	pattern := fmt.Sprintf("oracle_%016x_*.c2oracle", s.cfg.MachineID)
	matches, err := filepath.Glob(filepath.Join(s.cfg.StorageDir, pattern))
	if err != nil {
		return nil
	}
	return oracleDayFiles(matches, s.cfg.MachineID)
}

// relinkSuccessorsLocked repropage le chaînage après le scellement du jour
// day sous le sceau seal : une tranche postérieure dont PrevDaySeal ne désigne
// plus le sceau de sa devancière est réécrite (mêmes entrées, même en-tête,
// PrevDaySeal corrigé, nouveau sceau), puis la suivante est examinée à son
// tour ; la propagation s'arrête à la première tranche déjà cohérente. C'est le
// cas d'un rattrapage (journal plus ancien ingéré après un plus récent) ; en
// régime établi le jour scellé est le dernier et rien n'est réécrit. Une
// tranche postérieure qui ne se charge pas sous la clé n'est jamais réécrite,
// pour ne pas effacer la trace d'une altération : la propagation s'arrête,
// l'alerte est journalisée et VerifyOracleChain signalera la rupture.
func (s *DailyOracleSilo) relinkSuccessorsLocked(day uint32, seal [32]byte) error {
	for _, f := range s.storedDayFilesLocked() {
		if f.epochDay <= day {
			continue
		}
		hdr, entries, err := loadOracleDayFile(f.path, s.cfg.HMACKey)
		if err == nil && (hdr.Version != engine.OracleVersion || hdr.MachineID != s.cfg.MachineID || hdr.EpochDay != f.epochDay) {
			err = errors.New("version, machine ou jour hors chaine")
		}
		if err != nil {
			slog.Error("c2oracle: ALERTE SECURITE, tranche posterieure invalide, chainage non repropage",
				"jour", day, "posterieure", f.epochDay, "erreur", err)
			return nil
		}
		if hdr.PrevDaySeal == seal {
			return nil
		}
		hdr.PrevDaySeal = seal
		if err := writeOracleDayAtomic(f.path, hdr, entries, s.cfg.HMACKey); err != nil {
			return fmt.Errorf("c2oracle: repropagation du chainage au jour %d: %w", f.epochDay, err)
		}
		slog.Info("c2oracle: chainage repropage a une tranche posterieure", "jour", day, "posterieure", f.epochDay)
		s.chainDay, s.chainSeal, s.chainKnown = f.epochDay, hdr.Seal, true
		seal, day = hdr.Seal, f.epochDay
	}
	return nil
}

// prevDaySealLocked rend le sceau de la tranche la plus récente antérieure à
// day, qui devient le PrevDaySeal de la tranche de day : les tranches forment
// ainsi une chaîne où altérer, retirer ou remplacer un jour rompt le lien du
// jour suivant. Une journée sans événement n'a pas de fichier : le lien saute
// ce jour. Sans tranche antérieure, le sceau est nul (début de chaîne). Si la
// tranche antérieure ne se charge pas sous la clé du silo (altérée, d'une autre
// clé, de version antérieure à 4), le scellement n'est pas bloqué : le sceau est
// nul, ce que VerifyOracleChain signale, et la rupture est journalisée.
func (s *DailyOracleSilo) prevDaySealLocked(day uint32) ([32]byte, error) {
	var prev *oracleDayFile
	files := s.storedDayFilesLocked()
	for i := range files {
		if files[i].epochDay < day {
			prev = &files[i]
		}
	}
	if prev == nil {
		return [32]byte{}, nil
	}
	if s.chainKnown && s.chainDay == prev.epochDay {
		return s.chainSeal, nil
	}
	hdr, _, err := loadOracleDayFile(prev.path, s.cfg.HMACKey)
	if err == nil && hdr.Version != engine.OracleVersion {
		err = fmt.Errorf("version %d hors chaine", hdr.Version)
	}
	if err == nil && (hdr.MachineID != s.cfg.MachineID || hdr.EpochDay != prev.epochDay) {
		err = errors.New("machine ou jour contredisant le nom")
	}
	if err != nil {
		slog.Error("c2oracle: ALERTE SECURITE, tranche precedente invalide, chainage rompu",
			"jour", day, "precedente", prev.epochDay, "erreur", err)
		return [32]byte{}, nil
	}
	return hdr.Seal, nil
}

// loadOracleDayFile ouvre et charge une tranche sous key.
func loadOracleDayFile(path string, key []byte) (*engine.OracleDailyHeader, []engine.OracleVectorEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	return engine.LoadOracleDayHMAC(f, key)
}

// OracleChainBreak décrit un maillon rompu de la chaîne des tranches.
type OracleChainBreak struct {
	EpochDay uint32 // tranche dont le lien est rompu
	Reason   string
}

// VerifyOracleChain relit toutes les tranches de la machine sous la clé du
// silo, par jour croissant, et rend les maillons rompus : tranche illisible ou
// non authentifiée, et tranche de version 4 dont PrevDaySeal ne vaut pas le
// sceau de la tranche de version 4 qui la précède. Le premier maillon de
// version 4 n'a pas de prédécesseur connu : son PrevDaySeal n'est pas vérifié,
// la rétention ayant pu retirer le jour qu'il désigne. Les tranches de version
// antérieure, lisibles sans clé, sont hors chaîne et ignorées.
func (s *DailyOracleSilo) VerifyOracleChain() ([]OracleChainBreak, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var breaks []OracleChainBreak
	var prevSeal [32]byte
	havePrev := false
	for _, f := range s.storedDayFilesLocked() {
		hdr, _, err := loadOracleDayFile(f.path, s.cfg.HMACKey)
		if err == nil && hdr.Version != engine.OracleVersion {
			continue
		}
		if err == nil && (hdr.MachineID != s.cfg.MachineID || hdr.EpochDay != f.epochDay) {
			err = errors.New("machine ou jour contredisant le nom")
		}
		if err != nil {
			breaks = append(breaks, OracleChainBreak{EpochDay: f.epochDay, Reason: err.Error()})
			havePrev = false
			continue
		}
		if havePrev && hdr.PrevDaySeal != prevSeal {
			breaks = append(breaks, OracleChainBreak{EpochDay: f.epochDay,
				Reason: "PrevDaySeal different du sceau de la tranche precedente"})
		}
		prevSeal, havePrev = hdr.Seal, true
	}
	return breaks, nil
}

// archiveLegacyDay conserve une tranche de version antérieure sous le nom
// <chemin>.v<version>, hors du motif *.c2oracle lu par BuildServerBaseline,
// avant que le renommage atomique ne remplace le chemin d'origine. L'archive est
// un lien dur ; si le système de fichiers le refuse (EPERM, EXDEV, EMLINK,
// ENOTSUP…), elle devient une copie atomique (fichier temporaire synchronisé
// puis renommé). Une archive déjà présente et identique (même fichier ou même
// contenu, laissée par un scellement précédent interrompu) est admise ; une
// archive différente sous ce nom fait échouer le scellement.
func archiveLegacyDay(path string, version uint16) error {
	archive := fmt.Sprintf("%s.v%d", path, version)
	err := linkFile(path, archive)
	if err == nil {
		slog.Info("c2oracle: tranche de version anterieure archivee", "chemin", archive)
		return nil
	}
	if errors.Is(err, os.ErrExist) {
		return sameArchive(path, archive)
	}
	if _, serr := os.Lstat(archive); serr == nil {
		return sameArchive(path, archive)
	}
	if cerr := copyFileAtomic(path, archive); cerr != nil {
		return fmt.Errorf("c2oracle: archivage de la tranche v%d (lien refuse: %v): %w", version, err, cerr)
	}
	slog.Info("c2oracle: tranche de version anterieure archivee par copie", "chemin", archive, "lien", err)
	return nil
}

// linkFile crée le lien dur de l'archive ; variable pour que les tests
// simulent un système de fichiers sans liens durs.
var linkFile = os.Link

// sameArchive admet une archive déjà présente si elle désigne le même fichier
// que path ou en porte exactement le contenu.
func sameArchive(path, archive string) error {
	a, aerr := os.Stat(archive)
	p, perr := os.Stat(path)
	if aerr == nil && perr == nil && (os.SameFile(a, p) || (a.Size() == p.Size() && sameContent(path, archive))) {
		return nil
	}
	return fmt.Errorf("c2oracle: archive %s deja presente et distincte, ecrasement refuse", archive)
}

// sameContent compare deux fichiers octet par octet ; faux sur toute erreur de lecture.
func sameContent(a, b string) bool {
	fa, err := os.Open(a)
	if err != nil {
		return false
	}
	defer fa.Close()
	fb, err := os.Open(b)
	if err != nil {
		return false
	}
	defer fb.Close()
	ra, rb := bufio.NewReaderSize(fa, 1<<16), bufio.NewReaderSize(fb, 1<<16)
	var ba, bb [1 << 15]byte
	for {
		na, ea := io.ReadFull(ra, ba[:])
		nb, eb := io.ReadFull(rb, bb[:])
		if na != nb || !bytes.Equal(ba[:na], bb[:nb]) {
			return false
		}
		if ea == io.EOF || ea == io.ErrUnexpectedEOF {
			return eb == ea
		}
		if ea != nil || eb != nil {
			return false
		}
	}
}

// copyFileAtomic copie src vers dst par un fichier temporaire du répertoire de
// dst, synchronisé puis renommé, et synchronise le répertoire : dst n'existe
// jamais à moitié écrit.
func copyFileAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, filepath.Base(dst)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := io.Copy(tmp, in); err != nil {
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, dst); err != nil {
		return err
	}
	committed = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// oracleLockName est le fichier de verrou partagé par tous les processus qui scellent dans un répertoire.
const oracleLockName = ".lock"

// lockStorageDir prend le verrou flock exclusif du répertoire de stockage et
// rend sa libération. Le verrou tient à la description de fichier ouverte : deux
// silos d'un même processus s'excluent donc comme deux processus distincts.
func lockStorageDir(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, oracleLockName), os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, fmt.Errorf("c2oracle: ouverture du verrou: %w", err)
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("c2oracle: verrou exclusif: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}

type existingOracleDay struct {
	hdr     *engine.OracleDailyHeader
	entries []engine.OracleVectorEntry
	// unauthenticated marque une tranche de version antérieure à 4 lue sous
	// une clé HMAC : son en-tête n'est pas authentifié.
	unauthenticated bool
}

// loadExistingDay relit la tranche déjà scellée d'un jour ; nil sans erreur si
// elle n'existe pas. Sous une clé HMAC, une tranche de version 2 ou 3 est rendue
// sans entrées et marquée non authentifiée, pour être archivée.
func loadExistingDay(path string, machineID uint64, day uint32, key []byte) (*existingOracleDay, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	hdr, entries, err := engine.LoadOracleDayHMAC(f, key)
	unauthenticated := false
	if errors.Is(err, engine.ErrOracleUnkeyed) {
		err, unauthenticated = nil, true
	}
	if err != nil {
		return nil, fmt.Errorf("c2oracle: tranche existante %s illisible, ecrasement refuse: %w", path, err)
	}
	if hdr.MachineID != machineID || hdr.EpochDay != day {
		return nil, fmt.Errorf("c2oracle: tranche existante %s d'une autre machine ou d'un autre jour, ecrasement refuse", path)
	}
	return &existingOracleDay{hdr: hdr, entries: entries, unauthenticated: unauthenticated}, nil
}

// mergeOracleEntries conserve toutes les entrées scellées et n'ajoute que les
// entrées nouvelles, identifiées par leur encodage canonique de 80 octets ;
// réingérer le même journal est donc idempotent. Rend aussi le nombre
// d'entrées nouvelles écartées comme doublons.
func mergeOracleEntries(existing *existingOracleDay, fresh []engine.OracleVectorEntry) ([]engine.OracleVectorEntry, int) {
	var base []engine.OracleVectorEntry
	if existing != nil {
		base = existing.entries
	}
	seen := make(map[[engine.OracleEntrySize]byte]struct{}, len(base)+len(fresh))
	out := make([]engine.OracleVectorEntry, 0, len(base)+len(fresh))
	var key [engine.OracleEntrySize]byte
	dup := 0
	for n, src := range [][]engine.OracleVectorEntry{base, fresh} {
		for i := range src {
			engine.EncodeOracleVectorEntry(&key, &src[i])
			if _, d := seen[key]; d {
				if n == 1 {
					dup++
				}
				continue
			}
			seen[key] = struct{}{}
			out = append(out, src[i])
		}
	}
	return out, dup
}

// writeOracleDayAtomic écrit la tranche dans un fichier temporaire du même
// répertoire, le synchronise, puis le renomme sur le chemin définitif.
func writeOracleDayAtomic(path string, hdr *engine.OracleDailyHeader, entries []engine.OracleVectorEntry, key []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()
	if err := engine.SaveOracleDayHMAC(tmp, hdr, entries, key); err != nil {
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	committed = true
	return nil
}

// BuildServerBaseline charge les K dernières tranches journalières scellées
// depuis le répertoire de stockage et instancie l'oracle individuel de référence.
// Seules entrent les tranches retenues par loadBaselineDays ; une tranche
// échantillonnée entre avec le poids ObservedCount / VectorCount dans le
// modèle de rareté des gabarits.
func (s *DailyOracleSilo) BuildServerBaseline(maxDays int) (*engine.ServerBaselineOracle, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	days, err := s.loadBaselineDaysLocked(maxDays)
	if err != nil {
		return nil, err
	}
	oracle := engine.NewServerBaselineOracle(s.cfg.MachineID, s.cfg.NominalDist)
	for _, d := range days {
		oracle.IngestDailyEntriesWeighted(baselineAdmissible(d.entries), d.weight)
	}
	return oracle, nil
}

// baselineDay est une tranche admise dans la baseline.
type baselineDay struct {
	epochDay uint32
	entries  []engine.OracleVectorEntry
	weight   float64
}

// loadBaselineDaysLocked charge les maxDays dernières tranches scellées et ne
// garde que celles de version engine.OracleVersion, dont les bitcodes suivent
// l'encodage courant, dont le sceau se vérifie sous la clé du silo, et dont la
// machine et le jour sont conformes au nom. Une tranche marquée
// OracleFlagSaturated sans OracleFlagSampled (plafond atteint sans
// échantillonnage représentatif) est écartée ; une tranche échantillonnée est
// admise et pondérée. Si BaselineExcludeAnomalousDays est posé, une tranche
// marquée OracleFlagAnomalies est écartée en entier. Une tranche dont le sceau
// ne se vérifie pas est écartée et journalisée comme alerte.
func (s *DailyOracleSilo) loadBaselineDaysLocked(maxDays int) ([]baselineDay, error) {
	pattern := fmt.Sprintf("oracle_%016x_*.c2oracle", s.cfg.MachineID)
	matches, err := filepath.Glob(filepath.Join(s.cfg.StorageDir, pattern))
	if err != nil {
		return nil, err
	}
	files := oracleDayFiles(matches, s.cfg.MachineID)
	if maxDays > 0 && len(files) > maxDays {
		files = files[len(files)-maxDays:]
	}
	days := make([]baselineDay, 0, len(files))
	for _, day := range files {
		hdr, entries, lerr := loadOracleDayFile(day.path, s.cfg.HMACKey)
		if errors.Is(lerr, engine.ErrOracleSeal) {
			slog.Error("c2oracle: ALERTE SECURITE, sceau de tranche invalide, tranche ecartee de la baseline",
				"chemin", day.path)
		}
		if lerr != nil {
			continue // Fichier corrompu, incomplet ou non authentifié ignoré pour l'oracle
		}
		if hdr.MachineID != s.cfg.MachineID || hdr.Version != engine.OracleVersion || hdr.EpochDay != day.epochDay {
			continue
		}
		if hdr.Flags&engine.OracleFlagSaturated != 0 && hdr.Flags&engine.OracleFlagSampled == 0 {
			continue
		}
		if s.cfg.BaselineExcludeAnomalousDays && hdr.Flags&engine.OracleFlagAnomalies != 0 {
			continue
		}
		weight := 1.0
		if hdr.Flags&engine.OracleFlagSampled != 0 && hdr.VectorCount > 0 && hdr.ObservedCount > hdr.VectorCount {
			weight = float64(hdr.ObservedCount) / float64(hdr.VectorCount)
		}
		days = append(days, baselineDay{epochDay: day.epochDay, entries: entries, weight: weight})
	}
	return days, nil
}

// oracleDayFile est une tranche journalière repérée par son nom de fichier.
type oracleDayFile struct {
	path     string
	epochDay uint32
}

// oracleDayFiles extrait le jour de chaque nom oracle_<machineID>_<jour>.c2oracle
// et trie les tranches par jour numérique croissant : un tri lexicographique
// placerait le jour 9 après le jour 10 (finding F_DS_05). Un nom dont le jour
// n'est pas un entier décimal canonique (vide, signe, zéro de tête, hors
// uint32) est écarté, si bien qu'un jour n'a qu'un seul nom admis.
func oracleDayFiles(matches []string, machineID uint64) []oracleDayFile {
	prefix := fmt.Sprintf("oracle_%016x_", machineID)
	days := make([]oracleDayFile, 0, len(matches))
	for _, m := range matches {
		digits, ok := strings.CutPrefix(filepath.Base(m), prefix)
		if !ok {
			continue
		}
		digits, ok = strings.CutSuffix(digits, ".c2oracle")
		if !ok {
			continue
		}
		day, err := strconv.ParseUint(digits, 10, 32)
		if err != nil || strconv.FormatUint(day, 10) != digits {
			continue
		}
		days = append(days, oracleDayFile{path: m, epochDay: uint32(day)})
	}
	slices.SortFunc(days, func(a, b oracleDayFile) int { return cmp.Compare(a.epochDay, b.epochDay) })
	return days
}

// baselineAdmissible retire les entrées High/Critical, dégradées (score < DegradedHealthScore) ou
// marquées anomalie ou dégradation, pour qu'une attaque ou une panne consignée
// dans une tranche ne devienne jamais une référence nominale.
func baselineAdmissible(entries []engine.OracleVectorEntry) []engine.OracleVectorEntry {
	kept := entries[:0]
	for i := range entries {
		e := &entries[i]
		if e.Severity >= engine.SeverityHigh || e.HealthScore < engine.DegradedHealthScore ||
			e.Flags&(engine.OracleFlagAnomalies|engine.OracleFlagDegraded) != 0 {
			continue
		}
		kept = append(kept, entries[i])
	}
	return kept
}

// Stats retourne les métriques globales du silo.
func (s *DailyOracleSilo) Stats() (currentDay uint32, activeEntries int, totalIngested uint64, totalRotations uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentDay, len(s.currentEntries) + len(s.currentPriority), s.totalIngested, s.totalRotations
}

// Dropped retourne le nombre d'entrées écartées ou remplacées faute de place
// (OracleMaxVectorCount), à l'ingestion comme au scellement.
func (s *DailyOracleSilo) Dropped() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.totalDropped
}

// LogStreamIngester lit et convertit des flux de journaux réels (syslog, auth, dpkg, audit)
// en instantanés d'état pour alimenter le silo journalier.
type LogStreamIngester struct {
	silo *DailyOracleSilo
}

// NewLogStreamIngester instancie l'ingesteur rattaché à son silo.
func NewLogStreamIngester(silo *DailyOracleSilo) *LogStreamIngester {
	return &LogStreamIngester{silo: silo}
}

// IngestLogFile lit un fichier de journal réel du système et incorpore ses
// événements. Le nom du fichier ne sert qu'à qualifier le sous-système et, à
// défaut d'étiquette syslog dans la ligne, l'acteur (nom normalisé par
// NormalizeLogActor, indépendant de la rotation : auth.log et auth.log.1
// désignent le même acteur).
func (ing *LogStreamIngester) IngestLogFile(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	return ing.IngestReader(f, filepath.Base(path))
}

// IngestReader consomme un flux de lignes de journal réelles. Une ligne sans
// horodatage (suite d'une entrée multiligne) prend celui de la dernière ligne
// horodatée du flux ; avant toute ligne horodatée, elle est ignorée. Une ligne
// dont l'horodatage est mal formé ou impossible est ignorée.
func (ing *LogStreamIngester) IngestReader(r io.Reader, logSource string) (int, error) {
	scanner := bufio.NewScanner(r)
	// Augmente la capacité maximale de ligne pour tolérer les longues lignes de log
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)

	count := 0
	var lastTs uint64
	for scanner.Scan() {
		line := scanner.Text()
		if len(strings.TrimSpace(line)) == 0 {
			continue
		}

		snap, ok := parseLogLineAt(line, logSource, lastTs)
		if !ok {
			continue
		}
		lastTs = snap.TimestampSec

		if err := ing.silo.IngestSnapshot(&snap); err != nil {
			return count, err
		}
		count++
	}

	return count, scanner.Err()
}

// ParseLogLine analyse une ligne de journal réel et construit l'instantané
// d'état typé. La ligne doit porter un horodatage valide (voir
// parseTimestamp) : sans horodatage, ou avec un horodatage mal formé ou
// impossible, elle est refusée, jamais datée de l'instant présent.
//
// L'entité est l'acteur qui a émis la ligne (étiquette syslog « sshd[42]: »,
// « kernel: », « sudo: »…), à défaut le nom normalisé de la source ; la charge
// est le gabarit normalisé de la ligne (LogTemplate), si bien que deux lignes
// qui ne diffèrent que par un PID, une adresse ou un nombre ont le même mot de
// contenu. L'entropie reste mesurée sur le texte brut.
func ParseLogLine(line string, logSource string) (engine.ServerHealthSnapshot, bool) {
	return parseLogLineAt(line, logSource, 0)
}

// parseLogLineAt analyse la ligne ; une ligne sans horodatage prend inheritTs
// s'il est non nul, et est refusée sinon.
func parseLogLineAt(line string, logSource string, inheritTs uint64) (engine.ServerHealthSnapshot, bool) {
	var snap engine.ServerHealthSnapshot
	line = strings.TrimSpace(line)
	if len(line) == 0 {
		return snap, false
	}

	// 1. Détection de format de timestamp et parsing chronologique
	tsSec, remLine, st := parseTimestamp(line)
	switch st {
	case tsValid:
	case tsAbsent:
		if inheritTs == 0 {
			return snap, false
		}
		tsSec, remLine = inheritTs, line
	default:
		return snap, false
	}
	snap.TimestampSec = tsSec
	snap.CorrelatedCount = 1
	snap.HealthScore = 980 // Score nominal par défaut
	snap.Severity = engine.SeverityLow
	snap.Subsystem = engine.OracleSubService
	snap.Action = engine.OracleActStateNominal

	// 2. Déduction du sous-système selon le fichier source ou les mots-clés
	lowerLine := strings.ToLower(remLine)
	lowerSource := strings.ToLower(logSource)

	switch {
	case strings.Contains(lowerSource, "dpkg") || strings.Contains(lowerSource, "apt"):
		snap.Subsystem = engine.OracleSubStorage
		snap.Action = engine.OracleActFileMutate
		if strings.Contains(lowerLine, "status half-installed") || strings.Contains(lowerLine, "error") {
			snap.HealthScore = 800
			snap.Severity = engine.SeverityMedium
		}

	case strings.Contains(lowerSource, "auth") || strings.Contains(lowerLine, "sshd") || strings.Contains(lowerLine, "sudo") || strings.Contains(lowerLine, "pam"):
		snap.Subsystem = engine.OracleSubAuth
		if strings.Contains(lowerLine, "failed password") || strings.Contains(lowerLine, "authentication failure") || strings.Contains(lowerLine, "invalid user") {
			snap.Action = engine.OracleActAuthFailure
			snap.HealthScore = 400
			snap.Severity = engine.SeverityHigh
		} else if strings.Contains(lowerLine, "accepted publickey") || strings.Contains(lowerLine, "session opened") {
			snap.Action = engine.OracleActStateNominal
			snap.HealthScore = 990
		}

	case strings.Contains(lowerSource, "kern") || strings.Contains(lowerSource, "dmesg") || strings.Contains(lowerLine, "kernel:"):
		snap.Subsystem = engine.OracleSubKernel
		if strings.Contains(lowerLine, "segfault") || strings.Contains(lowerLine, "out of memory") || strings.Contains(lowerLine, "panic") {
			snap.Action = engine.OracleActErrorFault
			snap.HealthScore = 200
			snap.Severity = engine.SeverityCritical
		} else if strings.Contains(lowerLine, "warn") || strings.Contains(lowerLine, "tainted") {
			snap.HealthScore = 700
			snap.Severity = engine.SeverityMedium
		}

	case strings.Contains(lowerSource, "ufw") || strings.Contains(lowerSource, "net") || strings.Contains(lowerLine, "[ufw block]"):
		snap.Subsystem = engine.OracleSubNet
		if strings.Contains(lowerLine, "block") {
			snap.Action = engine.OracleActAnomalyBurst
			snap.HealthScore = 750
			snap.Severity = engine.SeverityMedium
		}

	case strings.Contains(lowerSource, "c2_events") || strings.Contains(lowerSource, "c2blue"):
		snap.Subsystem = engine.OracleSubAgent
		if strings.Contains(lowerLine, "dns_tunnel") || strings.Contains(lowerLine, "drop") {
			snap.Action = engine.OracleActAnomalyBurst
			snap.HealthScore = 300
			snap.Severity = engine.SeverityHigh
		}
	}

	// 3. Entropie Shannon Q8.8 du texte brut, gabarit normalisé en charge
	raw := remLine
	if len(raw) > len(snap.RawPayload) {
		raw = raw[:len(snap.RawPayload)]
	}
	var profile engine.C2bt_entropy_profile_t
	engine.C2bt_profile_payload([]byte(raw), uint64(len(raw)), &profile)
	snap.EntropyQ8 = profile.Entropy_q8
	LogTemplate(&snap.RawPayload, remLine)

	// 4. Entité : acteur émetteur de la ligne, indépendant du nom de fichier
	snap.EntityID = LogActorID(LogActor(remLine, logSource))

	return snap, true
}
