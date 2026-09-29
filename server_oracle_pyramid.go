package c2blue55

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

// PyramidRetentionDays est le nombre maximal de tranches lues pour condenser
// la pyramide : l'horizon le plus long, 365 jours, en compte au plus autant.
const PyramidRetentionDays = 365

// pyramidHorizonNames nomme chaque échelle dans les noms de fichiers
// pyramid_<machineID>_<horizon>.c2pyramid, dans l'ordre des bits DeltaScale*.
var pyramidHorizonNames = [engine.DeltaScaleCount]string{"4h", "12h", "24h", "7d", "30d", "120d", "365d"}

// PyramidHorizonName rend le nom d'horizon d'une échelle à un seul bit, et
// faux pour toute autre valeur.
func PyramidHorizonName(scale uint16) (string, bool) {
	for i, name := range pyramidHorizonNames {
		if scale == 1<<i {
			return name, true
		}
	}
	return "", false
}

// ParsePyramidHorizon rend l'échelle d'un nom d'horizon (« 24h », « 7d »…).
func ParsePyramidHorizon(name string) (uint16, bool) {
	i := slices.Index(pyramidHorizonNames[:], name)
	if i < 0 {
		return 0, false
	}
	return 1 << i, true
}

// PyramidFileName rend le nom de fichier de la pyramide d'une échelle.
func PyramidFileName(machineID uint64, scale uint16) (string, error) {
	name, ok := PyramidHorizonName(scale)
	if !ok {
		return "", fmt.Errorf("%w: 0x%04x", engine.ErrPyramidScale, scale)
	}
	return fmt.Sprintf("pyramid_%016x_%s.c2pyramid", machineID, name), nil
}

// MachineID rend l'identité de machine du silo.
func (s *DailyOracleSilo) MachineID() uint64 { return s.cfg.MachineID }

// StorageDir rend le répertoire de stockage du silo.
func (s *DailyOracleSilo) StorageDir() string { return s.cfg.StorageDir }

// LoadCondenseDays charge les maxDays dernières tranches scellées sous les
// mêmes filtres que BuildServerBaseline (voir loadBaselineDaysLocked) : machine,
// version et jour conformes au nom, sceau vérifié sous la clé du silo, tranche
// non saturée ou échantillonnée, et tranche sans anomalie si
// BaselineExcludeAnomalousDays est posé. Une tranche illisible est écartée.
// Les entrées sont rendues entières : CondensePrototypes applique lui-même le
// filtre de référence (sévérité, score, drapeaux).
func (s *DailyOracleSilo) LoadCondenseDays(maxDays int) ([]engine.CondenseDay, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	loaded, err := s.loadBaselineDaysLocked(maxDays)
	if err != nil {
		return nil, err
	}
	days := make([]engine.CondenseDay, 0, len(loaded))
	for _, d := range loaded {
		days = append(days, engine.CondenseDay{EpochDay: d.epochDay, Entries: d.entries})
	}
	return days, nil
}

// PyramidFile décrit une pyramide écrite par CondensePyramids.
type PyramidFile struct {
	Scale  uint16
	Path   string
	Header engine.PyramidHeader
	Len    int
	Stats  engine.CondenseStats
}

// CondensePyramids condense les tranches du silo (au plus PyramidRetentionDays)
// en une pyramide par échelle de cfg.Scales, par
// engine.CondensePyramidHierarchyStats, et écrit chacune, scellée sous key
// (SHA-256 si key est vide), dans pyramid_<machineID>_<horizon>.c2pyramid du
// répertoire de stockage. Chaque fichier est écrit à part puis renommé, si bien
// qu'un lecteur ne voit jamais une pyramide à moitié écrite.
func (s *DailyOracleSilo) CondensePyramids(cfg engine.CondenseConfig, key []byte) ([]PyramidFile, error) {
	days, err := s.LoadCondenseDays(PyramidRetentionDays)
	if err != nil {
		return nil, err
	}
	pyr, stats, err := engine.CondensePyramidHierarchyStats(days, cfg, s.cfg.MachineID)
	if err != nil {
		return nil, err
	}
	var out []PyramidFile
	for i := range engine.DeltaScaleCount {
		scale := uint16(1) << i
		p, ok := pyr[scale]
		if !ok {
			continue
		}
		name, err := PyramidFileName(s.cfg.MachineID, scale)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(s.cfg.StorageDir, name)
		if err := writePyramidAtomic(path, p, key); err != nil {
			return nil, err
		}
		out = append(out, PyramidFile{Scale: scale, Path: path, Header: p.Header(), Len: p.Len(), Stats: stats[scale]})
	}
	return out, nil
}

// writePyramidAtomic écrit la pyramide dans un fichier temporaire du même
// répertoire, le synchronise, puis le renomme sur path.
func writePyramidAtomic(path string, p *engine.Pyramid, key []byte) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()
	if err = p.SaveHMAC(tmp, key); err != nil {
		return err
	}
	if err = tmp.Sync(); err != nil {
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ErrPyramidFileScale refuse une pyramide dont l'en-tête contredit le nom.
var ErrPyramidFileScale = errors.New("c2pyramid: echelle de l'en-tete differente de celle du nom de fichier")

// LoadPyramids charge chaque pyramid_<machineID>_<horizon>.c2pyramid du
// répertoire de stockage sous key et les installe dans un moteur multi-échelle.
// Un fichier qui ne se charge pas (sceau, clé, machine, gardes) ou dont
// l'en-tête contredit le nom fait échouer le chargement entier : une pyramide
// forgée ne doit pas passer inaperçue en étant simplement omise. Rend aussi le
// masque des échelles installées.
func (s *DailyOracleSilo) LoadPyramids(key []byte) (*engine.MultiScalePyramid, uint16, error) {
	m := engine.NewMultiScalePyramid(s.cfg.MachineID)
	prefix := fmt.Sprintf("pyramid_%016x_", s.cfg.MachineID)
	matches, err := filepath.Glob(filepath.Join(s.cfg.StorageDir, prefix+"*.c2pyramid"))
	if err != nil {
		return nil, 0, err
	}
	slices.Sort(matches)
	for _, path := range matches {
		horizon := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), prefix), ".c2pyramid")
		scale, ok := ParsePyramidHorizon(horizon)
		if !ok {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			return nil, 0, err
		}
		p, err := engine.LoadPyramidHMAC(f, s.cfg.MachineID, key)
		_ = f.Close()
		if err != nil {
			return nil, 0, fmt.Errorf("%s: %w", path, err)
		}
		if p.Header().Scale != scale {
			return nil, 0, fmt.Errorf("%s: %w", path, ErrPyramidFileScale)
		}
		if err := m.Install(p); err != nil {
			return nil, 0, fmt.Errorf("%s: %w", path, err)
		}
	}
	return m, m.Scales(), nil
}
