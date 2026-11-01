package projlearn

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
)

const checkpointLimit = 256 << 20

// SaveCheckpoint écrit path de façon atomique (tmp + fsync + rename, 0600) :
// magic C2PL1, configuration, pas, corps float32 petit-boutien, SHA-256.
func SaveCheckpoint(path string, p *Params, cfg Config, step int) error {
	if p == nil || step < 0 {
		return ErrConfigContract
	}
	var body []byte
	body = append(body, "C2PL1"...)
	for _, dimension := range [6]int{cfg.EmbedDim, cfg.ConvOut, cfg.Kernel, cfg.Hidden, cfg.CodeBits, cfg.StructFeatures} {
		if dimension <= 0 || uint64(dimension) > math.MaxUint32 {
			return ErrConfigContract
		}
		body = binary.LittleEndian.AppendUint32(body, uint32(dimension))
	}
	body = binary.LittleEndian.AppendUint64(body, uint64(step))
	for _, slot := range paramSlots(p) {
		body = binary.LittleEndian.AppendUint32(body, uint32(len(slot)))
		for _, x := range slot {
			body = binary.LittleEndian.AppendUint32(body, math.Float32bits(x))
		}
	}
	digest := sha256.Sum256(body)
	body = append(body, digest[:]...)
	file, err := os.CreateTemp(filepath.Dir(path), ".c2pl-*.tmp")
	if err != nil {
		return fmt.Errorf("creation point de controle: %w", err)
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return fmt.Errorf("mode point de controle: %w", err)
	}
	if _, err := file.Write(body); err != nil {
		file.Close()
		return fmt.Errorf("ecriture point de controle: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("synchronisation point de controle: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("fermeture point de controle: %w", err)
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return fmt.Errorf("renommage point de controle: %w", err)
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("ouverture repertoire point de controle: %w", err)
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return fmt.Errorf("synchronisation repertoire point de controle: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("fermeture repertoire point de controle: %w", closeErr)
	}
	return nil
}

// LoadCheckpoint relit et vérifie magic, taille et SHA-256 avant de rendre.
func LoadCheckpoint(path string) (*Params, Config, int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, Config{}, 0, fmt.Errorf("ouverture point de controle: %w", err)
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, checkpointLimit+1))
	if err != nil {
		return nil, Config{}, 0, fmt.Errorf("lecture point de controle: %w", err)
	}
	if len(body) > checkpointLimit || len(body) < 5+6*4+8+9*4+32 || string(body[:5]) != "C2PL1" {
		return nil, Config{}, 0, fmt.Errorf("en-tete: %w", ErrCheckpointIntegrity)
	}
	digest := sha256.Sum256(body[:len(body)-32])
	if !bytes.Equal(body[len(body)-32:], digest[:]) {
		return nil, Config{}, 0, fmt.Errorf("empreinte: %w", ErrCheckpointIntegrity)
	}
	position := 5
	var dims [6]int
	for i := range dims {
		dims[i] = int(binary.LittleEndian.Uint32(body[position:]))
		position += 4
	}
	cfg := Config{dims[0], dims[1], dims[2], dims[3], dims[4], dims[5]}
	step64 := binary.LittleEndian.Uint64(body[position:])
	position += 8
	if step64 > uint64(math.MaxInt) || cfg.EmbedDim < 1 || cfg.EmbedDim > 1<<16 || cfg.ConvOut < 1 || cfg.ConvOut > 1<<16 || cfg.Kernel < 1 || cfg.Kernel > 1<<16 || cfg.Kernel%2 == 0 || cfg.Hidden < 1 || cfg.Hidden > 1<<16 || cfg.CodeBits < 1 || cfg.CodeBits > 512 || cfg.CodeBits%64 != 0 || cfg.StructFeatures < 1 || cfg.StructFeatures > 8 {
		return nil, Config{}, 0, fmt.Errorf("dimensions: %w", ErrCheckpointIntegrity)
	}
	expected := [9]uint64{256 * uint64(cfg.EmbedDim), uint64(cfg.ConvOut) * uint64(cfg.Kernel) * uint64(cfg.EmbedDim), uint64(cfg.ConvOut), uint64(cfg.Hidden) * (uint64(cfg.ConvOut) + uint64(cfg.StructFeatures)), uint64(cfg.Hidden), uint64(cfg.CodeBits) * uint64(cfg.Hidden), uint64(cfg.CodeBits), uint64(cfg.CodeBits), 1}
	for _, length := range expected {
		if length > checkpointLimit/4 {
			return nil, Config{}, 0, fmt.Errorf("taille: %w", ErrCheckpointIntegrity)
		}
	}
	p := &Params{}
	var slots [9][]float32
	for i := range slots {
		if position+4 > len(body)-32 {
			return nil, Config{}, 0, fmt.Errorf("taille: %w", ErrCheckpointIntegrity)
		}
		length := uint64(binary.LittleEndian.Uint32(body[position:]))
		position += 4
		if length != expected[i] || length*4 > uint64(len(body)-32-position) {
			return nil, Config{}, 0, fmt.Errorf("taille: %w", ErrCheckpointIntegrity)
		}
		slots[i] = make([]float32, int(length))
		for j := range slots[i] {
			slots[i][j] = math.Float32frombits(binary.LittleEndian.Uint32(body[position:]))
			position += 4
		}
	}
	if position != len(body)-32 {
		return nil, Config{}, 0, fmt.Errorf("taille: %w", ErrCheckpointIntegrity)
	}
	p.Embed, p.ConvW, p.ConvB, p.Dense1W, p.Dense1B, p.Dense2W, p.Dense2B, p.ReadoutW, p.ReadoutB = slots[0], slots[1], slots[2], slots[3], slots[4], slots[5], slots[6], slots[7], slots[8]
	return p, cfg, int(step64), nil
}
