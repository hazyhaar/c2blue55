package engine

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/hazyhaar/c2slm/gguf"
	"github.com/hazyhaar/c2slm/tensor"
)

// N4Tensor describes one mapped interleaved matrix.
type N4Tensor struct {
	Rows, Cols int
	Data       []byte
	Bits       int
}

var ErrN4SidecarMismatch = errors.New("désaccord du compagnon N4")

func IsN4SidecarMismatch(err error) bool { return errors.Is(err, ErrN4SidecarMismatch) }
func (m *Model) N4Loaded() bool          { return m != nil && m.n4Loaded }
func (m *Model) closeN4Mapping() error {
	err := syscall.Munmap(m.n4Mapping)
	m.n4Mapping = nil
	m.n4Loaded = false
	return err
}

func projectionN4(nom string) bool {
	if !strings.HasPrefix(nom, "blk.") || !strings.HasSuffix(nom, ".weight") {
		return false
	}
	parties := strings.Split(nom, ".")
	if len(parties) != 4 {
		return false
	}
	var couche int
	if _, err := fmt.Sscanf(parties[1], "%d", &couche); err != nil || couche < 0 {
		return false
	}
	switch parties[2] {
	case "attn_q", "attn_k", "attn_v", "attn_output", "ffn_gate", "ffn_up", "ffn_down":
		return true
	}
	return false
}

func alignementN4(position uint64) uint64 { return (position + 63) &^ uint64(63) }

// ExportN4 writes a complete source-bound sidecar through a temporary file.
func ExportN4(ggufPath, sidecarPath string) error {
	return ExportNatif(ggufPath, sidecarPath, 4)
}

// ExportNatif écrit un compagnon de poids sur quatre ou cinq bits.
func ExportNatif(ggufPath, sidecarPath string, bits int) error {
	if bits != 4 && bits != 5 {
		return fmt.Errorf("compagnon natif : largeur %d invalide", bits)
	}
	tailleNatif := func(rows, cols int) int {
		if bits == 5 {
			return tensor.N5Size(rows, cols)
		}
		return tensor.N4Size(rows, cols)
	}
	source, err := gguf.Open(ggufPath)
	if err != nil {
		return err
	}
	defer source.Close()
	fichierSource, err := os.Open(ggufPath)
	if err != nil {
		return err
	}
	hachage := sha256.New()
	_, err = io.Copy(hachage, fichierSource)
	erreurFermeture := fichierSource.Close()
	if err == nil {
		err = erreurFermeture
	}
	if err != nil {
		return err
	}
	selection := make([]*gguf.TensorInfo, 0, len(source.Tensors))
	position := uint64(64)
	for i := range source.Tensors {
		matrice := &source.Tensors[i]
		if !projectionN4(matrice.Name) || len(matrice.Dimensions) != 2 {
			continue
		}
		cols, rows := matrice.Dimensions[0], matrice.Dimensions[1]
		if cols%256 != 0 || rows%4 != 0 {
			continue
		}
		if cols > uint64(int(^uint(0)>>1)) || rows > uint64(int(^uint(0)>>1)) || rows*cols > uint64(int(^uint(0)>>1)) {
			return fmt.Errorf("N4: dimensions excessives %s", matrice.Name)
		}
		if matrice.Type != gguf.GGMLTypeQ8_0 && matrice.Type != gguf.GGMLTypeQ5_0 && matrice.Type != gguf.GGMLTypeQ4_K {
			return fmt.Errorf("N4: type non pris en charge %s pour %s", matrice.Type, matrice.Name)
		}
		selection = append(selection, matrice)
		position += uint64(2 + len(matrice.Name) + 4 + 4 + 8 + 8)
	}
	if len(selection) > int(^uint32(0)) {
		return fmt.Errorf("N4: trop de tenseurs")
	}
	decalages := make([]uint64, len(selection))
	for i, matrice := range selection {
		position = alignementN4(position)
		decalages[i] = position
		position += uint64(tailleNatif(int(matrice.Dimensions[1]), int(matrice.Dimensions[0])))
	}
	temporaire, err := os.CreateTemp(filepath.Dir(sidecarPath), ".c2n4-*")
	if err != nil {
		return err
	}
	nomTemporaire := temporaire.Name()
	defer os.Remove(nomTemporaire)
	defer temporaire.Close()
	if err := temporaire.Chmod(0600); err != nil {
		return err
	}
	var entete [64]byte
	copy(entete[:8], []byte{'C', '2', 'N', '4', 0, 0, 0, 1})
	binary.LittleEndian.PutUint32(entete[8:], 1)
	binary.LittleEndian.PutUint32(entete[12:], uint32(bits))
	copy(entete[16:48], hachage.Sum(nil))
	binary.LittleEndian.PutUint32(entete[48:], uint32(len(selection)))
	binary.LittleEndian.PutUint32(entete[52:], 64)
	if _, err := temporaire.Write(entete[:]); err != nil {
		return err
	}
	for i, matrice := range selection {
		if len(matrice.Name) > int(^uint16(0)) {
			return fmt.Errorf("N4: nom trop long")
		}
		var entree [26]byte
		binary.LittleEndian.PutUint16(entree[:], uint16(len(matrice.Name)))
		if _, err := temporaire.Write(entree[:2]); err != nil {
			return err
		}
		if _, err := io.WriteString(temporaire, matrice.Name); err != nil {
			return err
		}
		binary.LittleEndian.PutUint32(entree[:4], uint32(matrice.Dimensions[1]))
		binary.LittleEndian.PutUint32(entree[4:8], uint32(matrice.Dimensions[0]))
		binary.LittleEndian.PutUint64(entree[8:16], decalages[i])
		binary.LittleEndian.PutUint64(entree[16:24], uint64(tailleNatif(int(matrice.Dimensions[1]), int(matrice.Dimensions[0]))))
		if _, err := temporaire.Write(entree[:24]); err != nil {
			return err
		}
	}
	for i, matrice := range selection {
		if _, err := temporaire.Seek(int64(decalages[i]), io.SeekStart); err != nil {
			return err
		}
		cols, rows := int(matrice.Dimensions[0]), int(matrice.Dimensions[1])
		poids := make([]float32, 4*cols)
		encodage := make([]byte, tailleNatif(4, cols))
		for groupe := 0; groupe < rows/4; groupe++ {
			for ligne := 0; ligne < 4; ligne++ {
				destination := poids[ligne*cols : (ligne+1)*cols]
				var tailleBloc int
				switch matrice.Type {
				case gguf.GGMLTypeQ8_0:
					tailleBloc = cols / 32 * tensor.BlockSizeQ8_0
				case gguf.GGMLTypeQ5_0:
					tailleBloc = cols / 32 * tensor.BlockSizeQ5_0
				case gguf.GGMLTypeQ4_K:
					tailleBloc = cols / 256 * tensor.BlockSizeQ4_K
				}
				debut := (groupe*4 + ligne) * tailleBloc
				if debut > len(matrice.Data) || tailleBloc > len(matrice.Data)-debut {
					return fmt.Errorf("N4: données tronquées %s", matrice.Name)
				}
				switch matrice.Type {
				case gguf.GGMLTypeQ8_0:
					tensor.DequantizeRowQ8_0(destination, matrice.Data[debut:debut+tailleBloc], cols)
				case gguf.GGMLTypeQ5_0:
					tensor.DequantizeRowQ5_0(destination, matrice.Data[debut:debut+tailleBloc], cols)
				case gguf.GGMLTypeQ4_K:
					tensor.DequantizeRowQ4_K(destination, matrice.Data[debut:debut+tailleBloc], cols)
				}
			}
			var err error
			if bits == 5 {
				err = tensor.QuantizeRowsN5(poids, 4, cols, encodage)
			} else {
				err = tensor.QuantizeRowsN4(poids, 4, cols, encodage)
			}
			if err != nil {
				return err
			}
			if _, err := temporaire.Write(encodage); err != nil {
				return err
			}
		}
	}
	if err := temporaire.Sync(); err != nil {
		return err
	}
	if err := temporaire.Close(); err != nil {
		return err
	}
	return os.Rename(nomTemporaire, sidecarPath)
}

// LoadN4Sidecar maps and validates the table and the complete tensor spans.
func LoadN4Sidecar(path string, ggufSHA [32]byte) (map[string]*N4Tensor, error) {
	tenseurs, _, err := loadN4Mapping(path, ggufSHA)
	return tenseurs, err
}

func loadN4Mapping(path string, ggufSHA [32]byte) (map[string]*N4Tensor, []byte, error) {
	fichier, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer fichier.Close()
	statut, err := fichier.Stat()
	if err != nil {
		return nil, nil, err
	}
	if statut.Size() < 64 || statut.Size() > int64(int(^uint(0)>>1)) {
		return nil, nil, fmt.Errorf("%w: taille", ErrN4SidecarMismatch)
	}
	contenu, err := syscall.Mmap(int(fichier.Fd()), 0, int(statut.Size()), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, nil, err
	}
	refus := func(message string) (map[string]*N4Tensor, []byte, error) {
		_ = syscall.Munmap(contenu)
		return nil, nil, fmt.Errorf("%w: %s", ErrN4SidecarMismatch, message)
	}
	if !bytes.Equal(contenu[:8], []byte{'C', '2', 'N', '4', 0, 0, 0, 1}) || binary.LittleEndian.Uint32(contenu[8:]) != 1 || !bytes.Equal(contenu[16:48], ggufSHA[:]) {
		return refus("en-tête ou SHA-256 source")
	}
	bits := int(binary.LittleEndian.Uint32(contenu[12:]))
	if bits == 0 {
		bits = 4
	}
	if bits != 4 && bits != 5 {
		return refus("largeur de quantification inconnue")
	}
	tailleBloc := uint64(80)
	if bits == 5 {
		tailleBloc = 96
	}
	compte := uint64(binary.LittleEndian.Uint32(contenu[48:]))
	position := uint64(binary.LittleEndian.Uint32(contenu[52:]))
	if position < 64 || position > uint64(len(contenu)) || compte > (uint64(len(contenu))-position)/26 {
		return refus("table hors limites")
	}
	tenseurs := make(map[string]*N4Tensor, compte)
	for i := uint64(0); i < compte; i++ {
		if position > uint64(len(contenu)) || 2 > uint64(len(contenu))-position {
			return refus("nom tronqué")
		}
		longueur := uint64(binary.LittleEndian.Uint16(contenu[position:]))
		position += 2
		if longueur > uint64(len(contenu))-position || 24 > uint64(len(contenu))-position-longueur {
			return refus("entrée tronquée")
		}
		nom := string(contenu[position : position+longueur])
		position += longueur
		rows := uint64(binary.LittleEndian.Uint32(contenu[position:]))
		cols := uint64(binary.LittleEndian.Uint32(contenu[position+4:]))
		debut := binary.LittleEndian.Uint64(contenu[position+8:])
		taille := binary.LittleEndian.Uint64(contenu[position+16:])
		position += 24
		if rows == 0 || cols == 0 || rows%4 != 0 || cols%256 != 0 || rows*cols > uint64(math.MaxInt) || taille != rows/4*(cols/32)*tailleBloc || debut%64 != 0 || debut > uint64(len(contenu)) || taille > uint64(len(contenu))-debut {
			return refus("données hors limites")
		}
		if _, ok := tenseurs[nom]; ok {
			return refus("nom en double")
		}
		tenseurs[nom] = &N4Tensor{Rows: int(rows), Cols: int(cols), Data: contenu[debut : debut+taille], Bits: bits}
	}
	return tenseurs, contenu, nil
}
