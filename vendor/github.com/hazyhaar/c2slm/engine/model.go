package engine

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"

	"github.com/hazyhaar/c2slm/gguf"
	"github.com/hazyhaar/c2slm/tensor"
)

// defaultRoPEBaseQwen3 is Qwen3's native RoPE frequency base (1e6). At a 16k
// context the sequence stays inside the 32k training window, so the table is
// built straight from this base with no RoPE scaling.
const defaultRoPEBaseQwen3 float32 = 1_000_000.0

// Layer contains all mapped weights and biases for one Transformer block
type Layer struct {
	Index                                int
	AttnNorm                             []float32 // [896]
	AttnQ                                *gguf.TensorInfo
	AttnQKV                              *gguf.TensorInfo
	AttnQBias                            []float32
	AttnQNorm                            []float32 // QK-Norm per-head (Qwen3)
	AttnK                                *gguf.TensorInfo
	AttnKBias                            []float32
	AttnKNorm                            []float32 // QK-Norm per-head (Qwen3)
	AttnV                                *gguf.TensorInfo
	AttnVBias                            []float32 // [128]
	AttnOut                              *gguf.TensorInfo
	FFNNorm                              []float32 // [896]
	FFNGate                              *gguf.TensorInfo
	FFNGateUp                            *gguf.TensorInfo
	FFNUp                                *gguf.TensorInfo
	FFNDown                              *gguf.TensorInfo
	AttnQN4, AttnKN4, AttnVN4, AttnOutN4 *N4Tensor
	AttnQKVN4                            *N4Tensor
	FFNGateN4, FFNUpN4, FFNDownN4        *N4Tensor
	FFNGateUpN4                          *N4Tensor
}

// fusionnerMatrices joins whole quantized rows without changing their order or encoding.
func fusionnerMatrices(matrices ...*gguf.TensorInfo) (*gguf.TensorInfo, error) {
	premiere := matrices[0]
	if premiere == nil || len(premiere.Dimensions) != 2 || premiere.Dimensions[1] == 0 {
		return nil, fmt.Errorf("fusion : matrice absente ou dimensions invalides")
	}
	colonnes := premiere.Dimensions[0]
	var lignes uint64
	var taille int
	for _, matrice := range matrices {
		if matrice == nil || len(matrice.Dimensions) != 2 || matrice.Dimensions[0] != colonnes || matrice.Type != premiere.Type || matrice.Dimensions[1] == 0 || len(matrice.Data)%int(matrice.Dimensions[1]) != 0 {
			return nil, fmt.Errorf("fusion : matrices incompatibles")
		}
		lignes += matrice.Dimensions[1]
		taille += len(matrice.Data)
	}
	donnees := make([]byte, taille)
	position := 0
	for _, matrice := range matrices {
		position += copy(donnees[position:], matrice.Data)
	}
	return &gguf.TensorInfo{Dimensions: []uint64{colonnes, lignes}, Type: premiere.Type, Data: donnees}, nil
}

func matricesCompatibles(matrices ...*gguf.TensorInfo) bool {
	if matrices[0] == nil {
		return false
	}
	for _, matrice := range matrices[1:] {
		if matrice == nil || matrice.Type != matrices[0].Type {
			return false
		}
	}
	return true
}

func fusionnerN4(matrices ...*N4Tensor) (*N4Tensor, error) {
	if matrices[0] == nil {
		return nil, fmt.Errorf("fusion N4 : matrice absente")
	}
	colonnes := matrices[0].Cols
	bits := matrices[0].Bits
	lignes, taille := 0, 0
	for _, matrice := range matrices {
		if matrice == nil || matrice.Cols != colonnes || matrice.Bits != bits || matrice.Rows%4 != 0 || (bits != 4 && bits != 5) || (bits == 4 && len(matrice.Data) != tensor.N4Size(matrice.Rows, colonnes)) || (bits == 5 && len(matrice.Data) != tensor.N5Size(matrice.Rows, colonnes)) {
			return nil, fmt.Errorf("fusion N4 : matrices incompatibles")
		}
		lignes += matrice.Rows
		taille += len(matrice.Data)
	}
	donnees := make([]byte, taille)
	position := 0
	for _, matrice := range matrices {
		position += copy(donnees[position:], matrice.Data)
	}
	return &N4Tensor{Rows: lignes, Cols: colonnes, Data: donnees, Bits: bits}, nil
}

// Model represents Qwen2.5-0.5B-Instruct architecture
type Model struct {
	EmbdLength int
	NumLayers  int
	NumHeads   int
	NumKVHeads int
	HeadDim    int
	FFNDim     int
	VocabSize  int
	RoPEBase   float32
	RMSNormEps float32

	TokenEmbd    *gguf.TensorInfo
	OutputNorm   []float32
	OutputWeight *gguf.TensorInfo
	RoPETable    *tensor.RoPETable

	Layers    []Layer
	GGUFFile  *gguf.File
	n4Mapping []byte
	n4Loaded  bool
}

// LoadModel loads Qwen2.5 weights and tensors from GGUF
func LoadModel(path string) (*Model, error) {
	gf, err := gguf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open gguf: %w", err)
	}

	embdLen, _ := gf.GetUint32("qwen2.embedding_length")
	if embdLen == 0 {
		embdLen, _ = gf.GetUint32("qwen3.embedding_length")
	}
	if embdLen == 0 {
		embdLen = 896
	}
	numLayers, _ := gf.GetUint32("qwen2.block_count")
	if numLayers == 0 {
		numLayers, _ = gf.GetUint32("qwen3.block_count")
	}
	if numLayers == 0 {
		numLayers = 24
	}
	numHeads, _ := gf.GetUint32("qwen2.attention.head_count")
	if numHeads == 0 {
		numHeads, _ = gf.GetUint32("qwen3.attention.head_count")
	}
	if numHeads == 0 {
		numHeads = 14
	}
	dimensionTete := embdLen / numHeads
	architectureTete := "qwen2"
	if architecture, ok := gf.GetString("general.architecture"); ok && architecture == "qwen3" {
		architectureTete = "qwen3"
	}
	if longueurCle, ok := gf.GetUint32(architectureTete + ".attention.key_length"); ok {
		if longueurCle == 0 {
			_ = gf.Close()
			return nil, fmt.Errorf("invalid %s.attention.key_length: zero", architectureTete)
		}
		dimensionTete = longueurCle
	}
	if longueurValeur, ok := gf.GetUint32(architectureTete + ".attention.value_length"); ok && longueurValeur != dimensionTete {
		_ = gf.Close()
		return nil, fmt.Errorf("%s.attention.value_length %d differs from key length %d", architectureTete, longueurValeur, dimensionTete)
	}
	numKVHeads, _ := gf.GetUint32("qwen2.attention.head_count_kv")
	if numKVHeads == 0 {
		numKVHeads, _ = gf.GetUint32("qwen3.attention.head_count_kv")
	}
	if numKVHeads == 0 {
		numKVHeads = 2
	}
	ffnDim, _ := gf.GetUint32("qwen2.feed_forward_length")
	if ffnDim == 0 {
		ffnDim, _ = gf.GetUint32("qwen3.feed_forward_length")
	}
	if ffnDim == 0 {
		ffnDim = 4864
	}
	ropeTheta, _ := gf.GetFloat32("qwen2.rope.freq_base")
	if ropeTheta == 0 {
		ropeTheta, _ = gf.GetFloat32("qwen3.rope.freq_base")
	}
	if ropeTheta == 0 {
		ropeTheta = defaultRoPEBaseQwen3
	}
	eps, _ := gf.GetFloat32("qwen2.attention.layer_norm_rms_epsilon")
	if eps == 0 {
		eps, _ = gf.GetFloat32("qwen3.attention.layer_norm_rms_epsilon")
	}
	if eps == 0 {
		eps = 1e-6
	}

	tokEmbd, ok := gf.TensorMap["token_embd.weight"]
	if !ok {
		return nil, fmt.Errorf("missing token_embd.weight")
	}
	vocabSize := int(tokEmbd.Dimensions[1])

	outNormTi, ok := gf.TensorMap["output_norm.weight"]
	if !ok {
		return nil, fmt.Errorf("missing output_norm.weight")
	}
	outNorm := bytesToF32(outNormTi.Data)

	outWeight, ok := gf.TensorMap["output.weight"]
	if !ok {
		// Tied embeddings fallback
		outWeight = tokEmbd
	}

	m := &Model{
		EmbdLength:   int(embdLen),
		NumLayers:    int(numLayers),
		NumHeads:     int(numHeads),
		NumKVHeads:   int(numKVHeads),
		HeadDim:      int(dimensionTete),
		FFNDim:       int(ffnDim),
		VocabSize:    vocabSize,
		RoPEBase:     ropeTheta,
		RMSNormEps:   eps,
		TokenEmbd:    tokEmbd,
		OutputNorm:   outNorm,
		OutputWeight: outWeight,
		RoPETable:    tensor.NewRoPETable(MaxContextLen, int(dimensionTete), ropeTheta),
		Layers:       make([]Layer, numLayers),
		GGUFFile:     gf,
	}

	for i := 0; i < int(numLayers); i++ {
		l := &m.Layers[i]
		l.Index = i

		// Attention Norm
		if ti, ok := gf.TensorMap[fmt.Sprintf("blk.%d.attn_norm.weight", i)]; ok {
			l.AttnNorm = bytesToF32(ti.Data)
		} else {
			return nil, fmt.Errorf("missing blk.%d.attn_norm.weight", i)
		}

		// Q, K, V weights and biases
		if ti, ok := gf.TensorMap[fmt.Sprintf("blk.%d.attn_q.weight", i)]; ok {
			l.AttnQ = ti
		}
		if ti, ok := gf.TensorMap[fmt.Sprintf("blk.%d.attn_q.bias", i)]; ok {
			l.AttnQBias = bytesToF32(ti.Data)
		}
		if ti, ok := gf.TensorMap[fmt.Sprintf("blk.%d.attn_q_norm.weight", i)]; ok {
			l.AttnQNorm = bytesToF32(ti.Data)
		}
		if ti, ok := gf.TensorMap[fmt.Sprintf("blk.%d.attn_k.weight", i)]; ok {
			l.AttnK = ti
		}
		if ti, ok := gf.TensorMap[fmt.Sprintf("blk.%d.attn_k.bias", i)]; ok {
			l.AttnKBias = bytesToF32(ti.Data)
		}
		if ti, ok := gf.TensorMap[fmt.Sprintf("blk.%d.attn_k_norm.weight", i)]; ok {
			l.AttnKNorm = bytesToF32(ti.Data)
		}
		if ti, ok := gf.TensorMap[fmt.Sprintf("blk.%d.attn_v.weight", i)]; ok {
			l.AttnV = ti
		}
		if ti, ok := gf.TensorMap[fmt.Sprintf("blk.%d.attn_v.bias", i)]; ok {
			l.AttnVBias = bytesToF32(ti.Data)
		}

		// Output projection
		if ti, ok := gf.TensorMap[fmt.Sprintf("blk.%d.attn_output.weight", i)]; ok {
			l.AttnOut = ti
		}

		// FFN Norm
		if ti, ok := gf.TensorMap[fmt.Sprintf("blk.%d.ffn_norm.weight", i)]; ok {
			l.FFNNorm = bytesToF32(ti.Data)
		}

		// FFN projections
		if ti, ok := gf.TensorMap[fmt.Sprintf("blk.%d.ffn_gate.weight", i)]; ok {
			l.FFNGate = ti
		}
		if ti, ok := gf.TensorMap[fmt.Sprintf("blk.%d.ffn_up.weight", i)]; ok {
			l.FFNUp = ti
		}
		if ti, ok := gf.TensorMap[fmt.Sprintf("blk.%d.ffn_down.weight", i)]; ok {
			l.FFNDown = ti
		}
		if matricesCompatibles(l.AttnQ, l.AttnK, l.AttnV) {
			l.AttnQKV, err = fusionnerMatrices(l.AttnQ, l.AttnK, l.AttnV)
			if err != nil {
				_ = m.Close()
				return nil, fmt.Errorf("couche %d QKV : %w", i, err)
			}
		}
		if matricesCompatibles(l.FFNGate, l.FFNUp) {
			l.FFNGateUp, err = fusionnerMatrices(l.FFNGate, l.FFNUp)
			if err != nil {
				_ = m.Close()
				return nil, fmt.Errorf("couche %d gate/up : %w", i, err)
			}
		}
	}
	compagnon := path + ".c2n4"
	if _, err := os.Stat(compagnon); err == nil {
		fichier, err := os.Open(path)
		if err != nil {
			_ = m.Close()
			return nil, err
		}
		empreinte := sha256.New()
		_, err = io.Copy(empreinte, fichier)
		erreurFermeture := fichier.Close()
		if err == nil {
			err = erreurFermeture
		}
		if err != nil {
			_ = m.Close()
			return nil, err
		}
		var shaGGUF [32]byte
		copy(shaGGUF[:], empreinte.Sum(nil))
		tenseurs, mapping, err := loadN4Mapping(compagnon, shaGGUF)
		if err != nil {
			_ = m.Close()
			return nil, err
		}
		m.n4Mapping = mapping
		for i := range m.Layers {
			couche := &m.Layers[i]
			prefixe := fmt.Sprintf("blk.%d.", i)
			couche.AttnQN4 = tenseurs[prefixe+"attn_q.weight"]
			couche.AttnKN4 = tenseurs[prefixe+"attn_k.weight"]
			couche.AttnVN4 = tenseurs[prefixe+"attn_v.weight"]
			couche.AttnOutN4 = tenseurs[prefixe+"attn_output.weight"]
			couche.FFNGateN4 = tenseurs[prefixe+"ffn_gate.weight"]
			couche.FFNUpN4 = tenseurs[prefixe+"ffn_up.weight"]
			couche.FFNDownN4 = tenseurs[prefixe+"ffn_down.weight"]
			couche.AttnQKVN4, err = fusionnerN4(couche.AttnQN4, couche.AttnKN4, couche.AttnVN4)
			if err != nil {
				_ = m.Close()
				return nil, fmt.Errorf("couche %d QKV N4 : %w", i, err)
			}
			couche.FFNGateUpN4, err = fusionnerN4(couche.FFNGateN4, couche.FFNUpN4)
			if err != nil {
				_ = m.Close()
				return nil, fmt.Errorf("couche %d gate/up N4 : %w", i, err)
			}
		}
		m.n4Loaded = true
	} else if !os.IsNotExist(err) {
		_ = m.Close()
		return nil, err
	}

	return m, nil
}

// Close releases mmap memory
func (m *Model) Close() error {
	if len(m.n4Mapping) != 0 {
		if err := m.closeN4Mapping(); err != nil {
			return err
		}
	}
	if m.GGUFFile != nil {
		return m.GGUFFile.Close()
	}
	return nil
}

// EmbedToken extracts and dequantizes token embedding into out float32 slice
func (m *Model) EmbedToken(out []float32, tokenID int32) {
	if int(tokenID) >= m.VocabSize || tokenID < 0 {
		tokenID = 0
	}
	switch m.TokenEmbd.Type {
	case gguf.GGMLTypeQ4_K:
		rowBytes := (m.EmbdLength / tensor.QK4_K) * tensor.BlockSizeQ4_K
		rowOffset := int(tokenID) * rowBytes
		tensor.DequantizeRowQ4_K(out, m.TokenEmbd.Data[rowOffset:rowOffset+rowBytes], m.EmbdLength)
	case gguf.GGMLTypeQ5_0:
		rowBytes := (m.EmbdLength / tensor.QK5_0) * tensor.BlockSizeQ5_0
		rowOffset := int(tokenID) * rowBytes
		tensor.DequantizeRowQ5_0(out, m.TokenEmbd.Data[rowOffset:rowOffset+rowBytes], m.EmbdLength)
	case gguf.GGMLTypeQ8_0:
		rowBytes := (m.EmbdLength / tensor.QK8_0) * tensor.BlockSizeQ8_0
		rowOffset := int(tokenID) * rowBytes
		tensor.DequantizeRowQ8_0(out, m.TokenEmbd.Data[rowOffset:rowOffset+rowBytes], m.EmbdLength)
	case gguf.GGMLTypeF32:
		rowBytes := m.EmbdLength * 4
		rowOffset := int(tokenID) * rowBytes
		data := m.TokenEmbd.Data[rowOffset : rowOffset+rowBytes]
		for i := 0; i < m.EmbdLength; i++ {
			bits := binary.LittleEndian.Uint32(data[i*4 : (i+1)*4])
			out[i] = math.Float32frombits(bits)
		}
	}
}

// DispatchGEMV performs GEMV based on tensor quantization type, using pool if non-nil
func DispatchGEMV(pool *WorkerPool, y []float32, ti *gguf.TensorInfo, x []float32, rows, cols int, n4 ...*N4Tensor) {
	if len(n4) > 0 && n4[0] != nil {
		if pool != nil {
			pool.ParallelGEMVN4(y, n4[0].Data, x, rows, cols, n4[0].Bits)
			return
		}
		// The standalone path uses a reusable stack buffer for supported dimensions.
		var tampon [16384 / 256 * tensor.BlockSizeQ8_K]byte
		tensor.QuantizeRowQ8_K(x, tampon[:], cols)
		if n4[0].Bits == 5 {
			tensor.GEMVN5Q8KRange(y, n4[0].Data, tampon[:], 0, rows/4, cols)
		} else {
			tensor.GEMVN4Q8KRange(y, n4[0].Data, tampon[:], 0, rows/4, cols)
		}
		return
	}
	if pool != nil {
		pool.ParallelGEMV(y, ti.Data, x, rows, cols, ti.Type)
		return
	}
	switch ti.Type {
	case gguf.GGMLTypeQ5_0:
		tensor.GEMVQ5_0(y, ti.Data, x, rows, cols)
	case gguf.GGMLTypeQ8_0:
		tensor.GEMVQ8_0(y, ti.Data, x, rows, cols)
	case gguf.GGMLTypeQ6_K:
		tensor.GEMVQ6_K(y, ti.Data, x, rows, cols)
	case gguf.GGMLTypeQ4_K:
		tensor.GEMVQ4_K(y, ti.Data, x, rows, cols)
	default:
		// Fallback zero
		for i := range y {
			y[i] = 0
		}
	}
}

func bytesToF32(b []byte) []float32 {
	n := len(b) / 4
	res := make([]float32, n)
	for i := 0; i < n; i++ {
		bits := binary.LittleEndian.Uint32(b[i*4 : (i+1)*4])
		res[i] = math.Float32frombits(bits)
	}
	return res
}
