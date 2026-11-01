package engine

import (
	"math"

	"github.com/hazyhaar/c2slm/gguf"
	"github.com/hazyhaar/c2slm/internal/simd"
	"github.com/hazyhaar/c2slm/tensor"
)

// PrefillTile is the number of tokens processed per tiled prefill step. A tile
// of 32 tokens keeps the whole activation working set cache-resident while
// amortizing each weight row fetch over 32 activations.
const PrefillTile = 32

// TileWorkspace holds the pre-allocated activation buffers for tiled prefill.
// Every buffer is laid out as PrefillTile contiguous rows so a single
// quantized weight row can be multiplied against all tile activations without
// any heap allocation in the prefill loop.
type TileWorkspace struct {
	X       []float32 // [PrefillTile * EmbdLength]
	NormX   []float32 // [PrefillTile * EmbdLength]
	Q       []float32 // [PrefillTile * NumHeads * HeadDim]
	QKV     []float32 // [PrefillTile * (NumHeads + 2*NumKVHeads) * HeadDim]
	K       []float32 // [PrefillTile * NumKVHeads * HeadDim]
	V       []float32 // [PrefillTile * NumKVHeads * HeadDim]
	AttnOut []float32 // [PrefillTile * NumHeads * HeadDim]
	Down    []float32 // [PrefillTile * EmbdLength]
	Gate    []float32 // [PrefillTile * FFNDim]
	GateUp  []float32 // [PrefillTile * 2 * FFNDim]
	Up      []float32 // [PrefillTile * FFNDim]
	Q8K     []byte    // [PrefillTile * q8kStride]
	Scratch []float32 // [MaxContextLen]
}

// Arena holds pre-allocated activation buffers to guarantee 0 heap allocation during forward pass
type Arena struct {
	X          []float32 // [896]
	NormX      []float32 // [896]
	Q          []float32 // [NumHeads * HeadDim]
	QKV        []float32 // [NumHeads*HeadDim + 2*NumKVHeads*HeadDim]
	K          []float32 // [128]
	V          []float32 // [128]
	AttnScores []float32 // [512]
	AttnOut    []float32 // [NumHeads * HeadDim]
	Gate       []float32 // [4864]
	GateUp     []float32 // [2 * FFNDim]
	Up         []float32 // [4864]
	Down       []float32 // [896]
	Logits     []float32 // [151936]
	Pool       *WorkerPool
	Tile       *TileWorkspace
}

// roundUp256 returns n rounded up to the next multiple of the K-quant block
// size (256 values).
func roundUp256(n int) int {
	if n%256 == 0 {
		return n
	}
	return (n/256 + 1) * 256
}

// NewArena allocates static activation workspace
func NewArena(m *Model) *Arena {
	kvDim := m.NumKVHeads * m.HeadDim
	dimensionRequete := m.NumHeads * m.HeadDim
	projection := make([]float32, dimensionRequete+2*kvDim)
	activation := make([]float32, 2*m.FFNDim)
	maxCols := m.EmbdLength
	if m.FFNDim > maxCols {
		maxCols = m.FFNDim
	}
	q8kStride := tensor.Q8KRowStride(roundUp256(maxCols))
	return &Arena{
		X:          make([]float32, m.EmbdLength),
		NormX:      make([]float32, m.EmbdLength),
		QKV:        projection,
		Q:          projection[:dimensionRequete],
		K:          projection[dimensionRequete : dimensionRequete+kvDim],
		V:          projection[dimensionRequete+kvDim:],
		AttnScores: make([]float32, MaxContextLen),
		AttnOut:    make([]float32, dimensionRequete),
		GateUp:     activation,
		Gate:       activation[:m.FFNDim],
		Up:         activation[m.FFNDim:],
		Down:       make([]float32, m.EmbdLength),
		Logits:     make([]float32, m.VocabSize),
		Pool:       NewWorkerPool(),
		Tile: &TileWorkspace{
			X:       make([]float32, PrefillTile*m.EmbdLength),
			NormX:   make([]float32, PrefillTile*m.EmbdLength),
			Q:       make([]float32, PrefillTile*dimensionRequete),
			QKV:     make([]float32, PrefillTile*(dimensionRequete+2*kvDim)),
			K:       make([]float32, PrefillTile*kvDim),
			V:       make([]float32, PrefillTile*kvDim),
			AttnOut: make([]float32, PrefillTile*dimensionRequete),
			Down:    make([]float32, PrefillTile*m.EmbdLength),
			Gate:    make([]float32, PrefillTile*m.FFNDim),
			GateUp:  make([]float32, PrefillTile*2*m.FFNDim),
			Up:      make([]float32, PrefillTile*m.FFNDim),
			Q8K:     make([]byte, PrefillTile*q8kStride),
			Scratch: make([]float32, MaxContextLen),
		},
	}
}

// Close gracefully terminates persistent background workers
func (a *Arena) Close() {
	if a != nil && a.Pool != nil {
		a.Pool.Close()
	}
}

// Forward computes one Transformer decoder step for the given token at position pos.
// It writes normalized hidden states into arena.NormX and returns it.
func Forward(m *Model, cache *KVCache, a *Arena, tokenID int32, pos int) []float32 {
	// 1. Embed input token
	m.EmbedToken(a.X, tokenID)

	headDim := m.HeadDim
	dimensionRequete := m.NumHeads * headDim
	scale := float32(1.0 / math.Sqrt(float64(headDim)))
	kvHeads := m.NumKVHeads

	// 2. Loop through all 24 Transformer layers
	for lIdx := 0; lIdx < m.NumLayers; lIdx++ {
		layer := &m.Layers[lIdx]

		// Pre-attention RMSNorm
		tensor.RMSNorm(a.NormX, a.X, layer.AttnNorm, m.RMSNormEps)

		// Q, K, V Projections
		if layer.AttnQKV != nil || layer.AttnQKVN4 != nil {
			DispatchGEMV(a.Pool, a.QKV, layer.AttnQKV, a.NormX, len(a.QKV), m.EmbdLength, layer.AttnQKVN4)
		} else {
			DispatchGEMV(a.Pool, a.Q, layer.AttnQ, a.NormX, dimensionRequete, m.EmbdLength, layer.AttnQN4)
			DispatchGEMV(a.Pool, a.K, layer.AttnK, a.NormX, kvHeads*headDim, m.EmbdLength, layer.AttnKN4)
			DispatchGEMV(a.Pool, a.V, layer.AttnV, a.NormX, kvHeads*headDim, m.EmbdLength, layer.AttnVN4)
		}
		tensor.AddBias(a.Q, layer.AttnQBias)
		tensor.AddBias(a.K, layer.AttnKBias)
		tensor.AddBias(a.V, layer.AttnVBias)

		// Per-head QK-Norm (Qwen3)
		if len(layer.AttnQNorm) > 0 {
			for h := 0; h < m.NumHeads; h++ {
				qHead := a.Q[h*headDim : (h+1)*headDim]
				tensor.RMSNorm(qHead, qHead, layer.AttnQNorm, m.RMSNormEps)
			}
		}
		if len(layer.AttnKNorm) > 0 {
			for h := 0; h < kvHeads; h++ {
				kHead := a.K[h*headDim : (h+1)*headDim]
				tensor.RMSNorm(kHead, kHead, layer.AttnKNorm, m.RMSNormEps)
			}
		}

		// RoPE NeoX with precomputed ARCHTIME cache (zero transcendental calls)
		if m.RoPETable != nil {
			m.RoPETable.Apply(a.Q, m.NumHeads, pos)
			m.RoPETable.Apply(a.K, kvHeads, pos)
		} else {
			tensor.RoPENeoX(a.Q, m.NumHeads, headDim, pos, m.RoPEBase)
			tensor.RoPENeoX(a.K, kvHeads, headDim, pos, m.RoPEBase)
		}

		// Store K, V in KV-Cache
		cache.StoreKV(lIdx, pos, a.K, a.V)

		// Multi-Head Attention with Grouped-Query Attention (14:2)
		DispatchAttention(a.Pool, a.AttnScores, cache, lIdx, pos, a.Q, a.AttnOut, m.NumHeads, kvHeads, headDim, scale)

		// Output projection W_o
		DispatchGEMV(a.Pool, a.Down, layer.AttnOut, a.AttnOut, m.EmbdLength, dimensionRequete, layer.AttnOutN4)

		// Residual connection
		for i := 0; i < m.EmbdLength; i++ {
			a.X[i] += a.Down[i]
		}

		// Pre-FFN RMSNorm
		tensor.RMSNorm(a.NormX, a.X, layer.FFNNorm, m.RMSNormEps)

		// FFN SwiGLU: gate = W_gate * normX, up = W_up * normX
		if layer.FFNGateUp != nil || layer.FFNGateUpN4 != nil {
			DispatchGEMV(a.Pool, a.GateUp, layer.FFNGateUp, a.NormX, 2*m.FFNDim, m.EmbdLength, layer.FFNGateUpN4)
		} else {
			DispatchGEMV(a.Pool, a.Gate, layer.FFNGate, a.NormX, m.FFNDim, m.EmbdLength, layer.FFNGateN4)
			DispatchGEMV(a.Pool, a.Up, layer.FFNUp, a.NormX, m.FFNDim, m.EmbdLength, layer.FFNUpN4)
		}

		tensor.SwiGLU(a.Gate, a.Gate, a.Up)

		// Down projection: down = W_down * hidden
		DispatchGEMV(a.Pool, a.Down, layer.FFNDown, a.Gate, m.EmbdLength, m.FFNDim, layer.FFNDownN4)

		// Residual connection
		for i := 0; i < m.EmbdLength; i++ {
			a.X[i] += a.Down[i]
		}
	}

	// Final RMSNorm
	tensor.RMSNorm(a.NormX, a.X, m.OutputNorm, m.RMSNormEps)

	return a.NormX
}

// DispatchGEMVTiled performs a tiled GEMV Y = W * X over the tile activation
// rows, based on the tensor quantization type, using the worker pool when
// non-nil. y holds K output rows of stride yStride, x holds K input rows of
// stride xStride. For K-quantized weights the K input rows are first quantized
// to Q8_K into the tile buffer.
func DispatchGEMVTiled(pool *WorkerPool, tile *TileWorkspace, y []float32, yStride int, ti *gguf.TensorInfo, x []float32, xStride, rows, cols, k int) {
	if pool != nil {
		pool.ParallelGEMVTiled(y, yStride, ti.Data, x, xStride, rows, cols, k, ti.Type,
			tile.Q8K, tensor.Q8KRowStride(cols))
		return
	}
	switch ti.Type {
	case gguf.GGMLTypeQ5_0:
		tensor.GEMVTiledQ5_0Range(y, yStride, ti.Data, x, xStride, 0, rows, cols, k)
	case gguf.GGMLTypeQ8_0:
		tensor.GEMVTiledQ8_0Range(y, yStride, ti.Data, x, xStride, 0, rows, cols, k)
	case gguf.GGMLTypeQ6_K:
		q8kStride := tensor.Q8KRowStride(cols)
		tensor.QuantizeRowsQ8_K(x, xStride, tile.Q8K, q8kStride, k, cols)
		tensor.GEMVTiledQ6_K_Q8_KRange(y, yStride, ti.Data, tile.Q8K, q8kStride, 0, rows, cols, k)
	case gguf.GGMLTypeQ4_K:
		q8kStride := tensor.Q8KRowStride(cols)
		tensor.QuantizeRowsQ8_K(x, xStride, tile.Q8K, q8kStride, k, cols)
		tensor.GEMVTiledQ4_K_Q8_KRange(y, yStride, ti.Data, tile.Q8K, q8kStride, 0, rows, cols, k)
	default:
		for j := 0; j < k; j++ {
			for r := 0; r < rows; r++ {
				y[j*yStride+r] = 0
			}
		}
	}
}

// ForwardTile computes one Transformer decoder step for a whole tile of tokens
// starting at position startPos, writing the K/V pairs into the cache at their
// respective positions and returning the normalized hidden state of the last
// token (aliasing the tile arena, valid until the next ForwardTile call). The
// token slice may be longer than PrefillTile: it is then walked in successive
// sub-tiles so the pre-allocated tile workspace is never exceeded.
func ForwardTile(m *Model, cache *KVCache, a *Arena, tokens []int32, startPos int) []float32 {
	var last []float32
	for off := 0; off < len(tokens); off += PrefillTile {
		end := off + PrefillTile
		if end > len(tokens) {
			end = len(tokens)
		}
		last = forwardTileOnce(m, cache, a, tokens[off:end], startPos+off)
	}
	return last
}

// forwardTileOnce computes the tiled decoder step for a tile of at most
// PrefillTile tokens. The computation is layer-major and causal: within a layer
// every token's Q/K/V projection is a tiled GEMV that fetches each weight row
// once, then the tokens are walked in order so token i only attends to
// positions <= startPos+i. Each per-token operation is identical in order and
// values to the sequential Forward, so the results are bit-exact.
func forwardTileOnce(m *Model, cache *KVCache, a *Arena, tokens []int32, startPos int) []float32 {
	k := len(tokens)
	if k == 0 {
		return nil
	}
	tile := a.Tile

	embd := m.EmbdLength
	headDim := m.HeadDim
	dimensionRequete := m.NumHeads * headDim
	kvDim := m.NumKVHeads * headDim
	kvHeads := m.NumKVHeads
	scale := float32(1.0 / math.Sqrt(float64(headDim)))

	// 1. Embed every token of the tile into its own row.
	for j := 0; j < k; j++ {
		m.EmbedToken(tile.X[j*embd:(j+1)*embd], tokens[j])
	}

	// 2. Loop through all Transformer layers, layer-major.
	for lIdx := 0; lIdx < m.NumLayers; lIdx++ {
		layer := &m.Layers[lIdx]

		// Pre-attention RMSNorm for every token.
		for j := 0; j < k; j++ {
			tensor.RMSNorm(tile.NormX[j*embd:(j+1)*embd], tile.X[j*embd:(j+1)*embd], layer.AttnNorm, m.RMSNormEps)
		}

		// Q, K, V projections as tiled GEMV: each weight row is loaded once
		// and multiplied against all k activation rows.
		projectionStride := dimensionRequete + 2*kvDim
		if layer.AttnQKV != nil {
			DispatchGEMVTiled(a.Pool, tile, tile.QKV, projectionStride, layer.AttnQKV, tile.NormX, embd, projectionStride, embd, k)
		} else {
			DispatchGEMVTiled(a.Pool, tile, tile.Q, dimensionRequete, layer.AttnQ, tile.NormX, embd, dimensionRequete, embd, k)
			DispatchGEMVTiled(a.Pool, tile, tile.K, kvDim, layer.AttnK, tile.NormX, embd, kvDim, embd, k)
			DispatchGEMVTiled(a.Pool, tile, tile.V, kvDim, layer.AttnV, tile.NormX, embd, kvDim, embd, k)
		}

		// Bias, QK-Norm, RoPE, KV store and causal attention, walked in token
		// order so causality inside the tile is preserved.
		for j := 0; j < k; j++ {
			pos := startPos + j
			q := tile.QKV[j*projectionStride : j*projectionStride+dimensionRequete]
			kk := tile.QKV[j*projectionStride+dimensionRequete : j*projectionStride+dimensionRequete+kvDim]
			vv := tile.QKV[j*projectionStride+dimensionRequete+kvDim : (j+1)*projectionStride]
			if layer.AttnQKV == nil {
				q = tile.Q[j*dimensionRequete : (j+1)*dimensionRequete]
				kk = tile.K[j*kvDim : (j+1)*kvDim]
				vv = tile.V[j*kvDim : (j+1)*kvDim]
			}

			tensor.AddBias(q, layer.AttnQBias)
			tensor.AddBias(kk, layer.AttnKBias)
			tensor.AddBias(vv, layer.AttnVBias)

			if len(layer.AttnQNorm) > 0 {
				for h := 0; h < m.NumHeads; h++ {
					qHead := q[h*headDim : (h+1)*headDim]
					tensor.RMSNorm(qHead, qHead, layer.AttnQNorm, m.RMSNormEps)
				}
			}
			if len(layer.AttnKNorm) > 0 {
				for h := 0; h < kvHeads; h++ {
					kHead := kk[h*headDim : (h+1)*headDim]
					tensor.RMSNorm(kHead, kHead, layer.AttnKNorm, m.RMSNormEps)
				}
			}

			if m.RoPETable != nil {
				m.RoPETable.Apply(q, m.NumHeads, pos)
				m.RoPETable.Apply(kk, kvHeads, pos)
			} else {
				tensor.RoPENeoX(q, m.NumHeads, headDim, pos, m.RoPEBase)
				tensor.RoPENeoX(kk, kvHeads, headDim, pos, m.RoPEBase)
			}

			cache.StoreKV(lIdx, pos, kk, vv)

			DispatchAttention(a.Pool, tile.Scratch, cache, lIdx, pos, q,
				tile.AttnOut[j*dimensionRequete:(j+1)*dimensionRequete], m.NumHeads, kvHeads, headDim, scale)
		}

		// Output projection W_o as tiled GEMV, then residual.
		DispatchGEMVTiled(a.Pool, tile, tile.Down, embd, layer.AttnOut, tile.AttnOut, dimensionRequete, embd, dimensionRequete, k)
		for j := 0; j < k; j++ {
			x := tile.X[j*embd : (j+1)*embd]
			d := tile.Down[j*embd : (j+1)*embd]
			for i := 0; i < embd; i++ {
				x[i] += d[i]
			}
		}

		// Pre-FFN RMSNorm for every token.
		for j := 0; j < k; j++ {
			tensor.RMSNorm(tile.NormX[j*embd:(j+1)*embd], tile.X[j*embd:(j+1)*embd], layer.FFNNorm, m.RMSNormEps)
		}

		// FFN SwiGLU as tiled GEMV.
		if layer.FFNGateUp != nil {
			DispatchGEMVTiled(a.Pool, tile, tile.GateUp, 2*m.FFNDim, layer.FFNGateUp, tile.NormX, embd, 2*m.FFNDim, embd, k)
		} else {
			DispatchGEMVTiled(a.Pool, tile, tile.Gate, m.FFNDim, layer.FFNGate, tile.NormX, embd, m.FFNDim, embd, k)
			DispatchGEMVTiled(a.Pool, tile, tile.Up, m.FFNDim, layer.FFNUp, tile.NormX, embd, m.FFNDim, embd, k)
		}
		for j := 0; j < k; j++ {
			g := tile.GateUp[j*2*m.FFNDim : j*2*m.FFNDim+m.FFNDim]
			u := tile.GateUp[j*2*m.FFNDim+m.FFNDim : (j+1)*2*m.FFNDim]
			if layer.FFNGateUp == nil {
				g = tile.Gate[j*m.FFNDim : (j+1)*m.FFNDim]
				u = tile.Up[j*m.FFNDim : (j+1)*m.FFNDim]
			}
			tensor.SwiGLU(g, g, u)
			if layer.FFNGateUp != nil {
				copy(tile.Gate[j*m.FFNDim:(j+1)*m.FFNDim], g)
			}
		}

		// Down projection as tiled GEMV, then residual.
		DispatchGEMVTiled(a.Pool, tile, tile.Down, embd, layer.FFNDown, tile.Gate, m.FFNDim, embd, m.FFNDim, k)
		for j := 0; j < k; j++ {
			x := tile.X[j*embd : (j+1)*embd]
			d := tile.Down[j*embd : (j+1)*embd]
			for i := 0; i < embd; i++ {
				x[i] += d[i]
			}
		}
	}

	// Final RMSNorm of the last token, mirroring the sequential Forward which
	// only exposes the hidden state of the token that completes the step.
	lastX := tile.X[(k-1)*embd : k*embd]
	lastNormX := tile.NormX[(k-1)*embd : k*embd]
	tensor.RMSNorm(lastNormX, lastX, m.OutputNorm, m.RMSNormEps)
	return lastNormX
}

// attentionHead computes one query head against its Grouped-Query KV head:
// scaled Q@K scores, softmax, then the weighted sum Attn@V. Both products are
// delegated to the AVX2 micro-kernels; scores is caller-owned scratch.
func attentionHead(cache *KVCache, layer, pos int, q, out []float32, h, qPerKV, headDim int, scale float32, scores []float32) {
	kvHead := h / qPerKV
	qHead := q[h*headDim : (h+1)*headDim]

	kOff := cache.getOffset(false, layer, kvHead, 0)
	vOff := cache.getOffset(true, layer, kvHead, 0)

	simd.C2_tensor_attn_qk(qHead, cache.Data[kOff:], int32(pos), int32(headDim), scale, scores, int32(headDim))
	tensor.Softmax(scores[:pos+1])

	outHead := out[h*headDim : (h+1)*headDim]
	simd.C2_tensor_attn_av(scores, cache.Data[vOff:], int32(pos), int32(headDim), outHead, int32(headDim))
}

// DispatchAttention runs attention with the pool when available, falling back
// to a sequential head loop on the caller-owned scratch otherwise.
func DispatchAttention(pool *WorkerPool, scratch []float32, cache *KVCache, layer, pos int, q, out []float32, numHeads, kvHeads, headDim int, scale float32) {
	if pool != nil {
		pool.ParallelAttention(scratch, cache, layer, pos, q, out, numHeads, kvHeads, headDim, scale)
		return
	}
	qPerKV := numHeads / kvHeads
	for h := 0; h < numHeads; h++ {
		attentionHead(cache, layer, pos, q, out, h, qPerKV, headDim, scale, scratch[:pos+1])
	}
}

// ComputeLogits projects final hidden states to vocabulary logits (or restricted tokens)
func ComputeLogits(m *Model, a *Arena, normX []float32, outLogits []float32, targetTokens []int32) {
	cols := m.EmbdLength

	if len(targetTokens) > 0 {
		// ARCHTIME restricted projection: only compute for requested tokens
		for _, tokID := range targetTokens {
			if int(tokID) >= m.VocabSize || tokID < 0 {
				continue
			}
			outLogits[tokID] = computeSingleTokenLogit(m, normX, int(tokID), cols)
		}
		return
	}

	// Full vocabulary projection parallelized over worker pool
	var pool *WorkerPool
	if a != nil {
		pool = a.Pool
	}
	DispatchGEMV(pool, outLogits, m.OutputWeight, normX, m.VocabSize, cols)
}

func computeSingleTokenLogit(m *Model, normX []float32, tokID, cols int) float32 {
	switch m.OutputWeight.Type {
	case gguf.GGMLTypeQ8_0:
		rowBytes := (cols / tensor.QK8_0) * tensor.BlockSizeQ8_0
		rowOffset := tokID * rowBytes
		return tensor.DotQ8_0(m.OutputWeight.Data[rowOffset:rowOffset+rowBytes], normX, cols)
	case gguf.GGMLTypeQ5_0:
		rowBytes := (cols / tensor.QK5_0) * tensor.BlockSizeQ5_0
		rowOffset := tokID * rowBytes
		return tensor.DotQ5_0(m.OutputWeight.Data[rowOffset:rowOffset+rowBytes], normX, cols)
	case gguf.GGMLTypeQ6_K:
		rowBytes := (cols / tensor.QK6_K) * tensor.BlockSizeQ6_K
		rowOffset := tokID * rowBytes
		return tensor.DotQ6_K(m.OutputWeight.Data[rowOffset:rowOffset+rowBytes], normX, cols)
	case gguf.GGMLTypeQ4_K:
		rowBytes := (cols / tensor.QK4_K) * tensor.BlockSizeQ4_K
		rowOffset := tokID * rowBytes
		return tensor.DotQ4_K(m.OutputWeight.Data[rowOffset:rowOffset+rowBytes], normX, cols)
	}
	return 0
}
