package engine

// EmbeddingTable holds the input token embedding matrix as a single flat,
// contiguous float32 tensor laid out as [VocabSize*HiddenDim]. Each token row
// is contiguous, so a lookup is a straight memory copy that the Go compiler
// lowers to a vectorised block move, and the whole path performs no heap
// allocation.
type EmbeddingTable struct {
	// Weights is the flat embedding tensor of length VocabSize*HiddenDim,
	// aligned to 32 bytes by the caller for SIMD transfers.
	Weights []float32
	// VocabSize is the number of distinct token rows.
	VocabSize int
	// HiddenDim is the width of one embedding row in float32 words.
	HiddenDim int

	// PosWeights optionally holds absolute position embeddings of length
	// MaxPositions*HiddenDim. When non-nil with MaxPositions > 0 the fused
	// LookupSequenceWithPosition path adds one position row per token in a
	// single pass.
	PosWeights []float32
	// MaxPositions is the number of rows available in PosWeights.
	MaxPositions int
}

// NewEmbeddingTable allocates a zeroed contiguous table for vocabSize tokens of
// hiddenDim float32 words each. The backing slice is a single heap allocation.
func NewEmbeddingTable(vocabSize, hiddenDim int) *EmbeddingTable {
	if vocabSize < 0 {
		vocabSize = 0
	}
	if hiddenDim < 0 {
		hiddenDim = 0
	}
	return &EmbeddingTable{
		Weights:   make([]float32, vocabSize*hiddenDim),
		VocabSize: vocabSize,
		HiddenDim: hiddenDim,
	}
}

// LookupSequence copies the embedding row of each token into the matching
// HiddenDim-wide slot of outVectors. An out-of-range identifier, negative or
// >= VocabSize, falls back to the [UNK] row at index 0 without an index panic.
// At most len(outVectors)/HiddenDim rows are written.
func (t *EmbeddingTable) LookupSequence(tokenIDs []int32, outVectors []float32) {
	if t == nil || t.HiddenDim <= 0 || t.VocabSize <= 0 {
		return
	}
	hd := t.HiddenDim
	n := len(tokenIDs)
	if rows := len(outVectors) / hd; rows < n {
		n = rows
	}
	for i := 0; i < n; i++ {
		off := t.rowOffset(tokenIDs[i])
		if off < 0 {
			continue
		}
		copy(outVectors[i*hd:(i+1)*hd], t.Weights[off:off+hd])
	}
}

// LookupSequenceWithPosition behaves like LookupSequence but adds the absolute
// position embedding of positions[i] to token tokenIDs[i] in one fused pass,
// avoiding a second traversal of the output row. A missing or out-of-range
// position contributes nothing; positions is then treated as the row of index
// zero when PosWeights is present. The token bound fallback is unchanged.
func (t *EmbeddingTable) LookupSequenceWithPosition(tokenIDs []int32, positions []int, outVectors []float32) {
	if t == nil || t.HiddenDim <= 0 || t.VocabSize <= 0 {
		return
	}
	hd := t.HiddenDim
	n := len(tokenIDs)
	if rows := len(outVectors) / hd; rows < n {
		n = rows
	}
	hasPos := t.PosWeights != nil && t.MaxPositions > 0
	for i := 0; i < n; i++ {
		off := t.rowOffset(tokenIDs[i])
		if off < 0 {
			continue
		}
		dst := outVectors[i*hd : (i+1)*hd]
		if !hasPos {
			copy(dst, t.Weights[off:off+hd])
			continue
		}
		pos := 0
		if i < len(positions) {
			pos = positions[i]
		}
		if pos < 0 || pos >= t.MaxPositions {
			pos = 0
		}
		pOff := pos * hd
		if pOff < 0 || pOff+hd > len(t.PosWeights) {
			copy(dst, t.Weights[off:off+hd])
			continue
		}
		src := t.Weights[off : off+hd]
		pw := t.PosWeights[pOff : pOff+hd]
		for j := 0; j < hd; j++ {
			dst[j] = src[j] + pw[j]
		}
	}
}

// rowOffset resolves a token identifier to a valid flat row offset, falling
// back to row 0 for an out-of-range identifier or a malformed table. It returns
// -1 when no row can be addressed.
func (t *EmbeddingTable) rowOffset(tokenID int32) int {
	tok := int(tokenID)
	if tok < 0 || tok >= t.VocabSize {
		tok = 0
	}
	off := tok * t.HiddenDim
	if off < 0 || off+t.HiddenDim > len(t.Weights) {
		return -1
	}
	return off
}
