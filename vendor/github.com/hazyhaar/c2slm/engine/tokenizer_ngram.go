package engine

// NgramTokenUNK, NgramTokenCLS and NgramTokenSEP are the three control token
// identifiers reserved by the byte n-gram tokenizer. Content n-grams are
// projected into the open range [NgramNumSpecial, VocabSize). A 64-bit hash
// that lands inside the reserved low range is folded to UNK, so a content
// token can never collide with CLS or SEP.
const (
	NgramTokenUNK   int32 = 0
	NgramTokenCLS   int32 = 1
	NgramTokenSEP   int32 = 2
	NgramNumSpecial int32 = 3
)

// FNV-1a 64-bit constants (Fowler-Noll-Vo). The 64-bit offset basis and prime
// are used verbatim so that the projection stays bit-reproducible across hosts.
const (
	fnvOffset64 uint64 = 14695981039346656037
	fnvPrime64  uint64 = 1099511628211
)

// NgramTokenizerConfig declares the byte n-gram tokenizer shape before any
// runtime work. VocabSize is expected to be a power of two so the projection
// reduces to a bitwise mask; MaxSeqLen bounds the emitted sequence length,
// including the CLS and SEP control tokens.
type NgramTokenizerConfig struct {
	NgramMin  int
	NgramMax  int
	VocabSize int
	MaxSeqLen int
}

// NgramTokenizer maps sliding byte n-grams to a compact fixed-size vocabulary
// with no heap allocation on the tokenization path. Sliding windows of order
// NgramMin..NgramMax are folded through a 64-bit FNV-1a hash and projected by
// a bitwise mask when VocabSize is a power of two, by an integer modulo
// otherwise.
type NgramTokenizer struct {
	cfg     NgramTokenizerConfig
	mask    uint64
	useMask bool
}

// NewNgramTokenizer normalises the supplied configuration and returns a ready
// tokenizer. Zero or inconsistent fields are repaired to deterministic
// defaults: NgramMin 2, NgramMax 3, VocabSize 8192, MaxSeqLen 256.
func NewNgramTokenizer(cfg NgramTokenizerConfig) *NgramTokenizer {
	if cfg.NgramMin < 1 {
		cfg.NgramMin = 2
	}
	if cfg.NgramMax < 1 {
		cfg.NgramMax = 3
	}
	if cfg.NgramMax < cfg.NgramMin {
		cfg.NgramMax = cfg.NgramMin
	}
	if cfg.VocabSize <= int(NgramNumSpecial) {
		cfg.VocabSize = 8192
	}
	if cfg.MaxSeqLen <= 0 {
		cfg.MaxSeqLen = 256
	}

	t := &NgramTokenizer{cfg: cfg}
	if cfg.VocabSize&(cfg.VocabSize-1) == 0 {
		t.useMask = true
		t.mask = uint64(cfg.VocabSize - 1)
	}
	return t
}

// Config returns the normalised configuration held by the tokenizer.
func (t *NgramTokenizer) Config() NgramTokenizerConfig {
	return t.cfg
}

// TokenizeInto converts input into token identifiers written to outTokenIDs
// and returns the number of identifiers produced. The sequence is framed by
// CLS and SEP and truncated to at most MaxSeqLen entries. The function reads
// the input in place, never copies it and performs no heap allocation.
//
// Emission is position-major: for each byte offset the sliding windows of
// increasing order (NgramMin..NgramMax) are emitted in order, feeding a single
// FNV-1a state as the window grows, before advancing to the next offset.
func (t *NgramTokenizer) TokenizeInto(input []byte, outTokenIDs []int32) int {
	if len(outTokenIDs) == 0 {
		return 0
	}

	limit := t.cfg.MaxSeqLen
	if len(outTokenIDs) < limit {
		limit = len(outTokenIDs)
	}
	if limit <= 0 {
		return 0
	}
	if limit < 2 {
		outTokenIDs[0] = NgramTokenCLS
		return 1
	}

	n := 0
	outTokenIDs[n] = NgramTokenCLS
	n++

	// One slot is held back so SEP always closes a bounded sequence.
	contentLimit := limit - 1
	minN := t.cfg.NgramMin
	maxN := t.cfg.NgramMax

	for i := 0; i < len(input) && n < contentLimit; i++ {
		remaining := len(input) - i
		orderMax := maxN
		if remaining < orderMax {
			orderMax = remaining
		}

		h := fnvOffset64
		for k := 0; k < orderMax; k++ {
			h ^= uint64(input[i+k])
			h *= fnvPrime64

			if k+1 >= minN {
				if n >= contentLimit {
					break
				}
				outTokenIDs[n] = t.project(h)
				n++
			}
		}
	}

	outTokenIDs[n] = NgramTokenSEP
	return n + 1
}

// project folds a 64-bit hash into the content vocabulary. Reserved low slots
// are reported as UNK rather than aliasing a control token.
func (t *NgramTokenizer) project(h uint64) int32 {
	var slot int32
	if t.useMask {
		slot = int32(h & t.mask)
	} else {
		slot = int32(h % uint64(t.cfg.VocabSize))
	}
	if slot < NgramNumSpecial {
		return NgramTokenUNK
	}
	return slot
}
