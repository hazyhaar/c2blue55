package engine

import (
	"context"
	"math"

	"github.com/hazyhaar/c2slm/internal/simd"
	"github.com/hazyhaar/c2slm/tensor"
)

// EncoderBlockConfig décrit la géométrie d'un bloc d'encodage Transformer de
// type DeBERTa. HiddenDim est la largeur du flux résiduel, IntermediateDim la
// largeur de la couche feed-forward, NumHeads le nombre de têtes d'attention et
// MaxRelDist la distance relative maximale k de l'attention désentrelacée.
// LayerNormEps stabilise la normalisation.
type EncoderBlockConfig struct {
	HiddenDim       int
	IntermediateDim int
	NumHeads        int
	MaxRelDist      int
	LayerNormEps    float32
}

// HeadDim retourne la largeur d'une tête d'attention. La division est exacte
// lorsque la configuration est valide.
func (c EncoderBlockConfig) HeadDim() int {
	if c.NumHeads <= 0 {
		return 0
	}
	return c.HiddenDim / c.NumHeads
}

// RelTableLen retourne le nombre d'entrées de la table de position relative,
// soit 2*k+1.
func (c EncoderBlockConfig) RelTableLen() int {
	return 2*c.MaxRelDist + 1
}

// Validate vérifie les invariants géométriques. La largeur cachée doit être un
// multiple de 64 pour rester alignée sur les blocs AVX2, et divisible par le
// nombre de têtes.
func (c EncoderBlockConfig) Validate() bool {
	if c.HiddenDim <= 0 || c.HiddenDim%64 != 0 {
		return false
	}
	if c.NumHeads <= 0 || c.HiddenDim%c.NumHeads != 0 {
		return false
	}
	if c.IntermediateDim <= 0 {
		return false
	}
	if c.MaxRelDist < 0 {
		return false
	}
	return true
}

// EncoderBlockWeights regroupe les tenseurs d'un bloc. Les matrices sont en
// disposition ligne-major [lignes*colonnes]. Les biais sont optionnels : un
// biais nil est traité comme un vecteur nul.
type EncoderBlockWeights struct {
	// Attention : projections requête, clé, valeur et sortie.
	Wq   []float32
	Bq   []float32
	Wk   []float32
	Bk   []float32
	Wv   []float32
	Bv   []float32
	Wout []float32
	Bout []float32

	// Feed-forward à activation GELU.
	WIntermediate []float32
	BIntermediate []float32
	WOutput       []float32
	BOutput       []float32

	// Normalisations post-attention (1) et post-feed-forward (2).
	Gamma1 []float32
	Beta1  []float32
	Gamma2 []float32
	Beta2  []float32
}

// EncoderBlock assemble la configuration, les poids et le facteur d'échelle
// d'un bloc d'encodage.
type EncoderBlock struct {
	Config  EncoderBlockConfig
	Weights EncoderBlockWeights
	scale   float32
}

// NewEncoderBlock construit un bloc à partir de sa configuration et de ses
// poids. Le facteur d'échelle de l'attention vaut 1/sqrt(d_h) et est calculé une
// seule fois hors du chemin chaud.
func NewEncoderBlock(cfg EncoderBlockConfig, w EncoderBlockWeights) *EncoderBlock {
	headDim := cfg.HeadDim()
	scale := float32(1)
	if headDim > 0 {
		scale = float32(1.0 / math.Sqrt(float64(headDim)))
	}
	return &EncoderBlock{Config: cfg, Weights: w, scale: scale}
}

// EncoderScratch est le tampon de travail préalloué du bloc. Toutes les vues
// partielles sont des sous-tranches de ces tranches, de sorte que Forward
// n'effectue aucune allocation sur le tas.
type EncoderScratch struct {
	SeqLen int

	Norm1 []float32 // [SeqLen*HiddenDim]
	Norm2 []float32 // [SeqLen*HiddenDim]

	Q []float32 // [SeqLen*HiddenDim]
	K []float32 // [SeqLen*HiddenDim]
	V []float32 // [SeqLen*HiddenDim]

	HeadQ   []float32 // [SeqLen*HeadDim]
	HeadK   []float32 // [SeqLen*HeadDim]
	HeadV   []float32 // [SeqLen*HeadDim]
	HeadOut []float32 // [SeqLen*HeadDim]

	Heads  []float32 // [SeqLen*HiddenDim]
	Attn   []float32 // [SeqLen*HiddenDim]
	Scores []float32 // [SeqLen*SeqLen]
	PP     []float32 // [2*MaxRelDist+1]

	Inter []float32 // [SeqLen*IntermediateDim]
	FFN   []float32 // [SeqLen*HiddenDim]
	Out   []float32 // [SeqLen*HiddenDim]
}

// NewEncoderScratch alloue une fois pour toutes les tampons nécessaires à une
// séquence de seqLen positions.
func NewEncoderScratch(cfg EncoderBlockConfig, seqLen int) *EncoderScratch {
	if seqLen < 0 {
		seqLen = 0
	}
	hidden := cfg.HiddenDim
	headDim := cfg.HeadDim()
	return &EncoderScratch{
		SeqLen:  seqLen,
		Norm1:   make([]float32, seqLen*hidden),
		Norm2:   make([]float32, seqLen*hidden),
		Q:       make([]float32, seqLen*hidden),
		K:       make([]float32, seqLen*hidden),
		V:       make([]float32, seqLen*hidden),
		HeadQ:   make([]float32, seqLen*headDim),
		HeadK:   make([]float32, seqLen*headDim),
		HeadV:   make([]float32, seqLen*headDim),
		HeadOut: make([]float32, seqLen*headDim),
		Heads:   make([]float32, seqLen*hidden),
		Attn:    make([]float32, seqLen*hidden),
		Scores:  make([]float32, seqLen*seqLen),
		PP:      make([]float32, cfg.RelTableLen()),
		Inter:   make([]float32, seqLen*cfg.IntermediateDim),
		FFN:     make([]float32, seqLen*hidden),
		Out:     make([]float32, seqLen*hidden),
	}
}

// suitableFor vérifie que le tampon couvre la configuration et la longueur de
// séquence demandées, sans allocation.
func (s *EncoderScratch) suitableFor(cfg EncoderBlockConfig, seqLen int) bool {
	if s == nil || s.SeqLen < seqLen {
		return false
	}
	hidden := cfg.HiddenDim
	headDim := cfg.HeadDim()
	return len(s.Norm1) >= seqLen*hidden &&
		len(s.Q) >= seqLen*hidden &&
		len(s.K) >= seqLen*hidden &&
		len(s.V) >= seqLen*hidden &&
		len(s.HeadQ) >= seqLen*headDim &&
		len(s.HeadK) >= seqLen*headDim &&
		len(s.HeadV) >= seqLen*headDim &&
		len(s.HeadOut) >= seqLen*headDim &&
		len(s.Heads) >= seqLen*hidden &&
		len(s.Attn) >= seqLen*hidden &&
		len(s.Scores) >= seqLen*seqLen &&
		len(s.PP) >= cfg.RelTableLen() &&
		len(s.Inter) >= seqLen*cfg.IntermediateDim &&
		len(s.FFN) >= seqLen*hidden &&
		len(s.Out) >= seqLen*hidden
}

// denseMatVec calcule y = W*x + b pour une matrice ligne-major W de dimensions
// [rows, cols] et un vecteur x de longueur cols. Aucune allocation.
func denseMatVec(y, w, x, b []float32, rows, cols int) {
	for r := 0; r < rows; r++ {
		row := w[r*cols : (r+1)*cols]
		var acc float32
		for c := 0; c < cols; c++ {
			acc += row[c] * x[c]
		}
		if len(b) >= rows {
			acc += b[r]
		}
		y[r] = acc
	}
}

// Forward applique le chaînage complet d'un bloc d'encodage :
//
//	x_norm1 = LayerNorm(x)
//	attn    = AttentionDésentrelacée(x_norm1, posK, posQ)
//	x_res1  = x + attn
//	x_norm2 = LayerNorm(x_res1)
//	ffn     = W_out * GELU(W_inter * x_norm2)
//	x_res2  = x_res1 + ffn
//
// x est la séquence aplatie [SeqLen*HiddenDim]. posK et posQ sont les tables de
// position relative en disposition tête-major [NumHeads, 2*MaxRelDist+1,
// HeadDim]. La sortie pointe vers scratch.Out et ne provoque aucune allocation.
// Le tampon peut couvrir une séquence plus longue que celle fournie.
func (b *EncoderBlock) Forward(ctx context.Context, x []float32, posK, posQ []float32, scratch *EncoderScratch) []float32 {
	if b == nil {
		return nil
	}
	cfg := b.Config
	hidden := cfg.HiddenDim
	headDim := cfg.HeadDim()
	headCount := cfg.NumHeads
	relLen := cfg.RelTableLen()

	if hidden <= 0 || headDim <= 0 || headCount <= 0 {
		return nil
	}
	seqLen := len(x) / hidden
	if seqLen == 0 {
		return nil
	}
	if !scratch.suitableFor(cfg, seqLen) {
		return nil
	}
	if len(posK) < headCount*relLen*headDim || len(posQ) < headCount*relLen*headDim {
		return nil
	}
	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}

	w := &b.Weights
	eps := cfg.LayerNormEps
	interDim := cfg.IntermediateDim
	attnScale := b.scale

	norm1 := scratch.Norm1
	norm2 := scratch.Norm2
	qBuf := scratch.Q
	kBuf := scratch.K
	vBuf := scratch.V
	heads := scratch.Heads
	attn := scratch.Attn
	scores := scratch.Scores
	pp := scratch.PP
	inter := scratch.Inter
	ffn := scratch.FFN
	out := scratch.Out

	// 1. Normalisation pré-attention puis projections requête/clé/valeur.
	for p := 0; p < seqLen; p++ {
		xRow := x[p*hidden : (p+1)*hidden]
		n1Row := norm1[p*hidden : (p+1)*hidden]
		simd.C2_tensor_layernorm(xRow, w.Gamma1, w.Beta1, n1Row, hidden, eps)
		denseMatVec(qBuf[p*hidden:(p+1)*hidden], w.Wq, n1Row, w.Bq, hidden, hidden)
		denseMatVec(kBuf[p*hidden:(p+1)*hidden], w.Wk, n1Row, w.Bk, hidden, hidden)
		denseMatVec(vBuf[p*hidden:(p+1)*hidden], w.Wv, n1Row, w.Bv, hidden, hidden)
	}

	// 2. Attention désentrelacée tête par tête. Les projections sont ramenées
	// en disposition contiguë [SeqLen, HeadDim] pour le noyau, qui attend un
	// pas de ligne égal à HeadDim.
	headQ := scratch.HeadQ
	headK := scratch.HeadK
	headV := scratch.HeadV
	headOut := scratch.HeadOut
	headSpan := seqLen * headDim
	for h := 0; h < headCount; h++ {
		col := h * headDim
		for p := 0; p < seqLen; p++ {
			copy(headQ[p*headDim:(p+1)*headDim], qBuf[p*hidden+col:p*hidden+col+headDim])
			copy(headK[p*headDim:(p+1)*headDim], kBuf[p*hidden+col:p*hidden+col+headDim])
			copy(headV[p*headDim:(p+1)*headDim], vBuf[p*hidden+col:p*hidden+col+headDim])
		}

		relOff := h * relLen * headDim
		posQh := posQ[relOff : relOff+relLen*headDim]
		posKh := posK[relOff : relOff+relLen*headDim]

		PrecomputePositionPositionTable(posQh, posKh, cfg.MaxRelDist, headDim, pp)
		C2_deberta_disentangled_attn_fast(headQ[:headSpan], headK[:headSpan], posQh, posKh, pp, scores[:seqLen*seqLen], seqLen, headDim, cfg.MaxRelDist, attnScale)

		for p := 0; p < seqLen; p++ {
			row := scores[p*seqLen : (p+1)*seqLen]
			tensor.Softmax(row)
			outRow := headOut[p*headDim : (p+1)*headDim]
			for t := 0; t < headDim; t++ {
				outRow[t] = 0
			}
			for j := 0; j < seqLen; j++ {
				weight := row[j]
				if weight == 0 {
					continue
				}
				vRow := headV[j*headDim : (j+1)*headDim]
				for t := 0; t < headDim; t++ {
					outRow[t] += weight * vRow[t]
				}
			}
			dst := heads[p*hidden+col : p*hidden+col+headDim]
			copy(dst, outRow)
		}
	}

	// 3. Projection de sortie d'attention, résidu, puis normalisation
	// post-attention.
	for p := 0; p < seqLen; p++ {
		attnRow := attn[p*hidden : (p+1)*hidden]
		denseMatVec(attnRow, w.Wout, heads[p*hidden:(p+1)*hidden], w.Bout, hidden, hidden)
		xRow := x[p*hidden : (p+1)*hidden]
		outRow := out[p*hidden : (p+1)*hidden]
		n2Row := norm2[p*hidden : (p+1)*hidden]
		for i := 0; i < hidden; i++ {
			outRow[i] = xRow[i] + attnRow[i]
		}
		simd.C2_tensor_layernorm(outRow, w.Gamma2, w.Beta2, n2Row, hidden, eps)
	}

	// 4. Feed-forward GELU : W_inter puis activation vectorisée puis W_out,
	// résidu final.
	for p := 0; p < seqLen; p++ {
		interRow := inter[p*interDim : (p+1)*interDim]
		denseMatVec(interRow, w.WIntermediate, norm2[p*hidden:(p+1)*hidden], w.BIntermediate, interDim, hidden)
		simd.C2_tensor_gelu(interRow, interRow, interDim)
		ffnRow := ffn[p*hidden : (p+1)*hidden]
		denseMatVec(ffnRow, w.WOutput, interRow, w.BOutput, hidden, interDim)
		outRow := out[p*hidden : (p+1)*hidden]
		for i := 0; i < hidden; i++ {
			outRow[i] += ffnRow[i]
		}
	}

	if ctx != nil {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}

	return out[:seqLen*hidden]
}
