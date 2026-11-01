package tensor

import (
	"encoding/binary"
	"math"

	"github.com/hazyhaar/pkg/c2archsimd"
	"github.com/hazyhaar/c2slm/internal/simd"
)

// Block sizes and byte footprints in GGML
const (
	QK5_0 = 32
	QK8_0 = 32
	QK4_K = 256
	QK6_K = 256

	BlockSizeQ5_0 = 22  // 2 (fp16) + 4 (qh) + 16 (qs)
	BlockSizeQ8_0 = 34  // 2 (fp16) + 32 (int8)
	BlockSizeQ4_K = 144 // 2*2 (fp16 d,dmin) + 12 (scales) + 128 (qs)
	BlockSizeQ6_K = 210 // 128 (ql) + 64 (qh) + 16 (scales) + 2 (d)
	BlockSizeQ8_K = 292 // 4 (fp32 d) + 256 (int8 qs) + 32 (int16 bsums)
)

// GEMVQ5_0Range performs y = W * x for rows in [startRow, endRow) where W is in Q5_0.
func GEMVQ5_0Range(y []float32, weight []byte, x []float32, startRow, endRow, cols int) {
	rowBytes := (cols / QK5_0) * BlockSizeQ5_0
	for r := startRow; r < endRow; r++ {
		rowOffset := r * rowBytes
		rowWeight := weight[rowOffset : rowOffset+rowBytes]
		y[r] = DotQ5_0(rowWeight, x, cols)
	}
}

// GEMVQ5_0 performs y = W * x where W is encoded in Q5_0 format (rows x cols).
func GEMVQ5_0(y []float32, weight []byte, x []float32, rows, cols int) {
	GEMVQ5_0Range(y, weight, x, 0, rows, cols)
}

// DotQ5_0 computes dot product of one Q5_0 row with float32 vector x.
func DotQ5_0(weight []byte, x []float32, cols int) float32 {
	var total float32
	numBlocks := cols / QK5_0

	for b := 0; b < numBlocks; b++ {
		blkOffset := b * BlockSizeQ5_0
		dRaw := binary.LittleEndian.Uint16(weight[blkOffset : blkOffset+2])
		d := FP16ToF32(dRaw)

		qh := binary.LittleEndian.Uint32(weight[blkOffset+2 : blkOffset+6])
		qs := weight[blkOffset+6 : blkOffset+22] // 16 bytes

		xBase := b * QK5_0
		var sum float32

		for i := 0; i < 16; i++ {
			byteVal := qs[i]
			x0 := byteVal & 0x0F
			x1 := byteVal >> 4

			h0 := uint8((qh >> i) & 1)
			h1 := uint8((qh >> (i + 16)) & 1)

			q0 := float32(int32(x0|(h0<<4)) - 16)
			q1 := float32(int32(x1|(h1<<4)) - 16)

			sum += q0 * x[xBase+i]
			sum += q1 * x[xBase+i+16]
		}

		total += d * sum
	}

	return total
}

// GEMVQ8_0Range performs y = W * x for rows in [startRow, endRow) where W is in Q8_0.
func GEMVQ8_0Range(y []float32, weight []byte, x []float32, startRow, endRow, cols int) {
	rowBytes := (cols / QK8_0) * BlockSizeQ8_0
	for r := startRow; r < endRow; r++ {
		rowOffset := r * rowBytes
		rowWeight := weight[rowOffset : rowOffset+rowBytes]
		y[r] = DotQ8_0(rowWeight, x, cols)
	}
}

// GEMVQ8_0 performs y = W * x where W is encoded in Q8_0 format (rows x cols).
func GEMVQ8_0(y []float32, weight []byte, x []float32, rows, cols int) {
	GEMVQ8_0Range(y, weight, x, 0, rows, cols)
}

// DotQ8_0 computes dot product of one Q8_0 row with float32 vector x.
// Delegated to sgoiter-transpiled c2archsimd kernel (100% bit-exact against GCC -O2).
func DotQ8_0(weight []byte, x []float32, cols int) float32 {
	return c2archsimd.C2_tensor_dot_q8_0(weight, x, cols)
}

// GEMVQ6_KRange performs y = W * x for rows in [startRow, endRow) where W is in Q6_K.
func GEMVQ6_KRange(y []float32, weight []byte, x []float32, startRow, endRow, cols int) {
	rowBytes := (cols / QK6_K) * BlockSizeQ6_K
	for r := startRow; r < endRow; r++ {
		rowOffset := r * rowBytes
		rowWeight := weight[rowOffset : rowOffset+rowBytes]
		y[r] = DotQ6_K(rowWeight, x, cols)
	}
}

// GEMVQ6_K performs y = W * x where W is encoded in Q6_K format (rows x cols).
func GEMVQ6_K(y []float32, weight []byte, x []float32, rows, cols int) {
	GEMVQ6_KRange(y, weight, x, 0, rows, cols)
}

// DotQ6_K computes dot product of one Q6_K row with float32 vector x.
// Delegated to sgoiter-transpiled c2archsimd kernel (100% bit-exact against GCC -O2).
func DotQ6_K(weight []byte, x []float32, cols int) float32 {
	return c2archsimd.C2_tensor_dot_q6_k(weight, x, cols)
}

// GEMVQ6_K_Q8_KRange performs y = W * x for rows in [startRow, endRow) where W is in Q6_K and x is in Q8_K.
// Processes rows pairwise using fused GEMV2 kernel (reusing activation registers in L1D/AVX2).
func GEMVQ6_K_Q8_KRange(y []float32, weight []byte, q8k []byte, startRow, endRow, cols int) {
	rowBytes := (cols / QK6_K) * BlockSizeQ6_K
	r := startRow
	for ; r+1 < endRow; r += 2 {
		rowOffset0 := r * rowBytes
		rowOffset1 := (r + 1) * rowBytes
		c2archsimd.C2_tensor_gemv2_q6_k_q8_k(
			weight[rowOffset0:rowOffset0+rowBytes],
			weight[rowOffset1:rowOffset1+rowBytes],
			q8k, cols, &y[r], &y[r+1],
		)
	}
	if r < endRow {
		rowOffset0 := r * rowBytes
		var unused float32
		c2archsimd.C2_tensor_gemv2_q6_k_q8_k(
			weight[rowOffset0:rowOffset0+rowBytes],
			weight[rowOffset0:rowOffset0+rowBytes],
			q8k, cols, &y[r], &unused,
		)
	}
}

// GEMVQ6_K_Q8_K performs y = W * x where W is in Q6_K and x is pre-quantized in Q8_K.
func GEMVQ6_K_Q8_K(y []float32, weight []byte, q8k []byte, rows, cols int) {
	GEMVQ6_K_Q8_KRange(y, weight, q8k, 0, rows, cols)
}

// GEMVQ4_KRange performs y = W * x for rows in [startRow, endRow) where W is in Q4_K.
func GEMVQ4_KRange(y []float32, weight []byte, x []float32, startRow, endRow, cols int) {
	rowBytes := (cols / QK4_K) * BlockSizeQ4_K
	for r := startRow; r < endRow; r++ {
		rowOffset := r * rowBytes
		rowWeight := weight[rowOffset : rowOffset+rowBytes]
		y[r] = DotQ4_K(rowWeight, x, cols)
	}
}

// GEMVQ4_K performs y = W * x where W is encoded in Q4_K format (rows x cols).
func GEMVQ4_K(y []float32, weight []byte, x []float32, rows, cols int) {
	GEMVQ4_KRange(y, weight, x, 0, rows, cols)
}

// DotQ4_K computes dot product of one Q4_K row with float32 vector x.
// Delegated to sgoiter-transpiled c2archsimd kernel (100% bit-exact against GCC -O2).
func DotQ4_K(weight []byte, x []float32, cols int) float32 {
	return c2archsimd.C2_tensor_dot_q4_k(weight, x, cols)
}

// QuantizeRowQ8_K quantizes a float32 vector into Q8_K format.
func QuantizeRowQ8_K(x []float32, y []byte, cols int) {
	c2archsimd.C2_quantize_row_q8_k(x, y, cols)
}

// DotQ4_K_Q8_K computes integer AVX2 dot product of one Q4_K row with Q8_K vector.
// Delegated to sgoiter-transpiled c2archsimd kernel (100% bit-exact against GCC -O2).
func DotQ4_K_Q8_K(weight []byte, q8k []byte, cols int) float32 {
	return c2archsimd.C2_tensor_dot_q4_k_q8_k(weight, q8k, cols)
}

// GEMVQ4_K_Q8_KRange performs y = W * x for rows in [startRow, endRow) where W is in Q4_K and x is in Q8_K.
// Processes rows pairwise using fused GEMV2 kernel (reusing activation registers in L1D/AVX2).
func GEMVQ4_K_Q8_KRange(y []float32, weight []byte, q8k []byte, startRow, endRow, cols int) {
	rowBytes := (cols / QK4_K) * BlockSizeQ4_K
	r := startRow
	for ; r+1 < endRow; r += 2 {
		rowOffset0 := r * rowBytes
		rowOffset1 := (r + 1) * rowBytes
		c2archsimd.C2_tensor_gemv2_q4_k_q8_k(
			weight[rowOffset0:rowOffset0+rowBytes],
			weight[rowOffset1:rowOffset1+rowBytes],
			q8k, cols, &y[r], &y[r+1],
		)
	}
	if r < endRow {
		rowOffset := r * rowBytes
		y[r] = DotQ4_K_Q8_K(weight[rowOffset:rowOffset+rowBytes], q8k, cols)
	}
}

// GEMVQ4_K_Q8_K performs y = W * x where W is in Q4_K and x is pre-quantized in Q8_K.
func GEMVQ4_K_Q8_K(y []float32, weight []byte, q8k []byte, rows, cols int) {
	GEMVQ4_K_Q8_KRange(y, weight, q8k, 0, rows, cols)
}

// QuantizeRowsQ8_K quantizes k contiguous float32 activation rows into k
// contiguous Q8_K rows. Each row is quantized independently and identically to
// QuantizeRowQ8_K, so the result is bit-exact with the per-token sequential path.
func QuantizeRowsQ8_K(x []float32, xStride int, q8k []byte, q8kStride, k, cols int) {
	for j := 0; j < k; j++ {
		c2archsimd.C2_quantize_row_q8_k(x[j*xStride:], q8k[j*q8kStride:], cols)
	}
}

// Q8KRowStride returns the byte footprint of one Q8_K-quantized row of cols
// elements.
func Q8KRowStride(cols int) int {
	return (cols / QK4_K) * BlockSizeQ8_K
}

// GEMVTiledQ5_0Range performs the tiled GEMV Y = W * X for weight rows in
// [startRow, endRow), where the K activation rows live back-to-back in x with
// stride xStride and the K output rows live back-to-back in y with stride
// yStride. The quantized 5-bit weights of one row are decoded once per 32-value
// block and reused across the K activations, so the weight bytes are fetched
// from memory exactly once per row instead of once per token. The accumulation
// order of each scalar dot product is identical to DotQ5_0, which makes the
// tiled result bit-exact with the sequential GEMV.
func GEMVTiledQ5_0Range(y []float32, yStride int, weight []byte, x []float32, xStride, startRow, endRow, cols, k int) {
	rowBytes := (cols / QK5_0) * BlockSizeQ5_0
	numBlocks := cols / QK5_0
	var q0v, q1v [16]float32
	for r := startRow; r < endRow; r++ {
		rowOffset := r * rowBytes
		rowWeight := weight[rowOffset : rowOffset+rowBytes]
		for j := 0; j < k; j++ {
			y[j*yStride+r] = 0
		}
		for b := 0; b < numBlocks; b++ {
			blkOffset := b * BlockSizeQ5_0
			dRaw := binary.LittleEndian.Uint16(rowWeight[blkOffset : blkOffset+2])
			d := FP16ToF32(dRaw)
			qh := binary.LittleEndian.Uint32(rowWeight[blkOffset+2 : blkOffset+6])
			qs := rowWeight[blkOffset+6 : blkOffset+22]
			xBase := b * QK5_0

			// Decode the 5-bit weights of the block once and reuse the decoded
			// coefficients across every activation of the tile.
			for i := 0; i < 16; i++ {
				byteVal := qs[i]
				h0 := uint8((qh >> i) & 1)
				h1 := uint8((qh >> (i + 16)) & 1)
				q0v[i] = float32(int32((byteVal&0x0F)|(h0<<4)) - 16)
				q1v[i] = float32(int32((byteVal>>4)|(h1<<4)) - 16)
			}

			for j := 0; j < k; j++ {
				xj := x[j*xStride:]
				var sum float32
				for i := 0; i < 16; i++ {
					sum += q0v[i] * xj[xBase+i]
					sum += q1v[i] * xj[xBase+i+16]
				}
				y[j*yStride+r] += d * sum
			}
		}
	}
}

// GEMVTiledQ8_0Range performs the tiled GEMV Y = W * X for Q8_0 weights. Each
// row is reused across the K activations and every dot product is delegated to
// the same AVX2 kernel as the sequential path, so the values are bit-exact.
func GEMVTiledQ8_0Range(y []float32, yStride int, weight []byte, x []float32, xStride, startRow, endRow, cols, k int) {
	rowBytes := (cols / QK8_0) * BlockSizeQ8_0
	for r := startRow; r < endRow; r++ {
		rowOffset := r * rowBytes
		rowWeight := weight[rowOffset : rowOffset+rowBytes]
		for j := 0; j < k; j++ {
			y[j*yStride+r] = DotQ8_0(rowWeight, x[j*xStride:], cols)
		}
	}
}

// GEMVTiledQ6_K_Q8_KRange performs the tiled GEMV Y = W * X for Q6_K weights
// against K pre-quantized Q8_K activation rows. Rows are processed pairwise
// through the fused gemv2 kernel exactly as in GEMVQ6_K_Q8_KRange, which keeps
// the per-row values bit-exact with the sequential path.
func GEMVTiledQ6_K_Q8_KRange(y []float32, yStride int, weight []byte, q8k []byte, q8kStride, startRow, endRow, cols, k int) {
	rowBytes := (cols / QK6_K) * BlockSizeQ6_K
	r := startRow
	for ; r+1 < endRow; r += 2 {
		rowOffset0 := r * rowBytes
		rowOffset1 := (r + 1) * rowBytes
		w0 := weight[rowOffset0 : rowOffset0+rowBytes]
		w1 := weight[rowOffset1 : rowOffset1+rowBytes]
		for j := 0; j < k; j++ {
			c2archsimd.C2_tensor_gemv2_q6_k_q8_k(w0, w1, q8k[j*q8kStride:], cols,
				&y[j*yStride+r], &y[j*yStride+r+1])
		}
	}
	if r < endRow {
		rowOffset := r * rowBytes
		w0 := weight[rowOffset : rowOffset+rowBytes]
		var unused float32
		for j := 0; j < k; j++ {
			c2archsimd.C2_tensor_gemv2_q6_k_q8_k(w0, w0, q8k[j*q8kStride:], cols,
				&y[j*yStride+r], &unused)
		}
	}
}

// GEMVTiledQ4_K_Q8_KRange performs the tiled GEMV Y = W * X for Q4_K weights
// against K pre-quantized Q8_K activation rows, mirroring the pairwise fused
// kernel of GEMVQ4_K_Q8_KRange for bit-exact results.
func GEMVTiledQ4_K_Q8_KRange(y []float32, yStride int, weight []byte, q8k []byte, q8kStride, startRow, endRow, cols, k int) {
	rowBytes := (cols / QK4_K) * BlockSizeQ4_K
	r := startRow
	for ; r+1 < endRow; r += 2 {
		rowOffset0 := r * rowBytes
		rowOffset1 := (r + 1) * rowBytes
		w0 := weight[rowOffset0 : rowOffset0+rowBytes]
		w1 := weight[rowOffset1 : rowOffset1+rowBytes]
		for j := 0; j < k; j++ {
			c2archsimd.C2_tensor_gemv2_q4_k_q8_k(w0, w1, q8k[j*q8kStride:], cols,
				&y[j*yStride+r], &y[j*yStride+r+1])
		}
	}
	if r < endRow {
		rowOffset := r * rowBytes
		w0 := weight[rowOffset : rowOffset+rowBytes]
		for j := 0; j < k; j++ {
			y[j*yStride+r] = DotQ4_K_Q8_K(w0, q8k[j*q8kStride:], cols)
		}
	}
}

// RMSNorm normalizes vector x in-place or into out using weights and epsilon:
// out[i] = (x[i] / sqrt(mean(x^2) + eps)) * weight[i]
func RMSNorm(out, x, weight []float32, eps float32) {
	n := len(x)
	var sumSq float32
	for i := 0; i < n; i++ {
		sumSq += x[i] * x[i]
	}

	invRMS := float32(1.0 / math.Sqrt(float64(sumSq/float32(n)+eps)))
	for i := 0; i < n; i++ {
		out[i] = x[i] * invRMS * weight[i]
	}
}

// AddBias adds bias in-place to x: x[i] += bias[i]
func AddBias(x, bias []float32) {
	for i := range bias {
		x[i] += bias[i]
	}
}

// RoPETable precomputes cosine and sine rotary embeddings at ARCHTIME/init to avoid runtime transcendental calls.
type RoPETable struct {
	Cos     []float32 // [maxLen * halfDim]
	Sin     []float32 // [maxLen * halfDim]
	HeadDim int
	HalfDim int
	MaxLen  int
}

// NewRoPETable precomputes rotary angles for all positions in [0, maxLen).
func NewRoPETable(maxLen, headDim int, theta float32) *RoPETable {
	halfDim := headDim / 2
	cos := make([]float32, maxLen*halfDim)
	sin := make([]float32, maxLen*halfDim)
	for p := 0; p < maxLen; p++ {
		pOffset := p * halfDim
		for i := 0; i < halfDim; i++ {
			freq := 1.0 / math.Pow(float64(theta), float64(2*i)/float64(headDim))
			val := float64(p) * freq
			cos[pOffset+i] = float32(math.Cos(val))
			sin[pOffset+i] = float32(math.Sin(val))
		}
	}
	return &RoPETable{
		Cos:     cos,
		Sin:     sin,
		HeadDim: headDim,
		HalfDim: halfDim,
		MaxLen:  maxLen,
	}
}

// Apply applies precomputed RoPE to vec for pos. A position outside the
// precomputed table is rejected, so an out-of-range pos can neither read past
// the cosine/sine tables nor write past the vector.
func (t *RoPETable) Apply(vec []float32, numHeads, pos int) {
	if t == nil || pos < 0 || pos >= t.MaxLen {
		return
	}
	if numHeads <= 0 || numHeads*t.HeadDim > len(vec) {
		return
	}
	pOffset := pos * t.HalfDim
	cosSlice := t.Cos[pOffset : pOffset+t.HalfDim]
	sinSlice := t.Sin[pOffset : pOffset+t.HalfDim]
	halfDim := t.HalfDim
	headDim := t.HeadDim

	for h := 0; h < numHeads; h++ {
		headOffset := h * headDim
		for i := 0; i < halfDim; i++ {
			c := cosSlice[i]
			s := sinSlice[i]
			x0 := vec[headOffset+i]
			x1 := vec[headOffset+i+halfDim]
			vec[headOffset+i] = x0*c - x1*s
			vec[headOffset+i+halfDim] = x0*s + x1*c
		}
	}
}

// RoPENeoX applies rotary position embedding (NeoX / Qwen2 rotate_half convention):
// For headDim (e.g. 64), split into two halves: [0..31] and [32..63]
// x'[i]    = x[i] * cos(theta_i) - x[i+32] * sin(theta_i)
// x'[i+32] = x[i] * sin(theta_i) + x[i+32] * cos(theta_i)
func RoPENeoX(vec []float32, numHeads, headDim, pos int, theta float32) {
	halfDim := headDim / 2
	for h := 0; h < numHeads; h++ {
		headOffset := h * headDim
		for i := 0; i < halfDim; i++ {
			freq := 1.0 / math.Pow(float64(theta), float64(2*i)/float64(headDim))
			val := float64(pos) * freq
			cos := float32(math.Cos(val))
			sin := float32(math.Sin(val))

			x0 := vec[headOffset+i]
			x1 := vec[headOffset+i+halfDim]

			vec[headOffset+i] = x0*cos - x1*sin
			vec[headOffset+i+halfDim] = x0*sin + x1*cos
		}
	}
}

// SwiGLU computes out[i] = SiLU(gate[i]) * up[i] using AVX2 vectorization when available.
func SwiGLU(out, gate, up []float32) {
	simd.C2_tensor_swiglu(out, gate, up, len(out))
}

// Softmax computes in-place softmax over slice
func Softmax(x []float32) {
	if len(x) == 0 {
		return
	}
	maxVal := x[0]
	for _, v := range x[1:] {
		if v > maxVal {
			maxVal = v
		}
	}

	var sumExp float32
	for i := range x {
		e := float32(math.Exp(float64(x[i] - maxVal)))
		x[i] = e
		sumExp += e
	}

	invSum := 1.0 / sumExp
	for i := range x {
		x[i] *= invSum
	}
}

// DequantizeRowQ4_K dequantizes a row of Q4_K blocks into destination float32 slice.
func DequantizeRowQ4_K(dst []float32, data []byte, cols int) {
	numBlocks := cols / QK4_K
	for b := 0; b < numBlocks; b++ {
		blkOffset := b * BlockSizeQ4_K
		dRaw := binary.LittleEndian.Uint16(data[blkOffset : blkOffset+2])
		dminRaw := binary.LittleEndian.Uint16(data[blkOffset+2 : blkOffset+4])
		d := FP16ToF32(dRaw)
		dmin := FP16ToF32(dminRaw)

		scales := data[blkOffset+4 : blkOffset+16]
		qs := data[blkOffset+16 : blkOffset+144]

		var sc [8]uint8
		var m [8]uint8
		for j := 0; j < 4; j++ {
			sc[j] = scales[j] & 63
			m[j] = scales[j+4] & 63
			sc[j+4] = (scales[j+8] & 0x0F) | ((scales[j] >> 6) << 4)
			m[j+4] = (scales[j+8] >> 4) | ((scales[j+4] >> 6) << 4)
		}

		dstBase := b * QK4_K
		for sb := 0; sb < 4; sb++ {
			d0 := d * float32(sc[2*sb+0])
			m0 := dmin * float32(m[2*sb+0])
			d1 := d * float32(sc[2*sb+1])
			m1 := dmin * float32(m[2*sb+1])

			sbOffset := sb * 32
			dstOffset := dstBase + sb*64

			for l := 0; l < 32; l++ {
				v := qs[sbOffset+l]
				dst[dstOffset+l] = d0*float32(v&0x0F) - m0
				dst[dstOffset+l+32] = d1*float32(v>>4) - m1
			}
		}
	}
}

// DequantizeRowQ5_0 dequantizes a row of Q5_0 blocks into destination float32 slice.
func DequantizeRowQ5_0(dst []float32, data []byte, cols int) {
	numBlocks := cols / QK5_0
	for b := 0; b < numBlocks; b++ {
		blkOffset := b * BlockSizeQ5_0
		dRaw := binary.LittleEndian.Uint16(data[blkOffset : blkOffset+2])
		d := FP16ToF32(dRaw)

		qh := binary.LittleEndian.Uint32(data[blkOffset+2 : blkOffset+6])
		qs := data[blkOffset+6 : blkOffset+22]

		base := b * QK5_0
		for i := 0; i < 16; i++ {
			byteVal := qs[i]
			x0 := byteVal & 0x0F
			x1 := byteVal >> 4

			h0 := uint8((qh >> i) & 1)
			h1 := uint8((qh >> (i + 16)) & 1)

			q0 := float32(int32(x0|(h0<<4)) - 16)
			q1 := float32(int32(x1|(h1<<4)) - 16)

			dst[base+i] = d * q0
			dst[base+i+16] = d * q1
		}
	}
}

// DequantizeRowQ8_0 dequantizes a row of Q8_0 blocks into destination float32 slice.
func DequantizeRowQ8_0(dst []float32, data []byte, cols int) {
	numBlocks := cols / QK8_0
	for b := 0; b < numBlocks; b++ {
		blkOffset := b * BlockSizeQ8_0
		dRaw := binary.LittleEndian.Uint16(data[blkOffset : blkOffset+2])
		d := FP16ToF32(dRaw)
		qs := data[blkOffset+2 : blkOffset+34]
		base := b * QK8_0
		for i := 0; i < 32; i++ {
			dst[base+i] = d * float32(int8(qs[i]))
		}
	}
}
