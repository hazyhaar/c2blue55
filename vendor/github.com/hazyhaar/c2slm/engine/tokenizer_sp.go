package engine

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// SentencePiece piece types, mirroring ModelProto.SentencePiece.Type.
const (
	spTypeNormal      int32 = 1
	spTypeUnknown     int32 = 2
	spTypeControl     int32 = 3
	spTypeUserDefined int32 = 4
	spTypeByte        int32 = 5
	spTypeUnused      int32 = 6
)

// spSpace is the SentencePiece whitespace meta-symbol U+2581 (LOWER ONE EIGHTH
// BLOCK). A leading space is carried by the dummy prefix, so every word start is
// encoded as a piece beginning with this symbol.
const spSpace rune = '\u2581'

// spUnkPenalty mirrors SentencePiece kUnkPenalty. The unknown fallback scores
// min_score - 10, which keeps any real piece strictly above an unknown rune.
const spUnkPenalty float32 = 10.0

// debertaV3SpecialTokens lists the control symbols of the DeBERTa-v3 vocabulary
// reused by open-jev. They are matched as whole tokens before normalization.
var debertaV3SpecialTokens = []string{
	"[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]", "[STATE]", "[Q]", "[OPT]",
}

// spPiece is one entry of the SentencePiece vocabulary.
type spPiece struct {
	Piece string
	Score float32
	Type  int32
}

// spNode is one frozen trie node. Children are stored as a contiguous, rune
// sorted edge range so lookup is a branch-free binary search over L1D-resident
// arrays rather than a pointer chase through maps.
type spNode struct {
	firstEdge int32
	numEdges  int32
	pieceID   int32
}

type spEdge struct {
	r    rune
	next int32
}

type spBuildNode struct {
	children map[rune]int32
	pieceID  int32
}

func spNewBuildNode() spBuildNode {
	return spBuildNode{children: make(map[rune]int32), pieceID: -1}
}

// spModelProto is the subset of ModelProto required by a unigram encoder.
type spModelProto struct {
	Pieces                 []spPiece
	AddDummyPrefix         bool
	RemoveExtraWhitespaces bool
	EscapeWhitespaces      bool
}

func defaultSPModelProto() spModelProto {
	return spModelProto{
		AddDummyPrefix:         true,
		RemoveExtraWhitespaces: true,
		EscapeWhitespaces:      true,
	}
}

// SentencePieceTokenizer encodes text with a SentencePiece unigram model read
// from a binary spm.model or an equivalent JSON description.
//
// A tokenizer owns reusable normalization and Viterbi scratch buffers, so it is
// not safe for concurrent use: one instance per goroutine, or guard EncodeInto
// with a mutex.
type SentencePieceTokenizer struct {
	pieces    []spPiece
	pieceToID map[string]int32
	unkID     int32
	unkScore  float32
	byteToID  map[byte]int32

	nodes []spNode
	edges []spEdge

	specials     map[string]int32
	specialNames []string

	LowerCase              bool
	AddDummyPrefix         bool
	RemoveExtraWhitespaces bool
	EscapeWhitespaces      bool

	normBuf   []byte
	runeBuf   []rune
	bestScore []float32
	prev      []int32
	pieceSel  []int32
	pathBuf   []int32
}

// LoadSentencePieceTokenizer reads a spm.model file. A leading '{' selects the
// JSON representation; anything else is parsed as a binary ModelProto.
func LoadSentencePieceTokenizer(path string) (*SentencePieceTokenizer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read sentencepiece model: %w", err)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return NewSentencePieceTokenizerFromJSON(data)
	}
	return ParseSentencePieceModel(data)
}

// ParseSentencePieceModel decodes a binary SentencePiece ModelProto without any
// protobuf runtime dependency.
func ParseSentencePieceModel(data []byte) (*SentencePieceTokenizer, error) {
	m := defaultSPModelProto()
	i := 0
	for i < len(data) {
		key, next, ok := spReadVarint(data, i)
		if !ok {
			return nil, fmt.Errorf("sentencepiece: malformed field key at byte %d", i)
		}
		i = next
		field, wire := key>>3, key&7
		switch field {
		case 1:
			if wire != 2 {
				return nil, fmt.Errorf("sentencepiece: pieces wire type %d, want 2", wire)
			}
			ln, next, ok := spReadVarint(data, i)
			if !ok {
				return nil, fmt.Errorf("sentencepiece: malformed piece length at byte %d", i)
			}
			i = next
			end := i + int(ln)
			if end > len(data) {
				return nil, fmt.Errorf("sentencepiece: piece overruns buffer")
			}
			piece, err := parseSPPiece(data[i:end])
			if err != nil {
				return nil, err
			}
			m.Pieces = append(m.Pieces, piece)
			i = end
		case 3:
			if wire != 2 {
				return nil, fmt.Errorf("sentencepiece: normalizer wire type %d, want 2", wire)
			}
			ln, next, ok := spReadVarint(data, i)
			if !ok {
				return nil, fmt.Errorf("sentencepiece: malformed normalizer length")
			}
			i = next
			end := i + int(ln)
			if end > len(data) {
				return nil, fmt.Errorf("sentencepiece: normalizer overruns buffer")
			}
			if err := parseSPNormalizer(data[i:end], &m); err != nil {
				return nil, err
			}
			i = end
		default:
			next, ok := spSkipField(data, i, wire)
			if !ok {
				return nil, fmt.Errorf("sentencepiece: cannot skip field %d wire %d", field, wire)
			}
			i = next
		}
	}
	if len(m.Pieces) == 0 {
		return nil, fmt.Errorf("sentencepiece: model contains no pieces")
	}
	return newSentencePieceTokenizer(m)
}

func parseSPPiece(data []byte) (spPiece, error) {
	p := spPiece{Type: spTypeNormal}
	i := 0
	for i < len(data) {
		key, next, ok := spReadVarint(data, i)
		if !ok {
			return p, fmt.Errorf("sentencepiece: malformed piece field key")
		}
		i = next
		field, wire := key>>3, key&7
		switch field {
		case 1:
			if wire != 2 {
				return p, fmt.Errorf("sentencepiece: piece string wire type %d", wire)
			}
			ln, next, ok := spReadVarint(data, i)
			if !ok {
				return p, fmt.Errorf("sentencepiece: malformed piece string length")
			}
			i = next
			end := i + int(ln)
			if end > len(data) {
				return p, fmt.Errorf("sentencepiece: piece string overruns buffer")
			}
			p.Piece = string(data[i:end])
			i = end
		case 2:
			if wire != 5 || i+4 > len(data) {
				return p, fmt.Errorf("sentencepiece: malformed piece score")
			}
			p.Score = math.Float32frombits(binary.LittleEndian.Uint32(data[i : i+4]))
			i += 4
		case 3:
			if wire != 0 {
				return p, fmt.Errorf("sentencepiece: piece type wire %d", wire)
			}
			v, next, ok := spReadVarint(data, i)
			if !ok {
				return p, fmt.Errorf("sentencepiece: malformed piece type")
			}
			p.Type = int32(v)
			i = next
		default:
			next, ok := spSkipField(data, i, wire)
			if !ok {
				return p, fmt.Errorf("sentencepiece: cannot skip piece field %d", field)
			}
			i = next
		}
	}
	return p, nil
}

func parseSPNormalizer(data []byte, m *spModelProto) error {
	i := 0
	for i < len(data) {
		key, next, ok := spReadVarint(data, i)
		if !ok {
			return fmt.Errorf("sentencepiece: malformed normalizer field key")
		}
		i = next
		field, wire := key>>3, key&7
		switch field {
		case 3, 4, 5:
			if wire != 0 {
				return fmt.Errorf("sentencepiece: normalizer flag %d wire %d", field, wire)
			}
			v, next, ok := spReadVarint(data, i)
			if !ok {
				return fmt.Errorf("sentencepiece: malformed normalizer flag %d", field)
			}
			i = next
			switch field {
			case 3:
				m.AddDummyPrefix = v != 0
			case 4:
				m.RemoveExtraWhitespaces = v != 0
			case 5:
				m.EscapeWhitespaces = v != 0
			}
		default:
			next, ok := spSkipField(data, i, wire)
			if !ok {
				return fmt.Errorf("sentencepiece: cannot skip normalizer field %d", field)
			}
			i = next
		}
	}
	return nil
}

func spReadVarint(b []byte, i int) (uint64, int, bool) {
	var v uint64
	var shift uint
	for i < len(b) {
		c := b[i]
		i++
		v |= uint64(c&0x7f) << shift
		if c < 0x80 {
			return v, i, true
		}
		shift += 7
		if shift > 63 {
			return 0, i, false
		}
	}
	return 0, i, false
}

func spSkipField(data []byte, i int, wire uint64) (int, bool) {
	switch wire {
	case 0:
		_, next, ok := spReadVarint(data, i)
		return next, ok
	case 1:
		if i+8 > len(data) {
			return 0, false
		}
		return i + 8, true
	case 2:
		ln, next, ok := spReadVarint(data, i)
		if !ok {
			return 0, false
		}
		end := next + int(ln)
		if end > len(data) {
			return 0, false
		}
		return end, true
	case 5:
		if i+4 > len(data) {
			return 0, false
		}
		return i + 4, true
	default:
		return 0, false
	}
}

type sentencePieceJSON struct {
	Pieces []struct {
		Piece string  `json:"piece"`
		Score float64 `json:"score"`
		Type  int     `json:"type"`
	} `json:"pieces"`
	AddDummyPrefix         *bool `json:"add_dummy_prefix"`
	RemoveExtraWhitespaces *bool `json:"remove_extra_whitespaces"`
	EscapeWhitespaces      *bool `json:"escape_whitespaces"`
	LowerCase              *bool `json:"lowercase"`
}

// NewSentencePieceTokenizerFromJSON builds a tokenizer from a JSON description
// equivalent to spm.model. Fields absent from the document keep the
// SentencePiece defaults (dummy prefix on, extra whitespace collapsed, spaces
// escaped); lowercase defaults to true.
func NewSentencePieceTokenizerFromJSON(data []byte) (*SentencePieceTokenizer, error) {
	var doc sentencePieceJSON
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("sentencepiece json: %w", err)
	}
	m := defaultSPModelProto()
	if doc.AddDummyPrefix != nil {
		m.AddDummyPrefix = *doc.AddDummyPrefix
	}
	if doc.RemoveExtraWhitespaces != nil {
		m.RemoveExtraWhitespaces = *doc.RemoveExtraWhitespaces
	}
	if doc.EscapeWhitespaces != nil {
		m.EscapeWhitespaces = *doc.EscapeWhitespaces
	}
	m.Pieces = make([]spPiece, 0, len(doc.Pieces))
	for _, p := range doc.Pieces {
		typ := int32(p.Type)
		if typ == 0 {
			typ = spTypeNormal
		}
		m.Pieces = append(m.Pieces, spPiece{Piece: p.Piece, Score: float32(p.Score), Type: typ})
	}
	if len(m.Pieces) == 0 {
		return nil, fmt.Errorf("sentencepiece json: model contains no pieces")
	}
	t, err := newSentencePieceTokenizer(m)
	if err != nil {
		return nil, err
	}
	if doc.LowerCase != nil {
		t.LowerCase = *doc.LowerCase
	}
	return t, nil
}

func newSentencePieceTokenizer(m spModelProto) (*SentencePieceTokenizer, error) {
	t := &SentencePieceTokenizer{
		pieces:                 m.Pieces,
		pieceToID:              make(map[string]int32, len(m.Pieces)),
		byteToID:               make(map[byte]int32),
		specials:               make(map[string]int32),
		LowerCase:              true,
		AddDummyPrefix:         m.AddDummyPrefix,
		RemoveExtraWhitespaces: m.RemoveExtraWhitespaces,
		EscapeWhitespaces:      m.EscapeWhitespaces,
		unkID:                  -1,
	}
	minScore := float32(math.Inf(1))
	for id, p := range m.Pieces {
		id32 := int32(id)
		t.pieceToID[p.Piece] = id32
		switch p.Type {
		case spTypeUnknown:
			if t.unkID < 0 {
				t.unkID = id32
			}
		case spTypeByte:
			if b, ok := spParseBytePiece(p.Piece); ok {
				t.byteToID[b] = id32
			}
		case spTypeControl, spTypeUserDefined:
			t.specials[p.Piece] = id32
		}
		if p.Type == spTypeNormal && p.Score < minScore {
			minScore = p.Score
		}
	}
	if t.unkID < 0 {
		return nil, fmt.Errorf("sentencepiece: no UNKNOWN piece")
	}
	if math.IsInf(float64(minScore), 1) {
		minScore = 0
	}
	t.unkScore = minScore - spUnkPenalty

	build := []spBuildNode{spNewBuildNode()}
	for id, p := range m.Pieces {
		if p.Type != spTypeNormal && p.Type != spTypeUserDefined {
			continue
		}
		if p.Piece == "" {
			continue
		}
		node := int32(0)
		for _, r := range p.Piece {
			child, ok := build[node].children[r]
			if !ok {
				child = int32(len(build))
				build = append(build, spNewBuildNode())
				build[node].children[r] = child
			}
			node = child
		}
		build[node].pieceID = int32(id)
	}
	t.freeze(build)

	for name := range t.specials {
		t.specialNames = append(t.specialNames, name)
	}
	for _, name := range debertaV3SpecialTokens {
		if id, ok := t.pieceToID[name]; ok {
			if _, exists := t.specials[name]; !exists {
				t.specials[name] = id
				t.specialNames = append(t.specialNames, name)
			}
		}
	}
	sort.Slice(t.specialNames, func(i, j int) bool {
		a, b := t.specialNames[i], t.specialNames[j]
		if len(a) != len(b) {
			return len(a) > len(b)
		}
		return a < b
	})
	return t, nil
}

func (t *SentencePieceTokenizer) freeze(build []spBuildNode) {
	t.nodes = make([]spNode, len(build))
	total := 0
	for i := range build {
		total += len(build[i].children)
	}
	t.edges = make([]spEdge, 0, total)
	for i := range build {
		n := &build[i]
		start := len(t.edges)
		if len(n.children) > 0 {
			runes := make([]rune, 0, len(n.children))
			for r := range n.children {
				runes = append(runes, r)
			}
			sort.Slice(runes, func(a, b int) bool { return runes[a] < runes[b] })
			for _, r := range runes {
				t.edges = append(t.edges, spEdge{r: r, next: n.children[r]})
			}
		}
		t.nodes[i] = spNode{firstEdge: int32(start), numEdges: int32(len(n.children)), pieceID: n.pieceID}
	}
}

func (t *SentencePieceTokenizer) child(node int32, r rune) int32 {
	n := &t.nodes[node]
	lo := n.firstEdge
	hi := n.firstEdge + n.numEdges
	for lo < hi {
		mid := (lo + hi) >> 1
		if t.edges[mid].r < r {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < n.firstEdge+n.numEdges && t.edges[lo].r == r {
		return t.edges[lo].next
	}
	return -1
}

func spParseBytePiece(s string) (byte, bool) {
	if len(s) != 6 || s[0] != '<' || s[1] != '0' || s[2] != 'x' || s[5] != '>' {
		return 0, false
	}
	hi := spHexVal(s[3])
	lo := spHexVal(s[4])
	if hi < 0 || lo < 0 {
		return 0, false
	}
	return byte(hi<<4 | lo), true
}

func spHexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// EncodeInto encodes text into outIDs and returns the number of tokens written.
// It writes at most maxLen tokens, itself clamped to the length of outIDs. A
// preallocated outIDs combined with a warmed-up tokenizer yields no heap
// allocation: normalization and Viterbi reuse internal scratch buffers.
func (t *SentencePieceTokenizer) EncodeInto(text string, outIDs []int32, maxLen int) int {
	limit := maxLen
	if limit <= 0 || limit > len(outIDs) {
		limit = len(outIDs)
	}
	n := 0
	remainder := text
	for len(remainder) > 0 && n < limit {
		idx, name, id := t.findSpecial(remainder)
		if idx < 0 {
			n = t.encodeTextInto(remainder, outIDs, n, limit)
			break
		}
		if idx > 0 {
			n = t.encodeTextInto(remainder[:idx], outIDs, n, limit)
			if n >= limit {
				break
			}
		}
		outIDs[n] = id
		n++
		remainder = remainder[idx+len(name):]
	}
	return n
}

// Encode allocates the result slice. It is a convenience wrapper for callers
// that do not manage a reusable buffer.
func (t *SentencePieceTokenizer) Encode(text string) []int32 {
	if text == "" {
		return nil
	}
	buf := make([]int32, 4*len(text)+16)
	n := t.EncodeInto(text, buf, len(buf))
	return buf[:n]
}

// EncodePairInto writes the DeBERTa-v3 sentence-pair layout
// [CLS] a [SEP] b [SEP].
func (t *SentencePieceTokenizer) EncodePairInto(a, b string, outIDs []int32, maxLen int) int {
	limit := maxLen
	if limit <= 0 || limit > len(outIDs) {
		limit = len(outIDs)
	}
	n := 0
	put := func(id int32) {
		if n < limit {
			outIDs[n] = id
			n++
		}
	}
	if id, ok := t.specials["[CLS]"]; ok {
		put(id)
	}
	n += t.EncodeInto(a, outIDs[n:], limit-n)
	if id, ok := t.specials["[SEP]"]; ok {
		put(id)
	}
	n += t.EncodeInto(b, outIDs[n:], limit-n)
	if id, ok := t.specials["[SEP]"]; ok {
		put(id)
	}
	return n
}

func (t *SentencePieceTokenizer) findSpecial(s string) (int, string, int32) {
	best := -1
	var bestName string
	var bestID int32
	for _, name := range t.specialNames {
		if name == "" {
			continue
		}
		idx := strings.Index(s, name)
		if idx < 0 {
			continue
		}
		if best < 0 || idx < best || (idx == best && len(name) > len(bestName)) {
			best = idx
			bestName = name
			bestID = t.specials[name]
		}
	}
	return best, bestName, bestID
}

func (t *SentencePieceTokenizer) encodeTextInto(chunk string, out []int32, n, limit int) int {
	if chunk == "" || n >= limit {
		return n
	}
	norm := t.normalize(chunk)
	if len(norm) == 0 {
		return n
	}
	runes := t.decodeRunes(norm)
	l := len(runes)
	if l == 0 {
		return n
	}

	if cap(t.bestScore) < l+1 {
		t.bestScore = make([]float32, l+1)
		t.prev = make([]int32, l+1)
		t.pieceSel = make([]int32, l+1)
	}
	best := t.bestScore[:l+1]
	prev := t.prev[:l+1]
	pieceSel := t.pieceSel[:l+1]
	t.bestScore, t.prev, t.pieceSel = best, prev, pieceSel

	negInf := float32(math.Inf(-1))
	for i := range best {
		best[i] = negInf
	}
	best[0] = 0
	prev[0] = -1
	pieceSel[0] = -1

	for i := 0; i < l; i++ {
		if best[i] == negInf {
			continue
		}
		node := int32(0)
		for j := i; j < l; j++ {
			node = t.child(node, runes[j])
			if node < 0 {
				break
			}
			if pid := t.nodes[node].pieceID; pid >= 0 {
				if s := best[i] + t.pieces[pid].Score; s > best[j+1] {
					best[j+1] = s
					prev[j+1] = int32(i)
					pieceSel[j+1] = pid
				}
			}
		}
		if s := best[i] + t.unkScore; s > best[i+1] {
			best[i+1] = s
			prev[i+1] = int32(i)
			pieceSel[i+1] = -1
		}
	}

	if cap(t.pathBuf) < l {
		t.pathBuf = make([]int32, l)
	}
	path := t.pathBuf[:l]
	count := 0
	for pos := l; pos > 0; pos = int(prev[pos]) {
		path[count] = int32(pos)
		count++
	}
	for a, b := 0, count-1; a < b; a, b = a+1, b-1 {
		path[a], path[b] = path[b], path[a]
	}
	for k := 0; k < count && n < limit; k++ {
		end := int(path[k])
		start := int(prev[end])
		if pid := pieceSel[end]; pid >= 0 {
			out[n] = pid
			n++
			continue
		}
		n = t.emitUnknown(runes[start], out, n, limit)
	}
	return n
}

func (t *SentencePieceTokenizer) emitUnknown(r rune, out []int32, n, limit int) int {
	if len(t.byteToID) == 0 {
		if n < limit {
			out[n] = t.unkID
			n++
		}
		return n
	}
	var tmp [4]byte
	buf := utf8.AppendRune(tmp[:0], r)
	for _, b := range buf {
		if n >= limit {
			break
		}
		if id, ok := t.byteToID[b]; ok {
			out[n] = id
		} else {
			out[n] = t.unkID
		}
		n++
	}
	return n
}

func (t *SentencePieceTokenizer) normalize(chunk string) []byte {
	buf := t.normBuf[:0]
	if chunk == "" {
		t.normBuf = buf
		return buf
	}
	for _, r := range chunk {
		if t.LowerCase {
			r = unicode.ToLower(r)
		}
		if unicode.IsSpace(r) {
			buf = append(buf, ' ')
		} else {
			buf = utf8.AppendRune(buf, r)
		}
	}
	if t.RemoveExtraWhitespaces {
		buf = spCollapseSpaces(buf)
	}
	if t.AddDummyPrefix {
		buf = append(buf, ' ')
		copy(buf[1:], buf[:len(buf)-1])
		buf[0] = ' '
	}
	if t.EscapeWhitespaces {
		buf = spEscapeSpaces(buf)
	}
	t.normBuf = buf
	return buf
}

func spCollapseSpaces(b []byte) []byte {
	w := 0
	prevSpace := true
	for _, c := range b {
		if c == ' ' {
			if prevSpace {
				continue
			}
			prevSpace = true
			b[w] = ' '
			w++
			continue
		}
		prevSpace = false
		b[w] = c
		w++
	}
	if w > 0 && b[w-1] == ' ' {
		w--
	}
	return b[:w]
}

func spEscapeSpaces(b []byte) []byte {
	spaces := 0
	for _, c := range b {
		if c == ' ' {
			spaces++
		}
	}
	if spaces == 0 {
		return b
	}
	n := len(b)
	b = append(b, make([]byte, 2*spaces)...)
	w := len(b)
	for r := n - 1; r >= 0; r-- {
		if b[r] == ' ' {
			w -= 3
			b[w] = 0xE2
			b[w+1] = 0x96
			b[w+2] = 0x81
		} else {
			w--
			b[w] = b[r]
		}
	}
	return b
}

func (t *SentencePieceTokenizer) decodeRunes(b []byte) []rune {
	r := t.runeBuf[:0]
	for len(b) > 0 {
		ru, size := utf8.DecodeRune(b)
		r = append(r, ru)
		b = b[size:]
	}
	t.runeBuf = r
	return r
}

// Decode concatenates pieces back into text. The space meta-symbol becomes a
// plain space and byte pieces recombine into their original UTF-8 bytes.
func (t *SentencePieceTokenizer) Decode(ids []int32) string {
	var sb strings.Builder
	for _, id := range ids {
		if id < 0 || int(id) >= len(t.pieces) {
			continue
		}
		p := t.pieces[id]
		switch p.Type {
		case spTypeByte:
			if b, ok := spParseBytePiece(p.Piece); ok {
				sb.WriteByte(b)
			}
		case spTypeControl, spTypeUnknown, spTypeUserDefined:
			sb.WriteString(p.Piece)
		default:
			for _, r := range p.Piece {
				if r == spSpace {
					sb.WriteByte(' ')
				} else {
					sb.WriteRune(r)
				}
			}
		}
	}
	return sb.String()
}

// VocabSize returns the number of vocabulary entries.
func (t *SentencePieceTokenizer) VocabSize() int { return len(t.pieces) }

// Piece returns the string form of a token id, or "" when out of range.
func (t *SentencePieceTokenizer) Piece(id int32) string {
	if id < 0 || int(id) >= len(t.pieces) {
		return ""
	}
	return t.pieces[id].Piece
}

// PieceID resolves a piece string to its token id.
func (t *SentencePieceTokenizer) PieceID(piece string) (int32, bool) {
	id, ok := t.pieceToID[piece]
	return id, ok
}

// UnknownID returns the id of the UNKNOWN piece.
func (t *SentencePieceTokenizer) UnknownID() int32 { return t.unkID }

// SpecialID resolves a control or user-defined symbol to its token id.
func (t *SentencePieceTokenizer) SpecialID(name string) (int32, bool) {
	id, ok := t.specials[name]
	return id, ok
}

// DeBERTaSpecialIDs returns the DeBERTa-v3 control ids present in the model.
func (t *SentencePieceTokenizer) DeBERTaSpecialIDs() map[string]int32 {
	out := make(map[string]int32, len(debertaV3SpecialTokens))
	for _, name := range debertaV3SpecialTokens {
		if id, ok := t.specials[name]; ok {
			out[name] = id
		}
	}
	return out
}
