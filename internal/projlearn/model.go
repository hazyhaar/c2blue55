// Package projlearn est le projecteur DNS appris (strate K-2) : plongement
// d'octets, convolution 1D, tangente hyperbolique, mise en commun par label
// puis sur les labels, traits structurels, deux couches denses et 512 bits.
// Toute l'arithmétique vectorielle passe par c2pkg/c2projlearn.
package projlearn

import (
	"errors"
	"math"

	"github.com/hazyhaar/c2pkg/c2projlearn"
)

// Erreurs du paquet.
var (
	ErrConfigContract      = errors.New("projlearn: configuration hors contrat")
	ErrCheckpointIntegrity = errors.New("projlearn: point de controle corrompu (magic, taille ou SHA-256)")
	ErrWorkspaceTooSmall   = errors.New("projlearn: espace de travail trop petit pour l'exemple")
	ErrCorpusContract      = errors.New("projlearn: corpus hors contrat")
)

// Config fixe les dimensions du modèle.
type Config struct {
	EmbedDim       int
	ConvOut        int
	Kernel         int
	Hidden         int
	CodeBits       int
	StructFeatures int
}

// DefaultConfig est la configuration du projecteur DNS (16, 32, 5, 128, 512, 8).
func DefaultConfig() Config {
	return Config{EmbedDim: 16, ConvOut: 32, Kernel: 5, Hidden: 128, CodeBits: 512, StructFeatures: 8}
}

// Params porte tous les paramètres entraînables.
type Params struct {
	Embed    []float32
	ConvW    []float32
	ConvB    []float32
	Dense1W  []float32
	Dense1B  []float32
	Dense2W  []float32
	Dense2B  []float32
	ReadoutW []float32
	ReadoutB []float32
}

// NewParams construit des paramètres initialisés de façon déterministe par seed.
func NewParams(cfg Config, seed uint64) *Params {
	p := &Params{
		Embed: make([]float32, 256*cfg.EmbedDim), ConvW: make([]float32, cfg.ConvOut*cfg.Kernel*cfg.EmbedDim),
		ConvB: make([]float32, cfg.ConvOut), Dense1W: make([]float32, cfg.Hidden*(cfg.ConvOut+cfg.StructFeatures)),
		Dense1B: make([]float32, cfg.Hidden), Dense2W: make([]float32, cfg.CodeBits*cfg.Hidden),
		Dense2B: make([]float32, cfg.CodeBits), ReadoutW: make([]float32, cfg.CodeBits), ReadoutB: make([]float32, 1),
	}
	rng := NewPCG64(seed)
	fill := func(slot []float32, radius float64) {
		for i := range slot {
			slot[i] = float32((float64(rng.Uint64())/18446744073709551616*2 - 1) * radius)
		}
	}
	fill(p.Embed, 0.5)
	fill(p.ConvW, math.Sqrt(6/float64(cfg.Kernel*cfg.EmbedDim+cfg.ConvOut)))
	fill(p.Dense1W, math.Sqrt(6/float64(cfg.ConvOut+cfg.StructFeatures+cfg.Hidden)))
	fill(p.Dense2W, math.Sqrt(6/float64(cfg.Hidden+cfg.CodeBits)))
	fill(p.ReadoutW, math.Sqrt(6/float64(cfg.CodeBits+1)))
	return p
}

// Workspace porte tous les tampons avant et arrière, alloués une fois.
type Workspace struct {
	cfg                                                                                 Config
	x, conv, activated, labels, pooled, joined, dense1, hidden1, dense2, hidden2, score []float32
	segStart, segEnd, labelArg, poolArg                                                 []int
	dJoined, dHidden1, dDense1, dHidden2, dDense2, dLabels, dActivated, dConv, dx       []float32
	dReadW, dReadB, dSecondW, dSecondB, dFirstW, dFirstB, dConvW, dConvB                []float32
}

// NewWorkspace alloue les tampons pour des noms de maxLen octets et maxLabels labels.
func NewWorkspace(cfg Config, maxLen, maxLabels int) *Workspace {
	if maxLen < 1 || maxLabels < 1 {
		return nil
	}
	return &Workspace{cfg: cfg,
		x: make([]float32, maxLen*cfg.EmbedDim), conv: make([]float32, maxLen*cfg.ConvOut), activated: make([]float32, maxLen*cfg.ConvOut),
		labels: make([]float32, maxLabels*cfg.ConvOut), pooled: make([]float32, cfg.ConvOut),
		joined: make([]float32, cfg.ConvOut+cfg.StructFeatures), dense1: make([]float32, cfg.Hidden), hidden1: make([]float32, cfg.Hidden),
		dense2: make([]float32, cfg.CodeBits), hidden2: make([]float32, cfg.CodeBits), score: make([]float32, 1),
		segStart: make([]int, maxLabels), segEnd: make([]int, maxLabels), labelArg: make([]int, maxLabels*cfg.ConvOut), poolArg: make([]int, cfg.ConvOut),
		dJoined: make([]float32, cfg.ConvOut+cfg.StructFeatures), dHidden1: make([]float32, cfg.Hidden), dDense1: make([]float32, cfg.Hidden),
		dHidden2: make([]float32, cfg.CodeBits), dDense2: make([]float32, cfg.CodeBits),
		dLabels: make([]float32, maxLabels*cfg.ConvOut), dActivated: make([]float32, maxLen*cfg.ConvOut), dConv: make([]float32, maxLen*cfg.ConvOut), dx: make([]float32, maxLen*cfg.EmbedDim),
		dReadW: make([]float32, cfg.CodeBits), dReadB: make([]float32, 1), dSecondW: make([]float32, cfg.CodeBits*cfg.Hidden), dSecondB: make([]float32, cfg.CodeBits),
		dFirstW: make([]float32, cfg.Hidden*(cfg.ConvOut+cfg.StructFeatures)), dFirstB: make([]float32, cfg.Hidden),
		dConvW: make([]float32, cfg.ConvOut*cfg.Kernel*cfg.EmbedDim), dConvB: make([]float32, cfg.ConvOut),
	}
}

// CheckExample valide la configuration, les bornes et la capacité de l'espace de travail.
func CheckExample(cfg Config, ws *Workspace, ex *Example) error {
	if ws == nil || ex == nil || cfg != ws.cfg || cfg.EmbedDim < 1 || cfg.ConvOut < 1 || cfg.Kernel < 1 || cfg.Kernel%2 == 0 || cfg.Hidden < 1 || cfg.CodeBits < 1 || cfg.CodeBits > 512 || cfg.CodeBits%64 != 0 || cfg.StructFeatures < 1 || cfg.StructFeatures > 8 || len(ws.hidden2) != cfg.CodeBits || len(ws.joined) != cfg.ConvOut+cfg.StructFeatures {
		return ErrConfigContract
	}
	if len(ex.Name) < 1 || len(ex.Labels) < 2 || len(ex.Labels)%2 != 0 {
		return ErrConfigContract
	}
	if len(ex.Name) > len(ws.x)/cfg.EmbedDim || len(ex.Name) > len(ws.conv)/cfg.ConvOut || len(ex.Labels)/2 > len(ws.segStart) || len(ex.Labels)/2 > len(ws.segEnd) {
		return ErrWorkspaceTooSmall
	}
	previous := -1
	for _, bound := range ex.Labels {
		if bound < 0 || bound > len(ex.Name) || bound <= previous {
			return ErrConfigContract
		}
		previous = bound
	}
	return nil
}

// Forward calcule le code de 512 bits, la sortie continue h et le score de lecture.
// Un score NaN, un code nul et h nul signalent une incohérence de configuration.
func Forward(p *Params, cfg Config, ex *Example, ws *Workspace) (code [8]uint64, h []float32, score float32) {
	failure := func() ([8]uint64, []float32, float32) {
		if ws != nil {
			clear(ws.hidden2)
			return [8]uint64{}, ws.hidden2, float32(math.NaN())
		}
		return [8]uint64{}, nil, float32(math.NaN())
	}
	if CheckExample(cfg, ws, ex) != nil || p == nil || len(p.Embed) < 256*cfg.EmbedDim {
		return failure()
	}
	tlen, nseg := len(ex.Name), len(ex.Labels)/2
	x := ws.x[:tlen*cfg.EmbedDim]
	for t, b := range ex.Name {
		copy(x[t*cfg.EmbedDim:(t+1)*cfg.EmbedDim], p.Embed[int(b)*cfg.EmbedDim:(int(b)+1)*cfg.EmbedDim])
	}
	conv, activated := ws.conv[:tlen*cfg.ConvOut], ws.activated[:tlen*cfg.ConvOut]
	if err := c2projlearn.Conv1DForward(x, tlen, cfg.EmbedDim, p.ConvW, p.ConvB, cfg.ConvOut, cfg.Kernel, conv); err != nil {
		return failure()
	}
	if err := c2projlearn.TanhForward(conv, activated); err != nil {
		return failure()
	}
	for i := range nseg {
		ws.segStart[i], ws.segEnd[i] = ex.Labels[2*i], ex.Labels[2*i+1]
	}
	if err := c2projlearn.MaxPoolForward(activated, tlen, cfg.ConvOut, ws.segStart[:nseg], ws.segEnd[:nseg], ws.labels[:nseg*cfg.ConvOut], ws.labelArg[:nseg*cfg.ConvOut]); err != nil {
		return failure()
	}
	var start, end [1]int
	end[0] = nseg
	if err := c2projlearn.MaxPoolForward(ws.labels[:nseg*cfg.ConvOut], nseg, cfg.ConvOut, start[:], end[:], ws.pooled, ws.poolArg); err != nil {
		return failure()
	}
	copy(ws.joined, ws.pooled)
	copy(ws.joined[cfg.ConvOut:], ex.Struct[:cfg.StructFeatures])
	if err := c2projlearn.DenseForward(ws.joined, p.Dense1W, p.Dense1B, ws.dense1); err != nil {
		return failure()
	}
	if err := c2projlearn.TanhForward(ws.dense1, ws.hidden1); err != nil {
		return failure()
	}
	if err := c2projlearn.DenseForward(ws.hidden1, p.Dense2W, p.Dense2B, ws.dense2); err != nil {
		return failure()
	}
	if err := c2projlearn.TanhForward(ws.dense2, ws.hidden2); err != nil {
		return failure()
	}
	if err := c2projlearn.SignBits(ws.hidden2, code[:cfg.CodeBits/64]); err != nil {
		return failure()
	}
	if err := c2projlearn.DenseForward(ws.hidden2, p.ReadoutW, p.ReadoutB, ws.score); err != nil {
		return failure()
	}
	return code, ws.hidden2, ws.score[0]
}

// Backward accumule dans grads les gradients de dh (sur h) et dscore.
func Backward(p *Params, cfg Config, ex *Example, ws *Workspace, dh []float32, dscore float32, grads *Params) {
	if CheckExample(cfg, ws, ex) != nil || p == nil || grads == nil || len(dh) != cfg.CodeBits || len(grads.Embed) < 256*cfg.EmbedDim {
		return
	}
	tlen, nseg := len(ex.Name), len(ex.Labels)/2
	ws.score[0] = dscore
	if err := c2projlearn.DenseBackward(ws.hidden2, p.ReadoutW, ws.score, ws.dHidden2, ws.dReadW, ws.dReadB); err != nil {
		return
	}
	for i := range dh {
		ws.dHidden2[i] += dh[i]
	}
	if err := c2projlearn.TanhBackward(ws.hidden2, ws.dHidden2, ws.dDense2); err != nil {
		return
	}
	if err := c2projlearn.DenseBackward(ws.hidden1, p.Dense2W, ws.dDense2, ws.dHidden1, ws.dSecondW, ws.dSecondB); err != nil {
		return
	}
	if err := c2projlearn.TanhBackward(ws.hidden1, ws.dHidden1, ws.dDense1); err != nil {
		return
	}
	if err := c2projlearn.DenseBackward(ws.joined, p.Dense1W, ws.dDense1, ws.dJoined, ws.dFirstW, ws.dFirstB); err != nil {
		return
	}
	if err := c2projlearn.MaxPoolBackward(ws.poolArg, 1, cfg.ConvOut, ws.dJoined[:cfg.ConvOut], nseg, ws.dLabels[:nseg*cfg.ConvOut]); err != nil {
		return
	}
	if err := c2projlearn.MaxPoolBackward(ws.labelArg[:nseg*cfg.ConvOut], nseg, cfg.ConvOut, ws.dLabels[:nseg*cfg.ConvOut], tlen, ws.dActivated[:tlen*cfg.ConvOut]); err != nil {
		return
	}
	if err := c2projlearn.TanhBackward(ws.activated[:tlen*cfg.ConvOut], ws.dActivated[:tlen*cfg.ConvOut], ws.dConv[:tlen*cfg.ConvOut]); err != nil {
		return
	}
	if err := c2projlearn.Conv1DBackward(ws.x[:tlen*cfg.EmbedDim], tlen, cfg.EmbedDim, p.ConvW, cfg.ConvOut, cfg.Kernel, ws.dConv[:tlen*cfg.ConvOut], ws.dx[:tlen*cfg.EmbedDim], ws.dConvW, ws.dConvB); err != nil {
		return
	}
	for t, b := range ex.Name {
		for d := 0; d < cfg.EmbedDim; d++ {
			grads.Embed[int(b)*cfg.EmbedDim+d] += ws.dx[t*cfg.EmbedDim+d]
		}
	}
	accumulate := func(dst, src []float32) {
		for i := range src {
			dst[i] += src[i]
		}
	}
	accumulate(grads.ConvW, ws.dConvW)
	accumulate(grads.ConvB, ws.dConvB)
	accumulate(grads.Dense1W, ws.dFirstW)
	accumulate(grads.Dense1B, ws.dFirstB)
	accumulate(grads.Dense2W, ws.dSecondW)
	accumulate(grads.Dense2B, ws.dSecondB)
	accumulate(grads.ReadoutW, ws.dReadW)
	accumulate(grads.ReadoutB, ws.dReadB)
}
