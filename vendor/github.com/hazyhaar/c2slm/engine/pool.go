package engine

import (
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/hazyhaar/c2slm/gguf"
	"github.com/hazyhaar/c2slm/tensor"
)

// attnParallelThreshold is the context length above which attention heads are
// distributed across the worker pool instead of being computed sequentially.
const attnParallelThreshold = 256

// WorkerPool provides pre-spawned worker goroutines to parallelize GEMV computations with 0 heap allocations
type WorkerPool struct {
	numWorkers int
	startChans []chan struct{}
	doneWg     sync.WaitGroup
	quitChan   chan struct{}
	dispatches atomic.Uint64

	// Flat task fields (strictly 0 allocation during dispatch)
	y      []float32
	weight []byte
	x      []float32
	q8k    []byte
	rows   int
	cols   int
	qtype  gguf.GGMLType
	n4Mode bool
	n4Bits int

	// Attention task fields, also flat and 0 allocation during dispatch.
	attnMode    bool
	attnCache   *KVCache
	attnLayer   int
	attnPos     int
	attnScale   float32
	attnNumHead int
	attnQPerKV  int
	attnHeadDim int
	attnQ       []float32
	attnOut     []float32
	attnScratch []float32

	// Tiled GEMV task fields: each worker owns a disjoint row range and loops
	// over the K activation rows, reusing the decoded weight row. Flat and 0
	// allocation during dispatch.
	tiledMode      bool
	tiledY         []float32
	tiledYStride   int
	tiledWeight    []byte
	tiledX         []float32
	tiledXStride   int
	tiledQ8K       []byte
	tiledQ8KStride int
	tiledRows      int
	tiledCols      int
	tiledK         int
	tiledType      gguf.GGMLType
}

// NewWorkerPool initializes persistent workers
func NewWorkerPool() *WorkerPool {
	nw := runtime.GOMAXPROCS(0)
	if nw < 1 {
		nw = 1
	}
	if nw > 32 {
		nw = 32
	}

	p := &WorkerPool{
		numWorkers:  nw,
		startChans:  make([]chan struct{}, nw),
		quitChan:    make(chan struct{}),
		q8k:         make([]byte, (16384/256)*tensor.BlockSizeQ8_K),
		attnScratch: make([]float32, nw*MaxContextLen),
	}

	for i := 0; i < nw; i++ {
		p.startChans[i] = make(chan struct{}, 1)
		go p.workerLoop(i)
	}

	return p
}

// Close gracefully terminates worker goroutines
func (p *WorkerPool) Close() {
	select {
	case <-p.quitChan:
		// already closed
	default:
		close(p.quitChan)
		for _, canal := range p.startChans {
			close(canal)
		}
	}
}

// NumWorkers returns the number of active workers
func (p *WorkerPool) NumWorkers() int {
	return p.numWorkers
}

// DispatchCount returns the number of collective worker wakeups.
func (p *WorkerPool) DispatchCount() uint64 { return p.dispatches.Load() }

func (p *WorkerPool) workerLoop(workerID int) {
	for {
		// Attente bloquante d'origine (aucune allocation par réveil mesurée sur main) ;
		// l'attente active de V4 allouait et dormait par microseconde.
		select {
		case <-p.quitChan:
			return
		case _, ouvert := <-p.startChans[workerID]:
			if !ouvert {
				return
			}
		}
		{
			if p.attnMode {
				p.runAttnHeads(workerID)
				p.doneWg.Done()
				continue
			}

			if p.tiledMode {
				p.runTiledRows(workerID)
				p.doneWg.Done()
				continue
			}
			if p.n4Mode {
				debut := workerID * (p.rows / 4) / p.numWorkers
				fin := (workerID + 1) * (p.rows / 4) / p.numWorkers
				if p.n4Bits == 5 {
					tensor.GEMVN5Q8KRange(p.y, p.weight, p.q8k, debut, fin, p.cols)
				} else {
					tensor.GEMVN4Q8KRange(p.y, p.weight, p.q8k, debut, fin, p.cols)
				}
				p.doneWg.Done()
				continue
			}

			startRow := (workerID * p.rows) / p.numWorkers
			endRow := ((workerID + 1) * p.rows) / p.numWorkers

			if startRow < endRow && startRow < p.rows {
				if endRow > p.rows {
					endRow = p.rows
				}
				switch p.qtype {
				case gguf.GGMLTypeQ8_0:
					tensor.GEMVQ8_0Range(p.y, p.weight, p.x, startRow, endRow, p.cols)
				case gguf.GGMLTypeQ5_0:
					tensor.GEMVQ5_0Range(p.y, p.weight, p.x, startRow, endRow, p.cols)
				case gguf.GGMLTypeQ6_K:
					tensor.GEMVQ6_K_Q8_KRange(p.y, p.weight, p.q8k, startRow, endRow, p.cols)
				case gguf.GGMLTypeQ4_K:
					tensor.GEMVQ4_K_Q8_KRange(p.y, p.weight, p.q8k, startRow, endRow, p.cols)
				}
			}
			p.doneWg.Done()
		}
	}
}

// ParallelGEMVN4 quantizes once and distributes disjoint quadruplets.
func (p *WorkerPool) ParallelGEMVN4(y []float32, poids []byte, x []float32, rows, cols, bits int) {
	tensor.QuantizeRowQ8_K(x, p.q8k, cols)
	if p.numWorkers <= 1 || rows/4 < 64 {
		if bits == 5 {
			tensor.GEMVN5Q8KRange(y, poids, p.q8k, 0, rows/4, cols)
		} else {
			tensor.GEMVN4Q8KRange(y, poids, p.q8k, 0, rows/4, cols)
		}
		return
	}
	p.y, p.weight, p.rows, p.cols = y, poids, rows, cols
	p.n4Bits = bits
	p.n4Mode = true
	p.doneWg.Add(p.numWorkers)
	p.dispatches.Add(1)
	for i := 0; i < p.numWorkers; i++ {
		p.startChans[i] <- struct{}{}
	}
	p.doneWg.Wait()
	p.n4Mode = false
}

// ParallelGEMV executes GEMV across workers with 0 heap allocation
func (p *WorkerPool) ParallelGEMV(y []float32, weight []byte, x []float32, rows, cols int, qtype gguf.GGMLType) {
	if qtype == gguf.GGMLTypeQ4_K || qtype == gguf.GGMLTypeQ6_K {
		tensor.QuantizeRowQ8_K(x, p.q8k, cols)
	}

	if p.numWorkers <= 1 || rows < 256 {
		// Single-threaded path for small projections (ex: KV heads), avoiding goroutine wakeups
		switch qtype {
		case gguf.GGMLTypeQ8_0:
			tensor.GEMVQ8_0Range(y, weight, x, 0, rows, cols)
		case gguf.GGMLTypeQ5_0:
			tensor.GEMVQ5_0Range(y, weight, x, 0, rows, cols)
		case gguf.GGMLTypeQ6_K:
			tensor.GEMVQ6_K_Q8_KRange(y, weight, p.q8k, 0, rows, cols)
		case gguf.GGMLTypeQ4_K:
			tensor.GEMVQ4_K_Q8_KRange(y, weight, p.q8k, 0, rows, cols)
		}
		return
	}

	p.y = y
	p.weight = weight
	p.x = x
	p.rows = rows
	p.cols = cols
	p.qtype = qtype

	p.doneWg.Add(p.numWorkers)
	p.dispatches.Add(1)
	for i := 0; i < p.numWorkers; i++ {
		p.startChans[i] <- struct{}{}
	}
	p.doneWg.Wait()
}

// ParallelGEMVTiled executes a tiled GEMV Y = W * X across the persistent
// workers with 0 heap allocation. The K activation rows are laid out
// back-to-back in x with stride xStride, and the K output rows are laid out in
// y with stride yStride. Each worker owns a disjoint weight-row range and, for
// every row, loops over the K activations so the decoded weight row is reused K
// times from L1 instead of being re-fetched from memory once per token. For
// K-quantized weights the activation rows are quantized to Q8_K once, before the
// dispatch, into the caller-supplied q8k buffer.
func (p *WorkerPool) ParallelGEMVTiled(y []float32, yStride int, weight []byte, x []float32, xStride, rows, cols, k int, qtype gguf.GGMLType, q8k []byte, q8kStride int) {
	if qtype == gguf.GGMLTypeQ4_K || qtype == gguf.GGMLTypeQ6_K {
		tensor.QuantizeRowsQ8_K(x, xStride, q8k, q8kStride, k, cols)
	}

	if p.numWorkers <= 1 || rows < 256 {
		// Single-threaded path for small projections (ex: KV heads), avoiding
		// goroutine wakeups while still reusing each weight row across K tokens.
		switch qtype {
		case gguf.GGMLTypeQ8_0:
			tensor.GEMVTiledQ8_0Range(y, yStride, weight, x, xStride, 0, rows, cols, k)
		case gguf.GGMLTypeQ5_0:
			tensor.GEMVTiledQ5_0Range(y, yStride, weight, x, xStride, 0, rows, cols, k)
		case gguf.GGMLTypeQ6_K:
			tensor.GEMVTiledQ6_K_Q8_KRange(y, yStride, weight, q8k, q8kStride, 0, rows, cols, k)
		case gguf.GGMLTypeQ4_K:
			tensor.GEMVTiledQ4_K_Q8_KRange(y, yStride, weight, q8k, q8kStride, 0, rows, cols, k)
		}
		return
	}

	p.tiledY = y
	p.tiledYStride = yStride
	p.tiledWeight = weight
	p.tiledX = x
	p.tiledXStride = xStride
	p.tiledQ8K = q8k
	p.tiledQ8KStride = q8kStride
	p.tiledRows = rows
	p.tiledCols = cols
	p.tiledK = k
	p.tiledType = qtype
	p.tiledMode = true

	p.doneWg.Add(p.numWorkers)
	p.dispatches.Add(1)
	for i := 0; i < p.numWorkers; i++ {
		p.startChans[i] <- struct{}{}
	}
	p.doneWg.Wait()

	p.tiledMode = false
}

// runTiledRows computes the disjoint weight-row range owned by one worker,
// looping over the K activations for each row.
func (p *WorkerPool) runTiledRows(workerID int) {
	startRow := (workerID * p.tiledRows) / p.numWorkers
	endRow := ((workerID + 1) * p.tiledRows) / p.numWorkers
	if startRow >= p.tiledRows {
		return
	}
	if endRow > p.tiledRows {
		endRow = p.tiledRows
	}

	switch p.tiledType {
	case gguf.GGMLTypeQ8_0:
		tensor.GEMVTiledQ8_0Range(p.tiledY, p.tiledYStride, p.tiledWeight, p.tiledX, p.tiledXStride, startRow, endRow, p.tiledCols, p.tiledK)
	case gguf.GGMLTypeQ5_0:
		tensor.GEMVTiledQ5_0Range(p.tiledY, p.tiledYStride, p.tiledWeight, p.tiledX, p.tiledXStride, startRow, endRow, p.tiledCols, p.tiledK)
	case gguf.GGMLTypeQ6_K:
		tensor.GEMVTiledQ6_K_Q8_KRange(p.tiledY, p.tiledYStride, p.tiledWeight, p.tiledQ8K, p.tiledQ8KStride, startRow, endRow, p.tiledCols, p.tiledK)
	case gguf.GGMLTypeQ4_K:
		tensor.GEMVTiledQ4_K_Q8_KRange(p.tiledY, p.tiledYStride, p.tiledWeight, p.tiledQ8K, p.tiledQ8KStride, startRow, endRow, p.tiledCols, p.tiledK)
	}
}

// runAttnHeads computes the disjoint head range owned by one worker. Each head
// writes its own slice of out and uses a private scratch region, so no
// synchronization is required inside the worker.
func (p *WorkerPool) runAttnHeads(workerID int) {
	startHead := (workerID * p.attnNumHead) / p.numWorkers
	endHead := ((workerID + 1) * p.attnNumHead) / p.numWorkers
	if startHead >= p.attnNumHead {
		return
	}
	if endHead > p.attnNumHead {
		endHead = p.attnNumHead
	}

	base := workerID * MaxContextLen
	scratch := p.attnScratch[base : base+p.attnPos+1]

	for h := startHead; h < endHead; h++ {
		attentionHead(p.attnCache, p.attnLayer, p.attnPos, p.attnQ, p.attnOut, h, p.attnQPerKV, p.attnHeadDim, p.attnScale, scratch)
	}
}

// ParallelAttention distributes the query heads across the persistent workers
// once the context is long enough to amortize the wake-up cost. Below the
// threshold, or without a usable pool, the heads are computed sequentially.
func (p *WorkerPool) ParallelAttention(scratch []float32, cache *KVCache, layer, pos int, q, out []float32, numHeads, kvHeads, headDim int, scale float32) {
	qPerKV := numHeads / kvHeads

	if p == nil || p.numWorkers <= 1 || numHeads < 2 || pos < attnParallelThreshold {
		for h := 0; h < numHeads; h++ {
			attentionHead(cache, layer, pos, q, out, h, qPerKV, headDim, scale, scratch[:pos+1])
		}
		return
	}

	p.attnCache = cache
	p.attnLayer = layer
	p.attnPos = pos
	p.attnScale = scale
	p.attnNumHead = numHeads
	p.attnQPerKV = qPerKV
	p.attnHeadDim = headDim
	p.attnQ = q
	p.attnOut = out
	p.attnMode = true

	p.doneWg.Add(p.numWorkers)
	p.dispatches.Add(1)
	for i := 0; i < p.numWorkers; i++ {
		p.startChans[i] <- struct{}{}
	}
	p.doneWg.Wait()

	p.attnMode = false
}
