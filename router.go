package c2blue55

import (
	"runtime"
	"sync"
	"sync/atomic"
)

// Le routeur fan-out SPSC segmente le flux d'observation global en quatre
// sous-anneaux spécialisés par sous-système. Chaque sous-anneau est une file
// circulaire verrouillage-libre à producteur unique et consommateur unique,
// dimensionnée sur une ligne de cache L1D : les têtes de production et de
// consommation résident sur des lignes distinctes, ce qui supprime le
// faux-partage.

const (
	// subRingSlots fixe la capacité d'un sous-anneau. 256 événements de 128
	// octets occupent 32 Kio, soit la taille d'un cache L1D usuel.
	subRingSlots = 256

	// subRingMask réalise l'indexation circulaire par masque binaire ; il
	// n'est valide que parce que subRingSlots est une puissance de deux.
	subRingMask = subRingSlots - 1

	// cacheLine est la taille de ligne de cache x86_64 visée par le rembourrage.
	cacheLine = 64

	// dispatchBatch borne le dépilage par lot de l'anneau global.
	dispatchBatch = 64

	// consumeBatch borne le vidage par lot d'un sous-anneau.
	consumeBatch = 64

	// routerRingCount est le nombre de sous-anneaux spécialisés.
	routerRingCount = 4
)


// SubRing est une file circulaire SPSC verrouillage-libre de 256 événements.
// Le rembourrage place head, tail, drops et slots sur des lignes de cache
// disjointes.
type SubRing struct {
	head  atomic.Uint64
	_     [cacheLine - 8]byte
	tail  atomic.Uint64
	_     [cacheLine - 8]byte
	drops atomic.Uint64
	_     [cacheLine - 8]byte
	slots [subRingSlots]Event
}

// Push dépose un événement dans le sous-anneau. Retourne faux et incrémente le
// compteur de rejets lorsque la file est saturée.
func (r *SubRing) Push(ev *Event) bool {
	head := r.head.Load()
	if head-r.tail.Load() >= subRingSlots {
		r.drops.Add(1)
		return false
	}
	r.slots[head&subRingMask] = *ev
	r.head.Store(head + 1)
	return true
}

// Pop retire un événement du sous-anneau. Retourne faux lorsque la file est vide.
func (r *SubRing) Pop(ev *Event) bool {
	tail := r.tail.Load()
	if tail >= r.head.Load() {
		return false
	}
	*ev = r.slots[tail&subRingMask]
	r.tail.Store(tail + 1)
	return true
}

// PopBatch retire jusqu'à maxEvents événements sans blocage.
func (r *SubRing) PopBatch(out []Event, maxEvents int) int {
	if maxEvents <= 0 {
		return 0
	}
	if len(out) < maxEvents {
		maxEvents = len(out)
	}
	tail := r.tail.Load()
	available := r.head.Load() - tail
	if available == 0 {
		return 0
	}
	n := int(available)
	if n > maxEvents {
		n = maxEvents
	}
	for i := 0; i < n; i++ {
		out[i] = r.slots[(tail+uint64(i))&subRingMask]
	}
	r.tail.Store(tail + uint64(n))
	return n
}

// Len retourne le nombre d'événements en attente dans le sous-anneau.
func (r *SubRing) Len() uint64 {
	head := r.head.Load()
	tail := r.tail.Load()
	if head < tail {
		return 0
	}
	return head - tail
}

// Drops retourne le compteur de rejets sur saturation.
func (r *SubRing) Drops() uint64 {
	return r.drops.Load()
}

// Router détient les quatre sous-anneaux spécialisés et un tampon de dépilage
// par lot réutilisé sans allocation.
type Router struct {
	rings        [routerRingCount]SubRing
	batch        [dispatchBatch]Event
	dropsUnknown atomic.Uint64
}

// NewRouter initialise un routeur et ses quatre sous-anneaux.
func NewRouter() *Router {
	return &Router{}
}

// RingProc retourne le sous-anneau des événements de processus (0x0001).
func (r *Router) RingProc() *SubRing { return &r.rings[0] }

// RingFile retourne le sous-anneau des événements de fichiers (0x0002).
func (r *Router) RingFile() *SubRing { return &r.rings[1] }

// RingNet retourne le sous-anneau des événements réseau (0x0003).
func (r *Router) RingNet() *SubRing { return &r.rings[2] }

// RingMCP retourne le sous-anneau des événements MCP (0x0004).
func (r *Router) RingMCP() *SubRing { return &r.rings[3] }

// RingMem retourne le sous-anneau des événements de mémoire (0x0004), alias conservé pour rétro-compatibilité.
func (r *Router) RingMem() *SubRing { return r.RingMCP() }

// ringIndex associe un identifiant de sous-système à son sous-anneau.
func ringIndex(subsystem uint16) int {
	switch subsystem {
	case SubProc:
		return 0
	case SubFile:
		return 1
	case SubNet:
		return 2
	case SubMCP: // SubMem pointe sur SubMCP
		return 3
	default:
		return -1
	}
}

// Dispatch achemine un événement vers son sous-anneau selon ev.Subsystem.
func (r *Router) Dispatch(ev *Event) bool {
	index := ringIndex(ev.Subsystem)
	if index < 0 {
		r.dropsUnknown.Add(1)
		return false
	}
	return r.rings[index].Push(ev)
}

// DropsUnknown retourne le nombre total d'événements rejetés car associés à un sous-système non routé.
func (r *Router) DropsUnknown() uint64 {
	return r.dropsUnknown.Load()
}

// DispatchBatch achemine un lot et retourne le nombre d'événements routés.
func (r *Router) DispatchBatch(events []Event) int {
	routed := 0
	for i := range events {
		if r.Dispatch(&events[i]) {
			routed++
		}
	}
	return routed
}

// DispatchLoop dépile l'anneau global par lot de 64 et achemine chaque
// événement. La boucle se retire proprement à la fermeture du canal d'arrêt.
func (r *Router) DispatchLoop(inputChannel *Channel, stop <-chan struct{}) {
	if inputChannel == nil {
		return
	}
	for {
		select {
		case <-stop:
			return
		default:
		}
		n := inputChannel.ReadBatch(r.batch[:], dispatchBatch)
		if n == 0 {
			runtime.Gosched()
			continue
		}
		r.DispatchBatch(r.batch[:n])
	}
}

// Worker consomme les événements d'un sous-anneau. L'implémentation ne doit pas
// retenir le pointeur reçu : le tampon de vidage est réutilisé d'un lot à l'autre.
type Worker interface {
	Handle(ev *Event)
}

// WorkerFunc adapte une fonction au contrat Worker.
type WorkerFunc func(ev *Event)

// Handle implémente Worker.
func (f WorkerFunc) Handle(ev *Event) { f(ev) }

// Consume vide le sous-anneau par lot de 64 jusqu'au signal d'arrêt.
func (r *SubRing) Consume(worker Worker, stop <-chan struct{}) {
	if worker == nil {
		return
	}
	var local [consumeBatch]Event
	for {
		select {
		case <-stop:
			return
		default:
		}
		n := r.PopBatch(local[:], consumeBatch)
		if n == 0 {
			runtime.Gosched()
			continue
		}
		for i := 0; i < n; i++ {
			worker.Handle(&local[i])
		}
	}
}

// WorkerProc corps de la goroutine de travail du sous-anneau processus.
func (r *Router) WorkerProc(worker Worker, stop <-chan struct{}) {
	r.rings[0].Consume(worker, stop)
}

// WorkerFile corps de la goroutine de travail du sous-anneau fichiers.
func (r *Router) WorkerFile(worker Worker, stop <-chan struct{}) {
	r.rings[1].Consume(worker, stop)
}

// WorkerNet corps de la goroutine de travail du sous-anneau réseau.
func (r *Router) WorkerNet(worker Worker, stop <-chan struct{}) {
	r.rings[2].Consume(worker, stop)
}

// WorkerMCP corps de la goroutine de travail du sous-anneau MCP.
func (r *Router) WorkerMCP(worker Worker, stop <-chan struct{}) {
	r.rings[3].Consume(worker, stop)
}

// WorkerMem corps de la goroutine de travail du sous-anneau mémoire (alias rétro-compatible).
func (r *Router) WorkerMem(worker Worker, stop <-chan struct{}) {
	r.WorkerMCP(worker, stop)
}

// Workers regroupe les quatre consommateurs spécialisés.
type Workers struct {
	Proc Worker
	File Worker
	Net  Worker
	MCP  Worker
	Mem  Worker // Alias rétro-compatible pour MCP
}

// RunWorkers lance les quatre goroutines de travail et attend leur retrait.
func (r *Router) RunWorkers(workers Workers, stop <-chan struct{}) {
	mcpWorker := workers.MCP
	if mcpWorker == nil && workers.Mem != nil {
		mcpWorker = workers.Mem
	}
	var wg sync.WaitGroup
	wg.Add(routerRingCount)
	go func() { defer wg.Done(); r.WorkerProc(workers.Proc, stop) }()
	go func() { defer wg.Done(); r.WorkerFile(workers.File, stop) }()
	go func() { defer wg.Done(); r.WorkerNet(workers.Net, stop) }()
	go func() { defer wg.Done(); r.WorkerMCP(mcpWorker, stop) }()
	wg.Wait()
}
