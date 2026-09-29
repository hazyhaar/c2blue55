package c2blue55

import "sync"

// Le routeur multi-corpus prolonge le routeur fan-out par sous-système. Là où
// Router segmente le flux selon le sous-système d'origine (processus, fichiers,
// réseau, mémoire), CorpusRouter segmente le même flux selon le domaine
// applicatif de sécurité évalué, afin que le scanner d'audit puisse confronter
// une fenêtre de code à plusieurs catalogues de menaces en parallèle.
//
// Chaque corpus dispose d'un sous-anneau SPSC verrouillage-libre identique à
// ceux de router.go. Les six sous-anneaux sont disjoints par ligne de cache :
// six producteurs logiques peuvent y déposer sans faux-partage, et six
// consommateurs spécialisés les vident chacun de leur côté.

const (
	// CorpusRingCount fixe le nombre de sous-anneaux de corpus.
	CorpusRingCount = 6

	// CorpusWebCache cible les piles d'exécution web et de file d'attente :
	// Node.js, Redis, BullMQ.
	CorpusWebCache uint16 = 1

	// CorpusK8sContainer cible l'orchestration de conteneurs et les garanties
	// de noyau associées : Kubernetes, containerd, cgroups.
	CorpusK8sContainer uint16 = 2

	// CorpusMiddleware cible les bus de messages et leur runtime : Apache
	// Kafka, machine virtuelle Java, Spring.
	CorpusMiddleware uint16 = 3

	// CorpusProxyMicro cible les intermédiaires réseau et la persistance
	// adressable par clé : proxies, gRPC, bases NoSQL.
	CorpusProxyMicro uint16 = 4

	// CorpusCloudCI cible les services d'instance cloud et les chaînes
	// d'intégration : métadonnées d'instance IMDS, secrets de CI/CD.
	CorpusCloudCI uint16 = 5

	// CorpusKernelUnix cible le bruit d'origine système : Unix, noyau Linux,
	// avis de vulnérabilité CVE.
	CorpusKernelUnix uint16 = 6
)

// CorpusRouter détient les six sous-anneaux spécialisés.
type CorpusRouter struct {
	rings [CorpusRingCount]SubRing
}

// NewCorpusRouter initialise un routeur multi-corpus et ses six sous-anneaux.
func NewCorpusRouter() *CorpusRouter {
	return &CorpusRouter{}
}

// RingWebCache retourne le sous-anneau du corpus web et file d'attente.
func (r *CorpusRouter) RingWebCache() *SubRing { return &r.rings[0] }

// RingK8sContainer retourne le sous-anneau du corpus orchestration conteneurs.
func (r *CorpusRouter) RingK8sContainer() *SubRing { return &r.rings[1] }

// RingMiddleware retourne le sous-anneau du corpus bus de messages et JVM.
func (r *CorpusRouter) RingMiddleware() *SubRing { return &r.rings[2] }

// RingProxyMicro retourne le sous-anneau du corpus proxies et micro-services.
func (r *CorpusRouter) RingProxyMicro() *SubRing { return &r.rings[3] }

// RingCloudCI retourne le sous-anneau du corpus instance cloud et CI/CD.
func (r *CorpusRouter) RingCloudCI() *SubRing { return &r.rings[4] }

// RingKernelUnix retourne le sous-anneau du corpus noyau Unix et CVE.
func (r *CorpusRouter) RingKernelUnix() *SubRing { return &r.rings[5] }

// corpusIndex associe un identifiant de corpus (1..6) à son sous-anneau.
func corpusIndex(corpusID uint16) int {
	if corpusID < CorpusWebCache || corpusID > CorpusKernelUnix {
		return -1
	}
	return int(corpusID - CorpusWebCache)
}

// Dispatch achemine un événement vers le corpus désigné par son identifiant.
// Il retourne faux lorsque l'identifiant est hors du domaine connu, lorsque
// l'événement est nul, ou lorsque le sous-anneau cible est saturé.
func (r *CorpusRouter) Dispatch(corpusID uint16, ev *Event) bool {
	index := corpusIndex(corpusID)
	if index < 0 || ev == nil {
		return false
	}
	return r.rings[index].Push(ev)
}

// DispatchFanout distribue le même événement à tous les sous-anneaux de corpus.
// Cette voie sert lorsqu'une fenêtre de code doit être confrontée simultanément
// à l'ensemble des catalogues. Il retourne le nombre d'anneaux ayant accepté
// l'événement sans rejet.
func (r *CorpusRouter) DispatchFanout(ev *Event) int {
	if ev == nil {
		return 0
	}
	accepted := 0
	for i := range r.rings {
		if r.rings[i].Push(ev) {
			accepted++
		}
	}
	return accepted
}

// DispatchFanoutBatch distribue un lot d'événements à tous les sous-anneaux.
// Chaque sous-anneau reçoit la totalité du lot en une seule opération de dépôt :
// la tête de production n'est publiée qu'une fois par anneau, ce qui remplace
// n paires Load/Store par une seule et réduit d'autant les barrières mémoire.
// Il retourne le nombre total de placements acceptés, soit au plus
// len(events) * CorpusRingCount ; les placements refusés sur saturation sont
// comptabilisés dans le compteur de rejets de l'anneau concerné.
func (r *CorpusRouter) DispatchFanoutBatch(events []Event) int {
	if len(events) == 0 {
		return 0
	}
	accepted := 0
	for i := range r.rings {
		accepted += r.rings[i].pushBatch(events)
	}
	return accepted
}

// pushBatch dépose au plus len(events) événements contigus sur un sous-anneau.
// La capacité résiduelle est évaluée une seule fois à partir de head et tail,
// puis la tête est publiée par un store unique. L'appelant demeure l'unique
// producteur du sous-anneau, condition nécessaire au caractère verrouillage-libre
// du protocole SPSC.
func (r *SubRing) pushBatch(events []Event) int {
	if len(events) == 0 {
		return 0
	}
	head := r.head.Load()
	available := uint64(subRingSlots) - (head - r.tail.Load())
	if available == 0 {
		r.drops.Add(uint64(len(events)))
		return 0
	}
	n := len(events)
	if uint64(n) > available {
		n = int(available)
	}
	for i := 0; i < n; i++ {
		r.slots[(head+uint64(i))&subRingMask] = events[i]
	}
	r.head.Store(head + uint64(n))
	if n < len(events) {
		r.drops.Add(uint64(len(events) - n))
	}
	return n
}

// CorpusWorkers regroupe les six consommateurs spécialisés, un par corpus.
type CorpusWorkers struct {
	WebCache     Worker
	K8sContainer Worker
	Middleware   Worker
	ProxyMicro   Worker
	CloudCI      Worker
	KernelUnix   Worker
}

// RunWorkers lance les six goroutines de travail, une par corpus, puis attend
// leur retrait effectif après fermeture du canal d'arrêt.
func (r *CorpusRouter) RunWorkers(workers CorpusWorkers, stop <-chan struct{}) {
	var wg sync.WaitGroup
	wg.Add(CorpusRingCount)
	go func() { defer wg.Done(); r.rings[0].Consume(workers.WebCache, stop) }()
	go func() { defer wg.Done(); r.rings[1].Consume(workers.K8sContainer, stop) }()
	go func() { defer wg.Done(); r.rings[2].Consume(workers.Middleware, stop) }()
	go func() { defer wg.Done(); r.rings[3].Consume(workers.ProxyMicro, stop) }()
	go func() { defer wg.Done(); r.rings[4].Consume(workers.CloudCI, stop) }()
	go func() { defer wg.Done(); r.rings[5].Consume(workers.KernelUnix, stop) }()
	wg.Wait()
}
