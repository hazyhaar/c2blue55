// Package engine — inference_cascade.go
// Cascade d'inférence CPU à trois étages :
// - Couche 0 (< 500 ns, 0 B/op) : Filtres réflexes, axiomes ontologiques O(1), hachage parfait
// - Couche 1a (< 1 µs, 0 B/op) : goclassifier conforme (1-alpha) + sonde ternaire RaBitQ
// - Couche 1b (< 3 µs, 0 B/op) : Inférence spécialisée sur disquette .c2book mmap (INT8 DecisionHead)
// Intègre le principe d'invariance défensive : interdiction stricte d'adoucissement des menaces.
package engine

import (
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/goclassifier"
)

// Étages de décision de la cascade.
const (
	StageL0  uint8 = 0 // Réflexe O(1)
	StageL1a uint8 = 1 // Conforme goclassifier
	StageL1b uint8 = 2 // Disquette spécialisée INT8
)

// Actions de verdict de la cascade.
const (
	VerdictPass       uint8 = 1 // Trafic nominal certifié
	VerdictBlock      uint8 = 2 // Menace confirmée (veto formel)
	VerdictQuarantine uint8 = 3 // Ambiguïté résiduelle / isolation
)

// FlagArenaInvalid marque un verdict rendu sans avoir pu lire la charge
// longue scellée : page d'arène recyclée, en cours d'écriture ou altérée.
const FlagArenaInvalid uint32 = 0x2000

// CascadeVerdict structure le résultat d'évaluation sans allocation.
type CascadeVerdict struct {
	Stage        uint8
	Action       uint8
	Flags        uint32
	ThreatID     uint32
	HammingDist  int
	ConfidenceQ8 uint16
	DurationNs   int64
	// OntoSubject et OntoContext recopient le contexte ontologique sous
	// lequel l'événement a été évalué ; la preuve forensique les scelle pour
	// que le rejeu se fasse sous le même contexte.
	OntoSubject uint8
	OntoContext uint8
}

// CascadeContext porte le sujet et le contexte ontologiques d'un événement.
// L'événement de 128 octets ne dit ni si le processus tient un terminal ni
// s'il appartient à une unité systemd : ces faits viennent de la provenance
// vérifiée par la sonde (LSM, /proc), jamais d'une déclaration du processus.
// La valeur nulle (sujet et contexte inconnus) ne certifie rien.
type CascadeContext struct {
	Subject uint8 // Subj*
	Context uint8 // Ctx*
}

// ProcessProvenance rassemble les constatations système qui permettent de
// dériver un CascadeContext.
type ProcessProvenance struct {
	PID          uint32
	UID          uint32
	EUID         uint32
	LoginSession bool   // audit loginuid posé : processus issu d'une session utilisateur
	HasTTY       bool   // terminal de contrôle attaché
	SystemdUnit  bool   // cgroup v2 d'une unité de service systemd (system.slice)
	ExeTarget    []byte // cible de /proc/<pid>/exe
	IsMemfd      bool
	IsDeleted    bool
	HasWXAnon    bool
	Comm         []byte
}

// DeriveCascadeContext dérive le contexte ontologique d'un événement depuis sa
// provenance. Les contextes hostiles établis par DeriveOntoContext (kworker
// usurpé, memfd, binaire supprimé, pages W+X, résidence temporaire) priment
// toujours. Un contexte bénin (CtxInteractiveTTY, CtxSystemdUnit) n'est posé
// que si la provenance l'établit sans ambiguïté et sans élévation setuid.
func DeriveCascadeContext(pv ProcessProvenance) CascadeContext {
	var c CascadeContext
	switch {
	case pv.IsMemfd:
		c.Subject = SubjMemfdAnon
	case pv.IsDeleted:
		c.Subject = SubjDeletedBinary
	case pv.SystemdUnit && !pv.LoginSession && pv.UID == 0:
		c.Subject = SubjRootSystemd
	case pv.SystemdUnit && !pv.LoginSession:
		c.Subject = SubjServiceUnpriv
	case pv.LoginSession && pv.HasTTY && pv.UID == 0:
		c.Subject = SubjRootInteractive
	case pv.LoginSession && pv.HasTTY:
		c.Subject = SubjUserInteractive
	default:
		c.Subject = SubjUnknown
	}

	if hostile := DeriveOntoContext(pv.ExeTarget, pv.IsMemfd, pv.IsDeleted, pv.HasWXAnon, pv.Comm, pv.PID); hostile != CtxDefault {
		c.Context = hostile
		return c
	}
	if pv.EUID != pv.UID {
		c.Context = CtxDefault // élévation setuid : aucune certification bénigne
		return c
	}
	switch c.Subject {
	case SubjRootSystemd, SubjServiceUnpriv:
		c.Context = CtxSystemdUnit
	case SubjUserInteractive, SubjRootInteractive:
		c.Context = CtxInteractiveTTY
	default:
		c.Context = CtxDefault
	}
	return c
}

// CascadeEngine orchestre le pipeline d'inférence CPU haute cadence.
type CascadeEngine struct {
	extractor FeatureExtractor
	arena     *ArenaPool
	codebook  *Codebook
	grayzone  *GrayZoneDecider
	floppies  [4]*FloppySlot // index 1: LOLBAS, 2: DNS, 3: MCP
	// probe est la sonde conforme de repli, alimentée à la main par
	// AddPrototype ; elle ne sert que si la disquette montée n'embarque pas sa
	// propre sonde.
	probe *goclassifier.RabitqProbe
}

// NewCascadeEngine initialise la cascade avec ses composants pré-alloués.
func NewCascadeEngine(cb *Codebook, gz *GrayZoneDecider) *CascadeEngine {
	ce := &CascadeEngine{
		extractor: NewFeatureExtractor(),
		arena:     DefaultArenaPool(),
		codebook:  cb,
		grayzone:  gz,
	}
	for i := range ce.floppies {
		ce.floppies[i] = NewFloppySlot()
	}
	probe, _ := goclassifier.NewRabitqProbe(4)
	ce.probe = probe
	return ce
}

// MountFloppy associe une disquette spécialisée à son sous-système (1=Proc/LOLBAS, 2=Net/DNS, 3=MCP).
// La sonde conforme L1a construite au chargement à partir des prototypes de la
// disquette commute avec elle, atomiquement : une famille n'évalue jamais contre
// les prototypes d'une autre, et aucun lecteur ne voit une sonde en cours de
// remplissage.
func (ce *CascadeEngine) MountFloppy(family uint16, disk *FloppyDisk) {
	if family >= 1 && int(family) < len(ce.floppies) {
		ce.floppies[family].Swap(disk)
	}
}

// AddPrototype ajoute un vecteur prototype d'étalonnage dans la sonde conforme
// de repli (0=Bénin, 1=Hostile). Cette sonde n'est consultée que pour une
// famille dont la disquette n'embarque pas de prototypes ; l'appel doit
// précéder toute évaluation concurrente.
func (ce *CascadeEngine) AddPrototype(class int, features []float32) error {
	if ce.probe == nil {
		return nil
	}
	return ce.probe.AddPrototype(class, features)
}

// GetFloppy retourne la disquette actuellement montée pour une famille donnée.
func (ce *CascadeEngine) GetFloppy(family uint16) *FloppyDisk {
	if family >= 1 && int(family) < len(ce.floppies) {
		return ce.floppies[family].Current()
	}
	return nil
}

// EvaluateEvent évalue un événement sans contexte ontologique établi.
// Garanti sans allocation tas (0 B/op) sur tout le parcours.
func (ce *CascadeEngine) EvaluateEvent(ev *Probe_event_t) CascadeVerdict {
	return ce.EvaluateEventCtx(ev, CascadeContext{})
}

// EvaluateEventCtx évalue un événement en suivant strictement la hiérarchie
// L0 -> L1a -> L1b, sous le contexte ontologique établi par la provenance.
// La charge est résolue une seule fois ; si la charge longue scellée ne peut
// être relue à l'identique, le verdict est au moins VerdictQuarantine
// (fail-closed), jamais une évaluation du seul préfixe.
func (ce *CascadeEngine) EvaluateEventCtx(ev *Probe_event_t, cctx CascadeContext) CascadeVerdict {
	start := time.Now().UnixNano()
	if ev == nil {
		return CascadeVerdict{Stage: StageL0, Action: VerdictPass}
	}
	disk := ce.diskFor(ev.Subsystem)

	if ev.Flags&FlagLongPayload == 0 {
		return ce.evaluateResolved(ev, ev.Payload[:payloadUsed(ev.Payload[:])], cctx, disk, start)
	}

	var page [PageSize]byte
	payload, err := ce.arena.ResolvePayload(ev, &page)
	if err != nil {
		v := CascadeVerdict{
			Stage:       StageL0,
			Action:      VerdictQuarantine,
			Flags:       ev.Flags | 0x0004 | FlagArenaInvalid, // FlagAnomaly
			OntoSubject: cctx.Subject,
			OntoContext: cctx.Context,
		}
		// Le préfixe de 80 octets appartient à l'événement et reste
		// authentique : un mot-clé hostile y aggrave la quarantaine en veto,
		// il ne peut jamais l'adoucir.
		if _, hit := disk.MatchKeyword(ev.Payload[:metaOffsetPageIdx]); hit {
			v.Action = VerdictBlock
			v.Flags |= 0x0002 | 0x0008 // FlagBlocked | FlagLOLBAS
			v.ConfidenceQ8 = 256
		}
		v.DurationNs = time.Now().UnixNano() - start
		return v
	}
	return ce.evaluateResolved(ev, payload, cctx, disk, start)
}

// diskFor retourne la disquette montée pour le sous-système de l'événement.
func (ce *CascadeEngine) diskFor(subsystem uint16) *FloppyDisk {
	var family uint16
	switch subsystem {
	case 1: // SubProc
		family = FloppyFamilyLOLBAS
	case 3: // SubNet
		family = FloppyFamilyDNSC2
	case 4: // SubMCP
		family = FloppyFamilyAgentMCP
	default:
		return nil
	}
	return ce.floppies[family].Current()
}

// evaluateResolved déroule la cascade sur une charge déjà résolue. Le rejeu
// forensique l'appelle avec la charge scellée dans la preuve.
func (ce *CascadeEngine) evaluateResolved(ev *Probe_event_t, payload []byte, cctx CascadeContext, disk *FloppyDisk, start int64) CascadeVerdict {
	var v CascadeVerdict
	v.Stage = StageL0
	v.Action = VerdictPass
	v.Flags = ev.Flags
	v.OntoSubject = cctx.Subject
	v.OntoContext = cctx.Context

	// =========================================================================
	// COUCHE 0 : Réflexe Métrique SIMD & Axiomes Ontologiques (< 500 ns)
	// =========================================================================

	// 1. Détection de mots-clés réflexes sur la disquette montée
	if disk != nil {
		if _, hit := disk.MatchKeyword(payload); hit {
			v.Action = VerdictBlock
			v.Flags |= 0x0002 | 0x0008 // FlagBlocked | FlagLOLBAS
			v.ConfidenceQ8 = 256
			v.DurationNs = time.Now().UnixNano() - start
			return v // Veto immédiat L0
		}
	}

	// 2. Évaluation ontologique déterministe O(1)
	ontoKey := deriveCascadeOntoKey(ev, cctx)
	ontoVerdict := EvaluateOntology(ontoKey)
	if ontoVerdict == OntoVerdictDeny {
		v.Action = VerdictBlock
		v.Flags |= 0x0002 // FlagBlocked
		v.ConfidenceQ8 = 256
		v.DurationNs = time.Now().UnixNano() - start
		return v // Veto ontologique inviolable
	}

	// Si bénignité ontologique certifiée et charge anodine
	if ontoVerdict == OntoVerdictAllow && len(payload) < 32 {
		v.Action = VerdictPass
		v.DurationNs = time.Now().UnixNano() - start
		return v
	}

	// =========================================================================
	// COUCHE 1a : goclassifier Conforme + Sonde RaBitQ (< 1 µs)
	// =========================================================================
	v.Stage = StageL1a

	var features [EmbeddingDim]float32
	if !ce.extractor.ExtractResolvedTo(ev, payload, features[:]) {
		v.Action = VerdictQuarantine
		v.Flags |= 0x0004 // FlagAnomaly (fail-safe)
		v.DurationNs = time.Now().UnixNano() - start
		return v
	}

	var bitcode [codebookWords]uint64
	QuantizeFHT512(features[:], &bitcode)

	// Sonde conforme : celle de la disquette montée, sinon la sonde de repli.
	probe := disk.Probe()
	if probe == nil && ce.probe != nil && ce.probe.PrototypeCount(0) > 0 && ce.probe.PrototypeCount(1) > 0 {
		probe = ce.probe
	}
	if probe != nil {
		stats, err := probe.Probe(features[:], 0, 1)
		if err == nil {
			if stats.Verdict == goclassifier.ProbeConfirm && !disk.nearThreat(&bitcode) {
				// Confirmé bénin sans ambiguïté, hors du voisinage strict de
				// toute attaque réelle de la disquette.
				v.Action = ce.applyNonSoftening(v.Action, VerdictPass)
				v.DurationNs = time.Now().UnixNano() - start
				return v
			} else if stats.Verdict == goclassifier.ProbeAnomaly {
				// Échantillon hors distribution manifeste
				v.Flags |= 0x0004 // FlagAnomaly
			}
		}
	}

	// =========================================================================
	// COUCHE 1b : Tête de Décision INT8 sur Disquette Spécialisée (< 3 µs)
	// =========================================================================
	v.Stage = StageL1b

	if disk != nil {
		// 1. Recherche du centroïde RaBitQ le plus proche dans la disquette
		match, dist, found := disk.SearchCentroid(&bitcode, 128)
		if found {
			v.HammingDist = dist
			v.ThreatID = match.ThreatID
			if dist <= disk.BlockRadius() { // Proximité stricte avec un centroïde d'attaque réel
				v.Action = ce.applyNonSoftening(v.Action, VerdictBlock)
				v.Flags |= 0x0002 // FlagBlocked
				v.ConfidenceQ8 = uint16((128 - dist) * 2)
				v.DurationNs = time.Now().UnixNano() - start
				return v
			} else if dist <= 24 { // Zone suspecte : mise en quarantaine
				v.Action = ce.applyNonSoftening(v.Action, VerdictQuarantine)
				v.Flags |= 0x0004 // FlagAnomaly
				v.ConfidenceQ8 = 160
			}
		}

		// 2. Inférence linéaire entière DecisionHead (Zero-Alloc, INT8)
		predClass, _, conforms := disk.PredictINT8(features[:])
		if predClass == 1 && conforms {
			// Classe hostile certifiée conforme
			v.Action = ce.applyNonSoftening(v.Action, VerdictBlock)
			v.Flags |= 0x0002 // FlagBlocked
			v.ConfidenceQ8 = 220
			v.DurationNs = time.Now().UnixNano() - start
			return v
		} else if predClass == 1 && !conforms {
			// Suspicion sans conformité complète : mise en quarantaine
			v.Action = ce.applyNonSoftening(v.Action, VerdictQuarantine)
			v.Flags |= 0x0004 // FlagAnomaly
			v.ConfidenceQ8 = 128
			v.DurationNs = time.Now().UnixNano() - start
			return v
		}
	}

	v.Action = ce.applyNonSoftening(v.Action, VerdictPass)
	v.DurationNs = time.Now().UnixNano() - start
	return v
}

// deriveCascadeOntoKey extrait un quadruplet ontologique propre et typé depuis
// l'événement et son contexte établi. Sans provenance, le sujet et le contexte
// restent inconnus : aucun axiome de bénignité ne peut alors s'appliquer.
func deriveCascadeOntoKey(ev *Probe_event_t, cctx CascadeContext) OntoKey {
	subj := cctx.Subject
	var act uint8
	var tgt uint8

	switch ev.Action {
	case 1: // ActExec
		act = ActExecve
	case 2: // ActOpen
		act = ActWriteFile
	case 3: // ActConnect
		act = ActConnectNet
	case 7: // ActMmapExec
		act = ActMprotectWX
	default:
		act = ActUnknown
	}

	switch ev.Subsystem {
	case 1: // SubProc
		tgt = TgtBinSystem
	case 2: // SubFile
		tgt = TgtTmpExec
	case 3: // SubNet
		tgt = TgtNetExternal
	case 4: // SubMCP
		tgt = TgtPipeInterpreter
	default:
		tgt = TgtUnknown
	}

	return PackOntoKey(subj, act, tgt, cctx.Context)
}

// applyNonSoftening garantit l'invariance défensive :
// Un verdict plus sévère (VerdictBlock > VerdictQuarantine > VerdictPass) posé
// par un étage antérieur ne peut JAMAIS être rétrogradé par un étage ultérieur.
func (ce *CascadeEngine) applyNonSoftening(priorAction, newAction uint8) uint8 {
	if priorAction == VerdictBlock {
		return VerdictBlock
	}
	if priorAction == VerdictQuarantine && newAction == VerdictPass {
		return VerdictQuarantine
	}
	return newAction
}
