package c2blue55

import "sync"

// Garde d'épisode des QNAME hors LDH par domaine parent (lot V1).
const (
	capaciteGardeNonLDH       = 1024 // puissance de deux
	sondesGardeNonLDH         = 8
	empreintesSousGardeNonLDH = 32
	// FenetreGardeNonLDHNs borne l'épisode : 300 s glissantes depuis la première question.
	FenetreGardeNonLDHNs int64 = 300_000_000_000

	seuilSousDistinctsSalveBinaire = 3
	seuilQuestionsTypeTunnel       = 2
	seuilSousDistinctsSalveUTF8    = 8
)

// Indicateurs et raisons rendus par la garde (chaînes constantes, sans allocation).
const (
	IndicatorNonLDHBinaryBurst     = "NON_LDH_BINARY_BURST"
	IndicatorNonLDHTunnelQType     = "NON_LDH_TUNNEL_QTYPE"
	IndicatorNonLDHUTF8UniqueBurst = "NON_LDH_UTF8_UNIQUE_BURST"

	ReasonV1NonLDHBinaryBurst     = "REASON_V1_NONLDH_BINARY_BURST"
	ReasonV1NonLDHTunnelQType     = "REASON_V1_NONLDH_TUNNEL_QTYPE"
	ReasonV1NonLDHUTF8UniqueBurst = "REASON_V1_NONLDH_UTF8_UNIQUE_BURST"
)

// NonLDHVerdict est la décision de la garde pour une question hors LDH.
type NonLDHVerdict struct {
	Hostile          bool
	Indicator        string
	Reason           string
	QuestionsFenetre uint16
	SousDistincts    uint16
}

type caseGardeNonLDH struct {
	empreinteParent  uint64
	debutFenetreNs   int64
	derniereVueNs    int64
	questions        uint16
	sousDistincts    uint16
	questionsTunnel  uint16
	curseurEmpreinte uint8
	occupee          bool
	empreintesSous   [empreintesSousGardeNonLDH]uint64
}

// NonLDHBurstGuard compte, par domaine parent et sur une fenêtre bornée, les
// questions hors LDH et leurs sous-domaines distincts. Table fixe allouée une
// fois ; Observe n'alloue rien. Sûr pour un usage concurrent.
type NonLDHBurstGuard struct {
	mu        sync.Mutex
	cases     [capaciteGardeNonLDH]caseGardeNonLDH
	evictions uint64
}

// Reset vide la garde (changement de capture dans l'évaluation de laboratoire).
func (garde *NonLDHBurstGuard) Reset() {
	garde.mu.Lock()
	garde.cases = [capaciteGardeNonLDH]caseGardeNonLDH{}
	garde.evictions = 0
	garde.mu.Unlock()
}

// Evictions rend le nombre de parents vivants évincés faute de place.
func (garde *NonLDHBurstGuard) Evictions() uint64 {
	garde.mu.Lock()
	defer garde.mu.Unlock()
	return garde.evictions
}

// IsTunnelQType reconnaît NULL et la plage d'usage privé RFC 6895 (65280-65534).
func IsTunnelQType(qtype uint16) bool {
	return qtype == TypeNULL || (qtype >= 65280 && qtype <= 65534)
}

// Observe enregistre une question et rend la décision de la garde. Un QNAME LDH
// ou une instance DNS-SD n'est jamais compté ni condamné par la garde.
func (garde *NonLDHBurstGuard) Observe(parent, sousDomaine []byte, profil QNameGrammarProfile, qtype uint16, instantNs int64) NonLDHVerdict {
	if profil.Classe == QNameGrammarLDH || profil.Classe == QNameGrammarDNSSDInstance {
		return NonLDHVerdict{}
	}
	empreinteParent := fnv64Msg(parent)
	empreinteSous := fnv64Msg(sousDomaine)

	garde.mu.Lock()
	defer garde.mu.Unlock()
	entree := garde.trouverOuReserver(empreinteParent, instantNs)
	if instantNs < entree.derniereVueNs {
		instantNs = entree.derniereVueNs
	}
	if instantNs-entree.debutFenetreNs > FenetreGardeNonLDHNs {
		*entree = caseGardeNonLDH{empreinteParent: empreinteParent, debutFenetreNs: instantNs, occupee: true}
	}
	entree.derniereVueNs = instantNs
	if entree.questions < ^uint16(0) {
		entree.questions++
	}
	if IsTunnelQType(qtype) && entree.questionsTunnel < ^uint16(0) {
		entree.questionsTunnel++
	}
	if !entree.empreinteRecente(empreinteSous) {
		entree.empreintesSous[entree.curseurEmpreinte] = empreinteSous
		entree.curseurEmpreinte = (entree.curseurEmpreinte + 1) % empreintesSousGardeNonLDH
		if entree.sousDistincts < ^uint16(0) {
			entree.sousDistincts++
		}
	}

	decision := NonLDHVerdict{QuestionsFenetre: entree.questions, SousDistincts: entree.sousDistincts}
	switch {
	case IsTunnelQType(qtype) && entree.questionsTunnel >= seuilQuestionsTypeTunnel:
		decision.Hostile, decision.Indicator, decision.Reason = true, IndicatorNonLDHTunnelQType, ReasonV1NonLDHTunnelQType
	case (profil.Classe == QNameGrammarBinary || profil.Classe == QNameGrammarASCIIOutsideLDH) &&
		entree.sousDistincts >= seuilSousDistinctsSalveBinaire:
		decision.Hostile, decision.Indicator, decision.Reason = true, IndicatorNonLDHBinaryBurst, ReasonV1NonLDHBinaryBurst
	case profil.Classe == QNameGrammarUTF8Local && entree.sousDistincts >= seuilSousDistinctsSalveUTF8 &&
		uint32(entree.sousDistincts)*10 >= uint32(entree.questions)*9:
		decision.Hostile, decision.Indicator, decision.Reason = true, IndicatorNonLDHUTF8UniqueBurst, ReasonV1NonLDHUTF8UniqueBurst
	}
	return decision
}

func (entree *caseGardeNonLDH) empreinteRecente(empreinte uint64) bool {
	retenues := min(int(entree.sousDistincts), empreintesSousGardeNonLDH)
	for indice := range retenues {
		if entree.empreintesSous[indice] == empreinte {
			return true
		}
	}
	return false
}

// trouverOuReserver sonde au plus sondesGardeNonLDH cases ; à défaut de case
// libre ou expirée, la case la plus anciennement vue est évincée et comptée.
func (garde *NonLDHBurstGuard) trouverOuReserver(empreinteParent uint64, instantNs int64) *caseGardeNonLDH {
	depart := int(empreinteParent & (capaciteGardeNonLDH - 1))
	var candidate *caseGardeNonLDH
	for sonde := range sondesGardeNonLDH {
		entree := &garde.cases[(depart+sonde)&(capaciteGardeNonLDH-1)]
		if entree.occupee && entree.empreinteParent == empreinteParent {
			return entree
		}
		expiree := entree.occupee && instantNs-entree.derniereVueNs > FenetreGardeNonLDHNs
		if !entree.occupee || expiree {
			if candidate == nil || candidate.occupee {
				candidate = entree
			}
			continue
		}
		if candidate == nil || (candidate.occupee && entree.derniereVueNs < candidate.derniereVueNs) {
			candidate = entree
		}
	}
	if candidate.occupee && instantNs-candidate.derniereVueNs <= FenetreGardeNonLDHNs {
		garde.evictions++
	}
	*candidate = caseGardeNonLDH{empreinteParent: empreinteParent, debutFenetreNs: instantNs, occupee: true}
	return candidate
}
