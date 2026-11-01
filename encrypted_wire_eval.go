package c2blue55

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
)

var (
	// ErrEncryptedWireTableFull : plus aucune case libre ; la capture n'est pas jugée.
	ErrEncryptedWireTableFull = errors.New("c2blue55: table des conversations chiffrées saturée ; capture non jugée")
	// ErrEncryptedWireContract : configuration ou capture hors contrat.
	ErrEncryptedWireContract = errors.New("c2blue55: évaluation de flux chiffrés hors contrat")
)

// Bornes physiques a priori (non apprises) des flux chiffrés.
const (
	chargePorteuseMin            = 56   // en deçà : accusé QUIC 1-RTT ou TCP pur
	chargeIntermediaireMax       = 900  // bande montante intermédiaire 56..900
	chargeQuasiMTUMin            = 1200 // paquet descendant proche du MTU
	saturationTournantsParKio    = 0.5  // plafond d'alternance d'un dialogue requête-réponse
	amplificationNetteCoupleeMax = 6    // borne d'amplification descendante d'un tunnel pollé
	octetsMontantsFenetreMin     = 256
	tournantsFenetreMin          = 2
	rafalesPorteusesBaliseMin    = 6
	dureeBaliseMinNs             = 60_000_000_000
	paquetsIsochronieMin         = 200
	regulariteNeutre             = 0.0
	plancherCoefficientVariation = 1.0 / 16

	// TailleMaximaleCaptureChiffree borne la lecture d'une capture (16 Gio).
	TailleMaximaleCaptureChiffree int64 = 16 << 30
)

// EncryptedWireConfig paramètre l'évaluateur ; la valeur nulle prend les défauts.
type EncryptedWireConfig struct {
	CapaciteConversations      int    // puissance de deux, défaut 4096
	DureeFenetreNs             uint64 // défaut 5 s
	SilenceInterRafaleNs       uint64 // défaut 1 s
	PaquetsMinimumConversation uint32 // défaut 4
}

func (config EncryptedWireConfig) avecDefauts() (EncryptedWireConfig, error) {
	if config.CapaciteConversations == 0 {
		config.CapaciteConversations = 4096
	}
	if config.DureeFenetreNs == 0 {
		config.DureeFenetreNs = 5_000_000_000
	}
	if config.SilenceInterRafaleNs == 0 {
		config.SilenceInterRafaleNs = 1_000_000_000
	}
	if config.PaquetsMinimumConversation == 0 {
		config.PaquetsMinimumConversation = 4
	}
	capacite := config.CapaciteConversations
	if capacite < 16 || capacite > 1<<20 || capacite&(capacite-1) != 0 {
		return config, fmt.Errorf("%w: capacité %d (puissance de deux entre 16 et 2^20)", ErrEncryptedWireContract, capacite)
	}
	return config, nil
}

// EncryptedWireStats compte chaque trame dans exactement une issue de décodage.
// Invariant : Trames == TramesRetenues + TramesHorsPerimetre + FragmentsIP + TramesMalformees.
type EncryptedWireStats struct {
	Trames                   uint64
	TramesRetenues           uint64
	TramesHorsPerimetre      uint64
	FragmentsIP              uint64
	TramesMalformees         uint64
	DatagrammesQUIC          uint64
	DatagrammesQUICInvalides uint64
	HorodatagesRegressifs    uint64
	Conversations            uint64
}

// ConversationKey regroupe client, serveur, port et transport, sans le port
// client : la clé survit au rebinding NAT et agrège les connexions multiples.
type ConversationKey struct {
	Client      [16]byte
	Serveur     [16]byte
	PortServeur uint16
	Transport   EncryptedTransport
}

type welfordCinetique struct {
	effectif          uint64
	moyenne           float64
	sommeEcartsCarres float64
}

func (accumulateur *welfordCinetique) ajouter(mesure float64) {
	accumulateur.effectif++
	ecart := mesure - accumulateur.moyenne
	accumulateur.moyenne += ecart / float64(accumulateur.effectif)
	accumulateur.sommeEcartsCarres += ecart * (mesure - accumulateur.moyenne)
}

// coefficientVariation rend l'écart-type d'échantillon rapporté à la moyenne
// et vrai, ou (0, faux) si l'effectif est inférieur à 2 ou la moyenne nulle.
func (accumulateur welfordCinetique) coefficientVariation() (float64, bool) {
	if accumulateur.effectif < 2 || accumulateur.moyenne <= 0 {
		return 0, false
	}
	coefficient := math.Sqrt(accumulateur.sommeEcartsCarres/float64(accumulateur.effectif-1)) / accumulateur.moyenne
	if math.IsNaN(coefficient) || math.IsInf(coefficient, 0) {
		return 0, false
	}
	return coefficient, true
}

// ConversationCounters est le relevé brut intégral d'une conversation.
type ConversationCounters struct {
	PremierNs, DernierNs              uint64
	OctetsMontants, OctetsDescendants uint64
	OctetsPorteurs                    uint64
	OctetsMontantsPorteurs            uint64
	OctetsMontantsNets                uint64
	OctetsDescendantsNets             uint64
	PaquetsMontants                   uint32
	PaquetsDescendants                uint32
	PaquetsMontantsIntermediaires     uint32
	PaquetsDescendantsQuasiMTU        uint32
	ChangementsDeSens                 uint32
	Rafales                           uint32
	RafalesPorteuses                  uint32
	FenetresObservees                 uint64
	FenetresActives                   uint32
	FenetresBidirectionnelles         uint32
	SerieBidirectionnelleMax          uint32
	ConnexionsInitiales               uint32
	ReassociationsPort                uint32
	DatagrammesQUICInvalides          uint32
}

type conversationChiffree struct {
	cle                  ConversationKey
	occupee              bool
	rang                 uint64 // ordre de première apparition
	releve               ConversationCounters
	sensPrecedentPorteur int8

	debutRafaleNs                 uint64
	octetsMontantsRafale          uint64
	octetsDescendantsRafale       uint64
	debutRafalePorteusePrecedente uint64
	interRafales                  welfordCinetique
	chargeMontanteRafale          welfordCinetique
	dernierMontantNs              uint64
	cadenceMontante               welfordCinetique

	debutFenetreNs                uint64
	paquetsFenetre                uint32
	tournantsFenetre              uint32
	octetsMontantsPorteursFenetre uint64
	serieBidirectionnelle         uint32

	longueurDCIDInitial uint8
	dcidInitial         [quicLongueurCIDMax]byte
	dernierPortClient   uint16
}

// EncryptedWireEvaluator agrège des trames chiffrées en conversations. Les
// tampons sont alloués par NewEncryptedWireEvaluator ; Observe n'alloue rien.
// Non sûr pour un usage concurrent : une instance par flux de capture.
type EncryptedWireEvaluator struct {
	config        EncryptedWireConfig
	conversations []conversationChiffree
	Stats         EncryptedWireStats
	trame         EncryptedWireFrame
}

// NewEncryptedWireEvaluator alloue la table fixe des conversations.
func NewEncryptedWireEvaluator(config EncryptedWireConfig) (*EncryptedWireEvaluator, error) {
	retenue, err := config.avecDefauts()
	if err != nil {
		return nil, err
	}
	return &EncryptedWireEvaluator{config: retenue, conversations: make([]conversationChiffree, retenue.CapaciteConversations)}, nil
}

// Observe décode une trame et met à jour sa conversation. Zéro allocation tas.
func (evaluateur *EncryptedWireEvaluator) Observe(paquet BenchPacket) error {
	evaluateur.Stats.Trames++
	trame := &evaluateur.trame
	switch DecodeEncryptedWireFrame(paquet, trame) {
	case EncryptedFrameRetained:
		evaluateur.Stats.TramesRetenues++
	case EncryptedFrameOutOfScope:
		evaluateur.Stats.TramesHorsPerimetre++
		return nil
	case EncryptedFrameIPFragment:
		evaluateur.Stats.FragmentsIP++
		return nil
	default:
		evaluateur.Stats.TramesMalformees++
		return nil
	}
	if trame.Transport == EncryptedTransportDoQ || trame.Transport == EncryptedTransportQUIC {
		evaluateur.Stats.DatagrammesQUIC++
		if trame.QUICInvalide {
			evaluateur.Stats.DatagrammesQUICInvalides++
		}
	}
	cle := ConversationKey{Transport: trame.Transport}
	portClient := trame.SourcePort
	if trame.Montant {
		cle.Client, cle.Serveur, cle.PortServeur = trame.SourceIP, trame.DestIP, trame.DestPort
	} else {
		cle.Client, cle.Serveur, cle.PortServeur = trame.DestIP, trame.SourceIP, trame.SourcePort
		portClient = trame.DestPort
	}
	conversation, err := evaluateur.trouverOuCreer(cle)
	if err != nil {
		return err
	}
	evaluateur.accumuler(conversation, trame, portClient)
	return nil
}

func empreinteConversation(cle *ConversationKey) uint64 {
	empreinte := uint64(14695981039346656037)
	melanger := func(octet byte) {
		empreinte ^= uint64(octet)
		empreinte *= 1099511628211
	}
	for _, octet := range cle.Client {
		melanger(octet)
	}
	for _, octet := range cle.Serveur {
		melanger(octet)
	}
	melanger(byte(cle.PortServeur >> 8))
	melanger(byte(cle.PortServeur))
	melanger(byte(cle.Transport))
	return empreinte
}

func (evaluateur *EncryptedWireEvaluator) trouverOuCreer(cle ConversationKey) (*conversationChiffree, error) {
	masque := uint64(len(evaluateur.conversations) - 1)
	position := empreinteConversation(&cle) & masque
	for range len(evaluateur.conversations) {
		conversation := &evaluateur.conversations[position]
		if !conversation.occupee {
			*conversation = conversationChiffree{cle: cle, occupee: true, rang: evaluateur.Stats.Conversations}
			evaluateur.Stats.Conversations++
			return conversation, nil
		}
		if conversation.cle == cle {
			return conversation, nil
		}
		position = (position + 1) & masque
	}
	return nil, ErrEncryptedWireTableFull
}

func (evaluateur *EncryptedWireEvaluator) accumuler(conversation *conversationChiffree, trame *EncryptedWireFrame, portClient uint16) {
	releve := &conversation.releve
	instant := trame.TimestampNs
	premierPaquet := releve.PaquetsMontants+releve.PaquetsDescendants == 0
	if premierPaquet {
		releve.PremierNs, releve.DernierNs = instant, instant
		conversation.debutFenetreNs = instant
		conversation.debutRafaleNs = instant
		conversation.dernierPortClient = portClient
		releve.Rafales = 1
	}
	if instant < releve.DernierNs {
		evaluateur.Stats.HorodatagesRegressifs++
		instant = releve.DernierNs
	}
	evaluateur.avancerFenetres(conversation, instant)
	if !premierPaquet && instant-releve.DernierNs >= evaluateur.config.SilenceInterRafaleNs {
		cloturerRafale(conversation)
		releve.Rafales++
		conversation.debutRafaleNs = instant
	}
	releve.DernierNs = instant

	charge := uint64(trame.ChargeUtile)
	porteur := charge >= chargePorteuseMin
	conversation.paquetsFenetre++
	if trame.Montant {
		releve.PaquetsMontants++
		releve.OctetsMontants += charge
		conversation.octetsMontantsRafale += charge
		if porteur {
			conversation.octetsMontantsPorteursFenetre += charge
			releve.OctetsMontantsPorteurs += charge
			releve.OctetsMontantsNets += charge - chargePorteuseMin
			if charge <= chargeIntermediaireMax {
				releve.PaquetsMontantsIntermediaires++
			}
		}
		if conversation.dernierMontantNs != 0 && instant-conversation.dernierMontantNs < evaluateur.config.SilenceInterRafaleNs {
			conversation.cadenceMontante.ajouter(float64(instant - conversation.dernierMontantNs))
		}
		conversation.dernierMontantNs = instant
	} else {
		releve.PaquetsDescendants++
		releve.OctetsDescendants += charge
		conversation.octetsDescendantsRafale += charge
		if porteur {
			releve.OctetsDescendantsNets += charge - chargePorteuseMin
		}
		if charge >= chargeQuasiMTUMin {
			releve.PaquetsDescendantsQuasiMTU++
		}
	}
	if porteur {
		releve.OctetsPorteurs += charge
		sens := int8(-1)
		if trame.Montant {
			sens = 1
		}
		if conversation.sensPrecedentPorteur != 0 && sens != conversation.sensPrecedentPorteur {
			releve.ChangementsDeSens++
			conversation.tournantsFenetre++
		}
		conversation.sensPrecedentPorteur = sens
	}
	evaluateur.suivreQUIC(conversation, trame, portClient)
}

func (evaluateur *EncryptedWireEvaluator) suivreQUIC(conversation *conversationChiffree, trame *EncryptedWireFrame, portClient uint16) {
	releve := &conversation.releve
	if trame.QUICInvalide {
		releve.DatagrammesQUICInvalides++
		return
	}
	entete := &trame.QUIC
	if !entete.Present {
		return
	}
	if trame.Montant && entete.FormeLongue && !entete.NegociationVersion && entete.TypeLong == QUICLongTypeInitial {
		longueur := entete.LongueurDCID
		if longueur != conversation.longueurDCIDInitial || conversation.dcidInitial != entete.DCID {
			releve.ConnexionsInitiales++
			conversation.longueurDCIDInitial, conversation.dcidInitial = longueur, entete.DCID
		}
	}
	if trame.Montant && portClient != conversation.dernierPortClient {
		if !entete.FormeLongue {
			releve.ReassociationsPort++
		}
		conversation.dernierPortClient = portClient
	}
}

func cloturerRafale(conversation *conversationChiffree) {
	if conversation.octetsMontantsRafale >= chargePorteuseMin {
		releve := &conversation.releve
		if releve.RafalesPorteuses > 0 {
			conversation.interRafales.ajouter(float64(conversation.debutRafaleNs - conversation.debutRafalePorteusePrecedente))
		}
		releve.RafalesPorteuses++
		conversation.debutRafalePorteusePrecedente = conversation.debutRafaleNs
		conversation.chargeMontanteRafale.ajouter(float64(conversation.octetsMontantsRafale))
	}
	conversation.octetsMontantsRafale, conversation.octetsDescendantsRafale = 0, 0
}

// avancerFenetres clôt la fenêtre courante puis compte en O(1) les fenêtres
// vides sautées : un horodatage aberrant ne déclenche aucune boucle longue.
func (evaluateur *EncryptedWireEvaluator) avancerFenetres(conversation *conversationChiffree, instant uint64) {
	duree := evaluateur.config.DureeFenetreNs
	if instant < conversation.debutFenetreNs+duree {
		return
	}
	cloturerFenetre(conversation)
	sautees := (instant-conversation.debutFenetreNs)/duree - 1
	if sautees > 0 {
		conversation.releve.FenetresObservees += sautees
		conversation.serieBidirectionnelle = 0
	}
	conversation.debutFenetreNs += (sautees + 1) * duree
}

func cloturerFenetre(conversation *conversationChiffree) {
	releve := &conversation.releve
	releve.FenetresObservees++
	if conversation.paquetsFenetre > 0 {
		releve.FenetresActives++
	}
	if conversation.tournantsFenetre >= tournantsFenetreMin && conversation.octetsMontantsPorteursFenetre >= octetsMontantsFenetreMin {
		releve.FenetresBidirectionnelles++
		conversation.serieBidirectionnelle++
		releve.SerieBidirectionnelleMax = max(releve.SerieBidirectionnelleMax, conversation.serieBidirectionnelle)
	} else {
		conversation.serieBidirectionnelle = 0
	}
	conversation.paquetsFenetre, conversation.tournantsFenetre, conversation.octetsMontantsPorteursFenetre = 0, 0, 0
}

// NombreTraitsChiffres est la dimension du vecteur cinétique.
const NombreTraitsChiffres = 9

// KineticVector est le vecteur cinétique à faible dimension d'une conversation.
type KineticVector struct {
	AsymetrieDescendanteLog2      float64 // log2((descendants+1)/(montants+1))
	FractionQuasiMTUDescendante   float64 // paquets descendants >= 1200 / paquets descendants
	TournantsParKioPorteur        float64 // changements de sens porteurs par Kio porteur (plafonné à 0,5)
	FractionMontanteIntermediaire float64 // paquets montants 56..900 / paquets montants
	DebitMontantPorteurLog2       float64 // log2(1 + octets montants porteurs par seconde active)
	PersistanceBidirectionnelle   float64 // log2(1 + volume bidirectionnel net couplé en Kio)
	RegulariteInterRafales        float64 // -log2(CV + 1/16) si >= 6 rafales porteuses sur >= 60 s
	RegulariteChargeMontante      float64 // -log2(CV + 1/16) sous la même condition
	IsochronieMontante            float64 // -log2(CV + 1/16) si >= 200 écarts montants intra-rafale
}

// Traits rend le vecteur dans l'ordre canonique de l'orientation.
func (vecteur *KineticVector) Traits() [NombreTraitsChiffres]float64 {
	return [NombreTraitsChiffres]float64{
		vecteur.AsymetrieDescendanteLog2, vecteur.FractionQuasiMTUDescendante, vecteur.TournantsParKioPorteur,
		vecteur.FractionMontanteIntermediaire, vecteur.DebitMontantPorteurLog2, vecteur.PersistanceBidirectionnelle,
		vecteur.RegulariteInterRafales, vecteur.RegulariteChargeMontante, vecteur.IsochronieMontante,
	}
}

// EncryptedRegime nomme les quatre régimes physiques du lot V2.
type EncryptedRegime uint8

const (
	RegimeR0aResolutionSporadique EncryptedRegime = iota
	RegimeR0bTelechargement
	RegimeR1aTunnelInteractif
	RegimeR1bBalisageLent
)

// String rend le jeton du régime.
func (regime EncryptedRegime) String() string {
	switch regime {
	case RegimeR0aResolutionSporadique:
		return "R0a"
	case RegimeR0bTelechargement:
		return "R0b"
	case RegimeR1aTunnelInteractif:
		return "R1a"
	case RegimeR1bBalisageLent:
		return "R1b"
	}
	return "R?"
}

// ConversationVerdict est le constat intégral rendu pour une conversation.
type ConversationVerdict struct {
	Cle                    ConversationKey
	Releve                 ConversationCounters
	Vecteur                KineticVector
	CVInterRafales         float64
	CVInterRafalesDefini   bool
	CVChargeMontante       float64
	CVChargeMontanteDefini bool
	RegimeEstime           EncryptedRegime
	RegimeLabel            string
	Insuffisante           bool // moins de PaquetsMinimumConversation paquets : constatée, non jugée
}

func construireVerdict(conversation *conversationChiffree, config EncryptedWireConfig) ConversationVerdict {
	cloturerRafale(conversation)
	cloturerFenetre(conversation)
	releve := conversation.releve
	verdict := ConversationVerdict{Cle: conversation.cle, Releve: releve}
	verdict.Insuffisante = releve.PaquetsMontants+releve.PaquetsDescendants < config.PaquetsMinimumConversation
	vecteur := &verdict.Vecteur
	vecteur.AsymetrieDescendanteLog2 = assainirFlottantChiffre(math.Log2(float64(releve.OctetsDescendants+1) / float64(releve.OctetsMontants+1)))
	if releve.PaquetsDescendants > 0 {
		vecteur.FractionQuasiMTUDescendante = assainirFlottantChiffre(float64(releve.PaquetsDescendantsQuasiMTU) / float64(releve.PaquetsDescendants))
	}
	tournantsBruts := float64(releve.ChangementsDeSens) / (float64(releve.OctetsPorteurs)/1024 + 1)
	vecteur.TournantsParKioPorteur = assainirFlottantChiffre(min(tournantsBruts, saturationTournantsParKio))
	if releve.PaquetsMontants > 0 {
		vecteur.FractionMontanteIntermediaire = assainirFlottantChiffre(float64(releve.PaquetsMontantsIntermediaires) / float64(releve.PaquetsMontants))
	}
	dureeReelleS := max(float64(releve.DernierNs-releve.PremierNs)/1e9, 0.1)
	dureeFenetresS := float64(max(releve.FenetresActives, 1)) * float64(config.DureeFenetreNs) / 1e9
	secondesActives := min(dureeReelleS, dureeFenetresS)
	vecteur.DebitMontantPorteurLog2 = assainirFlottantChiffre(math.Log2(1 + float64(releve.OctetsMontantsPorteurs)/secondesActives))
	volumeNetCouple := releve.OctetsMontantsNets + min(releve.OctetsDescendantsNets, amplificationNetteCoupleeMax*releve.OctetsMontantsNets)
	vecteur.PersistanceBidirectionnelle = assainirFlottantChiffre(math.Log2(1 + float64(volumeNetCouple)/4096))
	verdict.CVInterRafales, verdict.CVInterRafalesDefini = conversation.interRafales.coefficientVariation()
	verdict.CVChargeMontante, verdict.CVChargeMontanteDefini = conversation.chargeMontanteRafale.coefficientVariation()
	vecteur.RegulariteInterRafales, vecteur.RegulariteChargeMontante = regulariteNeutre, regulariteNeutre
	if releve.RafalesPorteuses >= rafalesPorteusesBaliseMin && releve.DernierNs-releve.PremierNs >= dureeBaliseMinNs &&
		verdict.CVInterRafalesDefini && verdict.CVChargeMontanteDefini {
		vecteur.RegulariteInterRafales = assainirFlottantChiffre(regulariteDepuisCV(verdict.CVInterRafales))
		vecteur.RegulariteChargeMontante = assainirFlottantChiffre(regulariteDepuisCV(verdict.CVChargeMontante))
	}
	if conversation.cadenceMontante.effectif >= paquetsIsochronieMin {
		if cvCadence, defini := conversation.cadenceMontante.coefficientVariation(); defini {
			vecteur.IsochronieMontante = assainirFlottantChiffre(regulariteDepuisCV(cvCadence))
		}
	}
	verdict.RegimeEstime = EstimateEncryptedRegime(&verdict)
	verdict.RegimeLabel = verdict.RegimeEstime.String()
	return verdict
}

// EstimateEncryptedRegime applique les bornes physiques a priori ; elle décrit,
// elle ne décide pas : la décision est le score calibré hors famille.
func EstimateEncryptedRegime(verdict *ConversationVerdict) EncryptedRegime {
	releve, vecteur := &verdict.Releve, &verdict.Vecteur
	switch {
	case releve.RafalesPorteuses >= rafalesPorteusesBaliseMin && releve.DernierNs-releve.PremierNs >= dureeBaliseMinNs &&
		verdict.CVInterRafalesDefini && verdict.CVChargeMontanteDefini &&
		verdict.CVInterRafales <= 0.55 && verdict.CVChargeMontante <= 0.55 && vecteur.AsymetrieDescendanteLog2 <= 4:
		return RegimeR1bBalisageLent
	case vecteur.PersistanceBidirectionnelle >= 4.3 && vecteur.FractionMontanteIntermediaire >= 0.4 &&
		vecteur.TournantsParKioPorteur >= 0.45 && vecteur.AsymetrieDescendanteLog2 <= 3.5 && vecteur.FractionQuasiMTUDescendante < 0.6:
		return RegimeR1aTunnelInteractif
	case vecteur.AsymetrieDescendanteLog2 >= 2.2 &&
		(vecteur.FractionQuasiMTUDescendante >= 0.5 || vecteur.FractionMontanteIntermediaire < 0.4):
		return RegimeR0bTelechargement
	}
	return RegimeR0aResolutionSporadique
}

// Finalize clôt toutes les conversations et les rend dans l'ordre de première
// apparition. L'évaluateur est ensuite remis à zéro.
func (evaluateur *EncryptedWireEvaluator) Finalize(visit func(*ConversationVerdict) error) error {
	occupees := make([]int, 0, evaluateur.Stats.Conversations)
	for indice := range evaluateur.conversations {
		if evaluateur.conversations[indice].occupee {
			occupees = append(occupees, indice)
		}
	}
	slices.SortFunc(occupees, func(gauche, droite int) int {
		return int(evaluateur.conversations[gauche].rang) - int(evaluateur.conversations[droite].rang)
	})
	for _, indice := range occupees {
		verdict := construireVerdict(&evaluateur.conversations[indice], evaluateur.config)
		if err := visit(&verdict); err != nil {
			return err
		}
	}
	clear(evaluateur.conversations)
	evaluateur.Stats = EncryptedWireStats{}
	return nil
}

// EncryptedWireCapture est le constat intégral d'une capture : empreinte,
// comptes de lecture et de décodage, conversations dans l'ordre d'apparition.
type EncryptedWireCapture struct {
	Chemin        string
	SHA256        string
	Lecture       BenchPCAPStats
	Decodage      EncryptedWireStats
	Conversations []ConversationVerdict
}

// EvaluateEncryptedWirePCAP lit intégralement une capture bornée par
// TailleMaximaleCaptureChiffree et rend toutes ses conversations. Toute erreur
// de lecture, de format ou de saturation rend un constat vide (OBJET-INTEGRAL-001).
func EvaluateEncryptedWirePCAP(chemin string, config EncryptedWireConfig) (constat EncryptedWireCapture, err error) {
	evaluateur, err := NewEncryptedWireEvaluator(config)
	if err != nil {
		return EncryptedWireCapture{}, err
	}
	fichier, err := os.Open(chemin)
	if err != nil {
		return EncryptedWireCapture{}, err
	}
	defer func() {
		if errFermeture := fichier.Close(); errFermeture != nil && err == nil {
			constat = EncryptedWireCapture{}
			err = errFermeture
		}
	}()
	etat, err := fichier.Stat()
	if err != nil {
		return EncryptedWireCapture{}, err
	}
	if !etat.Mode().IsRegular() || etat.Size() > TailleMaximaleCaptureChiffree {
		return EncryptedWireCapture{}, fmt.Errorf("%w: %s n'est pas un fichier régulier de taille <= %d", ErrEncryptedWireContract, chemin, TailleMaximaleCaptureChiffree)
	}
	empreinte := sha256.New()
	borne := &io.LimitedReader{R: fichier, N: etat.Size()}
	lecteur := io.TeeReader(bufio.NewReaderSize(borne, 1<<16), empreinte)
	lecture, err := ReadBenchPCAP(lecteur, evaluateur.Observe)
	if err != nil {
		return EncryptedWireCapture{}, fmt.Errorf("capture %s: %w", chemin, err)
	}
	if lecture.Bytes != uint64(etat.Size()) {
		return EncryptedWireCapture{}, fmt.Errorf("%w: %s lu sur %d octets au lieu de %d", ErrEncryptedWireContract, chemin, lecture.Bytes, etat.Size())
	}
	constat = EncryptedWireCapture{Chemin: chemin, SHA256: hex.EncodeToString(empreinte.Sum(nil)), Lecture: lecture, Decodage: evaluateur.Stats}
	constat.Conversations = make([]ConversationVerdict, 0, evaluateur.Stats.Conversations)
	err = evaluateur.Finalize(func(verdict *ConversationVerdict) error {
		constat.Conversations = append(constat.Conversations, *verdict)
		return nil
	})
	if err != nil {
		return EncryptedWireCapture{}, err
	}
	return constat, nil
}

// regulariteDepuisCV rend -log2(CV + 1/16), borné à [-8, 4] : un CV hors plage
// ne propage ni infini ni NaN dans la calibration.
func regulariteDepuisCV(coefficient float64) float64 {
	return -math.Log2(min(max(coefficient, 0), 256) + plancherCoefficientVariation)
}

func assainirFlottantChiffre(valeur float64) float64 {
	if math.IsNaN(valeur) || math.IsInf(valeur, 0) {
		return 0
	}
	return valeur
}
