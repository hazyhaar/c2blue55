package c2blue55

import (
	"bytes"
	"cmp"
	"math"
	"slices"
)

const (
	// ReasonHostMultipathTunnel signale la détection d'un tunnel interactif R1a
	// réparti simultanément sur plusieurs cibles résolveurs chiffrés d'un même hôte.
	ReasonHostMultipathTunnel = "REASON_HOST_MULTIPATH_TUNNEL"

	largeurTrancheSynchronieNs uint64 = 100_000_000
	capaciteTranchesSynchronie        = 256

	seuilPersistanceHoteR1a               = 4.30
	gardeFractionMontanteIntermediaireMin = 0.40
	gardeTournantsParKioPorteurMin        = 0.45
	gardeAsymetrieDescendanteMax          = 3.50
	gardeFractionQuasiMTUDescendanteMax   = 0.60
	facteurSilenceActifMax                = 4
)

// HostResolverAggregateKey identifie un hôte client agrégé : adresse IPv4
// canonique sur les 4 premiers octets ou préfixe IPv6 /64 sur les 8 premiers.
type HostResolverAggregateKey struct {
	Client       [16]byte
	IPv6Prefix64 bool
}

// NormalizeHostClientKey ramène une adresse cliente à sa clé d'agrégation hôte :
// IPv4 exacte sur les 4 premiers octets (IPv6Prefix64=false) ou préfixe IPv6 /64
// sur les 8 premiers octets (IPv6Prefix64=true, RFC 8981).
func NormalizeHostClientKey(client [16]byte, ipv6 bool) HostResolverAggregateKey {
	if estAdresseIPv4Mappee(client) {
		var canonique [16]byte
		copy(canonique[:4], client[12:16])
		return HostResolverAggregateKey{Client: canonique, IPv6Prefix64: false}
	}
	if !ipv6 {
		var canonique [16]byte
		copy(canonique[:4], client[:4])
		return HostResolverAggregateKey{Client: canonique, IPv6Prefix64: false}
	}
	var prefixe64 [16]byte
	copy(prefixe64[:8], client[:8])
	return HostResolverAggregateKey{Client: prefixe64, IPv6Prefix64: true}
}

func estAdresseIPv4Mappee(adresse [16]byte) bool {
	for indice := range 10 {
		if adresse[indice] != 0 {
			return false
		}
	}
	return adresse[10] == 0xff && adresse[11] == 0xff
}

// HostAggregateVerdict synthétise l'agrégat multi-résolveurs d'un hôte client
// sur ses conversations candidates simultanées vers des résolveurs chiffrés.
type HostAggregateVerdict struct {
	Cle                             HostResolverAggregateKey
	PremierNs                       uint64
	DernierNs                       uint64
	Conversations                   uint32
	CiblesResolveurs                uint32
	OctetsMontantsNets              uint64
	OctetsDescendantsNets           uint64
	PersistanceBidirectionnelleHote float64
	SynchroniePermille              int64
	SynchronieDefinie               bool
	RegimeHote                      EncryptedRegime
	RegimeHoteLabel                 string
	RaisonHote                      string
}

type suiviSynchronieConversation struct {
	effectif uint16
	tranches [capaciteTranchesSynchronie]uint64
}

func enregistrerTrancheSynchronie(suivi *suiviSynchronieConversation, instantNs uint64) {
	tranche := instantNs / largeurTrancheSynchronieNs
	if suivi.effectif > 0 && suivi.tranches[suivi.effectif-1] == tranche {
		return
	}
	if int(suivi.effectif) < len(suivi.tranches) {
		suivi.tranches[suivi.effectif] = tranche
		suivi.effectif++
	}
}

func calculerDispersionDescendante(paquetsPorteurs uint32, histogramme *[classesDispersionDescendante]uint16) (int64, bool) {
	if paquetsPorteurs < paquetsDispersionDescendanteMin {
		return 0, false
	}
	var effectifHistogramme uint64
	for indice := range classesDispersionDescendante {
		effectifHistogramme += uint64(histogramme[indice])
	}
	if effectifHistogramme < paquetsDispersionDescendanteMin {
		return 0, false
	}

	centreAuRang := func(rangCible uint64) int64 {
		var cumul uint64
		for indice := range classesDispersionDescendante {
			cumul += uint64(histogramme[indice])
			if cumul >= rangCible {
				return int64(chargePorteuseMin) + int64(indice)*int64(pasDispersionDescendante) + int64(pasDispersionDescendante/2)
			}
		}
		return int64(chargePorteuseMin) + int64(classesDispersionDescendante-1)*int64(pasDispersionDescendante) + int64(pasDispersionDescendante/2)
	}

	rangQuartInf := (effectifHistogramme + 3) / 4
	rangQuartSup := effectifHistogramme - rangQuartInf + 1
	quartileInf := centreAuRang(rangQuartInf)
	quartileSup := centreAuRang(rangQuartSup)

	var mediane int64
	if effectifHistogramme%2 == 1 {
		mediane = centreAuRang((effectifHistogramme + 1) / 2)
	} else {
		mediane = (centreAuRang(effectifHistogramme/2) + centreAuRang(effectifHistogramme/2+1)) / 2
	}
	denominateur := max(mediane, int64(1))
	dispersionPermille := max(quartileSup-quartileInf, int64(0)) * 1000 / denominateur
	return dispersionPermille, true
}

func estPortResolveurActif(cle ConversationKey, portsAdditionnels [MaxPortsResolveurChiffres]uint16) bool {
	if cle.Transport == EncryptedTransportDoQ || cle.Transport == EncryptedTransportDoT {
		return true
	}
	if cle.PortServeur == 0 {
		return false
	}
	for _, portExplicite := range portsAdditionnels {
		if portExplicite != 0 && cle.PortServeur == portExplicite {
			return true
		}
	}
	return false
}

func estConversationCandidateHote(verdict *ConversationVerdict, config EncryptedWireConfig) bool {
	if verdict.Insuffisante || verdict.RegimeEstime == RegimeR1bBalisageLent {
		return false
	}
	if !estPortResolveurActif(verdict.Cle, config.PortsResolveurChiffres) {
		return false
	}
	vecteur := &verdict.Vecteur
	if vecteur.FractionMontanteIntermediaire < gardeFractionMontanteIntermediaireMin ||
		vecteur.TournantsParKioPorteur < gardeTournantsParKioPorteurMin ||
		vecteur.AsymetrieDescendanteLog2 > gardeAsymetrieDescendanteMax ||
		vecteur.FractionQuasiMTUDescendante >= gardeFractionQuasiMTUDescendanteMax {
		return false
	}
	releve := &verdict.Releve
	if releve.FenetresActives == 0 {
		return false
	}
	var fenetresSilence uint64
	if releve.FenetresObservees > uint64(releve.FenetresActives) {
		fenetresSilence = releve.FenetresObservees - uint64(releve.FenetresActives)
	}
	return fenetresSilence <= facteurSilenceActifMax*uint64(releve.FenetresActives)
}

type candidatConversationHote struct {
	cleHote     HostResolverAggregateKey
	rang        uint64
	indiceTable int
	verdict     ConversationVerdict
}

type cibleResolveurChiffre struct {
	serveur     [16]byte
	portServeur uint16
}

func comparerCibleResolveur(gauche, droite cibleResolveurChiffre) int {
	if ordreServeur := bytes.Compare(gauche.serveur[:], droite.serveur[:]); ordreServeur != 0 {
		return ordreServeur
	}
	return cmp.Compare(gauche.portServeur, droite.portServeur)
}

// FinalizeWithHosts clôt toutes les conversations dans l'ordre de première
// apparition puis, si AgregationHote est activé et visitHost non nul, émet les
// agrégats multi-résolveurs par hôte client avant de réinitialiser l'évaluateur.
func (evaluateur *EncryptedWireEvaluator) FinalizeWithHosts(
	visitConversation func(*ConversationVerdict) error,
	visitHost func(*HostAggregateVerdict) error,
) error {
	occupees := make([]int, 0, evaluateur.Stats.Conversations)
	for indice := range evaluateur.conversations {
		if evaluateur.conversations[indice].occupee {
			occupees = append(occupees, indice)
		}
	}
	slices.SortFunc(occupees, func(gauche, droite int) int {
		return cmp.Compare(evaluateur.conversations[gauche].rang, evaluateur.conversations[droite].rang)
	})

	var candidats []candidatConversationHote
	agregationActive := evaluateur.config.AgregationHote && visitHost != nil
	for _, indice := range occupees {
		conversation := &evaluateur.conversations[indice]
		verdict := construireVerdict(conversation, evaluateur.config)
		if visitConversation != nil {
			if err := visitConversation(&verdict); err != nil {
				return err
			}
		}
		if agregationActive && estConversationCandidateHote(&verdict, evaluateur.config) {
			candidats = append(candidats, candidatConversationHote{
				cleHote:     NormalizeHostClientKey(verdict.Cle.Client, conversation.ipv6),
				rang:        conversation.rang,
				indiceTable: indice,
				verdict:     verdict,
			})
		}
	}

	if agregationActive && len(candidats) >= 2 {
		verdictsHotes := agregerCandidatsParHote(candidats, evaluateur.synchronieConversations)
		for indice := range verdictsHotes {
			if err := visitHost(&verdictsHotes[indice]); err != nil {
				return err
			}
		}
	}

	clear(evaluateur.conversations)
	clear(evaluateur.synchronieConversations)
	evaluateur.Stats = EncryptedWireStats{}
	return nil
}

func agregerCandidatsParHote(
	candidats []candidatConversationHote,
	synchronieConversations []suiviSynchronieConversation,
) []HostAggregateVerdict {
	var clesOrdonnees []HostResolverAggregateKey
	for indice := range candidats {
		cle := candidats[indice].cleHote
		if !slices.Contains(clesOrdonnees, cle) {
			clesOrdonnees = append(clesOrdonnees, cle)
		}
	}

	var verdicts []HostAggregateVerdict
	for _, cleHote := range clesOrdonnees {
		var groupe []candidatConversationHote
		for indice := range candidats {
			if candidats[indice].cleHote == cleHote {
				groupe = append(groupe, candidats[indice])
			}
		}
		if len(groupe) < 2 {
			continue
		}
		slices.SortFunc(groupe, func(gauche, droite candidatConversationHote) int {
			if ordreDebut := cmp.Compare(gauche.verdict.Releve.PremierNs, droite.verdict.Releve.PremierNs); ordreDebut != 0 {
				return ordreDebut
			}
			if ordreFin := cmp.Compare(gauche.verdict.Releve.DernierNs, droite.verdict.Releve.DernierNs); ordreFin != 0 {
				return ordreFin
			}
			return cmp.Compare(gauche.rang, droite.rang)
		})

		var meilleurVerdict HostAggregateVerdict
		meilleurTrouve := false
		debutAmas := 0
		finTemporelleAmas := groupe[0].verdict.Releve.DernierNs
		for position := 1; position <= len(groupe); position++ {
			if position < len(groupe) && groupe[position].verdict.Releve.PremierNs <= finTemporelleAmas {
				finTemporelleAmas = max(finTemporelleAmas, groupe[position].verdict.Releve.DernierNs)
				continue
			}
			amas := groupe[debutAmas:position]
			if verdictAmas, retenu := construireVerdictAmasHote(cleHote, amas, synchronieConversations); retenu {
				if !meilleurTrouve || verdictAmas.PersistanceBidirectionnelleHote > meilleurVerdict.PersistanceBidirectionnelleHote {
					meilleurVerdict = verdictAmas
					meilleurTrouve = true
				}
			}
			if position < len(groupe) {
				debutAmas = position
				finTemporelleAmas = groupe[position].verdict.Releve.DernierNs
			}
		}
		if meilleurTrouve {
			verdicts = append(verdicts, meilleurVerdict)
		}
	}
	return verdicts
}

func construireVerdictAmasHote(
	cleHote HostResolverAggregateKey,
	amas []candidatConversationHote,
	synchronieConversations []suiviSynchronieConversation,
) (HostAggregateVerdict, bool) {
	if len(amas) < 2 {
		return HostAggregateVerdict{}, false
	}

	cibles := make([]cibleResolveurChiffre, 0, len(amas))
	premierNs := amas[0].verdict.Releve.PremierNs
	dernierNs := amas[0].verdict.Releve.DernierNs
	var sommeMontantsNets, sommeDescendantsNets uint64

	for indice := range amas {
		releve := &amas[indice].verdict.Releve
		premierNs = min(premierNs, releve.PremierNs)
		dernierNs = max(dernierNs, releve.DernierNs)
		sommeMontantsNets += releve.OctetsMontantsNets
		sommeDescendantsNets += releve.OctetsDescendantsNets

		cible := cibleResolveurChiffre{
			serveur:     amas[indice].verdict.Cle.Serveur,
			portServeur: amas[indice].verdict.Cle.PortServeur,
		}
		if !slices.Contains(cibles, cible) {
			cibles = append(cibles, cible)
		}
	}
	if len(cibles) < 2 {
		return HostAggregateVerdict{}, false
	}

	volumeNetCoupleHote := sommeMontantsNets + min(sommeDescendantsNets, amplificationNetteCoupleeMax*sommeMontantsNets)
	persistanceHote := assainirFlottantChiffre(math.Log2(1 + float64(volumeNetCoupleHote)/4096))
	synchroniePermille, synchronieDefinie := calculerSynchronieAmas(amas, synchronieConversations)

	regimeHote := RegimeR0aResolutionSporadique
	raisonHote := ""
	if persistanceHote >= seuilPersistanceHoteR1a {
		regimeHote = RegimeR1aTunnelInteractif
		raisonHote = ReasonHostMultipathTunnel
	}

	return HostAggregateVerdict{
		Cle:                             cleHote,
		PremierNs:                       premierNs,
		DernierNs:                       dernierNs,
		Conversations:                   uint32(len(amas)),
		CiblesResolveurs:                uint32(len(cibles)),
		OctetsMontantsNets:              sommeMontantsNets,
		OctetsDescendantsNets:           sommeDescendantsNets,
		PersistanceBidirectionnelleHote: persistanceHote,
		SynchroniePermille:              synchroniePermille,
		SynchronieDefinie:               synchronieDefinie,
		RegimeHote:                      regimeHote,
		RegimeHoteLabel:                 regimeHote.String(),
		RaisonHote:                      raisonHote,
	}, true
}

func calculerSynchronieAmas(
	amas []candidatConversationHote,
	synchronieConversations []suiviSynchronieConversation,
) (int64, bool) {
	type activiteTrancheCible struct {
		tranche uint64
		cible   cibleResolveurChiffre
	}
	var activites []activiteTrancheCible
	for indice := range amas {
		indiceTable := amas[indice].indiceTable
		if indiceTable < 0 || indiceTable >= len(synchronieConversations) {
			continue
		}
		suivi := &synchronieConversations[indiceTable]
		cible := cibleResolveurChiffre{
			serveur:     amas[indice].verdict.Cle.Serveur,
			portServeur: amas[indice].verdict.Cle.PortServeur,
		}
		for posTranche := range int(suivi.effectif) {
			activites = append(activites, activiteTrancheCible{
				tranche: suivi.tranches[posTranche],
				cible:   cible,
			})
		}
	}
	if len(activites) == 0 {
		return 0, false
	}

	slices.SortFunc(activites, func(gauche, droite activiteTrancheCible) int {
		if ordreTranche := cmp.Compare(gauche.tranche, droite.tranche); ordreTranche != 0 {
			return ordreTranche
		}
		return comparerCibleResolveur(gauche.cible, droite.cible)
	})

	var tranchesUnion, tranchesCoactives uint64
	for debut := 0; debut < len(activites); {
		trancheCourante := activites[debut].tranche
		ciblesDansTranche := 1
		derniereCible := activites[debut].cible
		fin := debut + 1
		for fin < len(activites) && activites[fin].tranche == trancheCourante {
			if activites[fin].cible != derniereCible {
				ciblesDansTranche++
				derniereCible = activites[fin].cible
			}
			fin++
		}
		tranchesUnion++
		if ciblesDansTranche >= 2 {
			tranchesCoactives++
		}
		debut = fin
	}
	return int64(tranchesCoactives*1000) / int64(tranchesUnion), true
}
