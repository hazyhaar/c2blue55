package c2blue55

import (
	"bytes"
	"cmp"
	"encoding/binary"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

type rat02bEnregistrementFlux struct {
	instantNs    uint64
	ipv6         bool
	source       [16]byte
	destination  [16]byte
	portSource   uint16
	portDest     uint16
	tailleCharge int
}

func rat02bAdresseIPv4(a, b, c, d byte) [16]byte {
	return [16]byte{a, b, c, d}
}

func rat02bAdresseIPv6(t *testing.T, texte string) [16]byte {
	t.Helper()
	adresse, err := netip.ParseAddr(texte)
	if err != nil || !adresse.Is6() {
		t.Fatalf("adresse IPv6 invalide %q : %v", texte, err)
	}
	return adresse.As16()
}

func rat02bConstruireTrameEthernetUDP(enreg rat02bEnregistrementFlux) []byte {
	longueurUDP := 8 + enreg.tailleCharge
	if !enreg.ipv6 {
		trame := make([]byte, 14+20+longueurUDP)
		binary.BigEndian.PutUint16(trame[12:14], 0x0800)
		enteteIP := trame[14:34]
		enteteIP[0] = 0x45
		binary.BigEndian.PutUint16(enteteIP[2:4], uint16(20+longueurUDP))
		enteteIP[8] = 64
		enteteIP[9] = 17
		copy(enteteIP[12:16], enreg.source[:4])
		copy(enteteIP[16:20], enreg.destination[:4])
		segmentUDP := trame[34:]
		binary.BigEndian.PutUint16(segmentUDP[0:2], enreg.portSource)
		binary.BigEndian.PutUint16(segmentUDP[2:4], enreg.portDest)
		binary.BigEndian.PutUint16(segmentUDP[4:6], uint16(longueurUDP))
		if enreg.tailleCharge >= 2 {
			segmentUDP[8] = 0x40
		}
		return trame
	}

	trame := make([]byte, 14+40+longueurUDP)
	binary.BigEndian.PutUint16(trame[12:14], 0x86dd)
	enteteIP6 := trame[14:54]
	enteteIP6[0] = 0x60
	binary.BigEndian.PutUint16(enteteIP6[4:6], uint16(longueurUDP))
	enteteIP6[6] = 17
	enteteIP6[7] = 64
	copy(enteteIP6[8:24], enreg.source[:])
	copy(enteteIP6[24:40], enreg.destination[:])
	segmentUDP := trame[54:]
	binary.BigEndian.PutUint16(segmentUDP[0:2], enreg.portSource)
	binary.BigEndian.PutUint16(segmentUDP[2:4], enreg.portDest)
	binary.BigEndian.PutUint16(segmentUDP[4:6], uint16(longueurUDP))
	if enreg.tailleCharge >= 2 {
		segmentUDP[8] = 0x40
	}
	return trame
}

func rat02bEcrireCaptureEthernet(t *testing.T, chemin string, paquets []rat02bEnregistrementFlux) {
	t.Helper()
	ordonnes := slices.Clone(paquets)
	slices.SortStableFunc(ordonnes, func(gauche, droite rat02bEnregistrementFlux) int {
		return cmp.Compare(gauche.instantNs, droite.instantNs)
	})

	var tampon bytes.Buffer
	var enteteGlobale [24]byte
	binary.LittleEndian.PutUint32(enteteGlobale[0:4], 0xa1b23c4d)
	binary.LittleEndian.PutUint16(enteteGlobale[4:6], 2)
	binary.LittleEndian.PutUint16(enteteGlobale[6:8], 4)
	binary.LittleEndian.PutUint32(enteteGlobale[16:20], 65535)
	binary.LittleEndian.PutUint32(enteteGlobale[20:24], 1)
	tampon.Write(enteteGlobale[:])

	var enteteEnreg [16]byte
	for _, enreg := range ordonnes {
		trame := rat02bConstruireTrameEthernetUDP(enreg)
		binary.LittleEndian.PutUint32(enteteEnreg[0:4], uint32(enreg.instantNs/1_000_000_000))
		binary.LittleEndian.PutUint32(enteteEnreg[4:8], uint32(enreg.instantNs%1_000_000_000))
		binary.LittleEndian.PutUint32(enteteEnreg[8:12], uint32(len(trame)))
		binary.LittleEndian.PutUint32(enteteEnreg[12:16], uint32(len(trame)))
		tampon.Write(enteteEnreg[:])
		tampon.Write(trame)
	}
	if err := os.WriteFile(chemin, tampon.Bytes(), 0o600); err != nil {
		t.Fatalf("écriture capture %s : %v", chemin, err)
	}
}

// rat02bFluxCandidatDemiTunnel construit 80 échanges aller-retour vérifiant les
// 4 gardes intensives R1a mais demeurant sous le seuil individuel (pers ~ 3.80 < 4.30).
// Deux tels flux simultanés atteignent PersistanceBidirectionnelleHote ~ 4.74 >= 4.30.
func rat02bFluxCandidatDemiTunnel(ipv6 bool, client, serveur [16]byte, portClient, portServeur uint16, debutNs uint64) []rat02bEnregistrementFlux {
	paquets := make([]rat02bEnregistrementFlux, 0, 160)
	for tour := range 80 {
		instantAller := debutNs + uint64(tour)*20_000_000
		paquets = append(paquets,
			rat02bEnregistrementFlux{
				instantNs:    instantAller,
				ipv6:         ipv6,
				source:       client,
				destination:  serveur,
				portSource:   portClient,
				portDest:     portServeur,
				tailleCharge: 256,
			},
			rat02bEnregistrementFlux{
				instantNs:    instantAller + 5_000_000,
				ipv6:         ipv6,
				source:       serveur,
				destination:  client,
				portSource:   portServeur,
				portDest:     portClient,
				tailleCharge: 516,
			},
		)
	}
	return paquets
}

func TestRatiosWireHote_InvarianceVecteurCanonique(t *testing.T) {
	if NombreTraitsChiffres != 9 {
		t.Fatalf("NombreTraitsChiffres = %d, attendu 9", NombreTraitsChiffres)
	}
	var vecteurZero KineticVector
	if len(vecteurZero.Traits()) != 9 {
		t.Fatalf("len(Traits()) = %d, attendu 9", len(vecteurZero.Traits()))
	}

	capturesReelles := []string{
		"slipstream-2doq-multipath-transit.pcap",
		"slipstream-doq-transit.pcap",
		"benign-dns-doq.pcap",
	}
	for _, nomCapture := range capturesReelles {
		t.Run(nomCapture, func(t *testing.T) {
			chemin := filepath.Join("testdata", "rat-20261101", nomCapture)
			constatSans, errSans := EvaluateEncryptedWirePCAP(chemin, EncryptedWireConfig{AgregationHote: false})
			if errSans != nil {
				t.Fatalf("EvaluateEncryptedWirePCAP(AgregationHote=false) : %v", errSans)
			}
			if len(constatSans.Hotes) != 0 {
				t.Fatalf("len(constatSans.Hotes) = %d avec AgregationHote=false, attendu 0", len(constatSans.Hotes))
			}

			constatAvec, errAvec := EvaluateEncryptedWirePCAP(chemin, EncryptedWireConfig{AgregationHote: true})
			if errAvec != nil {
				t.Fatalf("EvaluateEncryptedWirePCAP(AgregationHote=true) : %v", errAvec)
			}
			if len(constatAvec.Conversations) == 0 || len(constatAvec.Conversations) != len(constatSans.Conversations) {
				t.Fatalf("nombre de conversations = %d (avec) vs %d (sans)", len(constatAvec.Conversations), len(constatSans.Conversations))
			}

			for indice := range constatSans.Conversations {
				attendu := constatSans.Conversations[indice]
				obtenu := constatAvec.Conversations[indice]
				if obtenu.Cle != attendu.Cle {
					t.Errorf("conversation[%d] Cle modifiée : %+v != %+v", indice, obtenu.Cle, attendu.Cle)
				}
				if obtenu.Releve != attendu.Releve {
					t.Errorf("conversation[%d] Releve modifié : %+v != %+v", indice, obtenu.Releve, attendu.Releve)
				}
				if obtenu.Vecteur != attendu.Vecteur {
					t.Errorf("conversation[%d] Vecteur modifié : %+v != %+v", indice, obtenu.Vecteur, attendu.Vecteur)
				}
				if obtenu.RegimeEstime != attendu.RegimeEstime || obtenu.RegimeLabel != attendu.RegimeLabel {
					t.Errorf("conversation[%d] Régime modifié : (%v,%q) != (%v,%q)",
						indice, obtenu.RegimeEstime, obtenu.RegimeLabel, attendu.RegimeEstime, attendu.RegimeLabel)
				}
			}
		})
	}
}

func TestRatiosWireHote_MultipathDoQReel(t *testing.T) {
	chemin := filepath.Join("testdata", "rat-20261101", "slipstream-2doq-multipath-transit.pcap")

	constatSans, err := EvaluateEncryptedWirePCAP(chemin, EncryptedWireConfig{AgregationHote: false})
	if err != nil {
		t.Fatalf("EvaluateEncryptedWirePCAP(sans agrégation) : %v", err)
	}
	if len(constatSans.Conversations) != 2 {
		t.Fatalf("len(Conversations) = %d, attendu 2", len(constatSans.Conversations))
	}
	for indice, conv := range constatSans.Conversations {
		if conv.Cle.Transport != EncryptedTransportDoQ {
			t.Errorf("conv[%d] Transport = %v, attendu EncryptedTransportDoQ", indice, conv.Cle.Transport)
		}
		if conv.Vecteur.PersistanceBidirectionnelle >= 4.30 {
			t.Errorf("conv[%d] PersistanceBidirectionnelle = %v, attendu < 4.30 (diluée)", indice, conv.Vecteur.PersistanceBidirectionnelle)
		}
		if conv.RegimeEstime != RegimeR0aResolutionSporadique || conv.RegimeLabel != "R0a" {
			t.Errorf("conv[%d] régime = (%v,%q), attendu (R0a,\"R0a\")", indice, conv.RegimeEstime, conv.RegimeLabel)
		}
	}

	constatAvec, err := EvaluateEncryptedWirePCAP(chemin, EncryptedWireConfig{AgregationHote: true})
	if err != nil {
		t.Fatalf("EvaluateEncryptedWirePCAP(avec agrégation) : %v", err)
	}
	if len(constatAvec.Hotes) != 1 {
		t.Fatalf("len(Hotes) = %d, attendu 1", len(constatAvec.Hotes))
	}

	hote := constatAvec.Hotes[0]
	cleAttendue := NormalizeHostClientKey(rat02bAdresseIPv4(10, 55, 0, 2), false)
	if hote.Cle != cleAttendue || hote.Cle.IPv6Prefix64 {
		t.Errorf("Hotes[0].Cle = %+v, attendu %+v (IPv6Prefix64=false)", hote.Cle, cleAttendue)
	}
	if hote.Conversations != 2 {
		t.Errorf("Hotes[0].Conversations = %d, attendu 2", hote.Conversations)
	}
	if hote.CiblesResolveurs != 2 {
		t.Errorf("Hotes[0].CiblesResolveurs = %d, attendu 2 (:853 et :8853)", hote.CiblesResolveurs)
	}
	montantsNetsAttendus := constatAvec.Conversations[0].Releve.OctetsMontantsNets + constatAvec.Conversations[1].Releve.OctetsMontantsNets
	descendantsNetsAttendus := constatAvec.Conversations[0].Releve.OctetsDescendantsNets + constatAvec.Conversations[1].Releve.OctetsDescendantsNets
	if hote.OctetsMontantsNets != montantsNetsAttendus {
		t.Errorf("Hotes[0].OctetsMontantsNets = %d, attendu %d", hote.OctetsMontantsNets, montantsNetsAttendus)
	}
	if hote.OctetsDescendantsNets != descendantsNetsAttendus {
		t.Errorf("Hotes[0].OctetsDescendantsNets = %d, attendu %d", hote.OctetsDescendantsNets, descendantsNetsAttendus)
	}
	if hote.PersistanceBidirectionnelleHote < 4.30 {
		t.Errorf("Hotes[0].PersistanceBidirectionnelleHote = %v, attendu >= 4.30", hote.PersistanceBidirectionnelleHote)
	}
	if !hote.SynchronieDefinie || hote.SynchroniePermille <= 0 || hote.SynchroniePermille > 1000 {
		t.Errorf("Hotes[0] synchronie = (%d, %t), attendu définie dans ]0, 1000]", hote.SynchroniePermille, hote.SynchronieDefinie)
	}
	if hote.RegimeHote != RegimeR1aTunnelInteractif || hote.RegimeHoteLabel != "R1a" {
		t.Errorf("Hotes[0] régime = (%v, %q), attendu (R1a, \"R1a\")", hote.RegimeHote, hote.RegimeHoteLabel)
	}

	// Vérification directe de FinalizeWithHosts sur EncryptedWireEvaluator.
	evaluateur, errEval := NewEncryptedWireEvaluator(EncryptedWireConfig{AgregationHote: true})
	if errEval != nil {
		t.Fatalf("NewEncryptedWireEvaluator : %v", errEval)
	}
	fichier, errFichier := os.Open(chemin)
	if errFichier != nil {
		t.Fatalf("ouverture %s : %v", chemin, errFichier)
	}
	defer fichier.Close()
	if _, errLecture := ReadBenchPCAP(io.LimitReader(fichier, 1<<20), evaluateur.Observe); errLecture != nil {
		t.Fatalf("ReadBenchPCAP : %v", errLecture)
	}
	var conversationsVisitees []ConversationVerdict
	var hotesVisites []HostAggregateVerdict
	errFinal := evaluateur.FinalizeWithHosts(
		func(verdictConv *ConversationVerdict) error {
			conversationsVisitees = append(conversationsVisitees, *verdictConv)
			return nil
		},
		func(verdictHote *HostAggregateVerdict) error {
			hotesVisites = append(hotesVisites, *verdictHote)
			return nil
		},
	)
	if errFinal != nil {
		t.Fatalf("FinalizeWithHosts : %v", errFinal)
	}
	if len(conversationsVisitees) != 2 || len(hotesVisites) != 1 || hotesVisites[0] != hote {
		t.Fatalf("FinalizeWithHosts divergent : convs=%d hotes=%+v attendu=%+v", len(conversationsVisitees), hotesVisites, hote)
	}
}

func TestRatiosWireHote_JumeauxNegatifsEtIPv6Prefix64(t *testing.T) {
	t.Run("MonoResolveur_SlipstreamDoQTransit", func(t *testing.T) {
		chemin := filepath.Join("testdata", "rat-20261101", "slipstream-doq-transit.pcap")
		constat, err := EvaluateEncryptedWirePCAP(chemin, EncryptedWireConfig{AgregationHote: true})
		if err != nil {
			t.Fatalf("EvaluateEncryptedWirePCAP : %v", err)
		}
		if len(constat.Conversations) != 1 || constat.Conversations[0].RegimeEstime != RegimeR1aTunnelInteractif {
			t.Fatalf("attendu 1 conversation R1a mono-résolveur, obtenu %+v", constat.Conversations)
		}
		if len(constat.Hotes) != 0 {
			t.Fatalf("mono-résolveur : len(Hotes) = %d, attendu 0", len(constat.Hotes))
		}
	})

	t.Run("BeninDoQ_CaptureReelle", func(t *testing.T) {
		chemin := filepath.Join("testdata", "rat-20261101", "benign-dns-doq.pcap")
		constat, err := EvaluateEncryptedWirePCAP(chemin, EncryptedWireConfig{AgregationHote: true})
		if err != nil {
			t.Fatalf("EvaluateEncryptedWirePCAP : %v", err)
		}
		if len(constat.Hotes) != 0 {
			t.Fatalf("benign-dns-doq : len(Hotes) = %d, attendu 0", len(constat.Hotes))
		}
	})

	t.Run("NATSimule_UnSeulCandidatR1aPlusR0aPlusR0b", func(t *testing.T) {
		clientNAT := rat02bAdresseIPv4(10, 0, 0, 2)
		resolveurDoQ1 := rat02bAdresseIPv4(192, 0, 2, 53)
		resolveurDoQ2 := rat02bAdresseIPv4(192, 0, 2, 54)
		serveurWebH3 := rat02bAdresseIPv4(198, 51, 100, 80)
		const debutNs = uint64(1_000_000_000)

		// 1. Unique conversation candidate R1a sous le seuil (pers ~ 3.80) sur DoQ :853.
		paquets := rat02bFluxCandidatDemiTunnel(false, clientNAT, resolveurDoQ1, 51001, 853, debutNs)

		// 2. Conversation DoQ bénigne R0a sur :8853 (FractionMontanteIntermediaire = 10/40 = 0.25 < 0.40).
		for tour := range 40 {
			instant := debutNs + uint64(tour)*35_000_000
			chargeMontante := 45
			chargeDescendante := 45
			if tour%4 == 0 {
				chargeMontante = 100
				chargeDescendante = 350
			}
			paquets = append(paquets,
				rat02bEnregistrementFlux{instantNs: instant, source: clientNAT, destination: resolveurDoQ2, portSource: 51002, portDest: 8853, tailleCharge: chargeMontante},
				rat02bEnregistrementFlux{instantNs: instant + 4_000_000, source: resolveurDoQ2, destination: clientNAT, portSource: 8853, portDest: 51002, tailleCharge: chargeDescendante},
			)
		}

		// 3. Conversation téléchargement HTTP/3 :443 (R0b : QuasiMTU descendant massif + petits ACK montants).
		paquets = append(paquets, rat02bEnregistrementFlux{
			instantNs: debutNs, source: clientNAT, destination: serveurWebH3, portSource: 51003, portDest: 443, tailleCharge: 320,
		})
		for segment := range 300 {
			instant := debutNs + 2_000_000 + uint64(segment)*4_000_000
			paquets = append(paquets, rat02bEnregistrementFlux{
				instantNs: instant, source: serveurWebH3, destination: clientNAT, portSource: 443, portDest: 51003, tailleCharge: 1350,
			})
			if segment%2 == 1 {
				paquets = append(paquets, rat02bEnregistrementFlux{
					instantNs: instant + 500_000, source: clientNAT, destination: serveurWebH3, portSource: 51003, portDest: 443, tailleCharge: 45,
				})
			}
		}

		chemin := filepath.Join(t.TempDir(), "nat-simule.pcap")
		rat02bEcrireCaptureEthernet(t, chemin, paquets)

		constat, err := EvaluateEncryptedWirePCAP(chemin, EncryptedWireConfig{AgregationHote: true})
		if err != nil {
			t.Fatalf("EvaluateEncryptedWirePCAP(NAT simulé) : %v", err)
		}
		if len(constat.Conversations) != 3 {
			t.Fatalf("NAT simulé : len(Conversations) = %d, attendu 3", len(constat.Conversations))
		}
		if constat.Conversations[0].Vecteur.PersistanceBidirectionnelle < 3.6 || constat.Conversations[0].Vecteur.PersistanceBidirectionnelle >= 4.3 {
			t.Fatalf("flux 1 candidat hors plage attendue (~3.8) : pers=%v", constat.Conversations[0].Vecteur.PersistanceBidirectionnelle)
		}
		if constat.Conversations[1].RegimeEstime != RegimeR0aResolutionSporadique {
			t.Fatalf("flux 2 DoQ sporadique : régime=%s, attendu R0a", constat.Conversations[1].RegimeEstime)
		}
		if constat.Conversations[2].RegimeEstime != RegimeR0bTelechargement {
			t.Fatalf("flux 3 HTTP/3 : régime=%s, attendu R0b", constat.Conversations[2].RegimeEstime)
		}
		if len(constat.Hotes) != 0 {
			t.Fatalf("NAT simulé avec 1 seul candidat R1a : len(Hotes) = %d, attendu 0 (%+v)", len(constat.Hotes), constat.Hotes)
		}
	})

	t.Run("DeuxCandidatsDisjointsDansLeTemps", func(t *testing.T) {
		client := rat02bAdresseIPv4(10, 0, 0, 2)
		resolveur1 := rat02bAdresseIPv4(192, 0, 2, 53)
		resolveur2 := rat02bAdresseIPv4(192, 0, 2, 54)

		paquets := rat02bFluxCandidatDemiTunnel(false, client, resolveur1, 52001, 853, 1_000_000_000)
		paquets = append(paquets, rat02bFluxCandidatDemiTunnel(false, client, resolveur2, 52002, 853, 25_000_000_000)...)

		chemin := filepath.Join(t.TempDir(), "candidats-disjoints.pcap")
		rat02bEcrireCaptureEthernet(t, chemin, paquets)

		constat, err := EvaluateEncryptedWirePCAP(chemin, EncryptedWireConfig{AgregationHote: true})
		if err != nil {
			t.Fatalf("EvaluateEncryptedWirePCAP(disjoints) : %v", err)
		}
		if len(constat.Conversations) != 2 {
			t.Fatalf("len(Conversations) = %d, attendu 2", len(constat.Conversations))
		}
		if constat.Conversations[0].Releve.DernierNs >= constat.Conversations[1].Releve.PremierNs {
			t.Fatalf("précondition de disjonction temporelle violée : %d >= %d",
				constat.Conversations[0].Releve.DernierNs, constat.Conversations[1].Releve.PremierNs)
		}
		if len(constat.Hotes) != 0 {
			t.Fatalf("flux disjoints sans recouvrement : len(Hotes) = %d, attendu 0 (%+v)", len(constat.Hotes), constat.Hotes)
		}
	})

	t.Run("IPv6TemporairesRFC8981_MemePrefixe64", func(t *testing.T) {
		clientIPv6A := rat02bAdresseIPv6(t, "2001:db8:55:1:aaaa::1")
		clientIPv6B := rat02bAdresseIPv6(t, "2001:db8:55:1:bbbb::2")
		clientAutre64 := rat02bAdresseIPv6(t, "2001:db8:55:2:bbbb::2")
		resolveurIPv6A := rat02bAdresseIPv6(t, "2001:db8:53::1")
		resolveurIPv6B := rat02bAdresseIPv6(t, "2001:db8:53::2")

		cleAttendue64 := HostResolverAggregateKey{
			Client:       rat02bAdresseIPv6(t, "2001:db8:55:1::"),
			IPv6Prefix64: true,
		}
		cleA := NormalizeHostClientKey(clientIPv6A, true)
		cleB := NormalizeHostClientKey(clientIPv6B, true)
		cleAutre := NormalizeHostClientKey(clientAutre64, true)
		if cleA != cleAttendue64 || cleB != cleAttendue64 {
			t.Fatalf("NormalizeHostClientKey même /64 : cleA=%+v cleB=%+v attendu=%+v", cleA, cleB, cleAttendue64)
		}
		if cleA == cleAutre {
			t.Fatalf("préfixes /64 distincts confondus : %+v == %+v", cleA, cleAutre)
		}

		// Cas positif : même préfixe /64 menant simultanément deux flux DoQ :853 candidats.
		paquetsMeme64 := rat02bFluxCandidatDemiTunnel(true, clientIPv6A, resolveurIPv6A, 53001, 853, 1_000_000_000)
		paquetsMeme64 = append(paquetsMeme64, rat02bFluxCandidatDemiTunnel(true, clientIPv6B, resolveurIPv6B, 53002, 853, 1_002_000_000)...)
		cheminMeme64 := filepath.Join(t.TempDir(), "ipv6-meme-prefix64.pcap")
		rat02bEcrireCaptureEthernet(t, cheminMeme64, paquetsMeme64)

		constatMeme64, err := EvaluateEncryptedWirePCAP(cheminMeme64, EncryptedWireConfig{AgregationHote: true})
		if err != nil {
			t.Fatalf("EvaluateEncryptedWirePCAP(IPv6 /64) : %v", err)
		}
		if len(constatMeme64.Conversations) != 2 {
			t.Fatalf("IPv6 /64 : len(Conversations) = %d, attendu 2", len(constatMeme64.Conversations))
		}
		if len(constatMeme64.Hotes) != 1 {
			t.Fatalf("IPv6 /64 : len(Hotes) = %d, attendu 1", len(constatMeme64.Hotes))
		}
		hote64 := constatMeme64.Hotes[0]
		if hote64.Cle != cleA || !hote64.Cle.IPv6Prefix64 {
			t.Errorf("IPv6 /64 Cle = %+v, attendu %+v", hote64.Cle, cleA)
		}
		if hote64.Conversations != 2 || hote64.CiblesResolveurs != 2 {
			t.Errorf("IPv6 /64 Conversations=%d CiblesResolveurs=%d, attendu 2 et 2", hote64.Conversations, hote64.CiblesResolveurs)
		}
		if hote64.PersistanceBidirectionnelleHote < 4.30 || hote64.RegimeHote != RegimeR1aTunnelInteractif || hote64.RegimeHoteLabel != "R1a" {
			t.Errorf("IPv6 /64 verdict hôte inattendu : %+v", hote64)
		}

		// Jumeau négatif : deux préfixes /64 distincts ne fusionnent pas.
		paquetsDeux64 := rat02bFluxCandidatDemiTunnel(true, clientIPv6A, resolveurIPv6A, 53001, 853, 1_000_000_000)
		paquetsDeux64 = append(paquetsDeux64, rat02bFluxCandidatDemiTunnel(true, clientAutre64, resolveurIPv6B, 53002, 853, 1_002_000_000)...)
		cheminDeux64 := filepath.Join(t.TempDir(), "ipv6-deux-prefix64.pcap")
		rat02bEcrireCaptureEthernet(t, cheminDeux64, paquetsDeux64)

		constatDeux64, err := EvaluateEncryptedWirePCAP(cheminDeux64, EncryptedWireConfig{AgregationHote: true})
		if err != nil {
			t.Fatalf("EvaluateEncryptedWirePCAP(IPv6 /64 distincts) : %v", err)
		}
		if len(constatDeux64.Hotes) != 0 {
			t.Fatalf("préfixes /64 distincts fusionnés à tort : %+v", constatDeux64.Hotes)
		}
	})
}

func TestRatiosWireHote_PortQUIC9443ExcluPuisInclus(t *testing.T) {
	client := rat02bAdresseIPv4(10, 0, 0, 2)
	resolveur1 := rat02bAdresseIPv4(192, 0, 2, 53)
	resolveur2 := rat02bAdresseIPv4(192, 0, 2, 54)

	paquets := rat02bFluxCandidatDemiTunnel(false, client, resolveur1, 54001, 9443, 1_000_000_000)
	paquets = append(paquets, rat02bFluxCandidatDemiTunnel(false, client, resolveur2, 54002, 9443, 1_002_000_000)...)

	chemin := filepath.Join(t.TempDir(), "quic-9443-multipath.pcap")
	rat02bEcrireCaptureEthernet(t, chemin, paquets)

	constatParDefaut, err := EvaluateEncryptedWirePCAP(chemin, EncryptedWireConfig{AgregationHote: true})
	if err != nil {
		t.Fatalf("EvaluateEncryptedWirePCAP(défaut sans 9443) : %v", err)
	}
	if len(constatParDefaut.Conversations) != 2 {
		t.Fatalf("len(Conversations) = %d, attendu 2", len(constatParDefaut.Conversations))
	}
	if len(constatParDefaut.Hotes) != 0 {
		t.Fatalf("port QUIC :9443 agrégé à tort par défaut : %+v", constatParDefaut.Hotes)
	}

	constatInclus, err := EvaluateEncryptedWirePCAP(chemin, EncryptedWireConfig{
		AgregationHote:         true,
		PortsResolveurChiffres: [8]uint16{9443},
	})
	if err != nil {
		t.Fatalf("EvaluateEncryptedWirePCAP(PortsResolveurChiffres={9443}) : %v", err)
	}
	if len(constatInclus.Hotes) != 1 {
		t.Fatalf("port QUIC :9443 explicite : len(Hotes) = %d, attendu 1", len(constatInclus.Hotes))
	}
	hote := constatInclus.Hotes[0]
	if hote.Conversations != 2 || hote.CiblesResolveurs != 2 || hote.PersistanceBidirectionnelleHote < 4.30 ||
		hote.RegimeHote != RegimeR1aTunnelInteractif || hote.RegimeHoteLabel != "R1a" {
		t.Fatalf("verdict hôte :9443 inattendu : %+v", hote)
	}
}

func TestRatiosWireHote_DispersionDescendanteDescriptive(t *testing.T) {
	client := rat02bAdresseIPv4(10, 0, 0, 2)
	serveur := rat02bAdresseIPv4(192, 0, 2, 53)
	repertoire := t.TempDir()

	// 1. Moins de 16 paquets descendants porteurs (15 porteurs de 900 o + 8 accusés non porteurs de 45 o).
	var paquetsCourt []rat02bEnregistrementFlux
	for tour := range 15 {
		instant := uint64(1_000_000_000 + tour*20_000_000)
		paquetsCourt = append(paquetsCourt,
			rat02bEnregistrementFlux{instantNs: instant, source: client, destination: serveur, portSource: 55001, portDest: 853, tailleCharge: 200},
			rat02bEnregistrementFlux{instantNs: instant + 5_000_000, source: serveur, destination: client, portSource: 853, portDest: 55001, tailleCharge: 900},
		)
	}
	for ack := range 8 {
		instant := uint64(1_400_000_000 + ack*10_000_000)
		paquetsCourt = append(paquetsCourt, rat02bEnregistrementFlux{
			instantNs: instant, source: serveur, destination: client, portSource: 853, portDest: 55001, tailleCharge: 45,
		})
	}
	cheminCourt := filepath.Join(repertoire, "dispersion-15-porteurs.pcap")
	rat02bEcrireCaptureEthernet(t, cheminCourt, paquetsCourt)
	constatCourt, err := EvaluateEncryptedWirePCAP(cheminCourt, EncryptedWireConfig{})
	if err != nil || len(constatCourt.Conversations) != 1 {
		t.Fatalf("dispersion < 16 : err=%v convs=%d", err, len(constatCourt.Conversations))
	}
	if constatCourt.Conversations[0].DispersionDescendanteDefinie {
		t.Errorf("< 16 paquets descendants porteurs : DispersionDescendanteDefinie = true (permille=%d), attendu false",
			constatCourt.Conversations[0].DispersionDescendantePermille)
	}

	// 2. >= 16 paquets descendants porteurs de taille constante 900 octets -> définie et égale à 0.
	var paquetsConst900 []rat02bEnregistrementFlux
	for tour := range 24 {
		instant := uint64(1_000_000_000 + tour*20_000_000)
		paquetsConst900 = append(paquetsConst900,
			rat02bEnregistrementFlux{instantNs: instant, source: client, destination: serveur, portSource: 55002, portDest: 853, tailleCharge: 200},
			rat02bEnregistrementFlux{instantNs: instant + 5_000_000, source: serveur, destination: client, portSource: 853, portDest: 55002, tailleCharge: 900},
		)
	}
	cheminConst900 := filepath.Join(repertoire, "dispersion-const-900.pcap")
	rat02bEcrireCaptureEthernet(t, cheminConst900, paquetsConst900)
	constatConst900, err := EvaluateEncryptedWirePCAP(cheminConst900, EncryptedWireConfig{})
	if err != nil || len(constatConst900.Conversations) != 1 {
		t.Fatalf("dispersion 900 : err=%v convs=%d", err, len(constatConst900.Conversations))
	}
	verdict900 := constatConst900.Conversations[0]
	if !verdict900.DispersionDescendanteDefinie || verdict900.DispersionDescendantePermille != 0 {
		t.Errorf("taille constante 900 o : Dispersion=(%d, %t), attendu (0, true)",
			verdict900.DispersionDescendantePermille, verdict900.DispersionDescendanteDefinie)
	}

	// 3. Invariance de RegimeEstime et KineticVector entre dispersion nulle (24 * 650 o) et bimodale (12 * 200 o + 12 * 1100 o).
	var paquetsConst650, paquetsBimodal []rat02bEnregistrementFlux
	for tour := range 24 {
		instant := uint64(1_000_000_000 + tour*20_000_000)
		tailleBimodale := 200
		if tour%2 == 1 {
			tailleBimodale = 1100
		}
		paquetsConst650 = append(paquetsConst650,
			rat02bEnregistrementFlux{instantNs: instant, source: client, destination: serveur, portSource: 55003, portDest: 853, tailleCharge: 200},
			rat02bEnregistrementFlux{instantNs: instant + 5_000_000, source: serveur, destination: client, portSource: 853, portDest: 55003, tailleCharge: 650},
		)
		paquetsBimodal = append(paquetsBimodal,
			rat02bEnregistrementFlux{instantNs: instant, source: client, destination: serveur, portSource: 55003, portDest: 853, tailleCharge: 200},
			rat02bEnregistrementFlux{instantNs: instant + 5_000_000, source: serveur, destination: client, portSource: 853, portDest: 55003, tailleCharge: tailleBimodale},
		)
	}
	cheminConst650 := filepath.Join(repertoire, "dispersion-const-650.pcap")
	cheminBimodal := filepath.Join(repertoire, "dispersion-bimodal.pcap")
	rat02bEcrireCaptureEthernet(t, cheminConst650, paquetsConst650)
	rat02bEcrireCaptureEthernet(t, cheminBimodal, paquetsBimodal)

	constat650, err1 := EvaluateEncryptedWirePCAP(cheminConst650, EncryptedWireConfig{})
	constatBimodal, err2 := EvaluateEncryptedWirePCAP(cheminBimodal, EncryptedWireConfig{})
	if err1 != nil || err2 != nil {
		t.Fatalf("évaluation comparative dispersion : %v / %v", err1, err2)
	}
	v650 := constat650.Conversations[0]
	vBimodal := constatBimodal.Conversations[0]
	if !vBimodal.DispersionDescendanteDefinie || vBimodal.DispersionDescendantePermille <= 0 {
		t.Errorf("dispersion bimodale (200/1100) = (%d, %t), attendu (> 0, true)",
			vBimodal.DispersionDescendantePermille, vBimodal.DispersionDescendanteDefinie)
	}
	if v650.Vecteur != vBimodal.Vecteur || v650.RegimeEstime != vBimodal.RegimeEstime {
		t.Errorf("la dispersion descriptive a altéré Vecteur ou RegimeEstime : (%+v, %s) != (%+v, %s)",
			v650.Vecteur, v650.RegimeEstime, vBimodal.Vecteur, vBimodal.RegimeEstime)
	}
}

func TestRatiosWireHote_ObserveZeroAlloc(t *testing.T) {
	evaluateur, err := NewEncryptedWireEvaluator(EncryptedWireConfig{
		CapaciteConversations:  64,
		AgregationHote:         true,
		PortsResolveurChiffres: [8]uint16{8443, 9443},
	})
	if err != nil {
		t.Fatalf("NewEncryptedWireEvaluator : %v", err)
	}

	trameIPv4 := rat02bConstruireTrameEthernetUDP(rat02bEnregistrementFlux{
		source:       rat02bAdresseIPv4(10, 55, 0, 2),
		destination:  rat02bAdresseIPv4(10, 55, 0, 1),
		portSource:   56001,
		portDest:     853,
		tailleCharge: 320,
	})
	trameIPv6 := rat02bConstruireTrameEthernetUDP(rat02bEnregistrementFlux{
		ipv6:         true,
		source:       rat02bAdresseIPv6(t, "2001:db8:55:1:aaaa::1"),
		destination:  rat02bAdresseIPv6(t, "2001:db8:53::1"),
		portSource:   56002,
		portDest:     9443,
		tailleCharge: 640,
	})

	instantNs := uint64(1_000_000_000)
	allocs := testing.AllocsPerRun(500, func() {
		instantNs += 10_000_000
		if errObs := evaluateur.Observe(BenchPacket{TimestampNs: instantNs, LinkType: 1, Frame: trameIPv4}); errObs != nil {
			t.Fatalf("Observe IPv4 : %v", errObs)
		}
		instantNs += 5_000_000
		if errObs := evaluateur.Observe(BenchPacket{TimestampNs: instantNs, LinkType: 1, Frame: trameIPv6}); errObs != nil {
			t.Fatalf("Observe IPv6 : %v", errObs)
		}
	})
	if allocs != 0 {
		t.Fatalf("Observe avec AgregationHote=true : %v allocs/op, attendu 0", allocs)
	}
}
