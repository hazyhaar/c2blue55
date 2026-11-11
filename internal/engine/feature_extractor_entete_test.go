// Tests de contrat de la strate L1-S1 : neutralisation de la projection du
// numéro de processus et de l'adresse source, et comptage du seul drapeau de
// charge longue, dans le vecteur de caractéristiques.
//
// La fonction de test unique TestFillEventHeaderContratL1S1 transcrit les cas
// prescrits C01, C02 et C03 sur la déclaration réelle fillEventHeader. Chaque
// sous-test l'appelle directement à son premier niveau, vérifie ses longueurs
// de tampon avant indexation, relit le tampon muté et aserte ses sorties par
// des assertions de premier niveau qui échouent sur un corps vide, de sorte
// que le bouchonnage individuel posthoc-v9 de la déclaration rougit, que le
// code réel réussisse et que les mutants qui réintroduiraient une dépendance
// au PID, à la source ou aux bits de ev.Flags autres que FlagLongPayload, qui
// permuteraient le masquage en union bit à bit, qui transformeraient les trois
// divisions en multiplications ou qui omettraient l'une des trois écritures
// soient tués. Le scénario hostile SH-L1S1-1 est vérifié dans le corps du cas
// C01, sous forme d'épreuve en table balayant tous les octets bas de PID
// croisés avec des sources adverses, sans ouvrir de sous-test supplémentaire.
package engine

import "testing"

// TestFillEventHeaderContratL1S1 transcrit les cas prescrits C01 (invariance
// du vecteur face à Pid et Src, avec composantes neutralisées à zéro et
// témoins positifs sous charge longue), C02 (divergence maintenue sur
// hdrAction, hdrSubsystem et hdrFlagPopcount pour toute autre variation) et
// C03 (invariance du vecteur face aux bits de ev.Flags autres que
// FlagLongPayload, compté seul à 1/32) de la strate L1-S1.
func TestFillEventHeaderContratL1S1(t *testing.T) {
	t.Run("C01", func(t *testing.T) {
		evNul := Event{Action: 1, Subsystem: 1, Flags: FlagLongPayload, Pid: 0, Src: 0}
		evHostile := Event{Action: 1, Subsystem: 1, Flags: FlagLongPayload, Pid: 4321, Src: 1<<32 | 0xC0A80117}
		var a, b [EmbeddingDim]float32
		if len(a[:]) != EmbeddingDim || len(b[:]) != EmbeddingDim {
			t.Fatalf("C01 : tampons de %d et %d composantes, attendu %d", len(a[:]), len(b[:]), EmbeddingDim)
		}
		fillEventHeader(&evNul, a[:])
		fillEventHeader(&evHostile, b[:])
		if a[headerBase+hdrAction] != float32(1)/float32(65535) {
			t.Errorf("C01 : hdrAction = %v, attendu 1/65535", a[headerBase+hdrAction])
		}
		if a[headerBase+hdrFlagPopcount] != float32(1)/float32(32) {
			t.Errorf("C01 : hdrFlagPopcount = %v, attendu 1/32", a[headerBase+hdrFlagPopcount])
		}
		if a[headerBase+hdrPIDFresh] != 0 || a[headerBase+hdrPIDLow] != 0 || a[headerBase+hdrSrcClass] != 0 || a[headerBase+hdrSrcLow] != 0 {
			t.Errorf("C01 : composantes neutralisées (fresh=%v, low=%v, srcClass=%v, srcLow=%v), attendu 0/0/0/0",
				a[headerBase+hdrPIDFresh], a[headerBase+hdrPIDLow], a[headerBase+hdrSrcClass], a[headerBase+hdrSrcLow])
		}
		if a[aggregateBase+aggHeaderFusion] != (float32(1)/float32(65535))*(float32(1)/float32(65535)) {
			t.Errorf("C01 : aggHeaderFusion = %v, attendu (1/65535)*(1/65535)", a[aggregateBase+aggHeaderFusion])
		}
		if b != a {
			t.Errorf("C01 : vecteur de l'événement de Pid=4321 et Src=1<<32|0xC0A80117 différent du vecteur de l'événement nul")
		}

		// Scénario hostile SH-L1S1-1, en épreuve en table complémentaire :
		// tout octet bas de PID (0 à 255) croisé avec des sources choisies par
		// l'attaquant produit un vecteur égal composante par composante à la
		// référence, donc un code binaire et un verdict identiques.
		sourcesAdverses := []uint64{
			0,
			1 << 32,
			1<<32 | 0xC0A80117,
			3<<32 | 0x7F000001,
			8<<32 | 0xFFFFFFFF,
			0xFFFFFFFFFFFFFFFF,
		}
		for octetBas := range 256 {
			for _, src := range sourcesAdverses {
				ev := Event{Action: 1, Subsystem: 1, Flags: FlagLongPayload, Pid: uint32(octetBas), Src: src}
				var obtenu [EmbeddingDim]float32
				fillEventHeader(&ev, obtenu[:])
				if obtenu != a {
					t.Errorf("SH-L1S1-1 : octet bas de PID %d et source %#x : vecteur différent du vecteur de référence", octetBas, src)
				}
			}
		}
	})

	t.Run("C02", func(t *testing.T) {
		const (
			pid = uint32(4321)
			src = uint64(1<<32 | 0xC0A80117)
		)
		var (
			bufActionBase, bufActionVariante       [EmbeddingDim]float32
			bufSubsystemBase, bufSubsystemVariante [EmbeddingDim]float32
			bufFlagsBase, bufFlagsVariante         [EmbeddingDim]float32
		)
		if len(bufActionBase[:]) != EmbeddingDim || len(bufActionVariante[:]) != EmbeddingDim ||
			len(bufSubsystemBase[:]) != EmbeddingDim || len(bufSubsystemVariante[:]) != EmbeddingDim ||
			len(bufFlagsBase[:]) != EmbeddingDim || len(bufFlagsVariante[:]) != EmbeddingDim {
			t.Fatalf("C02 : tampon de longueur insuffisante, attendu %d composantes", EmbeddingDim)
		}

		// Paire 1 de la prescription : même Pid, même Src, Action 1 puis 3.
		// Appels et assertions de premier niveau : les tampons mutés sont lus
		// directement dans le corps du sous-test.
		baseAction := Event{Action: 1, Subsystem: 1, Flags: 0, Pid: pid, Src: src}
		variantAction := Event{Action: 3, Subsystem: 1, Flags: 0, Pid: pid, Src: src}
		fillEventHeader(&baseAction, bufActionBase[:])
		fillEventHeader(&variantAction, bufActionVariante[:])
		if bufActionBase[headerBase+hdrAction] != float32(1)/float32(65535) {
			t.Errorf("C02 : Action 1, hdrAction = %v, attendu 1/65535", bufActionBase[headerBase+hdrAction])
		}
		if bufActionVariante[headerBase+hdrAction] != float32(3)/float32(65535) {
			t.Errorf("C02 : Action 3, hdrAction = %v, attendu 3/65535", bufActionVariante[headerBase+hdrAction])
		}
		if bufActionBase[headerBase+hdrAction] == bufActionVariante[headerBase+hdrAction] {
			t.Errorf("C02 : Action 1 puis 3 : composante headerBase+hdrAction identique (%v), divergence attendue",
				bufActionBase[headerBase+hdrAction])
		}
		if bufActionVariante[aggregateBase+aggHeaderFusion] != (float32(3)/float32(65535))*(float32(1)/float32(65535)) {
			t.Errorf("C02 : Action 3, aggHeaderFusion = %v, attendu (3/65535)*(1/65535)",
				bufActionVariante[aggregateBase+aggHeaderFusion])
		}

		// Paire 2 de la prescription : même Pid, même Src, Subsystem 1 puis 3.
		baseSubsystem := Event{Action: 1, Subsystem: 1, Flags: 0, Pid: pid, Src: src}
		variantSubsystem := Event{Action: 1, Subsystem: 3, Flags: 0, Pid: pid, Src: src}
		fillEventHeader(&baseSubsystem, bufSubsystemBase[:])
		fillEventHeader(&variantSubsystem, bufSubsystemVariante[:])
		if bufSubsystemBase[headerBase+hdrSubsystem] != float32(1)/float32(65535) {
			t.Errorf("C02 : Subsystem 1, hdrSubsystem = %v, attendu 1/65535", bufSubsystemBase[headerBase+hdrSubsystem])
		}
		if bufSubsystemVariante[headerBase+hdrSubsystem] != float32(3)/float32(65535) {
			t.Errorf("C02 : Subsystem 3, hdrSubsystem = %v, attendu 3/65535", bufSubsystemVariante[headerBase+hdrSubsystem])
		}
		if bufSubsystemBase[headerBase+hdrSubsystem] == bufSubsystemVariante[headerBase+hdrSubsystem] {
			t.Errorf("C02 : Subsystem 1 puis 3 : composante headerBase+hdrSubsystem identique (%v), divergence attendue",
				bufSubsystemBase[headerBase+hdrSubsystem])
		}
		if bufSubsystemVariante[aggregateBase+aggHeaderFusion] != (float32(1)/float32(65535))*(float32(3)/float32(65535)) {
			t.Errorf("C02 : Subsystem 3, aggHeaderFusion = %v, attendu (1/65535)*(3/65535)",
				bufSubsystemVariante[aggregateBase+aggHeaderFusion])
		}

		// Paire 3 de la prescription : même Pid, même Src, dont seul le
		// drapeau FlagLongPayload diffère (Flags 0 puis FlagLongPayload).
		baseFlags := Event{Action: 1, Subsystem: 1, Flags: 0, Pid: pid, Src: src}
		variantFlags := Event{Action: 1, Subsystem: 1, Flags: FlagLongPayload, Pid: pid, Src: src}
		fillEventHeader(&baseFlags, bufFlagsBase[:])
		fillEventHeader(&variantFlags, bufFlagsVariante[:])
		if bufFlagsBase[headerBase+hdrFlagPopcount] != 0 {
			t.Errorf("C02 : Flags 0, hdrFlagPopcount = %v, attendu 0", bufFlagsBase[headerBase+hdrFlagPopcount])
		}
		if bufFlagsVariante[headerBase+hdrFlagPopcount] != float32(1)/float32(32) {
			t.Errorf("C02 : FlagLongPayload, hdrFlagPopcount = %v, attendu 1/32", bufFlagsVariante[headerBase+hdrFlagPopcount])
		}
		if bufFlagsBase[headerBase+hdrFlagPopcount] == bufFlagsVariante[headerBase+hdrFlagPopcount] {
			t.Errorf("C02 : Flags 0 puis FlagLongPayload : composante headerBase+hdrFlagPopcount identique (%v), divergence attendue",
				bufFlagsBase[headerBase+hdrFlagPopcount])
		}

		// Épreuve en table complémentaire, en plus des appels et assertions de
		// premier niveau : recompte des trois paires prescrites et vérification
		// du maintien à zéro des quatre composantes neutralisées.
		zeroIndices := []int{hdrPIDFresh, hdrPIDLow, hdrSrcClass, hdrSrcLow}
		paires := []struct {
			nom     string
			base    Event
			variant Event
			indice  int
		}{
			{"Action 1 puis 3", baseAction, variantAction, hdrAction},
			{"Subsystem 1 puis 3", baseSubsystem, variantSubsystem, hdrSubsystem},
			{"Flags 0 puis FlagLongPayload", baseFlags, variantFlags, hdrFlagPopcount},
		}
		for _, paire := range paires {
			var tamponBase, tamponVariante [EmbeddingDim]float32
			base := paire.base
			variant := paire.variant
			fillEventHeader(&base, tamponBase[:])
			fillEventHeader(&variant, tamponVariante[:])
			if tamponBase[headerBase+paire.indice] == tamponVariante[headerBase+paire.indice] {
				t.Errorf("%s : recompte en table, composante headerBase+%d identique (%v), divergence attendue",
					paire.nom, paire.indice, tamponBase[headerBase+paire.indice])
			}
			for _, idx := range zeroIndices {
				if tamponBase[headerBase+idx] != 0 || tamponVariante[headerBase+idx] != 0 {
					t.Errorf("%s : composante neutralisée headerBase+%d écrite (%v, %v), attendu 0",
						paire.nom, idx, tamponBase[headerBase+idx], tamponVariante[headerBase+idx])
				}
			}
		}
	})

	t.Run("C03", func(t *testing.T) {
		// Appel et assertions de premier niveau : l'événement de référence à
		// drapeaux nuls projette une action non nulle et un compteur de
		// drapeaux nul, si bien que le sous-test échoue par assertion sur un
		// corps vide de fillEventHeader.
		evReference := Event{Action: 1, Subsystem: 1, Pid: 0, Src: 0}
		var bufReference [EmbeddingDim]float32
		if len(bufReference[:]) != EmbeddingDim {
			t.Fatalf("C03 : tampon de %d composantes, attendu %d", len(bufReference[:]), EmbeddingDim)
		}
		fillEventHeader(&evReference, bufReference[:])
		if bufReference[headerBase+hdrAction] != float32(1)/float32(65535) {
			t.Errorf("C03 : hdrAction = %v, attendu 1/65535", bufReference[headerBase+hdrAction])
		}
		if bufReference[headerBase+hdrFlagPopcount] != 0 {
			t.Errorf("C03 : Flags 0, hdrFlagPopcount = %v, attendu 0", bufReference[headerBase+hdrFlagPopcount])
		}

		// Drapeaux neutres prescrits : 0x0004, 0x0106 et 0xFFFF0FFF (tous les
		// bits sauf FlagLongPayload). Aucun n'influence le vecteur, qui reste
		// égal composante par composante à la référence à drapeaux nuls, avec
		// un compteur de drapeaux maintenu à zéro.
		drapeauxNeutres := []uint32{0x0004, 0x0106, 0xFFFF0FFF}
		for _, drapeaux := range drapeauxNeutres {
			ev := Event{Action: 1, Subsystem: 1, Pid: 0, Src: 0, Flags: drapeaux}
			var buf [EmbeddingDim]float32
			fillEventHeader(&ev, buf[:])
			if buf != bufReference {
				t.Errorf("C03 : Flags %#x : vecteur différent du vecteur de référence à drapeaux nuls", drapeaux)
			}
			if buf[headerBase+hdrFlagPopcount] != 0 {
				t.Errorf("C03 : Flags %#x, hdrFlagPopcount = %v, attendu 0", drapeaux, buf[headerBase+hdrFlagPopcount])
			}
		}

		// Charge longue prescrite : FlagLongPayload seul puis porté avec un
		// autre bit donnent le même vecteur, dont hdrFlagPopcount vaut 1/32.
		drapeauxLongs := []uint32{FlagLongPayload, FlagLongPayload | 0x0106}
		var bufLongueReference [EmbeddingDim]float32
		for i, drapeaux := range drapeauxLongs {
			ev := Event{Action: 1, Subsystem: 1, Pid: 0, Src: 0, Flags: drapeaux}
			var buf [EmbeddingDim]float32
			fillEventHeader(&ev, buf[:])
			if buf[headerBase+hdrFlagPopcount] != float32(1)/float32(32) {
				t.Errorf("C03 : Flags %#x, hdrFlagPopcount = %v, attendu 1/32", drapeaux, buf[headerBase+hdrFlagPopcount])
			}
			if i == 0 {
				bufLongueReference = buf
			} else if buf != bufLongueReference {
				t.Errorf("C03 : Flags %#x : vecteur différent du vecteur à FlagLongPayload seul", drapeaux)
			}
		}
	})
}
