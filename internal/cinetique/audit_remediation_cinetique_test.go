package cinetique

import "testing"

func TestAuditProfilAmorcageQuotientOptionnel(t *testing.T) {
	table := NouvelleTableProfilsCinetiques(ConfigProfilParDefaut())
	cleExecutable := HashIdentifiantBinaire("/usr/sbin/audit-io-daemon")

	masqueReposSansPreemption := uint16(
		(1 << IndiceOctetsParAppelES) |
			(1 << IndicePartEcriturePermille) |
			(1 << IndiceAmplificationBlocPermille) |
			(1 << IndiceNsCPUParKioLogique) |
			(1 << IndiceKioPicRSSParFil) |
			(1 << IndiceAttenteOrdonnanceur) |
			(1 << IndiceDilatationHorsCPU),
	)

	// 8 épisodes d'amorçage calmes sur le même coeur où IndicePartPreemptionPermille est invalide (< 4 commutations).
	for pas := range 8 {
		epCalme := QuotientsEpisode{
			PID:                    4242,
			DebutTacheTicks:        100_000,
			DureeHorlogeNs:         10_000_000,
			DeltaExecutionNs:       2_000_000,
			DeltaAttenteFileNs:     50_000,
			DeltaHorsCPUNs:         400_000,
			DeltaOctetsLusLogiques: 16_384,
			DeltaOctetsEcritsLog:   4_096,
			DeltaOctetsBloc:        4_096,
			PicRSSKio:              16_000,
			RSSResidentFinKio:      16_000,
			UnitesConcurrence:      1,
			ClasseCoeurDebut:       ClasseCoeurPerformance,
			ClasseCoeurFin:         ClasseCoeurPerformance,
			MasqueValidite:         masqueReposSansPreemption,
		}
		epCalme.Valeurs[IndiceOctetsParAppelES] = 4_096
		epCalme.Valeurs[IndicePartEcriturePermille] = 200
		epCalme.Valeurs[IndiceAmplificationBlocPermille] = 1_000
		epCalme.Valeurs[IndiceNsCPUParKioLogique] = 100_000
		epCalme.Valeurs[IndiceKioPicRSSParFil] = 16_000
		epCalme.Valeurs[IndiceAttenteOrdonnanceur] = 25
		epCalme.Valeurs[IndiceDilatationHorsCPU] = 200

		horodatageNs := uint64(1_000_000_000 + pas*10_000_000)
		_ = table.ObserverEpisode(cleExecutable, horodatageNs, epCalme)
	}

	// 9e épisode : panne E/S franche (IndiceDilatationHorsCPU = 8000, x40) avec IndicePartPreemptionPermille valide (ex. 32 fdatasync).
	epPanneES := QuotientsEpisode{
		PID:                    4242,
		DebutTacheTicks:        100_000,
		DureeHorlogeNs:         20_000_000,
		DeltaExecutionNs:       2_000_000,
		DeltaAttenteFileNs:     50_000,
		DeltaHorsCPUNs:         16_000_000,
		DeltaOctetsLusLogiques: 16_384,
		DeltaOctetsEcritsLog:   4_096,
		DeltaOctetsBloc:        4_096,
		PicRSSKio:              16_000,
		RSSResidentFinKio:      16_000,
		UnitesConcurrence:      1,
		ClasseCoeurDebut:       ClasseCoeurPerformance,
		ClasseCoeurFin:         ClasseCoeurPerformance,
		MasqueValidite:         masqueReposSansPreemption | (1 << IndicePartPreemptionPermille),
	}
	epPanneES.Valeurs[IndiceOctetsParAppelES] = 4_096
	epPanneES.Valeurs[IndicePartEcriturePermille] = 200
	epPanneES.Valeurs[IndiceAmplificationBlocPermille] = 1_000
	epPanneES.Valeurs[IndiceNsCPUParKioLogique] = 100_000
	epPanneES.Valeurs[IndiceKioPicRSSParFil] = 16_000
	epPanneES.Valeurs[IndicePartPreemptionPermille] = 30
	epPanneES.Valeurs[IndiceAttenteOrdonnanceur] = 25
	epPanneES.Valeurs[IndiceDilatationHorsCPU] = 8_000

	diagnostic := table.ObserverEpisode(cleExecutable, 1_090_000_000, epPanneES)
	if diagnostic.Orientation != OrientationDegradationES {
		t.Fatalf("9e episode (panne E/S x40 avec IndicePartPreemptionPermille nouvellement valide): obtenu %v (%s), attendu %v (%s)",
			diagnostic.Orientation, diagnostic.Orientation.String(),
			OrientationDegradationES, OrientationDegradationES.String())
	}
}
