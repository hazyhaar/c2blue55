package c2blue55_test

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"github.com/hazyhaar/c2blue55"
)

func TestRedhostLabRun_ProvenanceAndCardinality(t *testing.T) {
	validateTerrain(t)
	pcapPath, manifestPath := realLabPaths(t)
	oracle := readManifestOracle(t, manifestPath)
	run, err := c2blue55.IngestRedhostLabRun(pcapPath, manifestPath)
	if err != nil {
		t.Fatalf("IngestRedhostLabRun: %v", err)
	}
	if len(run.Views) != 69 || run.Stats.Accepted != 69 {
		t.Fatalf("écart fonctionnel: len(Views)=%d Accepted=%d, attendu 69 et 69", len(run.Views), run.Stats.Accepted)
	}
	pcapStats, pcapErr := c2blue55.ReadPCAPDNSQuestions(pcapPath, func(c2blue55.PCAPQuestionMeta, *c2blue55.DNSEvent) error {
		return nil
	})
	if pcapErr != nil {
		t.Fatalf("ReadPCAPDNSQuestions: %v", pcapErr)
	}
	if run.Stats != pcapStats {
		t.Errorf("Stats=%+v, ReadPCAPDNSQuestions=%+v", run.Stats, pcapStats)
	}
	loaded, loadErr := c2blue55.LoadRedhostLabManifest(manifestPath)
	if loadErr != nil {
		t.Fatalf("LoadRedhostLabManifest: %v", loadErr)
	}
	assertManifestEqual(t, run.Manifest, loaded)
	assertManifestFields(t, run.Manifest, oracle)
	wantClient := packIPv4(127, 0, 0, 1)
	first := run.Views[0]
	if string(first.View.FQDN) != "hazyhaar.fr" || first.View.QType != 1 || first.Record != 1 || first.Timestamp != firstQuestionStamp || first.ClientIP != wantClient {
		t.Fatalf("Views[0]=FQDN %q QType %d Record %d Timestamp %d ClientIP %v", first.View.FQDN, first.View.QType, first.Record, first.Timestamp, first.ClientIP)
	}
	for i := 1; i < len(run.Views); i++ {
		if run.Views[i].Record <= run.Views[i-1].Record {
			t.Errorf("Record non strictement croissant: %d puis %d", run.Views[i-1].Record, run.Views[i].Record)
		}
	}
	for i := range run.Views {
		view := run.Views[i]
		if view.RunID != oracle.RunID || view.Label != oracle.Label {
			t.Errorf("Views[%d] RunID=%q Label=%q, attendu %q %q", i, view.RunID, view.Label, oracle.RunID, oracle.Label)
		}
		shape, ok := terrainShape(string(view.View.FQDN))
		if !ok {
			t.Errorf("Views[%d] FQDN hors vérité terrain: %q", i, view.View.FQDN)
			continue
		}
		if string(view.View.Subdomain) != shape.sub {
			t.Errorf("Views[%d] Subdomain=%q, attendu %q", i, view.View.Subdomain, shape.sub)
		}
		if string(view.View.SLD) != shape.sld {
			t.Errorf("Views[%d] SLD=%q, attendu %q", i, view.View.SLD, shape.sld)
		}
		if string(view.View.TLD) != shape.tld {
			t.Errorf("Views[%d] TLD=%q, attendu %q", i, view.View.TLD, shape.tld)
		}
		if view.View.LabelCount != shape.labelCount {
			t.Errorf("Views[%d] LabelCount=%d, attendu %d", i, view.View.LabelCount, shape.labelCount)
		}
		if view.View.MaxLabelLen != shape.maxLabelLen {
			t.Errorf("Views[%d] MaxLabelLen=%d, attendu %d", i, view.View.MaxLabelLen, shape.maxLabelLen)
		}
		card, known := subCardinalityForParent(shape.parent)
		if !known || view.View.SubCardinality != card {
			t.Errorf("Views[%d] parent %s SubCardinality=%d, attendu %d", i, shape.parent, view.View.SubCardinality, card)
		}
	}
	naked := run.QueryViews()
	if len(naked) != 69 {
		t.Fatalf("len(QueryViews)=%d, attendu 69", len(naked))
	}
	for i := range run.Views {
		if !bytes.Equal(naked[i].FQDN, run.Views[i].View.FQDN) {
			t.Errorf("QueryViews[%d].FQDN différent de Views[%d].FQDN", i, i)
		}
	}
	for i := range run.Views {
		fqdn := run.Views[i].View.FQDN
		if len(fqdn) == 0 {
			t.Fatalf("Views[%d].FQDN vide", i)
		}
		saved := make([][]byte, len(run.Views))
		for j := range run.Views {
			saved[j] = append([]byte(nil), run.Views[j].View.FQDN...)
		}
		fqdn[0] ^= 0x01
		for j := range run.Views {
			if j == i {
				continue
			}
			if !bytes.Equal(run.Views[j].View.FQDN, saved[j]) {
				t.Fatalf("mutation de Views[%d].FQDN a modifié Views[%d].FQDN", i, j)
			}
		}
		fqdn[0] ^= 0x01
	}
}

func TestRedhostLabRun_ManifestRefusedBeforePCAP(t *testing.T) {
	_, manifestPath := realLabPaths(t)
	_, payload := readLabManifest(t)
	t.Run("manifeste hors contrat avant pcap", func(t *testing.T) {
		fields := manifestMap(t, payload)
		fields["champ_inconnu"] = "hors-contrat"
		badManifest := writeManifestMap(t, fields)
		absentPCAP := filepath.Join(t.TempDir(), "capture-absente.pcap")
		_, err := c2blue55.IngestRedhostLabRun(absentPCAP, badManifest)
		if !errors.Is(err, c2blue55.ErrLabManifestContract) {
			t.Fatalf("erreur=%v, attendu ErrLabManifestContract (la capture ne doit pas être ouverte)", err)
		}
	})
	t.Run("pcap amputé", func(t *testing.T) {
		_, capture := readRealCapture(t)
		truncated := append([]byte(nil), capture[:len(capture)-1]...)
		truncPath := writeTempBytes(t, "capture-amputee.pcap", truncated)
		run, err := c2blue55.IngestRedhostLabRun(truncPath, manifestPath)
		if !errors.Is(err, c2blue55.ErrPCAPTruncated) {
			t.Fatalf("erreur=%v, attendu ErrPCAPTruncated", err)
		}
		if len(run.Views) != 0 {
			t.Fatalf("len(Views)=%d, attendu 0", len(run.Views))
		}
	})
}
