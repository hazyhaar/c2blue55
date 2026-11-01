package c2blue55_test

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55"
)

const manifestSizeCap = 1 << 20

type manifestOracle struct {
	RunID          string   `json:"run_id"`
	Host           string   `json:"host"`
	Interface      string   `json:"interface"`
	Filter         string   `json:"filter"`
	Resolver       string   `json:"resolver"`
	Start          string   `json:"start"`
	End            string   `json:"end"`
	QueriedDomains []string `json:"queried_domains"`
	Label          string   `json:"label"`
	Note           string   `json:"note"`
}

func readManifestOracle(t *testing.T, path string) manifestOracle {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lecture du manifeste: %v", err)
	}
	var oracle manifestOracle
	if err := json.Unmarshal(payload, &oracle); err != nil {
		t.Fatalf("décodage json du manifeste: %v", err)
	}
	return oracle
}

func readLabManifest(t *testing.T) (path string, payload []byte) {
	t.Helper()
	_, path = realLabPaths(t)
	var err error
	payload, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("lecture du manifeste réel: %v", err)
	}
	return path, payload
}

func assertManifestFields(t *testing.T, got c2blue55.RedhostLabManifest, oracle manifestOracle) {
	t.Helper()
	if got.RunID != oracle.RunID {
		t.Errorf("RunID=%q, attendu %q", got.RunID, oracle.RunID)
	}
	if got.Host != oracle.Host {
		t.Errorf("Host=%q, attendu %q", got.Host, oracle.Host)
	}
	if got.Interface != oracle.Interface {
		t.Errorf("Interface=%q, attendu %q", got.Interface, oracle.Interface)
	}
	if got.Filter != oracle.Filter {
		t.Errorf("Filter=%q, attendu %q", got.Filter, oracle.Filter)
	}
	if got.Resolver != oracle.Resolver {
		t.Errorf("Resolver=%q, attendu %q", got.Resolver, oracle.Resolver)
	}
	if got.Start != oracle.Start {
		t.Errorf("Start=%q, attendu %q", got.Start, oracle.Start)
	}
	if got.End != oracle.End {
		t.Errorf("End=%q, attendu %q", got.End, oracle.End)
	}
	if got.Label != oracle.Label {
		t.Errorf("Label=%q, attendu %q", got.Label, oracle.Label)
	}
	if got.Note != oracle.Note {
		t.Errorf("Note=%q, attendu %q", got.Note, oracle.Note)
	}
	if !slices.Equal(got.QueriedDomains, oracle.QueriedDomains) {
		t.Errorf("QueriedDomains=%v, attendu %v", got.QueriedDomains, oracle.QueriedDomains)
	}
}

func assertManifestEqual(t *testing.T, got, want c2blue55.RedhostLabManifest) {
	t.Helper()
	if got.RunID != want.RunID || got.Host != want.Host || got.Interface != want.Interface || got.Filter != want.Filter || got.Resolver != want.Resolver || got.Start != want.Start || got.End != want.End || got.Label != want.Label || got.Note != want.Note || !slices.Equal(got.QueriedDomains, want.QueriedDomains) {
		t.Errorf("Manifest=%+v, attendu %+v", got, want)
	}
}

func manifestMap(t *testing.T, payload []byte) map[string]any {
	t.Helper()
	var fields map[string]any
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatalf("décodage du manifeste réel: %v", err)
	}
	return fields
}

func writeManifestMap(t *testing.T, fields map[string]any) string {
	t.Helper()
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("encodage du manifeste altéré: %v", err)
	}
	return writeTempBytes(t, "manifest.json", encoded)
}

func assertContractError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, c2blue55.ErrLabManifestContract) {
		t.Fatalf("erreur=%v, attendu ErrLabManifestContract", err)
	}
}

func TestLabManifest_RealManifestFields(t *testing.T) {
	manifestPath, _ := readLabManifest(t)
	oracle := readManifestOracle(t, manifestPath)
	if oracle.RunID != "local-dns-20261027T113715Z" || oracle.Label != "benign-own-domains" || len(oracle.QueriedDomains) != 4 {
		t.Fatalf("manifeste réel hors vérité: run_id=%q label=%q domaines=%d", oracle.RunID, oracle.Label, len(oracle.QueriedDomains))
	}
	wantDomains := []string{"hazyhaar.fr", "www.hazyhaar.fr", "pound2pound.fr", "lab.pound2pound.fr"}
	if !slices.Equal(oracle.QueriedDomains, wantDomains) {
		t.Fatalf("queried_domains=%v, attendu %v", oracle.QueriedDomains, wantDomains)
	}
	got, err := c2blue55.LoadRedhostLabManifest(manifestPath)
	if err != nil {
		t.Fatalf("LoadRedhostLabManifest: %v", err)
	}
	assertManifestFields(t, got, oracle)
}

func TestLabManifest_ContractRefusals(t *testing.T) {
	_, payload := readLabManifest(t)
	t.Run("champ inconnu", func(t *testing.T) {
		fields := manifestMap(t, payload)
		fields["champ_inconnu"] = "hors-contrat"
		_, err := c2blue55.LoadRedhostLabManifest(writeManifestMap(t, fields))
		assertContractError(t, err)
	})
	t.Run("run_id vide", func(t *testing.T) {
		fields := manifestMap(t, payload)
		fields["run_id"] = ""
		_, err := c2blue55.LoadRedhostLabManifest(writeManifestMap(t, fields))
		assertContractError(t, err)
	})
	t.Run("end antérieur à start", func(t *testing.T) {
		fields := manifestMap(t, payload)
		start, ok := fields["start"].(string)
		if !ok {
			t.Fatal("start réel absent")
		}
		stamp, err := time.Parse(time.RFC3339Nano, start)
		if err != nil {
			t.Fatalf("start réel non RFC 3339: %v", err)
		}
		fields["end"] = stamp.Add(-time.Second).Format(time.RFC3339Nano)
		_, err = c2blue55.LoadRedhostLabManifest(writeManifestMap(t, fields))
		assertContractError(t, err)
	})
	t.Run("start non RFC3339", func(t *testing.T) {
		fields := manifestMap(t, payload)
		fields["start"] = "2026-10-27 11:37:17"
		_, err := c2blue55.LoadRedhostLabManifest(writeManifestMap(t, fields))
		assertContractError(t, err)
	})
	t.Run("fichier trop grand", func(t *testing.T) {
		oversize := make([]byte, manifestSizeCap+1)
		copy(oversize, payload)
		if len(oversize) != manifestSizeCap+1 {
			t.Fatalf("taille construite %d", len(oversize))
		}
		path := writeTempBytes(t, "manifest-oversize.json", oversize)
		_, err := c2blue55.LoadRedhostLabManifest(path)
		assertContractError(t, err)
	})
	t.Run("fichier absent", func(t *testing.T) {
		absent := filepath.Join(t.TempDir(), "manifest-absent.json")
		_, err := c2blue55.LoadRedhostLabManifest(absent)
		if err == nil {
			t.Fatal("fichier absent: erreur attendue absente")
		}
		if errors.Is(err, c2blue55.ErrLabManifestContract) {
			t.Fatalf("fichier absent classé à tort comme hors contrat: %v", err)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("fichier absent: %v n'enveloppe pas fs.ErrNotExist", err)
		}
	})
}
