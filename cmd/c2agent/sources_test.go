package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55"
)

func TestSourceConfigurationRejectThenLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sources.json")
	for _, data := range []string{`[{"Name":"test","URI":"http://example.org"}]`, `[{"Unknown":true}]`, `[] []`, `not-json`} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadSources(path); err == nil {
			t.Fatalf("accepted %s", data)
		}
		want := []c2blue55.ReputationSource{{Name: "local-test", URI: "file:///devhoros/private-test-feed", Classification: c2blue55.RepClassBlockC2, MatchKind: c2blue55.MatchExact}}
		valid, err := json.Marshal(want)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, valid, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := loadSources(path)
		if err != nil || len(got) != 1 || got[0] != want[0] {
			t.Fatalf("source recovery: %+v %v", got, err)
		}
	}
	if got, err := loadSources(""); err != nil || len(got) != 0 {
		t.Fatalf("no sources: %+v %v", got, err)
	}
}
