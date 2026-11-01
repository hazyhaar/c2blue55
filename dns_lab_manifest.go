package c2blue55

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
)

// ErrLabManifestContract signale un manifeste de run hors contrat (champ
// inconnu, champ obligatoire vide, bornes temporelles invalides) ; la cause
// exacte est enveloppée.
var ErrLabManifestContract = errors.New("c2blue55: manifeste de run de laboratoire hors contrat")

// RedhostLabManifest décrit un run de capture du laboratoire DNS
// (wittgenstein/redhost_lab/<run_id>.manifest.json), en JSON strict.
type RedhostLabManifest struct {
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
	// Champs optionnels écrits par l'émetteur de laboratoire (strate S-05).
	Family  string `json:"family,omitempty"`
	Tool    string `json:"tool,omitempty"`
	Emitter string `json:"emitter,omitempty"`
	Server  string `json:"server,omitempty"`
}

// LoadRedhostLabManifest lit au plus 1 MiB, décode en JSON strict
// (DisallowUnknownFields), exige run_id, host, interface, filter, start, end et
// label non vides, start et end en RFC 3339 avec start <= end.
func LoadRedhostLabManifest(path string) (manifest RedhostLabManifest, err error) {
	file, err := os.Open(path)
	if err != nil {
		return RedhostLabManifest{}, fmt.Errorf("ouverture du manifeste: %w", err)
	}
	defer func() {
		if cerr := file.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("fermeture du manifeste: %w", cerr)
		}
	}()
	payload, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return RedhostLabManifest{}, fmt.Errorf("%w: lecture: %w", ErrLabManifestContract, err)
	}
	if len(payload) > 1<<20 {
		return RedhostLabManifest{}, fmt.Errorf("%w: taille supérieure à 1 MiB", ErrLabManifestContract)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return RedhostLabManifest{}, fmt.Errorf("%w: JSON: %w", ErrLabManifestContract, err)
	}
	var trailing any
	if decodeErr := decoder.Decode(&trailing); decodeErr == nil {
		return RedhostLabManifest{}, fmt.Errorf("%w: contenu après l'objet", ErrLabManifestContract)
	} else if decodeErr != io.EOF {
		return RedhostLabManifest{}, fmt.Errorf("%w: contenu après l'objet: %w", ErrLabManifestContract, decodeErr)
	}
	if manifest.RunID == "" || manifest.Host == "" || manifest.Interface == "" || manifest.Filter == "" || manifest.Start == "" || manifest.End == "" || manifest.Label == "" {
		return RedhostLabManifest{}, fmt.Errorf("%w: champ obligatoire vide", ErrLabManifestContract)
	}
	start, err := time.Parse(time.RFC3339Nano, manifest.Start)
	if err != nil {
		return RedhostLabManifest{}, fmt.Errorf("%w: start: %w", ErrLabManifestContract, err)
	}
	end, err := time.Parse(time.RFC3339Nano, manifest.End)
	if err != nil {
		return RedhostLabManifest{}, fmt.Errorf("%w: end: %w", ErrLabManifestContract, err)
	}
	if end.Before(start) {
		return RedhostLabManifest{}, fmt.Errorf("%w: end antérieur à start", ErrLabManifestContract)
	}
	return manifest, nil
}
