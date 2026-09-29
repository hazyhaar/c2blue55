// Package engine - thematic_corpora_test.go
package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestThematicCorporarRealDatasets(t *testing.T) {
	// Les jeux de données téléchargés vivent sous .llmcall, zone ignorée par
	// git : HOROS_LLMCALL_DIR s'il est posé, sinon .llmcall sous la racine du
	// dépôt. Le corpus des menaces sans fichier est versionné dans le paquet
	// voisin probes. Une section dont la source manque est omise, comme avant,
	// et l'omission est consignée.
	// Les noms reprennent, relativement à .llmcall, ceux des constantes
	// DefaultCVEExploitationSignalsPath, DefaultCVE5YearsPath,
	// DefaultKernelVulnCSVPath et DefaultCyberNativeDPOPath de
	// thematic_corpora.go.
	llm := testExternalDir(t, "HOROS_LLMCALL_DIR", ".llmcall")
	cvePath := filepath.Join(llm, "call-2492922534", "000-threatcluster__cve-exploitation-signals__data.jsonl")
	cve5Path := filepath.Join(llm, "call-2492922534", "001-sk75__2021_2026_CVE_Exploit_Dataset__cve_dataset_5years.jsonl")
	kernelPath := filepath.Join(llm, "call-1856088084", "001-quguanni__kernel-vuln-dataset__vuln_commits_full.csv")
	dpoPath := filepath.Join(llm, "call-2296473354", "001-CyberNative__Code_Vulnerability_Security_DPO__secure_programming_dpo.json")
	filelessDir := filepath.Join("..", "probes", "testdata")

	// 1. CVE Corpus
	if _, err := os.Stat(cvePath); err != nil {
		t.Logf("corpus CVE absent (%v) : section omise ; poser HOROS_LLMCALL_DIR depuis un worktree lié", err)
	} else {
		cbCVE, err := BuildThematicCVECorpus(cvePath, cve5Path)
		if err != nil {
			t.Fatalf("BuildThematicCVECorpus: %v", err)
		}
		if cbCVE.Len() == 0 {
			t.Fatalf("cbCVE.Len() == 0, attendu > 0")
		}
		t.Logf("CVE Corpus: %d entrees vectorisees", cbCVE.Len())
	}

	// 2. Kernel Vuln Corpus
	if _, err := os.Stat(kernelPath); err != nil {
		t.Logf("corpus des vulnérabilités du noyau absent (%v) : section omise ; poser HOROS_LLMCALL_DIR depuis un worktree lié", err)
	} else {
		cbKernel, err := BuildThematicKernelCorpus(kernelPath)
		if err != nil {
			t.Fatalf("BuildThematicKernelCorpus: %v", err)
		}
		if cbKernel.Len() == 0 {
			t.Fatalf("cbKernel.Len() == 0, attendu > 0")
		}
		t.Logf("Kernel Vuln Corpus: %d entrees vectorisees", cbKernel.Len())
	}

	// 3. CyberNative DPO Corpus
	if _, err := os.Stat(dpoPath); err != nil {
		t.Logf("corpus DPO CyberNative absent (%v) : section omise ; poser HOROS_LLMCALL_DIR depuis un worktree lié", err)
	} else {
		cbDPO, err := BuildThematicDPOCorpus(dpoPath)
		if err != nil {
			t.Fatalf("BuildThematicDPOCorpus: %v", err)
		}
		if cbDPO.Len() == 0 {
			t.Fatalf("cbDPO.Len() == 0, attendu > 0")
		}
		t.Logf("CyberNative DPO Corpus: %d entrees vectorisees", cbDPO.Len())
	}

	// 4. Fileless Memory Threats Corpus
	if _, err := os.Stat(filelessDir); err != nil {
		t.Logf("corpus des menaces sans fichier absent (%v) : section omise", err)
	} else {
		cbMem, err := BuildThematicFilelessCorpus(filelessDir)
		if err != nil {
			t.Fatalf("BuildThematicFilelessCorpus: %v", err)
		}
		if cbMem.Len() == 0 {
			t.Fatalf("cbMem.Len() == 0, attendu > 0")
		}
		t.Logf("Fileless Memory Corpus: %d entrees vectorisees", cbMem.Len())
	}

	// 5. Persistence FIM Corpus
	cbFIM, err := BuildThematicFIMCorpus()
	if err != nil {
		t.Fatalf("BuildThematicFIMCorpus: %v", err)
	}
	if cbFIM.Len() == 0 {
		t.Fatalf("cbFIM.Len() == 0, attendu > 0")
	}
	t.Logf("Persistence FIM Corpus: %d entrees vectorisees", cbFIM.Len())
}

func TestBuildThematicAllCodebooksTmp(t *testing.T) {
	tmpDir := t.TempDir()
	results, err := BuildThematicAllCodebooks(tmpDir)
	if err != nil {
		t.Fatalf("BuildThematicAllCodebooks: %v", err)
	}

	if len(results) != 5 {
		t.Fatalf("len(results) = %d, attendu 5", len(results))
	}

	for _, res := range results {
		if res.EntryCount == 0 {
			t.Fatalf("Corpus %s a 0 entrees", res.Name)
		}
		if res.SizeBytes <= int64(codebookHeaderSize) {
			t.Fatalf("Corpus %s a une taille suspecte: %d o", res.Name, res.SizeBytes)
		}

		// Verifie que le fichier est un codebook valide et rechargeable a chaud
		ac, err := LoadAtomicCodebook(res.Path)
		if err != nil {
			t.Fatalf("LoadAtomicCodebook(%s): %v", res.Path, err)
		}
		if ac.Len() != res.EntryCount {
			t.Fatalf("ac.Len() = %d != res.EntryCount = %d", ac.Len(), res.EntryCount)
		}

		// Test de recherche Hamming 0 B/op
		var query [codebookWords]uint64
		match, dist, found := ac.SearchNearest(&query, 512)
		if !found {
			t.Fatalf("SearchNearest dans %s n'a rien trouve pour seuil 512", res.Name)
		}
		if dist < 0 || dist > 512 {
			t.Fatalf("dist = %d hors bornes 0..512", dist)
		}
		_ = match
	}
}
