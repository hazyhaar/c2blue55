// Package engine — wittgenstein_corpus.go
// Règles de partition et de scellement partagées entre la forgerie des
// disquettes (cmd/c2forge) et le banc d'homologation (wittgenstein_bench_test.go).
// Le forgeur et le banc doivent tirer exactement la même frontière entre
// l'apprentissage et l'évaluation tenue à l'écart : la définir en un seul
// endroit interdit qu'une dérive de l'un réintroduise la fuite d'apprentissage.
package engine

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"os"
	"strings"
)

// ReverseShellTrainPercent est la part des reverse shells réels réservée à la
// forgerie des centroïdes ; le reste n'est vu que par le banc.
const ReverseShellTrainPercent = 70

// Clés HMAC-SHA256 d'épreuve de testabilité pour les disquettes d'évaluation.
// Les valeurs ci-dessous sont des clés de démonstration publiques destinées
// à garantir la reproductibilité des bancs de test chez tout évaluateur.
// En déploiement de production, elles doivent impérativement être surchargées
// via les variables d'environnement (C2BLUE_HMAC_KEY_LOLBAS, C2BLUE_HMAC_KEY_DNS,
// C2BLUE_HMAC_KEY_MCP) ou passées explicitement à SaveFloppyFile / LoadFloppyMmap.
var defaultWittgensteinFloppyKeys = map[uint16]string{
	FloppyFamilyLOLBAS:   "c2blue-hmac-key-lolbas-wittgenstein",
	FloppyFamilyDNSC2:    "c2blue-hmac-key-dns-wittgenstein",
	FloppyFamilyAgentMCP: "c2blue-hmac-key-mcp-wittgenstein",
}

// WittgensteinFloppyKey retourne la clé de sceau HMAC d'une famille,
// en résolvant d'abord l'environnement (C2BLUE_HMAC_KEY_*), puis les clés de test.
func WittgensteinFloppyKey(family uint16) []byte {
	var envVar string
	switch family {
	case FloppyFamilyLOLBAS:
		envVar = "C2BLUE_HMAC_KEY_LOLBAS"
	case FloppyFamilyDNSC2:
		envVar = "C2BLUE_HMAC_KEY_DNS"
	case FloppyFamilyAgentMCP:
		envVar = "C2BLUE_HMAC_KEY_MCP"
	}
	if envVar != "" {
		if k := os.Getenv(envVar); k != "" {
			return []byte(k)
		}
	}
	k, ok := defaultWittgensteinFloppyKeys[family]
	if !ok {
		return nil
	}
	return []byte(k)
}

// LoadReverseShellPayloads lit reverse_shells.jsonl et retourne les charges
// non vides et distinctes des lignes JSON valides, dans l'ordre de leur
// première apparition. Le fichier répète la plupart de ses charges (291 lignes
// valides pour 136 charges distinctes, mesuré le 2026-09-29) : sans ce
// dédoublonnage, 85 des 88 charges de la tranche d'évaluation étaient des
// copies exactes de charges d'apprentissage, et la partition reconduisait la
// fuite qu'elle devait rompre. Les lignes que encoding/json refuse
// (échappements invalides) sont écartées, au forgeur comme au banc.
func LoadReverseShellPayloads(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec struct {
			Payload string `json:"payload"`
		}
		if err := json.Unmarshal(line, &rec); err != nil || rec.Payload == "" || seen[rec.Payload] {
			continue
		}
		seen[rec.Payload] = true
		out = append(out, rec.Payload)
	}
	return out, sc.Err()
}

// ReverseShellTrainCount retourne le nombre de charges d'apprentissage : les
// ReverseShellTrainPercent premiers pour cent des charges distinctes.
func ReverseShellTrainCount(n int) int {
	return n * ReverseShellTrainPercent / 100
}

//go:embed corpus/benign_admin_commands.txt
var benignAdminCorpus string

// BenignAdminCommands retourne le corpus bénin de commandes d'administration
// Linux et Windows, dans l'ordre du fichier (provenance décrite dans l'en-tête
// de corpus/benign_admin_commands.txt).
func BenignAdminCommands() []string {
	var out []string
	for _, line := range strings.Split(benignAdminCorpus, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// IsBenignTrainIndex dit si la commande bénigne d'index i appartient à
// l'apprentissage (i modulo 10 dans 0..6) ou à l'évaluation tenue à l'écart.
func IsBenignTrainIndex(i int) bool {
	return i%10 < 7
}
