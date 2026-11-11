package c2blue55

import (
	"os"
	"strings"
	"testing"
)

type ld83Doc struct {
	file       string
	title      string
	forwardEnd string
}

var ld83Docs = []ld83Doc{
	{"README.md", "## 4e. Post-Audit Closed Lists & Header-Independent Vectors (2026-11-11, v8.3)", "are forwarded without inspection."},
	{"README.fr.md", "## 4e. Listes Fermées Post-Audit & Vecteur Indépendant de l'En-Tête (2026-11-11, v8.3)", "sont transmises sans inspection."},
}

func ld83Read(t *testing.T, name string) []string {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("lecture de %s: %v", name, err)
	}
	return strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
}

// LD83-01 : titre de section, jetons entre accents graves, arborescence.
func TestLD83_01_SectionVersionEtArborescence(t *testing.T) {
	for _, d := range ld83Docs {
		t.Run(d.file, func(t *testing.T) {
			lines := ld83Read(t, d.file)
			titleFound := false
			for _, l := range lines {
				if strings.TrimRight(l, " \t") == d.title {
					titleFound = true
					break
				}
			}
			if !titleFound {
				t.Errorf("%s: titre %q absent en ligne seule", d.file, d.title)
			}
			body := strings.Join(lines, "\n")
			for _, tok := range []string{"v8.3", "-32601", "-32600", "tools/list", "ServiceLive"} {
				if !strings.Contains(body, "`"+tok+"`") {
					t.Errorf("%s: jeton `%s` absent entre accents graves", d.file, tok)
				}
			}
			for _, dir := range []string{"c2blue-dns-live/", "dnslive/", "enveloppedepot/"} {
				found := false
				for _, l := range lines {
					s := strings.TrimLeft(l, "│ \t")
					if strings.HasPrefix(s, "├── "+dir) || strings.HasPrefix(s, "└── "+dir) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("%s: entrée d'arborescence %q absente", d.file, dir)
				}
			}
		})
	}
}

// LD83-02 : la phrase « transmises sans inspection » existe et exclut les méthodes inspectées.
func TestLD83_02_PhraseTransmisesSansInspection(t *testing.T) {
	forbidden := []string{"resources/read", "prompts/get", "completion/complete", "sampling/createMessage", "tools/call"}
	for _, d := range ld83Docs {
		t.Run(d.file, func(t *testing.T) {
			var sentence string
			found := false
			for _, l := range ld83Read(t, d.file) {
				if i := strings.Index(l, d.forwardEnd); i >= 0 {
					sentence = l[:i+len(d.forwardEnd)]
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("%s: phrase se terminant par %q absente", d.file, d.forwardEnd)
			}
			for _, m := range forbidden {
				if strings.Contains(sentence, m) {
					t.Errorf("%s: la phrase %q contient la méthode inspectée %q", d.file, sentence, m)
				}
			}
		})
	}
}
