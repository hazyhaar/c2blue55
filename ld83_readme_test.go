package c2blue55

import (
	_ "embed"
	"os"
	"regexp"
	"strings"
	"testing"
)

//go:embed README.md
var ld83ReadmeEN string

//go:embed README.fr.md
var ld83ReadmeFR string

//go:embed CHANGELOG.md
var ld83Changelog string

const (
	ld83TitleEN = "## 4e. Post-Audit Closed Lists & Header-Independent Vectors (2026-11-11, v8.3)"
	ld83TitleFR = "## 4e. Listes Fermées Post-Audit & Vecteur Indépendant de l'En-Tête (2026-11-11, v8.3)"
)

func ld83Lire(t *testing.T, nom string) string {
	t.Helper()
	b, err := os.ReadFile(nom)
	if err != nil {
		t.Fatalf("lecture de %s: %v", nom, err)
	}
	return string(b)
}

func ld83LigneExacte(texte, ligne string) bool {
	for _, l := range strings.Split(texte, "\n") {
		if strings.TrimRight(l, "\r") == ligne {
			return true
		}
	}
	return false
}

// ld83Phrase renvoie la phrase prise depuis le début de sa ligne jusqu'à la fin marquée.
func ld83Phrase(texte, fin string) (string, bool) {
	for _, l := range strings.Split(texte, "\n") {
		if i := strings.Index(l, fin); i >= 0 {
			return l[:i+len(fin)], true
		}
	}
	return "", false
}

func ld83Interdites(texte string, chaines []string) []string {
	var trouvees []string
	for _, c := range chaines {
		if strings.Contains(texte, c) {
			trouvees = append(trouvees, c)
		}
	}
	return trouvees
}

func TestLD83_01ReadmesPortentSection4e(t *testing.T) {
	cas := []struct {
		fichier, titre string
	}{
		{"README.md", ld83TitleEN},
		{"README.fr.md", ld83TitleFR},
	}
	jetons := []string{"`v8.3`", "`-32601`", "`-32600`", "`tools/list`", "`ServiceLive`"}
	arbo := []string{"c2blue-dns-live/", "dnslive/", "enveloppedepot/"}
	for _, c := range cas {
		txt := ld83Lire(t, c.fichier)
		if !ld83LigneExacte(txt, c.titre) {
			t.Errorf("%s: titre absent sur une ligne à lui seul: %q", c.fichier, c.titre)
		}
		for _, j := range jetons {
			if !strings.Contains(txt, j) {
				t.Errorf("%s: jeton absent: %s", c.fichier, j)
			}
		}
		for _, a := range arbo {
			re := regexp.MustCompile(`(?m)^[│├└─ \t]*` + regexp.QuoteMeta(a))
			if !re.MatchString(txt) {
				t.Errorf("%s: entrée d'arborescence absente: %s", c.fichier, a)
			}
		}
	}
}

func TestLD83_02PhraseListeFermeeSansMethodesRefusees(t *testing.T) {
	cas := []struct{ fichier, fin string }{
		{"README.md", "are forwarded without inspection."},
		{"README.fr.md", "sont transmises sans inspection."},
	}
	methodes := []string{"resources/read", "prompts/get", "completion/complete", "sampling/createMessage", "tools/call"}
	for _, c := range cas {
		phrase, ok := ld83Phrase(ld83Lire(t, c.fichier), c.fin)
		if !ok {
			t.Errorf("%s: phrase se terminant par %q introuvable", c.fichier, c.fin)
			continue
		}
		if m := ld83Interdites(phrase, methodes); len(m) > 0 {
			t.Errorf("%s: la phrase contient des méthodes refusées %v: %q", c.fichier, m, phrase)
		}
	}
	// témoins
	if _, ok := ld83Phrase("rien ici", "are forwarded without inspection."); ok {
		t.Error("témoin: phrase absente détectée à tort")
	}
	ph, _ := ld83Phrase("only tools/call are forwarded without inspection.", "are forwarded without inspection.")
	if m := ld83Interdites(ph, methodes); len(m) != 1 {
		t.Errorf("témoin: détection attendue de tools/call, obtenu %v", m)
	}
}

func TestLD83_03ChangelogPremiereSection(t *testing.T) {
	txt := ld83Lire(t, "CHANGELOG.md")
	for _, l := range strings.Split(txt, "\n") {
		if strings.HasPrefix(l, "## ") {
			if !strings.HasPrefix(l, "## 8.3.0 ") {
				t.Fatalf("première ligne « ## » inattendue: %q", l)
			}
			return
		}
	}
	t.Fatal("aucune ligne commençant par « ## » dans CHANGELOG.md")
}

func TestLD83_04ChainesDementiesAbsentes(t *testing.T) {
	interdites := []string{
		"hence the same verdict", "donc le même verdict",
		"counted in exactly one outcome", "une issue et une seule",
		"source address are no longer projected", "l'adresse source ne sont plus",
	}
	for _, f := range []string{"README.md", "README.fr.md", "CHANGELOG.md"} {
		if m := ld83Interdites(ld83Lire(t, f), interdites); len(m) > 0 {
			t.Errorf("%s: chaînes démenties présentes: %v", f, m)
		}
	}
	temoin := "so it is, hence the same verdict."
	if m := ld83Interdites(temoin, interdites); len(m) != 1 || m[0] != "hence the same verdict" {
		t.Errorf("témoin non signalé: %v", m)
	}
}

func TestLD83_05DocumentsEmbarques(t *testing.T) {
	docs := map[string]string{
		"README.md":    ld83ReadmeEN,
		"README.fr.md": ld83ReadmeFR,
		"CHANGELOG.md": ld83Changelog,
	}
	for nom, d := range docs {
		if d == "" {
			t.Errorf("%s: copie embarquée vide", nom)
		} else if !strings.HasPrefix(d, "# ") {
			t.Errorf("%s: ne commence pas par un titre de niveau 1", nom)
		}
	}
	src := ld83Lire(t, "ld83_readme_test.go")
	for _, nom := range []string{"README.md", "README.fr.md", "CHANGELOG.md"} {
		if !strings.Contains(src, "//go:embed "+nom+"\n") {
			t.Errorf("directive //go:embed %s absente", nom)
		}
	}
}

func TestLD83_06AffirmationsAlignees(t *testing.T) {
	en, fr, cl := ld83Lire(t, "README.md"), ld83Lire(t, "README.fr.md"), ld83Lire(t, "CHANGELOG.md")
	requis := []struct{ nom, txt, chaine string }{
		{"README.md", en, "a memory segment address"},
		{"CHANGELOG.md", cl, "a memory segment address"},
		{"README.fr.md", fr, "une adresse de segment mémoire"},
	}
	for _, r := range requis {
		if !strings.Contains(r.txt, r.chaine) {
			t.Errorf("%s: chaîne absente: %q", r.nom, r.chaine)
		}
	}
	if strings.Contains(en, "four timing-sensitive tests") {
		t.Error("README.md: affirmation démentie « four timing-sensitive tests »")
	}
	if strings.Contains(fr, "quatre tests sensibles au temps") {
		t.Error("README.fr.md: affirmation démentie « quatre tests sensibles au temps »")
	}
}

func TestLD83_07JetonsEtComptesAlignes(t *testing.T) {
	en, fr, cl := ld83Lire(t, "README.md"), ld83Lire(t, "README.fr.md"), ld83Lire(t, "CHANGELOG.md")
	jetons := []string{"`hdrFlagPopcount`", "`FlagLongPayload`", "`ComputeEpisodeP3TimingFeatures`", "`C2BLUE_DASHBOARD_TOKEN`"}
	for _, d := range []struct{ nom, txt string }{{"README.md", en}, {"README.fr.md", fr}, {"CHANGELOG.md", cl}} {
		for _, j := range jetons {
			if !strings.Contains(d.txt, j) {
				t.Errorf("%s: jeton absent: %s", d.nom, j)
			}
		}
	}
	interdites := []struct{ nom, txt, chaine string }{
		{"README.md", en, "it changes four behaviours"},
		{"README.fr.md", fr, "elle change quatre comportements"},
		{"CHANGELOG.md", cl, "four behaviour changes"},
	}
	for _, i := range interdites {
		if strings.Contains(i.txt, i.chaine) {
			t.Errorf("%s: affirmation démentie présente: %q", i.nom, i.chaine)
		}
	}
	// témoin : la recherche signale bien une chaîne présente
	if m := ld83Interdites("it changes four behaviours", []string{"it changes four behaviours"}); len(m) != 1 {
		t.Errorf("témoin non signalé: %v", m)
	}
}
