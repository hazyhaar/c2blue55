package form

import (
	"fmt"

	"github.com/hazyhaar/c2slm"
	"github.com/hazyhaar/c2slm/engine"
	"github.com/hazyhaar/c2slm/tokenizer"
)

type Case struct {
	Nom     string
	Valeurs []string
	// Libelle, s'il est non nil, remplace le libellé « \n<Nom> : » ingéré avant le
	// choix ; une chaîne vide signifie « aucun libellé » (le préfixe ou le brief
	// se termine déjà par l'amorce du choix, par exemple `{"cause":"`).
	Libelle *string
}

type Formulaire struct {
	Cases []Case
}

type Choix struct {
	Case   string
	Valeur string
	Jeton  int32
	Logits []float32
}

type Compile struct {
	casesCompilees []Case
	jetonsValeurs  [][]int32
	jetonsLibelles [][]int32
	jetonsIngeres  int
}

func (compilation *Compile) Jetons(indiceCase int) []int32 {
	return compilation.jetonsValeurs[indiceCase]
}

func (compilation *Compile) JetonsIngeres() int {
	return compilation.jetonsIngeres
}

// Compiler encodes labels and restricts every admissible answer to one token.
func Compiler(tok *tokenizer.Tokenizer, formulaire Formulaire) (*Compile, error) {
	if tok == nil {
		return nil, fmt.Errorf("tokeniseur absent")
	}
	compilation := &Compile{
		casesCompilees: make([]Case, 0, len(formulaire.Cases)),
		jetonsValeurs:  make([][]int32, 0, len(formulaire.Cases)),
		jetonsLibelles: make([][]int32, 0, len(formulaire.Cases)),
	}
	for _, caseFormulaire := range formulaire.Cases {
		if len(caseFormulaire.Valeurs) == 0 {
			return nil, fmt.Errorf("case %q sans valeur", caseFormulaire.Nom)
		}
		jetonsCase := make([]int32, 0, len(caseFormulaire.Valeurs))
		for _, valeurCase := range caseFormulaire.Valeurs {
			jetonsEncodes := tok.Encode(valeurCase)
			if len(jetonsEncodes) != 1 {
				return nil, fmt.Errorf("case %q : valeur %q exige %d jetons au lieu d'un", caseFormulaire.Nom, valeurCase, len(jetonsEncodes))
			}
			jetonsCase = append(jetonsCase, jetonsEncodes[0])
		}
		texteLibelle := "\n" + caseFormulaire.Nom + " :"
		if caseFormulaire.Libelle != nil {
			texteLibelle = *caseFormulaire.Libelle
		}
		var libelleCase []int32
		if texteLibelle != "" {
			libelleCase = tok.Encode(texteLibelle)
		}
		if len(libelleCase) == 0 && caseFormulaire.Libelle == nil {
			return nil, fmt.Errorf("case %q : libellé vide", caseFormulaire.Nom)
		}
		compilation.casesCompilees = append(compilation.casesCompilees, Case{Nom: caseFormulaire.Nom, Valeurs: append([]string(nil), caseFormulaire.Valeurs...)})
		compilation.jetonsValeurs = append(compilation.jetonsValeurs, jetonsCase)
		compilation.jetonsLibelles = append(compilation.jetonsLibelles, libelleCase)
		compilation.jetonsIngeres += len(libelleCase) + 1
	}
	return compilation, nil
}

// Remplir projects the final label token onto the compiled answer tokens.
func Remplir(eng *c2slm.Engine, compilation *Compile, prefixe, brief []int32) ([]Choix, error) {
	if eng == nil || eng.KVCache == nil || eng.Arena == nil || eng.Model == nil || compilation == nil {
		return nil, fmt.Errorf("moteur ou formulaire absent")
	}
	eng.KVCache.Reset()
	if err := eng.Ingest(prefixe); err != nil {
		return nil, fmt.Errorf("préfixe : %w", err)
	}
	return RemplirDepuis(eng, compilation, len(prefixe), brief)
}

// RemplirDepuis suppose le préfixe déjà présent dans le cache KV jusqu'à la
// position longueurPrefixe (calculé une fois, ou rechargé par kvfile) : il
// rembobine le cache à cette position, ingère le brief puis remplit les cases.
func RemplirDepuis(eng *c2slm.Engine, compilation *Compile, longueurPrefixe int, brief []int32) ([]Choix, error) {
	if eng == nil || eng.KVCache == nil || eng.Arena == nil || eng.Model == nil || compilation == nil {
		return nil, fmt.Errorf("moteur ou formulaire absent")
	}
	if longueurPrefixe < 0 || longueurPrefixe > eng.KVCache.SeqLen {
		return nil, fmt.Errorf("préfixe de %d jetons absent du cache (SeqLen %d)", longueurPrefixe, eng.KVCache.SeqLen)
	}
	eng.KVCache.Rewind(eng.KVCache.SeqLen - longueurPrefixe)
	if err := eng.Ingest(brief); err != nil {
		return nil, fmt.Errorf("brief : %w", err)
	}
	choixFormulaire := make([]Choix, 0, len(compilation.casesCompilees))
	for indiceCase, caseFormulaire := range compilation.casesCompilees {
		libelleCase := compilation.jetonsLibelles[indiceCase]
		nbDerniere := len(brief)
		if len(libelleCase) > 0 {
			if err := eng.Ingest(libelleCase); err != nil {
				return nil, fmt.Errorf("libellé %q : %w", caseFormulaire.Nom, err)
			}
			nbDerniere = len(libelleCase)
		} else if indiceCase > 0 {
			nbDerniere = 1 // la dernière ingestion est le jeton choisi de la case précédente
		}
		if nbDerniere == 0 {
			return nil, fmt.Errorf("case %q : aucun jeton ingéré avant le choix", caseFormulaire.Nom)
		}
		// ForwardTile leaves the normalized last row in the preallocated tile.
		indiceLigne := (nbDerniere - 1) % engine.PrefillTile
		dimensionCachee := eng.Model.EmbdLength
		etatNormalise := eng.Arena.Tile.NormX[indiceLigne*dimensionCachee : (indiceLigne+1)*dimensionCachee]
		jetonsCase := compilation.jetonsValeurs[indiceCase]
		engine.ComputeLogits(eng.Model, eng.Arena, etatNormalise, eng.Arena.Logits, jetonsCase)
		logitsCase := make([]float32, len(jetonsCase))
		indiceChoisi := 0
		for indiceValeur, jetonValeur := range jetonsCase {
			logitsCase[indiceValeur] = eng.Arena.Logits[jetonValeur]
			if logitsCase[indiceValeur] > logitsCase[indiceChoisi] {
				indiceChoisi = indiceValeur
			}
		}
		jetonChoisi := jetonsCase[indiceChoisi]
		choixFormulaire = append(choixFormulaire, Choix{Case: caseFormulaire.Nom, Valeur: caseFormulaire.Valeurs[indiceChoisi], Jeton: jetonChoisi, Logits: logitsCase})
		var jetonUnique [1]int32
		jetonUnique[0] = jetonChoisi
		if err := eng.Ingest(jetonUnique[:]); err != nil {
			return nil, fmt.Errorf("choix %q : %w", caseFormulaire.Nom, err)
		}
	}
	return choixFormulaire, nil
}
