package engine

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"path/filepath"
	"testing"
)

func TestDNSLeakFix(t *testing.T) {
	t.Run("SH-S12-01", func(t *testing.T) {
		benign := []string{
			"hazyhaar.fr", "api.hazyhaar.fr", "mail.hazyhaar.fr", "cdn.hazyhaar.fr",
			"git.hazyhaar.fr", "docs.hazyhaar.fr", "auth.hazyhaar.fr", "ns1.hazyhaar.fr",
			"ns2.hazyhaar.fr", "blog.hazyhaar.fr", "dev.hazyhaar.fr", "portal.hazyhaar.fr",
			"static.hazyhaar.fr", "media.hazyhaar.fr", "img.hazyhaar.fr", "support.hazyhaar.fr",
			"forum.hazyhaar.fr", "news.hazyhaar.fr", "app.hazyhaar.fr", "login.hazyhaar.fr",
			"secure.hazyhaar.fr", "smtp.hazyhaar.fr", "imap.hazyhaar.fr", "vpn.hazyhaar.fr",
			"status.hazyhaar.fr",
		}
		if len(benign) != 25 {
			t.Fatalf("famille bénigne : %d noms, attendu 25", len(benign))
		}

		var dst [EmbeddingDim]float32
		for _, name := range benign {
			if _, _, _, _, _, _, _, ok := splitDNSNameBytes([]byte(name)); !ok {
				t.Fatalf("splitDNSNameBytes(%q) : ok=false", name)
			}
			if !ExtractDNSDGA512([]byte("hazyhaar"), []byte("fr"), dst[:]) {
				t.Fatalf("ExtractDNSDGA512(%q) : ok=false", name)
			}
			if s := dst[aggregateBase+27]; s >= 0 {
				t.Errorf("%q : score DGA composite = %.4f, attendu < 0", name, s)
			}
		}

		if !ExtractDNSDGA512([]byte("xqzjkvwrp8492"), []byte("biz"), dst[:]) {
			t.Fatal("ExtractDNSDGA512(DGA) : ok=false")
		}
		if s := dst[aggregateBase+27]; s <= 0.35 {
			t.Errorf("DGA xqzjkvwrp8492.biz : score composite = %.4f, attendu > 0.35", s)
		}
	})

	t.Run("SH-S12-02", func(t *testing.T) {
		// 1. Garde-fou structurel AST sur BuildDNSFloppiesColdSplit et EvaluateDNSColdSplit :
		// tous les appels à ExtractDNSTunnel512 dans ces deux fonctions doivent recevoir
		// exactement la même expression qtype (coldSplitNeutralQType) et la même variable
		// de cardinalité (card), sans littéral 16 ni plancher max(..., 32) conditionné par le label.
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "dns_agent.go", nil, 0)
		if err != nil {
			t.Fatalf("parser.ParseFile(dns_agent.go) : %v", err)
		}

		exprStr := func(e ast.Expr) string {
			var buf bytes.Buffer
			_ = printer.Fprint(&buf, fset, e)
			return buf.String()
		}

		type callSig struct {
			fnName  string
			qtype   string
			card    string
			lineNum int
		}
		var calls []callSig

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil {
				continue
			}
			name := fn.Name.Name
			if name != "BuildDNSFloppiesColdSplit" && name != "EvaluateDNSColdSplit" {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				ident, ok := call.Fun.(*ast.Ident)
				if !ok || ident.Name != "ExtractDNSTunnel512" {
					return true
				}
				if len(call.Args) != 6 {
					t.Errorf("%s:%d : ExtractDNSTunnel512 a %d arguments, attendu 6", name, fset.Position(call.Pos()).Line, len(call.Args))
					return true
				}
				qArg := exprStr(call.Args[1])
				cArg := exprStr(call.Args[4])
				line := fset.Position(call.Pos()).Line
				if qArg == "16" || qArg == "10" || qArg == "255" {
					t.Errorf("%s:%d : fuite F-10/F-04 sur qtype positionnel (%s) dans ExtractDNSTunnel512", name, line, qArg)
				}
				if cArg != "card" {
					t.Errorf("%s:%d : asymétrie train/eval sur la cardinalité (%s != card) dans ExtractDNSTunnel512", name, line, cArg)
				}
				calls = append(calls, callSig{
					fnName:  name,
					qtype:   qArg,
					card:    cArg,
					lineNum: line,
				})
				return true
			})
		}

		if len(calls) != 4 {
			t.Fatalf("attendu exactement 4 appels à ExtractDNSTunnel512 dans BuildDNSFloppiesColdSplit (3) + EvaluateDNSColdSplit (1), trouvé %d", len(calls))
		}
		for idx, c := range calls[:3] {
			if c.qtype != "coldSplitNeutralQType" {
				t.Errorf("décalage qtype dans BuildDNSFloppiesColdSplit (appel #%d l.%d) : qtype=%q, attendu coldSplitNeutralQType",
					idx+1, c.lineNum, c.qtype)
			}
		}

		// 2. Garde-fou comportemental sur les prototypes forgés dans floppy_dns_tunnel.c2book :
		// la coordonnée isTunnelQType (aggregateBase+22) doit être strictement identique (-0.65)
		// pour tous les prototypes bénins (Class 0) et hostiles (Class 1), prouvant l'absence
		// totale de décalage train/eval ou de fuite F-10 sur le QType.
		dataDir := testWittgensteinDataDir(t)
		outDir := t.TempDir()
		hmacKey := WittgensteinFloppyKey(FloppyFamilyDNSC2)
		if err := BuildDNSFloppiesColdSplit(dataDir, outDir, hmacKey); err != nil {
			t.Fatalf("BuildDNSFloppiesColdSplit : %v", err)
		}
		tunnelDisk, err := LoadFloppyMmap(filepath.Join(outDir, "floppy_dns_tunnel.c2book"), hmacKey)
		if err != nil {
			t.Fatalf("LoadFloppyMmap : %v", err)
		}
		defer tunnelDisk.Close()

		if len(tunnelDisk.Prototypes) == 0 {
			t.Fatal("aucun prototype dans floppy_dns_tunnel.c2book")
		}
		wantQTypeNorm := float32(coldSplitNeutralQType) / 255.0
		for i, proto := range tunnelDisk.Prototypes {
			gotQTypeNorm := proto.Vector[headerBase+0]
			gotIsTunnelQType := proto.Vector[headerBase+1]
			if gotQTypeNorm != wantQTypeNorm || gotIsTunnelQType != -0.65 {
				t.Errorf("prototype[%d] (Class=%d) : qtypeNorm=%.6f (attendu %.6f), isTunnelQType=%.2f (attendu -0.65)",
					i, proto.Class, gotQTypeNorm, wantQTypeNorm, gotIsTunnelQType)
			}
		}
		// Preuve sur la tête de décision INT8 : le poids appris sur headerBase+0 (qtype)
		// et headerBase+1 (isTunnelQType) doit être strictement nul (0) puisque bénin et
		// hostile ont la même moyenne sur ces deux coordonnées.
		for clsIdx, head := range tunnelDisk.Head {
			if head.Weights[headerBase+0] != 0 || head.Weights[headerBase+1] != 0 {
				t.Errorf("Head[%d] a appris un poids non nul sur QType (w[headerBase+0]=%d, w[headerBase+1]=%d), attendu 0",
					clsIdx, head.Weights[headerBase+0], head.Weights[headerBase+1])
			}
		}
	})
}
