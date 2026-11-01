package dnslab_test

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55"
	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

func replayNames(t *testing.T) []string {
	t.Helper()
	suffix := "." + zoneApex
	var names []string
	for _, name := range zoneNames(t) {
		if strings.HasSuffix(name, suffix) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		t.Fatal("aucun sous-domaine réel sous la zone de laboratoire")
	}
	return names
}

func validReplay(t *testing.T) dnslab.Campaign {
	t.Helper()
	return dnslab.Campaign{
		RunID:    "s05-replay-valide",
		Family:   "redhost-replay",
		Tool:     "replay",
		Server:   "10.55.0.1",
		Zone:     zoneApex,
		Duration: 2 * time.Second,
		MaxQPS:   10,
		Names:    replayNames(t),
	}
}

func sourceDir() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Dir(file)
}

func canaryPassword(t *testing.T) (string, bool) {
	t.Helper()
	entries, err := os.ReadDir(sourceDir())
	if err != nil {
		t.Fatalf("lecture du repertoire source: %v", err)
	}
	fileSet := token.NewFileSet()
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(fileSet, filepath.Join(sourceDir(), entry.Name()), nil, 0)
		if err != nil {
			continue
		}
		for _, decl := range parsed.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range value.Names {
					if ident.Name != "CanaryPassword" || i >= len(value.Values) {
						continue
					}
					lit, ok := value.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					text, err := strconv.Unquote(lit.Value)
					if err != nil {
						continue
					}
					return text, true
				}
			}
		}
	}
	return "", false
}

func listenLocal(t *testing.T) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("écoute locale: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func catchDatagrams(t *testing.T, recv net.PacketConn) func() [][]byte {
	t.Helper()
	done := make(chan struct{})
	var datagrams [][]byte
	go func() {
		defer close(done)
		scratch := make([]byte, 1500)
		for {
			n, _, err := recv.ReadFrom(scratch)
			if n > 0 {
				datagrams = append(datagrams, append([]byte(nil), scratch[:n]...))
			}
			if err != nil {
				return
			}
		}
	}()
	return func() [][]byte {
		t.Helper()
		_ = recv.Close()
		<-done
		return datagrams
	}
}

func steppedNow(origin time.Time, step time.Duration) func() time.Time {
	seq := 0
	return func() time.Time {
		instant := origin.Add(time.Duration(seq) * step)
		seq++
		return instant
	}
}

func replayOnce(t *testing.T, campaign dnslab.Campaign, now func() time.Time) dnslab.CampaignReport {
	t.Helper()
	recv := listenLocal(t)
	sender := listenLocal(t)
	ctx, cancel := context.WithTimeout(context.Background(), campaign.Duration+2*time.Second)
	defer cancel()
	report, err := dnslab.RunReplay(ctx, sender, recv.LocalAddr(), &campaign, now)
	if err != nil {
		t.Fatalf("RunReplay: %v", err)
	}
	return report
}

func TestCampaign_Validate_Refusals(t *testing.T) {
	base := validReplay(t)
	foreign := append(append([]string(nil), base.Names...), "hazyhaar.fr")
	cases := []struct {
		name string
		edit func(*dnslab.Campaign)
	}{
		{"server_8_8_8_8", func(c *dnslab.Campaign) { c.Server = "8.8.8.8" }},
		{"server_10_56_0_1", func(c *dnslab.Campaign) { c.Server = "10.56.0.1" }},
		{"server_203_0_113_129", func(c *dnslab.Campaign) { c.Server = "203.0.113.129" }},
		{"server_nom", func(c *dnslab.Campaign) { c.Server = "redhost" }},
		{"maxqps_0", func(c *dnslab.Campaign) { c.MaxQPS = 0 }},
		{"maxqps_51", func(c *dnslab.Campaign) { c.MaxQPS = 51 }},
		{"duration_0", func(c *dnslab.Campaign) { c.Duration = 0 }},
		{"duration_2h", func(c *dnslab.Campaign) { c.Duration = 2 * time.Hour }},
		{"family_autre", func(c *dnslab.Campaign) { c.Family = "autre" }},
		{"tool_nc", func(c *dnslab.Campaign) { c.Tool = "nc" }},
		{"runid_vide", func(c *dnslab.Campaign) { c.RunID = "" }},
		{"runid_slash", func(c *dnslab.Campaign) { c.RunID = "a/b" }},
		{"names_hors_zone", func(c *dnslab.Campaign) { c.Names = foreign }},
		{"names_vides", func(c *dnslab.Campaign) { c.Names = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			campaign := base
			tc.edit(&campaign)
			err := campaign.Validate()
			if !errors.Is(err, dnslab.ErrCampaignContract) {
				t.Fatalf("err=%v, attendu ErrCampaignContract", err)
			}
		})
	}
	t.Run("campagne_valide", func(t *testing.T) {
		err := base.Validate()
		if err != nil {
			t.Fatalf("campagne valide refusée: %v", err)
		}
	})
}

func TestRunReplay_RateAndZoneBounds(t *testing.T) {
	campaign := validReplay(t)
	allowed := make(map[string]struct{}, len(campaign.Names))
	for _, name := range campaign.Names {
		allowed[name] = struct{}{}
	}
	suffix := "." + zoneApex

	t.Run("horloge_reelle", func(t *testing.T) {
		recv := listenLocal(t)
		sender := listenLocal(t)
		stop := catchDatagrams(t, recv)
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		report, err := dnslab.RunReplay(ctx, sender, recv.LocalAddr(), &campaign, time.Now)
		datagrams := stop()
		if err != nil {
			t.Fatalf("RunReplay: %v", err)
		}
		if report.Sent < 15 || report.Sent > 21 || report.Dropped != 0 {
			t.Fatalf("Sent=%d Dropped=%d, attendu Sent entre 15 et 21 et Dropped égal à 0", report.Sent, report.Dropped)
		}
		if uint32(len(datagrams)) != report.Sent {
			t.Fatalf("%d datagrammes reçus, Sent=%d", len(datagrams), report.Sent)
		}
		if !report.Start.Before(report.End) {
			t.Fatalf("Start=%s End=%s, Start doit précéder End", report.Start.Format(time.RFC3339Nano), report.End.Format(time.RFC3339Nano))
		}
		span := report.End.Sub(report.Start)
		if span < 1900*time.Millisecond || span > 2500*time.Millisecond {
			t.Fatalf("End-Start=%s, attendu entre 1,9 s et 2,5 s", span)
		}
		for i, datagram := range datagrams {
			var ev c2blue55.DNSEvent
			if err := c2blue55.ParseDNSQuery(datagram, &ev); err != nil {
				t.Fatalf("datagramme %d illisible: %v", i, err)
			}
			fqdn := ev.FQDN()
			if !strings.HasSuffix(fqdn, suffix) {
				t.Fatalf("datagramme %d: %s ne se termine pas par %s", i, fqdn, suffix)
			}
			if _, ok := allowed[fqdn]; !ok {
				t.Fatalf("datagramme %d: %s n'appartient pas à Names", i, fqdn)
			}
		}
	})

	t.Run("horloge_injectee", func(t *testing.T) {
		origin := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
		first := replayOnce(t, campaign, steppedNow(origin, 100*time.Millisecond))
		second := replayOnce(t, campaign, steppedNow(origin, 100*time.Millisecond))
		if first.Sent != 20 || first.Dropped != 0 || second.Sent != first.Sent || second.Dropped != 0 {
			t.Fatalf("horloge pas à pas de 100 ms, 10 q/s, 2 s: Sent=%d puis %d, Dropped=%d puis %d, attendu 20 envois identiques et Dropped égal à 0", first.Sent, second.Sent, first.Dropped, second.Dropped)
		}
	})

	t.Run("cadence_50", func(t *testing.T) {
		fast := campaign
		fast.RunID = "s05-replay-50"
		fast.MaxQPS = 50
		fast.Duration = time.Second
		origin := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
		report := replayOnce(t, fast, steppedNow(origin, 20*time.Millisecond))
		if report.Sent != 50 || report.Dropped != 0 {
			t.Fatalf("MaxQPS=50 sur 1 s, pas de 20 ms: Sent=%d Dropped=%d, attendu 50 et 0", report.Sent, report.Dropped)
		}
	})
}

func iodineCampaign(runID string, duration time.Duration) dnslab.Campaign {
	return dnslab.Campaign{
		RunID:    runID,
		Family:   "redhost-iodine",
		Tool:     "iodine",
		Server:   "10.55.0.1",
		Zone:     zoneApex,
		Duration: duration,
		MaxQPS:   10,
	}
}

func TestRunTool_FakeLauncherArgsAndTimeout(t *testing.T) {
	t.Run("iodine", func(t *testing.T) {
		password, ok := canaryPassword(t)
		if !ok {
			t.Fatal("constante dnslab.CanaryPassword absente du contrat")
		}
		var gotName string
		var gotArgs []string
		launch := func(ctx context.Context, name string, args ...string) (int, error) {
			gotName = name
			gotArgs = append([]string(nil), args...)
			<-ctx.Done()
			return 23, nil
		}
		campaign := iodineCampaign("s05-iodine-args", time.Second)
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		report, err := dnslab.RunTool(ctx, &campaign, launch)
		if err != nil {
			t.Fatalf("RunTool iodine: %v", err)
		}
		wantArgs := []string{"-f", "-r", "-T", "NULL", "-P", password, "10.55.0.1", zoneApex}
		if gotName != "iodine" || !slices.Equal(gotArgs, wantArgs) {
			t.Fatalf("name=%q args=%q, attendu iodine %q", gotName, gotArgs, wantArgs)
		}
		if report.ExitCode != 23 {
			t.Fatalf("ExitCode=%d, attendu 23 relayé par le lanceur", report.ExitCode)
		}
		span := report.End.Sub(report.Start)
		if span < time.Second || span >= 3*time.Second {
			t.Fatalf("End-Start=%s, attendu au moins 1 s et inférieur à 3 s", span)
		}
	})

	t.Run("dns2tcp", func(t *testing.T) {
		var gotName string
		var gotArgs []string
		launch := func(ctx context.Context, name string, args ...string) (int, error) {
			gotName = name
			gotArgs = append([]string(nil), args...)
			<-ctx.Done()
			return 0, nil
		}
		campaign := iodineCampaign("s05-dns2tcp-args", time.Second)
		campaign.Family = "redhost-dns2tcp"
		campaign.Tool = "dns2tcp"
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		_, err := dnslab.RunTool(ctx, &campaign, launch)
		if err != nil {
			t.Fatalf("RunTool dns2tcp: %v", err)
		}
		wantArgs := []string{"-z", zoneApex, "-r", "canari", "10.55.0.1"} // ordre mesuré le 2026-10-27 : dns2tcpc 0.5.2 (getopt POSIX) refuse un serveur positionnel avant -r
		if gotName != "dns2tcpc" || !slices.Equal(gotArgs, wantArgs) {
			t.Fatalf("name=%q args=%q, attendu dns2tcpc %q", gotName, gotArgs, wantArgs)
		}
	})
}

func TestRunTool_LaunchFailureIsError(t *testing.T) {
	errAbsent := errors.New("absent")
	launch := func(ctx context.Context, name string, args ...string) (int, error) {
		return -1, errAbsent
	}
	campaign := iodineCampaign("s05-outil-absent", time.Second)
	report, err := dnslab.RunTool(context.Background(), &campaign, launch)
	if err == nil || report.Errors != 1 || report.ExitCode != -1 {
		t.Fatalf("err=%v Errors=%d ExitCode=%d, attendu une erreur, Errors égal à 1 et ExitCode égal à -1", err, report.Errors, report.ExitCode)
	}
}

func TestWriteRunManifest_AtomicAndLoadable(t *testing.T) {
	campaign := validReplay(t)
	campaign.RunID = "s05-manifest-atomique"
	start := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	end := start.Add(2 * time.Second)
	report := dnslab.CampaignReport{
		RunID:    campaign.RunID,
		Start:    start,
		End:      end,
		Sent:     20,
		Dropped:  0,
		Tool:     campaign.Tool,
		ExitCode: 0,
	}
	dir := t.TempDir()
	written, err := dnslab.WriteRunManifest(dir, &campaign, report, "redbo")
	if err != nil {
		t.Fatalf("WriteRunManifest: %v", err)
	}
	wantName := campaign.RunID + ".manifest.json"
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatalf("lecture du répertoire: %v", readErr)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	if len(names) != 1 || names[0] != wantName {
		t.Fatalf("fichiers=%v chemin rendu=%q, attendu uniquement %s et aucun temporaire résiduel", names, written, wantName)
	}
	stat, statErr := os.Stat(filepath.Join(dir, wantName))
	if statErr != nil {
		t.Fatalf("stat: %v", statErr)
	}
	if stat.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o, attendu 0600", stat.Mode().Perm())
	}
	manifest, loadErr := c2blue55.LoadRedhostLabManifest(filepath.Join(dir, wantName))
	if loadErr != nil {
		t.Fatalf("LoadRedhostLabManifest: %v", loadErr)
	}
	if manifest.RunID != campaign.RunID || manifest.Label != campaign.Family || manifest.Family != campaign.Family || manifest.Tool != campaign.Tool || manifest.Emitter != "c2dnslab-emit" || manifest.Server != campaign.Server || manifest.Resolver != campaign.Server || manifest.Interface != "wg0" || manifest.Host != "redbo" {
		t.Fatalf("manifeste RunID=%q Label=%q Family=%q Tool=%q Emitter=%q Server=%q Resolver=%q Interface=%q Host=%q", manifest.RunID, manifest.Label, manifest.Family, manifest.Tool, manifest.Emitter, manifest.Server, manifest.Resolver, manifest.Interface, manifest.Host)
	}
	if len(manifest.QueriedDomains) != 1 || manifest.QueriedDomains[0] != campaign.Zone {
		t.Fatalf("queried_domains=%v, attendu [%s]", manifest.QueriedDomains, campaign.Zone)
	}
	gotStart, startErr := time.Parse(time.RFC3339Nano, manifest.Start)
	gotEnd, endErr := time.Parse(time.RFC3339Nano, manifest.End)
	if startErr != nil || endErr != nil || !gotStart.Equal(report.Start) || !gotEnd.Equal(report.End) {
		t.Fatalf("start=%q end=%q, attendu les instants RFC 3339 du rapport (%s, %s)", manifest.Start, manifest.End, report.Start.Format(time.RFC3339Nano), report.End.Format(time.RFC3339Nano))
	}
}
