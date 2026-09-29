package c2blue55

import (
	"strings"
	"testing"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

// fixNow fige l'instant de référence de l'inférence d'année syslog BSD.
func fixNow(t *testing.T, at time.Time) {
	t.Helper()
	prev := nowFunc
	nowFunc = func() time.Time { return at }
	t.Cleanup(func() { nowFunc = prev })
}

func TestParseTimestamp_Formats(t *testing.T) {
	fixNow(t, time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC))
	utc := func(y int, mo time.Month, d, h, mi, s int) uint64 {
		return uint64(time.Date(y, mo, d, h, mi, s, 0, time.UTC).Unix())
	}
	for _, tc := range []struct {
		line string
		want uint64
		rest string
	}{
		{"2026-09-01 00:24:50 status installed", utc(2026, 9, 1, 0, 24, 50), "status installed"},
		{"2026-09-19T18:45:00Z sshd[1]: x", utc(2026, 9, 19, 18, 45, 0), "sshd[1]: x"},
		{"2026-09-19T18:45:00+02:00 host sshd[1]: x", utc(2026, 9, 19, 16, 45, 0), "host sshd[1]: x"},
		{"2026-09-19T18:45:00-05:00 host cron[2]: y", utc(2026, 9, 19, 23, 45, 0), "host cron[2]: y"},
		{"2026-09-19T18:45:00.123456+02:00 host kernel: z", utc(2026, 9, 19, 16, 45, 0), "host kernel: z"},
		{"2026-09-19T18:45:00.5Z a", utc(2026, 9, 19, 18, 45, 0), "a"},
		{"2026-09-19 18:45:00,250 a", utc(2026, 9, 19, 18, 45, 0), "a"},
		{"2026-09-19T18:45:00+0530 a", utc(2026, 9, 19, 13, 15, 0), "a"},
		{"2026-09-19T18:45:00Z", utc(2026, 9, 19, 18, 45, 0), ""},
		{"2026-12-31T23:59:60Z fin", utc(2026, 12, 31, 23, 59, 59), "fin"},
		{"Sep 19 18:45:00 host sshd[42]: Accepted", utc(2026, 9, 19, 18, 45, 0), "host sshd[42]: Accepted"},
		{"Sep  9 08:05:00 host cron[1]: x", utc(2026, 9, 9, 8, 5, 0), "host cron[1]: x"},
		// Journal de décembre lu fin septembre : l'année précédente, pas le futur.
		{"Dec 30 23:00:00 host a: b", utc(2025, 12, 30, 23, 0, 0), "host a: b"},
		{"<34>1 2026-09-19T18:45:00Z host app - - msg", utc(2026, 9, 19, 18, 45, 0), "host app - - msg"},
		{"<13>Sep 19 18:45:00 host a: b", utc(2026, 9, 19, 18, 45, 0), "host a: b"},
	} {
		ts, rest, st := parseTimestamp(tc.line)
		if st != tsValid || ts != tc.want || rest != tc.rest {
			t.Errorf("%q: ts=%d (%s) rest=%q st=%d, attendu %d rest=%q",
				tc.line, ts, time.Unix(int64(ts), 0).UTC(), rest, st, tc.want, tc.rest)
		}
	}
}

// Les dates impossibles ou mal formées sont refusées, jamais normalisées ni
// remplacées par l'instant présent ; une ligne sans date est reconnue comme telle.
func TestParseTimestamp_RejectsInvalid(t *testing.T) {
	fixNow(t, time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC))
	for _, line := range []string{
		"2026-13-01 00:00:00 mois 13",
		"2026-02-30 00:00:00 30 fevrier",
		"2025-02-29T00:00:00Z annee non bissextile",
		"2026-09-19 24:00:00 heure 24",
		"2026-09-19 12:60:00 minute 60",
		"1969-12-31T23:59:59Z avant 1970",
		"2026-09-19T18:45:00+25:00 fuseau",
		"2026-09-19T18:45:00+02:7 fuseau tronque",
		"2026-09-19T18:45:00. fraction vide",
		"2026-09-19T18:45:00Zjunk colle",
		"2026-09-19 date seule",
		"2026-09-19T18:4",
		"Feb 30 10:00:00 host a: b",
		"Sep 19 25:00:00 host a: b",
		"Sep 19 18:45",
	} {
		if _, _, st := parseTimestamp(line); st != tsInvalid {
			t.Errorf("%q: statut %d, attendu tsInvalid", line, st)
		}
		if _, ok := ParseLogLine(line, "syslog"); ok {
			t.Errorf("%q: ligne admise", line)
		}
	}
	for _, line := range []string{"Commandline: apt install x", "status installed", "<>", "Sept 19", "12:00:00 x"} {
		if _, _, st := parseTimestamp(line); st != tsAbsent {
			t.Errorf("%q: statut %d, attendu tsAbsent", line, st)
		}
	}
}

// Aucune troncature de ligne ne fait paniquer l'analyse. L'ancienne version
// lisait line[:25] dès 20 octets et paniquait sur « 2026-09-19T18:45:00Z ».
func TestParseTimestamp_NoPanicOnPrefixes(t *testing.T) {
	for _, full := range []string{
		"2026-09-19T18:45:00.123456789+02:00 host sshd[42]: x",
		"<34>1 2026-09-19T18:45:00Z host",
		"Sep 19 18:45:00 host a: b",
		"2026-09-01 00:24:50 status installed",
	} {
		for n := 0; n <= len(full); n++ {
			ParseLogLine(full[:n], "auth.log")
		}
	}
}

// Une ligne sans horodatage n'est pas datée de l'instant présent : seule elle
// est refusée ; dans un flux, elle hérite de la dernière ligne horodatée.
func TestParseLogLine_NoWallClockFallback(t *testing.T) {
	if _, ok := ParseLogLine("Commandline: apt install curl", "history.log"); ok {
		t.Fatal("ligne sans horodatage admise")
	}
	dir := t.TempDir()
	silo := p0Silo(t, dir)
	stream := "Commandline: avant toute date\n" +
		"2026-09-19 10:00:00 status installed curl:amd64 8.0\n" +
		"Commandline: apt install curl\n"
	n, err := NewLogStreamIngester(silo).IngestReader(strings.NewReader(stream), "dpkg.log")
	if err != nil || n != 2 {
		t.Fatalf("ingestion: %d lignes, %v (attendu 2)", n, err)
	}
	day, _, _, _ := silo.Stats()
	if want := uint32(time.Date(2026, 9, 19, 0, 0, 0, 0, time.UTC).Unix() / 86400); day != want {
		t.Fatalf("jour %d, attendu %d : la ligne de suite n'a pas herite de l'horodatage", day, want)
	}
}

// L'entité est l'acteur qui émet la ligne, pas le nom du fichier : la
// rotation (auth.log → auth.log.1 → auth.log.2.gz) ne change pas l'entité,
// et deux démons d'un même fichier sont deux entités.
func TestParseLogLine_EntityIsActorNotFileName(t *testing.T) {
	line := "Sep 19 18:45:00 host sshd[4242]: Accepted publickey for cl-ment from 203.0.113.9 port 50022 ssh2"
	var ids []uint64
	for _, src := range []string{"auth.log", "auth.log.1", "auth.log.2.gz", "/var/log/secure-20260901"} {
		snap, ok := ParseLogLine(line, src)
		if !ok {
			t.Fatalf("%s: ligne refusee", src)
		}
		ids = append(ids, snap.EntityID)
	}
	for i := range ids {
		if ids[i] != LogActorID("sshd") {
			t.Fatalf("source %d: entite %x, attendu celle de sshd", i, ids[i])
		}
	}
	sudo, _ := ParseLogLine("Sep 19 18:46:00 host sudo:  cl-ment : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/usr/bin/id", "auth.log")
	cron, _ := ParseLogLine("Sep 19 18:47:00 host CRON[99]: pam_unix(cron:session): session opened for user root", "auth.log")
	kern, _ := ParseLogLine("Sep 19 18:48:00 host kernel: [12.3] audit: type=1400", "kern.log")
	tagPath, _ := ParseLogLine("Sep 19 18:49:00 host /usr/sbin/cron[12]: (root) CMD (x)", "syslog")
	bare, _ := ParseLogLine("2026-09-28 03:10:00 sshd[42]: Failed password for root", "auth.log")
	for name, got := range map[string]struct {
		snap engine.ServerHealthSnapshot
		want string
	}{
		"sudo": {sudo, "sudo"}, "cron": {cron, "cron"}, "kernel": {kern, "kernel"},
		"chemin": {tagPath, "cron"}, "sans hote": {bare, "sshd"},
	} {
		if got.snap.EntityID != LogActorID(got.want) {
			t.Errorf("%s: entite differente de %q", name, got.want)
		}
	}
	// Sans étiquette, l'acteur est la source normalisée, stable à la rotation.
	a, _ := ParseLogLine("2026-09-01 00:24:50 status installed libc6:amd64 2.40-1", "dpkg.log")
	b, _ := ParseLogLine("2026-09-01 00:24:50 status installed libc6:amd64 2.40-1", "dpkg.log.3.gz")
	if a.EntityID != b.EntityID || a.EntityID != LogActorID("dpkg") {
		t.Fatal("source sans etiquette: entite dependante de la rotation")
	}
}

func TestNormalizeLogActor(t *testing.T) {
	for in, want := range map[string]string{
		"auth.log": "auth", "auth.log.1": "auth", "auth.log.2.gz": "auth", "syslog.7.xz": "syslog",
		"messages-20260901": "messages", "SSHD": "sshd", "systemd-logind": "systemd-logind", "kern.log.10": "kern",
	} {
		if got := NormalizeLogActor(in); got != want {
			t.Errorf("%q: %q, attendu %q", in, got, want)
		}
	}
}

func templateOf(msg string) string {
	var p [engine.FeaturePayloadBytes]byte
	n := LogTemplate(&p, msg)
	return string(p[:n])
}

// Le gabarit masque PID, adresses, nombres, identifiants et chemins volatils,
// si bien que deux occurrences d'un même message ont la même charge.
func TestLogTemplate_Masking(t *testing.T) {
	for in, want := range map[string]string{
		"host sshd[4242]: Accepted publickey for cl-ment from 203.0.113.9 port 50022 ssh2": "host sshd[#]: Accepted publickey for cl-ment from <ip> port # ssh#",
		"connect to [2001:db8::1]:443 failed":                                              "connect to [<ip>]:# failed",
		"session 3f2a9c1e-77ab-4c21-9d3e-0a1b2c3d4e5f   closed":                            "session <uuid> closed",
		"exec /tmp/.x9f3k/payload by pid=812":                                              "exec /tmp/* by pid=#",
		"status installed libc6:amd64 2.40-1":                                              "status installed libc#:amd# #.#-#",
		"commit deadbeef01 pushed":                                                         "commit <hex> pushed",
		"from 10.0.0.1:22, retry":                                                          "from <ip>, retry",
	} {
		if got := templateOf(in); got != want {
			t.Errorf("%q\n  gabarit %q\n  attendu %q", in, got, want)
		}
	}
	a, _ := ParseLogLine("Sep 19 18:45:00 host sshd[1]: Accepted publickey for u from 10.0.0.1 port 1", "auth.log")
	b, _ := ParseLogLine("Sep 19 18:45:07 host sshd[99999]: Accepted publickey for u from 192.168.4.200 port 65000", "auth.log")
	if a.RawPayload != b.RawPayload {
		t.Fatal("deux occurrences du meme message ont des charges differentes")
	}
	var p [engine.FeaturePayloadBytes]byte
	for i := range p {
		p[i] = 'x'
	}
	if n := LogTemplate(&p, strings.Repeat("a1 ", 100)); n != len(p) {
		t.Fatalf("gabarit long: %d octets", n)
	}
	if n := LogTemplate(&p, "court"); n != 5 || p[5] != 0 || p[len(p)-1] != 0 {
		t.Fatal("reste de la charge non remis a zero")
	}
	if n := testing.AllocsPerRun(100, func() { LogTemplate(&p, "host sshd[4242]: from 203.0.113.9 port 50022") }); n != 0 {
		t.Fatalf("LogTemplate: %v allocations", n)
	}
}
