package dnslab_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hazyhaar/c2blue55/internal/dnslab"
)

func sampleLines() (dnslab.JournalLine, dnslab.JournalLine, dnslab.JournalLine) {
	first := dnslab.JournalLine{
		TS:          1793101037220066,
		Source:      "127.0.0.1",
		SourcePort:  38498,
		QName:       "hazyhaar.fr",
		QType:       1,
		QClass:      1,
		Verdict:     "refused",
		RCode:       5,
		ResponseLen: 41,
		RateLimited: false,
	}
	second := dnslab.JournalLine{
		TS:          1793101037220067,
		Source:      "127.0.0.1",
		SourcePort:  45493,
		QName:       "lab.pound2pound.fr",
		QType:       1,
		QClass:      1,
		Verdict:     "answer_a",
		RCode:       0,
		ResponseLen: 52,
		RateLimited: true,
		ParseError:  "",
	}
	third := dnslab.JournalLine{
		TS:          1793101037221000,
		Source:      "10.55.0.2",
		SourcePort:  53000,
		QName:       "probe-1.lab.pound2pound.fr",
		QType:       16,
		QClass:      1,
		Verdict:     "answer_txt",
		RCode:       0,
		ResponseLen: 80,
		RateLimited: false,
		ParseError:  "compression",
	}
	return first, second, third
}

func readHourFile(t *testing.T, dir, name string, wantLines int) []dnslab.JournalLine {
	t.Helper()
	path := filepath.Join(dir, name)
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("lecture %s: %v", name, err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", name, err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("%s mode %o, attendu 0600", name, st.Mode().Perm())
	}
	if len(payload) == 0 || payload[len(payload)-1] != '\n' {
		t.Fatalf("%s: saut de ligne final absent", name)
	}
	rows := bytes.Split(payload, []byte{'\n'})
	if len(rows) == 0 || len(rows[len(rows)-1]) != 0 {
		t.Fatalf("%s: terminaison inattendue", name)
	}
	rows = rows[:len(rows)-1]
	if len(rows) != wantLines {
		t.Fatalf("%s: %d lignes, attendu %d", name, len(rows), wantLines)
	}
	lines := make([]dnslab.JournalLine, 0, len(rows))
	for _, row := range rows {
		var line dnslab.JournalLine
		if err := json.Unmarshal(row, &line); err != nil {
			t.Fatalf("%s: JSON illisible: %v", name, err)
		}
		lines = append(lines, line)
	}
	return lines
}

func TestJournalWriter_RotationAndFormat(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "journal")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatalf("répertoire: %v", err)
	}
	instant := time.Date(2026, 10, 27, 10, 59, 59, 0, time.UTC)
	writer, err := dnslab.OpenJournal(dir, func() time.Time { return instant })
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	first, second, third := sampleLines()
	if err := writer.Append(&first); err != nil {
		t.Fatalf("Append 10:59:59 première ligne: %v", err)
	}
	if err := writer.Append(&second); err != nil {
		t.Fatalf("Append 10:59:59 seconde ligne: %v", err)
	}
	instant = time.Date(2026, 10, 27, 11, 0, 0, 0, time.UTC)
	if err := writer.Append(&third); err != nil {
		t.Fatalf("Append 11:00:00: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("lecture du répertoire: %v", err)
	}
	if len(entries) != 2 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("fichiers de journal: %v, attendu dnslab-20261027T10Z.jsonl et dnslab-20261027T11Z.jsonl", names)
	}
	dirMode, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat répertoire: %v", err)
	}
	if dirMode.Mode().Perm() != 0o700 {
		t.Fatalf("répertoire mode %o, attendu 0700", dirMode.Mode().Perm())
	}
	hour10 := readHourFile(t, dir, "dnslab-20261027T10Z.jsonl", 2)
	hour11 := readHourFile(t, dir, "dnslab-20261027T11Z.jsonl", 1)
	if hour10[0] != first || hour10[1] != second {
		t.Fatalf("T10: %+v / %+v, attendu les deux lignes de 10:59:59Z", hour10[0], hour10[1])
	}
	if hour11[0] != third {
		t.Fatalf("T11: %+v, attendu la ligne de 11:00:00Z", hour11[0])
	}

	scratch := make([]byte, 0, 1024)
	encoded, err := dnslab.EncodeJournalLine(&third, scratch)
	if err != nil || len(encoded) == 0 || encoded[len(encoded)-1] != '\n' {
		t.Fatalf("EncodeJournalLine: err=%v n=%d, attendu une ligne JSON terminée par un saut de ligne", err, len(encoded))
	}
	var decoded dnslab.JournalLine
	if err := json.Unmarshal(bytes.TrimRight(encoded, "\n"), &decoded); err != nil {
		t.Fatalf("EncodeJournalLine JSON illisible: %v", err)
	}
	if decoded != third {
		t.Fatalf("EncodeJournalLine: %+v, attendu %+v", decoded, third)
	}
	allocs := testing.AllocsPerRun(1000, func() {
		_, _ = dnslab.EncodeJournalLine(&third, scratch[:0])
	})
	if allocs != 0 {
		t.Fatalf("EncodeJournalLine alloue %v fois par appel, attendu 0", allocs)
	}
}

func TestJournalWriter_WriteErrorPropagated(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(func() {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Errorf("rétablissement du répertoire: %v", err)
		}
	})
	instant := time.Date(2026, 10, 27, 10, 59, 59, 0, time.UTC)
	writer, err := dnslab.OpenJournal(dir, func() time.Time { return instant })
	if err != nil {
		t.Fatalf("OpenJournal: %v", err)
	}
	first, _, _ := sampleLines()
	if err := writer.Append(&first); err != nil {
		t.Fatalf("Append initial: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	instant = time.Date(2026, 10, 27, 11, 0, 0, 0, time.UTC)
	err = writer.Append(&first)
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("Append err=%v, attendu une erreur enveloppant fs.ErrPermission", err)
	}
}
