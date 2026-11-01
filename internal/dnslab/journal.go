package dnslab

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
	"unicode/utf8"
)

// JournalLine est une ligne typée du journal : une par question reçue.
type JournalLine struct {
	TS          uint64 `json:"ts_us"`
	Source      string `json:"src"`
	SourcePort  uint16 `json:"sport"`
	QName       string `json:"qname"`
	QType       uint16 `json:"qtype"`
	QClass      uint16 `json:"qclass"`
	Verdict     string `json:"verdict"`
	RCode       uint8  `json:"rcode"`
	ResponseLen uint16 `json:"resp_len"`
	RateLimited bool   `json:"rrl"`
	ParseError  string `json:"parse_error,omitempty"`
}

// EncodeJournalLine encode la ligne en JSON suivi d'un saut de ligne dans
// scratch (sans allocation si la capacité suffit) et rend la tranche écrite.
func EncodeJournalLine(line *JournalLine, scratch []byte) ([]byte, error) {
	if line == nil {
		return nil, errors.New("dnslab: ligne de journal absente")
	}
	scratch = append(scratch, `{"ts_us":`...)
	scratch = strconv.AppendUint(scratch, line.TS, 10)
	scratch = append(scratch, `,"src":`...)
	scratch = appendJSONStringRFC8259(scratch, line.Source)
	scratch = append(scratch, `,"sport":`...)
	scratch = strconv.AppendUint(scratch, uint64(line.SourcePort), 10)
	scratch = append(scratch, `,"qname":`...)
	scratch = appendJSONStringRFC8259(scratch, line.QName)
	scratch = append(scratch, `,"qtype":`...)
	scratch = strconv.AppendUint(scratch, uint64(line.QType), 10)
	scratch = append(scratch, `,"qclass":`...)
	scratch = strconv.AppendUint(scratch, uint64(line.QClass), 10)
	scratch = append(scratch, `,"verdict":`...)
	scratch = appendJSONStringRFC8259(scratch, line.Verdict)
	scratch = append(scratch, `,"rcode":`...)
	scratch = strconv.AppendUint(scratch, uint64(line.RCode), 10)
	scratch = append(scratch, `,"resp_len":`...)
	scratch = strconv.AppendUint(scratch, uint64(line.ResponseLen), 10)
	if line.RateLimited {
		scratch = append(scratch, `,"rrl":true`...)
	} else {
		scratch = append(scratch, `,"rrl":false`...)
	}
	if line.ParseError != "" {
		scratch = append(scratch, `,"parse_error":`...)
		scratch = appendJSONStringRFC8259(scratch, line.ParseError)
	}
	return append(scratch, '}', '\n'), nil
}

func appendJSONStringRFC8259(dst []byte, fieldText string) []byte {
	const hexDigits = "0123456789abcdef"
	dst = append(dst, '"')
	for i := 0; i < len(fieldText); {
		octet := fieldText[i]
		if octet < utf8.RuneSelf {
			switch octet {
			case '"', '\\':
				dst = append(dst, '\\', octet)
			case '\b':
				dst = append(dst, '\\', 'b')
			case '\f':
				dst = append(dst, '\\', 'f')
			case '\n':
				dst = append(dst, '\\', 'n')
			case '\r':
				dst = append(dst, '\\', 'r')
			case '\t':
				dst = append(dst, '\\', 't')
			default:
				if octet < 0x20 {
					dst = append(dst, '\\', 'u', '0', '0', hexDigits[octet>>4], hexDigits[octet&0x0F])
				} else {
					dst = append(dst, octet)
				}
			}
			i++
			continue
		}
		decodedRune, width := utf8.DecodeRuneInString(fieldText[i:])
		if decodedRune == utf8.RuneError && width == 1 {
			dst = append(dst, `\ufffd`...)
		} else {
			dst = append(dst, fieldText[i:i+width]...)
		}
		i += width
	}
	return append(dst, '"')
}

// JournalWriter écrit les lignes en O_APPEND dans <dir>/dnslab-<YYYYMMDDTHH>Z.jsonl
// (0600, répertoire 0700), avec rotation au changement d'heure UTC et fsync
// toutes les 256 lignes et à la fermeture.
type JournalWriter struct {
	dir     string
	now     func() time.Time
	lines   uint32
	file    *os.File
	hour    string
	scratch []byte
}

// OpenJournal prépare le répertoire et l'horloge ; le premier fichier s'ouvre
// à la première ligne.
func OpenJournal(dir string, now func() time.Time) (*JournalWriter, error) {
	if now == nil {
		return nil, errors.New("dnslab: horloge absente")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	return &JournalWriter{dir: dir, now: now, scratch: make([]byte, 0, 1024)}, nil
}

// Append écrit une ligne ; toute erreur d'écriture est rendue.
func (w *JournalWriter) Append(line *JournalLine) error {
	encoded, err := EncodeJournalLine(line, w.scratch[:0])
	if err != nil {
		return err
	}
	w.scratch = encoded[:0]
	hour := w.now().UTC().Format("20060102T15")
	if hour != w.hour || w.file == nil {
		// Explicitly check permissions: root also has to reject a rotated file
		// in a directory made unwritable after startup.
		stat, err := os.Stat(w.dir)
		if err != nil {
			return err
		}
		if stat.Mode().Perm()&0o222 == 0 {
			return fmt.Errorf("dnslab: rotation: %w", os.ErrPermission)
		}
		path := filepath.Join(w.dir, "dnslab-"+hour+"Z.jsonl")
		next, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		if err != nil {
			return err
		}
		if err := next.Chmod(0o600); err != nil {
			return errors.Join(err, next.Close())
		}
		if w.file != nil {
			if err := w.Close(); err != nil {
				closeErr := next.Close()
				return errors.Join(err, closeErr)
			}
		}
		w.file, w.hour, w.lines = next, hour, 0
	}
	n, err := w.file.Write(encoded)
	if err != nil {
		return err
	}
	if n != len(encoded) {
		return fmt.Errorf("dnslab: écriture partielle: %w", os.ErrInvalid)
	}
	w.lines++
	if w.lines%256 == 0 {
		return w.file.Sync()
	}
	return nil
}

// Close synchronise et ferme le fichier courant.
func (w *JournalWriter) Close() error {
	if w.file == nil {
		return nil
	}
	err := errors.Join(w.file.Sync(), w.file.Close())
	w.file = nil
	return err
}
