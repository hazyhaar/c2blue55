package c2blue55_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	c2 "github.com/hazyhaar/c2blue55"
)

// fixtureBenchPCAP: emitter: generator;
// generator: bench_pcap_banc_test.go:fixtureBenchPCAP.
// Ces octets éprouvent le format PCAP, jamais la performance d'un détecteur.
func fixtureBenchPCAP(order binary.ByteOrder, nano bool, link uint32, frames ...[]byte) []byte {
	out := make([]byte, 24)
	magic := uint32(0xa1b2c3d4)
	if nano {
		magic = 0xa1b23c4d
	}
	order.PutUint32(out, magic)
	order.PutUint16(out[4:], 2)
	order.PutUint16(out[6:], 4)
	order.PutUint32(out[16:], 1<<20)
	order.PutUint32(out[20:], link)
	for _, frame := range frames {
		record := make([]byte, 16)
		order.PutUint32(record, 17)
		order.PutUint32(record[4:], 123456)
		order.PutUint32(record[8:], uint32(len(frame)))
		order.PutUint32(record[12:], uint32(len(frame)))
		out = append(out, record...)
		out = append(out, frame...)
	}
	return out
}

// benchOraclePCAP décode indépendamment tous les octets d'une pièce existante.
// Il ne passe jamais par ReadBenchPCAP ni par les étiquettes des manifestes.
func benchOraclePCAP(t *testing.T, path string) ([]byte, []c2.BenchPacket) {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(content) < 24 {
		t.Fatalf("%s: en-tête incomplet", path)
	}
	var order binary.ByteOrder
	var factor uint64
	switch string(content[:4]) {
	case "\xd4\xc3\xb2\xa1":
		order, factor = binary.LittleEndian, 1000
	case "\xa1\xb2\xc3\xd4":
		order, factor = binary.BigEndian, 1000
	case "\x4d\x3c\xb2\xa1":
		order, factor = binary.LittleEndian, 1
	case "\xa1\xb2\x3c\x4d":
		order, factor = binary.BigEndian, 1
	default:
		t.Fatalf("%s: magique inconnu", path)
	}
	if order.Uint16(content[4:]) != 2 || order.Uint16(content[6:]) != 4 {
		t.Fatalf("%s: version non classique", path)
	}
	link, snap := order.Uint32(content[20:]), order.Uint32(content[16:])
	if snap == 0 || snap > 1<<20 {
		t.Fatalf("%s: snaplen %d", path, snap)
	}
	packets := make([]c2.BenchPacket, 0, (len(content)-24)/64)
	for offset := 24; offset < len(content); {
		if len(content)-offset < 16 {
			t.Fatalf("%s: fin partielle à %d", path, offset)
		}
		record := content[offset : offset+16]
		size, original := order.Uint32(record[8:]), order.Uint32(record[12:])
		fraction := uint64(order.Uint32(record[4:])) * factor
		offset += 16
		if size != original || size > snap || uint64(size) > uint64(len(content)-offset) || fraction >= 1e9 {
			t.Fatalf("%s: enregistrement invalide à %d", path, offset-16)
		}
		packets = append(packets, c2.BenchPacket{
			TimestampNs: uint64(order.Uint32(record))*1e9 + fraction,
			LinkType:    link, Frame: content[offset : offset+int(size)],
		})
		offset += int(size)
	}
	return content, packets
}

func benchRealCaptures(t *testing.T) []string {
	t.Helper()
	paths := make([]string, 0, 14)
	for _, directory := range []string{"n04-20261029", "a04-20261029", "i03-20261029"} {
		matches, err := filepath.Glob(filepath.Join("testdata", directory, "*.pcap"))
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, matches...)
	}
	if len(paths) != 14 {
		t.Fatalf("inventaire réel modifié: %d captures, attendu 14; réexaminer le scellement", len(paths))
	}
	return paths
}

func TestBancAPCAP_FourMagicsFourLinksAndEOF(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, nano := range []bool{false, true} {
			for _, link := range []uint32{1, 101, 113, 276} {
				t.Run(fmt.Sprintf("%s/nano=%v/link=%d", order, nano, link), func(t *testing.T) {
					frames := [][]byte{{1, 2, 3}, {4, 5}, {6, 7, 8, 9}}
					fixture := fixtureBenchPCAP(order, nano, link, frames...)
					reader := bytes.NewReader(fixture)
					index := 0
					factor := uint64(1000)
					if nano {
						factor = 1
					}
					stats, err := c2.ReadBenchPCAP(reader, func(packet c2.BenchPacket) error {
						if index >= len(frames) {
							t.Fatal("rappel supplémentaire")
						}
						if packet.LinkType != link || packet.TimestampNs != 17e9+123456*factor || !bytes.Equal(packet.Frame, frames[index]) {
							t.Fatalf("paquet %d = %+v, trame attendue %x", index, packet, frames[index])
						}
						index++
						return nil
					})
					if err != nil || index != len(frames) || stats.Packets != uint64(index) || stats.Bytes != uint64(len(fixture)) || reader.Len() != 0 {
						t.Fatalf("err=%v rappels=%d stats=%+v restant=%d", err, index, stats, reader.Len())
					}
				})
			}
		}
	}
	fixture := fixtureBenchPCAP(binary.LittleEndian, false, 101)
	stats, err := c2.ReadBenchPCAP(bytes.NewReader(fixture), func(c2.BenchPacket) error {
		t.Fatal("capture vide: rappel inattendu")
		return nil
	})
	if err != nil || stats.Packets != 0 || stats.Bytes != 24 {
		t.Fatalf("capture vide valide: %+v, %v", stats, err)
	}
}

func TestBancAPCAP_RealFilesEntirelyRead(t *testing.T) {
	for _, path := range benchRealCaptures(t) {
		t.Run(path, func(t *testing.T) {
			content, expected := benchOraclePCAP(t, path)
			index := 0
			reader := bytes.NewReader(content)
			stats, err := c2.ReadBenchPCAP(reader, func(packet c2.BenchPacket) error {
				if index >= len(expected) || !reflect.DeepEqual(packet, expected[index]) {
					t.Fatalf("divergence au paquet %d", index+1)
				}
				index++
				return nil
			})
			if err != nil || index != len(expected) || stats.Packets != uint64(len(expected)) || stats.Bytes != uint64(len(content)) || reader.Len() != 0 {
				t.Fatalf("lecture intégrale: index=%d/%d stats=%+v restant=%d err=%v", index, len(expected), stats, reader.Len(), err)
			}
		})
	}
}

// fixtureHeaderGuard: emitter: generator;
// generator: bench_pcap_banc_test.go:fixtureHeaderGuard.Read.
// L'accès au corps et la taille de la demande sont observés avant tout retour.
type fixtureHeaderGuard struct {
	header     []byte
	bodyRead   bool
	maxRequest int
	terminal   error
}

func (reader *fixtureHeaderGuard) Read(dst []byte) (int, error) {
	if len(dst) > reader.maxRequest {
		reader.maxRequest = len(dst)
	}
	if len(reader.header) == 0 {
		reader.bodyRead = true
		return 0, reader.terminal
	}
	n := copy(dst, reader.header)
	reader.header = reader.header[n:]
	return n, nil
}

func TestBancAPCAP_InvalidBoundsBeforeBodyRead(t *testing.T) {
	for _, name := range []string{"magic", "major", "minor", "link", "snap-zero", "snap-too-large", "incl-over-snap", "incl-under-orig", "incl-over-orig", "over-one-mib", "huge-record", "clock-us", "clock-ns"} {
		t.Run(name, func(t *testing.T) {
			fixture := fixtureBenchPCAP(binary.LittleEndian, name == "clock-ns", 101, []byte{1})[:40]
			put := binary.LittleEndian.PutUint32
			switch name {
			case "magic":
				fixture[0] ^= 0xff
			case "major":
				binary.LittleEndian.PutUint16(fixture[4:], 3)
			case "minor":
				binary.LittleEndian.PutUint16(fixture[6:], 3)
			case "link":
				put(fixture[20:], 999)
			case "snap-zero":
				put(fixture[16:], 0)
			case "snap-too-large":
				put(fixture[16:], 1<<20+1)
			case "incl-over-snap":
				put(fixture[16:], 8)
				put(fixture[32:], 9)
				put(fixture[36:], 9)
			case "incl-under-orig":
				put(fixture[36:], 2)
			case "incl-over-orig":
				put(fixture[36:], 0)
			case "over-one-mib":
				put(fixture[32:], 1<<20+1)
				put(fixture[36:], 1<<20+1)
			case "huge-record":
				put(fixture[32:], ^uint32(0))
				put(fixture[36:], ^uint32(0))
			case "clock-us":
				put(fixture[28:], 1_000_000)
			case "clock-ns":
				put(fixture[28:], 1_000_000_000)
			}
			stop := errors.New("fixture: corps interdit")
			reader := &fixtureHeaderGuard{header: fixture, terminal: stop}
			calls := 0
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			_, err := c2.ReadBenchPCAP(reader, func(c2.BenchPacket) error { calls++; return nil })
			runtime.ReadMemStats(&after)
			if err == nil || errors.Is(err, stop) || calls != 0 || reader.bodyRead || reader.maxRequest > 1<<20 {
				t.Fatalf("borne non opposée avant corps: err=%v rappels=%d corps=%v demande=%d", err, calls, reader.bodyRead, reader.maxRequest)
			}
			// Le plafond vient du snaplen contractuel; il ne mesure pas une
			// performance de détection sur la fixture de format.
			if name == "over-one-mib" && after.TotalAlloc-before.TotalAlloc >= 1<<20+1 {
				t.Fatalf("allocation d'une trame hors borne avant refus: %d octets", after.TotalAlloc-before.TotalAlloc)
			}
		})
	}
}

func TestBancAPCAP_EveryTruncationAndTrailingByteRefused(t *testing.T) {
	fixture := fixtureBenchPCAP(binary.BigEndian, true, 276, []byte{1, 2, 3}, []byte{4, 5, 6, 7})
	for length := 0; length < len(fixture); length++ {
		// Les frontières exactes entre enregistrements sont des EOF valides.
		if length == 24 || length == 43 {
			continue
		}
		t.Run(fmt.Sprintf("prefix-%d", length), func(t *testing.T) {
			if _, err := c2.ReadBenchPCAP(bytes.NewReader(fixture[:length]), func(c2.BenchPacket) error { return nil }); err == nil {
				t.Fatal("troncature acceptée")
			}
		})
	}
	fixture = append(fixture, 0x42)
	seenPackets := 0
	if _, err := c2.ReadBenchPCAP(bytes.NewReader(fixture), func(c2.BenchPacket) error { seenPackets++; return nil }); err == nil || seenPackets != 2 {
		t.Fatalf("octet final après deux trames: count=%d err=%v", seenPackets, err)
	}
}

func TestBancAPCAP_ReaderAndCallbackErrorsPropagate(t *testing.T) {
	fixture := fixtureBenchPCAP(binary.LittleEndian, false, 101, []byte{1}, []byte{2})
	visitorError := errors.New("fixture: visiteur interrompu")
	seenPackets := 0
	if _, err := c2.ReadBenchPCAP(bytes.NewReader(fixture), func(c2.BenchPacket) error { seenPackets++; return visitorError }); !errors.Is(err, visitorError) || seenPackets != 1 {
		t.Fatalf("visiteur: rappels=%d err=%v", seenPackets, err)
	}
	readError := errors.New("fixture: lecteur défaillant")
	for _, length := range []int{0, 12, 24, 30, 40, len(fixture)} {
		t.Run(fmt.Sprintf("reader-at-%d", length), func(t *testing.T) {
			reader := &fixtureHeaderGuard{header: bytes.Clone(fixture[:length]), terminal: readError}
			if _, err := c2.ReadBenchPCAP(reader, func(c2.BenchPacket) error { return nil }); !errors.Is(err, readError) {
				t.Fatalf("erreur lecteur perdue: %v", err)
			}
		})
	}
	// Une lecture courte sans erreur doit être poursuivie, pas assimilée à EOF.
	stats, err := c2.ReadBenchPCAP(&fixtureOneByteReader{Reader: bytes.NewReader(fixture)}, func(c2.BenchPacket) error { return nil })
	if err != nil || stats.Packets != 2 || stats.Bytes != uint64(len(fixture)) {
		t.Fatalf("lectures courtes: %+v %v", stats, err)
	}
}

// fixtureOneByteReader: emitter: generator;
// generator: bench_pcap_banc_test.go:fixtureOneByteReader.Read.
type fixtureOneByteReader struct{ io.Reader }

func (reader *fixtureOneByteReader) Read(dst []byte) (int, error) {
	if len(dst) > 1 {
		dst = dst[:1]
	}
	return reader.Reader.Read(dst)
}
