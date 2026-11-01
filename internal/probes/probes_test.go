package probes

import (
	"bytes"
	"os"
	"testing"
	"unsafe"

	c2blue55 "github.com/hazyhaar/c2blue55"
)

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// TestParseMaps_RealDumps valide le décodeur sur des captures réelles de
// /proc/<pid>/maps, dont le dump d'un processus Node.js porteur d'une région
// V8 rwxp et le dump d'un processus Python standard dépourvu de W^X.
func TestParseMaps_RealDumps(t *testing.T) {
	out := make([]Segment, 256)

	node := mustRead(t, "testdata/maps_node_jit.txt")
	n := ParseMaps(node, out, len(out))
	if n != 101 {
		t.Fatalf("node maps: got %d segments, want 101", n)
	}
	if out[0].Start != 0x00400000 || out[0].End != 0x00e37000 {
		t.Errorf("node[0] range = %x-%x", out[0].Start, out[0].End)
	}
	if out[0].Perms != PermRead {
		t.Errorf("node[0] perms = %s, want r--p", out[0].Perms)
	}
	if string(out[0].Path) != "/usr/bin/node" {
		t.Errorf("node[0] path = %q", out[0].Path)
	}
	if out[10].Start != 0x1c683000 || out[10].End != 0x1c6bf000 {
		t.Errorf("node[10] rwxp range = %x-%x", out[10].Start, out[10].End)
	}
	if out[10].Perms != PermRead|PermWrite|PermExec {
		t.Errorf("node[10] perms = %s, want rwxp", out[10].Perms)
	}
	if len(out[10].Path) != 0 {
		t.Errorf("node[10] anonymous region carries a path: %q", out[10].Path)
	}

	py := mustRead(t, "testdata/maps_python_clean.txt")
	if n := ParseMaps(py, out, len(out)); n != 44 {
		t.Fatalf("python maps: got %d segments, want 44", n)
	}

	tmp := mustRead(t, "testdata/maps_tmp_exec.txt")
	n = ParseMaps(tmp, out, len(out))
	if n != 50 {
		t.Fatalf("tmp maps: got %d segments, want 50", n)
	}
	seg := out[31]
	if seg.Start != 0x73dda39c7000 || seg.End != 0x73dda39c8000 {
		t.Errorf("tmp[31] range = %x-%x", seg.Start, seg.End)
	}
	if seg.Perms != PermRead|PermExec|PermShared {
		t.Errorf("tmp[31] perms = %s, want r-xs", seg.Perms)
	}
	if seg.Inode != 21286474 {
		t.Errorf("tmp[31] inode = %d, want 21286474", seg.Inode)
	}
	if string(seg.Path) != "/tmp/wpfixture.bin" {
		t.Errorf("tmp[31] path = %q", seg.Path)
	}

	del := mustRead(t, "testdata/maps_deleted_tmp.txt")
	n = ParseMaps(del, out, len(out))
	if n != 24 {
		t.Fatalf("deleted maps: got %d segments, want 24", n)
	}
	seg = out[12]
	if !seg.Deleted {
		t.Errorf("deleted[12] not marked deleted")
	}
	if string(seg.Path) != "/tmp/wp_del.bin (deleted)" {
		t.Errorf("deleted[12] path = %q", seg.Path)
	}
	if seg.Start != 0x70b303d2d000 {
		t.Errorf("deleted[12] start = %x", seg.Start)
	}
}

func TestParseMaps_LimitAndFinalLine(t *testing.T) {
	node := mustRead(t, "testdata/maps_node_jit.txt")
	out := make([]Segment, 256)
	if n := ParseMaps(node, out, 3); n != 3 {
		t.Fatalf("limit=3 got %d", n)
	}
	nl := bytes.IndexByte(node, '\n')
	if nl <= 0 {
		t.Fatal("fixture lacks newline")
	}
	single := node[:nl]
	if n := ParseMaps(single, out, len(out)); n != 1 {
		t.Fatalf("final line without newline got %d segments, want 1", n)
	}
	if string(out[0].Path) != "/usr/bin/node" {
		t.Errorf("final line path = %q", out[0].Path)
	}
}

func TestParseMaps_ZeroAlloc(t *testing.T) {
	mapsFixture := mustRead(t, "testdata/maps_node_jit.txt")
	out := make([]Segment, 256)
	allocs := testing.AllocsPerRun(500, func() {
		_ = ParseMaps(mapsFixture, out, len(out))
	})
	if allocs != 0 {
		t.Errorf("ParseMaps allocs = %.2f, want 0", allocs)
	}
}

// TestInspect_Fileless utilise la cible réelle lue au readlink d'un processus
// fexecve sur memfd_create, et la cible réelle d'un binaire exécuté puis
// supprimé du disque.
func TestInspect_Fileless(t *testing.T) {
	memfd := trimNL(mustRead(t, "testdata/exe_memfd.txt"))
	deleted := trimNL(mustRead(t, "testdata/exe_deleted.txt"))

	cases := []struct {
		name   string
		target []byte
		want   ExeFlags
	}{
		{"memfd", memfd, ExeMemfd | ExeDeleted},
		{"deleted", deleted, ExeDeleted},
		{"memfd-only", []byte("/memfd:payload"), ExeMemfd},
		{"ondisk", []byte("/usr/bin/python3"), 0},
		{"node", []byte("/usr/bin/node"), 0},
	}
	for _, c := range cases {
		if got := ClassifyExe(c.target); got != c.want {
			t.Errorf("%s: ClassifyExe = %b, want %b (target %q)", c.name, got, c.want, c.target)
		}
		if c.want != 0 && !ClassifyExe(c.target).Fileless() {
			t.Errorf("%s: Fileless() = false", c.name)
		}
	}

	var out [4]Anomaly
	n := Inspect(4242, memfd, nil, out[:], len(out))
	if n != 1 {
		t.Fatalf("Inspect fileless got %d anomalies, want 1", n)
	}
	if out[0].Kind != AnomalyFilelessExec || out[0].Pid != 4242 || out[0].Addr != 0 {
		t.Errorf("fileless anomaly = %+v", out[0])
	}
}

// TestInspect_WX_NonJIT confronte une vraie cartographie anonyme rwxp d'un
// binaire C non-JIT : la violation doit être remontée.
func TestInspect_WX_NonJIT(t *testing.T) {
	wx := mustRead(t, "testdata/maps_wx_anon.txt")
	var out [16]Anomaly
	n := Inspect(7, []byte("/tmp/wp_wx_c"), wx, out[:], len(out))
	if n != 1 {
		t.Fatalf("Inspect wx got %d anomalies, want 1: %+v", n, out[:n])
	}
	a := out[0]
	if a.Kind != AnomalyWX {
		t.Errorf("kind = %s, want wx", a.Kind)
	}
	if a.Addr != 0x7fc843a89000 {
		t.Errorf("addr = %x, want 7fc843a89000", a.Addr)
	}
	if a.Perms != PermRead|PermWrite|PermExec {
		t.Errorf("perms = %s, want rwxp", a.Perms)
	}
	if len(a.Path) != 0 {
		t.Errorf("anonymous wx region path = %q", a.Path)
	}
}

// TestInspect_WX_JITExempt vérifie qu'un processus Node.js, dont la capture
// porte pourtant une région rwxp, n'est pas signalé comme violation.
func TestInspect_WX_JITExempt(t *testing.T) {
	node := mustRead(t, "testdata/maps_node_jit.txt")
	var out [16]Anomaly
	if n := Inspect(9, []byte("/usr/bin/node"), node, out[:], len(out)); n != 0 {
		t.Fatalf("jit process reported %d anomalies, want 0: %+v", n, out[:n])
	}
}

// TestInspect_InjectedLib confronte une cartographie réelle d'un fichier de
// /tmp chargé dans un processus Python standard.
func TestInspect_InjectedLib(t *testing.T) {
	tmp := mustRead(t, "testdata/maps_tmp_exec.txt")
	var out [8]Anomaly
	n := Inspect(11, []byte("/usr/bin/python3"), tmp, out[:], len(out))
	if n != 1 {
		t.Fatalf("Inspect inject got %d anomalies, want 1: %+v", n, out[:n])
	}
	a := out[0]
	if a.Kind != AnomalyInjectedLib {
		t.Errorf("kind = %s, want inject", a.Kind)
	}
	if a.Addr != 0x73dda39c7000 {
		t.Errorf("addr = %x", a.Addr)
	}
	if string(a.Path) != "/tmp/wpfixture.bin" {
		t.Errorf("path = %q", a.Path)
	}
}

// TestInspect_DeletedTmpMapping vérifie qu'une cartographie /tmp supprimée est
// signalée pour le processus dont l'exécutable n'est pas cette cartographie.
func TestInspect_DeletedTmpMapping(t *testing.T) {
	del := mustRead(t, "testdata/maps_deleted_tmp.txt")
	var out [8]Anomaly
	n := Inspect(13, []byte("/tmp/wp_del"), del, out[:], len(out))
	if n != 1 {
		t.Fatalf("Inspect deleted tmp got %d anomalies, want 1: %+v", n, out[:n])
	}
	a := out[0]
	if a.Kind != AnomalyInjectedLib {
		t.Errorf("kind = %s, want inject", a.Kind)
	}
	if !bytes.Contains(a.Path, []byte("/tmp/wp_del.bin (deleted)")) {
		t.Errorf("path = %q", a.Path)
	}
}

// TestEmitAlert_Ring encode l'alerte dans l'Event de 128 octets et la relit
// depuis la mémoire annulaire.
func TestEmitAlert_Ring(t *testing.T) {
	if unsafe.Sizeof(c2blue55.Event{}) != EventSize {
		t.Fatalf("Event size = %d, want %d", unsafe.Sizeof(c2blue55.Event{}), EventSize)
	}
	ring := c2blue55.NewChannel()

	wx := Anomaly{Kind: AnomalyWX, Pid: 77, Addr: 0x7f00, Perms: PermRead | PermWrite | PermExec, Path: []byte("/dev/shm/evil (deleted)")}
	if rc := EmitAlert(ring, 123456789, 77, &wx); rc != 0 {
		t.Fatalf("EmitAlert wx rc = %d", rc)
	}
	var ev c2blue55.Event
	if ring.Read(&ev) != 1 {
		t.Fatal("ring read wx returned no event")
	}
	if ev.Ts_ns != 123456789 || ev.Pid != 77 || ev.Subsystem != c2blue55.SubProc {
		t.Errorf("event header = %+v", ev)
	}
	if ev.Action != c2blue55.ActMmapExec {
		t.Errorf("action = %d, want ActMmapExec", ev.Action)
	}
	if ev.Flags&c2blue55.FlagAnomaly == 0 {
		t.Errorf("flags = 0x%x, want FlagAnomaly", ev.Flags)
	}
	if ev.Src != 0x7f00 {
		t.Errorf("src = %x", ev.Src)
	}
	if !bytes.Contains(ev.Payload[:], []byte("WX rwxp")) {
		t.Errorf("payload lacks WX marker: %q", ev.Payload[:])
	}
	if !bytes.Contains(ev.Payload[:], []byte("/dev/shm/evil (deleted)")) {
		t.Errorf("payload lacks path: %q", ev.Payload[:])
	}

	fl := Anomaly{Kind: AnomalyFilelessExec, Pid: 88, Path: []byte("/memfd:payload (deleted)")}
	if rc := EmitAlert(ring, 5, 88, &fl); rc != 0 {
		t.Fatalf("EmitAlert fileless rc = %d", rc)
	}
	if ring.Read(&ev) != 1 {
		t.Fatal("ring read fileless returned no event")
	}
	if ev.Action != c2blue55.ActExec {
		t.Errorf("fileless action = %d, want ActExec", ev.Action)
	}
	if !bytes.Contains(ev.Payload[:], []byte("memfd")) || !bytes.Contains(ev.Payload[:], []byte("deleted")) {
		t.Errorf("fileless payload = %q", ev.Payload[:])
	}
}

func TestEncodeAlert_ZeroAlloc(t *testing.T) {
	var ev c2blue55.Event
	a := Anomaly{Kind: AnomalyInjectedLib, Pid: 5, Addr: 0x1234, Perms: PermRead | PermExec | PermShared, Path: make([]byte, 40)}
	allocs := testing.AllocsPerRun(1000, func() {
		EncodeAlert(&ev, 1, 5, &a)
	})
	if allocs != 0 {
		t.Errorf("EncodeAlert allocs = %.2f, want 0", allocs)
	}
}

// TestParseMaps_LiveSelf exécute le décodeur sur le /proc/self/maps réel du
// processus de test.
func TestParseMaps_LiveSelf(t *testing.T) {
	mapsBytes, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Skipf("/proc/self/maps unavailable: %v", err)
	}
	out := make([]Segment, 4096)
	n := ParseMaps(mapsBytes, out, len(out))
	if n == 0 {
		t.Fatal("live /proc/self/maps parsed to zero segments")
	}
	for i := range n {
		if out[i].End <= out[i].Start {
			t.Fatalf("segment %d invalid range %x-%x", i, out[i].Start, out[i].End)
		}
	}
	lines := bytes.Count(mapsBytes, []byte("\n"))
	if len(mapsBytes) > 0 && mapsBytes[len(mapsBytes)-1] != '\n' {
		lines++
	}
	if n != lines {
		t.Errorf("live maps: parsed %d segments for %d lines", n, lines)
	}
}
