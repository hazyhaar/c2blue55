//go:build linux

// Tests de la sonde réseau WP04 : parsing inode, classification
// d'interpréteur, détection de reverse shell sur processus réel adossé à un
// socket, corrélation PID/inode, dump NETLINK_INET_DIAG réel et egress de
// démon passif. Les données de reverse shell proviennent exclusivement du
// corpus réel reverse_shells.jsonl.
package probes

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	blue "github.com/hazyhaar/c2blue55"
)

// reverseShellDatasetPath rend le corpus reverse_shells.jsonl, rangé sous
// data, zone ignorée par git : HOROS_DATA_DIR s'il est posé, sinon data sous
// la racine du dépôt.
func reverseShellDatasetPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(testExternalDir(t, "HOROS_DATA_DIR", "data"), "wittgenstein", "reverse_shells.jsonl")
}

func TestParseSocketInode(t *testing.T) {
	cases := []struct {
		link string
		want uint64
		ok   bool
	}{
		{"socket:[12345]", 12345, true},
		{"socket:[1]", 1, true},
		{"socket:[]", 0, false},
		{"socket:[12a]", 0, false},
		{"pipe:[123]", 0, false},
		{"/run/systemd/private", 0, false},
		{"socket:[18446744073709551615]", 18446744073709551615, true},
		{"socket:[123456789012345678901]", 0, false},
	}
	for _, tc := range cases {
		got, ok := parseSocketInode([]byte(tc.link))
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("parseSocketInode(%q) = (%d,%v), attendu (%d,%v)", tc.link, got, ok, tc.want, tc.ok)
		}
	}
}

func TestClassifyInterpreter(t *testing.T) {
	cases := []struct {
		comm string
		want Interpreter
	}{
		{"bash", InterpBash},
		{"/bin/bash", InterpBash},
		{"sh", InterpSh},
		{"/usr/bin/dash", InterpSh},
		{"python3", InterpPython},
		{"python3.11", InterpPython},
		{"/usr/bin/python2", InterpPython},
		{"perl", InterpPerl},
		{"perl5.36", InterpPerl},
		{"nc", InterpNetcat},
		{"ncat", InterpNetcat},
		{"redis-server", InterpNone},
		{"ls", InterpNone},
		{"", InterpNone},
	}
	for _, tc := range cases {
		if got := ClassifyInterpreter([]byte(tc.comm)); got != tc.want {
			t.Fatalf("ClassifyInterpreter(%q) = %d, attendu %d", tc.comm, got, tc.want)
		}
	}
}

// TestParseInetDiagMessageLayout valide le décodeur sur une charge utile de
// 72 octets conforme à la disposition noyau d'inet_diag_msg.
func TestParseInetDiagMessageLayout(t *testing.T) {
	var b [inetDiagMsgLen]byte
	b[0] = unix.AF_INET
	b[1] = tcpEstablished
	binary.BigEndian.PutUint16(b[4:6], 40000)
	binary.BigEndian.PutUint16(b[6:8], 443)
	copy(b[8:24], []byte{10, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	copy(b[24:40], []byte{93, 184, 216, 34, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	binary.NativeEndian.PutUint32(b[64:68], 1000)
	binary.NativeEndian.PutUint32(b[68:72], 424242)

	got := parseInetDiagMsg(b[:])
	if got.Family != unix.AF_INET || got.State != tcpEstablished {
		t.Fatalf("famille/etat: %+v", got)
	}
	if got.SrcPort != 40000 || got.DstPort != 443 {
		t.Fatalf("ports: %d -> %d", got.SrcPort, got.DstPort)
	}
	if got.Src[0] != 10 || got.Src[3] != 5 || got.Dst[0] != 93 || got.Dst[3] != 34 {
		t.Fatalf("adresses: src=%v dst=%v", got.Src, got.Dst)
	}
	if got.UID != 1000 || got.Inode != 424242 {
		t.Fatalf("uid/inode: %d/%d", got.UID, got.Inode)
	}
}

// socketBackedInterpreter lance un interpréteur réel dont les trois flux
// standard sont adossés à un même socket Unix. Il retourne le pid, l'inode du
// socket attendu dans /proc/<pid>/fd et une fonction de nettoyage.
func socketBackedInterpreter(t *testing.T, bin string) (pid uint32, inode uint64, cleanup func()) {
	t.Helper()
	sp, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	parent, child := sp[0], sp[1]
	c1, err := unix.Dup(child)
	if err != nil {
		unix.Close(parent)
		unix.Close(child)
		t.Fatalf("Dup: %v", err)
	}
	c2, err := unix.Dup(child)
	if err != nil {
		unix.Close(parent)
		unix.Close(child)
		unix.Close(c1)
		t.Fatalf("Dup: %v", err)
	}
	f0 := os.NewFile(uintptr(child), "sock0")
	f1 := os.NewFile(uintptr(c1), "sock1")
	f2 := os.NewFile(uintptr(c2), "sock2")

	var st unix.Stat_t
	if err := unix.Fstat(child, &st); err != nil {
		t.Fatalf("Fstat: %v", err)
	}

	cmd := exec.Command(bin)
	cmd.Stdin = f0
	cmd.Stdout = f1
	cmd.Stderr = f2
	if err := cmd.Start(); err != nil {
		f0.Close()
		f1.Close()
		f2.Close()
		unix.Close(parent)
		t.Fatalf("Start(%s): %v", bin, err)
	}
	cleanup = func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		f0.Close()
		f1.Close()
		f2.Close()
		unix.Close(parent)
	}
	return uint32(cmd.Process.Pid), st.Ino, cleanup
}

func TestDetectReverseShellSocketBackedInterpreter(t *testing.T) {
	bins := []struct {
		path string
		comm []byte
	}{
		{"/bin/bash", []byte("bash")},
		{"/bin/sh", []byte("sh")},
		{"/usr/bin/python3", []byte("python3")},
		{"/usr/bin/perl", []byte("perl")},
	}
	tested := 0
	for _, b := range bins {
		if _, err := os.Stat(b.path); err != nil {
			continue
		}
		pid, wantInode, cleanup := socketBackedInterpreter(t, b.path)
		hit, ok := DetectReverseShell(DefaultProcRoot, pid, b.comm)
		gotInode := hit.Inode
		gotMask := hit.FDBitmask
		cleanup()
		if !ok {
			t.Fatalf("reverse shell non detecte pour %s (pid=%d, inode=%d)", b.path, pid, wantInode)
		}
		if gotInode != wantInode {
			t.Fatalf("%s: inode=%d, attendu %d", b.path, gotInode, wantInode)
		}
		if gotMask != 7 {
			t.Fatalf("%s: masque fd=%#x, attendu 0x7", b.path, gotMask)
		}
		tested++
	}
	if tested == 0 {
		t.Skip("aucun interpréteur de test disponible")
	}
}

func TestDetectReverseShellNegative(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("sh indisponible")
	}
	cmd := exec.Command("/bin/sh", "-c", "sleep 1")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()
	if _, ok := DetectReverseShell(DefaultProcRoot, uint32(cmd.Process.Pid), []byte("sh")); ok {
		t.Fatalf("faux positif: sh sans socket standard detecte comme reverse shell")
	}
}

// TestReverseShellDataset confronte la classification d'interpréteur et la
// détection réelle au corpus reverse_shells.jsonl, sans donnée fabriquée.
func TestReverseShellDataset(t *testing.T) {
	f, err := os.Open(reverseShellDatasetPath(t))
	if err != nil {
		t.Skipf("corpus absent: %v ; poser HOROS_DATA_DIR depuis un worktree lié", err)
	}
	defer f.Close()

	langToInterp := map[string]Interpreter{
		"bash":   InterpBash,
		"python": InterpPython,
		"perl":   InterpPerl,
		"netcat": InterpNetcat,
		"sh":     InterpSh,
	}
	langToBin := map[string]string{
		"bash":   "/bin/bash",
		"python": "/usr/bin/python3",
		"perl":   "/usr/bin/perl",
	}

	type entry struct {
		ID       string `json:"id"`
		Language string `json:"language"`
		Payload  string `json:"payload"`
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	total := 0
	classified := 0
	malformed := 0
	seenLang := map[string]bool{}
	for sc.Scan() {
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		total++
		var e entry
		lang := ""
		if err := json.Unmarshal(line, &e); err != nil {
			malformed++
			lang = languageFieldFallback(line)
		} else {
			lang = e.Language
		}
		if lang == "" {
			t.Fatalf("ligne %d sans langue exploitable", total)
		}
		seenLang[lang] = true
		want, tracked := langToInterp[lang]
		if !tracked {
			continue
		}
		if got := ClassifyInterpreter([]byte(lang)); got != want {
			t.Fatalf("ligne %d: langue %q classee %d, attendu %d", total, lang, got, want)
		}
		classified++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("lecture corpus: %v", err)
	}
	if total == 0 {
		t.Fatal("corpus vide")
	}
	if classified == 0 {
		t.Fatal("aucune entree du corpus classee")
	}

	spawned := map[string]bool{}
	for lang := range seenLang {
		if spawned[lang] {
			continue
		}
		bin, ok := langToBin[lang]
		if !ok {
			continue
		}
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		pid, wantInode, cleanup := socketBackedInterpreter(t, bin)
		hit, ok := DetectReverseShell(DefaultProcRoot, pid, []byte(lang))
		gotInode, gotMask := hit.Inode, hit.FDBitmask
		cleanup()
		if !ok || gotInode != wantInode || gotMask != 7 {
			t.Fatalf("langue %q: detection reelle invalide (ok=%v inode=%d/%d fd=%#x)", lang, ok, gotInode, wantInode, gotMask)
		}
		spawned[lang] = true
	}
	t.Logf("corpus: %d entrees, %d classees, %d lignes JSON non strictes, langues testees en reel: %v", total, classified, malformed, spawned)
}

// TestDumpInetDiagLive valide la requête binaire contre le noyau sur une
// connexion TCP réellement établie.
func TestDumpInetDiagLive(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatal("connexion non TCP")
	}
	raw, err := tcpConn.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var wantInode uint32
	if err := raw.Control(func(fd uintptr) {
		var st unix.Stat_t
		if err := unix.Fstat(int(fd), &st); err != nil {
			t.Fatalf("Fstat: %v", err)
		}
		wantInode = uint32(st.Ino)
	}); err != nil {
		t.Fatalf("Control: %v", err)
	}

	fd, err := OpenInetDiag()
	if err != nil {
		t.Skipf("NETLINK_INET_DIAG indisponible: %v", err)
	}
	defer unix.Close(fd)

	dst := make([]SocketInfo, 512)
	buf := make([]byte, 1<<16)
	socketCount, err := DumpInetDiag(fd, unix.AF_INET, unix.IPPROTO_TCP, StateMaskTCP, dst, buf, 1)
	if err != nil {
		t.Fatalf("DumpInetDiag: %v", err)
	}
	found := false
	for i := range socketCount {
		if dst[i].Inode == wantInode {
			if dst[i].State != tcpEstablished {
				t.Fatalf("etat=%d, attendu ESTABLISHED", dst[i].State)
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("inode %d absent du dump inet_diag (%d sockets lus)", wantInode, socketCount)
	}
}

func TestDaemonEgressDetection(t *testing.T) {
	var public4 [16]byte
	copy(public4[:], []byte{8, 8, 8, 8})
	var loop4 [16]byte
	copy(loop4[:], []byte{127, 0, 0, 1})

	var ula6 [16]byte
	ula6[0] = 0xfd
	var global6 [16]byte
	global6[0] = 0x20
	global6[1] = 0x01

	cases := []struct {
		name string
		comm string
		s    SocketInfo
		want bool
	}{
		{"redis sortant public", "redis-server", SocketInfo{Family: unix.AF_INET, State: tcpEstablished, Dst: public4, DstPort: 6379, Inode: 9}, true},
		{"redis SYN_SENT public", "/usr/bin/redis-server", SocketInfo{Family: unix.AF_INET, State: tcpSynSent, Dst: public4, DstPort: 4444}, true},
		{"redis boucle locale", "redis-server", SocketInfo{Family: unix.AF_INET, State: tcpEstablished, Dst: loop4}, false},
		{"redis ecoute", "redis-server", SocketInfo{Family: unix.AF_INET, State: 10, Dst: public4}, false},
		{"processus non demon", "curl", SocketInfo{Family: unix.AF_INET, State: tcpEstablished, Dst: public4}, false},
		{"postgres sortant public v6", "postgres", SocketInfo{Family: unix.AF_INET6, State: tcpEstablished, Dst: global6}, true},
		{"postgres ULA locale", "postgres", SocketInfo{Family: unix.AF_INET6, State: tcpEstablished, Dst: ula6}, false},
	}
	for _, tc := range cases {
		hit, ok := DetectDaemonEgress([]byte(tc.comm), tc.s)
		if ok != tc.want {
			t.Fatalf("%s: ok=%v, attendu %v", tc.name, ok, tc.want)
		}
		if ok && hit.Inode != tc.s.Inode {
			t.Fatalf("%s: inode=%d, attendu %d", tc.name, hit.Inode, tc.s.Inode)
		}
	}
}

// TestNetHotPathZeroAlloc vérifie que la chaîne chaude réseau (classification,
// parsing inode, transcription Event) n'alloue rien sur le tas.
func TestNetHotPathZeroAlloc(t *testing.T) {
	link := []byte("socket:[424242]")
	comm := []byte("/usr/bin/bash")
	hit := ReverseShellHit{Interp: InterpBash, Inode: 424242, FDBitmask: 7}
	var ev blue.Event

	allocs := testing.AllocsPerRun(1000, func() {
		if ino, ok := parseSocketInode(link); !ok || ino != 424242 {
			t.Fatalf("parsing inode")
		}
		if ClassifyInterpreter(comm) != InterpBash {
			t.Fatalf("classification")
		}
		TranscribeReverseShell(&ev, 42, 4242, comm, hit)
	})
	if ev.Subsystem != blue.SubNet || ev.Flags != blue.FlagBlocked|blue.FlagAnomaly {
		t.Fatalf("transcription invalide: %+v", ev)
	}
	if allocs != 0 {
		t.Fatalf("allocations tas sur le chemin chaud reseau = %v, attendu 0", allocs)
	}
}

// languageFieldFallback extrait le champ langue d'une ligne JSONL dont
// l'échappement n'est pas strictement valide, sans fabriquer de valeur.
func languageFieldFallback(line []byte) string {
	const key = `"language":"`
	_, after, ok := bytes.Cut(line, []byte(key))
	if !ok {
		return ""
	}
	rest := after
	before0, _, ok0 := bytes.Cut(rest, []byte{'"'})
	if !ok0 {
		return ""
	}
	return string(before0)
}
