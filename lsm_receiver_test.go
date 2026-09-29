package c2blue55

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

const lsmTs = uint64(1789732800) * 1_000_000_000

func lsmExec(comm, parent, path string, uid, euid uint32, binary []byte) LSMEvent {
	ev := LSMEvent{Hook: LSMHookBprmCheck, WallNs: lsmTs, PID: 4242, PPID: 1, UID: uid, EUID: euid,
		Flags: LSMFlagHashValid, CgroupID: 0x1a2b}
	ev.BinaryHash = sha256.Sum256(binary)
	copy(ev.Comm[:], comm)
	copy(ev.ParentComm[:], parent)
	copy(ev.Path[:], path)
	return ev
}

func TestLSMRecord_RoundTrip(t *testing.T) {
	ev := lsmExec("curl", "bash", "/usr/bin/curl", 1000, 1000, []byte("curl-8.0"))
	ev.LoginUID = 1000
	var rec [LSMRecordSize]byte
	EncodeLSMRecord(&rec, &ev)
	var got LSMEvent
	if err := DecodeLSMRecord(&rec, &got); err != nil || got != ev {
		t.Fatalf("aller-retour: %v", err)
	}
	if n := testing.AllocsPerRun(100, func() { _ = DecodeLSMRecord(&rec, &got) }); n != 0 {
		t.Fatalf("DecodeLSMRecord: %v allocations", n)
	}
	rec[0] ^= 1
	if err := DecodeLSMRecord(&rec, &got); !errors.Is(err, ErrLSMMagic) {
		t.Fatalf("signature: %v", err)
	}
}

// L'identité suit le contenu du binaire : un curl copié sous /tmp/x garde
// l'identité de curl ; un sshd remplacé sous le même nom en change.
func TestLSMEvent_IdentityFollowsBinary(t *testing.T) {
	curl := lsmExec("curl", "bash", "/usr/bin/curl", 1000, 1000, []byte("curl-8.0"))
	renamed := lsmExec("x", "bash", "/tmp/x", 1000, 1000, []byte("curl-8.0"))
	sshd := lsmExec("sshd", "systemd", "/usr/sbin/sshd", 0, 0, []byte("sshd-9.6"))
	trojan := lsmExec("sshd", "systemd", "/usr/sbin/sshd", 0, 0, []byte("sshd-9.6-backdoor"))
	if LSMEntityID(&curl) != LSMEntityID(&renamed) {
		t.Fatal("binaire renomme: identite perdue")
	}
	if LSMEntityID(&sshd) == LSMEntityID(&trojan) {
		t.Fatal("binaire remplace: meme identite")
	}
	nohash := curl
	nohash.Flags &^= LSMFlagHashValid
	if LSMEntityID(&nohash) != LogActorID("curl") {
		t.Fatal("sans condensat: identite par nom attendue")
	}
}

// Les indices d'attaque relèvent la sévérité : exécution depuis /tmp ou un
// memfd, élévation d'UID, refus de la politique ; la filiation est dans la charge.
func TestLSMEvent_SnapshotSeverityAndLineage(t *testing.T) {
	normal := lsmExec("curl", "bash", "/usr/bin/curl", 1000, 1000, []byte("curl"))
	s := normal.Snapshot()
	if s.Subsystem != engine.OracleSubProc || s.Action != engine.OracleActProcessSpawn || s.Severity != engine.SeverityLow ||
		s.TimestampSec != lsmTs/1_000_000_000 {
		t.Fatalf("exec ordinaire: %+v", s)
	}
	if got := string(bytes.TrimRight(s.RawPayload[:], "\x00")); got != "exec bash>curl uid=user cg=hqir /usr/bin/curl" {
		t.Fatalf("charge %q", got)
	}
	for name, ev := range map[string]LSMEvent{
		"tmp":    lsmExec("x", "nginx", "/tmp/x", 33, 33, []byte("x")),
		"memfd":  func() LSMEvent { e := lsmExec("x", "nginx", "memfd:x", 33, 33, nil); e.Flags |= LSMFlagMemfd; return e }(),
		"refus":  func() LSMEvent { e := normal; e.Flags |= LSMFlagDenied; return e }(),
		"setuid": lsmExec("pkexec", "bash", "/usr/bin/pkexec", 1000, 0, []byte("pk")),
	} {
		s := ev.Snapshot()
		want := engine.SeverityHigh
		if name == "setuid" {
			want = engine.SeverityMedium
		}
		if s.Severity != want {
			t.Errorf("%s: severite %d, attendu %d", name, s.Severity, want)
		}
	}
	// Un serveur web qui lance un shell a un gabarit distinct du shell d'une session.
	web := lsmExec("sh", "nginx", "/usr/bin/sh", 33, 33, []byte("sh"))
	user := lsmExec("sh", "sshd", "/usr/bin/sh", 1000, 1000, []byte("sh"))
	if web.Snapshot().RawPayload == user.Snapshot().RawPayload {
		t.Fatal("filiations distinctes, meme gabarit")
	}
}

// Le récepteur verse au silo les enregistrements valides, saute un point
// d'accroche inconnu, et s'arrête sur une signature invalide.
func TestLSMReceiver_Consume(t *testing.T) {
	dir := t.TempDir()
	silo := p0Silo(t, dir)
	r := NewLSMReceiver(silo)
	var stream bytes.Buffer
	var rec [LSMRecordSize]byte
	for _, ev := range []LSMEvent{
		lsmExec("curl", "bash", "/usr/bin/curl", 1000, 1000, []byte("curl")),
		{Hook: 99, WallNs: lsmTs},
		lsmExec("x", "nginx", "/tmp/x", 33, 33, []byte("x")),
	} {
		EncodeLSMRecord(&rec, &ev)
		stream.Write(rec[:])
	}
	n, err := r.Consume(bytes.NewReader(stream.Bytes()))
	if err != nil || n != 2 {
		t.Fatalf("Consume: %d, %v", n, err)
	}
	if recv, rej := r.Stats(); recv != 2 || rej != 1 {
		t.Fatalf("stats: %d versés, %d rejetés", recv, rej)
	}
	if _, active, _, _ := silo.Stats(); active != 2 {
		t.Fatalf("silo: %d entrees", active)
	}
	bad := bytes.Clone(stream.Bytes())
	bad[0] = 0
	if _, err := NewLSMReceiver(silo).Consume(bytes.NewReader(bad)); !errors.Is(err, ErrLSMMagic) {
		t.Fatalf("flux desaligne: %v", err)
	}
	if _, err := NewLSMReceiver(silo).Consume(bytes.NewReader(stream.Bytes()[:100])); err == nil {
		t.Fatal("enregistrement tronque accepte")
	}
}
