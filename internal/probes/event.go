package probes

import c2blue55 "github.com/hazyhaar/c2blue55"

// RingMem est la mémoire annulaire SPSC à 1024 emplacements de 128 octets dans
// laquelle les alertes encodées sont déposées sans verrou.
type RingMem = c2blue55.Channel

// Event est l'alias vers l'événement canonique universel de 128 octets.
type Event = c2blue55.Event

// RingNet est l'interface du récepteur de trames réseau décodées.
type RingNet interface {
	Write(ev *c2blue55.Event) int
}

// EventSize est la taille contractuelle d'un événement du canal.
const EventSize = 128

// EncodeAlert transcrit une anomalie dans un Event de 128 octets. Le cache de
// sous-système reste SubProc ; l'action distingue l'exécution (fileless) de la
// cartographie (W^X, injection). Le texte descriptif est tronqué proprement à
// la capacité de la charge utile.
func EncodeAlert(ev *c2blue55.Event, tsNs uint64, pid uint32, a *Anomaly) {
	*ev = c2blue55.Event{}
	ev.Ts_ns = tsNs
	ev.Pid = pid
	ev.Subsystem = c2blue55.SubProc
	ev.Flags = c2blue55.FlagAnomaly
	ev.Src = a.Addr
	switch a.Kind {
	case AnomalyFilelessExec:
		ev.Action = c2blue55.ActExec
	default:
		ev.Action = c2blue55.ActMmapExec
	}
	encodePayload(&ev.Payload, a)
}

// EmitAlert encode une anomalie puis la dépose dans la mémoire annulaire.
// Elle retourne 0 en succès et -2 lorsque la file est saturée.
func EmitAlert(ring *RingMem, tsNs uint64, pid uint32, a *Anomaly) int {
	var ev c2blue55.Event
	EncodeAlert(&ev, tsNs, pid, a)
	return ring.Write(&ev)
}

func encodePayload(dst *[96]byte, a *Anomaly) {
	w := textWriter{b: dst[:0], max: len(dst)}
	switch a.Kind {
	case AnomalyFilelessExec:
		w.putStr("FILELESS pid=")
		w.putUint(uint64(a.Pid))
		w.putStr(" exe=")
		if indexOfStr(a.Path, "/memfd:") >= 0 {
			w.putStr("memfd ")
		}
		if indexOfStr(a.Path, "(deleted)") >= 0 {
			w.putStr("deleted ")
		}
	case AnomalyWX:
		w.putStr("WX ")
		w.putPerm(a.Perms)
		w.putStr(" pid=")
		w.putUint(uint64(a.Pid))
		w.putStr(" addr=0x")
		w.putHex(a.Addr)
		w.putByte(' ')
	case AnomalyInjectedLib:
		w.putStr("INJECT ")
		w.putPerm(a.Perms)
		w.putStr(" pid=")
		w.putUint(uint64(a.Pid))
		w.putStr(" addr=0x")
		w.putHex(a.Addr)
		w.putByte(' ')
	}
	w.putBytes(a.Path)
}

// textWriter assemble une charge utile bornée sans jamais allouer : toute
// écriture au-delà de la capacité est silencieusement abandonnée.
type textWriter struct {
	b   []byte
	max int
}

func (t *textWriter) putByte(c byte) {
	if len(t.b) < t.max {
		t.b = append(t.b, c)
	}
}

func (t *textWriter) putStr(s string) {
	for i := 0; i < len(s); i++ {
		t.putByte(s[i])
	}
}

func (t *textWriter) putBytes(p []byte) {
	for i := range p {
		t.putByte(p[i])
	}
}

func (t *textWriter) putUint(v uint64) {
	if v == 0 {
		t.putByte('0')
		return
	}
	var tmp [20]byte
	i := len(tmp)
	for v > 0 {
		i--
		tmp[i] = byte('0' + v%10)
		v /= 10
	}
	t.putBytes(tmp[i:])
}

func (t *textWriter) putHex(v uint64) {
	if v == 0 {
		t.putByte('0')
		return
	}
	var tmp [16]byte
	i := len(tmp)
	for v > 0 {
		i--
		d := byte(v & 0xf)
		if d < 10 {
			tmp[i] = '0' + d
		} else {
			tmp[i] = 'a' + (d - 10)
		}
		v >>= 4
	}
	t.putBytes(tmp[i:])
}

func (t *textWriter) putPerm(p Perm) {
	if p&PermRead != 0 {
		t.putByte('r')
	} else {
		t.putByte('-')
	}
	if p&PermWrite != 0 {
		t.putByte('w')
	} else {
		t.putByte('-')
	}
	if p&PermExec != 0 {
		t.putByte('x')
	} else {
		t.putByte('-')
	}
	if p&PermShared != 0 {
		t.putByte('s')
	} else {
		t.putByte('p')
	}
}
