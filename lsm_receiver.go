// Package c2blue55 — lsm_receiver.go
// Récepteur des traces d'une sonde eBPF-LSM, en Go pur.
//
// Un journal texte ne dit ni qui a lancé un binaire, ni sous quelle identité
// réelle, ni dans quel service, ni si le binaire est bien celui qu'il prétend
// être : une attaque « Living off the Land » (outils légitimes du système
// détournés, binaire copié et renommé) y passe pour de l'activité ordinaire.
// Un programme BPF attaché aux points d'accroche LSM du noyau (exécution,
// ouverture de fichier, connexion, chargement de module, ptrace) voit ces
// faits au moment de la décision de sécurité. Ce fichier définit le format
// d'enregistrement que ce programme dépose dans son anneau (BPF ring buffer),
// son décodage sans allocation, sa traduction en instantané d'état pour le
// silo journalier, et un récepteur qui consomme un flux d'enregistrements.
//
// Le chargement du programme BPF lui-même (compilation, vérification,
// attachement) est hors de ce paquet : le récepteur lit n'importe quel
// io.Reader qui livre des enregistrements de LSMRecordSize octets (anneau
// relu par un chargeur, fichier de capture, tube).
package c2blue55

import (
	"encoding/binary"
	"errors"
	"io"
	"strings"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55/internal/engine"
)

// LSMRecordSize est la taille fixe d'un enregistrement de la sonde (256 octets).
const LSMRecordSize = 256

// LSMRecordMagic ouvre chaque enregistrement ('LSM1' en little-endian) : un
// flux désaligné ou d'un autre format est détecté au premier enregistrement.
const LSMRecordMagic uint32 = 0x314D534C

// Points d'accroche LSM transcrits.
const (
	LSMHookBprmCheck     uint16 = 1 // bprm_check_security : exécution d'un binaire
	LSMHookFileOpen      uint16 = 2 // file_open : ouverture d'un fichier
	LSMHookSocketConnect uint16 = 3 // socket_connect : connexion sortante
	LSMHookKernelModule  uint16 = 4 // kernel_read_file / kernel_load_data : module ou firmware
	LSMHookPtrace        uint16 = 5 // ptrace_access_check : inspection d'un autre processus
	LSMHookMmapExec      uint16 = 6 // mmap_file / file_mprotect avec PROT_EXEC
)

// Drapeaux d'un enregistrement.
const (
	LSMFlagWrite       uint32 = 1 << 0 // ouverture en écriture
	LSMFlagHashValid   uint32 = 1 << 1 // BinaryHash calculé (IMA ou fs-verity)
	LSMFlagMemfd       uint32 = 1 << 2 // binaire sans fichier (memfd, fichier supprimé)
	LSMFlagDenied      uint32 = 1 << 3 // la politique LSM a refusé l'opération
	LSMFlagLoginUIDSet uint32 = 1 << 4 // LoginUID valide (session d'un utilisateur)
)

// LSMEvent est un enregistrement décodé. Disposition little-endian :
//
//	0..4     Magic       LSMRecordMagic
//	4..6     Hook        LSMHook*
//	6..8     Reserved
//	8..16    WallNs      horodatage Unix en nanosecondes (le chargeur convertit l'horloge BPF)
//	16..20   PID         identifiant du processus (tgid)
//	20..24   PPID        identifiant du parent réel
//	24..28   UID         UID réel
//	28..32   EUID        UID effectif
//	32..36   LoginUID    UID de la session d'origine (audit loginuid)
//	36..40   Flags       LSMFlag*
//	40..48   CgroupID    identifiant du cgroup v2 (service systemd, conteneur)
//	48..80   BinaryHash  SHA-256 du binaire exécuté ou du fichier visé
//	80..96   Comm        nom court du processus
//	96..112  ParentComm  nom court du parent
//	112..256 Path        chemin visé (binaire, fichier, ou « ip:port » en connexion), NUL-terminé
type LSMEvent struct {
	Hook       uint16
	WallNs     uint64
	PID        uint32
	PPID       uint32
	UID        uint32
	EUID       uint32
	LoginUID   uint32
	Flags      uint32
	CgroupID   uint64
	BinaryHash [32]byte
	Comm       [16]byte
	ParentComm [16]byte
	Path       [144]byte
}

// Erreurs du récepteur.
var (
	ErrLSMMagic = errors.New("c2lsm: signature d'enregistrement invalide")
	ErrLSMHook  = errors.New("c2lsm: point d'accroche inconnu")
)

// DecodeLSMRecord décode un enregistrement sans allocation.
func DecodeLSMRecord(src *[LSMRecordSize]byte, ev *LSMEvent) error {
	if binary.LittleEndian.Uint32(src[0:4]) != LSMRecordMagic {
		return ErrLSMMagic
	}
	ev.Hook = binary.LittleEndian.Uint16(src[4:6])
	if ev.Hook < LSMHookBprmCheck || ev.Hook > LSMHookMmapExec {
		return ErrLSMHook
	}
	ev.WallNs = binary.LittleEndian.Uint64(src[8:16])
	ev.PID = binary.LittleEndian.Uint32(src[16:20])
	ev.PPID = binary.LittleEndian.Uint32(src[20:24])
	ev.UID = binary.LittleEndian.Uint32(src[24:28])
	ev.EUID = binary.LittleEndian.Uint32(src[28:32])
	ev.LoginUID = binary.LittleEndian.Uint32(src[32:36])
	ev.Flags = binary.LittleEndian.Uint32(src[36:40])
	ev.CgroupID = binary.LittleEndian.Uint64(src[40:48])
	copy(ev.BinaryHash[:], src[48:80])
	copy(ev.Comm[:], src[80:96])
	copy(ev.ParentComm[:], src[96:112])
	copy(ev.Path[:], src[112:256])
	return nil
}

// EncodeLSMRecord écrit un enregistrement ; il sert au chargeur en Go et aux tests.
func EncodeLSMRecord(dst *[LSMRecordSize]byte, ev *LSMEvent) {
	*dst = [LSMRecordSize]byte{}
	binary.LittleEndian.PutUint32(dst[0:4], LSMRecordMagic)
	binary.LittleEndian.PutUint16(dst[4:6], ev.Hook)
	binary.LittleEndian.PutUint64(dst[8:16], ev.WallNs)
	binary.LittleEndian.PutUint32(dst[16:20], ev.PID)
	binary.LittleEndian.PutUint32(dst[20:24], ev.PPID)
	binary.LittleEndian.PutUint32(dst[24:28], ev.UID)
	binary.LittleEndian.PutUint32(dst[28:32], ev.EUID)
	binary.LittleEndian.PutUint32(dst[32:36], ev.LoginUID)
	binary.LittleEndian.PutUint32(dst[36:40], ev.Flags)
	binary.LittleEndian.PutUint64(dst[40:48], ev.CgroupID)
	copy(dst[48:80], ev.BinaryHash[:])
	copy(dst[80:96], ev.Comm[:])
	copy(dst[96:112], ev.ParentComm[:])
	copy(dst[112:256], ev.Path[:])
}

// cstr rend la chaîne NUL-terminée de b.
func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// LSMEntityID rend l'identité d'entité d'un événement : le condensat du
// binaire quand il est connu, si bien qu'un outil copié et renommé
// (/tmp/x copie de curl) garde l'identité de curl et qu'un binaire remplacé
// sous le même nom (/usr/sbin/sshd altéré) en prend une nouvelle ; à défaut
// le nom court du processus, normalisé comme un acteur de journal.
func LSMEntityID(ev *LSMEvent) uint64 {
	if ev.Flags&LSMFlagHashValid != 0 {
		return binary.LittleEndian.Uint64(ev.BinaryHash[0:8]) ^ binary.LittleEndian.Uint64(ev.BinaryHash[8:16])
	}
	return LogActorID(cstr(ev.Comm[:]))
}

// Contexte d'exécution porté par ContextFlags d'un instantané LSM.
const (
	lsmCtxRoot      uint32 = 1 << 0 // UID réel 0
	lsmCtxElevated  uint32 = 1 << 1 // EUID différent de l'UID réel (setuid, capacité)
	lsmCtxSession   uint32 = 1 << 2 // issu d'une session utilisateur (LoginUID valide)
	lsmCtxVolatile  uint32 = 1 << 3 // binaire ou fichier sous /tmp, /var/tmp, /dev/shm, /run/user, ou sans fichier
	lsmCtxDenied    uint32 = 1 << 4 // opération refusée par la politique
	lsmCtxUnhashed  uint32 = 1 << 5 // binaire sans condensat : identité par nom seulement
	lsmCtxWriteOpen uint32 = 1 << 6 // ouverture en écriture
)

// Snapshot traduit l'événement en instantané d'état pour le silo. Le
// sous-système et l'action suivent le point d'accroche ; l'entité est
// LSMEntityID ; la charge est le gabarit de la filiation « hook parent>comm
// uid=<classe> cg=<cgroup> chemin », si bien qu'une filiation inédite
// (serveur web qui lance un shell) est un gabarit rare pour le modèle de
// rareté de la baseline. La sévérité monte avec les indices d'attaque :
// exécution depuis un répertoire volatil ou sans fichier, élévation d'UID,
// chargement de module, ptrace, refus par la politique.
func (ev *LSMEvent) Snapshot() engine.ServerHealthSnapshot {
	var s engine.ServerHealthSnapshot
	s.TimestampSec = ev.WallNs / 1_000_000_000
	s.CorrelatedCount = 1
	s.HealthScore = 980
	s.Severity = engine.SeverityLow
	s.EntityID = LSMEntityID(ev)

	path := cstr(ev.Path[:])
	var ctx uint32
	if ev.UID == 0 {
		ctx |= lsmCtxRoot
	}
	if ev.EUID != ev.UID {
		ctx |= lsmCtxElevated
	}
	if ev.Flags&LSMFlagLoginUIDSet != 0 {
		ctx |= lsmCtxSession
	}
	if ev.Flags&LSMFlagMemfd != 0 || isVolatilePath(path) {
		ctx |= lsmCtxVolatile
	}
	if ev.Flags&LSMFlagDenied != 0 {
		ctx |= lsmCtxDenied
	}
	if ev.Flags&LSMFlagHashValid == 0 {
		ctx |= lsmCtxUnhashed
	}
	if ev.Flags&LSMFlagWrite != 0 {
		ctx |= lsmCtxWriteOpen
	}
	s.ContextFlags = ctx

	hook := "exec"
	switch ev.Hook {
	case LSMHookBprmCheck:
		s.Subsystem, s.Action = engine.OracleSubProc, engine.OracleActProcessSpawn
	case LSMHookFileOpen:
		s.Subsystem, s.Action, hook = engine.OracleSubStorage, engine.OracleActStateNominal, "open"
		if ev.Flags&LSMFlagWrite != 0 {
			s.Action = engine.OracleActFileMutate
		}
	case LSMHookSocketConnect:
		s.Subsystem, s.Action, hook = engine.OracleSubNet, engine.OracleActNetConnect, "connect"
	case LSMHookKernelModule:
		s.Subsystem, s.Action, hook = engine.OracleSubKernel, engine.OracleActFileMutate, "module"
		raiseSeverity(&s, engine.SeverityMedium, 700)
	case LSMHookPtrace:
		s.Subsystem, s.Action, hook = engine.OracleSubProc, engine.OracleActAnomalyBurst, "ptrace"
		raiseSeverity(&s, engine.SeverityMedium, 700)
	case LSMHookMmapExec:
		s.Subsystem, s.Action, hook = engine.OracleSubProc, engine.OracleActProcessSpawn, "mmapx"
	}
	if ctx&lsmCtxElevated != 0 {
		raiseSeverity(&s, engine.SeverityMedium, 750)
	}
	if ctx&lsmCtxVolatile != 0 && (ev.Hook == LSMHookBprmCheck || ev.Hook == LSMHookMmapExec) {
		raiseSeverity(&s, engine.SeverityHigh, 350)
	}
	if ctx&lsmCtxDenied != 0 {
		raiseSeverity(&s, engine.SeverityHigh, 400)
	}

	uidClass := "user"
	switch {
	case ev.UID == 0:
		uidClass = "root"
	case ev.UID < 1000:
		uidClass = "system"
	}
	var b strings.Builder
	b.Grow(engine.FeaturePayloadBytes)
	b.WriteString(hook)
	b.WriteByte(' ')
	b.WriteString(cstr(ev.ParentComm[:]))
	b.WriteByte('>')
	b.WriteString(cstr(ev.Comm[:]))
	b.WriteString(" uid=")
	b.WriteString(uidClass)
	if ctx&lsmCtxElevated != 0 {
		b.WriteString(" setuid")
	}
	b.WriteString(" cg=")
	b.WriteString(lsmHex(ev.CgroupID))
	b.WriteByte(' ')
	b.WriteString(path)
	msg := b.String()
	LogTemplate(&s.RawPayload, msg)

	var profile engine.C2bt_entropy_profile_t
	raw := []byte(path)
	engine.C2bt_profile_payload(raw, uint64(len(raw)), &profile)
	s.EntropyQ8 = profile.Entropy_q8
	return s
}

// lsmHex écrit v en hexadécimal, préfixé d'un « g » : le gabarit garde
// l'identité du cgroup (un service donné) au lieu de la masquer comme un nombre.
func lsmHex(v uint64) string {
	const digits = "ghijklmnopqrstuv" // alphabet hors hexadécimal, non masqué par LogTemplate
	var buf [16]byte
	i := len(buf)
	for {
		i--
		buf[i] = digits[v&15]
		v >>= 4
		if v == 0 {
			break
		}
	}
	return string(buf[i:])
}

// raiseSeverity relève la sévérité et abaisse le score, sans jamais les adoucir.
func raiseSeverity(s *engine.ServerHealthSnapshot, sev, score uint16) {
	s.Severity = max(s.Severity, sev)
	s.HealthScore = min(s.HealthScore, score)
}

// isVolatilePath dit si le chemin est sous un répertoire éphémère.
func isVolatilePath(p string) bool {
	if strings.HasPrefix(p, "memfd:") || strings.HasSuffix(p, " (deleted)") {
		return true
	}
	for _, root := range volatileRoots {
		if strings.HasPrefix(p, root) {
			return true
		}
	}
	return false
}

// LSMReceiver consomme un flux d'enregistrements de la sonde eBPF-LSM et les
// verse au silo journalier.
type LSMReceiver struct {
	silo     *DailyOracleSilo
	received uint64
	rejected uint64
}

// NewLSMReceiver rattache un récepteur à son silo.
func NewLSMReceiver(silo *DailyOracleSilo) *LSMReceiver {
	return &LSMReceiver{silo: silo}
}

// Handle verse un événement décodé au silo.
func (r *LSMReceiver) Handle(ev *LSMEvent) error {
	snap := ev.Snapshot()
	if snap.TimestampSec == 0 {
		r.rejected++
		return nil
	}
	r.received++
	return r.silo.IngestSnapshot(&snap)
}

// Consume lit des enregistrements de LSMRecordSize octets jusqu'à la fin du
// flux et rend le nombre d'événements versés. Un enregistrement à point
// d'accroche inconnu ou horodatage nul est compté comme rejeté et sauté ; une
// signature invalide arrête la lecture (flux désaligné), de même qu'un
// enregistrement tronqué en fin de flux.
func (r *LSMReceiver) Consume(src io.Reader) (int, error) {
	var rec [LSMRecordSize]byte
	var ev LSMEvent
	n := 0
	for {
		if _, err := io.ReadFull(src, rec[:]); err != nil {
			if err == io.EOF {
				return n, nil
			}
			return n, err
		}
		if err := DecodeLSMRecord(&rec, &ev); err != nil {
			if errors.Is(err, ErrLSMHook) {
				r.rejected++
				continue
			}
			return n, err
		}
		before := r.received
		if err := r.Handle(&ev); err != nil {
			return n, err
		}
		if r.received > before {
			n++
		}
	}
}

// Stats rend le nombre d'événements versés et rejetés.
func (r *LSMReceiver) Stats() (received, rejected uint64) { return r.received, r.rejected }
