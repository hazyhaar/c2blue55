package probes

// ExeFlags qualifie la cible lue dans /proc/<pid>/exe.
type ExeFlags uint8

const (
	// ExeMemfd signale une image servie depuis un descripteur memfd_create.
	ExeMemfd ExeFlags = 1 << iota
	// ExeDeleted signale une image dont le fichier de support a été supprimé.
	ExeDeleted
)

// Fileless indique une exécution sans fichier de support persistant.
func (f ExeFlags) Fileless() bool { return f != 0 }

// AnomalyKind classe une constatation de la sonde mémoire.
type AnomalyKind uint8

const (
	AnomalyFilelessExec AnomalyKind = iota + 1
	AnomalyWX
	AnomalyInjectedLib
)

// String restitue le libellé court du type d'anomalie.
func (k AnomalyKind) String() string {
	switch k {
	case AnomalyFilelessExec:
		return "fileless"
	case AnomalyWX:
		return "wx"
	case AnomalyInjectedLib:
		return "inject"
	default:
		return "unknown"
	}
}

// Anomaly décrit une constatation. Le champ Path aliase le tampon d'entrée de
// Inspect : il n'est valide que tant que ce tampon reste vivant et inchangé.
type Anomaly struct {
	Kind  AnomalyKind
	Pid   uint32
	Addr  uint64
	Perms Perm
	Path  []byte
}

// jitImageList énumère, séparés par des espaces et encadrés d'espaces, les noms
// de base des exécutables à compilation juste-à-temps autorisés à détenir des
// pages simultanément inscriptibles et exécutables.
const jitImageList = " node nodejs deno bun chrome chromium chromium-browser firefox java javaw dotnet mono electron code luajit julia wasmtime wasmer d8 qjs jsc "

// ClassifyExe qualifie la cible d'un lien /proc/<pid>/exe. La cible est
// fileless si elle contient la marque memfd_create ou la marque de suppression.
func ClassifyExe(target []byte) ExeFlags {
	var f ExeFlags
	if indexOfStr(target, "/memfd:") >= 0 {
		f |= ExeMemfd
	}
	if indexOfStr(target, "(deleted)") >= 0 {
		f |= ExeDeleted
	}
	return f
}

// isJITImage indique si la cible d'exécution correspond à un runtime à
// compilation juste-à-temps connu. La comparaison est insensible à la casse et
// n'alloue pas.
func isJITImage(target []byte) bool {
	base := basename(target)
	if len(base) == 0 || len(base) > 31 {
		return false
	}
	var fold [32]byte
	for i := range base {
		c := base[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		fold[i] = c
	}
	return tokenPresent(jitImageList, fold[:len(base)])
}

// isJITRegion reconnaît les régions anonymes nommées des moteurs de script.
func isJITRegion(path []byte) bool {
	switch len(path) {
	case 8:
		return equalBytes(path, jitAnonV8) || equalBytes(path, jitAnonJS)
	case 9:
		return equalBytes(path, jitAnonJIT) || equalBytes(path, jitAnonWasm)
	case 10:
		return equalBytes(path, jitAnonCode)
	}
	return false
}

var (
	jitAnonV8   = []byte("[anon:v8]")
	jitAnonJS   = []byte("[anon:js]")
	jitAnonJIT  = []byte("[anon:jit]")
	jitAnonWasm = []byte("[anon:wasm]")
	jitAnonCode = []byte("[anon:code]")
)

// isTempPath repère une cartographie originaire d'un répertoire temporaire
// inscriptible par tout un chacun.
func isTempPath(path []byte) bool {
	return hasPrefixStr(path, "/tmp/") ||
		hasPrefixStr(path, "/dev/shm/") ||
		hasPrefixStr(path, "/var/tmp/")
}

// Inspect analyse un processus à partir de la cible de /proc/<pid>/exe et du
// contenu de /proc/<pid>/maps. Les anomalies sont empilées dans out, plafonnées
// à limit. La fonction retourne le nombre d'anomalies retenues. Aucune
// allocation n'est effectuée.
func Inspect(pid uint32, exeTarget, mapsData []byte, out []Anomaly, limit int) int {
	if limit < 0 {
		limit = 0
	}
	if limit > len(out) {
		limit = len(out)
	}
	n := 0
	if ClassifyExe(exeTarget).Fileless() {
		addAnomaly(out, &n, limit, Anomaly{
			Kind: AnomalyFilelessExec,
			Pid:  pid,
			Path: exeTarget,
		})
	}
	jitProc := isJITImage(exeTarget)

	off := 0
	for off < len(mapsData) {
		var seg Segment
		next, ok := parseLine(mapsData, off, &seg)
		if next <= off {
			next = off + 1
		}
		off = next
		if !ok {
			continue
		}
		if seg.Perms&(PermWrite|PermExec) == (PermWrite|PermExec) && !jitProc && !isJITRegion(seg.Path) {
			addAnomaly(out, &n, limit, Anomaly{
				Kind:  AnomalyWX,
				Pid:   pid,
				Addr:  seg.Start,
				Perms: seg.Perms,
				Path:  seg.Path,
			})
		}
		if isTempPath(seg.Path) && !equalBytes(seg.Path, exeTarget) {
			addAnomaly(out, &n, limit, Anomaly{
				Kind:  AnomalyInjectedLib,
				Pid:   pid,
				Addr:  seg.Start,
				Perms: seg.Perms,
				Path:  seg.Path,
			})
		}
	}
	return n
}

func addAnomaly(out []Anomaly, n *int, limit int, a Anomaly) {
	if *n < limit {
		out[*n] = a
		*n++
	}
}
