//go:build linux

// Package cinetique mesure hors chemin chaud les compteurs noyau par tâche
// (/proc/[pid]/stat, schedstat, status, io et /proc/pressure/*), calcule en
// zéro allocation (0 B/op) des quotients invariants d'épisode sans dépendance
// aux compteurs matériels PMU, maintient leurs statistiques robustes (Welford,
// médiane et MADM) et produit un différentiel sémantique structuré destiné à
// l'arbitrage hors bande (c2slm ou opérateur SOC).
package cinetique

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"os"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	// ErrTamponProcSature signale qu'un pseudo-fichier /proc n'a pas pu être lu
	// intégralement dans le tampon fixe (violation potentielle d'OBJET-INTEGRAL-001).
	ErrTamponProcSature = errors.New("cinetique: tampon de lecture /proc sature sans fin de flux")
	// ErrFormatStatInvalide signale un contenu /proc/[pid]/stat mal formé.
	ErrFormatStatInvalide = errors.New("cinetique: format /proc/stat invalide")
	// ErrFormatSchedstatInvalide signale un contenu /proc/[pid]/schedstat mal formé.
	ErrFormatSchedstatInvalide = errors.New("cinetique: format /proc/schedstat invalide")
	// ErrFormatStatusInvalide signale un contenu /proc/[pid]/status mal formé.
	ErrFormatStatusInvalide = errors.New("cinetique: format /proc/status invalide")
	// ErrFormatIOInvalide signale un contenu /proc/[pid]/io mal formé.
	ErrFormatIOInvalide = errors.New("cinetique: format /proc/io invalide")
	// ErrFormatPSIInvalide signale un contenu /proc/pressure/* mal formé.
	ErrFormatPSIInvalide = errors.New("cinetique: format /proc/pressure invalide")
	// ErrListeCPUInvalide signale une liste de coeurs /sys/devices/*/cpus mal formée.
	ErrListeCPUInvalide = errors.New("cinetique: liste de coeurs CPU invalide")
)

// ClasseCoeurCPU distingue les domaines micro-architecturaux d'un processeur hybride.
type ClasseCoeurCPU uint8

const (
	// ClasseCoeurInconnue désigne un coeur hors topologie hybride connue.
	ClasseCoeurInconnue ClasseCoeurCPU = 0
	// ClasseCoeurPerformance désigne un coeur performance (/sys/devices/cpu_core/cpus).
	ClasseCoeurPerformance ClasseCoeurCPU = 1
	// ClasseCoeurEfficience désigne un coeur efficient (/sys/devices/cpu_atom/cpus).
	ClasseCoeurEfficience ClasseCoeurCPU = 2
)

// String rend l'étiquette canonique d'une classe de coeur CPU.
func (c ClasseCoeurCPU) String() string {
	switch c {
	case ClasseCoeurPerformance:
		return "cpu_core"
	case ClasseCoeurEfficience:
		return "cpu_atom"
	default:
		return "homogene"
	}
}

// TopologieHybride conserve sous forme de masques fixes (64 bits et 1024 bits
// en tableau de valeur sans allocation) la répartition des coeurs logiques
// entre domaines performance (cpu_core) et efficience (cpu_atom).
type TopologieHybride struct {
	MasquePerformance uint64
	MasqueEfficience  uint64
	MasquePerfEtendu  [16]uint64
	MasqueEffEtendu   [16]uint64
	EstHybride        bool
}

// ConstruireTopologieHybride peuple en 0 B/op les masques 64 bits et 1024 bits
// d'une topologie CPU hybride à partir des listes d'indices performance et efficience.
func ConstruireTopologieHybride(coeursPerformance, coeursEfficience []int) TopologieHybride {
	var topologie TopologieHybride
	for _, cpu := range coeursPerformance {
		if cpu >= 0 && cpu < 1024 {
			topologie.MasquePerfEtendu[cpu>>6] |= uint64(1) << uint(cpu&63)
			if cpu < 64 {
				topologie.MasquePerformance |= uint64(1) << uint(cpu)
			}
		}
	}
	for _, cpu := range coeursEfficience {
		if cpu >= 0 && cpu < 1024 {
			topologie.MasqueEffEtendu[cpu>>6] |= uint64(1) << uint(cpu&63)
			if cpu < 64 {
				topologie.MasqueEfficience |= uint64(1) << uint(cpu)
			}
		}
	}
	topologie.EstHybride = len(coeursPerformance) > 0 && len(coeursEfficience) > 0
	return topologie
}

// ClasseDuCoeur identifie en O(1) et 0 B/op le domaine d'un coeur logique (0..1023).
func (t TopologieHybride) ClasseDuCoeur(indiceCoeur int) ClasseCoeurCPU {
	if indiceCoeur < 0 || indiceCoeur >= 1024 {
		return ClasseCoeurInconnue
	}
	mot := indiceCoeur >> 6
	bit := uint64(1) << uint(indiceCoeur&63)
	if (t.MasqueEffEtendu[mot]&bit) != 0 || (indiceCoeur < 64 && (t.MasqueEfficience&bit) != 0) {
		return ClasseCoeurEfficience
	}
	if (t.MasquePerfEtendu[mot]&bit) != 0 || (indiceCoeur < 64 && (t.MasquePerformance&bit) != 0) {
		return ClasseCoeurPerformance
	}
	return ClasseCoeurInconnue
}

// EtatCapteursNoyau documente la disponibilité effective des capteurs sur l'hôte
// (notamment l'absence ou le verrouillage des compteurs PMU matériels en VM).
type EtatCapteursNoyau struct {
	PerfEventParanoid       int  `json:"perf_event_paranoid"`
	PerfParanoidLisible     bool `json:"perf_paranoid_lisible"`
	PMUMateriellePresente   bool `json:"pmu_materielle_presente"`
	SchedstatDisponible     bool `json:"schedstat_disponible"`
	ProcIODisponible        bool `json:"proc_io_disponible"`
	PSICPULisible           bool `json:"psi_cpu_lisible"`
	TopologieHybridePresent bool `json:"topologie_hybride_presente"`
	CoeursPerformance       int  `json:"coeurs_performance"`
	CoeursEfficience        int  `json:"coeurs_efficience"`
}

// InstantaneTache regroupe les compteurs noyau d'un processus ou d'un fil Linux
// lus hors bande sans aucun appel perf_event_open.
type InstantaneTache struct {
	PID                     int
	TID                     int
	HorodatageNs            int64
	DebutTacheTicks         uint64
	UtilisateurTicks        uint64
	SystemeTicks            uint64
	FautesMineures          uint64
	FautesMajeures          uint64
	NombreFils              uint32
	CoeurDerniereExecution  int32
	VmHWMKio                uint64
	VmRSSKio                uint64
	CommutationsVolontaires uint64
	CommutationsSubies      uint64
	TempsExecutionNs        uint64
	AttenteFileNs           uint64
	TranchesOrdonnanceur    uint64
	OctetsLusLogiques       uint64
	OctetsEcritsLogiques    uint64
	AppelsLecture           uint64
	AppelsEcriture          uint64
	OctetsLusBloc           uint64
	OctetsEcritsBloc        uint64
	OctetsEcritureAnnules   uint64
}

// InstantanePressionPSI conserve les compteurs cumulatifs Pressure Stall
// Information (/proc/pressure/{cpu,io,memory}) en microsecondes.
type InstantanePressionPSI struct {
	HorodatageNs       int64
	CPUSomeTotalUs     uint64
	CPUFullTotalUs     uint64
	CPUSomeAvg10Cent   uint32
	IOSomeTotalUs      uint64
	IOFullTotalUs      uint64
	MemoireSomeTotalUs uint64
	MemoireFullTotalUs uint64
}

// CapteurProcLinux maintient un descripteur ouvert sur /proc afin d'exécuter
// toutes les lectures par openat + pread sur tampons de pile en 0 B/op.
type CapteurProcLinux struct {
	fdProc int
}

// OuvrirCapteurProcLinux ouvre le répertoire /proc avec O_DIRECTORY|O_CLOEXEC.
func OuvrirCapteurProcLinux() (*CapteurProcLinux, error) {
	fd, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("cinetique: ouverture /proc: %w", err)
	}
	return &CapteurProcLinux{fdProc: fd}, nil
}

// Fermer libère le descripteur /proc détenu par le capteur.
func (c *CapteurProcLinux) Fermer() error {
	if c == nil || c.fdProc < 0 {
		return nil
	}
	fd := c.fdProc
	c.fdProc = -1
	return unix.Close(fd)
}

// LireInstantaneProcessus capture en 0 B/op les compteurs /proc/[pid]/{stat,schedstat,status,io}.
func (c *CapteurProcLinux) LireInstantaneProcessus(pid int, horodatageNs int64) (InstantaneTache, error) {
	return c.lireCible(pid, 0, horodatageNs)
}

// LireInstantaneFil capture en 0 B/op les compteurs propres au fil /proc/[pid]/task/[tid]/*.
func (c *CapteurProcLinux) LireInstantaneFil(pid, tid int, horodatageNs int64) (InstantaneTache, error) {
	return c.lireCible(pid, tid, horodatageNs)
}

func (c *CapteurProcLinux) lireCible(pid, tid int, horodatageNs int64) (InstantaneTache, error) {
	var instantane InstantaneTache
	if pid <= 0 || tid < 0 {
		return instantane, ErrFormatStatInvalide
	}
	fdRacine := unix.AT_FDCWD
	prefixeAbsolu := true
	if c != nil && c.fdProc >= 0 {
		fdRacine = c.fdProc
		prefixeAbsolu = false
	}

	var cheminOctets [96]byte
	var tamponCourt [1024]byte
	var tamponStatus [8192]byte

	cheminStat := formaterCheminProc(cheminOctets[:0], prefixeAbsolu, pid, tid, "stat")
	nStat, err := lireFichierProcComplet(fdRacine, cheminStat, tamponCourt[:])
	if err != nil {
		return instantane, err
	}
	if err := AnalyserStatProc(tamponCourt[:nStat], &instantane); err != nil {
		return instantane, err
	}

	cheminSched := formaterCheminProc(cheminOctets[:0], prefixeAbsolu, pid, tid, "schedstat")
	nSched, err := lireFichierProcComplet(fdRacine, cheminSched, tamponCourt[:])
	if err != nil {
		return instantane, err
	}
	if err := AnalyserSchedstatProc(tamponCourt[:nSched], &instantane); err != nil {
		return instantane, err
	}

	cheminStatus := formaterCheminProc(cheminOctets[:0], prefixeAbsolu, pid, tid, "status")
	nStatus, err := lireFichierProcComplet(fdRacine, cheminStatus, tamponStatus[:])
	if err != nil {
		return instantane, err
	}
	if err := AnalyserStatusProc(tamponStatus[:nStatus], &instantane); err != nil {
		return instantane, err
	}

	cheminIO := formaterCheminProc(cheminOctets[:0], prefixeAbsolu, pid, tid, "io")
	nIO, err := lireFichierProcComplet(fdRacine, cheminIO, tamponCourt[:])
	if err != nil {
		return instantane, err
	}
	if err := AnalyserIOProc(tamponCourt[:nIO], &instantane); err != nil {
		return instantane, err
	}

	// Dans Linux fs/proc/, /proc/[pid]/stat et /proc/[pid]/io agrègent tous les fils
	// du groupe de tâches, mais /proc/[pid]/schedstat et les compteurs de commutations
	// de /proc/[pid]/status ne décrivent que le fil leader tgid. Lors d'une lecture de
	// processus complet (tid == 0) multi-fils, on agrège en 0 B/op tous les fils vivants
	// de /proc/[pid]/task afin d'aligner le numérateur CPU/ordonnanceur sur le dénominateur E/S.
	if tid == 0 && instantane.NombreFils > 1 {
		if errAgreg := agregerFilsSecondairesProcessus(
			fdRacine,
			prefixeAbsolu,
			pid,
			&instantane,
			tamponCourt[:],
			tamponStatus[:],
		); errAgreg != nil {
			return instantane, errAgreg
		}
	}

	instantane.PID = pid
	if tid > 0 {
		instantane.TID = tid
	} else {
		instantane.TID = pid
	}
	instantane.HorodatageNs = horodatageNs
	return instantane, nil
}

func additionnerSatureProc(a, b uint64) uint64 {
	somme, retenue := bits.Add64(a, b, 0)
	if retenue != 0 {
		return math.MaxUint64
	}
	return somme
}

func agregerFilsSecondairesProcessus(
	fdRacine int,
	prefixeAbsolu bool,
	pid int,
	cible *InstantaneTache,
	tamponCourt []byte,
	tamponStatus []byte,
) error {
	var cheminTask [64]byte
	curseurTask := cheminTask[:0]
	if prefixeAbsolu {
		curseurTask = append(curseurTask, "/proc/"...)
	}
	curseurTask = strconv.AppendInt(curseurTask, int64(pid), 10)
	curseurTask = append(curseurTask, "/task"...)
	curseurTask = append(curseurTask, 0)

	rOpen, _, errnoOpen := unix.Syscall6(
		unix.SYS_OPENAT,
		uintptr(fdRacine),
		uintptr(unsafe.Pointer(&curseurTask[0])),
		uintptr(unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC),
		0, 0, 0,
	)
	runtime.KeepAlive(curseurTask)
	if errnoOpen != 0 {
		return errnoOpen
	}
	fdTask := uintptr(rOpen)

	var tamponDir [4096]byte
	var cheminRel [48]byte

	for {
		nDir, _, errnoDir := unix.Syscall(
			unix.SYS_GETDENTS64,
			fdTask,
			uintptr(unsafe.Pointer(&tamponDir[0])),
			uintptr(len(tamponDir)),
		)
		runtime.KeepAlive(&tamponDir)
		if errnoDir != 0 {
			if errnoDir == unix.EINTR {
				continue
			}
			_, _, _ = unix.Syscall(unix.SYS_CLOSE, fdTask, 0, 0)
			return errnoDir
		}
		if nDir == 0 {
			break
		}

		for offset := 0; offset+19 <= int(nDir); {
			reclen := int(uint16(tamponDir[offset+16]) | uint16(tamponDir[offset+17])<<8)
			if reclen < 19 || offset+reclen > int(nDir) {
				break
			}
			champNom := tamponDir[offset+19 : offset+reclen]
			offset += reclen

			finNom := bytes.IndexByte(champNom, 0)
			if finNom <= 0 {
				continue
			}
			nom := champNom[:finNom]
			if nom[0] < '0' || nom[0] > '9' {
				continue
			}
			tidFilU64, okTid := parserUintDecimal(nom)
			if !okTid || tidFilU64 == 0 || int(tidFilU64) == pid {
				continue
			}

			curRelSched := append(cheminRel[:0], nom...)
			curRelSched = append(curRelSched, "/schedstat"...)
			curRelSched = append(curRelSched, 0)
			nSched, errSched := lireFichierProcComplet(int(fdTask), curRelSched, tamponCourt)
			if errSched != nil {
				if errSched == unix.ENOENT || errSched == unix.ESRCH {
					continue
				}
				_, _, _ = unix.Syscall(unix.SYS_CLOSE, fdTask, 0, 0)
				return errSched
			}
			var snapFil InstantaneTache
			if errDec := AnalyserSchedstatProc(tamponCourt[:nSched], &snapFil); errDec != nil {
				_, _, _ = unix.Syscall(unix.SYS_CLOSE, fdTask, 0, 0)
				return errDec
			}

			curRelStatus := append(cheminRel[:0], nom...)
			curRelStatus = append(curRelStatus, "/status"...)
			curRelStatus = append(curRelStatus, 0)
			nStatFil, errStatFil := lireFichierProcComplet(int(fdTask), curRelStatus, tamponStatus)
			if errStatFil != nil {
				if errStatFil != unix.ENOENT && errStatFil != unix.ESRCH {
					_, _, _ = unix.Syscall(unix.SYS_CLOSE, fdTask, 0, 0)
					return errStatFil
				}
			} else if errDecStat := AnalyserStatusProc(tamponStatus[:nStatFil], &snapFil); errDecStat != nil {
				_, _, _ = unix.Syscall(unix.SYS_CLOSE, fdTask, 0, 0)
				return errDecStat
			}

			cible.TempsExecutionNs = additionnerSatureProc(cible.TempsExecutionNs, snapFil.TempsExecutionNs)
			cible.AttenteFileNs = additionnerSatureProc(cible.AttenteFileNs, snapFil.AttenteFileNs)
			cible.TranchesOrdonnanceur = additionnerSatureProc(cible.TranchesOrdonnanceur, snapFil.TranchesOrdonnanceur)
			cible.CommutationsVolontaires = additionnerSatureProc(cible.CommutationsVolontaires, snapFil.CommutationsVolontaires)
			cible.CommutationsSubies = additionnerSatureProc(cible.CommutationsSubies, snapFil.CommutationsSubies)
		}
	}

	if _, _, errnoClose := unix.Syscall(unix.SYS_CLOSE, fdTask, 0, 0); errnoClose != 0 {
		return errnoClose
	}
	return nil
}

// LirePressionPSI capture en 0 B/op l'état courant de /proc/pressure/{cpu,io,memory}.
func (c *CapteurProcLinux) LirePressionPSI(horodatageNs int64) (InstantanePressionPSI, error) {
	var instantane InstantanePressionPSI
	instantane.HorodatageNs = horodatageNs

	fdRacine := unix.AT_FDCWD
	cheminCPU := "/proc/pressure/cpu"
	cheminIO := "/proc/pressure/io"
	cheminMem := "/proc/pressure/memory"
	if c != nil && c.fdProc >= 0 {
		fdRacine = c.fdProc
		cheminCPU = "pressure/cpu"
		cheminIO = "pressure/io"
		cheminMem = "pressure/memory"
	}

	var tampon [512]byte
	nCPU, err := lireCheminStatiqueProc(fdRacine, cheminCPU, tampon[:])
	if err != nil {
		return instantane, err
	}
	cpuSome, cpuFull, cpuAvg10, err := AnalyserFichierPSI(tampon[:nCPU])
	if err != nil {
		return instantane, err
	}
	instantane.CPUSomeTotalUs = cpuSome
	instantane.CPUFullTotalUs = cpuFull
	instantane.CPUSomeAvg10Cent = cpuAvg10

	nIO, err := lireCheminStatiqueProc(fdRacine, cheminIO, tampon[:])
	if err != nil {
		return instantane, err
	}
	ioSome, ioFull, _, err := AnalyserFichierPSI(tampon[:nIO])
	if err != nil {
		return instantane, err
	}
	instantane.IOSomeTotalUs = ioSome
	instantane.IOFullTotalUs = ioFull

	nMem, err := lireCheminStatiqueProc(fdRacine, cheminMem, tampon[:])
	if err != nil {
		return instantane, err
	}
	memSome, memFull, _, err := AnalyserFichierPSI(tampon[:nMem])
	if err != nil {
		return instantane, err
	}
	instantane.MemoireSomeTotalUs = memSome
	instantane.MemoireFullTotalUs = memFull

	return instantane, nil
}

func formaterCheminProc(dst []byte, prefixeAbsolu bool, pid, tid int, feuille string) []byte {
	if prefixeAbsolu {
		dst = append(dst, "/proc/"...)
	}
	dst = strconv.AppendInt(dst, int64(pid), 10)
	if tid > 0 {
		dst = append(dst, "/task/"...)
		dst = strconv.AppendInt(dst, int64(tid), 10)
	}
	dst = append(dst, '/')
	dst = append(dst, feuille...)
	dst = append(dst, 0) // terminateur NUL pour openat sans allocation
	return dst
}

func lireCheminStatiqueProc(fdRacine int, chemin string, tampon []byte) (int, error) {
	var cheminOctets [64]byte
	curseur := append(cheminOctets[:0], chemin...)
	curseur = append(curseur, 0)
	return lireFichierProcComplet(fdRacine, curseur, tampon)
}

func lireFluxCompletFD(fd uintptr, tampon []byte) (int, error) {
	if len(tampon) == 0 {
		return 0, unix.EINVAL
	}
	totalLu := 0
	for totalLu < len(tampon) {
		tranche := tampon[totalLu:]
		nLu, _, errnoRead := unix.Syscall(
			unix.SYS_READ,
			fd,
			uintptr(unsafe.Pointer(&tranche[0])),
			uintptr(len(tranche)),
		)
		runtime.KeepAlive(tampon)
		if errnoRead != 0 {
			if errnoRead == unix.EINTR {
				continue
			}
			return 0, errnoRead
		}
		if nLu == 0 {
			break
		}
		totalLu += int(nLu)
	}
	if totalLu == len(tampon) {
		var sentinelle [1]byte
		for {
			nExtra, _, errnoExtra := unix.Syscall(
				unix.SYS_READ,
				fd,
				uintptr(unsafe.Pointer(&sentinelle[0])),
				1,
			)
			runtime.KeepAlive(&sentinelle)
			if errnoExtra != 0 {
				if errnoExtra == unix.EINTR {
					continue
				}
				return 0, errnoExtra
			}
			if nExtra > 0 {
				return 0, ErrTamponProcSature
			}
			break
		}
	}
	return totalLu, nil
}

func lireFichierProcComplet(fdRacine int, cheminNul []byte, tampon []byte) (int, error) {
	if len(cheminNul) < 2 || cheminNul[len(cheminNul)-1] != 0 || len(tampon) == 0 {
		return 0, unix.EINVAL
	}
	r1, _, errnoOpen := unix.Syscall6(
		unix.SYS_OPENAT,
		uintptr(fdRacine),
		uintptr(unsafe.Pointer(&cheminNul[0])),
		uintptr(unix.O_RDONLY|unix.O_CLOEXEC),
		0, 0, 0,
	)
	runtime.KeepAlive(cheminNul)
	if errnoOpen != 0 {
		return 0, errnoOpen
	}
	fd := uintptr(r1)
	totalLu, errLecture := lireFluxCompletFD(fd, tampon)
	_, _, errnoClose := unix.Syscall(unix.SYS_CLOSE, fd, 0, 0)
	if errLecture != nil {
		return 0, errLecture
	}
	if errnoClose != 0 {
		return 0, errnoClose
	}
	return totalLu, nil
}

// AnalyserStatProc décode intégralement un contenu /proc/[pid]/stat en 0 B/op.
// Exige la présence du saut de ligne final pour garantir l'absence de troncature.
func AnalyserStatProc(octets []byte, cible *InstantaneTache) error {
	if cible == nil || len(octets) == 0 || octets[len(octets)-1] != '\n' {
		if len(octets) > 0 && octets[len(octets)-1] != '\n' {
			return ErrTamponProcSature
		}
		return ErrFormatStatInvalide
	}
	debutComm := bytes.IndexByte(octets, '(')
	finComm := bytes.LastIndexByte(octets, ')')
	if debutComm <= 0 || finComm <= debutComm || finComm+2 >= len(octets) {
		return ErrFormatStatInvalide
	}
	pid64, okPID := parserUintDecimal(octets[:debutComm-1])
	if !okPID || octets[debutComm-1] != ' ' || octets[finComm+1] != ' ' {
		return ErrFormatStatInvalide
	}

	reste := octets[finComm+2 : len(octets)-1]
	// Indices 0-basés après "(comm) " :
	// 0:state(#3), 7:minflt(#10), 9:majflt(#12), 11:utime(#14), 12:stime(#15),
	// 17:num_threads(#20), 19:starttime(#22), 36:processor(#39).
	indiceChamp := 0
	curseur := 0
	var minflt, majflt, utime, stime, numThreads, starttime uint64
	var processeur int64 = -1
	champsRequis := 0

	for curseur < len(reste) {
		for curseur < len(reste) && reste[curseur] == ' ' {
			curseur++
		}
		if curseur >= len(reste) {
			break
		}
		finJetons := curseur
		for finJetons < len(reste) && reste[finJetons] != ' ' {
			finJetons++
		}
		jeton := reste[curseur:finJetons]
		var okJeton bool
		switch indiceChamp {
		case 7:
			minflt, okJeton = parserUintDecimal(jeton)
			if !okJeton {
				return ErrFormatStatInvalide
			}
			champsRequis++
		case 9:
			majflt, okJeton = parserUintDecimal(jeton)
			if !okJeton {
				return ErrFormatStatInvalide
			}
			champsRequis++
		case 11:
			utime, okJeton = parserUintDecimal(jeton)
			if !okJeton {
				return ErrFormatStatInvalide
			}
			champsRequis++
		case 12:
			stime, okJeton = parserUintDecimal(jeton)
			if !okJeton {
				return ErrFormatStatInvalide
			}
			champsRequis++
		case 17:
			numThreads, okJeton = parserUintDecimal(jeton)
			if !okJeton {
				return ErrFormatStatInvalide
			}
			champsRequis++
		case 19:
			starttime, okJeton = parserUintDecimal(jeton)
			if !okJeton {
				return ErrFormatStatInvalide
			}
			champsRequis++
		case 36:
			processeur, okJeton = parserIntDecimal(jeton)
			if !okJeton {
				return ErrFormatStatInvalide
			}
			champsRequis++
		}
		indiceChamp++
		curseur = finJetons
	}

	if champsRequis < 7 {
		return ErrFormatStatInvalide
	}
	cible.PID = int(pid64)
	cible.FautesMineures = minflt
	cible.FautesMajeures = majflt
	cible.UtilisateurTicks = utime
	cible.SystemeTicks = stime
	cible.NombreFils = uint32(numThreads)
	cible.DebutTacheTicks = starttime
	cible.CoeurDerniereExecution = int32(processeur)
	return nil
}

// AnalyserSchedstatProc décode /proc/[pid]/schedstat ("run_ns wait_ns slices\n") en 0 B/op.
func AnalyserSchedstatProc(octets []byte, cible *InstantaneTache) error {
	if cible == nil || len(octets) == 0 {
		return ErrFormatSchedstatInvalide
	}
	if octets[len(octets)-1] != '\n' {
		return ErrTamponProcSature
	}
	ligne := octets[:len(octets)-1]
	esp1 := bytes.IndexByte(ligne, ' ')
	if esp1 <= 0 {
		return ErrFormatSchedstatInvalide
	}
	reste := ligne[esp1+1:]
	esp2 := bytes.IndexByte(reste, ' ')
	if esp2 <= 0 || esp2+1 >= len(reste) {
		return ErrFormatSchedstatInvalide
	}
	execNs, ok1 := parserUintDecimal(ligne[:esp1])
	attenteNs, ok2 := parserUintDecimal(reste[:esp2])
	tranches, ok3 := parserUintDecimal(reste[esp2+1:])
	if !ok1 || !ok2 || !ok3 {
		return ErrFormatSchedstatInvalide
	}
	cible.TempsExecutionNs = execNs
	cible.AttenteFileNs = attenteNs
	cible.TranchesOrdonnanceur = tranches
	return nil
}

// AnalyserStatusProc extrait en 0 B/op VmHWM, VmRSS, Threads et les commutations
// de contexte volontaires et involontaires depuis /proc/[pid]/status.
func AnalyserStatusProc(octets []byte, cible *InstantaneTache) error {
	if cible == nil || len(octets) == 0 {
		return ErrFormatStatusInvalide
	}
	if octets[len(octets)-1] != '\n' {
		return ErrTamponProcSature
	}
	trouveVolontaire := false
	trouveSubie := false
	curseur := 0
	for curseur < len(octets) {
		finLigne := bytes.IndexByte(octets[curseur:], '\n')
		if finLigne < 0 {
			return ErrTamponProcSature
		}
		ligne := octets[curseur : curseur+finLigne]
		curseur += finLigne + 1

		switch {
		case bytes.HasPrefix(ligne, []byte("VmHWM:")):
			kio, ok := extrairePremierUintApresDeuxPoints(ligne[len("VmHWM:"):])
			if !ok {
				return ErrFormatStatusInvalide
			}
			cible.VmHWMKio = kio
		case bytes.HasPrefix(ligne, []byte("VmRSS:")):
			kio, ok := extrairePremierUintApresDeuxPoints(ligne[len("VmRSS:"):])
			if !ok {
				return ErrFormatStatusInvalide
			}
			cible.VmRSSKio = kio
		case bytes.HasPrefix(ligne, []byte("Threads:")):
			nbFils, ok := extrairePremierUintApresDeuxPoints(ligne[len("Threads:"):])
			if !ok {
				return ErrFormatStatusInvalide
			}
			cible.NombreFils = uint32(nbFils)
		case bytes.HasPrefix(ligne, []byte("voluntary_ctxt_switches:")):
			volontaires, ok := extrairePremierUintApresDeuxPoints(ligne[len("voluntary_ctxt_switches:"):])
			if !ok {
				return ErrFormatStatusInvalide
			}
			cible.CommutationsVolontaires = volontaires
			trouveVolontaire = true
		case bytes.HasPrefix(ligne, []byte("nonvoluntary_ctxt_switches:")):
			subies, ok := extrairePremierUintApresDeuxPoints(ligne[len("nonvoluntary_ctxt_switches:"):])
			if !ok {
				return ErrFormatStatusInvalide
			}
			cible.CommutationsSubies = subies
			trouveSubie = true
		}
	}
	if !trouveVolontaire || !trouveSubie {
		return ErrFormatStatusInvalide
	}
	return nil
}

// AnalyserIOProc extrait en 0 B/op les 7 compteurs de /proc/[pid]/io.
func AnalyserIOProc(octets []byte, cible *InstantaneTache) error {
	if cible == nil || len(octets) == 0 {
		return ErrFormatIOInvalide
	}
	if octets[len(octets)-1] != '\n' {
		return ErrTamponProcSature
	}
	masqueChamps := uint8(0)
	curseur := 0
	for curseur < len(octets) {
		finLigne := bytes.IndexByte(octets[curseur:], '\n')
		if finLigne < 0 {
			return ErrTamponProcSature
		}
		ligne := octets[curseur : curseur+finLigne]
		curseur += finLigne + 1
		if len(ligne) == 0 {
			continue
		}
		switch {
		case bytes.HasPrefix(ligne, []byte("rchar:")):
			nombre, ok := extrairePremierUintApresDeuxPoints(ligne[len("rchar:"):])
			if !ok {
				return ErrFormatIOInvalide
			}
			cible.OctetsLusLogiques = nombre
			masqueChamps |= 1 << 0
		case bytes.HasPrefix(ligne, []byte("wchar:")):
			nombre, ok := extrairePremierUintApresDeuxPoints(ligne[len("wchar:"):])
			if !ok {
				return ErrFormatIOInvalide
			}
			cible.OctetsEcritsLogiques = nombre
			masqueChamps |= 1 << 1
		case bytes.HasPrefix(ligne, []byte("syscr:")):
			nombre, ok := extrairePremierUintApresDeuxPoints(ligne[len("syscr:"):])
			if !ok {
				return ErrFormatIOInvalide
			}
			cible.AppelsLecture = nombre
			masqueChamps |= 1 << 2
		case bytes.HasPrefix(ligne, []byte("syscw:")):
			nombre, ok := extrairePremierUintApresDeuxPoints(ligne[len("syscw:"):])
			if !ok {
				return ErrFormatIOInvalide
			}
			cible.AppelsEcriture = nombre
			masqueChamps |= 1 << 3
		case bytes.HasPrefix(ligne, []byte("read_bytes:")):
			nombre, ok := extrairePremierUintApresDeuxPoints(ligne[len("read_bytes:"):])
			if !ok {
				return ErrFormatIOInvalide
			}
			cible.OctetsLusBloc = nombre
			masqueChamps |= 1 << 4
		case bytes.HasPrefix(ligne, []byte("write_bytes:")):
			nombre, ok := extrairePremierUintApresDeuxPoints(ligne[len("write_bytes:"):])
			if !ok {
				return ErrFormatIOInvalide
			}
			cible.OctetsEcritsBloc = nombre
			masqueChamps |= 1 << 5
		case bytes.HasPrefix(ligne, []byte("cancelled_write_bytes:")):
			nombre, ok := extrairePremierUintApresDeuxPoints(ligne[len("cancelled_write_bytes:"):])
			if !ok {
				return ErrFormatIOInvalide
			}
			cible.OctetsEcritureAnnules = nombre
			masqueChamps |= 1 << 6
		}
	}
	if (masqueChamps & 0x3F) != 0x3F {
		return ErrFormatIOInvalide
	}
	return nil
}

// AnalyserFichierPSI extrait en 0 B/op les compteurs some/full d'un fichier /proc/pressure/*.
func AnalyserFichierPSI(octets []byte) (someTotalUs uint64, fullTotalUs uint64, someAvg10Cent uint32, err error) {
	if len(octets) == 0 {
		return 0, 0, 0, ErrFormatPSIInvalide
	}
	if octets[len(octets)-1] != '\n' {
		return 0, 0, 0, ErrTamponProcSature
	}
	trouveSome := false
	curseur := 0
	for curseur < len(octets) {
		finLigne := bytes.IndexByte(octets[curseur:], '\n')
		if finLigne < 0 {
			return 0, 0, 0, ErrTamponProcSature
		}
		ligne := octets[curseur : curseur+finLigne]
		curseur += finLigne + 1
		if bytes.HasPrefix(ligne, []byte("some ")) {
			totalUs, avg10, ok := extraireChampsLignePSI(ligne[len("some "):])
			if !ok {
				return 0, 0, 0, ErrFormatPSIInvalide
			}
			someTotalUs = totalUs
			someAvg10Cent = avg10
			trouveSome = true
		} else if bytes.HasPrefix(ligne, []byte("full ")) {
			totalUs, _, ok := extraireChampsLignePSI(ligne[len("full "):])
			if !ok {
				return 0, 0, 0, ErrFormatPSIInvalide
			}
			fullTotalUs = totalUs
		}
	}
	if !trouveSome {
		return 0, 0, 0, ErrFormatPSIInvalide
	}
	return someTotalUs, fullTotalUs, someAvg10Cent, nil
}

func extraireChampsLignePSI(reste []byte) (totalUs uint64, avg10Cent uint32, ok bool) {
	trouveTotal := false
	trouveAvg10 := false
	curseur := 0
	for curseur < len(reste) {
		for curseur < len(reste) && reste[curseur] == ' ' {
			curseur++
		}
		if curseur >= len(reste) {
			break
		}
		fin := curseur
		for fin < len(reste) && reste[fin] != ' ' {
			fin++
		}
		jeton := reste[curseur:fin]
		if bytes.HasPrefix(jeton, []byte("total=")) {
			valTotal, okTot := parserUintDecimal(jeton[len("total="):])
			if !okTot {
				return 0, 0, false
			}
			totalUs = valTotal
			trouveTotal = true
		} else if bytes.HasPrefix(jeton, []byte("avg10=")) {
			cent, okAvg := parserCentiemesFixes(jeton[len("avg10="):])
			if !okAvg {
				return 0, 0, false
			}
			avg10Cent = cent
			trouveAvg10 = true
		}
		curseur = fin
	}
	return totalUs, avg10Cent, trouveTotal && trouveAvg10
}

// AnalyserListeCPUs convertit une liste Linux ("0-7,10-15\n") en tranche d'indices et masque 64 bits.
func AnalyserListeCPUs(texte string) ([]int, uint64, error) {
	propre := strings.TrimSpace(texte)
	if propre == "" {
		return nil, 0, ErrListeCPUInvalide
	}
	var indices []int
	var masque uint64
	for segment := range strings.SplitSeq(propre, ",") {
		segment = strings.TrimSpace(segment)
		if segment == "" {
			return nil, 0, ErrListeCPUInvalide
		}
		if tiret := strings.IndexByte(segment, '-'); tiret >= 0 {
			debut, errDebut := strconv.Atoi(segment[:tiret])
			fin, errFin := strconv.Atoi(segment[tiret+1:])
			if errDebut != nil || errFin != nil || debut < 0 || fin < debut || fin >= 1024 {
				return nil, 0, ErrListeCPUInvalide
			}
			for cpu := debut; cpu <= fin; cpu++ {
				indices = append(indices, cpu)
				if cpu < 64 {
					masque |= uint64(1) << uint(cpu)
				}
			}
		} else {
			cpu, errCPU := strconv.Atoi(segment)
			if errCPU != nil || cpu < 0 || cpu >= 1024 {
				return nil, 0, ErrListeCPUInvalide
			}
			indices = append(indices, cpu)
			if cpu < 64 {
				masque |= uint64(1) << uint(cpu)
			}
		}
	}
	return indices, masque, nil
}

// ChargerTopologieHybride lit hors chemin chaud /sys/devices/cpu_core/cpus et
// /sys/devices/cpu_atom/cpus afin de détecter une micro-architecture hybride.
func ChargerTopologieHybride() (TopologieHybride, []int, []int) {
	octetsCore, errCore := lirePetitFichierSysfs("/sys/devices/cpu_core/cpus")
	octetsAtom, errAtom := lirePetitFichierSysfs("/sys/devices/cpu_atom/cpus")
	var listeCore, listeAtom []int
	if errCore == nil {
		if coeurs, _, err := AnalyserListeCPUs(octetsCore); err == nil {
			listeCore = coeurs
		}
	}
	if errAtom == nil {
		if coeurs, _, err := AnalyserListeCPUs(octetsAtom); err == nil {
			listeAtom = coeurs
		}
	}
	return ConstruireTopologieHybride(listeCore, listeAtom), listeCore, listeAtom
}

// VerifierDisponibiliteCapteursNoyau dresse l'inventaire factuel des capteurs
// noyau accessibles sans jamais recourir à perf_event_open.
func VerifierDisponibiliteCapteursNoyau() EtatCapteursNoyau {
	var etat EtatCapteursNoyau
	if texteParanoid, err := lirePetitFichierSysfs("/proc/sys/kernel/perf_event_paranoid"); err == nil {
		if niveau, errConv := strconv.Atoi(strings.TrimSpace(texteParanoid)); errConv == nil {
			etat.PerfEventParanoid = niveau
			etat.PerfParanoidLisible = true
		}
	}
	for _, cheminPMU := range [...]string{
		"/sys/bus/event_source/devices/cpu",
		"/sys/bus/event_source/devices/cpu_core",
		"/sys/bus/event_source/devices/cpu_atom",
	} {
		if infoPMU, err := os.Stat(cheminPMU); err == nil && infoPMU.IsDir() {
			etat.PMUMateriellePresente = true
			break
		}
	}
	capteur, errCapteur := OuvrirCapteurProcLinux()
	if errCapteur == nil {
		var tampon [1024]byte
		var sonde InstantaneTache
		if nSched, errS := lireCheminStatiqueProc(capteur.fdProc, "self/schedstat", tampon[:]); errS == nil {
			if AnalyserSchedstatProc(tampon[:nSched], &sonde) == nil {
				etat.SchedstatDisponible = true
			}
		}
		if nIO, errI := lireCheminStatiqueProc(capteur.fdProc, "self/io", tampon[:]); errI == nil {
			if AnalyserIOProc(tampon[:nIO], &sonde) == nil {
				etat.ProcIODisponible = true
			}
		}
		if _, errPSI := capteur.LirePressionPSI(1); errPSI == nil {
			etat.PSICPULisible = true
		}
		_ = capteur.Fermer()
	}
	topo, listeCore, listeAtom := ChargerTopologieHybride()
	etat.TopologieHybridePresent = topo.EstHybride
	etat.CoeursPerformance = len(listeCore)
	etat.CoeursEfficience = len(listeAtom)
	return etat
}

func lirePetitFichierSysfs(chemin string) (string, error) {
	var tampon [256]byte
	fd, err := unix.Open(chemin, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	n, errLecture := unix.Read(fd, tampon[:])
	_ = unix.Close(fd)
	if errLecture != nil {
		return "", errLecture
	}
	if n == len(tampon) {
		return "", ErrTamponProcSature
	}
	return string(tampon[:n]), nil
}

func extrairePremierUintApresDeuxPoints(reste []byte) (uint64, bool) {
	idx := 0
	for idx < len(reste) && (reste[idx] == ' ' || reste[idx] == '\t') {
		idx++
	}
	if idx >= len(reste) {
		return 0, false
	}
	fin := idx
	for fin < len(reste) && reste[fin] >= '0' && reste[fin] <= '9' {
		fin++
	}
	if fin == idx {
		return 0, false
	}
	return parserUintDecimal(reste[idx:fin])
}

func parserUintDecimal(octets []byte) (uint64, bool) {
	if len(octets) == 0 {
		return 0, false
	}
	var acc uint64
	for _, c := range octets {
		if c < '0' || c > '9' {
			return 0, false
		}
		chiffre := uint64(c - '0')
		if acc > (uint64(18446744073709551615)-chiffre)/10 {
			return 0, false
		}
		acc = acc*10 + chiffre
	}
	return acc, true
}

func parserIntDecimal(octets []byte) (int64, bool) {
	if len(octets) == 0 {
		return 0, false
	}
	negatif := false
	if octets[0] == '-' {
		negatif = true
		octets = octets[1:]
	}
	mag, ok := parserUintDecimal(octets)
	if !ok || mag > 9223372036854775807 {
		return 0, false
	}
	if negatif {
		return -int64(mag), true
	}
	return int64(mag), true
}

func parserCentiemesFixes(octets []byte) (uint32, bool) {
	point := bytes.IndexByte(octets, '.')
	if point <= 0 || point+3 != len(octets) {
		return 0, false
	}
	entier, ok1 := parserUintDecimal(octets[:point])
	frac, ok2 := parserUintDecimal(octets[point+1:])
	if !ok1 || !ok2 || entier > 1000 {
		return 0, false
	}
	return uint32(entier*100 + frac), true
}
