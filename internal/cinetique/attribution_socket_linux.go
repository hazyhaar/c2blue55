//go:build linux

package cinetique

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strconv"
	"sync"
	"unsafe"

	"github.com/hazyhaar/c2blue55/internal/probes"
	"golang.org/x/sys/unix"
)

const (
	capaciteSocketsDiag    = 1024
	tailleTamponNetlink    = 32768
	capaciteCacheInodes    = 128
	capaciteTableProcessus = 256
)

var (
	// ErrSocketIntrouvable signale qu'aucune entrée inet_diag ne correspond au tuple demandé.
	ErrSocketIntrouvable = errors.New("cinetique: socket absente de la table noyau inet_diag")
	// ErrProprietaireIntrouvable signale qu'aucun processus /proc/[pid]/fd ne détient l'inode.
	ErrProprietaireIntrouvable = errors.New("cinetique: aucun processus detenteur trouve pour l'inode socket")
)

// IdentiteProcessusSocket associe un socket réseau résolu à l'identité anti-réutilisation
// (PID + DebutTacheTicks) de son processus détenteur.
type IdentiteProcessusSocket struct {
	PID             int    `json:"pid"`
	DebutTacheTicks uint64 `json:"debut_tache_ticks"`
	UID             uint32 `json:"uid"`
	InodeSocket     uint32 `json:"inode_socket"`
	NomExecutable   string `json:"nom_executable"`
}

type entreeCacheInode struct {
	occupee         bool
	inode           uint32
	pid             int
	debutTacheTicks uint64
	uid             uint32
	nomOctets       [48]byte
	longueurNom     uint8
}

// ResolveurSocketProcessus effectue hors chemin chaud la résolution
// (Famille, Protocole, PortLocal, PortDistant) -> Inode Netlink inet_diag -> (PID, DebutTacheTicks).
type ResolveurSocketProcessus struct {
	mu            sync.Mutex
	fdInetDiag    int
	capteurProc   *CapteurProcLinux
	prochaineSeq  uint32
	tamponNetlink [tailleTamponNetlink]byte
	tableSockets  [capaciteSocketsDiag]probes.SocketInfo
	cacheInodes   [capaciteCacheInodes]entreeCacheInode
	curseurCache  uint8
}

// OuvrirResolveurSocketProcessus initialise la socket NETLINK_INET_DIAG et le descripteur /proc.
func OuvrirResolveurSocketProcessus() (*ResolveurSocketProcessus, error) {
	fdDiag, errDiag := probes.OpenInetDiag()
	if errDiag != nil {
		return nil, fmt.Errorf("cinetique: ouverture netlink inet_diag: %w", errDiag)
	}
	capteur, errProc := OuvrirCapteurProcLinux()
	if errProc != nil {
		_ = unix.Close(fdDiag)
		return nil, errProc
	}
	return &ResolveurSocketProcessus{
		fdInetDiag:   fdDiag,
		capteurProc:  capteur,
		prochaineSeq: 1,
	}, nil
}

// Fermer libère les descripteurs netlink et /proc détenus par le résolveur.
func (r *ResolveurSocketProcessus) Fermer() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var premiereErr error
	if r.fdInetDiag >= 0 {
		if err := unix.Close(r.fdInetDiag); err != nil {
			premiereErr = err
		}
		r.fdInetDiag = -1
	}
	if r.capteurProc != nil {
		if err := r.capteurProc.Fermer(); err != nil && premiereErr == nil {
			premiereErr = err
		}
		r.capteurProc = nil
	}
	return premiereErr
}

// CapteurProc expose le capteur /proc sous-jacent pour partager le descripteur ouvert.
func (r *ResolveurSocketProcessus) CapteurProc() *CapteurProcLinux {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.capteurProc
}

// ResoudreTupleIPv4 identifie le processus propriétaire d'une socket UDP ou TCP IPv4
// à partir de son port source local et de son port distant, avec repli automatique sur
// les sockets double pile AF_INET6 (:: ou ::ffff:x.x.x.x) utilisées par défaut sous Linux/Go.
func (r *ResolveurSocketProcessus) ResoudreTupleIPv4(
	protocole uint8,
	portLocal uint16,
	portDistant uint16,
	pidCandidat int,
) (IdentiteProcessusSocket, error) {
	if r == nil {
		return IdentiteProcessusSocket{}, ErrSocketIntrouvable
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	ident, errV4 := r.resoudreTupleFamilleVerrouille(unix.AF_INET, protocole, portLocal, portDistant, pidCandidat, false)
	if errV4 == nil || !errors.Is(errV4, ErrSocketIntrouvable) {
		return ident, errV4
	}
	return r.resoudreTupleFamilleVerrouille(unix.AF_INET6, protocole, portLocal, portDistant, pidCandidat, true)
}

// ResoudreTupleIPv6 identifie le processus propriétaire d'une socket UDP ou TCP IPv6.
func (r *ResolveurSocketProcessus) ResoudreTupleIPv6(
	protocole uint8,
	portLocal uint16,
	portDistant uint16,
	pidCandidat int,
) (IdentiteProcessusSocket, error) {
	if r == nil {
		return IdentiteProcessusSocket{}, ErrSocketIntrouvable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resoudreTupleFamilleVerrouille(unix.AF_INET6, protocole, portLocal, portDistant, pidCandidat, false)
}

func estAdresseDualStackCompatibleIPv4(adr [16]byte) bool {
	for i := range 10 {
		if adr[i] != 0 {
			return false
		}
	}
	if adr[10] == 0xff && adr[11] == 0xff {
		return true
	}
	for i := 10; i < 16; i++ {
		if adr[i] != 0 {
			return false
		}
	}
	return true
}

func (r *ResolveurSocketProcessus) resoudreTupleFamilleVerrouille(
	famille uint8,
	protocole uint8,
	portLocal uint16,
	portDistant uint16,
	pidCandidat int,
	exigerDualStackIPv4 bool,
) (IdentiteProcessusSocket, error) {
	var identite IdentiteProcessusSocket
	if r == nil || r.fdInetDiag < 0 || r.capteurProc == nil || portLocal == 0 {
		return identite, ErrSocketIntrouvable
	}

	r.prochaineSeq++
	nbSockets, errDump := probes.DumpInetDiag(
		r.fdInetDiag,
		famille,
		protocole,
		probes.StateMaskAll,
		r.tableSockets[:],
		r.tamponNetlink[:],
		r.prochaineSeq,
	)
	if errDump != nil {
		return identite, fmt.Errorf("cinetique: dump inet_diag: %w", errDump)
	}

	// Collecte bornée sur pile en séparant correspondances exactes de DstPort et replis.
	var exactes [8]probes.SocketInfo
	nbExactes := 0
	var replis [8]probes.SocketInfo
	nbReplis := 0

	for i := range nbSockets {
		entree := r.tableSockets[i]
		if entree.Inode == 0 || entree.SrcPort != portLocal {
			continue
		}
		if exigerDualStackIPv4 && !estAdresseDualStackCompatibleIPv4(entree.Src) {
			continue
		}
		if entree.DstPort == portDistant {
			if nbExactes < len(exactes) {
				exactes[nbExactes] = entree
				nbExactes++
			}
			continue
		}
		if (portDistant > 0 && entree.DstPort == 0) || (portDistant == 0 && entree.DstPort > 0) {
			if nbReplis < len(replis) {
				replis[nbReplis] = entree
				nbReplis++
			}
		}
	}
	if nbExactes == 0 && nbReplis == 0 {
		return identite, ErrSocketIntrouvable
	}

	// Si un pidCandidat est proposé et plusieurs sockets partagent le port local (SO_REUSEPORT),
	// on vérifie d'abord la détention effective par pidCandidat sur toutes les entrées exactes puis replis.
	if pidCandidat > 0 {
		var cibleLien [32]byte
		for i := range nbExactes {
			motif := formaterCibleSocketInode(cibleLien[:0], exactes[i].Inode)
			if processusDetientSocket(r.capteurProc.fdProc, pidCandidat, motif) {
				return r.construireEtMettreEnCache(pidCandidat, exactes[i].UID, exactes[i].Inode)
			}
		}
		for i := range nbReplis {
			motif := formaterCibleSocketInode(cibleLien[:0], replis[i].Inode)
			if processusDetientSocket(r.capteurProc.fdProc, pidCandidat, motif) {
				return r.construireEtMettreEnCache(pidCandidat, replis[i].UID, replis[i].Inode)
			}
		}
	}

	var derniereErr error
	for i := range nbExactes {
		res, errRes := r.resoudreInodeSocketVerrouille(exactes[i].Inode, exactes[i].UID, pidCandidat)
		if errRes == nil {
			return res, nil
		}
		derniereErr = errRes
	}
	for i := range nbReplis {
		res, errRes := r.resoudreInodeSocketVerrouille(replis[i].Inode, replis[i].UID, pidCandidat)
		if errRes == nil {
			return res, nil
		}
		derniereErr = errRes
	}
	if derniereErr != nil {
		return identite, derniereErr
	}
	return identite, ErrSocketIntrouvable
}

// ResoudreInodeSocket retrouve le processus propriétaire d'un inode socket noyau
// en consultant d'abord le cache vérifié par starttime, puis pidCandidat, puis /proc.
func (r *ResolveurSocketProcessus) ResoudreInodeSocket(
	inode uint32,
	uidAttendu uint32,
	pidCandidat int,
) (IdentiteProcessusSocket, error) {
	if r == nil {
		return IdentiteProcessusSocket{}, ErrProprietaireIntrouvable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.resoudreInodeSocketVerrouille(inode, uidAttendu, pidCandidat)
}

func (r *ResolveurSocketProcessus) resoudreInodeSocketVerrouille(
	inode uint32,
	uidAttendu uint32,
	pidCandidat int,
) (IdentiteProcessusSocket, error) {
	var identite IdentiteProcessusSocket
	if inode == 0 || r == nil || r.capteurProc == nil {
		return identite, ErrProprietaireIntrouvable
	}

	var cibleLien [32]byte
	motifSocket := formaterCibleSocketInode(cibleLien[:0], inode)

	// 1. Vérification du cache d'inodes (avec revalidation PID + DebutTacheTicks + détention effective).
	for i := range capaciteCacheInodes {
		entree := &r.cacheInodes[i]
		if !entree.occupee || entree.inode != inode {
			continue
		}
		if processusDetientSocket(r.capteurProc.fdProc, entree.pid, motifSocket) {
			debutTicks, errStat := lireDebutTacheRapide(r.capteurProc.fdProc, entree.pid)
			if errStat == nil && debutTicks == entree.debutTacheTicks {
				return IdentiteProcessusSocket{
					PID:             entree.pid,
					DebutTacheTicks: entree.debutTacheTicks,
					UID:             entree.uid,
					InodeSocket:     inode,
					NomExecutable:   string(entree.nomOctets[:entree.longueurNom]),
				}, nil
			}
		}
		entree.occupee = false
	}

	// 2. Voie rapide sur pidCandidat s'il est fourni.
	if pidCandidat > 0 && processusDetientSocket(r.capteurProc.fdProc, pidCandidat, motifSocket) {
		return r.construireEtMettreEnCache(pidCandidat, uidAttendu, inode)
	}

	// 3. Parcours filtré par UID des répertoires numériques de /proc via getdents64.
	pidDecouvert, trouve := chercherPIDParInodeDansProc(r.capteurProc.fdProc, motifSocket, uidAttendu, true)
	if !trouve {
		// Repli sans filtre UID au cas où le processus a changé d'euid (setuid).
		pidDecouvert, trouve = chercherPIDParInodeDansProc(r.capteurProc.fdProc, motifSocket, 0, false)
	}
	if !trouve {
		return identite, ErrProprietaireIntrouvable
	}
	return r.construireEtMettreEnCache(pidDecouvert, uidAttendu, inode)
}

func (r *ResolveurSocketProcessus) construireEtMettreEnCache(
	pid int,
	uid uint32,
	inode uint32,
) (IdentiteProcessusSocket, error) {
	debutTicks, errStat := lireDebutTacheRapide(r.capteurProc.fdProc, pid)
	if errStat != nil {
		return IdentiteProcessusSocket{}, fmt.Errorf("%w: lecture stat PID %d: %w", ErrProprietaireIntrouvable, pid, errStat)
	}
	var tamponComm [64]byte
	nComm := lireCommProcessus(r.capteurProc.fdProc, pid, tamponComm[:])

	slot := &r.cacheInodes[r.curseurCache%capaciteCacheInodes]
	r.curseurCache++
	*slot = entreeCacheInode{
		occupee:         true,
		inode:           inode,
		pid:             pid,
		debutTacheTicks: debutTicks,
		uid:             uid,
	}
	copieLen := min(nComm, len(slot.nomOctets))
	copy(slot.nomOctets[:copieLen], tamponComm[:copieLen])
	slot.longueurNom = uint8(copieLen)

	return IdentiteProcessusSocket{
		PID:             pid,
		DebutTacheTicks: debutTicks,
		UID:             uid,
		InodeSocket:     inode,
		NomExecutable:   string(slot.nomOctets[:slot.longueurNom]),
	}, nil
}

func formaterCibleSocketInode(dst []byte, inode uint32) []byte {
	dst = append(dst, "socket:["...)
	dst = strconv.AppendUint(dst, uint64(inode), 10)
	dst = append(dst, ']')
	return dst
}

func chercherPIDParInodeDansProc(fdProc int, motifSocket []byte, uidAttendu uint32, filtrerUID bool) (int, bool) {
	fdScan, _, errnoDup := unix.Syscall6(
		unix.SYS_OPENAT,
		uintptr(fdProc),
		uintptr(unsafe.Pointer(&pointNul[0])),
		uintptr(unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC),
		0, 0, 0,
	)
	runtime.KeepAlive(&pointNul)
	if errnoDup != 0 {
		return 0, false
	}
	defer func() { _, _, _ = unix.Syscall(unix.SYS_CLOSE, fdScan, 0, 0) }()

	var tamponDir [8192]byte
	for {
		nLus, errDents := unix.Getdents(int(fdScan), tamponDir[:])
		if errDents != nil || nLus <= 0 {
			break
		}
		curseur := 0
		for curseur+19 < nLus {
			reclen := int(binary.NativeEndian.Uint16(tamponDir[curseur+16 : curseur+18]))
			if reclen < 20 || curseur+reclen > nLus {
				break
			}
			nomBrut := tamponDir[curseur+19 : curseur+reclen]
			finNom := bytes.IndexByte(nomBrut, 0)
			if finNom > 0 {
				nom := nomBrut[:finNom]
				if pid64, okNum := parserUintDecimal(nom); okNum && pid64 > 0 {
					pid := int(pid64)
					if !filtrerUID || verifierUIDRepertoireProc(fdProc, nom, uidAttendu) {
						if processusDetientSocket(fdProc, pid, motifSocket) {
							return pid, true
						}
					}
				}
			}
			curseur += reclen
		}
	}
	return 0, false
}

var pointNul = [2]byte{'.', 0}

func verifierUIDRepertoireProc(fdProc int, nomPID []byte, uidAttendu uint32) bool {
	var chemin [32]byte
	if len(nomPID)+1 > len(chemin) {
		return false
	}
	copy(chemin[:], nomPID)
	chemin[len(nomPID)] = 0
	var statNoyau unix.Stat_t
	err := unix.Fstatat(fdProc, unsafe.String(&chemin[0], len(nomPID)), &statNoyau, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil {
		return false
	}
	return statNoyau.Uid == uidAttendu
}

func processusDetientSocket(fdProc int, pid int, motifSocket []byte) bool {
	var cheminFD [32]byte
	curseur := strconv.AppendInt(cheminFD[:0], int64(pid), 10)
	curseur = append(curseur, "/fd"...)
	curseur = append(curseur, 0)

	fdDir, _, errnoOpen := unix.Syscall6(
		unix.SYS_OPENAT,
		uintptr(fdProc),
		uintptr(unsafe.Pointer(&curseur[0])),
		uintptr(unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC),
		0, 0, 0,
	)
	runtime.KeepAlive(curseur)
	if errnoOpen != 0 {
		return false
	}
	defer func() { _, _, _ = unix.Syscall(unix.SYS_CLOSE, fdDir, 0, 0) }()

	var tamponDir [4096]byte
	var tamponLien [64]byte
	for {
		nLus, errDents := unix.Getdents(int(fdDir), tamponDir[:])
		if errDents != nil || nLus <= 0 {
			break
		}
		pos := 0
		for pos+19 < nLus {
			reclen := int(binary.NativeEndian.Uint16(tamponDir[pos+16 : pos+18]))
			if reclen < 20 || pos+reclen > nLus {
				break
			}
			nomBrut := tamponDir[pos+19 : pos+reclen]
			finNom := bytes.IndexByte(nomBrut, 0)
			if finNom > 0 && nomBrut[0] >= '0' && nomBrut[0] <= '9' {
				var nomNul [24]byte
				if finNom+1 <= len(nomNul) {
					copy(nomNul[:], nomBrut[:finNom])
					nomNul[finNom] = 0
					nLien, _, errnoLink := unix.Syscall6(
						unix.SYS_READLINKAT,
						fdDir,
						uintptr(unsafe.Pointer(&nomNul[0])),
						uintptr(unsafe.Pointer(&tamponLien[0])),
						uintptr(len(tamponLien)),
						0, 0,
					)
					runtime.KeepAlive(&nomNul)
					runtime.KeepAlive(&tamponLien)
					if errnoLink == 0 && int(nLien) == len(motifSocket) &&
						bytes.Equal(tamponLien[:nLien], motifSocket) {
						return true
					}
				}
			}
			pos += reclen
		}
	}
	return false
}

func lireDebutTacheRapide(fdProc int, pid int) (uint64, error) {
	var chemin [32]byte
	var tampon [1024]byte
	cheminNul := formaterCheminProc(chemin[:0], false, pid, 0, "stat")
	nLus, err := lireFichierProcComplet(fdProc, cheminNul, tampon[:])
	if err != nil {
		return 0, err
	}
	var snap InstantaneTache
	if err := AnalyserStatProc(tampon[:nLus], &snap); err != nil {
		return 0, err
	}
	return snap.DebutTacheTicks, nil
}

func lireCommProcessus(fdProc int, pid int, dst []byte) int {
	var chemin [32]byte
	cheminNul := formaterCheminProc(chemin[:0], false, pid, 0, "comm")
	nLus, err := lireFichierProcComplet(fdProc, cheminNul, dst)
	if err != nil || nLus <= 0 {
		return 0
	}
	for nLus > 0 && (dst[nLus-1] == '\n' || dst[nLus-1] == '\r' || dst[nLus-1] == 0) {
		nLus--
	}
	return nLus
}

type entreeCollecteReseau struct {
	occupee         bool
	pid             int
	debutTacheTicks uint64
	dernierAccesSeq uint64
	compteurs       CompteursReseauEpisode
}

// CollecteurReseauParProcessus agrège en mémoire bornée (256 entrées, 0 B/op)
// les observations réseau et verdicts DNS/ICMP attribués à chaque (PID, DebutTacheTicks).
type CollecteurReseauParProcessus struct {
	mu       sync.Mutex
	seqAcces uint64
	entrees  [capaciteTableProcessus]entreeCollecteReseau
}

// NouveauCollecteurReseauParProcessus alloue la table bornée d'agrégation réseau.
func NouveauCollecteurReseauParProcessus() *CollecteurReseauParProcessus {
	return &CollecteurReseauParProcessus{}
}

// EnregistrerObservationReseau accumule en 0 B/op un événement réseau ou DNS
// sur le couple (pid, debutTacheTicks).
func (c *CollecteurReseauParProcessus) EnregistrerObservationReseau(
	pid int,
	debutTacheTicks uint64,
	octetsSortants uint64,
	octetsEntrants uint64,
	nouvelleConnexion bool,
	estResolutionDNS bool,
	portSuspect uint16,
	estUDP bool,
	codeRaisonDNS uint8,
) {
	if c == nil || pid <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.seqAcces++
	idxCible := -1
	idxLRU := 0
	minSeq := c.entrees[0].dernierAccesSeq

	for i := range capaciteTableProcessus {
		e := &c.entrees[i]
		if e.occupee && e.pid == pid && e.debutTacheTicks == debutTacheTicks {
			idxCible = i
			break
		}
		if !e.occupee {
			idxLRU = i
			minSeq = 0
			continue
		}
		if minSeq > 0 && e.dernierAccesSeq < minSeq {
			minSeq = e.dernierAccesSeq
			idxLRU = i
		}
	}
	if idxCible < 0 {
		idxCible = idxLRU
		c.entrees[idxCible] = entreeCollecteReseau{
			occupee:         true,
			pid:             pid,
			debutTacheTicks: debutTacheTicks,
		}
	}
	slot := &c.entrees[idxCible]
	slot.dernierAccesSeq = c.seqAcces
	slot.compteurs.OctetsSortants = additionnerSatureU64(slot.compteurs.OctetsSortants, octetsSortants)
	slot.compteurs.OctetsEntrants = additionnerSatureU64(slot.compteurs.OctetsEntrants, octetsEntrants)
	if nouvelleConnexion {
		slot.compteurs.ConnexionsSortantes = additionnerSatureU32(slot.compteurs.ConnexionsSortantes, 1)
	}
	if estResolutionDNS {
		slot.compteurs.ResolutionsDNS = additionnerSatureU32(slot.compteurs.ResolutionsDNS, 1)
	}
	if portSuspect > 0 {
		slot.compteurs.PortSuspect = portSuspect
		slot.compteurs.ProtocoleSuspectUDP = estUDP
	}
	if codeRaisonDNS > 0 {
		slot.compteurs.CodeRaisonDNS |= codeRaisonDNS
	}
}

// RecolterEtPurger extrait en 0 B/op les compteurs réseau accumulés pour l'épisode
// du processus (pid, debutTacheTicks) et libère l'emplacement pour la fenêtre suivante.
func (c *CollecteurReseauParProcessus) RecolterEtPurger(pid int, debutTacheTicks uint64) CompteursReseauEpisode {
	if c == nil || pid <= 0 {
		return CompteursReseauEpisode{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range capaciteTableProcessus {
		e := &c.entrees[i]
		if e.occupee && e.pid == pid && e.debutTacheTicks == debutTacheTicks {
			recolte := e.compteurs
			e.occupee = false
			e.compteurs = CompteursReseauEpisode{}
			return recolte
		}
	}
	return CompteursReseauEpisode{}
}

// Codes binaires d'anomalie filaire RFC 1035 mesurés par InspecterDatagrammeDNSFil.
const (
	RaisonDNSLabelLong      uint8 = 1 << 0
	RaisonDNSTypeInhabituel uint8 = 1 << 1
	RaisonDNSHauteEntropie  uint8 = 1 << 2
	RaisonDNSNomProfond     uint8 = 1 << 3
)

// InspectionFilaireDNS résume en 0 B/op les caractéristiques mesurées sur un
// datagramme UDP décodé intégralement selon RFC 1035.
type InspectionFilaireDNS struct {
	ID                        uint16
	QType                     uint16
	NombreLabels              uint8
	LongueurMaxLabel          uint8
	LongueurTotaleQName       uint16
	EntropieMaxLabelMilliBits uint16
	CodeRaisonDNS             uint8
}

// ConstruireRequeteDNSFil encode en 0 B/op dans dst[:0] une requête DNS RFC 1035 valide
// (en-tête 12 octets RD=1, QDCOUNT=1 + QNAME en labels préfixés + QTYPE + QCLASS=IN).
func ConstruireRequeteDNSFil(dst []byte, identifiant uint16, nomDomaine string, qtype uint16) ([]byte, error) {
	if len(nomDomaine) == 0 || len(nomDomaine) > 253 || qtype == 0 {
		return nil, unix.EINVAL
	}
	var assemblage [512]byte
	binary.BigEndian.PutUint16(assemblage[0:2], identifiant)
	binary.BigEndian.PutUint16(assemblage[2:4], 0x0100) // RD=1, requête standard
	binary.BigEndian.PutUint16(assemblage[4:6], 1)      // QDCOUNT=1
	curseur := assemblage[:12]

	debutLabel := 0
	for i := 0; i <= len(nomDomaine); i++ {
		if i == len(nomDomaine) || nomDomaine[i] == '.' {
			longueur := i - debutLabel
			if longueur == 0 && i == len(nomDomaine) {
				break
			}
			if longueur <= 0 || longueur > 63 {
				return nil, unix.EINVAL
			}
			curseur = append(curseur, byte(longueur))
			curseur = append(curseur, nomDomaine[debutLabel:i]...)
			debutLabel = i + 1
		}
	}
	curseur = append(curseur, 0) // racine NUL
	var pied [4]byte
	binary.BigEndian.PutUint16(pied[0:2], qtype)
	binary.BigEndian.PutUint16(pied[2:4], 1) // QCLASS = IN
	curseur = append(curseur, pied[:]...)

	if cap(dst) < len(curseur) {
		return nil, ErrTamponTropCourt
	}
	sortie := dst[:len(curseur)]
	copy(sortie, curseur)
	return sortie, nil
}

// InspecterDatagrammeDNSFil décode intégralement en 0 B/op un datagramme UDP selon
// RFC 1035 et calcule ses indicateurs objectifs de tunnel/exfiltration DNS (longueur
// de sous-domaine, entropie de Shannon par label et type d'enregistrement inhabituel).
func InspecterDatagrammeDNSFil(chargeUDP []byte) (InspectionFilaireDNS, bool) {
	var res InspectionFilaireDNS
	if len(chargeUDP) < 17 {
		return res, false
	}
	res.ID = binary.BigEndian.Uint16(chargeUDP[0:2])
	drapeaux := binary.BigEndian.Uint16(chargeUDP[2:4])
	opcode := (drapeaux >> 11) & 0x0F
	qdCount := binary.BigEndian.Uint16(chargeUDP[4:6])
	if opcode != 0 || qdCount == 0 {
		return res, false
	}

	pos := 12
	var longueursLabels [32]uint8
	var debutsLabels [32]int
	nbLabels := 0
	totalQName := 0

	for {
		if pos >= len(chargeUDP) {
			return InspectionFilaireDNS{}, false
		}
		longueur := int(chargeUDP[pos])
		if longueur == 0 {
			pos++
			break
		}
		// Pointeur de compression interdit dans la première question brute ou label > 63 octets.
		if (longueur&0xC0) != 0 || longueur > 63 || pos+1+longueur >= len(chargeUDP) {
			return InspectionFilaireDNS{}, false
		}
		if nbLabels < len(longueursLabels) {
			longueursLabels[nbLabels] = uint8(longueur)
			debutsLabels[nbLabels] = pos + 1
		}
		nbLabels++
		if totalQName > 0 {
			totalQName++
		}
		totalQName += longueur
		if totalQName > 255 {
			return InspectionFilaireDNS{}, false
		}
		pos += 1 + longueur
	}
	if nbLabels == 0 || pos+4 > len(chargeUDP) {
		return InspectionFilaireDNS{}, false
	}
	qtype := binary.BigEndian.Uint16(chargeUDP[pos : pos+2])
	qclass := binary.BigEndian.Uint16(chargeUDP[pos+2 : pos+4])
	if qtype == 0 || qclass != 1 {
		return InspectionFilaireDNS{}, false
	}

	res.QType = qtype
	if nbLabels > 255 {
		res.NombreLabels = 255
	} else {
		res.NombreLabels = uint8(nbLabels)
	}
	res.LongueurTotaleQName = uint16(totalQName)

	// Analyse des sous-domaines (hors SLD+TLD finaux lorsque >= 3 labels).
	limiteSousDomaines := min(nbLabels, len(longueursLabels))
	if nbLabels >= 3 {
		limiteSousDomaines = min(nbLabels-2, len(longueursLabels))
	}
	for i := range limiteSousDomaines {
		lg := longueursLabels[i]
		if lg > res.LongueurMaxLabel {
			res.LongueurMaxLabel = lg
		}
		entMilli := entropieShannonMilliBits(chargeUDP[debutsLabels[i] : debutsLabels[i]+int(lg)])
		if entMilli > res.EntropieMaxLabelMilliBits {
			res.EntropieMaxLabelMilliBits = entMilli
		}
	}

	if res.LongueurMaxLabel >= 32 {
		res.CodeRaisonDNS |= RaisonDNSLabelLong
	}
	if qtype == 16 || qtype == 10 || qtype == 255 {
		res.CodeRaisonDNS |= RaisonDNSTypeInhabituel
	}
	if res.LongueurMaxLabel >= 20 && res.EntropieMaxLabelMilliBits >= 3500 {
		res.CodeRaisonDNS |= RaisonDNSHauteEntropie
	}
	if res.LongueurTotaleQName >= 80 || res.NombreLabels >= 6 {
		res.CodeRaisonDNS |= RaisonDNSNomProfond
	}
	return res, true
}

func entropieShannonMilliBits(tranche []byte) uint16 {
	n := len(tranche)
	if n <= 1 {
		return 0
	}
	var freq [256]uint8
	var distincts [64]byte
	nbDistincts := 0
	for i := range n {
		b := tranche[i]
		if freq[b] == 0 && nbDistincts < len(distincts) {
			distincts[nbDistincts] = b
			nbDistincts++
		}
		if freq[b] < 255 {
			freq[b]++
		}
	}
	invN := 1.0 / float64(n)
	var entropie float64
	for i := range nbDistincts {
		p := float64(freq[distincts[i]]) * invN
		entropie -= p * math.Log2(p)
	}
	milli := int(math.Round(entropie * 1000.0))
	if milli < 0 {
		return 0
	}
	if milli > 65535 {
		return 65535
	}
	return uint16(milli)
}
