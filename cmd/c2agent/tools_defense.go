// Verbes d'intervention défensive pour l'agent c2blue55.
//
// Ces verbes observent l'état du poste (sockets, processus) et consignent une
// intention d'interception. Conformément à la doctrine de c2blue55, aucun
// blocage réseau n'est appliqué par le processus : ban_ip produit une règle
// nftables destinée à l'opérateur et une entrée de journal médico-légal
// chaînée par SHA-256, jamais une mutation silencieuse du pare-feu.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hazyhaar/c2slm"
)

// maxHashBytes borne la lecture d'un binaire pour empreinte. Au-delà, le
// fichier n'est pas haché en totalité et le résultat le signale.
const maxHashBytes = 256 << 20 // 256 Mio

// DefenseTools porte les handlers défensifs et l'état du journal de blocage.
type DefenseTools struct {
	procRoot    string
	journalPath string

	mu       sync.Mutex
	prevHash string

	clock func() time.Time
}

// NewDefenseTools crée l'ensemble défensif. journalPath vide désactive
// l'écriture disque : la chaîne de hachage reste calculée en mémoire.
func NewDefenseTools(journalPath string) *DefenseTools {
	d := &DefenseTools{
		procRoot:    "/proc",
		journalPath: journalPath,
		clock:       time.Now,
	}
	d.prevHash = d.recoverLastHash()
	return d
}

// RegisterDefenseTools enregistre les trois verbes défensifs dans un registre
// d'outils c2slm.
func RegisterDefenseTools(reg *c2slm.ToolRegistry, journalPath string) (*DefenseTools, error) {
	d := NewDefenseTools(journalPath)
	defs := []struct {
		def     c2slm.ToolDefinition
		handler c2slm.ToolHandler
	}{
		{
			def: c2slm.ToolDefinition{
				Name:        "inspect_socket",
				Description: "Inspecte /proc/net/{udp,tcp} pour un port donné et identifie les processus propriétaires du socket (inode -> PID) : localise l'émetteur d'une requête DNS suspecte.",
				Parameters:  json.RawMessage(`{"type":"object","properties":{"port":{"type":"integer","minimum":1,"maximum":65535,"description":"Port local ou distant recherché dans /proc/net"}},"required":["port"],"additionalProperties":false}`),
			},
			handler: d.InspectSocket,
		},
		{
			def: c2slm.ToolDefinition{
				Name:        "inspect_proc",
				Description: "Lit les métadonnées d'un processus (/proc/<pid>/cmdline, comm, exe, uid, ppid) et calcule l'empreinte SHA-256 de son binaire.",
				Parameters:  json.RawMessage(`{"type":"object","properties":{"pid":{"type":"integer","minimum":1,"description":"Identifiant du processus à inspecter"}},"required":["pid"],"additionalProperties":false}`),
			},
			handler: d.InspectProc,
		},
		{
			def: c2slm.ToolDefinition{
				Name:        "ban_ip",
				Description: "Consigne une intention d'interception d'une adresse IP : produit la règle nftables correspondante et une entrée de journal médico-légal chaînée SHA-256. N'applique aucun blocage lui-même.",
				Parameters:  json.RawMessage(`{"type":"object","properties":{"ip":{"type":"string","description":"Adresse IP à bloquer"},"duration_seconds":{"type":"integer","minimum":1,"description":"Durée du blocage en secondes"}},"required":["ip","duration_seconds"],"additionalProperties":false}`),
			},
			handler: d.BanIP,
		},
	}
	for _, entry := range defs {
		if err := reg.Register(entry.def, entry.handler); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// ---------------------------------------------------------------------------
// inspect_socket
// ---------------------------------------------------------------------------

type socketMatch struct {
	Proto  string   `json:"proto"`
	Local  string   `json:"local"`
	Remote string   `json:"remote"`
	State  string   `json:"state"`
	UID    string   `json:"uid"`
	Inode  string   `json:"inode"`
	PIDs   []int    `json:"pids,omitempty"`
	Comms  []string `json:"comms,omitempty"`
}

type inspectSocketResult struct {
	Port    int           `json:"port"`
	Matches []socketMatch `json:"matches"`
	Scanned []string      `json:"scanned"`
	Errors  []string      `json:"errors,omitempty"`
}

// InspectSocket recherche, dans /proc/net/udp et /proc/net/tcp, les sockets dont
// le port local ou distant correspond au port demandé, puis résout les
// processus propriétaires via les descripteurs socket:[inode].
func (d *DefenseTools) InspectSocket(args json.RawMessage) (string, error) {
	var req struct {
		Port int `json:"port"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return "", fmt.Errorf("inspect_socket: arguments invalides: %w", err)
	}
	if req.Port < 1 || req.Port > 65535 {
		return "", fmt.Errorf("inspect_socket: port hors bornes: %d", req.Port)
	}

	res := inspectSocketResult{Port: req.Port, Matches: []socketMatch{}}
	for _, proto := range []string{"udp", "tcp"} {
		path := filepath.Join(d.procRoot, "net", proto)
		matches, err := d.scanProcNet(path, proto, req.Port)
		res.Scanned = append(res.Scanned, path)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		res.Matches = append(res.Matches, matches...)
	}

	for i := range res.Matches {
		res.Matches[i].PIDs = d.findSocketOwners(res.Matches[i].Inode)
		for _, pid := range res.Matches[i].PIDs {
			if comm := readTrimmedFile(d.procPath(pid, "comm")); comm != "" {
				res.Matches[i].Comms = append(res.Matches[i].Comms, comm)
			}
		}
	}
	return marshalToolJSON(res)
}

func (d *DefenseTools) scanProcNet(path, proto string, port int) ([]socketMatch, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []socketMatch
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 8<<10), 1<<20)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		localIP, localPort, lErr := parseProcNetAddr(fields[1])
		if lErr != nil {
			continue
		}
		remoteIP, remotePort, rErr := parseProcNetAddr(fields[2])
		if rErr != nil {
			continue
		}
		if localPort != port && remotePort != port {
			continue
		}
		out = append(out, socketMatch{
			Proto:  proto,
			Local:  net.JoinHostPort(localIP, strconv.Itoa(localPort)),
			Remote: net.JoinHostPort(remoteIP, strconv.Itoa(remotePort)),
			State:  fields[3],
			UID:    fields[7],
			Inode:  fields[9],
		})
	}
	return out, sc.Err()
}

// parseProcNetAddr décode une adresse « HEXIP:HEXPORT » de /proc/net.
func parseProcNetAddr(s string) (string, int, error) {
	idx := strings.IndexByte(s, ':')
	if idx <= 0 || idx == len(s)-1 {
		return "", 0, errors.New("adresse /proc/net malformée")
	}
	port, err := strconv.ParseUint(s[idx+1:], 16, 16)
	if err != nil {
		return "", 0, err
	}
	ip, err := decodeProcNetIP(s[:idx])
	if err != nil {
		return "", 0, err
	}
	return ip, int(port), nil
}

// decodeProcNetIP convertit l'adresse hexadécimale de /proc/net. Les mots de
// 32 bits y sont stockés en ordre hôte (little-endian).
func decodeProcNetIP(h string) (string, error) {
	raw, err := hex.DecodeString(h)
	if err != nil {
		return "", err
	}
	switch len(raw) {
	case 4:
		return net.IPv4(raw[3], raw[2], raw[1], raw[0]).String(), nil
	case 16:
		for i := 0; i < 16; i += 4 {
			raw[i], raw[i+3] = raw[i+3], raw[i]
			raw[i+1], raw[i+2] = raw[i+2], raw[i+1]
		}
		return net.IP(raw).String(), nil
	default:
		return "", fmt.Errorf("largeur d'adresse /proc/net inattendue: %d octets", len(raw))
	}
}

// findSocketOwners résout l'inode d'un socket vers les PID qui le détiennent en
// parcourant les descripteurs de fichier de /proc.
func (d *DefenseTools) findSocketOwners(inode string) []int {
	if inode == "" {
		return nil
	}
	target := "socket:[" + inode + "]"
	entries, err := os.ReadDir(d.procRoot)
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		fdDir := filepath.Join(d.procRoot, e.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			if link == target {
				pids = append(pids, pid)
				break
			}
		}
	}
	return pids
}

// ---------------------------------------------------------------------------
// inspect_proc
// ---------------------------------------------------------------------------

type inspectProcResult struct {
	PID         int    `json:"pid"`
	Comm        string `json:"comm"`
	Cmdline     string `json:"cmdline"`
	Exe         string `json:"exe"`
	ExeSHA256   string `json:"exe_sha256,omitempty"`
	ExeHashNote string `json:"exe_hash_note,omitempty"`
	UID         string `json:"uid,omitempty"`
	PPID        string `json:"ppid,omitempty"`
}

// InspectProc lit les métadonnées d'un processus et l'empreinte SHA-256 de son
// binaire. Le binaire est lu via /proc/<pid>/exe, ce qui fonctionne même si le
// fichier a été supprimé après exécution.
func (d *DefenseTools) InspectProc(args json.RawMessage) (string, error) {
	var req struct {
		PID int `json:"pid"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return "", fmt.Errorf("inspect_proc: arguments invalides: %w", err)
	}
	if req.PID < 1 {
		return "", fmt.Errorf("inspect_proc: pid invalide: %d", req.PID)
	}

	exeLink := d.procPath(req.PID, "exe")
	exePath, _ := os.Readlink(exeLink)

	res := inspectProcResult{
		PID:     req.PID,
		Comm:    readTrimmedFile(d.procPath(req.PID, "comm")),
		Cmdline: readCmdline(d.procPath(req.PID, "cmdline")),
		Exe:     exePath,
	}
	if res.Comm == "" && res.Cmdline == "" && exePath == "" {
		if _, err := os.Stat(d.procPath(req.PID, "")); err != nil {
			return "", fmt.Errorf("inspect_proc: processus %d introuvable", req.PID)
		}
	}

	if status := readTrimmedFile(d.procPath(req.PID, "status")); status != "" {
		for _, line := range strings.Split(status, "\n") {
			switch {
			case strings.HasPrefix(line, "Uid:"):
				res.UID = firstField(strings.TrimPrefix(line, "Uid:"))
			case strings.HasPrefix(line, "PPid:"):
				res.PPID = firstField(strings.TrimPrefix(line, "PPid:"))
			}
		}
	}

	if exePath != "" {
		sum, truncated, err := hashFile(exeLink)
		switch {
		case err != nil:
			res.ExeHashNote = "empreinte indisponible: " + err.Error()
		case truncated:
			res.ExeSHA256 = sum
			res.ExeHashNote = fmt.Sprintf("empreinte partielle: binaire > %d octets", maxHashBytes)
		default:
			res.ExeSHA256 = sum
		}
	} else {
		res.ExeHashNote = "binaire non accessible"
	}
	return marshalToolJSON(res)
}

// hashFile calcule le SHA-256 d'un fichier et signale une éventuelle
// troncature au-delà de maxHashBytes.
func hashFile(path string) (sum string, truncated bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer f.Close()

	h := sha256.New()
	limited := io.LimitReader(f, maxHashBytes+1)
	n, err := io.Copy(h, limited)
	if err != nil {
		return "", false, err
	}
	if n > maxHashBytes {
		truncated = true
	}
	return hex.EncodeToString(h.Sum(nil)), truncated, nil
}

// ---------------------------------------------------------------------------
// ban_ip
// ---------------------------------------------------------------------------

type banJournalEntry struct {
	Time            string `json:"time"`
	IP              string `json:"ip"`
	DurationSeconds int    `json:"duration_seconds"`
	NFTRule         string `json:"nft_rule"`
	Actor           string `json:"actor"`
	Note            string `json:"note"`
	PrevHash        string `json:"prev_hash"`
	Hash            string `json:"hash"`
}

type banIPResult struct {
	Banned          bool   `json:"banned"`
	Applied         bool   `json:"applied"`
	IP              string `json:"ip"`
	DurationSeconds int    `json:"duration_seconds"`
	NFTRule         string `json:"nft_rule"`
	JournalPath     string `json:"journal_path,omitempty"`
	EntryHash       string `json:"entry_hash"`
	PrevHash        string `json:"prev_hash"`
	Note            string `json:"note"`
}

// BanIP valide l'adresse, compose la règle nftables d'interception et
// l'enregistre dans le journal chaîné. Aucune règle n'est appliquée : la sortie
// porte applied=false et la règle à soumettre par l'opérateur.
func (d *DefenseTools) BanIP(args json.RawMessage) (string, error) {
	var req struct {
		IP                   string `json:"ip"`
		Duration             int    `json:"duration_seconds"`
		DurationSecondsCamel int    `json:"durationSeconds"`
	}
	if err := json.Unmarshal(args, &req); err != nil {
		return "", fmt.Errorf("ban_ip: arguments invalides: %w", err)
	}
	if req.Duration == 0 {
		req.Duration = req.DurationSecondsCamel
	}
	ipRaw := strings.TrimSpace(req.IP)
	if ipRaw == "" {
		return "", errors.New("ban_ip: adresse IP absente")
	}
	parsed := net.ParseIP(ipRaw)
	if parsed == nil {
		return "", fmt.Errorf("ban_ip: adresse IP invalide: %q", req.IP)
	}
	if req.Duration <= 0 {
		return "", fmt.Errorf("ban_ip: durée invalide: %d", req.Duration)
	}

	ipStr := parsed.String()
	rule := fmt.Sprintf("add element inet c2blue55 blocked_ips { %s timeout %ds }", ipStr, req.Duration)

	entry := banJournalEntry{
		Time:            d.clock().UTC().Format(time.RFC3339Nano),
		IP:              ipStr,
		DurationSeconds: req.Duration,
		NFTRule:         rule,
		Actor:           "c2agent",
		Note:            "intention d'interception non appliquée; soumise à validation opérateur",
	}
	written, err := d.appendJournal(entry)
	if err != nil {
		return "", fmt.Errorf("ban_ip: écriture du journal: %w", err)
	}

	res := banIPResult{
		Banned:          true,
		Applied:         false,
		IP:              ipStr,
		DurationSeconds: req.Duration,
		NFTRule:         rule,
		JournalPath:     d.journalPath,
		EntryHash:       written.Hash,
		PrevHash:        written.PrevHash,
		Note:            "règle générée pour application explicite par l'opérateur (c2blue55 n'applique aucune interdiction réseau)",
	}
	return marshalToolJSON(res)
}

// appendJournal chaîne et écrit une entrée. Le hachage couvre les champs
// immuables et le maillon précédent, ce qui rend toute altération détectable.
func (d *DefenseTools) appendJournal(entry banJournalEntry) (banJournalEntry, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	entry.PrevHash = d.prevHash
	canonical := strings.Join([]string{
		entry.Time,
		entry.IP,
		strconv.Itoa(entry.DurationSeconds),
		entry.NFTRule,
		entry.Actor,
		entry.Note,
		entry.PrevHash,
	}, "\x1f")
	sum := sha256.Sum256([]byte(canonical))
	entry.Hash = hex.EncodeToString(sum[:])

	if d.journalPath != "" {
		f, err := os.OpenFile(d.journalPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return entry, err
		}
		payload, err := json.Marshal(entry)
		if err == nil {
			_, err = f.Write(append(payload, '\n'))
		}
		closeErr := f.Close()
		if err != nil {
			return entry, err
		}
		if closeErr != nil {
			return entry, closeErr
		}
	}
	d.prevHash = entry.Hash
	return entry, nil
}

// recoverLastHash relit le dernier maillon du journal pour poursuivre la
// chaîne entre deux exécutions.
func (d *DefenseTools) recoverLastHash() string {
	if d.journalPath == "" {
		return ""
	}
	f, err := os.Open(d.journalPath)
	if err != nil {
		return ""
	}
	defer f.Close()

	last := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			last = line
		}
	}
	if last == "" {
		return ""
	}
	var entry banJournalEntry
	if err := json.Unmarshal([]byte(last), &entry); err != nil {
		return ""
	}
	return entry.Hash
}

// ---------------------------------------------------------------------------
// utilitaires
// ---------------------------------------------------------------------------

func (d *DefenseTools) procPath(pid int, name string) string {
	base := filepath.Join(d.procRoot, strconv.Itoa(pid))
	if name == "" {
		return base
	}
	return filepath.Join(base, name)
}

func readTrimmedFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func readCmdline(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	fields := strings.Split(strings.TrimRight(string(data), "\x00"), "\x00")
	return strings.Join(fields, " ")
}

func firstField(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

func marshalToolJSON(v any) (string, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(payload), nil
}
