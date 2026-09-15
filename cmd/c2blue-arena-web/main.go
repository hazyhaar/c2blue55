package main

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55"
	"code.hazyhaar.fr/devhoros/pkg/c2blue55/socagent"
)

const (
	defaultAddr     = "127.0.0.1:4255"
	sseInterval     = 100 * time.Millisecond
	scanHz          = 10
	ringCap         = 1024
	maxProcsView    = 15
	maxIncidents    = 12
	entropySuspect  = 6.0
	procGrammarTool = "proc_exec"
	procGrammarMask = uint32(0x0001)
	procGrammarThr  = uint16(64)
)

var procGrammarSample = []byte("/usr/sbin/sshd -D -e")

var lolbasNames = [...]string{
	"netcat", "python", "base64", "socat", "ncat", "wget", "curl",
	"perl", "ruby", "bash", "dash", "php", "lua", "zsh", "ash", "nc", "sh",
}

var suspiciousNeedles = [...]string{
	"| sh", "| bash", "|sh", "|bash", "base64 -d", "base64 -D",
	"chmod 777", "rm -rf", "python -c", "perl -e", "nc -l", "ncat -l",
	"curl http", "wget http", "curl https", "wget https",
}

type ProcEvent struct {
	PID       uint32  `json:"pid"`
	StartTime uint64  `json:"starttime_ticks"`
	Comm      string  `json:"comm"`
	Cmdline   string  `json:"cmdline"`
	Entropy   float64 `json:"entropy"`
	Status    string  `json:"status"`
}

type hostMetrics struct {
	CPUPct     float64 `json:"cpu_pct"`
	MemTotalMB float64 `json:"mem_total_mb"`
	MemUsedMB  float64 `json:"mem_used_mb"`
	MemPct     float64 `json:"mem_pct"`
	ProcCount  int     `json:"proc_count"`
	Goroutines int     `json:"goroutines"`
	HeapMB     float64 `json:"heap_mb"`
}

type c2blueMetrics struct {
	EventsTotal     uint64  `json:"events_total"`
	EventsPerSec    float64 `json:"events_per_sec"`
	RingDrops       uint64  `json:"ring_drops"`
	RingOccupancy   uint64  `json:"ring_occupancy"`
	LastEntropyBits float64 `json:"last_entropy_bits"`
	LastDjsQ8       uint32  `json:"last_djs_q8"`
}

type incidentView struct {
	ID      string                 `json:"id"`
	Facts   []socagent.Proposition `json:"facts"`
	Verdict string                 `json:"verdict"`
	Score   uint32                 `json:"score"`
}

type telemetryPayload struct {
	Host      hostMetrics    `json:"host"`
	C2Blue    c2blueMetrics  `json:"c2blue"`
	Procs     []ProcEvent    `json:"procs"`
	Incidents []incidentView `json:"incidents"`
	UTC       string         `json:"utc"`
	UptimeS   float64        `json:"uptime_s"`
	SubProc   uint64         `json:"sub_proc"`
	SubFile   uint64         `json:"sub_file"`
	SubNet    uint64         `json:"sub_net"`
	SubMCP    uint64         `json:"sub_mcp"`
}

type cpuSnap struct {
	user, nice, system, idle, iowait, irq, softirq uint64
}

type arena struct {
	ch          *c2blue55.Channel
	t0          time.Time
	stop        chan struct{}
	once        sync.Once
	done        chan struct{}
	clients     chan struct{}
	token       string
	frame       []byte
	lastCollect time.Time

	mu      sync.RWMutex
	procs   []ProcEvent
	incs    []incidentView
	total   uint64
	eps     float64
	occ     uint64
	lastEnt float64
	lastDjs uint32
	subProc uint64
	subFile uint64
	subNet  uint64
	subMCP  uint64
	nprocs  int
}

var (
	cpuMu   sync.Mutex
	cpuPrev cpuSnap
	cpuHave bool

	grammarOnce sync.Once

	incMu  sync.Mutex
	incLog []incidentView
	scanMu sync.Mutex
)

func readCPUPercent() float64 {
	cur, ok := readCPUSnap()
	if !ok {
		return 0
	}
	cpuMu.Lock()
	defer cpuMu.Unlock()
	if !cpuHave {
		cpuPrev = cur
		cpuHave = true
		return 0
	}
	pct := cpuDelta(cpuPrev, cur)
	cpuPrev = cur
	return pct
}

func readCPUSnap() (cpuSnap, bool) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuSnap{}, false
	}
	defer f.Close()
	rd := bufio.NewReader(f)
	line, err := rd.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return cpuSnap{}, false
	}
	fields := bytes.Fields(line)
	if len(fields) < 8 || string(fields[0]) != "cpu" {
		return cpuSnap{}, false
	}
	var s cpuSnap
	s.user = parseU64(fields[1])
	s.nice = parseU64(fields[2])
	s.system = parseU64(fields[3])
	s.idle = parseU64(fields[4])
	s.iowait = parseU64(fields[5])
	s.irq = parseU64(fields[6])
	s.softirq = parseU64(fields[7])
	return s, true
}

func cpuDelta(prev, cur cpuSnap) float64 {
	pIdle := prev.idle + prev.iowait
	cIdle := cur.idle + cur.iowait
	pTot := prev.user + prev.nice + prev.system + prev.idle + prev.iowait + prev.irq + prev.softirq
	cTot := cur.user + cur.nice + cur.system + cur.idle + cur.iowait + cur.irq + cur.softirq
	if cTot <= pTot {
		return 0
	}
	dTot := cTot - pTot
	dIdle := cIdle - pIdle
	if dIdle > dTot {
		dIdle = dTot
	}
	pct := 100 * float64(dTot-dIdle) / float64(dTot)
	if pct < 0 {
		return 0
	}
	if pct > 100 {
		return 100
	}
	return pct
}

func readMemInfo() (totalMB, usedMB float64, pct float64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0, 0
	}
	defer f.Close()
	var totalKB, availKB uint64
	var haveTotal, haveAvail bool
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Bytes()
		if bytes.HasPrefix(line, []byte("MemTotal:")) {
			totalKB = parseMemKB(line)
			haveTotal = true
		} else if bytes.HasPrefix(line, []byte("MemAvailable:")) {
			availKB = parseMemKB(line)
			haveAvail = true
		}
		if haveTotal && haveAvail {
			break
		}
	}
	if !haveTotal || totalKB == 0 {
		return 0, 0, 0
	}
	usedKB := totalKB
	if haveAvail && availKB < totalKB {
		usedKB = totalKB - availKB
	}
	totalMB = float64(totalKB) / 1024
	usedMB = float64(usedKB) / 1024
	pct = 100 * float64(usedKB) / float64(totalKB)
	return totalMB, usedMB, pct
}

func parseMemKB(line []byte) uint64 {
	fields := bytes.Fields(line)
	if len(fields) < 2 {
		return 0
	}
	return parseU64(fields[1])
}

func parseU64(b []byte) uint64 {
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

func scanRealProcesses(ch *c2blue55.Channel) []ProcEvent {
	grammarOnce.Do(func() {
		if err := c2blue55.RegisterToolGrammar(procGrammarTool, procGrammarSample, procGrammarMask, procGrammarThr); err != nil {
			fmt.Fprintf(os.Stderr, "process grammar unavailable: %v\n", err)
		}
	})
	incMu.Lock()
	scanWritten, scanOccupancy, scanLastEnt, scanLastDjs = 0, 0, 0, 0
	incMu.Unlock()
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	raw := make([]ProcEvent, 0, 64)
	events := make([]c2blue55.Event, 0, 64)
	now := uint64(time.Now().UnixNano())
	for i := range ents {
		name := ents[i].Name()
		pid, ok := parsePID(name)
		if !ok {
			continue
		}
		commB, err := os.ReadFile("/proc/" + name + "/comm")
		if err != nil {
			continue
		}
		stat, err := os.ReadFile("/proc/" + name + "/stat")
		birth, valid := processStartTime(stat)
		if err != nil || !valid {
			continue
		}
		cmdB, err := os.ReadFile("/proc/" + name + "/cmdline")
		if err != nil {
			cmdB = nil
		}
		statAfter, err := os.ReadFile("/proc/" + name + "/stat")
		birthAfter, valid := processStartTime(statAfter)
		if err != nil || !valid || birthAfter != birth {
			continue
		}
		comm := strings.TrimSpace(string(bytes.TrimRight(commB, "\n")))
		cmdline := strings.TrimSpace(strings.ReplaceAll(string(cmdB), "\x00", " "))
		payloadSrc := cmdline
		if payloadSrc == "" {
			payloadSrc = comm
		}
		entBytes := []byte(payloadSrc)
		entropy := c2blue55.CalcEntropyBits(entBytes)
		var ev c2blue55.Event
		ev.Ts_ns = now
		ev.Pid = pid
		ev.Tid = pid
		ev.Subsystem = c2blue55.SubProc
		// A periodic presence observation is not an exec interception.
		ev.Action = 0
		ev.Src = uint64(entropy * 256)
		pl := comm
		if cmdline != "" {
			pl = comm + " " + cmdline
		}
		copy(ev.Payload[:len(ev.Payload)-1], pl)
		if entropy >= entropySuspect {
			ev.Flags |= c2blue55.FlagAnomaly
		}
		events = append(events, ev)
		raw = append(raw, ProcEvent{
			PID:       pid,
			StartTime: birth,
			Comm:      comm,
			Cmdline:   cmdline,
			Entropy:   entropy,
		})
	}
	n := len(events)
	if n == 0 {
		return nil
	}
	out := make([]c2blue55.Event, n)
	_ = c2blue55.EvalRulesBatch(events, out, n)
	occ := 0
	var lastEnt float64
	var lastDjs uint32
	for i := range out {
		if raw[i].Entropy >= entropySuspect {
			out[i].Flags |= c2blue55.FlagAnomaly
		}
		lolbas := out[i].Flags&c2blue55.FlagLOLBAS != 0 || hasLOLBAS(raw[i].Comm, raw[i].Cmdline)
		if lolbas {
			out[i].Flags |= c2blue55.FlagLOLBAS
		}
		suspect := out[i].Flags&c2blue55.FlagAnomaly != 0 || isSuspicious(raw[i].Cmdline)
		switch {
		case lolbas:
			raw[i].Status = "LOLBAS"
		case suspect:
			raw[i].Status = "SUSPECT"
			out[i].Flags |= c2blue55.FlagAnomaly
		default:
			raw[i].Status = "NOMINAL"
			if out[i].Flags == 0 {
				out[i].Flags = c2blue55.FlagVerdictOK
			}
		}
		if ch != nil {
			if occ >= ringCap-8 {
				drainChannel(ch)
				occ = 0
			}
			if ch.Write(&out[i]) == 0 {
				occ++
			}
		}
		lastEnt = raw[i].Entropy
	}
	last := raw[n-1]
	sample := last.Cmdline
	if sample == "" {
		sample = last.Comm
	}
	lastDjs, _, _ = c2blue55.EvalGrammar(procGrammarTool, []byte(sample))
	if ch != nil {
		drainChannel(ch)
	}
	incMu.Lock()
	scanWritten = uint64(n)
	scanOccupancy = 0 // The sole producer has drained the channel above.
	scanLastEnt = lastEnt
	scanLastDjs = lastDjs
	incMu.Unlock()
	// Raw arguments are used locally only, never published to HTTP clients.
	for i := range raw {
		raw[i].Cmdline = "[arguments withheld]"
	}
	if len(raw) > maxProcsView {
		return raw[len(raw)-maxProcsView:]
	}
	return raw
}

var (
	scanWritten   uint64
	scanOccupancy uint64
	scanLastEnt   float64
	scanLastDjs   uint32
)

func drainChannel(ch *c2blue55.Channel) {
	var ev c2blue55.Event
	for ch.Read(&ev) == 1 {
	}
}

func processStartTime(stat []byte) (uint64, bool) {
	end := bytes.LastIndexByte(stat, ')')
	if end < 0 {
		return 0, false
	}
	fields := bytes.Fields(stat[end+1:])
	if len(fields) <= 19 {
		return 0, false
	}
	n, err := strconv.ParseUint(string(fields[19]), 10, 64)
	return n, err == nil && n != 0
}

func copyIncidents() []incidentView {
	incMu.Lock()
	defer incMu.Unlock()
	if len(incLog) == 0 {
		return nil
	}
	out := make([]incidentView, len(incLog))
	copy(out, incLog)
	return out
}

func parsePID(name string) (uint32, bool) {
	if name == "" {
		return 0, false
	}
	var n uint64
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
		if n > uint64(^uint32(0)) {
			return 0, false
		}
	}
	return uint32(n), true
}

func hasLOLBAS(comm, cmdline string) bool {
	if tokenIn(comm, lolbasNames[:]) {
		return true
	}
	return tokenIn(cmdline, lolbasNames[:])
}

func tokenIn(hay string, names []string) bool {
	if hay == "" {
		return false
	}
	lower := strings.ToLower(hay)
	for _, name := range names {
		if tokenPresent(lower, name) {
			return true
		}
	}
	return false
}

func tokenPresent(s, name string) bool {
	i := 0
	for {
		j := strings.Index(s[i:], name)
		if j < 0 {
			return false
		}
		j += i
		beforeOK := j == 0 || isTokenSep(s[j-1])
		after := j + len(name)
		afterOK := after == len(s) || isTokenSep(s[after])
		if beforeOK && afterOK {
			return true
		}
		i = j + 1
	}
}

func isTokenSep(c byte) bool {
	return c == '/' || c == ' ' || c == '\t' || c == '|' || c == ';' || c == ':' || c == '=' || c == '"' || c == '\'' || c == ','
}

func isSuspicious(cmdline string) bool {
	if cmdline == "" {
		return false
	}
	lower := strings.ToLower(cmdline)
	for i := range suspiciousNeedles {
		if strings.Contains(lower, suspiciousNeedles[i]) {
			return true
		}
	}
	return false
}

func newArena() *arena {
	a := &arena{
		ch:      c2blue55.NewChannel(),
		t0:      time.Now(),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
		clients: make(chan struct{}, 8),
		token:   os.Getenv("C2BLUE_DASHBOARD_TOKEN"),
	}
	a.collect()
	go a.run()
	return a
}

func (a *arena) close() {
	a.once.Do(func() { close(a.stop) })
	<-a.done
}

func (a *arena) run() {
	defer close(a.done)
	tick := time.NewTicker(time.Second / scanHz)
	defer tick.Stop()
	for {
		select {
		case <-a.stop:
			return
		case <-tick.C:
			a.collect()
		}
	}
}

func (a *arena) collect() {
	scanMu.Lock()
	defer scanMu.Unlock()
	started := time.Now()
	procs := scanRealProcesses(a.ch)
	incMu.Lock()
	written := scanWritten
	occ := scanOccupancy
	ent := scanLastEnt
	djs := scanLastDjs
	incMu.Unlock()
	now := time.Now()
	previous := a.lastCollect
	if previous.IsZero() {
		previous = started
	}
	eps := float64(written) / now.Sub(previous).Seconds()
	a.lastCollect = now
	a.mu.Lock()
	a.procs = procs
	a.incs = copyIncidents()
	a.total += written
	a.eps = eps
	a.occ = occ
	a.lastEnt = ent
	a.lastDjs = djs
	a.subProc += written
	a.nprocs = countProcDirs()
	a.mu.Unlock()
	frame := a.buildFrame()
	a.mu.Lock()
	a.frame = frame
	a.mu.Unlock()
}

func countProcDirs() int {
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	n := 0
	for i := range ents {
		if _, ok := parsePID(ents[i].Name()); ok {
			n++
		}
	}
	return n
}

func (a *arena) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.serveIndex)
	mux.HandleFunc("GET /events", a.serveEvents)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, password, ok := r.BasicAuth()
		if !ok || a.token == "" || subtle.ConstantTimeCompare([]byte(password), []byte(a.token)) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="c2blue"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (a *arena) serveIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(indexHTML)
}

func (a *arena) serveEvents(w http.ResponseWriter, r *http.Request) {
	select {
	case a.clients <- struct{}{}:
		defer func() { <-a.clients }()
	default:
		http.Error(w, "subscriber limit", http.StatusServiceUnavailable)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "sse unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Second))
	w.WriteHeader(http.StatusOK)
	fl.Flush()
	tick := time.NewTicker(sseInterval)
	defer tick.Stop()
	for {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := w.Write(a.sseFrame()); err != nil {
			return
		}
		fl.Flush()
		select {
		case <-a.stop:
			return
		case <-r.Context().Done():
			return
		case <-tick.C:
		}
	}
}

func (a *arena) sseFrame() []byte {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.frame
}

func (a *arena) buildFrame() []byte {
	cpu := readCPUPercent()
	tot, used, mpct := readMemInfo()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	a.mu.RLock()
	tel := telemetryPayload{
		Host: hostMetrics{
			CPUPct:     cpu,
			MemTotalMB: tot,
			MemUsedMB:  used,
			MemPct:     mpct,
			ProcCount:  a.nprocs,
			Goroutines: runtime.NumGoroutine(),
			HeapMB:     float64(ms.HeapAlloc) / (1024 * 1024),
		},
		C2Blue: c2blueMetrics{
			EventsTotal:     a.total,
			EventsPerSec:    a.eps,
			RingDrops:       a.ch.Drops(),
			RingOccupancy:   a.occ,
			LastEntropyBits: a.lastEnt,
			LastDjsQ8:       a.lastDjs,
		},
		Procs:     a.procs,
		Incidents: a.incs,
		UTC:       time.Now().UTC().Format(time.RFC3339),
		UptimeS:   time.Since(a.t0).Seconds(),
		SubProc:   a.subProc,
		SubFile:   a.subFile,
		SubNet:    a.subNet,
		SubMCP:    a.subMCP,
	}
	a.mu.RUnlock()
	raw, err := json.Marshal(tel)
	if err != nil {
		return []byte("data: {}\n\n")
	}
	out := make([]byte, 0, len(raw)+8)
	out = append(out, "data: "...)
	out = append(out, raw...)
	out = append(out, '\n', '\n')
	return out
}

func main() {
	addr := flag.String("addr", defaultAddr, "adresse d'écoute HTTP")
	flag.Parse()
	if os.Getenv("C2BLUE_DASHBOARD_TOKEN") == "" {
		fmt.Fprintln(os.Stderr, "C2BLUE_DASHBOARD_TOKEN is required (HTTP Basic password)")
		os.Exit(2)
	}
	if !strings.HasPrefix(*addr, "127.0.0.1:") && !strings.HasPrefix(*addr, "[::1]:") {
		fmt.Fprintln(os.Stderr, "only loopback HTTP is supported; use an authenticated TLS tunnel")
		os.Exit(2)
	}
	a := newArena()
	defer a.close()
	server := &http.Server{Addr: *addr, Handler: a.handler(), ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10}
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "c2blue-arena-web: %v\n", err)
		os.Exit(1)
	}
}

var indexHTML = []byte(`<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>C2BLUE — OBSERVATIONS SYSTEME</title>
<style>
:root {
  --bg:#070b12; --panel:#0c1520; --ink:#d7e6f2; --muted:#7a93a7;
  --cyan:#00e5ff; --red:#ff3b4a; --green:#3dff9a; --line:#1c3a4d;
  --warn:#ffcc33; --orange:#ff8a3d; --card:#081018;
}
* { box-sizing:border-box; }
html,body { margin:0; min-height:100%; background:var(--bg); color:var(--ink);
  font-family: ui-sans-serif, system-ui, sans-serif; }
body { padding:16px 18px 24px; }
header { display:flex; flex-wrap:wrap; align-items:center; gap:12px 20px; margin-bottom:16px; }
header h1 { margin:0; font-size:18px; letter-spacing:.16em; text-transform:uppercase; color:#fff; }
.badge { border:1px solid var(--green); color:var(--green); padding:6px 10px; font-size:11px;
  letter-spacing:.12em; text-transform:uppercase; }
.meta { margin-left:auto; font-family:ui-monospace,monospace; font-size:12px; color:var(--muted); }
.kpis { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin-bottom:16px; }
@media (max-width:1100px) { .kpis { grid-template-columns:repeat(2,minmax(0,1fr)); } }
.card { background:var(--panel); border:1px solid var(--line); padding:14px 16px; }
.card h2 { margin:0 0 8px; font-size:11px; letter-spacing:.14em; text-transform:uppercase; color:var(--muted); }
.card .val { font-family:ui-monospace,monospace; font-size:28px; color:#fff; }
.card .sub { margin-top:4px; font-size:12px; color:var(--muted); font-family:ui-monospace,monospace; }
.bar { height:8px; background:#10202c; margin-top:10px; }
.bar > span { display:block; height:100%; background:var(--cyan); }
.bar.ram > span { background:var(--warn); }
.drop-ok { color:var(--green); }
.grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
@media (max-width:1100px) { .grid { grid-template-columns:1fr; } }
table { width:100%; border-collapse:collapse; font-family:ui-monospace,monospace; font-size:12px; }
th,td { text-align:left; padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-size:10px; letter-spacing:.1em; text-transform:uppercase; }
.cmd { color:var(--muted); max-width:28em; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.st-NOMINAL { color:var(--green); }
.st-LOLBAS { color:var(--red); }
.st-SUSPECT { color:var(--warn); }
.inc { list-style:none; margin:0; padding:0; display:flex; flex-direction:column; gap:8px; }
.inc li { background:var(--card); border:1px solid var(--line); padding:8px; font-family:ui-monospace,monospace; font-size:11px; }
.inc .id { color:var(--cyan); word-break:break-all; }
.inc .fact { color:var(--muted); margin-top:4px; }
.gauge-scale { display:flex; justify-content:space-between; font-size:10px; color:var(--muted); margin-top:4px; }
meter { width:100%; height:14px; }
.subs { display:grid; grid-template-columns:repeat(4,1fr); gap:8px; margin-top:12px; }
.subs div { background:var(--card); border:1px solid var(--line); padding:8px; text-align:center; }
.subs dt { font-size:10px; color:var(--muted); letter-spacing:.1em; text-transform:uppercase; }
.subs dd { margin:4px 0 0; font-family:ui-monospace,monospace; font-size:18px; }
</style>
</head>
<body>
<header>
  <h1>C2BLUE — OBSERVATIONS SYSTEME</h1>
  <span class="badge">OBSERVATION PERIODIQUE / AUCUN BLOCAGE</span>
  <div class="meta">UTC <span id="utc">—</span> · uptime <span id="uptime">0s</span></div>
</header>
<section class="kpis">
  <article class="card">
    <h2>CPU Machine</h2>
    <div class="val"><span id="cpu">0.0</span>%</div>
    <div class="bar"><span id="cpu-bar" style="width:0%"></span></div>
  </article>
  <article class="card">
    <h2>Mémoire RAM</h2>
    <div class="val"><span id="mem-used">0</span></div>
    <div class="sub"><span id="mem-total">0</span> · <span id="mem-pct">0</span>%</div>
    <div class="bar ram"><span id="mem-bar" style="width:0%"></span></div>
  </article>
  <article class="card">
    <h2>Moteur c2blue SPSC</h2>
    <div class="val"><span id="eps">0</span></div>
    <div class="sub">observations/s · total <span id="etot">0</span></div>
  </article>
  <article class="card">
    <h2>Intégrité Ring Buffer</h2>
    <div class="val drop-ok">Drops : <span id="drops">0</span></div>
    <div class="sub">occupation <span id="occ">0</span> · 0 allocation tas chemin chaud</div>
  </article>
</section>
<section class="grid">
  <article class="card">
    <h2>Télémétrie moteur &amp; entropie Shannon</h2>
    <div class="val"><span id="ent">0.00</span> <span style="font-size:14px;color:var(--muted)">b/o</span></div>
    <meter id="ent-meter" min="0" max="8" value="0"></meter>
    <div class="gauge-scale"><span>Normal &lt; 4.5</span><span>Code 4.5–6.0</span><span>Crypto &gt; 7.5</span></div>
    <p class="sub" style="margin-top:12px">Divergence D<sub>JS</sub> Q8.8 : <span id="djs">0</span></p>
    <meter id="djs-meter" min="0" max="2048" value="0"></meter>
    <dl class="subs">
      <div><dt>Proc</dt><dd id="sub-proc">0</dd></div>
      <div><dt>File</dt><dd id="sub-file">0</dd></div>
      <div><dt>Net</dt><dd id="sub-net">0</dd></div>
      <div><dt>MCP</dt><dd id="sub-mcp">0</dd></div>
    </dl>
  </article>
  <article class="card">
    <h2>Flux réel des processus (/proc)</h2>
    <table>
      <thead><tr><th>PID</th><th>Binaire</th><th>Entropie</th><th>Statut</th></tr></thead>
      <tbody id="procs"></tbody>
    </table>
    <h2 style="margin-top:16px">Incidents scellés UUIDv7 RFC 9562</h2>
    <ol class="inc" id="incidents"></ol>
  </article>
</section>
<script>
(function () {
  function $(id) { return document.getElementById(id); }
  function fmtMB(v) {
    if (v >= 1024) return (v / 1024).toFixed(2) + " Go";
    return v.toFixed(0) + " Mo";
  }
  function setBar(id, pct) {
    var el = $(id);
    if (!el) return;
    if (pct < 0) pct = 0;
    if (pct > 100) pct = 100;
    el.style.width = pct.toFixed(1) + "%";
  }
  function renderProcs(list) {
    var tb = $("procs");
    tb.textContent = "";
    if (!list) return;
    var i;
    for (i = 0; i < list.length; i++) {
      var p = list[i];
      var tr = document.createElement("tr");
      var td0 = document.createElement("td"); td0.textContent = String(p.pid);
      var td1 = document.createElement("td");
      td1.textContent = p.comm || "";
      var cmd = document.createElement("div");
      cmd.className = "cmd";
      cmd.textContent = p.cmdline || "";
      td1.appendChild(cmd);
      var td2 = document.createElement("td"); td2.textContent = (p.entropy || 0).toFixed(2);
      var td3 = document.createElement("td");
      td3.className = "st-" + (p.status || "NOMINAL");
      td3.textContent = p.status || "NOMINAL";
      tr.appendChild(td0); tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3);
      tb.appendChild(tr);
    }
  }
  function renderInc(list) {
    var ol = $("incidents");
    ol.textContent = "";
    if (!list) return;
    var i, j;
    for (i = list.length - 1; i >= 0; i--) {
      var inc = list[i];
      var li = document.createElement("li");
      var id = document.createElement("div");
      id.className = "id";
      id.textContent = inc.id || "";
      li.appendChild(id);
      var facts = inc.facts || [];
      for (j = 0; j < facts.length; j++) {
        var f = document.createElement("div");
        f.className = "fact";
        f.textContent = (facts[j].type || "") + " · conf " + facts[j].confidence + " · " + (facts[j].evidence || "");
        li.appendChild(f);
      }
      ol.appendChild(li);
    }
  }
  function onTel(d) {
    if (!d) return;
    var h = d.host || {};
    var c = d.c2blue || {};
    $("cpu").textContent = (h.cpu_pct || 0).toFixed(1);
    setBar("cpu-bar", h.cpu_pct || 0);
    $("mem-used").textContent = fmtMB(h.mem_used_mb || 0);
    $("mem-total").textContent = "totale " + fmtMB(h.mem_total_mb || 0);
    $("mem-pct").textContent = (h.mem_pct || 0).toFixed(1);
    setBar("mem-bar", h.mem_pct || 0);
    $("eps").textContent = (c.events_per_sec || 0).toFixed(0);
    $("etot").textContent = String(c.events_total || 0);
    $("drops").textContent = String(c.ring_drops || 0);
    $("occ").textContent = String(c.ring_occupancy || 0);
    $("ent").textContent = (c.last_entropy_bits || 0).toFixed(2);
    $("ent-meter").value = c.last_entropy_bits || 0;
    $("djs").textContent = String(c.last_djs_q8 || 0);
    $("djs-meter").value = c.last_djs_q8 || 0;
    $("sub-proc").textContent = String(d.sub_proc || 0);
    $("sub-file").textContent = String(d.sub_file || 0);
    $("sub-net").textContent = String(d.sub_net || 0);
    $("sub-mcp").textContent = String(d.sub_mcp || 0);
    $("utc").textContent = d.utc || "";
    $("uptime").textContent = (d.uptime_s || 0).toFixed(1) + "s";
    renderProcs(d.procs);
    renderInc(d.incidents);
  }
  var es = new EventSource("/events");
  es.onmessage = function (ev) {
    try { onTel(JSON.parse(ev.data)); } catch (e) {}
  };
})();
</script>
</body>
</html>
`)
