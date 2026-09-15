package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"

	"code.hazyhaar.fr/devhoros/pkg/c2blue55"
	"code.hazyhaar.fr/devhoros/pkg/c2blue55/socagent"
)

const maxScanLine = 1 << 20

var (
	methodToolsCall = []byte("tools/call")
	keyMethod       = []byte("method")
	keyID           = []byte("id")
	keyParams       = []byte("params")
	keyName         = []byte("name")
	keyArguments    = []byte("arguments")
	nl              = []byte{'\n'}
)

func FilterLine(line []byte) (forward bool, vetoResponse []byte, incident *socagent.Dossier) {
	method, idRaw, name, args, hasID, ok := parseMCPCall(line)
	if !ok {
		return false, []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32600,"message":"Invalid or ambiguous JSON-RPC request"}}`), nil
	}
	if !bytes.Equal(method, methodToolsCall) {
		return true, nil, nil
	}
	var arguments any
	decoder := json.NewDecoder(bytes.NewReader(args))
	decoder.UseNumber()
	if err := decoder.Decode(&arguments); err != nil {
		return false, encodeVeto(idRaw, name, 0), nil
	}
	args, _ = json.Marshal(arguments)
	djs, flags, vetoJSON := c2blue55.EvalToolCall(bytesString(name), args)
	if vetoJSON == nil && flags&(c2blue55.FlagAnomaly|c2blue55.FlagSuspiciousMCP|c2blue55.FlagBlocked) == 0 {
		return true, nil, nil
	}
	if hasID {
		vetoResponse = encodeVeto(idRaw, name, djs)
		var engineVeto struct {
			Error struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(vetoJSON, &engineVeto) == nil && engineVeto.Error.Code == -32601 {
			response := struct {
				JSONRPC string          `json:"jsonrpc"`
				ID      json.RawMessage `json:"id"`
				Error   any             `json:"error"`
			}{"2.0", idRaw, engineVeto.Error}
			vetoResponse, _ = json.Marshal(response)
		}
	}
	return false, vetoResponse, incident
}

func RunRelay(in io.Reader, out io.Writer, backendIn io.Writer, backendOut io.Reader) error {
	inputJoined, outputJoined := make(chan struct{}), make(chan struct{})
	defer func() {
		if c, ok := in.(io.Closer); ok {
			_ = c.Close()
		}
		if c, ok := backendIn.(io.Closer); ok {
			_ = c.Close()
		}
		if c, ok := backendOut.(io.Closer); ok {
			_ = c.Close()
		}
		if c, ok := out.(io.Closer); ok {
			_ = c.Close()
		}
		// The executable supplies closable OS pipes. Arbitrary non-closable
		// Reader/Writer implementations cannot promise interruptible I/O.
		timer := time.NewTimer(2 * time.Second)
		defer timer.Stop()
		for _, joined := range []chan struct{}{inputJoined, outputJoined} {
			select {
			case <-joined:
			case <-timer.C:
				return
			}
		}
	}()
	var outMu sync.Mutex
	errCh := make(chan error, 1)
	go func() {
		defer close(outputJoined)
		errCh <- copyLocked(&outMu, out, backendOut)
	}()
	inputDone := make(chan error, 1)
	go func() {
		defer close(inputJoined)
		inputDone <- relayRequests(in, out, backendIn, &outMu)
	}()
	select {
	case err := <-errCh:
		if err != nil {
			return err
		}
		select {
		case err := <-inputDone:
			return err
		default:
		}
		return fmt.Errorf("backend output closed")
	case err := <-inputDone:
		if err != nil {
			return err
		}
	}
	if c, ok := backendIn.(io.Closer); ok {
		_ = c.Close()
	}
	select {
	case err := <-errCh:
		return err
	case <-time.After(2 * time.Second):
		return fmt.Errorf("backend output did not close after input EOF")
	}
}

func relayRequests(in io.Reader, out io.Writer, backendIn io.Writer, outMu *sync.Mutex) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), maxScanLine)
	for sc.Scan() {
		line := sc.Bytes()
		forward, veto, _ := FilterLine(line)
		if forward {
			if err := writeMessage(backendIn, line); err != nil {
				return err
			}
			continue
		}
		if len(veto) == 0 {
			continue
		}
		outMu.Lock()
		err := writeMessage(out, veto)
		outMu.Unlock()
		if err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return nil
}

func writeMessage(out io.Writer, line []byte) error {
	message := append(append(make([]byte, 0, len(line)+1), line...), '\n')
	n, err := out.Write(message)
	if err == nil && n != len(message) {
		return io.ErrShortWrite
	}
	return err
}

func main() {
	cmdPath := flag.String("cmd", "", "commande du serveur MCP sous-jacent")
	flag.Parse()
	if *cmdPath == "" {
		fmt.Fprintf(os.Stderr, "usage: %s -cmd /path/to/mcp-server [args...]\n", os.Args[0])
		os.Exit(2)
	}
	if err := loadDefaultCatalog(); err != nil {
		fmt.Fprintf(os.Stderr, "c2blue-mcp-guard: catalogue: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "c2blue-mcp-guard: refus transmis au client; aucun dossier persistant")
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	child := exec.CommandContext(ctx, *cmdPath, flag.Args()...)
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	child.Cancel = func() error { return syscall.Kill(-child.Process.Pid, syscall.SIGKILL) }
	child.WaitDelay = 2 * time.Second
	child.Stderr = os.Stderr
	stdin, err := child.StdinPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "c2blue-mcp-guard: stdin pipe: %v\n", err)
		os.Exit(1)
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "c2blue-mcp-guard: stdout pipe: %v\n", err)
		os.Exit(1)
	}
	if err := child.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "c2blue-mcp-guard: start: %v\n", err)
		os.Exit(1)
	}
	err = RunRelay(os.Stdin, os.Stdout, stdin, stdout)
	_ = stdin.Close()
	if err != nil {
		_ = child.Cancel()
	}
	waited := make(chan error, 1)
	go func() { waited <- child.Wait() }()
	var waitErr error
	select {
	case waitErr = <-waited:
	case <-time.After(2 * time.Second):
		_ = child.Cancel()
		waitErr = <-waited
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "c2blue-mcp-guard: relay: %v\n", err)
		os.Exit(1)
	}
	if waitErr != nil {
		fmt.Fprintf(os.Stderr, "c2blue-mcp-guard: child: %v\n", waitErr)
		os.Exit(1)
	}
}

func loadDefaultCatalog() error {
	return c2blue55.RegisterToolGrammar("read_file", []byte(`{"path":"/workspace/src/main.go"}`), 0x0001, 64)
}

func encodeVeto(idRaw, tool []byte, djs uint32) []byte {
	dst := make([]byte, 0, 192+len(idRaw)+len(tool))
	dst = append(dst, `{"jsonrpc":"2.0","id":`...)
	dst = append(dst, idRaw...)
	dst = append(dst, `,"error":{"code":-32003,"message":"C2BLUE_VETO: Tool grammar divergence D_JS violation","data":{"tool":`...)
	dst = appendJSONString(dst, tool)
	dst = append(dst, `,"djs_q8":`...)
	dst = strconv.AppendUint(dst, uint64(djs), 10)
	dst = append(dst, `}}}`...)
	return dst
}

func appendJSONString(dst, s []byte) []byte {
	dst = append(dst, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"', '\\':
			dst = append(dst, '\\', c)
		case '\n':
			dst = append(dst, '\\', 'n')
		case '\r':
			dst = append(dst, '\\', 'r')
		case '\t':
			dst = append(dst, '\\', 't')
		default:
			if c < 0x20 {
				const hexdigits = "0123456789abcdef"
				dst = append(dst, '\\', 'u', '0', '0', hexdigits[c>>4], hexdigits[c&0xF])
			} else {
				dst = append(dst, c)
			}
		}
	}
	return append(dst, '"')
}

func copyLocked(mu *sync.Mutex, dst io.Writer, src io.Reader) error {
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 64*1024), maxScanLine)
	for sc.Scan() {
		line := append(sc.Bytes(), '\n')
		mu.Lock()
		n, err := dst.Write(line)
		mu.Unlock()
		if err != nil {
			return err
		}
		if n != len(line) {
			return io.ErrShortWrite
		}
	}
	return sc.Err()
}

func bytesString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}

func parseMCPCall(line []byte) (method, idRaw, name, args []byte, hasID bool, ok bool) {
	if !utf8.Valid(line) || !json.Valid(line) || !uniqueJSON(line) || !validEnvelope(line) {
		return
	}
	i := skipWS(line, 0)
	if i >= len(line) || line[i] != '{' {
		return
	}
	i++
	for {
		i = skipWS(line, i)
		if i >= len(line) {
			return
		}
		if line[i] == '}' {
			ok = validCall(method, idRaw, name, args, hasID)
			return
		}
		key, next, pok := parseString(line, i)
		if !pok {
			return
		}
		i = skipWS(line, next)
		if i >= len(line) || line[i] != ':' {
			return
		}
		i++
		i = skipWS(line, i)
		switch {
		case bytes.Equal(key, keyMethod):
			inner, next, pok := parseString(line, i)
			if !pok {
				return
			}
			method = inner
			i = next
		case bytes.Equal(key, keyID):
			start := i
			next, pok := skipValue(line, i)
			if !pok {
				return
			}
			idRaw = line[start:next]
			hasID = true
			i = next
		case bytes.Equal(key, keyParams):
			n, a, next, pok := parseParams(line, i)
			if !pok {
				return
			}
			name, args = n, a
			i = next
		default:
			next, pok := skipValue(line, i)
			if !pok {
				return
			}
			i = next
		}
		i = skipWS(line, i)
		if i >= len(line) {
			return
		}
		if line[i] == ',' {
			i++
			continue
		}
		if line[i] == '}' {
			ok = validCall(method, idRaw, name, args, hasID)
			return
		}
		return
	}
}

func parseParams(b []byte, i int) (name, args []byte, next int, ok bool) {
	i = skipWS(b, i)
	if i >= len(b) || b[i] != '{' {
		return
	}
	i++
	for {
		i = skipWS(b, i)
		if i >= len(b) {
			return
		}
		if b[i] == '}' {
			return name, args, i + 1, true
		}
		key, n, pok := parseString(b, i)
		if !pok {
			return
		}
		i = skipWS(b, n)
		if i >= len(b) || b[i] != ':' {
			return
		}
		i++
		i = skipWS(b, i)
		switch {
		case bytes.Equal(key, keyName):
			inner, n, pok := parseString(b, i)
			if !pok {
				return
			}
			name = inner
			i = n
		case bytes.Equal(key, keyArguments):
			start := i
			n, pok := skipValue(b, i)
			if !pok {
				return
			}
			args = b[start:n]
			i = n
		default:
			n, pok := skipValue(b, i)
			if !pok {
				return
			}
			i = n
		}
		i = skipWS(b, i)
		if i >= len(b) {
			return
		}
		if b[i] == ',' {
			i++
			continue
		}
		if b[i] == '}' {
			return name, args, i + 1, true
		}
		return
	}
}

func parseString(b []byte, i int) (inner []byte, next int, ok bool) {
	if i >= len(b) || b[i] != '"' {
		return nil, i, false
	}
	i++
	start := i
	for i < len(b) {
		c := b[i]
		if c == '\\' {
			i += 2
			if i > len(b) {
				return nil, i, false
			}
			continue
		}
		if c == '"' {
			var decoded string
			if err := json.Unmarshal(b[start-1:i+1], &decoded); err != nil {
				return nil, i, false
			}
			return []byte(decoded), i + 1, true
		}
		i++
	}
	return nil, i, false
}

func skipWS(b []byte, i int) int {
	for i < len(b) {
		c := b[i]
		if c != ' ' && c != '\t' && c != '\n' && c != '\r' {
			return i
		}
		i++
	}
	return i
}

func skipValue(b []byte, i int) (int, bool) {
	i = skipWS(b, i)
	if i >= len(b) {
		return i, false
	}
	switch b[i] {
	case '"':
		_, n, ok := parseString(b, i)
		return n, ok
	case '{', '[':
		return skipContainer(b, i)
	case 't':
		if i+4 <= len(b) && b[i+1] == 'r' && b[i+2] == 'u' && b[i+3] == 'e' {
			return i + 4, true
		}
		return i, false
	case 'f':
		if i+5 <= len(b) && b[i+1] == 'a' && b[i+2] == 'l' && b[i+3] == 's' && b[i+4] == 'e' {
			return i + 5, true
		}
		return i, false
	case 'n':
		if i+4 <= len(b) && b[i+1] == 'u' && b[i+2] == 'l' && b[i+3] == 'l' {
			return i + 4, true
		}
		return i, false
	default:
		return skipNumber(b, i)
	}
}

func skipContainer(b []byte, i int) (int, bool) {
	if i >= len(b) || (b[i] != '{' && b[i] != '[') {
		return i, false
	}
	depth := 0
	for i < len(b) {
		switch b[i] {
		case '"':
			_, n, ok := parseString(b, i)
			if !ok {
				return i, false
			}
			i = n
		case '{', '[':
			depth++
			i++
		case '}', ']':
			depth--
			i++
			if depth == 0 {
				return i, true
			}
			if depth < 0 {
				return i, false
			}
		default:
			i++
		}
	}
	return i, false
}

func skipNumber(b []byte, i int) (int, bool) {
	if i >= len(b) {
		return i, false
	}
	if b[i] == '-' {
		i++
	}
	if i >= len(b) || b[i] < '0' || b[i] > '9' {
		return i, false
	}
	for i < len(b) && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	if i < len(b) && b[i] == '.' {
		i++
		if i >= len(b) || b[i] < '0' || b[i] > '9' {
			return i, false
		}
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
	}
	if i < len(b) && (b[i] == 'e' || b[i] == 'E') {
		i++
		if i < len(b) && (b[i] == '+' || b[i] == '-') {
			i++
		}
		if i >= len(b) || b[i] < '0' || b[i] > '9' {
			return i, false
		}
		for i < len(b) && b[i] >= '0' && b[i] <= '9' {
			i++
		}
	}
	return i, true
}
