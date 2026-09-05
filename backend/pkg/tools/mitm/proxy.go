// Package mitm implements the Burp-lite intercepting proxy engine:
// a forward HTTP proxy with traffic history (HTTP capture, HTTPS SNI/host
// visibility via CONNECT tunneling), plus Repeater (single crafted raw
// request) and Intruder (position-based fuzzing with payload sets and attack
// modes) primitives used by the tools layer.
//
// Design notes:
//   - Plain HTTP traffic is captured in full (method, URL, headers, body,
//     status, response headers/body).
//   - HTTPS traffic through CONNECT is relayed byte-for-byte without
//     certificate forgery (no trusted CA is installed in target containers);
//     the proxy records host/SNI and byte counts. Full HTTPS inspection should
//     use the rawhttp repeater against the target directly.
//   - History is an in-memory ring buffer scoped to one engine instance
//     (one flow), protected by a mutex. It is intentionally not persisted.
package mitm

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Entry is one captured traffic record (HTTP history row).
type Entry struct {
	ID            int64     `json:"id"`
	Timestamp     time.Time `json:"timestamp"`
	Method        string    `json:"method"`
	Scheme        string    `json:"scheme"`
	Host          string    `json:"host"`
	Path          string    `json:"path"`
	Query         string    `json:"query,omitempty"`
	StatusCode    int       `json:"status_code"`
	RequestBytes  int       `json:"request_bytes"`
	ResponseBytes int       `json:"response_bytes"`
	ReqHeaders    string    `json:"req_headers,omitempty"`
	ReqBody       string    `json:"req_body,omitempty"`
	RespHeaders   string    `json:"resp_headers,omitempty"`
	RespBody      string    `json:"resp_body,omitempty"`
	HTTPS         bool      `json:"https"`
}

// Scope controls which hosts the proxy captures (Burp target scope).
type Scope struct {
	Include []*regexp.Regexp `json:"-"`
	Exclude []*regexp.Regexp `json:"-"`
}

// NewScopeFromPatterns compiles include/exclude regex patterns.
func NewScopeFromPatterns(include, exclude []string) (*Scope, error) {
	s := &Scope{}
	for _, p := range include {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("bad include pattern %q: %w", p, err)
		}
		s.Include = append(s.Include, re)
	}
	for _, p := range exclude {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("bad exclude pattern %q: %w", p, err)
		}
		s.Exclude = append(s.Exclude, re)
	}
	return s, nil
}

// Matches reports whether host+path is in scope.
func (s *Scope) Matches(host, path string) bool {
	target := host + path
	for _, re := range s.Exclude {
		if re.MatchString(target) {
			return false
		}
	}
	if len(s.Include) == 0 {
		return true
	}
	for _, re := range s.Include {
		if re.MatchString(target) {
			return true
		}
	}
	return false
}

// Engine is one proxy instance (per flow).
type Engine struct {
	id       int
	addr     string
	listener net.Listener
	scope    *Scope
	entries  []Entry
	nextID   int64
	maxEnts  int
	mu       sync.Mutex
	closed   bool
	started  time.Time
}

const (
	defaultMaxEntries = 500
	maxBodyCapture    = 16 * 1024 // per-direction body capture limit
)

var (
	enginesMu sync.Mutex
	engines   = map[int]*Engine{}
	nextEngID int
)

// Start launches a new proxy engine bound to 0.0.0.0:port (port 0 = ephemeral).
// include/exclude are optional regex scope patterns matched against host+path.
func Start(port int, include, exclude []string) (*Engine, error) {
	scope, err := NewScopeFromPatterns(include, exclude)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		return nil, fmt.Errorf("proxy listen: %w", err)
	}

	enginesMu.Lock()
	nextEngID++
	eng := &Engine{
		id:       nextEngID,
		addr:     ln.Addr().String(),
		listener: ln,
		scope:    scope,
		maxEnts:  defaultMaxEntries,
		started:  time.Now(),
	}
	engines[eng.id] = eng
	enginesMu.Unlock()

	go eng.serve()
	return eng, nil
}

// GetEngine returns a running engine by id.
func GetEngine(id int) (*Engine, error) {
	enginesMu.Lock()
	defer enginesMu.Unlock()
	e, ok := engines[id]
	if !ok {
		return nil, fmt.Errorf("proxy engine %d not found (stopped or never started)", id)
	}
	return e, nil
}

// StopEngine shuts down an engine by id.
func StopEngine(id int) error {
	enginesMu.Lock()
	defer enginesMu.Unlock()
	e, ok := engines[id]
	if !ok {
		return fmt.Errorf("proxy engine %d not found", id)
	}
	e.closed = true
	_ = e.listener.Close()
	delete(engines, id)
	return nil
}

// StopAll shuts down every engine (process shutdown safety).
func StopAll() {
	enginesMu.Lock()
	defer enginesMu.Unlock()
	for id, e := range engines {
		e.closed = true
		_ = e.listener.Close()
		delete(engines, id)
	}
}

// Addr returns the listening address.
func (e *Engine) Addr() string { return e.addr }

// Port returns the listening port.
func (e *Engine) Port() int {
	_, port, _ := net.SplitHostPort(e.addr)
	var p int
	fmt.Sscanf(port, "%d", &p)
	return p
}

// ID returns the engine id.
func (e *Engine) ID() int { return e.id }

// Uptime returns how long the engine has been running.
func (e *Engine) Uptime() time.Duration { return time.Since(e.started) }

func (e *Engine) serve() {
	for {
		conn, err := e.listener.Accept()
		if err != nil {
			return
		}
		go e.handleConn(conn)
	}
}

func (e *Engine) handleConn(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)

	reqLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(strings.TrimSpace(reqLine))
	if len(parts) < 3 {
		return
	}
	method, target := parts[0], parts[1]

	// read headers
	headers := make(map[string]string)
	var headerLines []string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		headerLines = append(headerLines, strings.TrimRight(line, "\r\n"))
		if i := strings.Index(line, ":"); i > 0 {
			headers[strings.ToLower(strings.TrimSpace(line[:i]))] = strings.TrimSpace(line[i+1:])
		}
	}

	if strings.EqualFold(method, "CONNECT") {
		e.handleConnect(conn, br, target, headerLines)
		return
	}

	// absolute-form proxy request: GET http://host/path HTTP/1.1
	u, err := url.Parse(target)
	if err != nil || u.Host == "" {
		// origin-form: requires Host header
		u = &url.URL{Scheme: "http", Host: headers["host"], Path: target}
		if q := strings.Index(target, "?"); q >= 0 {
			u.Path = target[:q]
			u.RawQuery = target[q+1:]
		}
	}
	body := readBody(br, headers)

	e.relayAndCapture(conn, u, method, headerLines, body)
}

// handleConnect relays TLS tunnels and records host visibility.
func (e *Engine) handleConnect(client net.Conn, br *bufio.Reader, target string, headerLines []string) {
	host := target
	if _, port, err := net.SplitHostPort(target); err == nil && port == "443" {
		// keep as-is
	}
	e.record(Entry{
		Method: "CONNECT", Scheme: "https", Host: host, HTTPS: true,
		ReqHeaders: strings.Join(headerLines, "\n"),
	})

	upstream, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()
	fmt.Fprintf(client, "HTTP/1.1 200 Connection Established\r\n\r\n")

	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(upstream, br); done <- struct{}{} }()
	go func() { _, _ = io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

// relayAndCapture forwards an origin-form HTTP request to its origin host and
// captures both directions into history.
func (e *Engine) relayAndCapture(client net.Conn, u *url.URL, method string, headerLines []string, body string) {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "80"
	}

	entry := Entry{
		Method: method, Scheme: "http", Host: u.Host,
		Path: u.Path, Query: u.RawQuery, HTTPS: false,
	}
	if !e.scope.Matches(u.Host, u.Path) {
		fmt.Fprintf(client, "HTTP/1.1 403 Out of scope\r\nContent-Length: 0\r\n\r\n")
		return
	}

	upstream, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()

	// rebuild request in origin-form
	reqBuf := &strings.Builder{}
	fmt.Fprintf(reqBuf, "%s %s HTTP/1.1\r\n", method, u.RequestURI())
	for _, hl := range headerLines {
		lower := strings.ToLower(hl)
		if strings.HasPrefix(lower, "proxy-") || strings.HasPrefix(lower, "host:") {
			continue
		}
		reqBuf.WriteString(hl + "\r\n")
	}
	fmt.Fprintf(reqBuf, "Host: %s\r\n", u.Host)
	if body != "" {
		fmt.Fprintf(reqBuf, "Content-Length: %d\r\n", len(body))
	}
	reqBuf.WriteString("\r\n")
	reqBuf.WriteString(body)

	entry.ReqHeaders = strings.Join(headerLines, "\n")
	entry.ReqBody = truncate(body, maxBodyCapture)
	entry.RequestBytes = reqBuf.Len()

	if _, err := upstream.Write([]byte(reqBuf.String())); err != nil {
		fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}

	// stream the response back while capturing. Body relaying honors
	// Content-Length (or streams until EOF) so keep-alive origins cannot
	// stall the exchange. Hop-by-hop connection reuse is disabled: the
	// response is emitted with Connection: close, matching our relay
	// lifecycle (one request per client connection).
	br := bufio.NewReader(upstream)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		fmt.Fprintf(client, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	fmt.Fprint(client, statusLine)
	var respHeaders strings.Builder
	_, _ = fmt.Sscanf(statusLine, "HTTP/1.%d %d", new(int), &entry.StatusCode)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		if strings.TrimSpace(line) == "" {
			break // header block terminator is re-emitted below
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "connection:") || strings.HasPrefix(lower, "proxy-connection:") ||
			strings.HasPrefix(lower, "keep-alive:") {
			continue // hop-by-hop headers are rewritten for the client
		}
		respHeaders.WriteString(strings.TrimRight(line, "\r\n") + "\n")
		fmt.Fprint(client, line)
	}
	// close the header block with forced connection-close semantics
	fmt.Fprint(client, "Connection: close\r\n\r\n")

	respBody := relayBody(client, br, respHeaders.String())
	entry.RespHeaders = strings.TrimRight(respHeaders.String(), "\n")
	entry.RespBody = truncate(respBody, maxBodyCapture)
	entry.ResponseBytes = len(statusLine) + respHeaders.Len() + len(respBody)
	e.record(entry)
}

// relayBody copies the response body to the client and captures up to
// maxBodyCapture bytes. Content-Length-bounded bodies are read exactly;
// anything else streams until upstream EOF (bounded by the connection
// deadline set by the caller dial timeout path).
func relayBody(client net.Conn, br *bufio.Reader, headerBlock string) string {
	cl := parseContentLength(headerBlock)
	switch {
	case cl > 0 && cl <= maxBodyCapture:
		buf := make([]byte, cl)
		n, _ := io.ReadFull(br, buf)
		if n > 0 {
			_, _ = client.Write(buf[:n])
		}
		return string(buf[:n])
	case cl > maxBodyCapture:
		// oversized: stream through, capture the head
		captured := &strings.Builder{}
		remaining := cl
		chunk := make([]byte, 8192)
		var got strings.Builder
		for remaining > 0 {
			n, err := br.Read(chunk)
			if n > 0 {
				_, _ = client.Write(chunk[:n])
				if got.Len() < maxBodyCapture {
					got.Write(chunk[:min(n, maxBodyCapture-got.Len())])
				}
				remaining -= int64(n)
			}
			if err != nil {
				break
			}
		}
		captured.WriteString(got.String())
		return captured.String()
	default:
		// no content-length: stream until upstream EOF
		buf := make([]byte, 8192)
		var got strings.Builder
		for {
			n, err := br.Read(buf)
			if n > 0 {
				_, _ = client.Write(buf[:n])
				if got.Len() < maxBodyCapture {
					got.Write(buf[:min(n, maxBodyCapture-got.Len())])
				}
			}
			if err != nil {
				break
			}
		}
		return got.String()
	}
}

// parseContentLength extracts Content-Length from a raw header block.
func parseContentLength(headerBlock string) int64 {
	for _, line := range strings.Split(headerBlock, "\n") {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(line)), "content-length:") {
			v := strings.TrimSpace(line[len("content-length:"):])
			var n int64
			fmt.Sscanf(v, "%d", &n)
			return n
		}
	}
	return 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// readBody consumes a request body honoring Content-Length.
func readBody(br *bufio.Reader, headers map[string]string) string {
	cl := headers["content-length"]
	if cl == "" {
		return ""
	}
	var n int
	fmt.Sscanf(cl, "%d", &n)
	if n <= 0 {
		return ""
	}
	if n > maxBodyCapture {
		n = maxBodyCapture
	}
	buf := make([]byte, n)
	total := 0
	for total < n {
		r, err := br.Read(buf[total:])
		if err != nil {
			break
		}
		total += r
	}
	return string(buf[:total])
}

func (e *Engine) record(entry Entry) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nextID++
	entry.ID = e.nextID
	entry.Timestamp = time.Now()
	e.entries = append(e.entries, entry)
	if len(e.entries) > e.maxEnts {
		// drop oldest 20% in one shot to avoid per-insert shifting
		cut := e.maxEnts / 5
		e.entries = e.entries[cut:]
	}
}

// History returns captured entries, optionally filtered by regex over
// "method host path status" summary or body contents.
func (e *Engine) History(filter string, onlyInScopeBodies bool, limit int) []Entry {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Entry, 0, len(e.entries))
	var re *regexp.Regexp
	if filter != "" {
		re, _ = regexp.Compile("(?i)" + filter)
	}
	for i := len(e.entries) - 1; i >= 0; i-- {
		en := e.entries[i]
		if re != nil {
			hay := fmt.Sprintf("%s %s %s %d %s %s", en.Method, en.Host, en.Path, en.StatusCode, en.ReqBody, en.RespBody)
			if !re.MatchString(hay) {
				continue
			}
		}
		out = append(out, en)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// Clear empties the history buffer.
func (e *Engine) Clear() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.entries = nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}

// ShutdownContext lets callers stop the engine on flow teardown.
func (e *Engine) ShutdownContext(ctx context.Context) error {
	return StopEngine(e.id)
}
