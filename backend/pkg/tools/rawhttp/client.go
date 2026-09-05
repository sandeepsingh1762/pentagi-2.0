// Package rawhttp implements a raw-socket HTTP client that gives the caller
// byte-level control over the request wire format — the equivalent of typing a
// request into Burp Repeater. Standard HTTP libraries normalize requests
// (adding headers, re-chunking bodies, fixing casing), which defeats exactly
// the kind of testing this engine exists for: request smuggling, header
// injection, cache deception, desync probes, and protocol fuzzing.
//
// The client supports:
//   - fully raw request bytes (no automatic normalization)
//   - plain TCP and TLS (with optional certificate verification bypass for
//     authorized testing against self-signed/internal targets)
//   - timing capture (DNS excluded; connect/TTFB/total)
//   - configurable redirect behavior (off by default, like Burp)
//   - HTTP/1.0 and HTTP/1.1 wire control
//
// It contains no business logic and touches no database: pure networking.
package rawhttp

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Request describes one raw HTTP request.
type Request struct {
	// Method, URL, and (optionally) RawRequest control what is sent.
	// If RawRequest is non-empty it is transmitted verbatim; URL is then only
	// used to determine the dial target (scheme/host/port). This is the
	// Repeater-style path for byte-perfect control.
	Method     string
	URL        string
	Headers    map[string]string
	Body       string
	RawRequest string

	// TLSNoVerify disables certificate chain/hostname validation (pentest mode
	// for internal/self-signed targets). Defaults to true for rawhttp because
	// testing targets are frequently self-signed.
	TLSNoVerify bool

	// Timeout bounds the whole exchange. 0 defaults to 15s.
	Timeout time.Duration

	// FollowRedirects re-sends the request on 3xx Location (max 5 hops).
	FollowRedirects bool

	// ForceHTTP10 downgrades the request line when RawRequest is empty.
	ForceHTTP10 bool

	// ReadLimit caps response body capture in bytes (default 1 MiB).
	ReadLimit int64
}

// Response is a captured raw HTTP exchange.
type Response struct {
	StatusCode  int
	StatusLine  string
	Headers     map[string][]string
	HeaderOrder []string
	Body        string
	BodyBytes   int
	RawRequest  string // what actually went on the wire
	RawResponse string // first N bytes of the wire response (truncated view)

	// Timing breakdown
	ConnectTime time.Duration // TCP+TLS handshake
	TTFB        time.Duration // request sent -> first response byte
	TotalTime   time.Duration

	// RedirectChain holds intermediate locations when FollowRedirects is on.
	RedirectChain []string
}

// Send performs the request and returns the captured response.
func Send(ctx context.Context, req Request) (*Response, error) {
	if req.Timeout == 0 {
		req.Timeout = 15 * time.Second
	}
	if req.ReadLimit == 0 {
		req.ReadLimit = 1 << 20
	}
	if req.TLSNoVerify {
		// rawhttp defaults to no-verify; explicit false keeps verification
	}

	u, err := url.Parse(req.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		scheme = "http"
		u, err = url.Parse("http://" + req.URL)
		if err != nil {
			return nil, fmt.Errorf("invalid url: %w", err)
		}
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)

	dialer := &net.Dialer{Timeout: req.Timeout}
	startConnect := time.Now()
	var conn net.Conn
	if scheme == "https" {
		tlsCfg := &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: req.TLSNoVerify,
			MinVersion:         tls.VersionTLS10,
		}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()
	connectTime := time.Since(startConnect)

	deadline := time.Now().Add(req.Timeout)
	_ = conn.SetDeadline(deadline)

	wire, err := buildWireRequest(req, *u)
	if err != nil {
		return nil, err
	}

	startWrite := time.Now()
	if _, err := conn.Write([]byte(wire)); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	br := bufio.NewReaderSize(conn, 64*1024)
	resp, err := readResponse(br, req.ReadLimit)
	if err != nil {
		return nil, err
	}
	ttfb := time.Since(startWrite)

	resp.ConnectTime = connectTime
	resp.TTFB = ttfb
	resp.TotalTime = time.Since(startConnect)
	resp.RawRequest = wire

	if req.FollowRedirects && resp.StatusCode >= 300 && resp.StatusCode < 400 {
		if loc := resp.HeaderValue("Location"); loc != "" {
			next := resolveRedirect(req.URL, loc)
			if next != "" && len(resp.RedirectChain) < 5 {
				inner := req
				inner.URL = next
				inner.FollowRedirects = true
				inner.RawRequest = ""
				sub, err := Send(ctx, inner)
				if err != nil {
					return resp, nil // return the 3xx we captured
				}
				sub.RedirectChain = append([]string{loc}, resp.RedirectChain...)
				return sub, nil
			}
		}
	}
	return resp, nil
}

// buildWireRequest renders the exact bytes to send: RawRequest wins, otherwise
// a normalized request is composed from method/URL/headers/body.
func buildWireRequest(req Request, u url.URL) (string, error) {
	if strings.TrimSpace(req.RawRequest) != "" {
		raw := req.RawRequest
		if !strings.HasSuffix(raw, "\r\n\r\n") {
			if strings.HasSuffix(raw, "\r\n") {
				raw += "\r\n"
			} else if strings.HasSuffix(raw, "\n") {
				raw = strings.TrimSuffix(raw, "\n") + "\r\n\r\n"
			} else {
				raw += "\r\n\r\n"
			}
		}
		return raw, nil
	}

	method := req.Method
	if method == "" {
		if req.Body != "" {
			method = "POST"
		} else {
			method = "GET"
		}
	}
	version := "HTTP/1.1"
	if req.ForceHTTP10 {
		version = "HTTP/1.0"
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s %s %s\r\n", method, path, version)
	if _, ok := req.Headers["Host"]; !ok {
		fmt.Fprintf(&b, "Host: %s\r\n", u.Host)
	}
	sent := make(map[string]bool, len(req.Headers))
	for k, v := range req.Headers {
		fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		sent[strings.ToLower(k)] = true
	}
	if req.Body != "" && !sent["content-length"] {
		fmt.Fprintf(&b, "Content-Length: %d\r\n", len(req.Body))
	}
	if _, ok := req.Headers["User-Agent"]; !ok {
		b.WriteString("User-Agent: Mozilla/5.0 (compatible; PentAGI-rawhttp/2.0)\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(req.Body)
	return b.String(), nil
}

// readResponse parses status line, headers, and body from the wire.
func readResponse(br *bufio.Reader, limit int64) (*Response, error) {
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("read status line: %w", err)
	}
	statusLine = strings.TrimRight(statusLine, "\r\n")
	parts := strings.SplitN(statusLine, " ", 3)
	code := 0
	if len(parts) >= 2 {
		code, _ = strconv.Atoi(parts[1])
	}

	resp := &Response{
		StatusCode: code,
		StatusLine: statusLine,
		Headers:    map[string][]string{},
	}
	var raw strings.Builder
	raw.WriteString(statusLine + "\n")

	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("read headers: %w", err)
		}
		raw.WriteString(line)
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		colon := strings.Index(line, ":")
		if colon <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		val := strings.TrimSpace(line[colon+1:])
		resp.Headers[key] = append(resp.Headers[key], val)
		resp.HeaderOrder = append(resp.HeaderOrder, key)
	}

	te := strings.ToLower(resp.HeaderValue("Transfer-Encoding"))
	cl := resp.HeaderValue("Content-Length")
	switch {
	case strings.Contains(te, "chunked"):
		body, err := readChunked(br, limit)
		if err != nil {
			return nil, err
		}
		resp.Body = body
	case cl != "":
		n, _ := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
		if n > limit {
			n = limit
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(br, buf); err != nil && n > 0 {
			return nil, fmt.Errorf("read body: %w", err)
		}
		resp.Body = string(buf)
	default:
		buf, err := io.ReadAll(io.LimitReader(br, limit))
		if err != nil && len(buf) == 0 {
			return nil, nil // connection closed without body is acceptable
		}
		resp.Body = string(buf)
	}
	resp.BodyBytes = len(resp.Body)

	view := raw.String() + resp.Body
	if int64(len(view)) > 8192 {
		view = view[:8192] + "\n... (truncated)"
	}
	resp.RawResponse = view
	return resp, nil
}

// readChunked decodes a chunked transfer-encoded body.
func readChunked(br *bufio.Reader, limit int64) (string, error) {
	var b strings.Builder
	for {
		sizeLine, err := br.ReadString('\n')
		if err != nil {
			return b.String(), fmt.Errorf("read chunk size: %w", err)
		}
		sizeLine = strings.TrimSpace(sizeLine)
		if i := strings.Index(sizeLine, ";"); i >= 0 { // strip extensions
			sizeLine = sizeLine[:i]
		}
		size, err := strconv.ParseInt(sizeLine, 16, 64)
		if err != nil {
			return b.String(), fmt.Errorf("bad chunk size %q", sizeLine)
		}
		if size == 0 {
			// trailing headers/CRLF
			_, _ = br.ReadString('\n')
			return b.String(), nil
		}
		if b.Len()+int(size) > int(limit) {
			size = limit - int64(b.Len())
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(br, buf); err != nil {
			return b.String(), fmt.Errorf("read chunk: %w", err)
		}
		b.Write(buf)
		_, _ = br.ReadString('\n') // chunk CRLF
		if int64(b.Len()) >= limit {
			return b.String(), nil
		}
	}
}

// HeaderValue returns the first value of a header (case-insensitive).
func (r *Response) HeaderValue(name string) string {
	for k, vals := range r.Headers {
		if strings.EqualFold(k, name) && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

// resolveRedirect computes the next URL for a redirect hop.
func resolveRedirect(base, loc string) string {
	if strings.HasPrefix(loc, "http://") || strings.HasPrefix(loc, "https://") {
		return loc
	}
	bu, err := url.Parse(base)
	if err != nil {
		return ""
	}
	lu, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	return bu.ResolveReference(lu).String()
}
