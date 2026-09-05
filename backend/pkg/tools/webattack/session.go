// Package webattack implements the web-exploitation specialization layer:
// session-aware HTTP, response differencing for injection detection,
// automated injection hunting, credential attacks, JWT tampering, cookie
// auditing, and WAF fingerprinting — for use against authorized targets only.
package webattack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/tools/rawhttp"
)

// Session is a stateful, cookie-aware HTTP session against one origin.
type Session struct {
	ID          int64
	FlowID      int64
	BaseURL     string
	UserAgent   string
	Timeout     time.Duration
	TLSNoVerify bool

	mu       sync.Mutex
	cookies  map[string]map[string]*cookieEntry // host -> name -> cookie
	headers  map[string]string                  // persistent headers (Authorization, CSRF...)
	Requests int
	LoggedIn bool
	LoginURL string
}

type cookieEntry struct {
	Name     string
	Value    string
	HttpOnly bool
	Secure   bool
	SameSite string
	Raw      string
}

var (
	sessMu    sync.Mutex
	sessions  = map[int64]*Session{}
	nextSess  int64
)

// NewSession creates and registers a session.
func NewSession(flowID int64, baseURL string, timeoutSec int) (*Session, error) {
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "http://" + baseURL
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid base url %q", baseURL)
	}
	if timeoutSec <= 0 {
		timeoutSec = 15
	}
	sessMu.Lock()
	defer sessMu.Unlock()
	nextSess++
	s := &Session{
		ID:          nextSess,
		FlowID:      flowID,
		BaseURL:     strings.TrimRight(baseURL, "/"),
		UserAgent:   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
		Timeout:     time.Duration(timeoutSec) * time.Second,
		TLSNoVerify: true,
		cookies:     map[string]map[string]*cookieEntry{},
		headers:     map[string]string{},
	}
	sessions[s.ID] = s
	return s, nil
}

// GetSession returns a session by id.
func GetSession(id int64) (*Session, error) {
	sessMu.Lock()
	defer sessMu.Unlock()
	s, ok := sessions[id]
	if !ok {
		return nil, fmt.Errorf("web session %d not found", id)
	}
	return s, nil
}

// DropSession removes a session.
func DropSession(id int64) {
	sessMu.Lock()
	defer sessMu.Unlock()
	delete(sessions, id)
}

// Exchange is one request/response round trip through a session.
type Exchange struct {
	StatusCode int
	StatusLine string
	Headers    map[string][]string
	Body       string
	SetCookies []string
	Elapsed    time.Duration
	FinalURL   string
}

// resolve turns a possibly-relative path into an absolute URL on the session origin.
func (s *Session) resolve(raw string) string {
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		return raw
	}
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	return s.BaseURL + raw
}

// Do sends one request with session cookies and persistent headers applied,
// and absorbs Set-Cookie from the response into the jar.
func (s *Session) Do(ctx context.Context, method, target string, headers map[string]string, body string, followRedirects bool) (*Exchange, error) {
	full := s.resolve(target)
	u, err := url.Parse(full)
	if err != nil {
		return nil, fmt.Errorf("invalid url: %w", err)
	}

	s.mu.Lock()
	reqHeaders := map[string]string{}
	for k, v := range s.headers {
		reqHeaders[k] = v
	}
	for k, v := range headers {
		reqHeaders[k] = v
	}
	if _, ok := reqHeaders["Cookie"]; !ok {
		jar := s.cookies[u.Host]
		if len(jar) > 0 {
			parts := make([]string, 0, len(jar))
			for _, c := range jar {
				parts = append(parts, c.Name+"="+c.Value)
			}
			reqHeaders["Cookie"] = strings.Join(parts, "; ")
		}
	}
	if _, ok := reqHeaders["User-Agent"]; !ok {
		reqHeaders["User-Agent"] = s.UserAgent
	}
	s.Requests++
	s.mu.Unlock()

	req := rawhttp.Request{
		URL:             full,
		Method:          method,
		Headers:         reqHeaders,
		Body:            body,
		TLSNoVerify:     s.TLSNoVerify,
		Timeout:         s.Timeout,
		FollowRedirects: followRedirects,
	}
	resp, err := rawhttp.Send(ctx, req)
	if err != nil {
		return nil, err
	}

	setC := resp.Headers["Set-Cookie"]
	if len(setC) > 0 {
		s.absorbCookies(u.Host, setC)
	}
	return &Exchange{
		StatusCode: resp.StatusCode,
		StatusLine: resp.StatusLine,
		Headers:    resp.Headers,
		Body:       resp.Body,
		SetCookies: setC,
		Elapsed:    resp.TotalTime,
		FinalURL:   full,
	}, nil
}

func (s *Session) cookieHeader(host string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	jar := s.cookies[host]
	if len(jar) == 0 {
		return ""
	}
	parts := make([]string, 0, len(jar))
	for _, c := range jar {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; ")
}

func (s *Session) absorbCookies(host string, raws []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	jar := s.cookies[host]
	if jar == nil {
		jar = map[string]*cookieEntry{}
		s.cookies[host] = jar
	}
	for _, raw := range raws {
		segments := strings.Split(raw, ";")
		nv := strings.TrimSpace(segments[0])
		eq := strings.Index(nv, "=")
		if eq <= 0 {
			continue
		}
		entry := &cookieEntry{
			Name:  strings.TrimSpace(nv[:eq]),
			Value: strings.TrimPrefix(strings.TrimSpace(nv[eq+1:]), "\""),
			Raw:   raw,
		}
		for _, seg := range segments[1:] {
			seg = strings.TrimSpace(strings.ToLower(seg))
			switch {
			case seg == "httponly":
				entry.HttpOnly = true
			case seg == "secure":
				entry.Secure = true
			case strings.HasPrefix(seg, "samesite="):
				entry.SameSite = strings.TrimPrefix(seg, "samesite=")
			}
		}
		jar[entry.Name] = entry
	}
}

// SetHeader sets a persistent header (e.g. Authorization) on the session.
func (s *Session) SetHeader(name, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if value == "" {
		delete(s.headers, name)
	} else {
		s.headers[name] = value
	}
}

// Login performs an authentication attempt and records success.
type LoginRequest struct {
	URL         string            `json:"url"`
	Method      string            `json:"method,omitempty"`
	Format      string            `json:"format,omitempty"` // "json" | "form" (default form)
	UserField   string            `json:"user_field,omitempty"`
	PassField   string            `json:"pass_field,omitempty"`
	Username    string            `json:"username"`
	Password    string            `json:"password"`
	ExtraFields map[string]string `json:"extra_fields,omitempty"`
	Success     *SuccessRule      `json:"success,omitempty"`
}

type LoginResult struct {
	Success     bool     `json:"success"`
	Reason      string   `json:"reason"`
	Cookies     []string `json:"cookies_set,omitempty"`
	StatusCode  int      `json:"status_code"`
	RedirectTo  string   `json:"redirect_to,omitempty"`
	BodySnippet string   `json:"body_snippet,omitempty"`
}

// Login posts credentials and evaluates the success rule; on success the
// session keeps the issued cookies/headers for subsequent requests.
func (s *Session) Login(ctx context.Context, lr LoginRequest) (*LoginResult, error) {
	if strings.TrimSpace(lr.URL) == "" {
		return nil, fmt.Errorf("login url is required")
	}
	method := lr.Method
	if method == "" {
		method = "POST"
	}
	if lr.UserField == "" {
		lr.UserField = "username"
	}
	if lr.PassField == "" {
		lr.PassField = "password"
	}

	before := s.cookieSnapshot()

	var body string
	headers := map[string]string{}
	switch strings.ToLower(lr.Format) {
	case "json":
		payload := map[string]string{
			lr.UserField: lr.Username,
			lr.PassField: lr.Password,
		}
		for k, v := range lr.ExtraFields {
			payload[k] = v
		}
		b, _ := json.Marshal(payload)
		body = string(b)
		headers["Content-Type"] = "application/json"
	default:
		vals := url.Values{}
		vals.Set(lr.UserField, lr.Username)
		vals.Set(lr.PassField, lr.Password)
		for k, v := range lr.ExtraFields {
			vals.Set(k, v)
		}
		body = vals.Encode()
		headers["Content-Type"] = "application/x-www-form-urlencoded"
	}

	ex, err := s.Do(ctx, method, lr.URL, headers, body, false)
	if err != nil {
		return nil, err
	}

	res := &LoginResult{StatusCode: ex.StatusCode}
	if len(ex.SetCookies) > 0 {
		for _, c := range ex.SetCookies {
			res.Cookies = append(res.Cookies, strings.SplitN(c, ";", 2)[0])
		}
	}
	if loc := headerGet(ex.Headers, "Location"); loc != "" {
		res.RedirectTo = loc
	}
	res.BodySnippet = clip(ex.Body, 300)

	if lr.Success != nil {
		ok, reason := lr.Success.evaluate(ex.StatusCode, ex.Body, res.RedirectTo, cookieDiff(before, ex.SetCookies))
		res.Success = ok
		res.Reason = reason
	} else {
		// heuristic: authenticated-looking response = 200/302 + a session-ish cookie + no "invalid/password" failure marker
		res.Success = (ex.StatusCode == 200 || ex.StatusCode == 302) && len(ex.SetCookies) > 0 && !failureMarker(ex.Body)
		if res.Success {
			res.Reason = "heuristic: 2xx/302 + new cookie + no failure marker"
		} else {
			res.Reason = "heuristic: failure marker present or no session cookie issued"
		}
	}
	if res.Success {
		s.LoggedIn = true
		s.LoginURL = lr.URL
	}
	return res, nil
}

func (s *Session) cookieSnapshot() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]bool{}
	for _, jar := range s.cookies {
		for name := range jar {
			out[name] = true
		}
	}
	return out
}

func cookieDiff(before map[string]bool, setCookies []string) []string {
	var fresh []string
	for _, raw := range setCookies {
		name := strings.TrimSpace(strings.SplitN(raw, "=", 2)[0])
		if name != "" && !before[name] {
			fresh = append(fresh, name)
		}
	}
	return fresh
}

func failureMarker(body string) bool {
	lb := strings.ToLower(body)
	for _, m := range []string{"invalid password", "invalid username", "incorrect password", "login failed", "authentication failed", "wrong password", "invalid credentials", "access denied"} {
		if strings.Contains(lb, m) {
			return true
		}
	}
	return false
}

// SuccessRule is an explicit login-success detector.
type SuccessRule struct {
	StatusCode    int    `json:"status_code,omitempty"`
	BodyRegex     string `json:"body_regex,omitempty"`
	CookieSet     string `json:"cookie_set,omitempty"`
	RedirectHas   string `json:"redirect_contains,omitempty"`
	FailureRegex  string `json:"failure_regex,omitempty"`
}

func (r *SuccessRule) evaluate(statusCode int, body, location string, freshCookies []string) (bool, string) {
	if r.FailureRegex != "" {
		if re, err := regexp.Compile("(?i)" + r.FailureRegex); err == nil && re.MatchString(body) {
			return false, "failure regex matched"
		}
	}
	if r.StatusCode > 0 {
		if statusCode != r.StatusCode {
			return false, fmt.Sprintf("status %d != expected %d", statusCode, r.StatusCode)
		}
		return true, fmt.Sprintf("status %d matched", statusCode)
	}
	if r.BodyRegex != "" {
		if re, err := regexp.Compile(r.BodyRegex); err == nil && re.MatchString(body) {
			return true, "body regex matched"
		}
		return false, "body regex not matched"
	}
	if r.CookieSet != "" {
		for _, c := range freshCookies {
			if c == r.CookieSet {
				return true, "session cookie issued: " + c
			}
		}
		return false, "expected cookie not issued"
	}
	if r.RedirectHas != "" {
		if strings.Contains(location, r.RedirectHas) {
			return true, "redirect target matched"
		}
		return false, "redirect target not matched"
	}
	return false, "empty success rule"
}

func headerGet(h map[string][]string, name string) string {
	for k, vals := range h {
		if strings.EqualFold(k, name) && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
