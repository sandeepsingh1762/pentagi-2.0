package webattack

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- differ ---

func TestSimilarity(t *testing.T) {
	if s := similarity("hello world page", "hello world page"); s < 0.99 {
		t.Errorf("identical bodies sim=%f", s)
	}
	a := strings.Repeat("alpha beta gamma delta epsilon zeta eta theta iota kappa ", 30)
	b := strings.Repeat("alpha beta gamma delta epsilon zeta eta theta iota kappa ", 30) + " EXTRA TOKENS ENTIRELY DIFFERENT CONTENT BLOCK"
	if s := similarity(a, b); s > 0.95 {
		t.Errorf("diverged bodies should not be near-identical: %f", s)
	}
}

func TestCompareErrorSignature(t *testing.T) {
	base := NewBaseline(200, "<html>normal page</html>")
	body := `<html>error: You have an error in your SQL syntax; check the manual near "''"</html>`
	v := Compare(base, 200, body, "'")
	if !v.Interesting || len(v.ErrorSignatures) == 0 {
		t.Fatalf("expected error signature hit, got %+v", v)
	}
	if v.ErrorSignatures[0] != "mysql" {
		t.Errorf("expected mysql signature, got %v", v.ErrorSignatures)
	}
}

func TestCompareReflection(t *testing.T) {
	base := NewBaseline(200, "<html>search results:</html>")
	body := `<html>search results: <b>st4canaryvalue</b></html>`
	v := Compare(base, 200, body, "st4canaryvalue")
	if !v.ReflectsPayload {
		t.Errorf("reflection not detected: %+v", v)
	}
}

func TestCompareStatusChange(t *testing.T) {
	base := NewBaseline(200, "content content content content content content")
	v := Compare(base, 500, "internal error page shown here", "'")
	if !v.StatusChanged || !v.Interesting {
		t.Errorf("status change missed: %+v", v)
	}
}

// --- session ---

func TestSessionLoginAndCookiePropagation(t *testing.T) {
	var gotCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			if r.FormValue("username") == "admin" && r.FormValue("password") == "s3cret" {
				http.SetCookie(w, &http.Cookie{Name: "SESSID", Value: "abc123", HttpOnly: true})
				w.WriteHeader(200)
				fmt.Fprint(w, `{"ok":true}`)
			} else {
				w.WriteHeader(401)
				fmt.Fprint(w, `invalid credentials`)
			}
			return
		}
		gotCookie = r.Header.Get("Cookie")
		fmt.Fprint(w, "dashboard for admin")
	}))
	defer srv.Close()

	s, err := NewSession(1, srv.URL, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer DropSession(s.ID)

	res, err := s.Login(context.Background(), LoginRequest{
		URL:      "/login",
		Format:   "form",
		Username: "admin",
		Password: "wrong",
		Success:  &SuccessRule{StatusCode: 200},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Success {
		t.Fatalf("bad password should fail: %+v", res)
	}

	res, err = s.Login(context.Background(), LoginRequest{
		URL:      "/login",
		Format:   "form",
		Username: "admin",
		Password: "s3cret",
		Success:  &SuccessRule{StatusCode: 200},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Success {
		t.Fatalf("good password should succeed: %+v", res)
	}

	ex, err := s.Do(context.Background(), "GET", "/dash", nil, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ex.Body, "dashboard") {
		t.Errorf("unexpected body: %q", ex.Body)
	}
	if gotCookie != "SESSID=abc123" {
		t.Errorf("session cookie not propagated: %q", gotCookie)
	}
}

// --- hunt ---

func TestHuntSQLErrorDetection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/item", func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") {
			w.WriteHeader(500)
			fmt.Fprintf(w, "Warning: mysqli_query(): You have an error in your SQL syntax near '%s'", id)
			return
		}
		fmt.Fprintf(w, "Item details for id=%s name=candy price=100 description=fresh stock available now", id)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	res, err := Hunt(context.Background(), HuntTarget{
		URL:         srv.URL + "/item?id=1",
		Params:      []string{"id"},
		Category:    "sqli",
		MaxPayloads: 15,
		TimeoutSec:  5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits["id"]) == 0 {
		t.Fatalf("no hits for vulnerable param: %+v", res)
	}
	found := false
	for _, f := range res.Hits["id"] {
		if strings.HasPrefix(f.Signal, "error:mysql") {
			found = true
		}
	}
	if !found {
		t.Errorf("mysql error signal missing: %+v", res.Hits["id"])
	}
}

func TestHuntCleanParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "static response page with plenty of common words to keep similarity stable and high across every single probe attempt")
	}))
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Millisecond)
		fmt.Fprintf(w, "static response page with plenty of common words to keep similarity stable and high across every single probe attempt")
	}))
	defer srv.Close()
	defer srv2.Close()

	res, err := Hunt(context.Background(), HuntTarget{
		URL:         srv.URL + "/page?q=x",
		Params:      []string{"q"},
		Category:    "sqli",
		MaxPayloads: 8,
		TimeoutSec:  5,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits["q"]) != 0 {
		t.Errorf("false positive on clean param: %+v", res.Hits["q"])
	}
	_ = srv2
}

// --- brute ---

func TestBruteFindsCredential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("username") == "test" && r.FormValue("password") == "changeme" {
			http.SetCookie(w, &http.Cookie{Name: "AUTH", Value: "1"})
			fmt.Fprint(w, "welcome to your account page")
			return
		}
		fmt.Fprint(w, "invalid login attempt, please retry")
	}))
	defer srv.Close()

	res, err := Brute(context.Background(), BruteTarget{
		URL:            srv.URL + "/login",
		UsernameStatic: "test",
		Success:        &SuccessRule{BodyRegex: `welcome to your account`},
		MaxAttempts:    100,
		Concurrency:    3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Found) != 1 || !strings.HasPrefix(res.Found[0], "test:changeme") {
		t.Fatalf("credential not found: %+v", res)
	}
}

// --- jwt ---

func TestJWTDecodeAndVariants(t *testing.T) {
	// header {"alg":"HS256","typ":"JWT","kid":"key1"}, payload {"sub":"1","role":"user","exp":9999999999}
	tok := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleTEifQ.eyJzdWIiOiIxIiwicm9sZSI6InVzZXIiLCJleHAiOjk5OTk5OTk5OTl9.sig"
	a, err := DecodeJWT(tok)
	if err != nil {
		t.Fatal(err)
	}
	if a.Alg != "HS256" || a.Header["kid"] != "key1" {
		t.Fatalf("decode mismatch: %+v", a)
	}
	variants, err := JWTAttackVariants(tok)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, v := range variants {
		names[v.Name] = true
		if _, err := DecodeJWT(strings.TrimSuffix(v.Token, ".")); err != nil && v.Name == "alg-none" {
			t.Errorf("alg-none variant unparsable: %v", err)
		}
	}
	for _, want := range []string{"alg-none", "claim-admin-unsigned", "exp-removed", "kid-sql-injection", "kid-path-traversal"} {
		if !names[want] {
			t.Errorf("missing variant %s (got %v)", want, names)
		}
	}
}

func TestShannonEntropy(t *testing.T) {
	if e := shannonEntropy("aaaaaaaaaaaaaaaa"); e > 0.01 {
		t.Errorf("constant string entropy %f", e)
	}
	if e := shannonEntropy("aB3xY9kQ2mZ7pL5v"); e < 3.5 {
		t.Errorf("random string entropy too low: %f", e)
	}
}

// --- waf ---

func TestWAFDetection(t *testing.T) {
	blocked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "'") || strings.Contains(r.URL.RawQuery, "<script>") {
			blocked++
			w.Header().Set("Cf-Ray", "abc123")
			w.WriteHeader(403)
			fmt.Fprint(w, "Attention Required! | Cloudflare")
			return
		}
		fmt.Fprint(w, "welcome page")
	}))
	defer srv.Close()

	res, err := DetectWAF(context.Background(), srv.URL, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Blocked {
		t.Fatalf("expected blocked=true, got %+v", res)
	}
	found := false
	for _, d := range res.Detected {
		if d == "Cloudflare" {
			found = true
		}
	}
	if !found {
		t.Errorf("cloudflare not detected: %v", res.Detected)
	}
	if len(res.Guidance) == 0 {
		t.Error("guidance missing")
	}
}

// --- goal engine lives in its own package; smoke test cookie audit here ---

func TestCookieAudit(t *testing.T) {
	s, _ := NewSession(7, "http://example.com", 5)
	defer DropSession(s.ID)
	s.absorbCookies("example.com", []string{
		"SESSID=AbC123xYz9876543210xyz; Path=/; HttpOnly",
		"pref=dark; Path=/",
	})
	audits := s.AuditCookies()
	if len(audits) != 2 {
		t.Fatalf("expected 2 cookies, got %d", len(audits))
	}
	var sess *CookieAudit
	for i := range audits {
		if audits[i].Name == "SESSID" {
			sess = &audits[i]
		}
	}
	if sess == nil {
		t.Fatal("SESSID audit missing")
	}
	if !sess.LooksSession {
		t.Errorf("SESSID not flagged as session cookie: %+v", sess)
	}
	if !sess.HttpOnly {
		t.Error("httponly flag lost")
	}
	// Secure missing and SameSite missing should be flagged
	found := 0
	for _, iss := range sess.Issues {
		if strings.Contains(iss, "Secure") || strings.Contains(iss, "SameSite") {
			found++
		}
	}
	if found < 2 {
		t.Errorf("expected Secure+SameSite issues, got %v", sess.Issues)
	}
}
