package mitm

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestScopeMatching(t *testing.T) {
	s, err := NewScopeFromPatterns([]string{`.*\.example\.com.*`}, []string{`.*/admin.*`})
	if err != nil {
		t.Fatal(err)
	}
	if !s.Matches("api.example.com", "/v1/users") {
		t.Error("in-scope host rejected")
	}
	if s.Matches("evil.net", "/x") {
		t.Error("out-of-scope host accepted")
	}
	if s.Matches("api.example.com", "/admin/panel") {
		t.Error("excluded path accepted")
	}
	// empty include = allow all except excludes
	s2, _ := NewScopeFromPatterns(nil, []string{`secret`})
	if !s2.Matches("anything.io", "/public") {
		t.Error("empty include must allow all")
	}
}

func TestProxyEndToEndCapture(t *testing.T) {
	// origin server
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Origin", "yes")
		fmt.Fprintf(w, "hello from origin: %s %s", r.Method, r.URL.Query().Get("q"))
	}))
	defer srv.Close()

	eng, err := Start(0, []string{".*"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer StopEngine(eng.ID())

	u, _ := url.Parse(srv.URL)
	proxyHost := "127.0.0.1"
	port := eng.Port()

	// issue a request THROUGH the proxy (absolute-form)
	reqURL := fmt.Sprintf("http://%s/probe?q=canary", u.Host)
	req, _ := http.NewRequest("GET", reqURL, nil)
	proxyURL, _ := url.Parse(fmt.Sprintf("http://%s:%d", proxyHost, port))
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   10 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxied request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "canary") {
		t.Fatalf("unexpected origin response: %q", body)
	}

	// history must contain the captured exchange
	deadline := time.Now().Add(3 * time.Second)
	var entries []Entry
	for time.Now().Before(deadline) {
		entries = eng.History("", false, 50)
		if len(entries) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if len(entries) == 0 {
		t.Fatal("proxy captured no history")
	}
	e := entries[0]
	if e.Method != "GET" || e.Path != "/probe" || e.Query != "q=canary" {
		t.Errorf("entry metadata wrong: %+v", e)
	}
	if e.StatusCode != 200 {
		t.Errorf("status = %d", e.StatusCode)
	}
	if !strings.Contains(e.RespBody, "canary") {
		t.Errorf("response body not captured: %q", e.RespBody)
	}
	if !strings.Contains(e.RespHeaders, "X-Origin") {
		t.Errorf("response headers not captured: %q", e.RespHeaders)
	}
}

func TestProxyConnectTunnel(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "tls-origin")
	}))
	defer srv.Close()

	eng, err := Start(0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer StopEngine(eng.ID())

	u, _ := url.Parse(srv.URL)
	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", eng.Port()))
	// reuse the httptest server's own client (trusts its self-signed CA) and
	// route it through the proxy
	transport := srv.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxyURL)
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("CONNECT tunnel failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "tls-origin" {
		t.Errorf("tunneled body = %q", body)
	}

	entries := eng.History("CONNECT", false, 10)
	found := false
	for _, e := range entries {
		if e.Method == "CONNECT" && e.HTTPS && strings.Contains(e.Host, u.Host) {
			found = true
		}
	}
	if !found {
		t.Error("CONNECT entry not recorded")
	}
}

func TestRunIntruderPositions(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		switch q {
		case "admin":
			w.WriteHeader(200)
			fmt.Fprint(w, "WELCOME-ADMIN-PANEL")
		case "timeout":
			time.Sleep(6 * time.Second) // exceeds the 5s per-request timeout
			fmt.Fprint(w, "slow")
		default:
			w.WriteHeader(404)
			fmt.Fprint(w, "not found")
		}
	}))
	defer srv.Close()

	attack, results := RunIntruder(
		withTestContext(t),
		srv.URL,
		"GET /?q=§FUZZ§ HTTP/1.1\r\nHost: x\r\n\r\n",
		IntruderOptions{
			AttackMode:   "sniper",
			PayloadSets:  [][]string{{"guest", "admin", "timeout"}},
			MaxRequests:  10,
			Concurrency:  3,
			TimeoutSec:   5,
			FilterStatus: "200",
		},
	)
	if len(attack.Errors) > 0 && attack.Requests != 3 {
		t.Logf("attack errors: %v", attack.Errors)
	}
	if attack.Requests != 3 {
		t.Fatalf("expected 3 requests, got %d (errors: %v)", attack.Requests, attack.Errors)
	}
	if len(results) != 1 {
		t.Fatalf("filter status=200 should leave 1 result, got %d", len(results))
	}
	if !strings.Contains(results[0].Snippet, "WELCOME-ADMIN-PANEL") {
		t.Errorf("did not capture the admin hit: %+v", results[0])
	}
}

func TestRunIntruderCategoryPayloads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	attack, _ := RunIntruder(withTestContext(t), srv.URL,
		"GET /?q=§FUZZ§ HTTP/1.1\r\nHost: x\r\n\r\n",
		IntruderOptions{PayloadCategory: "xss", MaxRequests: 8, Concurrency: 4, TimeoutSec: 5})
	if attack.Requests == 0 {
		t.Fatalf("category payload expansion failed: %v", attack.Errors)
	}
}

func TestEngineLifecycle(t *testing.T) {
	eng, err := Start(0, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if eng.Port() == 0 {
		t.Error("ephemeral port not reported")
	}
	if err := StopEngine(eng.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := GetEngine(eng.ID()); err == nil {
		t.Error("stopped engine must not be retrievable")
	}
	// listener must actually be closed
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", eng.Port()), time.Second); err == nil {
		c.Close()
		t.Error("port still accepting after stop")
	}
}
