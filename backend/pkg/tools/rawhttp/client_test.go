package rawhttp

import (
	"strings"
	"testing"
)

func TestBuildWireRequestRawVerbatim(t *testing.T) {
	raw := "GET /x HTTP/1.1\r\nHost: t\r\nX-Weird: spaced   value\r\n\r\n"
	wire, err := buildWireRequest(Request{RawRequest: raw, URL: "http://t/x"}, mustURL(t, "http://t/x"))
	if err != nil {
		t.Fatal(err)
	}
	if wire != raw {
		t.Errorf("raw request must be transmitted verbatim:\n got %q\nwant %q", wire, raw)
	}
}

func TestBuildWireRequestRawAutoTerminate(t *testing.T) {
	// missing final CRLFCRLF must be appended
	raw := "POST / HTTP/1.1\r\nHost: t\r\nContent-Length: 2\r\n\r\nhi"
	wire, err := buildWireRequest(Request{RawRequest: raw, URL: "http://t/"}, mustURL(t, "http://t/"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(wire, "hi\r\n\r\n") {
		t.Errorf("expected body + CRLFCRLF, got %q", wire)
	}
}

func TestBuildWireRequestComposed(t *testing.T) {
	req := Request{
		Method: "POST",
		URL:    "http://example.com/a/b?x=1",
		Headers: map[string]string{
			"X-Test": "1",
			"Host":   "override.example.com",
		},
		Body: "abc",
	}
	wire, err := buildWireRequest(req, mustURL(t, "http://example.com/a/b?x=1"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(wire, "POST /a/b?x=1 HTTP/1.1\r\n") {
		t.Errorf("request line wrong: %q", wire[:40])
	}
	if strings.Contains(wire, "Host: example.com") {
		t.Errorf("explicit Host header must win: %q", wire)
	}
	if !strings.Contains(wire, "Content-Length: 3") {
		t.Errorf("content-length missing: %q", wire)
	}
}

func TestBuildWireRequestHTTP10(t *testing.T) {
	wire, err := buildWireRequest(Request{URL: "http://e.com/", ForceHTTP10: true}, mustURL(t, "http://e.com/"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(wire, " HTTP/1.0\r\n") {
		t.Errorf("http/1.0 downgrade failed: %q", wire)
	}
}

func TestReadChunkedBody(t *testing.T) {
	wire := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n3;x-ext\r\nefg\r\n0\r\n\r\n"
	r := newTestReader(wire)
	resp, err := readResponse(r, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != "abcdefg" {
		t.Errorf("chunked body = %q", resp.Body)
	}
	if resp.HeaderValue("Transfer-Encoding") == "" {
		t.Error("transfer-encoding header lost")
	}
}

func TestReadContentLengthBody(t *testing.T) {
	wire := "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello-ignored"
	resp, err := readResponse(newTestReader(wire), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != "hello" {
		t.Errorf("cl body = %q", resp.Body)
	}
}

func TestReadResponseCapturesHeaderOrder(t *testing.T) {
	wire := "HTTP/1.1 404 Not Found\r\nX-A: 1\r\nX-B: 2\r\nContent-Length: 0\r\n\r\n"
	resp, err := readResponse(newTestReader(wire), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 404 {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if len(resp.HeaderOrder) < 3 {
		t.Errorf("header order not captured: %v", resp.HeaderOrder)
	}
}

func TestSmuggleVariantsBuild(t *testing.T) {
	for _, v := range SmuggleVariants() {
		wire := v.Build("/login", "pfx123")
		if wire == "" {
			t.Errorf("%s: empty probe", v.Name)
		}
		wire = NormalizeWire(wire, "target.example.com")
		if strings.Contains(wire, "%HOST%") {
			t.Errorf("%s: %%HOST%% not substituted", v.Name)
		}
		if !strings.Contains(wire, "HTTP/1.1") {
			t.Errorf("%s: malformed request line", v.Name)
		}
	}
}

func TestTimingProbe(t *testing.T) {
	probe, follow := TimingProbe("/x")
	if !strings.Contains(probe, "Content-Length: 4") || !strings.Contains(probe, "chunked") {
		t.Errorf("probe shape wrong: %q", probe)
	}
	if !strings.HasPrefix(follow, "GET / HTTP/1.1") {
		t.Errorf("follow-up shape wrong: %q", follow)
	}
}

func TestResolveRedirect(t *testing.T) {
	if got := resolveRedirect("https://a.com/x", "/y"); got != "https://a.com/y" {
		t.Errorf("relative redirect = %q", got)
	}
	if got := resolveRedirect("https://a.com/x", "https://b.com"); got != "https://b.com" {
		t.Errorf("absolute redirect = %q", got)
	}
}
