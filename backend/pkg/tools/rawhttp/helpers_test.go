package rawhttp

import (
	"bufio"
	"net/url"
	"strings"
	"testing"
)

func mustURL(t *testing.T, raw string) url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return *u
}

func newTestReader(wire string) *bufio.Reader {
	return bufio.NewReader(strings.NewReader(wire))
}
