package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"pentagi/pkg/tools/mitm"
	"pentagi/pkg/tools/payloads"
	"pentagi/pkg/tools/rawhttp"
)

// maxResultPayloads bounds how many payloads are embedded in a single tool
// result so LLM context windows are not flooded by the biggest categories.
const maxResultPayloads = 120

// handlePayloadEngine implements the payload_engine tool.
func (o *offensiveTools) handlePayloadEngine(ctx context.Context, action PayloadEngineAction) (string, error) {
	switch string(action.Action) {
	case "", string(PayloadEngineCategories):
		cats := payloads.Describe()
		var b strings.Builder
		b.WriteString("Payload Engine v2 categories:\n\n")
		b.WriteString("| category | payloads | description |\n|---|---|---|\n")
		for _, c := range cats {
			b.WriteString(fmt.Sprintf("| `%s` | %d | %s |\n", c.Name, c.Payloads, c.Description))
		}
		b.WriteString("\nUse action=generate with one of these category values. Pair with raw_http/proxy_intruder to fire them.")
		return b.String(), nil

	case string(PayloadEngineGenerate):
		if strings.TrimSpace(string(action.Category)) == "" {
			return "", fmt.Errorf("category is required for action=generate (see action=categories)")
		}
		cat, ok := payloads.ParseCategory(string(action.Category))
		if !ok {
			return "", fmt.Errorf("unknown category %q — call action=categories for the list", string(action.Category))
		}
		opts := payloads.GenerateOptions{
			Category:   cat,
			Context:    string(action.Context),
			Mutation:   string(action.Mutation),
			WAFEvasion: bool(action.Wafevasion),
			Seed:       string(action.Seed),
		}
		if action.Limit != nil && *action.Limit > 0 {
			opts.Limit = int(*action.Limit)
		}
		list, err := payloads.Generate(opts)
		if err != nil {
			return "", err
		}
		shown := list
		truncated := false
		if len(shown) > maxResultPayloads {
			shown = shown[:maxResultPayloads]
			truncated = true
		}
		var b strings.Builder
		fmt.Fprintf(&b, "payload_engine: category=%s context=%s — %d payloads (shown %d%s)\n\n",
			string(cat), orDefault(string(action.Context), "raw"), len(list), len(shown), truncatedNote(truncated))
		for i, p := range shown {
			fmt.Fprintf(&b, "%3d. %s\n", i+1, p)
		}
		if truncated {
			fmt.Fprintf(&b, "\n(%d more available — raise 'limit' or slice by index ranges in follow-up calls)\n", len(list)-maxResultPayloads)
		}
		return b.String(), nil

	default:
		return "", fmt.Errorf("unknown payload_engine action: %s", action.Action)
	}
}

func truncatedNote(t bool) string {
	if t {
		return ", truncated"
	}
	return ""
}

func orDefault(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}

// handleRawHTTP implements the raw_http tool (Repeater-style byte-exact requests).
func (o *offensiveTools) handleRawHTTP(ctx context.Context, action RawHTTPAction) (string, error) {
	url := strings.TrimSpace(string(action.URL))
	if url == "" {
		return "", fmt.Errorf("url is required")
	}
	timeout := int64(15)
	if action.TimeoutSec != nil && *action.TimeoutSec > 0 && *action.TimeoutSec <= 120 {
		timeout = *action.TimeoutSec
	}

	req := rawhttp.Request{
		URL:             url,
		Method:          string(action.Method),
		RawRequest:      string(action.RawRequest),
		Headers:         action.Headers,
		Body:            string(action.Body),
		TLSNoVerify:     true, // authorized testing against internal/self-signed targets
		FollowRedirects: bool(action.FollowRedirects),
		ForceHTTP10:     bool(action.ForceHTTP10),
		Timeout:         time.Duration(timeout) * time.Second,
	}

	resp, err := rawhttp.Send(ctx, req)
	if err != nil {
		return fmt.Sprintf("raw_http failed: %v", err), nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "=== response ===\n%s\n", resp.StatusLine)
	for _, k := range resp.HeaderOrder {
		for _, v := range resp.Headers[k] {
			fmt.Fprintf(&b, "%s: %s\n", k, v)
		}
	}
	fmt.Fprintf(&b, "\n%s\n", resp.Body)
	fmt.Fprintf(&b, "\n=== metrics ===\nstatus=%d bytes=%d connect=%dms ttfb=%dms total=%dms\n",
		resp.StatusCode, resp.BodyBytes, resp.ConnectTime.Milliseconds(), resp.TTFB.Milliseconds(), resp.TotalTime.Milliseconds())
	if len(resp.RedirectChain) > 0 {
		fmt.Fprintf(&b, "redirects: %s\n", strings.Join(resp.RedirectChain, " -> "))
	}
	if resp.TotalTime > 8*time.Second && resp.BodyBytes == 0 {
		b.WriteString("NOTE: near-timeout with empty body — consistent with a desync/stalled connection; re-send the follow-up request on a NEW connection to confirm smuggled behavior.\n")
	}
	return b.String(), nil
}

// handleSmuggleProbe runs the request-smuggling detection suite against one target.
func (o *offensiveTools) handleSmuggleProbe(ctx context.Context, action SmuggleProbeAction) (string, error) {
	url := strings.TrimSpace(string(action.URL))
	if url == "" {
		return "", fmt.Errorf("url is required")
	}
	path := string(action.Path)
	if path == "" {
		path = "/"
	}
	marker := string(action.Marker)
	if marker == "" {
		marker = fmt.Sprintf("smug%d", time.Now().UnixNano()%100000)
	}
	timeout := int64(10)
	if action.TimeoutSec != nil && *action.TimeoutSec > 0 && *action.TimeoutSec <= 60 {
		timeout = *action.TimeoutSec
	}

	var b strings.Builder
	fmt.Fprintf(&b, "request smuggling probes against %s%s (marker=%s)\n\n", url, path, marker)

	for _, v := range rawhttp.SmuggleVariants() {
		wire := rawhttp.NormalizeWire(v.Build(path, marker), hostOnly(url))
		resp, err := rawhttp.Send(ctx, rawhttp.Request{
			URL:         url,
			RawRequest:  wire,
			TLSNoVerify: true,
			Timeout:     time.Duration(timeout) * time.Second,
		})
		if err != nil {
			fmt.Fprintf(&b, "[%s] ERROR: %v\n", v.Name, err)
			continue
		}
		verdict := "no desync signal"
		switch {
		case resp.StatusCode == 400 || resp.StatusCode == 501:
			verdict = "server rejected the probe (parses strictly) — try remaining variants"
		case resp.TTFB > time.Duration(timeout)*time.Second*8/10:
			verdict = "TIMING SHIFT — back-end waited for more bytes; strong desync candidate"
		case strings.Contains(resp.Body, marker):
			verdict = "MARKER REFLECTED — smuggled request processed; DESYNC CONFIRMED"
		}
		fmt.Fprintf(&b, "[%s] status=%d ttfb=%dms body=%dB — %s\n",
			v.Name, resp.StatusCode, resp.TTFB.Milliseconds(), resp.BodyBytes, verdict)
	}

	b.WriteString("\nnext steps if a variant shows a timing shift or marker reflection: replay the probe, then send a benign GET on a fresh connection and check for the marker/front-end confusion; escalate only with reproduced evidence.\n")
	return b.String(), nil
}

// handleProxyStart starts an intercepting proxy for this flow.
func (o *offensiveTools) handleProxyStart(ctx context.Context, action ProxyStartAction) (string, error) {
	port := 0
	if action.Port != nil && *action.Port > 0 {
		port = int(*action.Port)
	}
	eng, err := mitm.Start(port, action.Include, action.Exclude)
	if err != nil {
		return "", fmt.Errorf("proxy start failed: %w", err)
	}

	o.proxyMu.Lock()
	o.lastProxyID = eng.ID()
	o.proxyEngines[eng.ID()] = struct{}{}
	o.proxyMu.Unlock()

	host := "pentagi" // docker-compose service name reachable from flow containers
	var b strings.Builder
	fmt.Fprintf(&b, "intercepting proxy started (engine_id=%d)\n", eng.ID())
	fmt.Fprintf(&b, "listen: 0.0.0.0:%d\n", eng.Port())
	fmt.Fprintf(&b, "use from flow container: export http_proxy=http://%s:%d https_proxy=http://%s:%d\n", host, eng.Port(), host, eng.Port())
	b.WriteString("capture: plain HTTP requests are logged in full (method/url/headers/body + response); HTTPS CONNECT tunnels are relayed with host/SNI visibility — for byte-level HTTPS use raw_http.\n")
	b.WriteString("view traffic with proxy_history (filter=regex), stop with proxy_stop.\n")
	return b.String(), nil
}

// handleProxyHistory returns captured traffic.
func (o *offensiveTools) handleProxyHistory(ctx context.Context, action ProxyHistoryAction) (string, error) {
	eng, err := o.lookupEngine(action.EngineID)
	if err != nil {
		return "", err
	}
	limit := 25
	if action.Limit != nil && *action.Limit > 0 && *action.Limit <= 200 {
		limit = int(*action.Limit)
	}
	entries := eng.History(string(action.Filter), false, limit)
	if len(entries) == 0 {
		return "no captured traffic yet (or filter matched nothing). Route container traffic through the proxy port first.", nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "captured traffic (engine_id=%d, showing %d newest):\n\n", eng.ID(), len(entries))
	for _, e := range entries {
		if e.HTTPS {
			fmt.Fprintf(&b, "#%d %s CONNECT %s [tls tunnel, bytes hidden]\n", e.ID, e.Timestamp.Format("15:04:05"), e.Host)
			continue
		}
		full := e.Host + e.Path
		if e.Query != "" {
			full += "?" + e.Query
		}
		fmt.Fprintf(&b, "#%d %s %s -> %d (%dB)\n", e.ID, e.Method, full, e.StatusCode, e.ResponseBytes)
		if e.ReqBody != "" {
			fmt.Fprintf(&b, "    req body: %s\n", oneLine(e.ReqBody, 200))
		}
		if e.RespBody != "" {
			fmt.Fprintf(&b, "    resp body: %s\n", oneLine(e.RespBody, 300))
		}
	}
	return b.String(), nil
}

// handleProxyStop stops a proxy engine.
func (o *offensiveTools) handleProxyStop(ctx context.Context, action ProxyStopAction) (string, error) {
	eng, err := o.lookupEngine(action.EngineID)
	if err != nil {
		return "", err
	}
	id := eng.ID()
	if err := mitm.StopEngine(id); err != nil {
		return "", err
	}
	o.proxyMu.Lock()
	delete(o.proxyEngines, id)
	o.proxyMu.Unlock()
	return fmt.Sprintf("proxy engine %d stopped (captured history discarded)", id), nil
}

// handleProxyIntruder runs a Burp-style fuzzing attack.
func (o *offensiveTools) handleProxyIntruder(ctx context.Context, action ProxyIntruderAction) (string, error) {
	url := strings.TrimSpace(string(action.URL))
	if url == "" {
		return "", fmt.Errorf("url is required")
	}
	tpl := string(action.RawTemplate)
	if strings.TrimSpace(tpl) == "" {
		return "", fmt.Errorf("raw_template with §...§ positions is required")
	}

	opts := mitm.IntruderOptions{
		AttackMode:      string(action.AttackMode),
		PayloadSets:     action.PayloadSets,
		PayloadCategory: string(action.PayloadCategory),
		MaxRequests:     int(derefInt64(action.MaxRequests, 200)),
		Concurrency:     int(derefInt64(action.Concurrency, 5)),
		TimeoutSec:      int(derefInt64(action.TimeoutSec, 10)),
		FilterRegex:     string(action.FilterRegex),
		FilterStatus:    string(action.FilterStatus),
	}

	attack, results := mitm.RunIntruder(ctx, url, tpl, opts)
	var b strings.Builder
	fmt.Fprintf(&b, "intruder attack: mode=%s requests=%d target=%s\n", attack.Mode, attack.Requests, url)
	for _, e := range attack.Errors {
		fmt.Fprintf(&b, "warning: %s\n", e)
	}
	if len(results) == 0 {
		b.WriteString("no responses matched the filters (or all requests errored). Widen filter_status/filter_regex or check reachability.\n")
		return b.String(), nil
	}
	b.WriteString("\nresults sorted by status,length — outliers against the dominant length are signal:\n\n")
	for _, r := range results {
		fmt.Fprintf(&b, "#%d status=%d len=%d ttfb=%dms %s\n", r.Index, r.StatusCode, r.Length, r.TTFBms, firstLine(r.StatusLine))
		if r.Snippet != "" {
			fmt.Fprintf(&b, "      %s\n", oneLine(r.Snippet, 240))
		}
	}
	return b.String(), nil
}

// lookupEngine resolves an engine id or falls back to the flow's last engine.
func (o *offensiveTools) lookupEngine(id *int64) (*mitm.Engine, error) {
	if id != nil && *id > 0 {
		return mitm.GetEngine(int(*id))
	}
	o.proxyMu.Lock()
	last := o.lastProxyID
	o.proxyMu.Unlock()
	if last == 0 {
		return nil, fmt.Errorf("no proxy engine started for this flow — call proxy_start first")
	}
	return mitm.GetEngine(last)
}

func derefInt64(p *int64, def int64) int64 {
	if p == nil || *p <= 0 {
		return def
	}
	return *p
}

func hostOnly(rawURL string) string {
	s := rawURL
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	return s
}

func oneLine(s string, max int) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", " ⏎ ")
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// helper used by json marshaling of results in tests
func marshalJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
