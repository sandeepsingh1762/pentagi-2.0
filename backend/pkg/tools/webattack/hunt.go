package webattack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/tools/payloads"
	"pentagi/pkg/tools/rawhttp"
)

// HuntTarget describes one injection-hunt run.
type HuntTarget struct {
	URL           string   `json:"url"`
	Method        string   `json:"method,omitempty"` // GET default; POST uses FormParams/JSONBody
	Params        []string `json:"params"`           // parameter names to test
	ParamIn       string   `json:"param_in,omitempty"` // query|json|form|header|cookie (default query)
	StaticParams  map[string]string `json:"static_params,omitempty"` // included unchanged
	JSONBody      map[string]string `json:"json_body,omitempty"`     // full JSON body template (ParamIn=json)
	Category      string   `json:"category,omitempty"` // payloads category (default sqli)
	MaxPayloads   int      `json:"max_payloads,omitempty"`
	Concurrency   int      `json:"concurrency,omitempty"`
	TimeoutSec    int      `json:"timeout_sec,omitempty"`
	SessionID     int64    `json:"session_id,omitempty"` // optional authenticated session
}

// Finding is one positive signal for a parameter.
type Finding struct {
	Param    string `json:"param"`
	Payload  string `json:"payload"`
	Signal   string `json:"signal"` // sql-error|template-error|error:<engine>|reflection|boolean|time-based|diverged
	Evidence string `json:"evidence"`
	Elapsed  int64  `json:"elapsed_ms"`
	Status   int    `json:"status"`
}

// HuntResult aggregates findings per parameter.
type HuntResult struct {
	URL       string              `json:"url"`
	Category  string              `json:"category"`
	Params    int                 `json:"params_tested"`
	Findings  []Finding           `json:"findings"`
	Hits      map[string][]Finding `json:"hits"` // param -> findings
	PayloadsSent int              `json:"payloads_sent"`
	Notes     []string            `json:"notes,omitempty"`
}

// BooleanPair is a true/false payload pair for differential detection.
type BooleanPair struct{ True, False string }

var booleanPairs = []BooleanPair{
	{"' AND '1'='1", "' AND '1'='2"},
	{"' AND 1=1 -- ", "' AND 1=2 -- "},
	{" AND 1=1", " AND 1=2"},
	{"' OR '1'='1", "' OR '1'='2"},
}

// Hunt runs the automated injection detection loop: baseline → payloads →
// classification (error signatures / reflection / boolean diff / timing) →
// per-parameter findings.
func Hunt(ctx context.Context, t HuntTarget) (*HuntResult, error) {
	if strings.TrimSpace(t.URL) == "" || len(t.Params) == 0 {
		return nil, fmt.Errorf("url and params are required")
	}
	if t.ParamIn == "" {
		t.ParamIn = "query"
	}
	if t.Method == "" {
		if t.ParamIn == "query" {
			t.Method = "GET"
		} else {
			t.Method = "POST"
		}
	}
	cat, ok := payloads.ParseCategory(orDefaultStr(t.Category, "sqli"))
	if !ok {
		return nil, fmt.Errorf("unknown payload category %q", t.Category)
	}
	maxPayloads := t.MaxPayloads
	if maxPayloads <= 0 {
		maxPayloads = 25
	}
	if maxPayloads > 80 {
		maxPayloads = 80
	}
	timeout := t.TimeoutSec
	if timeout <= 0 {
		timeout = 12
	}

	list, err := payloads.Generate(payloads.GenerateOptions{Category: cat, Limit: maxPayloads})
	if err != nil {
		return nil, err
	}

	var sess *Session
	if t.SessionID > 0 {
		sess, _ = GetSession(t.SessionID)
	}

	res := &HuntResult{
		URL:      t.URL,
		Category: string(cat),
		Params:   len(t.Params),
		Hits:     map[string][]Finding{},
	}

	send := func(param, value string) (int, string, time.Duration) {
		req := t.buildRequest(param, value)
		start := time.Now()
		var (
			status int
			body   string
		)
		if sess != nil {
			ex, err := sess.Do(ctx, req.method, req.url, req.headers, req.body, false)
			if err != nil {
				return 0, "", time.Since(start)
			}
			status, body = ex.StatusCode, ex.Body
		} else {
			resp, err := rawhttp.Send(ctx, rawhttp.Request{
				URL:         req.url,
				Method:      req.method,
				Headers:     req.headers,
				Body:        req.body,
				TLSNoVerify: true,
				Timeout:     time.Duration(timeout) * time.Second,
			})
			if err != nil {
				return 0, "", time.Since(start)
			}
			status, body = resp.StatusCode, resp.Body
		}
		return status, body, time.Since(start)
	}

	for _, param := range t.Params {
		// baseline with a benign canary
		canary := "pntg" + fmt.Sprintf("%d", time.Now().UnixNano()%100000)
		baseStatus, baseBody, baseElapsed := send(param, canary)
		base := NewBaseline(baseStatus, baseBody)

		var findings []Finding
		add := func(f Finding) {
			for _, ex := range findings {
				if ex.Payload == f.Payload && ex.Signal == f.Signal {
					return
				}
			}
			findings = append(findings, f)
			res.PayloadsSent++
		}

		for _, p := range list {
			if ctx.Err() != nil {
				break
			}
			status, body, elapsed := send(param, p)
			v := Compare(base, status, body, p)

			// error-based signals
			for _, eng := range v.ErrorSignatures {
				add(Finding{Param: param, Payload: p, Signal: "error:" + eng, Evidence: clip(extractErrorSnippet(body, eng), 200), Status: status, Elapsed: elapsed.Milliseconds()})
			}
			// time-based signal for time payloads
			lp := strings.ToLower(p)
			if (strings.Contains(lp, "sleep(") || strings.Contains(lp, "waitfor") || strings.Contains(lp, "pg_sleep")) &&
				elapsed > baseElapsed+3*time.Second {
				add(Finding{Param: param, Payload: p, Signal: "time-based", Evidence: fmt.Sprintf("baseline %dms vs %dms", baseElapsed.Milliseconds(), elapsed.Milliseconds()), Elapsed: elapsed.Milliseconds(), Status: status})
			}
			// reflection (XSS-relevant categories)
			if v.ReflectsPayload && cat != payloads.CategorySQLi {
				add(Finding{Param: param, Payload: p, Signal: "reflection", Evidence: clip(findAround(body, payloadCore(p)), 200), Status: status})
			} else if v.ReflectsPayload {
				add(Finding{Param: param, Payload: p, Signal: "reflection", Evidence: clip(findAround(body, payloadCore(p)), 200), Status: status})
			}
		}

		// boolean differential: true stays close to baseline, false diverges
		for _, pair := range booleanPairs {
			tStatus, tBody, _ := send(param, pair.True)
			fStatus, fBody, _ := send(param, pair.False)
			simTrue := similarity(baseBody, tBody)
			simFalse := similarity(baseBody, fBody)
			if simTrue > 0.85 && (simFalse < 0.65 || fStatus != tStatus) {
				add(Finding{
					Param: param, Payload: pair.True + "  vs  " + pair.False, Signal: "boolean",
					Evidence: fmt.Sprintf("true: sim=%.2f status=%d | false: sim=%.2f status=%d", simTrue, tStatus, simFalse, fStatus),
					Status:   tStatus,
				})
				break // one boolean hit per param is enough
			}
		}

		if len(findings) > 0 {
			res.Findings = append(res.Findings, findings...)
			res.Hits[param] = findings
		}
	}

	if len(res.Hits) > 0 {
		res.Notes = append(res.Notes, "confirm each hit with raw_http replay + validate_exploit proof before claiming exploitation")
	}
	return res, nil
}

type builtRequest struct {
	url     string
	method  string
	headers map[string]string
	body    string
}

// buildRequest produces the request for one param=value injection.
func (t *HuntTarget) buildRequest(param, value string) builtRequest {
	out := builtRequest{method: t.Method, headers: map[string]string{}}
	for k, v := range t.StaticParams {
		_ = k
		_ = v
	}
	switch t.ParamIn {
	case "header":
		out.url = t.URL
		out.headers[param] = value
		applyStatic(t, out.headers, nil, "")
	case "cookie":
		out.url = t.URL
		existing := ""
		if t.StaticParams != nil {
			existing = t.StaticParams["Cookie"]
		}
		if existing != "" {
			out.headers["Cookie"] = existing + "; " + param + "=" + value
		} else {
			out.headers["Cookie"] = param + "=" + value
		}
	case "form":
		vals := url.Values{}
		for k, v := range t.StaticParams {
			vals.Set(k, v)
		}
		vals.Set(param, value)
		out.url = t.URL
		out.body = vals.Encode()
		out.headers["Content-Type"] = "application/x-www-form-urlencoded"
	case "json":
		body := map[string]any{}
		for k, v := range t.JSONBody {
			body[k] = v
		}
		for k, v := range t.StaticParams {
			body[k] = v
		}
		body[param] = value
		b, _ := json.Marshal(body)
		out.url = t.URL
		out.body = string(b)
		out.headers["Content-Type"] = "application/json"
	default: // query
		u, err := url.Parse(t.URL)
		if err != nil {
			out.url = t.URL
			return out
		}
		q := u.Query()
		for k, v := range t.StaticParams {
			q.Set(k, v)
		}
		q.Set(param, value)
		u.RawQuery = q.Encode()
		out.url = u.String()
	}
	return out
}

func applyStatic(t *HuntTarget, headers map[string]string, body map[string]string, mode string) {
	if t.StaticParams == nil {
		return
	}
	for k, v := range t.StaticParams {
		if mode == "header" || strings.HasPrefix(strings.ToLower(k), "x-") || strings.EqualFold(k, "authorization") {
			headers[k] = v
		}
	}
}

// extractErrorSnippet pulls surrounding context around a matched error.
func extractErrorSnippet(body, engine string) string {
	lower := strings.ToLower(body)
	probe := strings.ToLower(engine)
	idx := strings.Index(lower, probe)
	if idx < 0 {
		for _, sig := range errorSignatures {
			if sig.name == engine && matchRegex(sig.re, body) {
				if loc := regexFindIndex(sig.re, body); loc >= 0 {
					idx = loc
				}
				break
			}
		}
	}
	if idx < 0 {
		return body
	}
	start := idx - 40
	if start < 0 {
		start = 0
	}
	end := idx + 120
	if end > len(body) {
		end = len(body)
	}
	return strings.ReplaceAll(body[start:end], "\n", " ")
}

func regexFindIndex(pattern, body string) int {
	reCacheMu.Lock()
	re, ok := reCache[pattern]
	reCacheMu.Unlock()
	if !ok || re == nil {
		return -1
	}
	loc := re.FindStringIndex(body)
	if loc == nil {
		return -1
	}
	return loc[0]
}

// findAround returns context around a substring occurrence.
func findAround(body, needle string) string {
	if needle == "" {
		return ""
	}
	idx := strings.Index(body, needle)
	if idx < 0 {
		idx = strings.Index(strings.ToLower(body), strings.ToLower(needle))
	}
	if idx < 0 {
		return ""
	}
	start := idx - 40
	if start < 0 {
		start = 0
	}
	end := idx + len(needle) + 80
	if end > len(body) {
		end = len(body)
	}
	return strings.ReplaceAll(body[start:end], "\n", " ")
}

func orDefaultStr(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}

// parallel helper kept for future concurrency of per-param hunts
var _ = sync.WaitGroup{}
