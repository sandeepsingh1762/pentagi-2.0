package webattack

import (
	"regexp"
	"strings"
	"sync"
)

// ---------------------------------------------------------------------------
// Response differ — the detection core for injection hunting
// ---------------------------------------------------------------------------

// Baseline captures a reference response.
type Baseline struct {
	StatusCode int
	Body       string
	BodyLen    int
}

// NewBaseline records a baseline response.
func NewBaseline(statusCode int, body string) *Baseline {
	return &Baseline{StatusCode: statusCode, Body: body, BodyLen: len(body)}
}

// DiffVerdict is the classification of one injected response against baseline.
type DiffVerdict struct {
	Similarity      float64  `json:"similarity"`
	LengthDelta     int      `json:"length_delta"`
	StatusChanged   bool     `json:"status_changed"`
	ReflectsPayload bool     `json:"reflects_payload"`
	ErrorSignatures []string `json:"error_signatures,omitempty"`
	Interesting     bool     `json:"interesting"`
	Reason          string   `json:"reason"`
}

// Compare classifies a response against the baseline for a given payload.
func Compare(base *Baseline, statusCode int, body string, payload string) DiffVerdict {
	sim := similarity(base.Body, body)
	v := DiffVerdict{
		Similarity:    sim,
		LengthDelta:   len(body) - base.BodyLen,
		StatusChanged: statusCode != base.StatusCode,
	}
	if p := payloadCore(payload); p != "" {
		if strings.Contains(body, p) || strings.Contains(strings.ToLower(body), strings.ToLower(p)) {
			v.ReflectsPayload = true
		} else if strings.Contains(body, htmlEscape(p)) {
			v.ReflectsPayload = true
		}
	}
	v.ErrorSignatures = matchErrorSignatures(body)

	switch {
	case len(v.ErrorSignatures) > 0:
		v.Interesting = true
		v.Reason = "error signature: " + strings.Join(v.ErrorSignatures, ", ")
	case v.StatusChanged:
		v.Interesting = true
		v.Reason = "status code changed"
	case sim < 0.55 && abs(v.LengthDelta) > 64:
		v.Interesting = true
		v.Reason = "response diverged from baseline"
	case v.ReflectsPayload:
		v.Interesting = true
		v.Reason = "payload reflected in response"
	}
	return v
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// payloadCore strips wrapper syntax so reflection checks survive quoting:
// `' OR '1'='1` → `OR `1`=`1`-ish tokens still match inside HTML.
func payloadCore(p string) string {
	p = strings.TrimSpace(p)
	p = strings.Trim(p, "'\"()<> ")
	if len(p) < 4 {
		return ""
	}
	return p
}

func htmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;")
	return r.Replace(s)
}

// tokenSet splits text into a lowercase word-token set.
func tokenSet(s string) map[string]bool {
	out := map[string]bool{}
	cur := strings.Builder{}
	flush := func() {
		if cur.Len() >= 3 {
			out[cur.String()] = true
		}
		cur.Reset()
	}
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			cur.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

func lengthRatio(a, b string) float64 {
	la, lb := len(a), len(b)
	if la == 0 && lb == 0 {
		return 1
	}
	if la == 0 || lb == 0 {
		return 0
	}
	if la > lb {
		return float64(lb) / float64(la)
	}
	return float64(la) / float64(lb)
}

// similarity blends token-Jaccard with a length ratio — cheap, robust, and
// deterministic for response diffing.
func similarity(a, b string) float64 {
	ta, tb := tokenSet(a), tokenSet(b)
	if len(ta) == 0 && len(tb) == 0 {
		return 1
	}
	inter := 0
	for k := range ta {
		if tb[k] {
			inter++
		}
	}
	union := len(ta) + len(tb) - inter
	j := 0.0
	if union > 0 {
		j = float64(inter) / float64(union)
	}
	return 0.75*j + 0.25*lengthRatio(a, b)
}

// errorSignatures are detection regexes for backend error disclosure — the
// classic injection canaries. Grouped by engine for reporting.
var errorSignatures = []struct {
	name string
	re   string
}{
	{"mysql", `(?i)you have an error in your sql syntax`},
	{"mysql", `(?i)warning:.*mysql`},
	{"mysql", `(?i)mysqlsyntaxerrorexception`},
	{"postgres", `(?i)pg_query\(\)|postgresql.*error|syntax error at or near`},
	{"mssql", `(?i)unclosed quotation mark after the character string`},
	{"mssql", `(?i)microsoft ole db provider for sql server`},
	{"mssql", `(?i)sql server.*error|sqlstate\[`},
	{"oracle", `(?i)ora-\d{5}`},
	{"sqlite", `(?i)sqlite3?\.(?:query|prepare|exec)|unrecognized token|sql logic error`},
	{"java-sql", `(?i)java\.sql\.sqlexception|hibernateexception|jdbctemplate`},
	{"dotnet", `(?i)system\.data\.sqlclient|server error in .* application`},
	{"php", `(?i)fatal error|parse error|warning: .*\.php on line`},
	{"ssti-jinja", `(?i)jinja2\.exceptions|undefinederror.*__class__`},
	{"ssti-twig", `(?i)twig[_\\]error|the function ".*" does not exist`},
	{"ssti-freemarker", `(?i)freemarker\.core|expression .* is undefined`},
	{"ssti-velocity", `(?i)org\.apache\.velocity`},
	{"ssti-thymeleaf", `(?i)thymeleaf.*exception|spelevaluationexception`},
	{"xpath", `(?i)xpathexception|xpath syntax error`},
	{"ldap", `(?i)ldap.*error|balance parenthesis|extra text`},
	{"mongodb", `(?i)mongoerror|unknown top level operator|\$where.*error`},
	{"xxe", `(?i)saxparseexception|xml parsing error|lt;!doctype`},
	{"deserialization", `(?i)invalid serialized data|un serialization|readobject`},
}

// matchErrorSignatures returns the engine names whose signatures appear in body.
func matchErrorSignatures(body string) []string {
	if body == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, sig := range errorSignatures {
		if seen[sig.name] {
			continue
		}
		if matchRegex(sig.re, body) {
			seen[sig.name] = true
			out = append(out, sig.name)
		}
	}
	return out
}

// reCache avoids recompiling hot patterns per response.
var (
	reCacheMu sync.Mutex
	reCache   = map[string]*regexp.Regexp{}
)

func matchRegex(pattern, body string) bool {
	reCacheMu.Lock()
	re, ok := reCache[pattern]
	if !ok {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			reCache[pattern] = nil
			reCacheMu.Unlock()
			return false
		}
		reCache[pattern] = re
	}
	reCacheMu.Unlock()
	if re == nil {
		return false
	}
	return re.MatchString(body)
}
