package tools

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/tools/rawhttp"
)

// surfacePage is one crawled page's extracted intelligence.
type surfacePage struct {
	URL       string
	Status    int
	Title     string
	Links     []string
	Forms     []surfaceForm
	Params    []string
	Commented []string // interesting HTML comments
}

type surfaceForm struct {
	Action string
	Method string
	Inputs []surfaceInput
}

type surfaceInput struct {
	Name string
	Type string
}

// handleAttackSurface implements the attack_surface tool: same-origin crawl +
// endpoint/parameter mining + tech fingerprint + quick exposure checks.
func (o *offensiveTools) handleAttackSurface(ctx context.Context, action AttackSurfaceAction) (string, error) {
	start := strings.TrimSpace(string(action.URL))
	if start == "" {
		return "", fmt.Errorf("url is required")
	}
	if !strings.HasPrefix(start, "http://") && !strings.HasPrefix(start, "https://") {
		start = "http://" + start
	}
	base, err := url.Parse(start)
	if err != nil || base.Host == "" {
		return "", fmt.Errorf("invalid url %q", start)
	}
	origin := base.Scheme + "://" + base.Host

	depth := 2
	if action.Depth != nil && *action.Depth > 0 && *action.Depth <= 4 {
		depth = int(*action.Depth)
	}
	maxPages := 25
	if action.MaxPages != nil && *action.MaxPages > 0 && *action.MaxPages <= 100 {
		maxPages = int(*action.MaxPages)
	}
	timeout := 10
	if action.TimeoutSec != nil && *action.TimeoutSec > 0 && *action.TimeoutSec <= 60 {
		timeout = int(*action.TimeoutSec)
	}

	mapper := newSurfaceMapper(origin, depth, maxPages, time.Duration(timeout)*time.Second)
	result := mapper.crawl(ctx, orDefault(base.Path, "/"))
	return renderSurfaceReport(result), nil
}

// ---------------------------------------------------------------------------
// surface mapper engine
// ---------------------------------------------------------------------------

type surfaceMapper struct {
	origin   string
	depth    int
	maxPages int
	timeout  time.Duration
	visited  map[string]bool
	mu       sync.Mutex
	techSeen map[string]bool
	endpoints map[string]map[string]bool // path -> params
	comments []string
}

type surfaceResp struct {
	StatusCode int
	Headers    map[string][]string
	Body       string
}

func newSurfaceMapper(origin string, depth, maxPages int, timeout time.Duration) *surfaceMapper {
	return &surfaceMapper{
		origin:    origin,
		depth:     depth,
		maxPages:  maxPages,
		timeout:   timeout,
		visited:   map[string]bool{},
		techSeen:  map[string]bool{},
		endpoints: map[string]map[string]bool{},
	}
}

type surfaceResult struct {
	Pages     []surfacePage
	Endpoints map[string][]string // path -> sorted params
	Comments  []string
	Findings  []string
	Tech      []string
}

func (m *surfaceMapper) fetch(ctx context.Context, rawURL string) (*surfaceResp, error) {
	resp, err := rawhttp.Send(ctx, rawhttp.Request{
		URL:         rawURL,
		TLSNoVerify: true,
		Timeout:     m.timeout,
	})
	if err != nil {
		return nil, err
	}
	out := &surfaceResp{
		StatusCode: resp.StatusCode,
		Headers:    resp.Headers,
		Body:       resp.Body,
	}
	m.recordTechFromHeaders(resp.Headers)
	return out, nil
}

func (m *surfaceMapper) recordTechFromHeaders(headers map[string][]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, vals := range headers {
		lk := strings.ToLower(k)
		if lk == "server" && len(vals) > 0 {
			m.techSeen["Server: "+oneLine(vals[0], 60)] = true
		}
		if lk == "x-powered-by" && len(vals) > 0 {
			m.techSeen["X-Powered-By: "+oneLine(vals[0], 60)] = true
		}
		if lk == "cf-ray" {
			m.techSeen["Cloudflare"] = true
		}
	}
}

func (m *surfaceMapper) crawl(ctx context.Context, startPath string) surfaceResult {
	queue := []struct {
		url   string
		depth int
	}{{m.origin + startPath, 0}}

	var pages []surfacePage
	findings := []string{}

	for len(queue) > 0 && len(pages) < m.maxPages {
		item := queue[0]
		queue = queue[1:]

		m.mu.Lock()
		if m.visited[item.url] {
			m.mu.Unlock()
			continue
		}
		m.visited[item.url] = true
		m.mu.Unlock()

		resp, err := m.fetch(ctx, item.url)
		if err != nil {
			continue
		}

		page := m.parsePage(item.url, resp)
		pages = append(pages, page)

		// register params
		m.mu.Lock()
		ep := m.endpoints[pathOnly(item.url)]
		if ep == nil {
			ep = map[string]bool{}
		}
		for _, p := range page.Params {
			ep[p] = true
		}
		m.endpoints[pathOnly(item.url)] = ep
		for _, c := range page.Commented {
			m.comments = append(m.comments, item.url+": "+c)
		}
		m.mu.Unlock()

		// enqueue same-origin links
		if item.depth < m.depth {
			for _, link := range page.Links {
				if strings.HasPrefix(link, m.origin) && !strings.Contains(link, "#") {
					queue = append(queue, struct {
						url   string
						depth int
					}{link, item.depth + 1})
				}
			}
		}
	}

	findings = append(findings, m.securityChecks(ctx)...)

	m.mu.Lock()
	endpoints := map[string][]string{}
	for p, params := range m.endpoints {
		list := make([]string, 0, len(params))
		for k := range params {
			list = append(list, k)
		}
		sort.Strings(list)
		endpoints[p] = list
	}
	comments := append([]string{}, m.comments...)
	tech := make([]string, 0, len(m.techSeen))
	for t := range m.techSeen {
		tech = append(tech, t)
	}
	sort.Strings(tech)
	m.mu.Unlock()

	return surfaceResult{Pages: pages, Endpoints: endpoints, Comments: comments, Findings: findings, Tech: tech}
}

// securityChecks probes a small set of high-signal exposure paths in parallel.
func (m *surfaceMapper) securityChecks(ctx context.Context) []string {
	probes := []struct {
		path   string
		reason string
		match  string
	}{
		{"/.git/HEAD", "exposed git repository", "ref: refs/"},
		{"/.env", "exposed environment file", "="},
		{"/robots.txt", "robots.txt (hidden paths)", "Disallow"},
		{"/sitemap.xml", "sitemap (more endpoints)", "<loc>"},
		{"/swagger.json", "swagger/OpenAPI spec", "\"paths\""},
		{"/api-docs", "API docs endpoint", "{"},
		{"/.well-known/openapi.json", "OpenAPI spec", "openapi"},
		{"/openapi.json", "OpenAPI spec", "openapi"},
		{"/actuator", "Spring Boot actuator", "_links"},
		{"/debug/vars", "Go expvar debug endpoint", "memstats"},
		{"/server-status", "Apache status page", "Server uptime"},
		{"/phpinfo.php", "phpinfo exposure", "phpinfo()"},
		{"/graphql", "GraphQL endpoint", "{"},
		{"/backup.sql", "database dump exposure", "CREATE TABLE"},
		{"/.DS_Store", "macOS Finder metadata leak", "\x00"},
	}
	var findings []string
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, p := range probes {
		wg.Add(1)
		sem <- struct{}{}
		go func(path, reason, match string) {
			defer wg.Done()
			defer func() { <-sem }()
			resp, err := m.fetch(ctx, m.origin+path)
			if err != nil {
				return
			}
			if resp.StatusCode == 200 && strings.Contains(resp.Body, match) {
				mu.Lock()
				findings = append(findings, fmt.Sprintf("EXPOSURE: %s returns 200 at %s (matched %q)", reason, path, match))
				mu.Unlock()
			}
		}(p.path, p.reason, p.match)
	}
	wg.Wait()
	sort.Strings(findings)
	return findings
}

// ---------------------------------------------------------------------------
// HTML parsing (stdlib regex — deliberately lightweight)
// ---------------------------------------------------------------------------

var (
	titleRe      = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	linkRe       = regexp.MustCompile(`(?is)<a[^>]+href=["']([^"'#]+)["']`)
	formRe       = regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	formActionRe = regexp.MustCompile(`(?is)action=["']?([^"'>\s]*)["']?`)
	formMethodRe = regexp.MustCompile(`(?is)method=["']?([^"'>\s]*)["']?`)
	inputNameRe  = regexp.MustCompile(`(?is)<(?:input|textarea|select)[^>]*name=["']([^"']+)["']`)
	inputTypeRe  = regexp.MustCompile(`(?is)<input[^>]*type=["']([^"']+)["']`)
	commentRe    = regexp.MustCompile(`<!--(.*?)-->`)
	queryParamRe = regexp.MustCompile(`[?&]([a-zA-Z_][a-zA-Z0-9_.\[\]-]*)=`)
	jsEndpointRe = regexp.MustCompile(`["'](/(?:api|v[0-9]|rest|internal)[a-zA-Z0-9_/.-]{2,60})["']`)
)

// techBodyMatchers fingerprint client/server frameworks from page bodies.
var techBodyMatchers = []struct {
	re     *regexp.Regexp
	target string
}{
	{regexp.MustCompile(`(?i)wp-content|wordpress`), "WordPress"},
	{regexp.MustCompile(`(?i)/misc/drupal|drupal-settings`), "Drupal"},
	{regexp.MustCompile(`(?i)joomla`), "Joomla"},
	{regexp.MustCompile(`(?i)__NEXT_DATA__|/_next/`), "Next.js"},
	{regexp.MustCompile(`(?i)__NUXT__`), "Nuxt"},
	{regexp.MustCompile(`(?i)data-reactroot|react.production`), "React"},
	{regexp.MustCompile(`(?i)ng-version|angular`), "Angular"},
	{regexp.MustCompile(`(?i)vue(?:\.runtime)?(?:\.min)?\.js`), "Vue"},
	{regexp.MustCompile(`(?i)jquery[-.]?([\d.]+)?\.js`), "jQuery"},
	{regexp.MustCompile(`(?i)laravel_session|XSRF-TOKEN`), "Laravel"},
	{regexp.MustCompile(`(?i)JSESSIONID`), "Java servlet container"},
	{regexp.MustCompile(`(?i)__VIEWSTATE|ASPSESSIONID|asp\.net`), "ASP.NET"},
	{regexp.MustCompile(`(?i)PHPSESSID`), "PHP"},
	{regexp.MustCompile(`(?i) grafana`), "Grafana"},
	{regexp.MustCompile(`(?i)kibana`), "Kibana"},
	{regexp.MustCompile(`(?i)jenkins`), "Jenkins"},
	{regexp.MustCompile(`(?i)swagger-ui`), "Swagger UI"},
}

// parsePage extracts links/forms/params/comments and fingerprints tech.
func (m *surfaceMapper) parsePage(rawURL string, resp *surfaceResp) surfacePage {
	page := surfacePage{URL: rawURL, Status: resp.StatusCode}

	if match := titleRe.FindStringSubmatch(resp.Body); match != nil {
		page.Title = strings.TrimSpace(match[1])
	}

	m.mu.Lock()
	for _, tm := range techBodyMatchers {
		if tm.re.MatchString(resp.Body) {
			m.techSeen[tm.target] = true
		}
	}
	m.mu.Unlock()

	base, _ := url.Parse(rawURL)
	for _, match := range linkRe.FindAllStringSubmatch(resp.Body, -1) {
		href := strings.TrimSpace(match[1])
		if href == "" {
			continue
		}
		ref, err := url.Parse(href)
		if err != nil {
			continue
		}
		resolved := base.ResolveReference(ref)
		if (resolved.Scheme == "http" || resolved.Scheme == "https") && resolved.Host != "" {
			page.Links = append(page.Links, resolved.String())
		}
	}

	for _, f := range formRe.FindAllStringSubmatch(resp.Body, -1) {
		form := surfaceForm{Method: "GET"}
		if fa := formActionRe.FindStringSubmatch(f[0]); fa != nil {
			form.Action = fa[1]
		}
		if fm := formMethodRe.FindStringSubmatch(f[0]); fm != nil {
			form.Method = strings.ToUpper(fm[1])
		}
		seen := map[string]bool{}
		for _, im := range inputNameRe.FindAllStringSubmatch(f[0], -1) {
			if !seen[im[1]] {
				form.Inputs = append(form.Inputs, surfaceInput{Name: im[1], Type: "text"})
				seen[im[1]] = true
			}
		}
		for _, im := range inputTypeRe.FindAllStringSubmatch(f[0], -1) {
			_ = im
		}
		if len(form.Inputs) > 0 || form.Action != "" {
			page.Forms = append(page.Forms, form)
		}
	}

	for _, match := range queryParamRe.FindAllStringSubmatch(rawURL, -1) {
		page.Params = append(page.Params, match[1])
	}
	for _, match := range jsEndpointRe.FindAllStringSubmatch(resp.Body, -1) {
		page.Params = append(page.Params, "js:"+match[1])
	}

	for _, match := range commentRe.FindAllStringSubmatch(resp.Body, -1) {
		c := strings.TrimSpace(match[1])
		if len(c) > 5 {
			page.Commented = append(page.Commented, c)
		}
	}
	return page
}

// renderSurfaceReport formats the crawl result for the agent.
func renderSurfaceReport(result surfaceResult) string {
	var b strings.Builder
	b.WriteString("=== attack surface map ===\n\n")

	if len(result.Tech) > 0 {
		b.WriteString("== technology signals ==\n")
		for _, t := range result.Tech {
			b.WriteString("  - " + t + "\n")
		}
		b.WriteString("\n")
	}

	if len(result.Findings) > 0 {
		b.WriteString("== immediate findings ==\n")
		for _, f := range result.Findings {
			b.WriteString("  [!] " + f + "\n")
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "== pages crawled: %d ==\n", len(result.Pages))
	for _, p := range result.Pages {
		fmt.Fprintf(&b, "  %d %s (%s)\n", p.Status, p.URL, orDefault(p.Title, "no title"))
		if len(p.Forms) > 0 {
			for _, f := range p.Forms {
				inputs := make([]string, 0, len(f.Inputs))
				for _, in := range f.Inputs {
					inputs = append(inputs, in.Name)
				}
				fmt.Fprintf(&b, "      form action=%q method=%s inputs=[%s]\n", f.Action, f.Method, strings.Join(inputs, ", "))
			}
		}
	}

	if len(result.Endpoints) > 0 {
		b.WriteString("\n== endpoints & parameters (attack targets) ==\n")
		paths := make([]string, 0, len(result.Endpoints))
		for p := range result.Endpoints {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		for _, p := range paths {
			params := result.Endpoints[p]
			fmt.Fprintf(&b, "  %s", p)
			if len(params) > 0 {
				fmt.Fprintf(&b, "  params: %s", strings.Join(params, ", "))
			}
			b.WriteString("\n")
		}
	}

	if len(result.Comments) > 0 {
		b.WriteString("\n== interesting HTML comments ==\n")
		for _, c := range result.Comments[:minInt(len(result.Comments), 15)] {
			b.WriteString("  - " + oneLine(c, 200) + "\n")
		}
	}

	b.WriteString(`
== next moves ==
  - parameterized endpoints -> payload_engine (category by suspected class) -> raw_http single probes or proxy_intruder for fuzzing
  - forms -> test auth_bypass / sqli / xss categories on their inputs
  - exposed specs (swagger/openapi) -> enumerate unlisted endpoints and their parameters
  - any confirmed hit -> validate_exploit before claiming it, technique_ledger record it after
`)
	return b.String()
}

// pathOnly strips query/fragment from a URL.
func pathOnly(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Path
}
