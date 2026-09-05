package tools

// Action schemas for the offensive toolset (Payload Engine v2, raw HTTP,
// MITM proxy, DNS enumeration, exploit finder, attack surface mapper,
// swarm execution, exploit validation, technique ledger).
//
// Field descriptions follow the layered convention used across this package:
// the tool description in registry.go states WHEN to use the tool, these
// schemas describe each field's exact contract.

// ---------------------------------------------------------------------------
// payload_engine
// ---------------------------------------------------------------------------

type PayloadEngineAction struct {
	Action   PayloadEngineOp `json:"action" jsonschema:"required,type=string,enum=categories,enum=generate" jsonschema_description:"'categories' lists every payload category with descriptions and counts (run this first if unsure). 'generate' produces the payload list for a category."`
	Category String          `json:"category,omitempty" jsonschema:"type=string" jsonschema_description:"generate only: vulnerability class, e.g. sqli, xss, ssrf, ssti, cmd_injection, path_traversal, xxe, nosql, jwt, smuggling, cache_poisoning. See 'categories' action for the full list."`
	Context  String          `json:"context,omitempty" jsonschema:"type=string" jsonschema_description:"generate only: where the payload lands — query, json, header, path, xml, cookie, form, raw (default raw). Controls escaping so payloads survive the surrounding syntax."`
	Mutation String          `json:"mutation,omitempty" jsonschema:"type=string" jsonschema_description:"generate only: optional transform — url_encode, double_url_encode, unicode_escape, html_entity, hex_encode, case_random, comment_insert, null_byte, newline_escape, ifs_substitution, json_escape, base64."`
	Wafevasion Bool           `json:"waf_evasion,omitempty" jsonschema:"type=boolean" jsonschema_description:"generate only: also produce encoding-chain and comment-obfuscation variants for filter/WAF evasion probing."`
	Seed     String          `json:"seed,omitempty" jsonschema:"type=string" jsonschema_description:"generate only: unique canary marker substituted into payloads supporting {{SEED}} — use a per-attempt random token so responses containing it are provably yours."`
	Limit    *int64          `json:"limit,omitempty" jsonschema:"type=integer" jsonschema_description:"generate only: cap the number of returned payloads (useful for the first probe round; raise for deeper runs)."`
	Message  string          `json:"message" jsonschema:"required,title=Payload engine message" jsonschema_description:"Engagement-log entry — 1-2 short sentences on which category is being generated and why. Written in the engagement language declared by your system prompt."`
}

type PayloadEngineOp = String

const (
	PayloadEngineCategories PayloadEngineOp = "categories"
	PayloadEngineGenerate   PayloadEngineOp = "generate"
)

// ---------------------------------------------------------------------------
// raw_http (Repeater-style raw request)
// ---------------------------------------------------------------------------

type RawHTTPAction struct {
	URL             String `json:"url" jsonschema:"required,type=string" jsonschema_description:"Target base URL including scheme, host and port (e.g. https://target.example.com:8443). Determines the dial target when 'raw_request' is used."`
	Method          String `json:"method,omitempty" jsonschema:"type=string" jsonschema_description:"HTTP method when composing from fields (default GET, or POST if body set). Ignored when raw_request is provided."`
	RawRequest      String `json:"raw_request,omitempty" jsonschema:"type=string" jsonschema_description:"Byte-exact request to transmit verbatim (use \\r\\n line endings). Nothing is normalized — this is full wire control for smuggling, header injection, desync, and cache deception probes. URL is still used for dialing/TLS."`
	Headers         map[string]string `json:"headers,omitempty" jsonschema:"type=object" jsonschema_description:"Headers when composing from fields. Host/User-Agent added automatically unless overridden."`
	Body            String `json:"body,omitempty" jsonschema:"type=string" jsonschema_description:"Request body when composing from fields (Content-Length set automatically)."`
	FollowRedirects Bool  `json:"follow_redirects,omitempty" jsonschema:"type=boolean" jsonschema_description:"Follow 3xx Location hops (default off, like a proxy tool)."`
	ForceHTTP10     Bool  `json:"force_http10,omitempty" jsonschema:"type=boolean" jsonschema_description:"Compose the request line as HTTP/1.0 (protocol downgrade tests)."`
	TimeoutSec      *int64 `json:"timeout_sec,omitempty" jsonschema:"type=integer" jsonschema_description:"Per-request timeout in seconds (default 15)."`
	Message         string `json:"message" jsonschema:"required,title=Raw HTTP message" jsonschema_description:"Engagement-log entry — 1-2 short sentences on which request is being replayed and why. Written in the engagement language declared by your system prompt."`
}

// ---------------------------------------------------------------------------
// MITM proxy: proxy_start / proxy_history / proxy_stop
// ---------------------------------------------------------------------------

type ProxyStartAction struct {
	Port    *int64 `json:"port,omitempty" jsonschema:"type=integer" jsonschema_description:"Listener port (0 or omitted = auto-pick a free port)."`
	Include []string `json:"include,omitempty" jsonschema:"type=array" jsonschema_description:"Scope regexes over 'host+path'; traffic matching none is rejected. Empty = capture everything."`
	Exclude []string `json:"exclude,omitempty" jsonschema:"type=array" jsonschema_description:"Scope exclusion regexes — matching traffic is ignored even if included."`
	Message string `json:"message" jsonschema:"required,title=Proxy start message" jsonschema_description:"Engagement-log entry — 1-2 short sentences on what the proxy will intercept. Written in the engagement language declared by your system prompt."`
}

type ProxyHistoryAction struct {
	EngineID *int64 `json:"engine_id,omitempty" jsonschema:"type=integer" jsonschema_description:"Engine id returned by proxy_start. Omit to use the flow's most recent engine."`
	Filter   String `json:"filter,omitempty" jsonschema:"type=string" jsonschema_description:"Regex applied to 'method host path status' plus bodies; non-matching entries are hidden."`
	Limit    *int64 `json:"limit,omitempty" jsonschema:"type=integer" jsonschema_description:"Max entries returned, newest first (default 25)."`
	Message  string `json:"message" jsonschema:"required,title=Proxy history message" jsonschema_description:"Engagement-log entry — 1-2 short sentences on which captured traffic is being reviewed. Written in the engagement language declared by your system prompt."`
}

type ProxyStopAction struct {
	EngineID *int64 `json:"engine_id,omitempty" jsonschema:"type=integer" jsonschema_description:"Engine id to stop. Omit to stop the flow's most recent engine."`
	Message  string `json:"message" jsonschema:"required,title=Proxy stop message" jsonschema_description:"Engagement-log entry — 1-2 short sentences on why interception is being stopped. Written in the engagement language declared by your system prompt."`
}

// ---------------------------------------------------------------------------
// proxy_intruder (position-based fuzzing)
// ---------------------------------------------------------------------------

type ProxyIntruderAction struct {
	URL             String     `json:"url" jsonschema:"required,type=string" jsonschema_description:"Target base URL used for dialing (scheme/host/port)."`
	RawTemplate     String     `json:"raw_template" jsonschema:"required,type=string" jsonschema_description:"Raw request template with §...§ markers around the parts to fuzz, e.g. GET /login?u=§USER§&p=§PASS§ HTTP/1.1\\r\\nHost: target\\r\\n\\r\\n. Byte-exact control like the repeater."`
	AttackMode      String     `json:"attack_mode,omitempty" jsonschema:"type=string" jsonschema_description:"sniper (each position fuzzed alone, default), battering_ram (same payload everywhere), pitchfork (parallel payload sets), cluster_bomb (all combinations)."`
	PayloadSets     [][]string `json:"payload_sets,omitempty" jsonschema:"type=array" jsonschema_description:"Explicit payload lists — one per §position§ for pitchfork/cluster_bomb; the first list is reused for every position otherwise."`
	PayloadCategory String     `json:"payload_category,omitempty" jsonschema:"type=string" jsonschema_description:"payload_engine category used when payload_sets is empty (e.g. sqli, xss, auth_bypass)."`
	MaxRequests     *int64     `json:"max_requests,omitempty" jsonschema:"type=integer" jsonschema_description:"Hard cap on total requests (default 200, max 2000)."`
	Concurrency     *int64     `json:"concurrency,omitempty" jsonschema:"type=integer" jsonschema_description:"Parallel workers (default 5, max 20)."`
	TimeoutSec      *int64     `json:"timeout_sec,omitempty" jsonschema:"type=integer" jsonschema_description:"Per-request timeout seconds (default 10)."`
	FilterRegex     String     `json:"filter_regex,omitempty" jsonschema:"type=string" jsonschema_description:"Keep only responses whose status/body match this regex (e.g. 'welcome|dashboard|200 OK')."`
	FilterStatus    String     `json:"filter_status,omitempty" jsonschema:"type=string" jsonschema_description:"Keep only these status codes, comma-separated (e.g. '200,500')."`
	Message         string     `json:"message" jsonschema:"required,title=Intruder message" jsonschema_description:"Engagement-log entry — 1-2 short sentences on what is being fuzzed and with which payloads. Written in the engagement language declared by your system prompt."`
}

// ---------------------------------------------------------------------------
// dns_enum
// ---------------------------------------------------------------------------

type DNSEnumAction struct {
	Domain     String  `json:"domain" jsonschema:"required,type=string" jsonschema_description:"Target domain (e.g. example.com)."`
	Action     DNSEnumOp `json:"dns_action,omitempty" jsonschema:"type=string,enum=records,enum=subdomains,enum=axfr,enum=reverse,enum=srv,enum=all" jsonschema_description:"'records' (A/AAAA/MX/NS/TXT/SOA/CAA/CNAME), 'subdomains' (brute-force common names), 'axfr' (zone transfer attempt), 'reverse' (PTR for the domain's A records), 'srv' (common SRV services), 'all' (everything, default)."`
	Nameservers []string `json:"nameservers,omitempty" jsonschema:"type=array" jsonschema_description:"Custom resolvers to query (default: system + 8.8.8.8 + 1.1.1.1)."`
	Subdomains []string  `json:"subdomains,omitempty" jsonschema:"type=array" jsonschema_description:"Extra candidate labels for the subdomain brute-force (merged with the built-in list)."`
	Message    string    `json:"message" jsonschema:"required,title=DNS enumeration message" jsonschema_description:"Engagement-log entry — 1-2 short sentences on which host is being resolved and why. Written in the engagement language declared by your system prompt."`
}

type DNSEnumOp = String

// ---------------------------------------------------------------------------
// exploit_finder
// ---------------------------------------------------------------------------

type ExploitFinderAction struct {
	Query    String `json:"query,omitempty" jsonschema:"type=string" jsonschema_description:"What to look up: product ('apache 2.4.49'), technology ('jenkins'), or a specific CVE id ('CVE-2021-41773')."`
	CVE      String `json:"cve,omitempty" jsonschema:"type=string" jsonschema_description:"Deep-dive a single CVE id: NVD record + EPSS exploitation probability + CISA KEV status in one result."`
	MinCVSS  *float64 `json:"min_cvss,omitempty" jsonschema:"type=number" jsonschema_description:"Filter search results to CVSS >= this value (0-10)."`
	MaxResults *int64 `json:"max_results,omitempty" jsonschema:"type=integer" jsonschema_description:"Cap the result list (default 15)."`
	Message  string `json:"message" jsonschema:"required,title=Exploit finder message" jsonschema_description:"Engagement-log entry — 1-2 short sentences on which technology or CVE is being researched. Written in the engagement language declared by your system prompt."`
}

// ---------------------------------------------------------------------------
// attack_surface
// ---------------------------------------------------------------------------

type AttackSurfaceAction struct {
	URL       String `json:"url" jsonschema:"required,type=string" jsonschema_description:"Starting URL (scheme + host required). The crawl stays on this origin."`
	Depth     *int64 `json:"depth,omitempty" jsonschema:"type=integer" jsonschema_description:"Crawl depth in link hops (default 2, max 4)."`
	MaxPages  *int64 `json:"max_pages,omitempty" jsonschema:"type=integer" jsonschema_description:"Max pages fetched (default 25, max 100)."`
	TimeoutSec *int64 `json:"timeout_sec,omitempty" jsonschema:"type=integer" jsonschema_description:"Per-request timeout seconds (default 10)."`
	Message   string `json:"message" jsonschema:"required,title=Attack surface message" jsonschema_description:"Engagement-log entry — 1-2 short sentences on which origin is being mapped. Written in the engagement language declared by your system prompt."`
}

// ---------------------------------------------------------------------------
// swarm_attack
// ---------------------------------------------------------------------------

type SwarmWorker struct {
	Role    String `json:"role,omitempty" jsonschema:"type=string" jsonschema_description:"Worker label shown in results — recon, fuzzer, scanner, exploiter, chain, etc. (max 4 workers total)."`
	Command String `json:"command" jsonschema:"required,type=string" jsonschema_description:"Shell command for this worker, executed in the flow container in parallel with the others."`
	TimeoutSec *int64 `json:"timeout_sec,omitempty" jsonschema:"type=integer" jsonschema_description:"Per-worker timeout seconds (default 300)."`
}

type SwarmAttackAction struct {
	Workers []SwarmWorker `json:"workers" jsonschema:"required" jsonschema_description:"1-4 parallel workers. Design them around ONE objective with disjoint angles, e.g. worker1=port sweep, worker2=dir brute force, worker3=service version probes, worker4=exploit search."`
	Message string        `json:"message" jsonschema:"required,title=Swarm message" jsonschema_description:"Engagement-log entry — 1-2 short sentences on what the swarm is attacking in parallel. Written in the engagement language declared by your system prompt."`
}

// ---------------------------------------------------------------------------
// validate_exploit
// ---------------------------------------------------------------------------

type ValidateExploitAction struct {
	Claim     String   `json:"claim" jsonschema:"required,type=string" jsonschema_description:"The finding to verify, stated precisely — e.g. 'SQL injection in /item.php?id allows full DB read'."`
	Evidence  String   `json:"evidence" jsonschema:"required,type=string" jsonschema_description:"What you observed that suggests the claim (raw output, status codes, timing)."`
	ProbeCmds []string `json:"probe_cmds,omitempty" jsonschema:"type=array" jsonschema_description:"Commands to run in the flow container that would SUCCEED only if the claim is real — e.g. an extraction query returning a canary, a file read showing known content, a marker echo through an RCE. 1-5 commands."`
	SuccessRegex String `json:"success_regex,omitempty" jsonschema:"type=string" jsonschema_description:"Regex that must match a probe's output to count as proof (e.g. 'root:x:0:0' for a passwd read, 'uid=\\\\d+' for command execution)."`
	Repeat    *int64   `json:"repeat,omitempty" jsonschema:"type=integer" jsonschema_description:"Run each probe N times to rule out flukes (default 1, max 5)."`
	Message   string   `json:"message" jsonschema:"required,title=Validation message" jsonschema_description:"Engagement-log entry — 1-2 short sentences on which claim is being validated. Written in the engagement language declared by your system prompt."`
}

// ---------------------------------------------------------------------------
// technique_ledger
// ---------------------------------------------------------------------------

type TechniqueLedgerAction struct {
	Action   LedgerOp `json:"action" jsonschema:"required,type=string,enum=record,enum=recall,enum=summary" jsonschema_description:"'record' logs a technique attempt with its outcome, 'recall' searches past attempts before you plan the next move, 'summary' returns the full tried-techniques digest for the current target."`
	Technique String  `json:"technique,omitempty" jsonschema:"type=string" jsonschema_description:"record only: what you tried, precisely — e.g. 'nmap -sV full port sweep on 10.0.0.5', 'union-based SQLi on /item.php?id'."`
	Target   String  `json:"target,omitempty" jsonschema:"type=string" jsonschema_description:"record/recall: the host/endpoint the technique applies to."`
	Outcome  String  `json:"outcome,omitempty" jsonschema:"type=string,enum=worked,enum=failed,enum=partial,enum=blocked" jsonschema_description:"record only: worked (proven impact), failed (no result), partial (some signal), blocked (defensive control stopped it)."`
	Details  String  `json:"details,omitempty" jsonschema:"type=string" jsonschema_description:"record only: concrete evidence and next-step hints; recall: optional filter keywords."`
	Message  string  `json:"message" jsonschema:"required,title=Ledger message" jsonschema_description:"Engagement-log entry — 1-2 short sentences. Written in the engagement language declared by your system prompt."`
}

type LedgerOp = String

const (
	LedgerRecord  LedgerOp = "record"
	LedgerRecall  LedgerOp = "recall"
	LedgerSummary LedgerOp = "summary"
)
