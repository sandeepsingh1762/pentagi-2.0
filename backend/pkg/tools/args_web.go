package tools

// Action schemas for the web-exploitation specialization and the autonomous
// goal engine.

// ---------------------------------------------------------------------------
// web_session — authenticated session management
// ---------------------------------------------------------------------------

type WebSessionAction struct {
	Action      WebSessionOp      `json:"action" jsonschema:"required,type=string,enum=start,enum=login,enum=request,enum=inspect,enum=reset" jsonschema_description:"'start' opens a session on a base URL, 'login' authenticates and stores the session, 'request' sends one cookie-authenticated request, 'inspect' shows held cookies with a security audit, 'reset' clears cookies (fresh unauthenticated state)."`
	SessionID   *int64            `json:"session_id,omitempty" jsonschema:"type=integer" jsonschema_description:"Existing session id (returned by start). Omit for the flow's most recent session."`
	BaseURL     String            `json:"base_url,omitempty" jsonschema:"type=string" jsonschema_description:"start only: origin, e.g. https://target.example.com — all later paths resolve against it."`
	LoginURL    String            `json:"login_url,omitempty" jsonschema:"type=string" jsonschema_description:"login only: login endpoint path, e.g. /api/login or /login."`
	Format      String            `json:"format,omitempty" jsonschema:"type=string,enum=form,enum=json" jsonschema_description:"login/brute only: request body format (default form)."`
	UserField   String            `json:"user_field,omitempty" jsonschema:"type=string" jsonschema_description:"login only: username field name (default username)."`
	PassField   String            `json:"pass_field,omitempty" jsonschema:"type=string" jsonschema_description:"login only: password field name (default password)."`
	Username    String            `json:"username,omitempty" jsonschema:"type=string" jsonschema_description:"login only: username."`
	Password    String            `json:"password,omitempty" jsonschema:"type=string" jsonschema_description:"login only: password."`
	ExtraFields map[string]string `json:"extra_fields,omitempty" jsonschema:"type=object" jsonschema_description:"login only: additional body fields (CSRF token, remember-me, etc.)."`
	Method      String            `json:"method,omitempty" jsonschema:"type=string" jsonschema_description:"request only: HTTP method (default GET)."`
	URL         String            `json:"url,omitempty" jsonschema:"type=string" jsonschema_description:"request only: absolute URL or path on the session origin."`
	Headers     map[string]string `json:"headers,omitempty" jsonschema:"type=object" jsonschema_description:"request only: extra headers for this call."`
	Body        String            `json:"body,omitempty" jsonschema:"type=string" jsonschema_description:"request only: request body (Content-Type via headers)."`
	Message     string            `json:"message" jsonschema:"required,title=Web session message" jsonschema_description:"Engagement-log entry — 1-2 short sentences on which session action is running and why. Written in the engagement language declared by your system prompt."`
}

type WebSessionOp = String

// ---------------------------------------------------------------------------
// injection_hunt — automated injection detection with response differencing
// ---------------------------------------------------------------------------

type InjectionHuntAction struct {
	URL          String            `json:"url" jsonschema:"required,type=string" jsonschema_description:"Target request URL. For query params include the current query string (e.g. https://t.example/item?id=1)."`
	Params       []string          `json:"params" jsonschema:"required,type=array" jsonschema_description:"Parameter names to test, e.g. [\"id\",\"q\",\"sort\"]. One hunt covers all of them."`
	ParamIn      String            `json:"param_in,omitempty" jsonschema:"type=string,enum=query,enum=json,enum=form,enum=header,enum=cookie" jsonschema_description:"Where the parameters live (default query)."`
	Method       String            `json:"method,omitempty" jsonschema:"type=string" jsonschema_description:"HTTP method (default GET for query, POST otherwise)."`
	Category     String            `json:"category,omitempty" jsonschema:"type=string" jsonschema_description:"payload_engine category to hunt with (default sqli; try ssti, xss, nosql, cmd_injection...)."`
	StaticParams map[string]string `json:"static_params,omitempty" jsonschema:"type=object" jsonschema_description:"Other parameters sent unchanged (context params the app requires)."`
	JSONBody     map[string]string `json:"json_body,omitempty" jsonschema:"type=object" jsonschema_description:"param_in=json: full JSON body template; the tested param's value is replaced per payload."`
	SessionID    *int64            `json:"session_id,omitempty" jsonschema:"type=integer" jsonschema_description:"web_session id for AUTHENTICATED hunting — always preferred when the endpoint needs login."`
	MaxPayloads  *int64            `json:"max_payloads,omitempty" jsonschema:"type=integer" jsonschema_description:"Payloads per parameter (default 25, max 80)."`
	TimeoutSec   *int64            `json:"timeout_sec,omitempty" jsonschema:"type=integer" jsonschema_description:"Per-request timeout seconds (default 12)."`
	Message      string            `json:"message" jsonschema:"required,title=Injection hunt message" jsonschema_description:"Engagement-log entry — 1-2 short sentences on which endpoint/params are being hunted and with which class. Written in the engagement language declared by your system prompt."`
}

// ---------------------------------------------------------------------------
// auth_attack — credential brute force, JWT toolkit
// ---------------------------------------------------------------------------

type AuthAttackAction struct {
	Action         AuthAttackOp      `json:"action" jsonschema:"required,type=string,enum=brute,enum=jwt_decode,enum=jwt_tamper,enum=cookie_audit" jsonschema_description:"'brute' runs a credential attack on a login endpoint, 'jwt_decode' decodes and risk-analyzes a JWT, 'jwt_tamper' generates classic tampered JWT variants (alg:none, claim escalation, exp removal, kid injection) to replay, 'cookie_audit' scores the session's cookies (flags, entropy, session detection)."`
	URL            String            `json:"url,omitempty" jsonschema:"type=string" jsonschema_description:"brute only: login endpoint URL."`
	Format         String            `json:"format,omitempty" jsonschema:"type=string,enum=form,enum=json" jsonschema_description:"brute only: body format (default form)."`
	UserField      String            `json:"user_field,omitempty" jsonschema:"type=string" jsonschema_description:"brute only: username field (default username)."`
	PassField      String            `json:"pass_field,omitempty" jsonschema:"type=string" jsonschema_description:"brute only: password field (default password)."`
	UsernameStatic String            `json:"username_static,omitempty" jsonschema:"type=string" jsonschema_description:"brute only: fixed username = password-spray mode (recommended first)."`
	Usernames      []string          `json:"usernames,omitempty" jsonschema:"type=array" jsonschema_description:"brute only: custom username list (built-in list used when omitted)."`
	Passwords      []string          `json:"passwords,omitempty" jsonschema:"type=array" jsonschema_description:"brute only: custom password list (built-in list used when omitted)."`
	ExtraFields    map[string]string `json:"extra_fields,omitempty" jsonschema:"type=object" jsonschema_description:"brute only: extra body fields (CSRF etc.)."`
	SuccessBody    String            `json:"success_body,omitempty" jsonschema:"type=string" jsonschema_description:"brute only: regex that matches ONLY a successful login response body (recommended; otherwise heuristics apply)."`
	Token          String            `json:"token,omitempty" jsonschema:"type=string" jsonschema_description:"jwt actions only: the JWT string (decode before tamper)."`
	SessionID      *int64            `json:"session_id,omitempty" jsonschema:"type=integer" jsonschema_description:"cookie_audit only: web_session id (default flow's latest)."`
	MaxAttempts    *int64            `json:"max_attempts,omitempty" jsonschema:"type=integer" jsonschema_description:"brute only: attempt cap (default 200)."`
	Message        string            `json:"message" jsonschema:"required,title=Auth attack message" jsonschema_description:"Engagement-log entry — 1-2 short sentences. Written in the engagement language declared by your system prompt."`
}

type AuthAttackOp = String

// ---------------------------------------------------------------------------
// waf_detect
// ---------------------------------------------------------------------------

type WAFDetectAction struct {
	URL        String `json:"url" jsonschema:"required,type=string" jsonschema_description:"Target URL to fingerprint."`
	TimeoutSec *int64 `json:"timeout_sec,omitempty" jsonschema:"type=integer" jsonschema_description:"Per-probe timeout seconds (default 10)."`
	Message    string `json:"message" jsonschema:"required,title=WAF detect message" jsonschema_description:"Engagement-log entry — 1-2 short sentences. Written in the engagement language declared by your system prompt."`
}

// ---------------------------------------------------------------------------
// goal_manager — autonomous goal-achievement engine
// ---------------------------------------------------------------------------

type GoalManagerAction struct {
	Action    GoalManagerOp `json:"action" jsonschema:"required,type=string,enum=define,enum=add_strategy,enum=strategy_result,enum=next,enum=status,enum=hint,enum=achieved,enum=blocked" jsonschema_description:"'define' states the goal + observable achievement criteria, 'add_strategy' queues an approach, 'strategy_result' records a strategy outcome WITH evidence, 'next' returns the next pending strategy, 'status' shows the full state, 'hint' suggests untouched methodology families, 'achieved' closes the goal (evidence REQUIRED), 'blocked' concedes (requires >=3 dead strategies across >=2 families)."`
	Goal      String        `json:"goal,omitempty" jsonschema:"type=string" jsonschema_description:"define only: the objective in one precise sentence — what state do you need to REACH (not what to try)."`
	Criteria  []string      `json:"criteria,omitempty" jsonschema:"type=array" jsonschema_description:"define only: observable criteria that PROVE achievement, e.g. [\"admin dashboard returns 200 with admin cookie\",\"users table rows visible\"]."`
	Strategy  String        `json:"strategy,omitempty" jsonschema:"type=string" jsonschema_description:"add_strategy/strategy_result: the approach name — specific, e.g. 'union sqli on /item.php?id'."`
	Family    String        `json:"family,omitempty" jsonschema:"type=string" jsonschema_description:"add_strategy only: methodology family — injection|auth-session|business-logic|infrastructure|client-side|protocol|recon|exploit-chain."`
	OutStatus String        `json:"out_status,omitempty" jsonschema:"type=string,enum=running,enum=worked,enum=failed,enum=blocked" jsonschema_description:"strategy_result only: outcome of the strategy."`
	Evidence  String        `json:"evidence,omitempty" jsonschema:"type=string" jsonschema_description:"strategy_result: what happened (required for failed/blocked/worked). achieved: the PROOF — commands + key output showing the criteria are met (always required). blocked: why every strategy died."`
	Message   string        `json:"message" jsonschema:"required,title=Goal manager message" jsonschema_description:"Engagement-log entry — 1-2 short sentences. Written in the engagement language declared by your system prompt."`
}

type GoalManagerOp = String
