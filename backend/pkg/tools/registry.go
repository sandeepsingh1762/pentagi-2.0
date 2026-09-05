package tools

import (
	"maps"
	"pentagi/pkg/database"

	"github.com/invopop/jsonschema"
	"github.com/vxcontrol/langchaingo/llms"
)

const (
	FinalyToolName             = "done"
	AskUserToolName            = "ask"
	MaintenanceToolName        = "maintenance"
	MaintenanceResultToolName  = "maintenance_result"
	CoderToolName              = "coder"
	CodeResultToolName         = "code_result"
	PentesterToolName          = "pentester"
	HackResultToolName         = "hack_result"
	AdviceToolName             = "advice"
	MemoristToolName           = "memorist"
	MemoristResultToolName     = "memorist_result"
	BrowserToolName            = "browser"
	GoogleToolName             = "google"
	DuckDuckGoToolName         = "duckduckgo"
	TavilyToolName             = "tavily"
	FirecrawlToolName          = "firecrawl"
	TraversaalToolName         = "traversaal"
	PerplexityToolName         = "perplexity"
	SearxngToolName            = "searxng"
	SploitusToolName           = "sploitus"
	WebSearchToolName          = "web_search"
	SearchToolName             = "search"
	SearchResultToolName       = "search_result"
	EnricherResultToolName     = "enricher_result"
	SearchInMemoryToolName     = "search_in_memory"
	SearchGuideToolName        = "search_guide"
	StoreGuideToolName         = "store_guide"
	SearchAnswerToolName       = "search_answer"
	StoreAnswerToolName        = "store_answer"
	SearchCodeToolName         = "search_code"
	StoreCodeToolName          = "store_code"
	GraphitiSearchToolName     = "graphiti_search"
	ReportResultToolName       = "report_result"
	SubtaskListToolName        = "subtask_list"
	SubtaskPatchToolName       = "subtask_patch"
	TerminalToolName           = "terminal"
	FileToolName               = "file"
	GetFlowStatusToolName      = "get_flow_status"
	StopFlowToolName           = "stop_flow"
	SubmitFlowInputToolName    = "submit_flow_input"
	PatchFlowSubtasksToolName  = "patch_flow_subtasks"
	WaitFlowCompletionToolName = "wait_flow_completion"
)

type ToolType int

const (
	NoneToolType ToolType = iota
	EnvironmentToolType
	SearchNetworkToolType
	SearchVectorDbToolType
	AgentToolType
	StoreAgentResultToolType
	StoreVectorDbToolType
	BarrierToolType
)

func (t ToolType) String() string {
	switch t {
	case EnvironmentToolType:
		return "environment"
	case SearchNetworkToolType:
		return "search_network"
	case SearchVectorDbToolType:
		return "search_vector_db"
	case AgentToolType:
		return "agent"
	case StoreAgentResultToolType:
		return "store_agent_result"
	case StoreVectorDbToolType:
		return "store_vector_db"
	case BarrierToolType:
		return "barrier"
	default:
		return "none"
	}
}

// GetToolType returns the tool type for a given tool name
func GetToolType(name string) ToolType {
	if toolType, ok := toolsTypeMapping[name]; ok {
		return toolType
	}
	return NoneToolType
}

var toolsTypeMapping = map[string]ToolType{
	FinalyToolName:             BarrierToolType,
	AskUserToolName:            BarrierToolType,
	MaintenanceToolName:        AgentToolType,
	MaintenanceResultToolName:  StoreAgentResultToolType,
	CoderToolName:              AgentToolType,
	CodeResultToolName:         StoreAgentResultToolType,
	PentesterToolName:          AgentToolType,
	HackResultToolName:         StoreAgentResultToolType,
	AdviceToolName:             AgentToolType,
	MemoristToolName:           AgentToolType,
	MemoristResultToolName:     StoreAgentResultToolType,
	BrowserToolName:            SearchNetworkToolType,
	GoogleToolName:             SearchNetworkToolType,
	DuckDuckGoToolName:         SearchNetworkToolType,
	TavilyToolName:             SearchNetworkToolType,
	FirecrawlToolName:          SearchNetworkToolType,
	TraversaalToolName:         SearchNetworkToolType,
	PerplexityToolName:         SearchNetworkToolType,
	SearxngToolName:            SearchNetworkToolType,
	SploitusToolName:           SearchNetworkToolType,
	WebSearchToolName:          SearchNetworkToolType,
	PayloadEngineToolName:      EnvironmentToolType,
	RawHTTPToolName:            EnvironmentToolType,
	SmuggleProbeToolName:       EnvironmentToolType,
	ProxyStartToolName:         EnvironmentToolType,
	ProxyHistoryToolName:       EnvironmentToolType,
	ProxyStopToolName:          EnvironmentToolType,
	ProxyIntruderToolName:      EnvironmentToolType,
	DNSEnumToolName:            EnvironmentToolType,
	ExploitFinderToolName:      SearchNetworkToolType,
	AttackSurfaceToolName:      EnvironmentToolType,
	SwarmAttackToolName:        EnvironmentToolType,
	ValidateExploitToolName:    EnvironmentToolType,
	TechniqueLedgerToolName:    StoreVectorDbToolType,
	WebSessionToolName:         EnvironmentToolType,
	InjectionHuntToolName:      EnvironmentToolType,
	AuthAttackToolName:         EnvironmentToolType,
	WAFDetectToolName:          EnvironmentToolType,
	GoalManagerToolName:        StoreAgentResultToolType,
	SearchToolName:             AgentToolType,
	SearchResultToolName:       StoreAgentResultToolType,
	EnricherResultToolName:     StoreAgentResultToolType,
	SearchInMemoryToolName:     SearchVectorDbToolType,
	SearchGuideToolName:        SearchVectorDbToolType,
	StoreGuideToolName:         StoreVectorDbToolType,
	SearchAnswerToolName:       SearchVectorDbToolType,
	StoreAnswerToolName:        StoreVectorDbToolType,
	SearchCodeToolName:         SearchVectorDbToolType,
	StoreCodeToolName:          StoreVectorDbToolType,
	GraphitiSearchToolName:     SearchVectorDbToolType,
	ReportResultToolName:       StoreAgentResultToolType,
	SubtaskListToolName:        StoreAgentResultToolType,
	SubtaskPatchToolName:       StoreAgentResultToolType,
	TerminalToolName:           EnvironmentToolType,
	FileToolName:               EnvironmentToolType,
	GetFlowStatusToolName:      EnvironmentToolType,
	StopFlowToolName:           EnvironmentToolType,
	SubmitFlowInputToolName:    EnvironmentToolType,
	PatchFlowSubtasksToolName:  EnvironmentToolType,
	WaitFlowCompletionToolName: EnvironmentToolType,
}

var reflector = &jsonschema.Reflector{
	DoNotReference: true,
	ExpandedStruct: true,
}

var allowedSummarizingToolsResult = []string{
	TerminalToolName,
	BrowserToolName,
}

var allowedStoringInMemoryTools = []string{
	TerminalToolName,
	FileToolName,
	SearchToolName,
	GoogleToolName,
	DuckDuckGoToolName,
	TavilyToolName,
	FirecrawlToolName,
	TraversaalToolName,
	PerplexityToolName,
	SearxngToolName,
	SploitusToolName,
	WebSearchToolName,
	MaintenanceToolName,
	CoderToolName,
	PentesterToolName,
	AdviceToolName,
}

var registryDefinitions = map[string]llms.FunctionDefinition{
	TerminalToolName: {
		Name: TerminalToolName,
		Description: "Calls a terminal command in blocking mode. " +
			"Use timeout=0 or a negative value to apply the configured server default timeout. " +
			"Explicit positive values are accepted up to 10800 seconds (3 hours); values outside this range are replaced by the server default. " +
			"Only one command can be executed at a time",
		Parameters: reflector.Reflect(&TerminalAction{}),
	},
	FileToolName: {
		Name: FileToolName,
		Description: "Reads, writes, or edits local files (see 'action'). " +
			"Prefer edit_file for targeted changes to an existing file; use write_file only for a new file or a full rewrite.",
		Parameters: reflector.Reflect(&FileAction{}),
	},
	ReportResultToolName: {
		Name:        ReportResultToolName,
		Description: "Send the report result to the user with execution status and description",
		Parameters:  reflector.Reflect(&TaskResult{}),
	},
	SubtaskListToolName: {
		Name:        SubtaskListToolName,
		Description: "Send new generated subtask list to the user",
		Parameters:  reflector.Reflect(&SubtaskList{}),
	},
	SubtaskPatchToolName: {
		Name: SubtaskPatchToolName,
		Description: "Submit delta operations to modify the current subtask list instead of regenerating all subtasks. " +
			"Supports add (create new subtask at position), remove (delete by ID), modify (update title/description), " +
			"and reorder (move to different position) operations. Use empty operations array if no changes needed.",
		Parameters: reflector.Reflect(&SubtaskPatch{}),
	},
	SearchToolName: {
		Name: SearchToolName,
		Description: "Search in a different search engines in the internet and long-term memory " +
			"by your complex question to the researcher team member, also you can add some instructions to get result " +
			"in a specific format or structure or content type like " +
			"code or command samples, manuals, guides, exploits, vulnerability details, repositories, libraries, etc.",
		Parameters: reflector.Reflect(&ComplexSearch{}),
	},
	SearchResultToolName: {
		Name:        SearchResultToolName,
		Description: "Send the complex search result as a answer for the user question to the user",
		Parameters:  reflector.Reflect(&SearchResult{}),
	},
	BrowserToolName: {
		Name:        BrowserToolName,
		Description: "Opens a browser to look for additional information from the web site",
		Parameters:  reflector.Reflect(&Browser{}),
	},
	GoogleToolName: {
		Name: GoogleToolName,
		Description: "Search in the google search engine, it's a fast query and the shortest content " +
			"to check some information or collect public links by short query",
		Parameters: reflector.Reflect(&SearchAction{}),
	},
	DuckDuckGoToolName: {
		Name: DuckDuckGoToolName,
		Description: "Search in the duckduckgo search engine, it's a anonymous query and returns a small content " +
			"to check some information from different sources or collect public links by short query",
		Parameters: reflector.Reflect(&SearchAction{}),
	},
	TavilyToolName: {
		Name: TavilyToolName,
		Description: "Search in the tavily search engine, it's a more complex query and more detailed content " +
			"with answer by query and detailed information from the web sites",
		Parameters: reflector.Reflect(&SearchAction{}),
	},
	FirecrawlToolName: {
		Name: FirecrawlToolName,
		Description: "Search in the firecrawl search engine, it combines web search with page scraping to return " +
			"the main-content markdown for each result, ideal for deep research on complex technical topics " +
			"and reading documentation directly from the discovered web sites",
		Parameters: reflector.Reflect(&SearchAction{}),
	},
	TraversaalToolName: {
		Name: TraversaalToolName,
		Description: "Search in the traversaal search engine, presents you answer and web-links " +
			"by your query according to relevant information from the web sites",
		Parameters: reflector.Reflect(&SearchAction{}),
	},
	PerplexityToolName: {
		Name: PerplexityToolName,
		Description: "Search in the perplexity search engine, it's a fully complex query and detailed research report " +
			"with answer by query and detailed information from the web sites and other sources augmented by the LLM",
		Parameters: reflector.Reflect(&SearchAction{}),
	},
	SearxngToolName: {
		Name: SearxngToolName,
		Description: "Search in the searxng meta search engine, it's a privacy-focused search engine " +
			"that aggregates results from multiple search engines with customizable categories, " +
			"language settings, and safety filters",
		Parameters: reflector.Reflect(&SearchAction{}),
	},
	SploitusToolName: {
		Name: SploitusToolName,
		Description: "Search the Sploitus exploit aggregator (https://sploitus.com) for public exploits, " +
			"proof-of-concept code, and offensive security tools. Sploitus indexes ExploitDB, Packet Storm, " +
			"GitHub Security Advisories, and many other sources. Use this tool to find exploit code and PoCs " +
			"for specific software, services, CVEs, or vulnerability classes (e.g. 'ssh', 'apache log4j', " +
			"'CVE-2021-44228'). Returns exploit URLs, CVSS scores, CVE references, and publication dates.",
		Parameters: reflector.Reflect(&SploitusAction{}),
	},
	WebSearchToolName: {
		Name: WebSearchToolName,
		Description: "Search the web through a unified engine. Provide a `query` and a `mode`: " +
			"`links` for a quick list of source links with snippets, `answer` for a synthesized answer over " +
			"live sources (default), `research` for deep multi-source analysis with reasoning, or `exploit` for " +
			"exploit code, PoCs, and offensive tooling. The tool selects the best available search provider for " +
			"that mode, retries transient failures, and automatically falls back to alternative providers, so you " +
			"do NOT choose or name a specific engine. Queries must be short, keyword-focused, and in English.",
		Parameters: reflector.Reflect(&WebSearchAction{}),
	},
	EnricherResultToolName: {
		Name:        EnricherResultToolName,
		Description: "Send the enriched user's question with additional information to the user",
		Parameters:  reflector.Reflect(&EnricherResult{}),
	},
	SearchInMemoryToolName: {
		Name: SearchInMemoryToolName,
		Description: "Search in the vector database (long-term memory) for relevant information by providing one or more semantically rich, " +
			"context-aware natural language queries (1 to 5 queries). Formulate each query with sufficient context, intent, and detailed descriptions " +
			"to enhance semantic matching and retrieval accuracy. Multiple queries allow exploring different semantic angles and improve recall. " +
			"Results from all queries are merged, deduplicated, and ranked by relevance score. This function is ideal when you need to retrieve specific information " +
			"to assist in generating accurate and informative responses. If Task ID or Subtask ID are known, " +
			"they can be used as strict filters to further refine the search results and improve relevancy.",
		Parameters: reflector.Reflect(&SearchInMemoryAction{}),
	},
	SearchGuideToolName: {
		Name: SearchGuideToolName,
		Description: "Search in the vector database for relevant guides by providing one or more semantically rich, context-aware natural language queries (1 to 5 queries). " +
			"Formulate each query with sufficient context, intent, and detailed descriptions of the guides you need to enhance semantic matching and " +
			"retrieval accuracy. Multiple queries allow exploring different aspects of the guide topic and improve search coverage. " +
			"Specify the type of guide required to further refine the search. Results from all queries are merged, deduplicated, and ranked by relevance score. " +
			"This function is ideal when you need to retrieve specific guides to assist in accomplishing tasks or solving issues.",
		Parameters: reflector.Reflect(&SearchGuideAction{}),
	},
	StoreGuideToolName: {
		Name: StoreGuideToolName,
		Description: "Store the guide to the vector database for future use. " +
			"Anonymize all sensitive data (IPs, domains, credentials, paths) using descriptive placeholders",
		Parameters: reflector.Reflect(&StoreGuideAction{}),
	},
	SearchAnswerToolName: {
		Name: SearchAnswerToolName,
		Description: "Search in the vector database for relevant answers by providing one or more semantically rich, context-aware natural language queries (1 to 5 queries). " +
			"Formulate each query with sufficient context, intent, and detailed descriptions of what you want to find and why you need it " +
			"to enhance semantic matching and retrieval accuracy. Multiple queries allow exploring different formulations and improve search coverage. " +
			"Specify the type of answer required to further refine the search. Results from all queries are merged, deduplicated, and ranked by relevance score. " +
			"This function is ideal when you need to retrieve specific answers to assist in tasks, solve issues, or answer questions.",
		Parameters: reflector.Reflect(&SearchAnswerAction{}),
	},
	StoreAnswerToolName: {
		Name: StoreAnswerToolName,
		Description: "Store the question answer to the vector database for future use. " +
			"Anonymize all sensitive data (IPs, domains, credentials) using descriptive placeholders",
		Parameters: reflector.Reflect(&StoreAnswerAction{}),
	},
	SearchCodeToolName: {
		Name: SearchCodeToolName,
		Description: "Search in the vector database for relevant code samples by providing one or more semantically rich, context-aware natural language queries (1 to 5 queries). " +
			"Formulate each query with sufficient context, intent, and detailed descriptions of what you want to achieve with the code and what should be included, " +
			"to enhance semantic matching and retrieval accuracy. Multiple queries allow exploring different code patterns and use cases. " +
			"Specify the programming language to further refine the search. Results from all queries are merged, deduplicated, and ranked by relevance score. " +
			"This function is ideal when you need to retrieve specific code examples to assist in development tasks or solve programming issues.",
		Parameters: reflector.Reflect(&SearchCodeAction{}),
	},
	StoreCodeToolName: {
		Name: StoreCodeToolName,
		Description: "Store the code sample to the vector database for future use. It's should be a sample like a one source code file for some question. " +
			"Anonymize all sensitive data (IPs, domains, credentials, API keys) using descriptive placeholders",
		Parameters: reflector.Reflect(&StoreCodeAction{}),
	},
	GraphitiSearchToolName: {
		Name: GraphitiSearchToolName,
		Description: "Search the Graphiti temporal knowledge graph for historical penetration testing context, " +
			"including previous agent responses, tool execution records, discovered entities, and their relationships. " +
			"Supports 7 search types: temporal_window (time-bounded search), entity_relationships (graph traversal from an entity), " +
			"diverse_results (anti-redundancy search), episode_context (full agent reasoning and tool outputs), " +
			"successful_tools (proven techniques), recent_context (latest findings), and entity_by_label (type-specific entity search). " +
			"Use this to avoid repeating failed approaches, reuse successful exploitation techniques, understand entity relationships, " +
			"and build on previous findings within the same penetration testing engagement.",
		Parameters: reflector.Reflect(&GraphitiSearchAction{}),
	},
	MemoristToolName: {
		Name:        MemoristToolName,
		Description: "Call to Archivist team member who remember all the information about the past work and made tasks and can answer your question about it",
		Parameters:  reflector.Reflect(&MemoristAction{}),
	},
	MemoristResultToolName: {
		Name:        MemoristResultToolName,
		Description: "Send the search in long-term memory result as a answer for the user question to the user",
		Parameters:  reflector.Reflect(&MemoristResult{}),
	},
	MaintenanceToolName: {
		Name:        MaintenanceToolName,
		Description: "Call to DevOps team member to maintain local environment and tools inside the docker container",
		Parameters:  reflector.Reflect(&MaintenanceAction{}),
	},
	MaintenanceResultToolName: {
		Name:        MaintenanceResultToolName,
		Description: "Send the maintenance result to the user with task status and fully detailed report about using the result",
		Parameters:  reflector.Reflect(&TaskResult{}),
	},
	CoderToolName: {
		Name:        CoderToolName,
		Description: "Call to developer team member to write a code for the specific task",
		Parameters:  reflector.Reflect(&CoderAction{}),
	},
	CodeResultToolName: {
		Name:        CodeResultToolName,
		Description: "Send the code result to the user with execution status and fully detailed report about using the result",
		Parameters:  reflector.Reflect(&CodeResult{}),
	},
	PentesterToolName: {
		Name:        PentesterToolName,
		Description: "Call to pentester team member to perform a penetration test or looking for vulnerabilities and weaknesses",
		Parameters:  reflector.Reflect(&PentesterAction{}),
	},
	HackResultToolName: {
		Name:        HackResultToolName,
		Description: "Send the penetration test result to the user with detailed report",
		Parameters:  reflector.Reflect(&HackResult{}),
	},
	AdviceToolName: {
		Name:        AdviceToolName,
		Description: "Get more complex answer from the mentor about some issue or difficult situation",
		Parameters:  reflector.Reflect(&AskAdvice{}),
	},
	AskUserToolName: {
		Name:        AskUserToolName,
		Description: "If you need to ask user for input, use this tool",
		Parameters:  reflector.Reflect(&AskUser{}),
	},
	FinalyToolName: {
		Name:        FinalyToolName,
		Description: "If you need to finish the task with success or failure, use this tool",
		Parameters:  reflector.Reflect(&Done{}),
	},
	GetFlowStatusToolName: {
		Name: GetFlowStatusToolName,
		Description: "Return structured information about the automation flow. " +
			"Choose the detail level based on what you need to know:\n" +
			"  'summary'  — flow health snapshot: status, task counts, subtask counts, active task/subtask IDs. Best first call.\n" +
			"  'tasks'    — all tasks with ID, status, title. Add verbose=true for inputs and results.\n" +
			"  'subtasks' — all subtasks, optionally filtered by task_id. Add verbose=true for descriptions and results.\n" +
			"  'running'  — full Task→Subtask execution chain: task input, subtask description, partial result, and recent agent messages (10 default, 50 with verbose=true). Use when you need to understand what is happening right now.\n" +
			"  'planned'  — subtasks with status 'created' (not yet started), optionally filtered by task_id. Add verbose=true for full descriptions.",
		Parameters: reflector.Reflect(&GetFlowStatusAction{}),
	},
	StopFlowToolName: {
		Name: StopFlowToolName,
		Description: "Cancel the currently executing automation task. " +
			"If a task is actively running its execution context is cancelled; the flow transitions to 'waiting' state and can accept new input or subtask patches. " +
			"If no task is running the tool returns an informational message and takes no further action. " +
			"After calling this tool, verify the flow reached 'waiting' state before making further changes.",
		Parameters: reflector.Reflect(&StopFlowAction{}),
	},
	SubmitFlowInputToolName: {
		Name: SubmitFlowInputToolName,
		Description: "Deliver text to the automation flow. The behaviour depends on the current flow state:\n" +
			"  Subtask at 'ask' checkpoint — the text is delivered as the user's answer and the subtask resumes immediately.\n" +
			"  Flow waiting with no active subtask — the text becomes the goal for a new task; the generator and refiner agents decompose it into a subtask list. Write a complete, detailed description with all context the automation needs.\n" +
			"Returns an error if a task is currently running — cancel the running task first.",
		Parameters: reflector.Reflect(&SubmitFlowInputAction{}),
	},
	PatchFlowSubtasksToolName: {
		Name: PatchFlowSubtasksToolName,
		Description: "Replace the planned (not-yet-started) subtask list for a specific task using delta operations. " +
			"Supported operations: add (insert a new subtask at a position), remove (delete a planned subtask by ID), modify (update title or description), reorder (move to a different position). " +
			"The currently executing or waiting subtask can also be targeted by including its ID in an operation; doing so resets it to 'created' status. " +
			"After patching, submit new input to trigger execution of the updated plan. " +
			"Returns an error if a task is currently running — cancel it first.",
		Parameters: reflector.Reflect(&PatchFlowSubtasksAction{}),
	},
	WaitFlowCompletionToolName: {
		Name: WaitFlowCompletionToolName,
		Description: "Block until the currently running automation task completes (or the timeout expires). " +
			"Use this when you need to wait for the automation to finish before inspecting its results or taking further action. " +
			"Returns immediately with an informational message if no tasks exist or if no task is currently running — " +
			"use " + GetFlowStatusToolName + " first to confirm the flow state before calling this tool. " +
			"On return, always call " + GetFlowStatusToolName + " with detail='summary' to inspect the final status.",
		Parameters: reflector.Reflect(&WaitFlowCompletionAction{}),
	},

	// ------------------------------------------------------------------------
	// Offensive toolkit (Payload Engine v2 + HTTP attack tooling)
	// ------------------------------------------------------------------------

	PayloadEngineToolName: {
		Name: PayloadEngineToolName,
		Description: "Payload Engine v2 — categorized, context-aware payload generation for authorized testing. " +
			"Curated sets for SQLi, XSS, SSRF, SSTI, command injection, path traversal, XXE, NoSQL, LDAP, JWT, " +
			"deserialization, prototype pollution, GraphQL abuse, request smuggling, cache poisoning, auth bypass, " +
			"IDOR and more, with encoding/mutation engines (double-URL, unicode, comment insertion, case randomization) " +
			"for filter and WAF evasion. Use action=categories to discover the catalog, then action=generate to get " +
			"payloads adapted to the injection context (query/json/header/path/xml/cookie). Fire them with raw_http or proxy_intruder.",
		Parameters: reflector.Reflect(&PayloadEngineAction{}),
	},
	RawHTTPToolName: {
		Name: RawHTTPToolName,
		Description: "Raw-socket HTTP client with byte-level wire control (Repeater-style). When 'raw_request' is set it is " +
			"transmitted VERBATIM — no header normalization, no re-chunking — enabling header injection, desync, cache " +
			"deception, HTTP/1.0 downgrade, and CRLF probes that normal HTTP libraries silently defeat. Returns the full " +
			"response with per-phase timing (connect/TTFB/total). Use for single crafted requests; use proxy_intruder for batches.",
		Parameters: reflector.Reflect(&RawHTTPAction{}),
	},
	SmuggleProbeToolName: {
		Name: SmuggleProbeToolName,
		Description: "Runs the HTTP request-smuggling detection suite (CL.TE, TE.CL, TE.TE duplicates/obfuscation, " +
			"Content-Length conflicts) against one target and reports per-variant verdicts with timing-shift and " +
			"marker-reflection analysis. Use when a front-end proxy/CDN sits in front of the target.",
		Parameters: reflector.Reflect(&SmuggleProbeAction{}),
	},
	ProxyStartToolName: {
		Name: ProxyStartToolName,
		Description: "Starts an intercepting HTTP proxy (MITM) for this flow: plain HTTP traffic routed through it is " +
			"captured in full (method, URL, headers, body, response), HTTPS CONNECT tunnels are relayed with host/SNI " +
			"visibility. Supports include/exclude scope regexes. Point flow-container traffic at it via http_proxy, " +
			"then review with proxy_history. It is the interception layer for observing what tools inside the container actually send.",
		Parameters: reflector.Reflect(&ProxyStartAction{}),
	},
	ProxyHistoryToolName: {
		Name: ProxyHistoryToolName,
		Description: "Shows the traffic captured by a running proxy engine (newest first) with optional regex filtering " +
			"over method/host/path/status and bodies — the HTTP history table of the intercepting proxy.",
		Parameters: reflector.Reflect(&ProxyHistoryAction{}),
	},
	ProxyStopToolName: {
		Name:        ProxyStopToolName,
		Description: "Stops a running intercepting proxy engine and discards its history.",
		Parameters:  reflector.Reflect(&ProxyStopAction{}),
	},
	ProxyIntruderToolName: {
		Name: ProxyIntruderToolName,
		Description: "Position-based fuzzing engine (Intruder-style): give a raw request template with §...§ markers " +
			"and payload sets; requests are fired in parallel with configurable attack modes — sniper (each position " +
			"alone), battering_ram (same payload everywhere), pitchfork (parallel sets), cluster_bomb (full cartesian " +
			"product) — and results are sorted by status/length so outliers pop. Payloads can come from payload_engine " +
			"categories (e.g. payload_category=sqli) or explicit lists. Use for login brute force, parameter fuzzing, " +
			"injection probing, endpoint enumeration.",
		Parameters: reflector.Reflect(&ProxyIntruderAction{}),
	},
	DNSEnumToolName: {
		Name: DNSEnumToolName,
		Description: "DNS enumeration: full record sweep (A/AAAA/CNAME/MX/NS/TXT/SOA), subdomain brute force over a " +
			"high-yield built-in wordlist (wildcard-aware), zone transfer (AXFR) attempts against every NS, reverse " +
			"PTR lookups, and SRV service discovery. Run it at the start of recon on any domain-scope target; feed " +
			"discovered hosts into attack_surface and the terminal tools.",
		Parameters: reflector.Reflect(&DNSEnumAction{}),
	},
	ExploitFinderToolName: {
		Name: ExploitFinderToolName,
		Description: "CVE and exploit intelligence: searches NVD for vulnerabilities, then enriches each result with " +
			"FIRST EPSS exploitation probability and CISA KEV known-exploited status (including ransomware campaign use), " +
			"and ranks them by real-world exploitation likelihood. cve=<ID> does a full deep-dive of one CVE. Use it to " +
			"prioritize which vulnerability to attack first; follow up with web_search (mode=exploit) or sploitus for " +
			"public PoC code.",
		Parameters: reflector.Reflect(&ExploitFinderAction{}),
	},
	AttackSurfaceToolName: {
		Name: AttackSurfaceToolName,
		Description: "Attack surface mapper: crawls the target origin (depth/budget controlled), extracts pages, links, " +
			"forms with input names, query parameters and JS-referenced API endpoints, fingerprints technologies from " +
			"headers and body markers, and runs high-signal exposure checks (.git, .env, swagger/openapi, actuator, " +
			"debug endpoints, backup dumps). Produces the endpoint+parameter inventory that drives payload selection.",
		Parameters: reflector.Reflect(&AttackSurfaceAction{}),
	},
	SwarmAttackToolName: {
		Name: SwarmAttackToolName,
		Description: "Parallel attack execution: runs up to 4 shell commands CONCURRENTLY in the flow container " +
			"(recon + fuzzer + scanner + exploiter in one call) and merges their outputs. Design workers around ONE " +
			"objective with disjoint angles. Cuts sequential nmap/ffuf/nuclei chains into a single parallel strike. " +
			"Use whenever the next step has 2+ independent probes.",
		Parameters: reflector.Reflect(&SwarmAttackAction{}),
	},
	ValidateExploitToolName: {
		Name: ValidateExploitToolName,
		Description: "Independent exploit validation — the false-positive killer. Supply the claim, your evidence, and " +
			"probe commands whose success is IMPOSSIBLE unless the vulnerability is real (known-content extraction, " +
			"marker echo through an RCE, canary reads). Probes are repeated N times; the verdict is VERIFIED only on " +
			"reproduced regex-matched proof. ALWAYS validate before reporting any exploitation claim; REFUTED findings " +
			"must not appear in reports.",
		Parameters: reflector.Reflect(&ValidateExploitAction{}),
	},
	TechniqueLedgerToolName: {
		Name: TechniqueLedgerToolName,
		Description: "Persistent technique ledger for this flow — your memory of everything tried and how it went, " +
			"surviving context compaction. record: log every technique attempt (worked/failed/partial/blocked) with " +
			"evidence. recall: search past attempts BEFORE planning the next move. summary: full digest. " +
			"HARD RULE: never repeat a failed or blocked technique without a materially different angle; " +
			"always check recall first and record every attempt after.",
		Parameters: reflector.Reflect(&TechniqueLedgerAction{}),
	},
	WebSessionToolName: {
		Name: WebSessionToolName,
		Description: "Stateful web session: start a cookie-jar session on an origin, login once (form or JSON), and every " +
			"subsequent request carries the session — the foundation for AUTHENTICATED web testing. inspect shows held " +
			"cookies with a security audit (flags, entropy, session detection). Pass the session id to injection_hunt " +
			"for logged-in attack surface. Always test authenticated areas — that is where the real target state lives.",
		Parameters: reflector.Reflect(&WebSessionAction{}),
	},
	InjectionHuntToolName: {
		Name: InjectionHuntToolName,
		Description: "Automated injection hunter: for each parameter it fires the payload category (sqli default; also " +
			"ssti, xss, nosql, cmd_injection...) and classifies responses against a baseline via error signatures " +
			"(MySQL/Postgres/MSSQL/Oracle/SQLite/PHP/Jinja/Twig/...), reflection, boolean differential (true vs false " +
			"payload pairs), and timing. Use attack_surface output as the input list. Feed the session_id for " +
			"authenticated endpoints. Any signal is a foothold candidate — confirm with raw_http and validate_exploit, then escalate.",
		Parameters: reflector.Reflect(&InjectionHuntAction{}),
	},
	AuthAttackToolName: {
		Name: AuthAttackToolName,
		Description: "Authentication attack toolkit: brute (credential attack with built-in or custom lists, password-spray " +
			"mode, lockout detection), jwt_decode (parse + risk analysis), jwt_tamper (alg:none, claim escalation, exp " +
			"removal, kid injection variants ready to replay), cookie_audit (session cookie flags/entropy). " +
			"Default to password spraying (username_static) before full brute; respect lockouts and rotate.",
		Parameters: reflector.Reflect(&AuthAttackAction{}),
	},
	WAFDetectToolName: {
		Name: WAFDetectToolName,
		Description: "WAF/CDN fingerprinting: probes the target with benign + malicious requests and identifies " +
			"Cloudflare, Akamai, Imperva, F5, AWS WAF, ModSecurity, Sucuri and others from response signatures. " +
			"Run BEFORE injection hunts on internet-facing targets; if a WAF is detected, switch to mutation/WAF-evasion " +
			"payloads and the suggested approaches.",
		Parameters: reflector.Reflect(&WAFDetectAction{}),
	},
	GoalManagerToolName: {
		Name: GoalManagerToolName,
		Description: "The autonomous goal-achievement engine. define the goal + observable achievement criteria, queue " +
			"strategies (>=5 across >=3 methodology families), execute, record strategy_result WITH evidence, verify " +
			"criteria, then achieved (proof REQUIRED — the engine refuses unevidenced claims) or blocked (requires >=3 " +
			"dead strategies across >=2 families — no premature surrender). 'next' always returns the next pending " +
			"strategy; 'hint' lists untouched families when you run dry. This is the loop of record for the whole flow: " +
			"every delegation you make should map to a strategy in it.",
		Parameters: reflector.Reflect(&GoalManagerAction{}),
	},
}

func getMessageType(name string) database.MsglogType {
	switch name {
	case TerminalToolName:
		return database.MsglogTypeTerminal
	case FileToolName:
		return database.MsglogTypeFile
	case BrowserToolName:
		return database.MsglogTypeBrowser
	case MemoristToolName, SearchToolName, GoogleToolName, DuckDuckGoToolName, TavilyToolName, FirecrawlToolName,
		TraversaalToolName, PerplexityToolName, SearxngToolName, SploitusToolName, WebSearchToolName,
		SearchGuideToolName, SearchAnswerToolName, SearchCodeToolName, SearchInMemoryToolName, GraphitiSearchToolName:
		return database.MsglogTypeSearch
	case AdviceToolName:
		return database.MsglogTypeAdvice
	case AskUserToolName:
		return database.MsglogTypeAsk
	case FinalyToolName:
		return database.MsglogTypeDone
	default:
		return database.MsglogTypeThoughts
	}
}

func getMessageResultFormat(name string) database.MsglogResultFormat {
	switch name {
	case TerminalToolName:
		return database.MsglogResultFormatTerminal
	case FileToolName, BrowserToolName:
		return database.MsglogResultFormatPlain
	default:
		return database.MsglogResultFormatMarkdown
	}
}

// GetRegistryDefinitions returns tool definitions from the tools package
func GetRegistryDefinitions() map[string]llms.FunctionDefinition {
	registry := make(map[string]llms.FunctionDefinition, len(registryDefinitions))
	maps.Copy(registry, registryDefinitions)
	return registry
}

// GetToolTypeMapping returns a mapping from tool names to tool types
func GetToolTypeMapping() map[string]ToolType {
	mapping := make(map[string]ToolType, len(toolsTypeMapping))
	maps.Copy(mapping, toolsTypeMapping)
	return mapping
}

// GetToolsByType returns a mapping from tool types to a list of tool names
func GetToolsByType() map[ToolType][]string {
	result := make(map[ToolType][]string)

	for toolName, toolType := range toolsTypeMapping {
		result[toolType] = append(result[toolType], toolName)
	}

	return result
}
