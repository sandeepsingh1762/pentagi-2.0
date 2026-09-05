package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"pentagi/pkg/config"

	"github.com/sirupsen/logrus"
)

// New offensive tool names. These extend the agent toolkit with the
// Payload Engine v2, raw HTTP, MITM proxy (intercept/history/repeater/
// intruder), DNS enumeration, exploit finder, attack surface mapping,
// parallel swarm execution, exploit validation, and the technique ledger.
const (
	PayloadEngineToolName   = "payload_engine"
	RawHTTPToolName         = "raw_http"
	SmuggleProbeToolName    = "smuggle_probe"
	ProxyStartToolName      = "proxy_start"
	ProxyHistoryToolName    = "proxy_history"
	ProxyStopToolName       = "proxy_stop"
	ProxyIntruderToolName   = "proxy_intruder"
	DNSEnumToolName         = "dns_enum"
	ExploitFinderToolName   = "exploit_finder"
	AttackSurfaceToolName   = "attack_surface"
	SwarmAttackToolName     = "swarm_attack"
	ValidateExploitToolName = "validate_exploit"
	TechniqueLedgerToolName = "technique_ledger"
)

// offensiveToolNames lists every tool handled by offensiveTools.Handle.
var offensiveToolNames = []string{
	PayloadEngineToolName,
	RawHTTPToolName,
	SmuggleProbeToolName,
	ProxyStartToolName,
	ProxyHistoryToolName,
	ProxyStopToolName,
	ProxyIntruderToolName,
	DNSEnumToolName,
	ExploitFinderToolName,
	AttackSurfaceToolName,
	SwarmAttackToolName,
	ValidateExploitToolName,
	TechniqueLedgerToolName,
}

// offensiveTools implements the new offensive toolkit. One instance is
// created per executor context (pentester, delegated specialists, primary).
// All network engines run in-process; command execution goes through the
// flow's primary terminal container.
type offensiveTools struct {
	flowID    int64
	taskID    *int64
	subtaskID *int64
	cfg       *config.Config
	term      *terminal

	// technique ledger state (per flow, in-memory + file persisted)
	ledger *techniqueLedger

	// most recently started proxy engine ids per flow
	proxyMu      sync.Mutex
	lastProxyID  int
	proxyEngines map[int]struct{}
}

// NewOffensiveTools wires the offensive toolkit for one executor context.
// The terminal handle must be the concrete *terminal created by
// NewTerminalTool — swarm workers and validation probes execute inside the
// same flow container. Safe for concurrent use.
func NewOffensiveTools(
	flowID int64,
	taskID, subtaskID *int64,
	cfg *config.Config,
	term *terminal,
) Tool {
	return &offensiveTools{
		flowID:       flowID,
		taskID:       taskID,
		subtaskID:    subtaskID,
		cfg:          cfg,
		term:         term,
		ledger:       newTechniqueLedger(flowID, cfg.DataDir),
		proxyEngines: map[int]struct{}{},
	}
}

func (o *offensiveTools) IsAvailable() bool { return true }

// Handle dispatches an offensive tool call.
func (o *offensiveTools) Handle(ctx context.Context, name string, args json.RawMessage) (string, error) {
	if !o.IsAvailable() {
		return "", fmt.Errorf("offensive tools are not available")
	}

	logger := logrus.WithContext(ctx).WithFields(enrichLogrusFields(o.flowID, o.taskID, o.subtaskID, logrus.Fields{
		"tool": name,
		"args": string(args),
	}))

	switch name {
	case PayloadEngineToolName:
		var action PayloadEngineAction
		if err := json.Unmarshal(args, &action); err != nil {
			logger.WithError(err).Error("failed to unmarshal payload_engine action")
			return "", fmt.Errorf("failed to unmarshal payload_engine action: %w", err)
		}
		return o.handlePayloadEngine(ctx, action)

	case RawHTTPToolName:
		var action RawHTTPAction
		if err := json.Unmarshal(args, &action); err != nil {
			logger.WithError(err).Error("failed to unmarshal raw_http action")
			return "", fmt.Errorf("failed to unmarshal raw_http action: %w", err)
		}
		return o.handleRawHTTP(ctx, action)

	case SmuggleProbeToolName:
		var action SmuggleProbeAction
		if err := json.Unmarshal(args, &action); err != nil {
			logger.WithError(err).Error("failed to unmarshal smuggle_probe action")
			return "", fmt.Errorf("failed to unmarshal smuggle_probe action: %w", err)
		}
		return o.handleSmuggleProbe(ctx, action)

	case ProxyStartToolName:
		var action ProxyStartAction
		if err := json.Unmarshal(args, &action); err != nil {
			logger.WithError(err).Error("failed to unmarshal proxy_start action")
			return "", fmt.Errorf("failed to unmarshal proxy_start action: %w", err)
		}
		return o.handleProxyStart(ctx, action)

	case ProxyHistoryToolName:
		var action ProxyHistoryAction
		if err := json.Unmarshal(args, &action); err != nil {
			logger.WithError(err).Error("failed to unmarshal proxy_history action")
			return "", fmt.Errorf("failed to unmarshal proxy_history action: %w", err)
		}
		return o.handleProxyHistory(ctx, action)

	case ProxyStopToolName:
		var action ProxyStopAction
		if err := json.Unmarshal(args, &action); err != nil {
			logger.WithError(err).Error("failed to unmarshal proxy_stop action")
			return "", fmt.Errorf("failed to unmarshal proxy_stop action: %w", err)
		}
		return o.handleProxyStop(ctx, action)

	case ProxyIntruderToolName:
		var action ProxyIntruderAction
		if err := json.Unmarshal(args, &action); err != nil {
			logger.WithError(err).Error("failed to unmarshal proxy_intruder action")
			return "", fmt.Errorf("failed to unmarshal proxy_intruder action: %w", err)
		}
		return o.handleProxyIntruder(ctx, action)

	case DNSEnumToolName:
		var action DNSEnumAction
		if err := json.Unmarshal(args, &action); err != nil {
			logger.WithError(err).Error("failed to unmarshal dns_enum action")
			return "", fmt.Errorf("failed to unmarshal dns_enum action: %w", err)
		}
		return o.handleDNSEnum(ctx, action)

	case ExploitFinderToolName:
		var action ExploitFinderAction
		if err := json.Unmarshal(args, &action); err != nil {
			logger.WithError(err).Error("failed to unmarshal exploit_finder action")
			return "", fmt.Errorf("failed to unmarshal exploit_finder action: %w", err)
		}
		return o.handleExploitFinder(ctx, action)

	case AttackSurfaceToolName:
		var action AttackSurfaceAction
		if err := json.Unmarshal(args, &action); err != nil {
			logger.WithError(err).Error("failed to unmarshal attack_surface action")
			return "", fmt.Errorf("failed to unmarshal attack_surface action: %w", err)
		}
		return o.handleAttackSurface(ctx, action)

	case SwarmAttackToolName:
		var action SwarmAttackAction
		if err := json.Unmarshal(args, &action); err != nil {
			logger.WithError(err).Error("failed to unmarshal swarm_attack action")
			return "", fmt.Errorf("failed to unmarshal swarm_attack action: %w", err)
		}
		return o.handleSwarmAttack(ctx, action)

	case ValidateExploitToolName:
		var action ValidateExploitAction
		if err := json.Unmarshal(args, &action); err != nil {
			logger.WithError(err).Error("failed to unmarshal validate_exploit action")
			return "", fmt.Errorf("failed to unmarshal validate_exploit action: %w", err)
		}
		return o.handleValidateExploit(ctx, action)

	case TechniqueLedgerToolName:
		var action TechniqueLedgerAction
		if err := json.Unmarshal(args, &action); err != nil {
			logger.WithError(err).Error("failed to unmarshal technique_ledger action")
			return "", fmt.Errorf("failed to unmarshal technique_ledger action: %w", err)
		}
		return o.handleTechniqueLedger(ctx, action)

	default:
		return "", fmt.Errorf("unknown offensive tool: %s", name)
	}
}

// SmuggleProbeAction drives the rawhttp smuggling probe suite.
type SmuggleProbeAction struct {
	URL        String `json:"url" jsonschema:"required,type=string" jsonschema_description:"Target base URL (scheme/host/port) to probe for request smuggling."`
	Path       String `json:"path,omitempty" jsonschema:"type=string" jsonschema_description:"Path to target (default /)."`
	Marker     String `json:"marker,omitempty" jsonschema:"type=string" jsonschema_description:"Unique marker embedded in smuggled probes to identify desync responses (default auto-generated)."`
	TimeoutSec *int64 `json:"timeout_sec,omitempty" jsonschema:"type=integer" jsonschema_description:"Per-probe timeout seconds (default 10)."`
	Message    string `json:"message" jsonschema:"required,title=Smuggle probe message" jsonschema_description:"Engagement-log entry — 1-2 short sentences on which endpoint is being probed for desync. Written in the engagement language declared by your system prompt."`
}

// ensure interface compliance with the tools.Tool contract
var _ Tool = (*offensiveTools)(nil)
