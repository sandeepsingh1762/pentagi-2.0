package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"pentagi/pkg/tools/goal"
	"pentagi/pkg/tools/webattack"
)

// Web-specialization and goal-loop tool names are declared in offensive.go;
// this file implements their handlers plus small shared helpers.

// lastWebSessionID tracks the flow's most recent web session.
func (o *offensiveTools) lastSession(id *int64) (*webattack.Session, error) {
	if id != nil && *id > 0 {
		return webattack.GetSession(*id)
	}
	o.proxyMu.Lock()
	last := o.lastWebSession
	o.proxyMu.Unlock()
	if last == 0 {
		return nil, fmt.Errorf("no web session for this flow — call %s action=start first", WebSessionToolName)
	}
	return webattack.GetSession(last)
}

// handleWebSession implements web_session.
func (o *offensiveTools) handleWebSession(ctx context.Context, action WebSessionAction) (string, error) {
	switch string(action.Action) {
	case "start":
		base := strings.TrimSpace(string(action.BaseURL))
		if base == "" {
			return "", fmt.Errorf("base_url is required for action=start")
		}
		s, err := webattack.NewSession(o.flowID, base, 15)
		if err != nil {
			return "", err
		}
		o.proxyMu.Lock()
		o.lastWebSession = s.ID
		o.proxyMu.Unlock()
		return fmt.Sprintf("web session %d opened on %s\ncookie jar ready — next: action=login with credentials (or use unauthenticated requests), then action=request for authenticated calls, action=inspect for the cookie audit.", s.ID, s.BaseURL), nil

	case "login":
		s, err := o.lastSession(action.SessionID)
		if err != nil {
			return "", err
		}
		var success *webattack.SuccessRule
		// heuristics + optional explicit body regex from the caller
		res, err := s.Login(ctx, webattack.LoginRequest{
			URL:         string(action.LoginURL),
			Format:      string(action.Format),
			UserField:   string(action.UserField),
			PassField:   string(action.PassField),
			Username:    string(action.Username),
			Password:    string(action.Password),
			ExtraFields: action.ExtraFields,
			Success:     success,
		})
		if err != nil {
			return "", err
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		var b strings.Builder
		b.WriteString(string(out))
		if res.Success {
			fmt.Fprintf(&b, "\n\nsession authenticated (id=%d). Subsequent action=request calls carry the session. Run action=inspect for the cookie audit; feed the session id into injection_hunt for authenticated testing.", s.ID)
		} else {
			b.WriteString("\n\nlogin did not succeed — adjust fields/format or try auth_attack brute against this endpoint.")
		}
		return b.String(), nil

	case "request":
		s, err := o.lastSession(action.SessionID)
		if err != nil {
			return "", err
		}
		ex, err := s.Do(ctx, orDefault(string(action.Method), "GET"), string(action.URL), action.Headers, string(action.Body), false)
		if err != nil {
			return fmt.Sprintf("request failed: %v", err), nil
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%s\n", ex.StatusLine)
		for k, vals := range ex.Headers {
			for _, v := range vals {
				fmt.Fprintf(&b, "%s: %s\n", k, v)
			}
		}
		fmt.Fprintf(&b, "\n%s\n", ex.Body)
		return b.String(), nil

	case "inspect":
		s, err := o.lastSession(action.SessionID)
		if err != nil {
			return "", err
		}
		audits := s.AuditCookies()
		if len(audits) == 0 {
			return "session holds no cookies yet (or not established).", nil
		}
		out, _ := json.MarshalIndent(audits, "", "  ")
		return fmt.Sprintf("session %d cookies (audited):\n%s", s.ID, string(out)), nil

	case "reset":
		s, err := o.lastSession(action.SessionID)
		if err != nil {
			return "", err
		}
		// dropping and recreating gives a clean jar
		base := s.BaseURL
		webattack.DropSession(s.ID)
		ns, err := webattack.NewSession(o.flowID, base, 15)
		if err != nil {
			return "", err
		}
		o.proxyMu.Lock()
		o.lastWebSession = ns.ID
		o.proxyMu.Unlock()
		return fmt.Sprintf("session reset: new session %d on %s (cookies cleared)", ns.ID, base), nil

	default:
		return "", fmt.Errorf("unknown web_session action: %s", action.Action)
	}
}

// handleInjectionHunt implements injection_hunt.
func (o *offensiveTools) handleInjectionHunt(ctx context.Context, action InjectionHuntAction) (string, error) {
	res, err := webattack.Hunt(ctx, webattack.HuntTarget{
		URL:          string(action.URL),
		Method:       string(action.Method),
		Params:       action.Params,
		ParamIn:      string(action.ParamIn),
		Category:     string(action.Category),
		StaticParams: action.StaticParams,
		JSONBody:     action.JSONBody,
		SessionID:    derefInt64(action.SessionID, 0),
		MaxPayloads:  int(derefInt64(action.MaxPayloads, 25)),
		TimeoutSec:   int(derefInt64(action.TimeoutSec, 12)),
	})
	if err != nil {
		return "", err
	}
	out, _ := json.MarshalIndent(res, "", "  ")

	var b strings.Builder
	if len(res.Hits) == 0 {
		fmt.Fprintf(&b, "injection_hunt: NO signals on %d param(s) of %s (category=%s, payloads=%d).\n", res.Params, res.URL, res.Category, res.PayloadsSent)
		b.WriteString("next: try a different category (ssti/nosql/cmd_injection), raise max_payloads, test other params from the attack surface map, or rotate methodology family via technique_ledger recall.\n")
	} else {
		fmt.Fprintf(&b, "injection_hunt: %d SIGNAL(S) on %s (category=%s):\n\n", len(res.Findings), res.URL, res.Category)
		for param, findings := range res.Hits {
			fmt.Fprintf(&b, "param %q:\n", param)
			for _, f := range findings {
				fmt.Fprintf(&b, "  [%s] payload=%s\n           evidence: %s\n", f.Signal, clipStr(f.Payload, 120), clipStr(f.Evidence, 180))
			}
		}
		b.WriteString("\nMANDATORY next steps: 1) replay the strongest payload with raw_http to capture the full response, 2) prove real impact with validate_exploit (known-content extraction / marker echo), 3) technique_ledger record the result, 4) escalate — an error-based hit is a foothold, not a finding to admire.\n")
		b.WriteString("\nfull JSON:\n" + string(out))
	}
	return b.String(), nil
}

// handleAuthAttack implements auth_attack.
func (o *offensiveTools) handleAuthAttack(ctx context.Context, action AuthAttackAction) (string, error) {
	switch string(action.Action) {
	case "brute":
		var success *webattack.SuccessRule
		_ = success
		res, err := webattack.Brute(ctx, webattack.BruteTarget{
			URL:            string(action.URL),
			Format:         string(action.Format),
			UserField:      string(action.UserField),
			PassField:      string(action.PassField),
			UsernameStatic: string(action.UsernameStatic),
			Usernames:      action.Usernames,
			Passwords:      action.Passwords,
			ExtraFields:    action.ExtraFields,
			MaxAttempts:    int(derefInt64(action.MaxAttempts, 200)),
			TimeoutSec:     10,
		})
		if err != nil {
			return "", err
		}
		var b strings.Builder
		if len(res.Found) > 0 {
			fmt.Fprintf(&b, "CREDENTIAL(S) FOUND: %s\n", strings.Join(res.Found, ", "))
			b.WriteString("next: web_session login with the found credentials and continue authenticated.\n")
		} else if res.LockedOut {
			fmt.Fprintf(&b, "LOCKOUT after %d attempts (%s). Stop hammering this endpoint.\n", res.Attempts, res.LockoutHit)
			b.WriteString("next: rotate — try a different vector, note the lockout policy in technique_ledger.\n")
		} else {
			fmt.Fprintf(&b, "no credentials found in %d attempts (errors: %d).\n", res.Attempts, res.Errors)
			b.WriteString("next: try username_static spray with a seasonal list, different endpoint, or move to another family via goal_manager hint.\n")
		}
		return b.String(), nil

	case "jwt_decode":
		a, err := webattack.DecodeJWT(string(action.Token))
		if err != nil {
			return "", err
		}
		out, _ := json.MarshalIndent(a, "", "  ")
		return "JWT analysis:\n" + string(out), nil

	case "jwt_tamper":
		variants, err := webattack.JWTAttackVariants(string(action.Token))
		if err != nil {
			return "", err
		}
		var b strings.Builder
		b.WriteString("tampered JWT variants — replay each against an authenticated endpoint (raw_http with Cookie/Authorization header) and compare against the 401/403 baseline:\n\n")
		for _, v := range variants {
			fmt.Fprintf(&b, "[%s] %s\n  token: %s\n\n", v.Name, v.Note, v.Token)
		}
		b.WriteString("a variant that returns 200 = broken token verification = goal-grade foothold. Validate with validate_exploit and escalate immediately.\n")
		return b.String(), nil

	case "cookie_audit":
		s, err := o.lastSession(action.SessionID)
		if err != nil {
			return "", err
		}
		audits := s.AuditCookies()
		if len(audits) == 0 {
			return "no cookies to audit.", nil
		}
		out, _ := json.MarshalIndent(audits, "", "  ")
		return "cookie audit:\n" + string(out), nil

	default:
		return "", fmt.Errorf("unknown auth_attack action: %s", action.Action)
	}
}

// handleWAFDetect implements waf_detect.
func (o *offensiveTools) handleWAFDetect(ctx context.Context, action WAFDetectAction) (string, error) {
	res, err := webattack.DetectWAF(ctx, string(action.URL), int(derefInt64(action.TimeoutSec, 10)))
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if len(res.Detected) > 0 {
		fmt.Fprintf(&b, "WAF/CDN detected: %s\n", strings.Join(res.Detected, ", "))
	} else {
		b.WriteString("no WAF/CDN signature detected on probes.\n")
	}
	if res.Blocked {
		b.WriteString("probes were actively BLOCKED:\n")
		for _, d := range res.Details {
			b.WriteString("  - " + d + "\n")
		}
	}
	b.WriteString("\nprobe log:\n")
	for _, l := range res.ProbeLog {
		b.WriteString("  " + l + "\n")
	}
	if len(res.Guidance) > 0 {
		b.WriteString("\napproach:\n")
		for _, g := range res.Guidance {
			b.WriteString("  - " + g + "\n")
		}
	}
	return b.String(), nil
}

// handleGoalManager implements goal_manager — the autonomous loop backbone.
func (o *offensiveTools) handleGoalManager(ctx context.Context, action GoalManagerAction) (string, error) {
	goal.InitStore(o.flowID, o.cfg.DataDir)

	switch string(action.Action) {
	case "define":
		g, err := goal.Define(o.flowID, string(action.Goal), action.Criteria)
		if err != nil {
			return "", err
		}
		var b strings.Builder
		fmt.Fprintf(&b, "GOAL SET: %s [in_progress]\n", g.Statement)
		if len(g.Criteria) > 0 {
			b.WriteString("achievement criteria:\n")
			for i, c := range g.Criteria {
				fmt.Fprintf(&b, "  %d. %s\n", i+1, c)
			}
		}
		b.WriteString(`
LOOP (mandatory): add_strategy (>=5 across >=3 families) -> execute each -> strategy_result with evidence -> verify criteria -> achieved (with proof) or next strategy. Use 'next' after every step. Do NOT stop to write reports mid-loop; the loop only ends on achieved or evidence-backed blocked.`)
		return b.String(), nil

	case "add_strategy":
		if err := goal.AddStrategy(o.flowID, string(action.Strategy), string(action.Family)); err != nil {
			return "", err
		}
		hint, _ := goal.RotationHint(o.flowID)
		return fmt.Sprintf("strategy queued: %s [%s]\n\n%s", action.Strategy, orDefault(string(action.Family), "unsorted"), hint), nil

	case "strategy_result":
		status := goal.StrategyStatus(string(action.OutStatus))
		if err := goal.StrategyResult(o.flowID, string(action.Strategy), status, string(action.Evidence)); err != nil {
			return "", err
		}
		hint, _ := goal.RotationHint(o.flowID)
		var verdict string
		switch status {
		case goal.StatusWorked:
			verdict = "strategy WORKED — verify the goal criteria against this evidence; if all criteria are met, close with achieved (include the proof)."
		case goal.StatusFailed:
			verdict = "strategy FAILED — do not retry as-is; take 'next' or queue a materially different angle (different family per 'hint')."
		case goal.StatusBlocked:
			verdict = "strategy BLOCKED by a defensive control — log it, rotate family."
		case goal.StatusRunning:
			verdict = "strategy marked running — execute now and record the outcome."
		}
		return fmt.Sprintf("strategy %s -> %s\n%s\n\n%s", action.Strategy, status, verdict, hint), nil

	case "next":
		ns, err := goal.NextStrategy(o.flowID)
		if err != nil {
			return "", err
		}
		if ns == nil {
			hint, _ := goal.RotationHint(o.flowID)
			return fmt.Sprintf("no pending strategies — generate NEW ones from fresh recon (exploit_finder for the fingerprinted stack, attack_surface deeper crawl, web_search for techniques against this tech) in UNTOUCHED families, then add_strategy.\n\n%s", hint), nil
		}
		return fmt.Sprintf("NEXT STRATEGY [%s]: %s\nexecute it now, then strategy_result with evidence.", orDefault(ns.Family, "unsorted"), ns.Name), nil

	case "status":
		g, err := goal.Get(o.flowID)
		if err != nil {
			return "", err
		}
		var b strings.Builder
		fmt.Fprintf(&b, "GOAL [%s]: %s\n\nachievement criteria:\n", g.Status, g.Statement)
		for i, c := range g.Criteria {
			fmt.Fprintf(&b, "  %d. %s\n", i+1, c)
		}
		b.WriteString("\nstrategies:\n")
		for _, s := range g.Strategies {
			fmt.Fprintf(&b, "  [%s] %s", s.Status, s.Name)
			if s.Evidence != "" {
				fmt.Fprintf(&b, " — %s", clipStr(s.Evidence, 140))
			}
			b.WriteString("\n")
		}
		if g.Status == "achieved" {
			fmt.Fprintf(&b, "\nACHIEVED — evidence: %s\n", g.Evidence)
		}
		return b.String(), nil

	case "hint":
		hint, err := goal.RotationHint(o.flowID)
		if err != nil {
			return "", err
		}
		return hint, nil

	case "achieved":
		if err := goal.Achieve(o.flowID, string(action.Evidence)); err != nil {
			return "", err
		}
		return fmt.Sprintf("GOAL ACHIEVED and recorded with evidence:\n%s\n\nclosing is now legitimate — hand the proof upstream (report_result/done) with the evidence verbatim.", action.Evidence), nil

	case "blocked":
		if err := goal.Block(o.flowID, string(action.Evidence)); err != nil {
			return "", err
		}
		g, _ := goal.Get(o.flowID)
		return fmt.Sprintf("goal BLOCKED with exhaustion proof (%d strategies). Reason: %s\nclose upstream with the full strategy history.", len(g.Strategies), action.Evidence), nil

	default:
		return "", fmt.Errorf("unknown goal_manager action: %s", action.Action)
	}
}

func clipStr(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
