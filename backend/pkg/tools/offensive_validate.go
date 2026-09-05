package tools

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// validationVerdict is the outcome of an exploit validation run.
type validationVerdict string

const (
	verdictVerified    validationVerdict = "VERIFIED"
	verdictRefuted     validationVerdict = "REFUTED"
	verdictInconclusive validationVerdict = "INCONCLUSIVE"
)

// handleValidateExploit implements the validate_exploit tool.
//
// Purpose: eliminate false positives BEFORE an agent reports a finding.
// A claim is VERIFIED only when a probe command that cannot succeed on an
// unexploited target produces output matching the caller's success regex —
// repeated `repeat` times. Anything else is REFUTED (claim is wrong) or
// INCONCLUSIVE (probes didn't exercise the claim; design better probes).
func (o *offensiveTools) handleValidateExploit(ctx context.Context, action ValidateExploitAction) (string, error) {
	if o.term == nil {
		return "", fmt.Errorf("validate_exploit requires a flow container (terminal unavailable)")
	}
	claim := strings.TrimSpace(string(action.Claim))
	if claim == "" {
		return "", fmt.Errorf("claim is required")
	}
	probes := action.ProbeCmds
	if len(probes) == 0 {
		return fmt.Sprintf("%s — no probes supplied. INCONCLUSIVE by definition: supply probe_cmds whose success can ONLY follow from the claim being real (an extraction returning known content, a marker echoed through the exploit primitive, a read of a file with known bytes).\n\nclaim: %s\nevidence: %s",
			verdictInconclusive, claim, string(action.Evidence)), nil
	}
	if len(probes) > 5 {
		probes = probes[:5]
	}

	repeat := 1
	if action.Repeat != nil && *action.Repeat > 1 {
		repeat = int(*action.Repeat)
		if repeat > 5 {
			repeat = 5
		}
	}

	var successRe *regexp.Regexp
	if r := strings.TrimSpace(string(action.SuccessRegex)); r != "" {
		var err error
		successRe, err = regexp.Compile(r)
		if err != nil {
			return "", fmt.Errorf("invalid success_regex: %w", err)
		}
	}

	type probeOutcome struct {
		cmd     string
		attempt int
		output  string
		matched bool
		err     error
	}
	var outcomes []probeOutcome
	verified := 0
	refuted := 0

	for _, cmd := range probes {
		cmdStr := string(cmd)
		matches := 0
		var lastOutput string
		var lastErr error
		for attempt := 0; attempt < repeat; attempt++ {
			pctx, cancel := context.WithTimeout(ctx, 60*time.Second)
			out, err := o.term.ExecCommand(pctx, "", cmdStr, false, 60*time.Second)
			cancel()
			lastOutput = out
			lastErr = err
			matched := false
			if err == nil && successRe != nil && successRe.MatchString(out) {
				matched = true
				matches++
			} else if err == nil && successRe == nil && strings.TrimSpace(out) != "" {
				matched = true
				matches++
			}
			outcomes = append(outcomes, probeOutcome{cmd: cmdStr, attempt: attempt + 1, output: out, matched: matched, err: err})
		}
		if matches == repeat && repeat > 0 {
			verified++
		} else if matches == 0 {
			refuted++
		}
		_ = lastOutput
		_ = lastErr
	}

	verdict := verdictInconclusive
	switch {
	case verified > 0:
		verdict = verdictVerified
	case refuted == len(probes):
		verdict = verdictRefuted
	}

	var b strings.Builder
	fmt.Fprintf(&b, "=== validation %s ===\n\nclaim: %s\n\n", verdict, claim)
	fmt.Fprintf(&b, "probes: %d commands x%d attempts — %d fully verified, %d fully empty\n\n", len(probes), repeat, verified, refuted)
	for _, oc := range outcomes {
		status := "NO-MATCH"
		if oc.matched {
			status = "MATCH"
		}
		if oc.err != nil {
			status = "ERR: " + oc.err.Error()
		}
		fmt.Fprintf(&b, "[%s] attempt %d: %s\n", status, oc.attempt, firstLine(oc.cmd))
		if oc.output != "" {
			fmt.Fprintf(&b, "      %s\n", oneLine(strings.TrimSpace(oc.output), 400))
		}
	}

	switch verdict {
	case verdictVerified:
		b.WriteString("\n=> exploit PROVEN with reproduced evidence. Include this probe output in the report. technique_ledger record outcome=worked.\n")
	case verdictRefuted:
		b.WriteString("\n=> claim NOT reproduced: the evidence was a false positive or environment changed. Do NOT report this as a finding — investigate why the probe failed (wrong context? transient? patched?) and try a different angle.\n")
	default:
		b.WriteString("\n=> INCONCLUSIVE: probes did not decisively exercise the claim. Design probes whose success is impossible without the vulnerability (canary extraction, marker echo, known-content read).\n")
	}
	return b.String(), nil
}
