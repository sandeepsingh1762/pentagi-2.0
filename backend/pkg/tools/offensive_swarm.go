package tools

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// maxSwarmWorkers bounds parallel command workers per swarm_attack call.
const maxSwarmWorkers = 4

// handleSwarmAttack implements the swarm_attack tool: runs up to
// maxSwarmWorkers shell commands CONCURRENTLY inside the flow container and
// merges their outputs. This gives agents real parallelism — recon + fuzzing +
// scanning + exploit search in one round-trip instead of four sequential
// terminal calls.
func (o *offensiveTools) handleSwarmAttack(ctx context.Context, action SwarmAttackAction) (string, error) {
	if o.term == nil {
		return "", fmt.Errorf("swarm_attack requires a flow container (terminal unavailable)")
	}
	if len(action.Workers) == 0 {
		return "", fmt.Errorf("at least one worker is required")
	}
	workers := action.Workers
	if len(workers) > maxSwarmWorkers {
		workers = workers[:maxSwarmWorkers]
	}

	type workerResult struct {
		index  int
		role   string
		cmd    string
		output string
		dur    time.Duration
		err    error
	}

	results := make([]workerResult, len(workers))
	var wg sync.WaitGroup

	for i, w := range workers {
		wg.Add(1)
		go func(idx int, w SwarmWorker) {
			defer wg.Done()
			timeout := 300 * time.Second
			if w.TimeoutSec != nil && *w.TimeoutSec > 0 {
				timeout = time.Duration(*w.TimeoutSec) * time.Second
				if timeout > 30*time.Minute {
					timeout = 30 * time.Minute
				}
			}
			role := orDefault(string(w.Role), fmt.Sprintf("worker-%d", idx+1))

			wctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			start := time.Now()
			out, err := o.term.ExecCommand(wctx, "", string(w.Command), false, timeout)
			results[idx] = workerResult{
				index:  idx,
				role:   role,
				cmd:    string(w.Command),
				output: out,
				dur:    time.Since(start),
				err:    err,
			}
		}(i, w)
	}
	wg.Wait()

	var b strings.Builder
	fmt.Fprintf(&b, "swarm_attack: %d workers executed in parallel\n\n", len(results))
	for _, r := range results {
		status := "ok"
		if r.err != nil {
			if ctx.Err() != nil {
				status = "cancelled"
			} else if strings.Contains(fmt.Sprint(r.err), "signal: killed") || strings.Contains(fmt.Sprint(r.err), "context deadline exceeded") {
				status = "timeout"
			} else {
				status = "error: " + r.err.Error()
			}
		}
		fmt.Fprintf(&b, "━━━ [%s] %s (%.1fs, %s) ━━━\n", r.role, firstLine(r.cmd), r.dur.Seconds(), status)
		out := strings.TrimSpace(r.output)
		if out == "" {
			out = "(no output)"
		}
		// keep each worker's output bounded so 4 workers cannot flood context
		fmt.Fprintf(&b, "%s\n\n", truncateOutput(out, 4000))
	}

	b.WriteString("merge analysis: compare worker outputs for overlapping targets, then chain the strongest leads (delegation or follow-up swarm). Record outcomes with technique_ledger.\n")
	return b.String(), nil
}

// truncateOutput keeps the head and tail of long outputs (most signal at both ends).
func truncateOutput(s string, max int) string {
	if len(s) <= max {
		return s
	}
	head := max * 2 / 3
	tail := max - head
	return s[:head] + "\n…(middle truncated)…\n" + s[len(s)-tail:]
}
