package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// techniqueLedger is the per-flow memory of tried techniques and their
// outcomes. It exists to fix the two failure modes the compaction pipeline
// cannot: (1) the agent repeating the same failed technique after its context
// was summarized, and (2) the agent never rotating to genuinely different
// attack angles because old attempts dropped out of context.
//
// The ledger is the agent's long-term attempt history for the flow:
//   - record: append one attempt (technique, target, outcome, evidence)
//   - recall: keyword search over past attempts BEFORE choosing a next move
//   - summary: the full digest, injected whenever the agent plans
//
// State lives in memory and is mirrored to <DataDir>/flows/<flowID>/ledger.json
// so it survives process restarts.
type techniqueLedger struct {
	flowID int64
	dir    string

	mu       sync.Mutex
	entries  []ledgerEntry
	nextID   int64
}

type ledgerEntry struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Technique string    `json:"technique"`
	Target    string    `json:"target,omitempty"`
	Outcome   string    `json:"outcome"` // worked | failed | partial | blocked
	Details   string    `json:"details,omitempty"`
}

func newTechniqueLedger(flowID int64, dataDir string) *techniqueLedger {
	dir := filepath.Join(orDefault(dataDir, "./data"), "flows", fmt.Sprintf("%d", flowID))
	l := &techniqueLedger{flowID: flowID, dir: dir}
	l.load()
	return l
}

func (l *techniqueLedger) ledgerFile() string {
	return filepath.Join(l.dir, "ledger.json")
}

func (l *techniqueLedger) load() {
	data, err := os.ReadFile(l.ledgerFile())
	if err != nil {
		return
	}
	var entries []ledgerEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return
	}
	l.entries = entries
	for _, e := range entries {
		if e.ID > l.nextID {
			l.nextID = e.ID
		}
	}
}

func (l *techniqueLedger) persist() {
	if err := os.MkdirAll(l.dir, 0o750); err != nil {
		return
	}
	data, err := json.MarshalIndent(l.entries, "", "  ")
	if err != nil {
		return
	}
	tmp := l.ledgerFile() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, l.ledgerFile())
}

// handleTechniqueLedger implements the technique_ledger tool.
func (o *offensiveTools) handleTechniqueLedger(ctx context.Context, action TechniqueLedgerAction) (string, error) {
	switch string(action.Action) {
	case string(LedgerRecord):
		technique := strings.TrimSpace(string(action.Technique))
		if technique == "" {
			return "", fmt.Errorf("technique is required for action=record")
		}
		outcome := strings.TrimSpace(string(action.Outcome))
		switch outcome {
		case "worked", "failed", "partial", "blocked":
		case "":
			outcome = "failed"
		default:
			return "", fmt.Errorf("outcome must be worked|failed|partial|blocked, got %q", outcome)
		}

		o.ledger.mu.Lock()
		o.ledger.nextID++
		entry := ledgerEntry{
			ID:        o.ledger.nextID,
			Timestamp: time.Now().UTC(),
			Technique: technique,
			Target:    string(action.Target),
			Outcome:   outcome,
			Details:   string(action.Details),
		}
		o.ledger.entries = append(o.ledger.entries, entry)
		o.ledger.persist()
		o.ledger.mu.Unlock()

		stats := o.ledger.stats()
		return fmt.Sprintf("recorded attempt #%d: %s -> %s\nledger: %s", entry.ID, technique, outcome, stats), nil

	case string(LedgerRecall):
		query := strings.ToLower(strings.TrimSpace(string(action.Details)) + " " + strings.ToLower(string(action.Target)))
		o.ledger.mu.Lock()
		defer o.ledger.mu.Unlock()
		if len(o.ledger.entries) == 0 {
			return "ledger is empty — nothing attempted yet in this flow. Plan freely, but record each attempt as you make it.", nil
		}
		var matches []ledgerEntry
		for _, e := range o.ledger.entries {
			if query == "" || strings.Contains(strings.ToLower(e.Technique), query) ||
				strings.Contains(strings.ToLower(e.Target), query) ||
				strings.Contains(strings.ToLower(e.Details), query) {
				matches = append(matches, e)
			}
		}
		if len(matches) == 0 {
			return fmt.Sprintf("no past attempts match %q — this angle is FRESH for this flow. Record it when done.\n\n%s", query, o.ledger.stats()), nil
		}
		var b strings.Builder
		fmt.Fprintf(&b, "past attempts matching %q:\n\n", orDefault(query, "(all)"))
		for _, e := range matches {
			fmt.Fprintf(&b, "#%d [%s] %s (target: %s)\n", e.ID, e.Outcome, e.Technique, orDefault(e.Target, "n/a"))
			if e.Details != "" {
				fmt.Fprintf(&b, "    %s\n", oneLine(e.Details, 200))
			}
		}
		b.WriteString("\nRULE: do not repeat failed/blocked techniques without a materially different angle (different vector, payload class, or entry point). Prefer angles with no prior attempt.\n")
		return b.String(), nil

	case string(LedgerSummary), "":
		o.ledger.mu.Lock()
		defer o.ledger.mu.Unlock()
		if len(o.ledger.entries) == 0 {
			return "ledger is empty — no attempts recorded yet.", nil
		}
		var b strings.Builder
		fmt.Fprintf(&b, "technique ledger: %s\n\n", o.ledger.stats())
		entries := append([]ledgerEntry{}, o.ledger.entries...)
		sort.Slice(entries, func(i, j int) bool { return entries[i].ID > entries[j].ID })
		for _, e := range entries {
			fmt.Fprintf(&b, "#%d [%s] %s -> %s\n", e.ID, e.Timestamp.Format("01-02 15:04"), e.Outcome, e.Technique)
		}
		b.WriteString(`
rotation rules:
  - a FAILED or BLOCKED technique needs a materially different angle before retrying
  - before claiming completion, check: has every discovered endpoint/param seen at least one attempt from each relevant payload category?
  - after any attempt, record it (technique_ledger record) so future-you after compaction still knows
`)
		return b.String(), nil

	default:
		return "", fmt.Errorf("unknown technique_ledger action: %s", action.Action)
	}
}

// stats renders the outcome histogram.
func (l *techniqueLedger) stats() string {
	counts := map[string]int{}
	for _, e := range l.entries {
		counts[e.Outcome]++
	}
	return fmt.Sprintf("%d attempts (%d worked, %d failed, %d partial, %d blocked)",
		len(l.entries), counts["worked"], counts["failed"], counts["partial"], counts["blocked"])
}
