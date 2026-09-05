// Package goal implements the autonomous goal-achievement engine: a
// per-flow, persistent record of the objective, its achievement criteria,
// the strategy queue, and per-strategy evidence. It exists to make the agent
// truly goal-driven: strategies are enumerated up-front, executed in order,
// marked with evidence on completion, and rotated across methodology
// families until the criteria are demonstrably met.
package goal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// StrategyStatus is the lifecycle of one strategy.
type StrategyStatus string

const (
	StatusPending StrategyStatus = "pending"
	StatusRunning StrategyStatus = "running"
	StatusWorked  StrategyStatus = "worked"
	StatusFailed  StrategyStatus = "failed"
	StatusBlocked StrategyStatus = "blocked"
)

// StrategyFamilies are the methodology families used for rotation discipline.
var StrategyFamilies = []string{
	"injection", "auth-session", "business-logic", "infrastructure",
	"client-side", "protocol", "recon", "exploit-chain", "social-engineering-assets",
}

// GoalState is the full goal record for one flow.
type GoalState struct {
	Statement  string     `json:"statement"`
	Criteria   []string   `json:"criteria"`
	Status     string     `json:"status"` // in_progress | achieved | blocked
	Evidence   string     `json:"evidence,omitempty"`
	Strategies []Strategy `json:"strategies"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// Strategy is one planned approach toward the goal.
type Strategy struct {
	Name      string         `json:"name"`
	Family    string         `json:"family,omitempty"`
	Status    StrategyStatus `json:"status"`
	Evidence  string         `json:"evidence,omitempty"`
	UpdatedAt time.Time      `json:"updated_at,omitempty"`
}

type store struct {
	mu     sync.Mutex
	dirs   map[int64]string
	states map[int64]*GoalState
}

var defaultStore = &store{
	dirs:   map[int64]string{},
	states: map[int64]*GoalState{},
}

// InitStore points a flow at its persistence directory (call once per flow).
func InitStore(flowID int64, dataDir string) {
	dir := filepath.Join(orDefault(dataDir, "./data"), "flows", fmt.Sprintf("%d", flowID))
	defaultStore.mu.Lock()
	defaultStore.dirs[flowID] = dir
	if _, ok := defaultStore.states[flowID]; !ok {
		if g := loadFromFile(goalFile(dir)); g != nil {
			defaultStore.states[flowID] = g
		}
	}
	defaultStore.mu.Unlock()
}

func goalFile(dir string) string { return filepath.Join(dir, "goal.json") }

func loadFromFile(path string) *GoalState {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var g GoalState
	if json.Unmarshal(data, &g) != nil {
		return nil
	}
	return &g
}

func (g *GoalState) persist(dir string) {
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return
	}
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return
	}
	tmp := goalFile(dir) + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, goalFile(dir))
	}
}

func (s *store) with(flowID int64, fn func(*GoalState, string) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.states[flowID]
	if !ok {
		return fmt.Errorf("no goal defined for flow %d — call goal_manager action=define first", flowID)
	}
	if err := fn(g, s.dirs[flowID]); err != nil {
		return err
	}
	g.UpdatedAt = time.Now().UTC()
	g.persist(s.dirs[flowID])
	return nil
}

// Define sets the goal and its achievement criteria. Re-defining resets
// strategies only when the statement changes.
func Define(flowID int64, statement string, criteria []string) (*GoalState, error) {
	statement = strings.TrimSpace(statement)
	if statement == "" {
		return nil, fmt.Errorf("goal statement is required")
	}
	var clean []string
	for _, c := range criteria {
		if c = strings.TrimSpace(c); c != "" {
			clean = append(clean, c)
		}
	}
	defaultStore.mu.Lock()
	defer defaultStore.mu.Unlock()
	if existing, ok := defaultStore.states[flowID]; ok && existing.Statement == statement {
		if len(clean) > 0 {
			existing.Criteria = clean
		}
		existing.UpdatedAt = time.Now().UTC()
		existing.persist(defaultStore.dirs[flowID])
		return existing, nil
	}
	g := &GoalState{
		Statement:  statement,
		Criteria:   clean,
		Status:     "in_progress",
		Strategies: []Strategy{},
		CreatedAt:  time.Now().UTC(),
		UpdatedAt:  time.Now().UTC(),
	}
	defaultStore.states[flowID] = g
	g.persist(defaultStore.dirs[flowID])
	return g, nil
}

// AddStrategy appends one planned approach.
func AddStrategy(flowID int64, name, family string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("strategy name is required")
	}
	return defaultStore.with(flowID, func(g *GoalState, _ string) error {
		if g.Status == "achieved" {
			return fmt.Errorf("goal already achieved — define a new goal for further work")
		}
		for _, s := range g.Strategies {
			if strings.EqualFold(s.Name, name) {
				return fmt.Errorf("strategy %q already exists (status %s)", name, s.Status)
			}
		}
		g.Strategies = append(g.Strategies, Strategy{
			Name:     name,
			Family:   family,
			Status:   StatusPending,
			UpdatedAt: time.Now().UTC(),
		})
		return nil
	})
}

// StrategyResult records the outcome of one strategy attempt. Failed and
// blocked strategies REQUIRE evidence describing why.
func StrategyResult(flowID int64, name string, status StrategyStatus, evidence string) error {
	name = strings.TrimSpace(name)
	switch status {
	case StatusWorked, StatusFailed, StatusBlocked, StatusRunning:
	case "":
		return fmt.Errorf("status is required (worked|failed|blocked|running)")
	default:
		return fmt.Errorf("invalid strategy status %q", status)
	}
	evidence = strings.TrimSpace(evidence)
	return defaultStore.with(flowID, func(g *GoalState, _ string) error {
		for i := range g.Strategies {
			if strings.EqualFold(g.Strategies[i].Name, name) {
				if g.Strategies[i].Status == StatusWorked {
					return fmt.Errorf("strategy %q already WORKED — evidence recorded", name)
				}
				if status != StatusRunning && evidence == "" {
					return fmt.Errorf("evidence is required when marking a strategy %s (what happened? what output?)", status)
				}
				g.Strategies[i].Status = status
				g.Strategies[i].Evidence = evidence
				g.Strategies[i].UpdatedAt = time.Now().UTC()
				return nil
			}
		}
		return fmt.Errorf("strategy %q not found — add it first", name)
	})
}

// Achieve marks the goal achieved. It refuses to record achievement without
// non-empty evidence.
func Achieve(flowID int64, evidence string) error {
	evidence = strings.TrimSpace(evidence)
	if evidence == "" {
		return fmt.Errorf("evidence is mandatory: describe the PROOF the goal was achieved (commands + key output). The system refuses unevidenced achievement claims")
	}
	return defaultStore.with(flowID, func(g *GoalState, _ string) error {
		g.Status = "achieved"
		g.Evidence = evidence
		return nil
	})
}

// Block marks the goal blocked; it requires at least three distinct FAILED
// or BLOCKED strategies as exhaustion proof.
func Block(flowID int64, reason string) error {
	reason = strings.TrimSpace(reason)
	return defaultStore.with(flowID, func(g *GoalState, _ string) error {
		dead := 0
		families := map[string]bool{}
		for _, s := range g.Strategies {
			if s.Status == StatusFailed || s.Status == StatusBlocked {
				dead++
				if s.Family != "" {
					families[s.Family] = true
				}
			}
		}
		if dead < 3 || len(families) < 2 {
			return fmt.Errorf("cannot mark blocked: only %d dead strategies across %d families. Blocking requires >=3 failed/blocked strategies across >=2 methodology families — rotate to a fresh family first", dead, len(families))
		}
		g.Status = "blocked"
		g.Evidence = reason
		return nil
	})
}

// Get returns the current goal state.
func Get(flowID int64) (*GoalState, error) {
	defaultStore.mu.Lock()
	defer defaultStore.mu.Unlock()
	g, ok := defaultStore.states[flowID]
	if !ok {
		return nil, fmt.Errorf("no goal defined for flow %d — call goal_manager action=define first", flowID)
	}
	return g, nil
}

// NextStrategy returns the highest-priority pending strategy.
func NextStrategy(flowID int64) (*Strategy, error) {
	g, err := Get(flowID)
	if err != nil {
		return nil, err
	}
	for i := range g.Strategies {
		if g.Strategies[i].Status == StatusPending {
			return &g.Strategies[i], nil
		}
	}
	return nil, nil
}

// RotationHint analyzes tried families vs untried families and suggests the
// least-explored methodology family plus counts.
func RotationHint(flowID int64) (string, error) {
	g, err := Get(flowID)
	if err != nil {
		return "", err
	}
	triedByFamily := map[string]int{}
	var pending []string
	for _, s := range g.Strategies {
		switch s.Status {
		case StatusWorked:
			triedByFamily[orDefault(s.Family, "unsorted")]++
		case StatusFailed, StatusBlocked:
			triedByFamily[orDefault(s.Family, "unsorted")]++
		case StatusPending:
			pending = append(pending, s.Name)
		}
	}
	var untried []string
	for _, f := range StrategyFamilies {
		if triedByFamily[f] == 0 {
			untried = append(untried, f)
		}
	}
	sort.Strings(untried)

	var b strings.Builder
	fmt.Fprintf(&b, "goal: %s [status=%s]\n", g.Statement, g.Status)
	fmt.Fprintf(&b, "strategies: %d total | worked=%d failed/blocked=%d pending=%d\n",
		len(g.Strategies), countStatus(g, StatusWorked), countStatus(g, StatusFailed)+countStatus(g, StatusBlocked), len(pending))
	if len(pending) > 0 {
		fmt.Fprintf(&b, "next pending: %s\n", pending[0])
	}
	if len(untried) > 0 {
		fmt.Fprintf(&b, "UNTOUCHED families (generate strategies here): %s\n", strings.Join(untried, ", "))
	} else {
		fmt.Fprintf(&b, "all families touched — go DEEPER on the least-tried family or stack combinations (e.g. foothold from family X + privesc from family Y)\n")
	}
	return b.String(), nil
}

func countStatus(g *GoalState, s StrategyStatus) int {
	n := 0
	for _, st := range g.Strategies {
		if st.Status == s {
			n++
		}
	}
	return n
}

func orDefault(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}
