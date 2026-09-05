package goal

import (
	"strings"
	"testing"
)

func TestDefineAndGet(t *testing.T) {
	InitStore(101, t.TempDir())
	g, err := Define(101, "obtain admin access on the target web app", []string{"admin panel reachable", "admin session cookie captured"})
	if err != nil {
		t.Fatal(err)
	}
	if g.Status != "in_progress" || len(g.Criteria) != 2 {
		t.Fatalf("bad state: %+v", g)
	}
	got, err := Get(101)
	if err != nil {
		t.Fatal(err)
	}
	if got.Statement != g.Statement {
		t.Errorf("persistence mismatch")
	}
}

func TestAchieveRequiresEvidence(t *testing.T) {
	InitStore(102, t.TempDir())
	Define(102, "dump the users table", nil)
	if err := Achieve(102, ""); err == nil {
		t.Fatal("empty evidence must be rejected")
	}
	if err := Achieve(102, "sqlmap -D app -T users --dump returned 4,102 rows; head shown in flow log"); err != nil {
		t.Fatalf("evidenced achievement rejected: %v", err)
	}
	g, _ := Get(102)
	if g.Status != "achieved" {
		t.Errorf("status = %s", g.Status)
	}
}

func TestBlockRequiresExhaustion(t *testing.T) {
	InitStore(103, t.TempDir())
	Define(103, "rce on the build server", nil)
	AddStrategy(103, "ssti probe", "injection")
	AddStrategy(103, "cred reuse", "auth-session")
	// one failure — must refuse
	if err := StrategyResult(103, "ssti probe", StatusFailed, "no template reflection"); err != nil {
		t.Fatal(err)
	}
	if err := Block(103, "giving up"); err == nil {
		t.Fatal("block with 1 failed strategy must be refused")
	}
	AddStrategy(103, "default creds jenkins", "auth-session")
	StrategyResult(103, "default creds jenkins", StatusBlocked, "lockout after 3 tries")
	AddStrategy(103, "deserialization gadget", "exploit-chain")
	StrategyResult(103, "deserialization gadget", StatusFailed, "no writable upload path")
	// 3 dead across 2 families — must pass
	if err := Block(103, "all realistic vectors exhausted with evidence"); err != nil {
		t.Fatalf("legitimate block refused: %v", err)
	}
}

func TestStrategyLifecycle(t *testing.T) {
	InitStore(104, t.TempDir())
	Define(104, "read /etc/shadow via web", nil)
	AddStrategy(104, "lfi /etc/shadow", "injection")
	AddStrategy(104, "path traversal", "injection")

	// duplicate add refused
	if err := AddStrategy(104, "lfi /etc/shadow", "injection"); err == nil {
		t.Error("duplicate strategy must be refused")
	}

	// failure requires evidence
	if err := StrategyResult(104, "lfi /etc/shadow", StatusFailed, ""); err == nil {
		t.Error("evidence-less failure must be refused")
	}

	if err := StrategyResult(104, "lfi /etc/shadow", StatusFailed, "filter strips ../ via sanitizer"); err != nil {
		t.Fatal(err)
	}
	// worked strategies are immutable
	StrategyResult(104, "path traversal", StatusRunning, "")
	if err := StrategyResult(104, "path traversal", StatusWorked, "read root:x:0:0 via ....//....// etc shadow bypass"); err != nil {
		t.Fatal(err)
	}
	if err := StrategyResult(104, "path traversal", StatusFailed, "changed my mind"); err == nil {
		t.Error("worked strategy must be immutable")
	}
}

func TestRotationHint(t *testing.T) {
	InitStore(105, t.TempDir())
	Define(105, "compromise the CRM", nil)
	AddStrategy(105, "union sqli", "injection")
	AddStrategy(105, "ssti", "injection")
	StrategyResult(105, "union sqli", StatusFailed, "waf blocks quotes")
	StrategyResult(105, "ssti", StatusBlocked, "template engine not user-facing")

	hint, err := RotationHint(105)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(hint, "UNTOUCHED") {
		t.Fatalf("hint should list untouched families: %s", hint)
	}
	// auth-session is untouched and comes early in the canonical order
	if !strings.Contains(hint, "auth-session") {
		t.Errorf("auth-session should be listed as untouched: %s", hint)
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	InitStore(106, dir)
	Define(106, "pivot to internal network", []string{"internal host reachable"})
	AddStrategy(106, "ssrf to metadata", "injection")

	// fresh store instance reading the same dir
	defaultStore.mu.Lock()
	delete(defaultStore.states, 106)
	defaultStore.mu.Unlock()
	InitStore(106, dir)

	g, err := Get(106)
	if err != nil {
		t.Fatalf("persisted goal not reloaded: %v", err)
	}
	if g.Statement != "pivot to internal network" || len(g.Strategies) != 1 {
		t.Fatalf("reload mismatch: %+v", g)
	}
}
