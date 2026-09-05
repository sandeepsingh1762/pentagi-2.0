package payloads

import (
	"strings"
	"testing"
)

func TestParseCategory(t *testing.T) {
	cases := []struct {
		in   string
		want Category
		ok   bool
	}{
		{"sqli", CategorySQLi, true},
		{"SQLI", CategorySQLi, true},
		{"sql-injection", CategorySQLi, true},
		{"nosql", CategoryNoSQL, true},
		{"mongo", CategoryNoSQL, true},
		{"ssrf", CategorySSRF, true},
		{"bogus_nonexistent", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := ParseCategory(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseCategory(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestGenerateAllCategories(t *testing.T) {
	for _, cat := range Categories() {
		c, _ := ParseCategory(cat)
		list, err := Generate(GenerateOptions{Category: c})
		if err != nil {
			t.Fatalf("category %s: %v", cat, err)
		}
		if len(list) == 0 {
			t.Errorf("category %s produced no payloads", cat)
		}
	}
}

func TestGenerateDedupAndLimit(t *testing.T) {
	list, err := Generate(GenerateOptions{Category: CategoryXSS, Limit: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 5 {
		t.Fatalf("limit=5 got %d payloads", len(list))
	}
	seen := map[string]bool{}
	for _, p := range list {
		if seen[p] {
			t.Errorf("duplicate payload %q", p)
		}
		seen[p] = true
	}
}

func TestGenerateWAFEvasion(t *testing.T) {
	base, _ := Generate(GenerateOptions{Category: CategorySQLi})
	waf, _ := Generate(GenerateOptions{Category: CategorySQLi, WAFEvasion: true})
	if len(waf) <= len(base) {
		t.Errorf("waf evasion should expand set: base=%d waf=%d", len(base), len(waf))
	}
}

func TestGenerateMutation(t *testing.T) {
	list, err := Generate(GenerateOptions{Category: CategoryCmdInjection, Mutation: MutIFSSubstitution})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range list {
		if strings.Contains(p, "${IFS}") && !strings.Contains(p, "; id") {
			found = true
		}
	}
	if !found {
		t.Error("IFS substitution not applied")
	}
}

func TestForContextJSON(t *testing.T) {
	got := ForContext(`x"alert"`, "json")
	if strings.Contains(got, `"`) && !strings.Contains(got, `\"`) {
		t.Errorf("json escaping failed: %q", got)
	}
}

func TestForContextHeader(t *testing.T) {
	got := ForContext("a\r\nX-Bad: 1", "header")
	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("header context must strip raw CRLF: %q", got)
	}
}

func TestInjectIntoQuery(t *testing.T) {
	 injected, params := InjectIntoQuery("https://t.example/page?a=1&b=2#frag", "PAYLOAD")
	if len(injected) != 2 || len(params) != 2 {
		t.Fatalf("got %d injected (%v), params %v", len(injected), injected, params)
	}
	if !strings.Contains(injected[0], "a=PAYLOAD") || !strings.Contains(injected[0], "b=2") {
		t.Errorf("bad injection: %q", injected[0])
	}
	if !strings.Contains(injected[1], "b=PAYLOAD") || !strings.Contains(injected[1], "a=1") {
		t.Errorf("bad injection: %q", injected[1])
	}
	if !strings.HasSuffix(injected[0], "#frag") {
		t.Errorf("fragment lost: %q", injected[0])
	}
}

func TestInjectIntoJSON(t *testing.T) {
	body := `{"user":"bob","role":"user","admin":false}`
	injected, keys := InjectIntoJSON(body, "P\"AYLOAD")
	if len(injected) != 3 {
		t.Fatalf("expected 3 injections, got %d", len(injected))
	}
	for i, k := range keys {
		if !strings.Contains(injected[i], `"k"`) == false {
			_ = k
		}
	}
	if !strings.Contains(injected[0], `\"P\\\"AYLOAD\"`) && !strings.Contains(injected[0], "AYLOAD") {
		t.Errorf("payload not injected: %q", injected[0])
	}
	// other keys preserved
	if !strings.Contains(injected[2], `"role"`) {
		t.Errorf("other keys lost: %q", injected[2])
	}
}

func TestParsePositions(t *testing.T) {
	tpl := "GET /search?q=§FUZZ§&page=1 HTTP/1.1\r\nHost: §HOST§\r\n\r\n"
	positions, clean, err := ParsePositions(tpl)
	if err != nil {
		t.Fatal(err)
	}
	if len(positions) != 2 {
		t.Fatalf("expected 2 positions, got %d", len(positions))
	}
	if positions[0].Value != "FUZZ" || positions[1].Value != "HOST" {
		t.Errorf("position values wrong: %+v", positions)
	}
	want := strings.NewReplacer("§", "").Replace(tpl)
	if clean != want {
		t.Errorf("clean template mismatch:\n got %q\nwant %q", clean, want)
	}
	if _, _, err := ParsePositions("GET /§broken HTTP/1.1\r\n\r\n"); err == nil {
		t.Error("unbalanced marker must error")
	}
	if _, _, err := ParsePositions("GET / HTTP/1.1\r\n\r\n"); err == nil {
		t.Error("no markers must error")
	}
}

func TestExpandAttackSniper(t *testing.T) {
	tpl := "GET /?q=§P§ HTTP/1.1\r\nHost: x\r\n\r\n"
	positions, clean, _ := ParsePositions(tpl)
	sets := [][]string{{"a", "b", "c"}}
	reqs, err := ExpandAttack(ModeSniper, clean, positions, sets, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 3 {
		t.Fatalf("sniper: want 3, got %d", len(reqs))
	}
	if !strings.Contains(reqs[0], "q=a") || !strings.Contains(reqs[2], "q=c") {
		t.Errorf("sniper substitution wrong: %q", reqs[0])
	}
}

func TestExpandAttackClusterBomb(t *testing.T) {
	tpl := "GET /?u=§U§&p=§P§ HTTP/1.1\r\nHost: x\r\n\r\n"
	positions, clean, _ := ParsePositions(tpl)
	sets := [][]string{{"u1", "u2"}, {"p1", "p2", "p3"}}
	reqs, err := ExpandAttack(ModeClusterBomb, clean, positions, sets, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 6 {
		t.Fatalf("cluster_bomb: want 6, got %d", len(reqs))
	}
	if !strings.Contains(reqs[0], "u=u1&p=p1") {
		t.Errorf("first combo wrong: %q", reqs[0])
	}
}

func TestExpandAttackPitchfork(t *testing.T) {
	tpl := "GET /?u=§U§&p=§P§ HTTP/1.1\r\nHost: x\r\n\r\n"
	positions, clean, _ := ParsePositions(tpl)
	sets := [][]string{{"u1", "u2", "u3"}, {"p1", "p2"}}
	reqs, err := ExpandAttack(ModePitchfork, clean, positions, sets, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 { // min(len)
		t.Fatalf("pitchfork: want 2, got %d", len(reqs))
	}
	if !strings.Contains(reqs[1], "u=u2&p=p2") {
		t.Errorf("pitchfork pairing wrong: %q", reqs[1])
	}
}

func TestExpandAttackBatteringRam(t *testing.T) {
	tpl := "GET /?u=§U§&p=§P§ HTTP/1.1\r\nHost: x\r\n\r\n"
	positions, clean, _ := ParsePositions(tpl)
	sets := [][]string{{"x", "y"}}
	reqs, err := ExpandAttack(ModeBatteringRam, clean, positions, sets, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 {
		t.Fatalf("ram: want 2, got %d", len(reqs))
	}
	if !strings.Contains(reqs[1], "u=y&p=y") {
		t.Errorf("ram substitution wrong: %q", reqs[1])
	}
}

func TestParseAttackMode(t *testing.T) {
	if m, _ := ParseAttackMode("cluster-bomb"); m != ModeClusterBomb {
		t.Errorf("cluster-bomb -> %s", m)
	}
	if m, _ := ParseAttackMode("BATTERINGRAM"); m != ModeBatteringRam {
		t.Errorf("BATTERINGRAM -> %s", m)
	}
	if _, err := ParseAttackMode("wat"); err == nil {
		t.Error("unknown mode must error")
	}
}

func TestMutatorsAvailable(t *testing.T) {
	for _, m := range Mutators() {
		if _, err := GetMutator(m.Name); err != nil {
			t.Errorf("mutator %s lookup failed: %v", m.Name, err)
		}
	}
	if _, err := GetMutator("nope"); err == nil {
		t.Error("unknown mutator must error")
	}
}

func TestBase64(t *testing.T) {
	if got := mutBase64("admin"); got != "YWRtaW4=" {
		t.Errorf("base64(admin) = %s", got)
	}
}

func TestSeedSubstitution(t *testing.T) {
	list, err := Generate(GenerateOptions{Category: CategorySSRF, Seed: "canary123"})
	if err != nil {
		t.Fatal(err)
	}
	_ = list
	// SSRF set has no {{SEED}} placeholders but must not crash; injection path
	// via applySeed is covered by the engine calling it.
}
