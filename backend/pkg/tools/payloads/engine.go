package payloads

import (
	"fmt"
	"sort"
	"strings"
)

// GenerateOptions controls payload generation.
type GenerateOptions struct {
	// Category selects the vulnerability class. Required.
	Category Category

	// Context is where the payload will be placed: query, json, header, path,
	// xml, cookie, form, raw. Controls escaping/wrapping. Defaults to raw.
	Context string

	// Mutation applies a named mutator to every payload (see Mutators()).
	// Optional; empty disables mutation.
	Mutation string

	// WAFEvasion generates additional WAF-evasion variants (comment insertion,
	// case randomization, encoding chains) on top of the base set.
	WAFEvasion bool

	// Limit caps the number of returned payloads. 0 = unlimited.
	Limit int

	// Seed injects a caller-specific fragment into payloads containing the
	// {{SEED}} placeholder (e.g. a unique canary marker for OOB detection).
	Seed string

	// Target allows target-aware payload tuning. Optional, currently used to
	// pick OS-specific command payloads ("windows" or "unix").
	Target string
}

// Generate produces the final payload list: base set -> seed substitution ->
// context adaptation -> optional mutation -> optional WAF-evasion extras ->
// deduplication + limit.
func Generate(opts GenerateOptions) ([]string, error) {
	set, ok := categoryPayloads[opts.Category]
	if !ok {
		return nil, fmt.Errorf("unknown payload category %q; valid categories: %s",
			opts.Category, strings.Join(Categories(), ", "))
	}

	out := make([]string, 0, len(set.base))
	seen := make(map[string]struct{}, len(set.base))
	add := func(p string) {
		if p == "" {
			return
		}
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	for _, p := range set.base {
		p = applySeed(p, opts.Seed)
		p = ForContext(p, opts.Context)
		if opts.Mutation != "" && opts.Mutation != "none" {
			m, err := GetMutator(opts.Mutation)
			if err != nil {
				return nil, err
			}
			p = m.Fn(p)
		}
		add(p)

		if opts.WAFEvasion {
			for _, v := range wafVariants(p) {
				add(v)
			}
		}
	}

	if opts.Limit > 0 && len(out) > opts.Limit {
		out = out[:opts.Limit]
	}
	return out, nil
}

// applySeed replaces the {{SEED}} placeholder with a caller-provided canary.
func applySeed(p, seed string) string {
	if seed == "" {
		return strings.ReplaceAll(p, "{{SEED}}", "seed")
	}
	return strings.ReplaceAll(p, "{{SEED}}", seed)
}

// wafVariants produces encoding-chain variants used to probe filter weaknesses.
func wafVariants(p string) []string {
	variants := make([]string, 0, 4)
	u := mutURLEncode(p)
	if u != p {
		variants = append(variants, u)
	}
	d := mutDoubleURLEncode(p)
	if d != u {
		variants = append(variants, d)
	}
	if c := mutCommentInsert(p); c != p {
		variants = append(variants, c)
	}
	if r := mutCaseRandom(p); r != p {
		variants = append(variants, r)
	}
	return variants
}

// InjectIntoQuery takes a raw URL (or query string) and a payload and returns
// copies with the payload injected into every parameter present in the query.
// Returns (injected []string, params []string).
func InjectIntoQuery(rawURL string, payload string) ([]string, []string) {
	qStart := strings.Index(rawURL, "?")
	if qStart < 0 {
		return nil, nil
	}
	base := rawURL[:qStart]
	query := rawURL[qStart+1:]
	frag := ""
	if i := strings.Index(query, "#"); i >= 0 {
		frag = query[i:]
		query = query[:i]
	}
	pairs := strings.Split(query, "&")
	result := make([]string, 0, len(pairs))
	paramNames := make([]string, 0, len(pairs))
	for _, pair := range pairs {
		if pair == "" {
			continue
		}
		name := pair
		if eq := strings.Index(pair, "="); eq >= 0 {
			name = pair[:eq]
		}
		clone := make([]string, len(pairs))
		for i, p2 := range pairs {
			if i == strings.Index(strings.Join(pairs, "&"), pair) || p2 == pair {
				clone[i] = name + "=" + payload
			} else {
				clone[i] = p2
			}
		}
		result = append(result, base+"?"+strings.Join(clone, "&")+frag)
		paramNames = append(paramNames, name)
	}
	return result, paramNames
}

// InjectIntoJSON injects a payload into every top-level value of a flat JSON
// object string ({"a":"1","b":"2"}) returning one candidate per key.
func InjectIntoJSON(body string, payload string) ([]string, []string) {
	trimmed := strings.TrimSpace(body)
	if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
		return nil, nil
	}
	inner := trimmed[1 : len(trimmed)-1]
	// split on commas that are outside quotes
	var pairs []string
	depthQuote := false
	cur := strings.Builder{}
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch {
		case c == '"' && (i == 0 || inner[i-1] != '\\'):
			depthQuote = !depthQuote
			cur.WriteByte(c)
		case c == ',' && !depthQuote:
			pairs = append(pairs, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		pairs = append(pairs, cur.String())
	}

	var out []string
	var keys []string
	for _, pair := range pairs {
		colon := strings.Index(pair, ":")
		if colon < 0 {
			continue
		}
		key := strings.TrimSpace(pair[:colon])
		val := strings.TrimSpace(pair[colon+1:])
		keys = append(keys, strings.Trim(key, `"`))

		var clone []string
		for _, p2 := range pairs {
			if p2 == pair {
				if val == "" || val[0] == '"' {
					clone = append(clone, key+"\""+jsonEscape(payload)+"\"")
				} else {
					clone = append(clone, key+"\""+jsonEscape(payload)+"\"")
				}
			} else {
				clone = append(clone, p2)
			}
		}
		out = append(out, "{"+strings.Join(clone, ",")+"}")
	}
	return out, keys
}

// IntruderPosition marks a fuzzing position inside a request template,
// mirroring Burp Intruder's §...§ convention.
type IntruderPosition struct {
	Start, End int // byte offsets into the template
	Value      string
}

// intruderMarker is the §...§ position marker. It is a 2-byte UTF-8 sequence,
// so all index arithmetic must use the full marker length.
const intruderMarker = "§"

// ParsePositions extracts §payload§ positions from a raw request template.
// Returned Start/End offsets refer to the CLEAN template (markers removed),
// so substitutions via ExpandAttack stay byte-accurate even when payloads
// contain multi-byte UTF-8.
func ParsePositions(template string) ([]IntruderPosition, string, error) {
	var positions []IntruderPosition
	var clean strings.Builder
	rest := template
	offset := 0
	for {
		start := strings.Index(rest, intruderMarker)
		if start < 0 {
			clean.WriteString(rest)
			break
		}
		bodyStart := start + len(intruderMarker)
		endRel := strings.Index(rest[bodyStart:], intruderMarker)
		if endRel < 0 {
			return nil, "", fmt.Errorf("unbalanced %s position marker at offset %d", intruderMarker, offset+start)
		}
		clean.WriteString(rest[:start])
		clean.WriteString(rest[bodyStart : bodyStart+endRel])
		positions = append(positions, IntruderPosition{
			Start: offset + start,
			End:   offset + start + endRel,
			Value: rest[bodyStart : bodyStart+endRel],
		})
		offset += start + endRel
		rest = rest[bodyStart+endRel+len(intruderMarker):]
	}
	if len(positions) == 0 {
		return nil, "", fmt.Errorf("no %s...%s positions found in template; wrap the part to fuzz like: %sFUZZ%s", intruderMarker, intruderMarker, intruderMarker, intruderMarker)
	}
	return positions, clean.String(), nil
}

// AttackMode names the classic Burp Intruder attack modes.
type AttackMode string

const (
	ModeSniper       AttackMode = "sniper"        // one position at a time
	ModeBatteringRam AttackMode = "battering_ram" // same payload in all positions
	ModePitchfork    AttackMode = "pitchfork"     // parallel payload sets, one item each
	ModeClusterBomb  AttackMode = "cluster_bomb"  // full cartesian product
)

// ParseAttackMode normalizes an attack mode string.
func ParseAttackMode(s string) (AttackMode, error) {
	switch strings.ToLower(strings.TrimSpace(strings.ReplaceAll(s, "-", "_"))) {
	case "", "sniper":
		return ModeSniper, nil
	case "battering_ram", "batteringram", "ram":
		return ModeBatteringRam, nil
	case "pitchfork":
		return ModePitchfork, nil
	case "cluster_bomb", "clusterbomb", "bomb":
		return ModeClusterBomb, nil
	default:
		return "", fmt.Errorf("unknown attack mode %q (want sniper|battering_ram|pitchfork|cluster_bomb)", s)
	}
}

// ExpandAttack builds the request variants for an attack.
// payloadSets[i] corresponds to positions[i] (pitchfork) or is used for every
// position (sniper/battering_ram) or combined (cluster_bomb).
// Returns one raw request wire string per variant.
func ExpandAttack(mode AttackMode, cleanTemplate string, positions []IntruderPosition, payloadSets [][]string, maxRequests int) ([]string, error) {
	replace := func(tpl string, idx int, val string) string {
		pos := positions[idx]
		return tpl[:pos.Start] + val + tpl[pos.End:]
	}

	build := func(assign map[int]string) string {
		out := cleanTemplate
		// replace from last to first so offsets stay valid
		idxs := make([]int, 0, len(assign))
		for i := range assign {
			idxs = append(idxs, i)
		}
		sort.Sort(sort.Reverse(sort.IntSlice(idxs)))
		for _, i := range idxs {
			out = replace(out, i, assign[i])
		}
		return out
	}

	var requests []string
	addReq := func(assign map[int]string) {
		requests = append(requests, build(assign))
	}

	switch mode {
	case ModeSniper:
		for i := range positions {
			for _, p := range payloadSets[0] {
				addReq(map[int]string{i: p})
			}
		}
	case ModeBatteringRam:
		for _, p := range payloadSets[0] {
			assign := map[int]string{}
			for i := range positions {
				assign[i] = p
			}
			addReq(assign)
		}
	case ModePitchfork:
		minLen := len(payloadSets[0])
		for _, set := range payloadSets[1:] {
			if len(set) < minLen {
				minLen = len(set)
			}
		}
		for row := 0; row < minLen; row++ {
			assign := map[int]string{}
			for i := range positions {
				assign[i] = payloadSets[i][row]
			}
			addReq(assign)
		}
	case ModeClusterBomb:
		if len(payloadSets) < len(positions) {
			return nil, fmt.Errorf("cluster_bomb needs one payload set per position")
		}
		idxSizes := make([]int, len(positions))
		total := 1
		for i := range positions {
			idxSizes[i] = len(payloadSets[i])
			total *= idxSizes[i]
			if total > maxRequests {
				break
			}
		}
		if total > maxRequests {
			return nil, fmt.Errorf("cluster_bomb expansion (%d) exceeds max requests (%d); reduce payload sets", total, maxRequests)
		}
		counters := make([]int, len(positions))
		for {
			assign := map[int]string{}
			for i := range positions {
				assign[i] = payloadSets[i][counters[i]]
			}
			addReq(assign)
			carry := true
			for i := len(counters) - 1; i >= 0 && carry; i-- {
				counters[i]++
				if counters[i] < idxSizes[i] {
					carry = false
				} else {
					counters[i] = 0
				}
			}
			if carry {
				break
			}
		}
	}

	if maxRequests > 0 && len(requests) > maxRequests {
		requests = requests[:maxRequests]
	}
	return requests, nil
}
