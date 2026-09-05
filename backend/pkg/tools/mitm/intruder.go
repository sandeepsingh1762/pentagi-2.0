package mitm

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"pentagi/pkg/tools/payloads"
	"pentagi/pkg/tools/rawhttp"
)

// IntruderAttack is one configured fuzzing run summary.
type IntruderAttack struct {
	ID        int64     `json:"id"`
	Target    string    `json:"target"`  // full URL (used for dialing)
	RawTPL    string    `json:"raw_tpl"` // template with §positions§
	Mode      string    `json:"mode"`    // sniper|battering_ram|pitchfork|cluster_bomb
	Requests  int       `json:"requests"`
	StartedAt time.Time `json:"started_at"`
	Errors    []string  `json:"errors,omitempty"`
}

// IntruderResult is a single fuzz request outcome.
type IntruderResult struct {
	Index      int    `json:"index"`
	Request    string `json:"request"`
	StatusCode int    `json:"status_code"`
	Length     int    `json:"length"`
	TTFBms     int64  `json:"ttfb_ms"`
	StatusLine string `json:"status_line"`
	Snippet    string `json:"snippet"`
}

// IntruderOptions tunes an attack.
type IntruderOptions struct {
	// AttackMode: sniper, battering_ram, pitchfork, cluster_bomb (default sniper).
	AttackMode string
	// PayloadSets: one list per §position§ for pitchfork/cluster_bomb; the first
	// list is used for all positions in sniper/battering_ram. If empty, the
	// payload engine category (PayloadCategory) fills the set.
	PayloadSets [][]string
	// PayloadCategory: a payloads engine category used when PayloadSets is empty.
	PayloadCategory string
	// MaxRequests hard cap (default 200, hard max 2000).
	MaxRequests int
	// Concurrency parallel workers (default 5, max 20).
	Concurrency int
	// TimeoutSec per request (default 10).
	TimeoutSec int
	// FilterRegex keeps only responses matching (status+body haystack).
	FilterRegex string
	// FilterStatus keeps only these status codes (comma list, e.g. "200,500").
	FilterStatus string
}

// RunIntruder executes a Burp-style fuzzing attack against a target URL with a
// raw request template containing §...§ positions. Results are filtered as
// requested and sorted by status then length — the classic Intruder table
// ordering used to spot outliers.
func RunIntruder(ctx context.Context, target, rawTemplate string, opts IntruderOptions) (*IntruderAttack, []IntruderResult) {
	attack := &IntruderAttack{
		Target:    target,
		RawTPL:    rawTemplate,
		StartedAt: time.Now(),
	}

	mode, err := payloads.ParseAttackMode(opts.AttackMode)
	if err != nil {
		attack.Errors = append(attack.Errors, err.Error())
		mode = payloads.ModeSniper
	}
	attack.Mode = string(mode)

	maxReq := opts.MaxRequests
	if maxReq <= 0 {
		maxReq = 200
	}
	if maxReq > 2000 {
		maxReq = 2000
	}

	positions, clean, err := payloads.ParsePositions(rawTemplate)
	if err != nil {
		attack.Errors = append(attack.Errors, err.Error())
		return attack, nil
	}

	// resolve payload sets
	sets := opts.PayloadSets
	if len(sets) == 0 || sets[0] == nil {
		cat, ok := payloads.ParseCategory(opts.PayloadCategory)
		if !ok {
			attack.Errors = append(attack.Errors, fmt.Sprintf("no payload sets and unknown payload category %q", opts.PayloadCategory))
			return attack, nil
		}
		list, err := payloads.Generate(payloads.GenerateOptions{Category: cat, Limit: maxReq})
		if err != nil {
			attack.Errors = append(attack.Errors, err.Error())
			return attack, nil
		}
		sets = [][]string{list}
	}
	// normalize set count to position count (repeat last set)
	for len(sets) < len(positions) {
		sets = append(sets, sets[len(sets)-1])
	}

	requests, err := payloads.ExpandAttack(mode, clean, positions, sets, maxReq)
	if err != nil {
		attack.Errors = append(attack.Errors, err.Error())
		return attack, nil
	}
	attack.Requests = len(requests)

	conc := opts.Concurrency
	if conc <= 0 {
		conc = 5
	}
	if conc > 20 {
		conc = 20
	}
	timeout := opts.TimeoutSec
	if timeout <= 0 {
		timeout = 10
	}

	var filterRe *regexp.Regexp
	if opts.FilterRegex != "" {
		filterRe, _ = regexp.Compile("(?i)" + opts.FilterRegex)
	}
	statusFilter := map[int]bool{}
	if opts.FilterStatus != "" {
		for _, s := range strings.Split(opts.FilterStatus, ",") {
			var code int
			if _, err := fmt.Sscanf(strings.TrimSpace(s), "%d", &code); err == nil {
				statusFilter[code] = true
			}
		}
	}

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []IntruderResult
		sem     = make(chan struct{}, conc)
	)

loop:
	for i, reqWire := range requests {
		select {
		case <-ctx.Done():
			break loop
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, wire string) {
			defer wg.Done()
			defer func() { <-sem }()

			resp, err := rawhttp.Send(ctx, rawhttp.Request{
				URL:         target,
				RawRequest:  wire,
				TLSNoVerify: true,
				Timeout:     time.Duration(timeout) * time.Second,
			})
			if err != nil {
				mu.Lock()
				attack.Errors = append(attack.Errors, fmt.Sprintf("req %d: %v", idx, err))
				if len(attack.Errors) > 20 {
					attack.Errors = attack.Errors[1:]
				}
				mu.Unlock()
				return
			}
			res := IntruderResult{
				Index:      idx,
				Request:    truncate(wire, 2048),
				StatusCode: resp.StatusCode,
				Length:     resp.BodyBytes,
				TTFBms:     resp.TTFB.Milliseconds(),
				StatusLine: resp.StatusLine,
				Snippet:    truncate(firstNonEmpty(resp.Body, resp.RawResponse), 512),
			}
			mu.Lock()
			defer mu.Unlock()
			if statusFilter != nil && !statusFilter[res.StatusCode] {
				return
			}
			if filterRe != nil {
				hay := fmt.Sprintf("%d %d %s %s", res.StatusCode, res.Length, resp.StatusLine, resp.Body)
				if !filterRe.MatchString(hay) {
					return
				}
			}
			results = append(results, res)
		}(i, reqWire)
	}
	wg.Wait()

	sort.Slice(results, func(a, b int) bool {
		if results[a].StatusCode != results[b].StatusCode {
			return results[a].StatusCode < results[b].StatusCode
		}
		return results[a].Length < results[b].Length
	})
	return attack, results
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
