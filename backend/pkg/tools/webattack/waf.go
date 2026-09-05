package webattack

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"pentagi/pkg/tools/rawhttp"
)

// wafSignature matches one WAF/CDN protection product.
type wafSignature struct {
	Name        string
	HeaderHints []string // "header: value-prefix"
	HeaderNames []string // header presence
	BodyHints   []string // case-insensitive body markers
	Statuses    []int    // status codes seen when blocking
}

var wafSignatures = []wafSignature{
	{Name: "Cloudflare", HeaderNames: []string{"Cf-Ray", "Server"}, BodyHints: []string{"attention required! | cloudflare", "cloudflare-ray-id", "checking your browser before accessing"}, Statuses: []int{403, 503}},
	{Name: "Akamai", HeaderNames: []string{"Server"}, BodyHints: []string{"akamai ghost", "access denied.*reference.*", "support id"}, Statuses: []int{403}},
	{Name: "Imperva/Incapsula", BodyHints: []string{"incapsula", "imperva", "_incapsula_resource"}, Statuses: []int{403}},
	{Name: "F5 BIG-IP ASM", HeaderHints: []string{"BIGipServer"}, BodyHints: []string{"the requested url was rejected", "support identifier"}, Statuses: []int{403, 406}},
	{Name: "AWS WAF", HeaderNames: []string{"X-Amzn-Waf-Action"}, BodyHints: []string{"aws waf", "request blocked"}, Statuses: []int{403}},
	{Name: "ModSecurity", BodyHints: []string{"mod_security", "modsecurity", "not acceptable you should not be using this method"}, Statuses: []int{403, 406, 501}},
	{Name: "Sucuri", HeaderNames: []string{"X-Sucuri-ID"}, BodyHints: []string{"sucuri website firewall", "access denied - sucuri website firewall"}, Statuses: []int{403}},
	{Name: "Edgecast", BodyHints: []string{"edgecast"}, Statuses: []int{400, 403}},
	{Name: "Barracuda", HeaderNames: []string{"X-BS-Status"}, BodyHints: []string{"barracudawaf"}, Statuses: []int{403}},
	{Name: "Citrix NetScaler", HeaderNames: []string{"NSC_*"}, BodyHints: []string{"netscaler", "cnee"}, Statuses: []int{403}},
	{Name: "DenyAll", BodyHints: []string{"denyall", "iisforward"}, Statuses: []int{403}},
	{Name: "Radware", BodyHints: []string{"radware"}, Statuses: []int{403}},
}

// WAFResult reports detected protections.
type WAFResult struct {
	Target    string         `json:"target"`
	Detected  []string       `json:"detected"`
	Blocked   bool           `json:"blocked"`
	Details   []string       `json:"details"`
	ProbeLog  []string       `json:"probe_log"`
	Guidance  []string       `json:"guidance,omitempty"`
}

// DetectWAF fingerprints WAF/CDN protections using benign + malicious probes.
func DetectWAF(ctx context.Context, target string, timeoutSec int) (*WAFResult, error) {
	if target == "" {
		return nil, fmt.Errorf("target url is required")
	}
	if timeoutSec <= 0 {
		timeoutSec = 10
	}

	probes := []struct {
		label string
		url   string
	}{
		{"benign", target},
		{"sqli-probe", appendQueryParam(target, "id=1'+OR+'1'='1")},
		{"traversal-probe", appendQueryParam(target, "file=../../../etc/passwd")},
		{"xss-probe", appendQueryParam(target, "q=<script>alert(1)</script>")},
		{"cmd-probe", appendQueryParam(target, "cmd=;cat+/etc/passwd")},
	}

	res := &WAFResult{Target: target}
	for _, p := range probes {
		resp, err := rawhttp.Send(ctx, rawhttp.Request{
			URL:         p.url,
			TLSNoVerify: true,
			Timeout:     time.Duration(timeoutSec) * time.Second,
		})
		if err != nil {
			res.ProbeLog = append(res.ProbeLog, fmt.Sprintf("%s: ERROR %v", p.label, err))
			continue
		}
		matched := matchWAF(resp.StatusCode, resp.Headers, resp.Body)
		blocked := resp.StatusCode == 403 || resp.StatusCode == 406 || resp.StatusCode == 429 || resp.StatusCode == 501
		line := fmt.Sprintf("%s: status=%d", p.label, resp.StatusCode)
		if len(matched) > 0 {
			line += " signature=" + strings.Join(matched, ",")
		}
		res.ProbeLog = append(res.ProbeLog, line)

		for _, m := range matched {
			seen := false
			for _, d := range res.Detected {
				if d == m {
					seen = true
				}
			}
			if !seen {
				res.Detected = append(res.Detected, m)
			}
		}
		if blocked && p.label != "benign" {
			res.Blocked = true
			res.Details = append(res.Details, fmt.Sprintf("%s blocked (status %d)", p.label, resp.StatusCode))
		}
	}
	sort.Strings(res.Detected)

	if len(res.Detected) > 0 || res.Blocked {
		res.Guidance = append(res.Guidance,
			"switch to payload_engine mutation=true + waf_evasion=true: double-URL, unicode, comment-insertion and case-random variants often slip signature filters",
			"probe smuggling (smuggle_probe) — the WAF may inspect only the front-end leg",
			"try chunked/obfuscated Transfer-Encoding and header-case tricks via raw_http",
			"split payloads across parameters or use encoding nesting the WAF does not normalize",
		)
	} else {
		res.Guidance = append(res.Guidance, "no WAF detected on the probes — standard payload sets should reach the origin")
	}
	return res, nil
}

// matchWAF checks one response against all signatures.
func matchWAF(status int, headers map[string][]string, body string) []string {
	var out []string
	lb := strings.ToLower(body)
	for _, sig := range wafSignatures {
		hit := false
		for _, hn := range sig.HeaderNames {
			if hn == "Cf-Ray" && headerGet(headers, "Cf-Ray") != "" {
				hit = true
			}
			if hn == "X-Sucuri-ID" && headerGet(headers, "X-Sucuri-ID") != "" {
				hit = true
			}
			if hn == "X-Amzn-Waf-Action" && headerGet(headers, "X-Amzn-Waf-Action") != "" {
				hit = true
			}
			if hn == "X-BS-Status" && headerGet(headers, "X-BS-Status") != "" {
				hit = true
			}
		}
		for _, hh := range sig.HeaderHints {
			for k, vals := range headers {
				lk := strings.ToLower(k)
				if strings.Contains(lk, strings.ToLower(hh)) {
					hit = true
					_ = vals
				}
			}
		}
		for _, bh := range sig.BodyHints {
			if strings.Contains(lb, bh) {
				hit = true
			}
		}
		for _, st := range sig.Statuses {
			if st == status && (len(sig.BodyHints) > 0 || len(sig.HeaderNames) > 0) {
				// status alone is weak; require a body/header hint too (checked above)
				_ = st
			}
		}
		if hit {
			out = append(out, sig.Name)
		}
	}
	return out
}

// appendQueryParam appends a raw query fragment to a URL.
func appendQueryParam(target, raw string) string {
	if strings.Contains(target, "?") {
		return target + "&" + raw
	}
	return target + "?" + raw
}
