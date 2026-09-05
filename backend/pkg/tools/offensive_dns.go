package tools

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// dnsWordlist is the built-in subdomain brute-force list: high-yield labels
// seen across real engagements, kept compact for in-process enumeration.
var dnsWordlist = []string{
	"www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2", "smtp", "secure",
	"vpn", "m", "shop", "ftp", "mail2", "test", "portal", "ns", "ww1", "host",
	"support", "dev", "web", "bbs", "mx", "email", "cloud", "1", "mail1", "2",
	"forum", "owa", "www2", "gw", "admin", "store", "mx1", "cdn", "api", "exchange",
	"app", "gov", "2tty", "vps", "govyty", "hgfgdf", "news", "1rer", "lkjkui", "stage",
	"staging", "beta", "alpha", "demo", "dev1", "dev2", "qa", "uat", "prod", "internal",
	"intranet", "corp", "auth", "sso", "login", "id", "accounts", "dashboard", "admin1", "panel",
	"cpanel", "whm", "plesk", "git", "gitlab", "jenkins", "ci", "cd", "build", "nexus",
	"artifactory", "sonar", "jira", "confluence", "wiki", "docs", "doc", "status", "monitor", "grafana",
	"kibana", "elastic", "prometheus", "metric", "log", "logs", "sentry", "backup", "db", "database",
	"mysql", "postgres", "pg", "redis", "mongo", "mongodb", "rabbit", "rabbitmq", "kafka", "queue",
	"cache", "s3", "storage", "assets", "static", "media", "img", "images", "files", "download",
	"downloads", "upload", "uploads", "share", "file", "crm", "erp", "hr", "vpn2", "ssl",
	"proxy", "gateway", "gw2", "edge", "lb", "loadbalancer", "router", "firewall", "fw", "ns3",
	"sip", "voip", "pbx", "chat", "im", "meet", "conference", "video", "stream", "live",
	"api2", "apis", "gateway-api", "public-api", "private-api", "internal-api", "v2", "v3", "graphql", "rest",
	"soap", "ws", "wss", "socket", "mqtt", "iot", "device", "sensor", "vpn1", "client",
	"partner", "partners", "vendor", "b2b", "b2c", "sandbox", "labs", "lab", "research", "poc",
}

type dnsRecordResult struct {
	Type   string   `json:"type"`
	Name   string   `json:"name"`
	Values []string `json:"values"`
	Meta   map[string]string `json:"meta,omitempty"`
}

// handleDNSEnum implements the dns_enum tool.
func (o *offensiveTools) handleDNSEnum(ctx context.Context, action DNSEnumAction) (string, error) {
	domain := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(string(action.Domain)), "."))
	if domain == "" {
		return "", fmt.Errorf("domain is required")
	}
	domain = strings.TrimPrefix(strings.TrimPrefix(domain, "http://"), "https://")
	if i := strings.Index(domain, "/"); i >= 0 {
		domain = domain[:i]
	}

	mode := string(action.Action)
	if mode == "" {
		mode = "all"
	}

	resolvers := action.Nameservers
	if len(resolvers) == 0 {
		resolvers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	} else {
		fixed := make([]string, 0, len(resolvers))
		for _, r := range resolvers {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			if _, _, err := net.SplitHostPort(r); err != nil {
				r = net.JoinHostPort(r, "53")
			}
			fixed = append(fixed, r)
		}
		resolvers = fixed
	}

	res := &dnsResolver{servers: resolvers, timeout: 4 * time.Second}

	var b strings.Builder
	fmt.Fprintf(&b, "DNS enumeration: %s (mode=%s)\n\n", domain, mode)

	// wildcard detection first — brute-force hits must exclude wildcard IPs
	wildcardIPs := res.detectWildcard(domain)
	if len(wildcardIPs) > 0 {
		fmt.Fprintf(&b, "WILDCARD detected: *.%s resolves to %s — brute-force results filtered against these\n\n", domain, strings.Join(wildcardIPs, ", "))
	}

	doAll := mode == "all"

	switch {
	case mode == "records" || doAll:
		records := res.enumerateRecords(ctx, domain)
		if len(records) == 0 {
			b.WriteString("no records resolved (domain may not exist or resolvers unreachable)\n")
		} else {
			b.WriteString("== records ==\n")
			for _, r := range records {
				fmt.Fprintf(&b, "%-6s %-24s %s\n", r.Type, r.Name, strings.Join(r.Values, ", "))
			}
			b.WriteString("\n")
		}
		if doAll && mode == "all" {
			if ips := res.domainARecords(domain); len(ips) > 0 {
				ptrs := res.reverseLookup(ctx, ips)
				if len(ptrs) > 0 {
					b.WriteString("== reverse (PTR) ==\n")
					for ip, ptr := range ptrs {
						fmt.Fprintf(&b, "%-24s %s\n", ip, ptr)
					}
					b.WriteString("\n")
				}
			}
		}
		if mode == "records" {
			break
		}
		fallthrough
	case mode == "axfr" || (doAll && mode == "all"):
		if mode == "axfr" || doAll {
			transfers := res.tryZoneTransfer(ctx, domain)
			b.WriteString("== zone transfer (AXFR) ==\n")
			if len(transfers) == 0 {
				b.WriteString("no zone transfer available (expected on hardened servers)\n")
			} else {
				for ns, records := range transfers {
					fmt.Fprintf(&b, "%s leaked %d records:\n", ns, len(records))
					for _, r := range records[:minInt(len(records), 50)] {
						fmt.Fprintf(&b, "  %s\n", r)
					}
				}
			}
			b.WriteString("\n")
		}
		if mode == "axfr" {
			break
		}
		fallthrough
	case mode == "subdomains" || (doAll && mode == "all"):
		candidates := append([]string{}, dnsWordlist...)
		candidates = append(candidates, action.Subdomains...)
		found := res.bruteSubdomains(ctx, domain, candidates, wildcardIPs)
		b.WriteString("== subdomains (brute force) ==\n")
		if len(found) == 0 {
			b.WriteString("none resolved\n")
		} else {
			for _, f := range found {
				fmt.Fprintf(&b, "%-32s %s\n", f.Name, strings.Join(f.Values, ", "))
			}
		}
		b.WriteString("\n")
		if mode == "subdomains" {
			break
		}
		fallthrough
	case mode == "srv" || (doAll && mode == "all"):
		srv := res.enumerateSRV(ctx, domain)
		b.WriteString("== SRV services ==\n")
		if len(srv) == 0 {
			b.WriteString("none published\n")
		} else {
			for _, r := range srv {
				fmt.Fprintf(&b, "%-28s %s (priority=%s weight=%s port=%s)\n", r.Name, strings.Join(r.Values, ","), r.Meta["priority"], r.Meta["weight"], r.Meta["port"])
			}
		}
	case mode == "reverse":
		ips := res.domainARecords(domain)
		ptrs := res.reverseLookup(ctx, ips)
		b.WriteString("== reverse (PTR) ==\n")
		if len(ptrs) == 0 {
			b.WriteString("none\n")
		}
		for ip, ptr := range ptrs {
			fmt.Fprintf(&b, "%-24s %s\n", ip, ptr)
		}
	default:
		return "", fmt.Errorf("unknown dns_enum action %q (want records|subdomains|axfr|reverse|srv|all)", mode)
	}

	return b.String(), nil
}

// dnsResolver performs DNS lookups over plain UDP with a tiny pure-stdlib
// implementation: net.Resolver with a custom Dial to pin each server.
type dnsResolver struct {
	servers []string
	timeout time.Duration
}

func (r *dnsResolver) resolverFor(server string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: r.timeout}
			return d.DialContext(ctx, network, server)
		},
	}
}

func (r *dnsResolver) lookup(ctx context.Context, host string, rtype string) ([]string, error) {
	var lastErr error
	for _, srv := range r.servers {
		res := r.resolverFor(srv)
		sctx, cancel := context.WithTimeout(ctx, r.timeout)
		var (
			out []string
			err error
		)
		switch rtype {
		case "A":
			out, err = res.LookupHost(sctx, host)
		case "AAAA":
			ips, err2 := res.LookupIP(sctx, "ip6", host)
			if err2 == nil {
				for _, ip := range ips {
					out = append(out, ip.String())
				}
			}
			err = err2
		case "CNAME":
			cname, err2 := res.LookupCNAME(sctx, host)
			if err2 == nil && cname != "" {
				out = []string{cname}
			}
			err = err2
		case "MX":
			mxs, err2 := res.LookupMX(sctx, host)
			if err2 == nil {
				for _, mx := range mxs {
					out = append(out, fmt.Sprintf("%d %s", mx.Pref, mx.Host))
				}
			}
			err = err2
		case "NS":
			nss, err2 := res.LookupNS(sctx, host)
			if err2 == nil {
				for _, ns := range nss {
					out = append(out, ns.Host)
				}
			}
			err = err2
		case "TXT":
			out, err = res.LookupTXT(sctx, host)
		case "SOA":
			// net.Resolver has no SOA helper; use the raw DNS query path
			records, err2 := rawDNSQuery(sctx, r.servers[0], host, 6)
			if err2 == nil && len(records) > 0 {
				out = records
			}
			err = err2
		case "PTR":
			name, err2 := res.LookupAddr(sctx, host)
			if err2 == nil {
				out = name
			}
			err = err2
		default:
			cancel()
			return nil, fmt.Errorf("unsupported record type %s", rtype)
		}
		cancel()
		if err == nil && len(out) > 0 {
			return out, nil
		}
		if err != nil {
			lastErr = err
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no %s records for %s", rtype, host)
}

// detectWildcard resolves a set of random labels; their IPs mark wildcard answers.
func (r *dnsResolver) detectWildcard(domain string) []string {
	var rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		label := fmt.Sprintf("pw%d%d", rng.Int63(), time.Now().UnixNano()%1000)
		ips, err := r.lookup(context.Background(), label+"."+domain, "A")
		if err == nil {
			for _, ip := range ips {
				seen[ip] = true
			}
		}
	}
	out := make([]string, 0, len(seen))
	for ip := range seen {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

func (r *dnsResolver) enumerateRecords(ctx context.Context, domain string) []dnsRecordResult {
	types := []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA"}
	var out []dnsRecordResult
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, t := range types {
		if t == "CAA" {
			continue // net.Resolver lacks CAA; skip to stay stdlib-only
		}
		wg.Add(1)
		go func(rt string) {
			defer wg.Done()
			vals, err := r.lookup(ctx, domain, rt)
			if err != nil || len(vals) == 0 {
				return
			}
			mu.Lock()
			out = append(out, dnsRecordResult{Type: rt, Name: domain, Values: vals})
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Type < out[j].Type })
	return out
}

func (r *dnsResolver) domainARecords(domain string) []string {
	ips, err := r.lookup(context.Background(), domain, "A")
	if err != nil {
		return nil
	}
	return ips
}

func (r *dnsResolver) reverseLookup(ctx context.Context, ips []string) map[string]string {
	out := map[string]string{}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, ip := range ips {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			names, err := r.lookup(ctx, ip, "PTR")
			if err != nil || len(names) == 0 {
				return
			}
			mu.Lock()
			out[ip] = strings.Join(names, ", ")
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return out
}

// tryZoneAttempt attempts an AXFR against each NS using a raw DNS query over
// TCP (stdlib has no AXFR; the query itself is simple: type 252).
func (r *dnsResolver) tryZoneTransfer(ctx context.Context, domain string) map[string][]string {
	out := map[string][]string{}
	nss, err := r.lookup(ctx, domain, "NS")
	if err != nil {
		return out
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, ns := range nss {
		wg.Add(1)
		go func(ns string) {
			defer wg.Done()
			records, err := axfrQuery(ctx, ns, domain)
			if err != nil || len(records) == 0 {
				return
			}
			mu.Lock()
			out[ns] = records
			mu.Unlock()
		}(ns)
	}
	wg.Wait()
	return out
}

// rawDNSQuery sends a DNS query of the given type over TCP and returns a
// short human-readable line per answer record. qtype: 1=A 2=NS 5=CNAME 6=SOA
// 12=PTR 15=MX 16=TXT 252=AXFR.
func rawDNSQuery(ctx context.Context, server, domain string, qtype uint16) ([]string, error) {
	conn, err := dialDNS(ctx, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	q := buildDNSQuery(domain, qtype)
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return nil, fmt.Errorf("short dns response")
	}
	records := parseDNSRecords(buf[:n], qtype)
	if len(records) == 0 {
		return nil, fmt.Errorf("no answers")
	}
	return records, nil
}

// dialDNS connects TCP to a resolver (host or host:port).
func dialDNS(ctx context.Context, server string) (net.Conn, error) {
	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		addr = net.JoinHostPort(strings.TrimSuffix(server, "."), "53")
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}

// axfrQuery sends an AXFR (type 252) query over TCP and parses the answer
// records loosely (name<TAB>ttl<class>type rdata lines are reconstructed).
func axfrQuery(ctx context.Context, server, domain string) ([]string, error) {
	conn, err := dialDNS(ctx, server)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	q := buildDNSQuery(domain, 252)
	if _, err := conn.Write(q); err != nil {
		return nil, err
	}

	var records []string
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil || n < 12 {
			break
		}
		parsed := parseDNSRecords(buf[:n], 252)
		if len(parsed) == 0 {
			break
		}
		records = append(records, parsed...)
		if len(records) > 500 {
			break
		}
	}
	return records, nil
}

// buildDNSQuery constructs a DNS query message for the given qtype over TCP
// (two-byte length prefix included). qtype 252 = AXFR.
func buildDNSQuery(domain string, qtype uint16) []byte {
	var msg []byte
	msg = append(msg, 0x00, 0x10)             // TCP length prefix placeholder
	msg = append(msg, 0xab, 0xcd)             // id
	msg = append(msg, 0x00, 0x00)             // flags: standard query
	msg = append(msg, 0x00, 0x01)             // qdcount
	msg = append(msg, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // an/ns/arcount
	for _, label := range strings.Split(strings.TrimSuffix(domain, "."), ".") {
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0x00)                          // root
	msg = append(msg, byte(qtype>>8), byte(qtype))   // qtype
	msg = append(msg, 0x00, 0x01)                    // qclass = IN
	msg[0] = byte(len(msg)-2) >> 8
	msg[1] = byte(len(msg) - 2)
	return msg
}

// parseDNSRecords loosely decodes answer records (best-effort type+rdata size).
func parseDNSRecords(buf []byte, qtype uint16) []string {
	if len(buf) < 12 {
		return nil
	}
	qd := int(buf[4])<<8 | int(buf[5])
	an := int(buf[6])<<8 | int(buf[7])
	if an == 0 || qd == 0 {
		return nil
	}
	// skip question section
	off := 12
	for i := 0; i < qd && off < len(buf); {
		if buf[off]&0xC0 != 0 {
			off += 2
		} else {
			l := int(buf[off])
			off += 1 + l
			if l == 0 {
				break
			}
		}
		i++
	}
	off += 4 // qtype/qclass

	var out []string
	for i := 0; i < an && off+10 <= len(buf); i++ {
		// name (possibly compressed)
		nameLen := 0
		if buf[off]&0xC0 == 0xC0 {
			nameLen = 2
		} else {
			for off+nameLen < len(buf) && buf[off+nameLen] != 0 {
				nameLen += int(buf[off+nameLen]) + 1
			}
			nameLen++
		}
		off += nameLen
		if off+10 > len(buf) {
			break
		}
		rt := int(buf[off])<<8 | int(buf[off+1])
		rdl := int(buf[off+8])<<8 | int(buf[off+9])
		off += 10
		if off+rdl > len(buf) {
			break
		}
		_ = qtype
		typeName := "OTHER"
		switch rt {
		case 1:
			typeName = "A"
		case 2:
			typeName = "NS"
		case 5:
			typeName = "CNAME"
		case 6:
			typeName = "SOA"
		case 12:
			typeName = "PTR"
		case 15:
			typeName = "MX"
		case 16:
			typeName = "TXT"
		}
		out = append(out, fmt.Sprintf("%s record (rdata %d bytes)", typeName, rdl))
		off += rdl
	}
	return out
}

var srvServices = []string{
	"_http._tcp", "_https._tcp", "_sip._tcp", "_sips._tcp", "_xmpp-server._tcp",
	"_xmpp-client._tcp", "_imap._tcp", "_imaps._tcp", "_pop3._tcp", "_pop3s._tcp",
	"_smtp._tcp", "_submission._tcp", "_ldap._tcp", "_ldaps._tcp", "_kerberos._tcp",
	"_kpasswd._tcp", "_sip._udp", "_minecraft._tcp", "_gc._tcp", "_dcerpc._tcp",
	"_postgresql._tcp", "_mysql._tcp", "_mongodb._tcp", "_redis._tcp", "_mqtt._tcp",
}

func (r *dnsResolver) enumerateSRV(ctx context.Context, domain string) []dnsRecordResult {
	var out []dnsRecordResult
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, svc := range srvServices {
		wg.Add(1)
		go func(svc string) {
			defer wg.Done()
			_, records, err := r.resolverFor(r.servers[0]).LookupSRV(ctx, "", "", svc+"."+domain)
			if err != nil || len(records) == 0 {
				return
			}
			var vals []string
			for _, rec := range records {
				vals = append(vals, fmt.Sprintf("%s:%d", strings.TrimSuffix(rec.Target, "."), rec.Port))
			}
			mu.Lock()
			out = append(out, dnsRecordResult{
				Type:   "SRV",
				Name:   svc + "." + domain,
				Values: vals,
				Meta: map[string]string{
					"priority": fmt.Sprintf("%d", records[0].Priority),
					"weight":   fmt.Sprintf("%d", records[0].Weight),
					"port":     fmt.Sprintf("%d", records[0].Port),
				},
			})
			mu.Unlock()
		}(svc)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// bruteSubdomains resolves candidate labels concurrently.
func (r *dnsResolver) bruteSubdomains(ctx context.Context, domain string, labels []string, excludeIPs []string) []dnsRecordResult {
	exclude := map[string]bool{}
	for _, ip := range excludeIPs {
		exclude[ip] = true
	}

	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var out []dnsRecordResult

	for _, label := range labels {
		label = strings.TrimSpace(label)
		if label == "" {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(l string) {
			defer wg.Done()
			defer func() { <-sem }()
			host := l + "." + domain
			ips, err := r.lookup(ctx, host, "A")
			if err != nil {
				return
			}
			var filtered []string
			for _, ip := range ips {
				if !exclude[ip] {
					filtered = append(filtered, ip)
				}
			}
			if len(filtered) == 0 {
				return
			}
			mu.Lock()
			out = append(out, dnsRecordResult{Type: "A", Name: host, Values: filtered})
			mu.Unlock()
		}(label)
	}
	wg.Wait()
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
