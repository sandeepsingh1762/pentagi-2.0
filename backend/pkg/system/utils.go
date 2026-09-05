package system

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"pentagi/pkg/config"
)

const (
	// defaultHTTPClientTimeout is the fallback timeout when no config is provided.
	defaultHTTPClientTimeout = 10 * time.Minute
)

// dockerResolverAddr is the DNS server address Docker Desktop injects into
// Linux containers (see /etc/resolv.conf). Forcing Go's HTTP transport through
// it makes HTTPS calls resolve external hostnames correctly — without this,
// Go's pure-Go resolver occasionally fails with "no such host" on the first
// request to a new domain inside the container.
const dockerResolverAddr = "127.0.0.11:53"

// newDialContext returns a DialContext that resolves names through the Docker
// embedded DNS when available, falling back to the system resolver otherwise.
func newDialContext() func(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	resolver := &net.Resolver{
		PreferGo: false,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 10 * time.Second}
			return d.DialContext(ctx, network, dockerResolverAddr)
		},
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Resolve the hostname using the Docker resolver, then dial directly.
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return dialer.DialContext(ctx, network, addr)
		}
		ips, err := resolver.LookupIPAddr(ctx, host)
		if err != nil || len(ips) == 0 {
			return dialer.DialContext(ctx, network, addr)
		}
		var firstErr error
		for _, ip := range ips {
			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if err == nil {
				return conn, nil
			}
			if firstErr == nil {
				firstErr = err
			}
		}
		return nil, firstErr
	}
}

func getHostname() string {
	hn, err := os.Hostname()
	if err != nil {
		return ""
	}

	return hn
}

func getIPs() []string {
	var ips []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return ips
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ips = append(ips, addr.String())
		}
	}

	return ips
}

func GetSystemCertPool(cfg *config.Config) (*x509.CertPool, error) {
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to get system cert pool: %w", err)
	}

	if cfg.ExternalSSLCAPath != "" {
		ca, err := os.ReadFile(cfg.ExternalSSLCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read external CA certificate: %w", err)
		}

		if !pool.AppendCertsFromPEM(ca) {
			return nil, fmt.Errorf("failed to append external CA certificate to pool")
		}
	}

	return pool, nil
}

func GetHTTPClient(cfg *config.Config) (*http.Client, error) {
	var httpClient *http.Client

	if cfg == nil {
		return &http.Client{
			Timeout: defaultHTTPClientTimeout,
		}, nil
	}

	rootCAPool, err := GetSystemCertPool(cfg)
	if err != nil {
		return nil, err
	}

	// Convert timeout from config (in seconds) to time.Duration
	// 0 = no timeout (unlimited), >0 = timeout in seconds
	// Default value (600) is automatically set in config.go via envDefault:"600" tag
	// when HTTP_CLIENT_TIMEOUT environment variable is not set
	timeout := max(time.Duration(cfg.HTTPClientTimeout)*time.Second, 0)

	dialCtx := newDialContext()
	if cfg.ProxyURL != "" {
		httpClient = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				Proxy: func(req *http.Request) (*url.URL, error) {
					return url.Parse(cfg.ProxyURL)
				},
				DialContext: dialCtx,
				TLSClientConfig: &tls.Config{
					RootCAs:            rootCAPool,
					InsecureSkipVerify: cfg.ExternalSSLInsecure,
				},
			},
		}
	} else {
		httpClient = &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				DialContext: dialCtx,
				TLSClientConfig: &tls.Config{
					RootCAs:            rootCAPool,
					InsecureSkipVerify: cfg.ExternalSSLInsecure,
				},
			},
		}
	}

	return httpClient, nil
}
