package lnurl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"syscall"
	"time"
)

var TorClient *http.Client
var Client = &http.Client{
	Timeout: 5 * time.Second,
}

// Option configures an LNURLClient.
type Option func(*LNURLClient)

// WithLogger sets a custom slog handler for the client.
// By default slog.Default() is used.
func WithLogger(handler slog.Handler) Option {
	return func(c *LNURLClient) { c.logger = slog.New(handler) }
}

// WithAllowedHosts exempts the given hostnames from the private/reserved IP
// check performed by the SSRF-safe transport built by New. Use it only for
// hosts you control that legitimately resolve to internal addresses (e.g. a
// test lightning address server running in-cluster), and never in production.
// Matching is case-insensitive on the hostname only, port excluded.
func WithAllowedHosts(hosts ...string) Option {
	return func(c *LNURLClient) {
		for _, h := range hosts {
			h = strings.ToLower(strings.TrimSpace(h))
			if h == "" {
				continue
			}
			if c.allowedHosts == nil {
				c.allowedHosts = make(map[string]struct{})
			}
			c.allowedHosts[h] = struct{}{}
		}
	}
}

// LNURLClient makes LNURL requests using the provided HTTP client.
// Use New for production (SSRF-safe) or NewWithClient/NewWithDefaultClient for dev/test.
type LNURLClient struct {
	httpClient   *http.Client
	logger       *slog.Logger
	allowedHosts map[string]struct{}
}

func newClient(httpClient *http.Client, opts []Option) *LNURLClient {
	c := &LNURLClient{
		httpClient: httpClient,
		logger:     slog.Default(),
	}
	for _, o := range opts {
		o(c)
	}

	return c
}

// New returns an LNURLClient with an SSRF-safe HTTP transport that blocks
// connections to private/reserved IP ranges via net.Dialer.Control and
// disables proxy forwarding to prevent proxy-based bypass. Hosts passed to
// WithAllowedHosts are exempt from the private/reserved IP check.
// .onion addresses are routed through TorClient when set.
func New(opts ...Option) (*LNURLClient, error) {
	c := newClient(nil, opts)

	httpClient, err := newSafeHTTPClient(c.allowedHosts)
	if err != nil {
		return nil, err
	}
	c.httpClient = httpClient

	return c, nil
}

// NewWithClient returns an LNURLClient using the provided http.Client.
// The caller is responsible for any transport-level security (e.g. SSRF protection).
func NewWithClient(httpClient *http.Client, opts ...Option) *LNURLClient {
	return newClient(httpClient, opts)
}

// NewWithDefaultClient returns an LNURLClient using OnioncapableTransport,
// preserving .onion routing behaviour. No SSRF protection — use only in dev/test.
func NewWithDefaultClient(opts ...Option) *LNURLClient {
	return newClient(&http.Client{Transport: onioncapableTransport{}}, opts)
}

// HTTPClient returns the underlying *http.Client. It is intended for use
// by wrappers that need to share the same transport (e.g. for direct HTTP
// calls). Do not mutate the returned client's transport.
func (c *LNURLClient) HTTPClient() *http.Client {
	return c.httpClient
}

func newSafeHTTPClient(allowedHosts map[string]struct{}) (*http.Client, error) {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("go-lnurl: http.DefaultTransport is not *http.Transport; cannot clone for SSRF-safe client")
	}

	t := base.Clone()
	t.DialContext = newSafeDialContext(buildPrivateIPRanges(), allowedHosts)
	t.Proxy = nil

	return &http.Client{Transport: onioncapableTransport{clearnet: t}}, nil
}

func buildPrivateIPRanges() []*net.IPNet {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10", // IANA Shared Address Space (RFC6598)
		"240.0.0.0/4",   // Reserved (future use, RFC1112)
		"fc00::/7",      // IPv6 ULA
	}
	ranges := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(fmt.Sprintf("go-lnurl: invalid private CIDR %q: %v", cidr, err))
		}
		ranges = append(ranges, network)
	}

	return ranges
}

// newSafeDialContext returns a DialContext function that uses net.Dialer.Control
// to validate resolved IPs before TCP connection. Control fires after DNS
// resolution but before the TCP handshake, preventing DNS-rebinding attacks.
func newSafeDialContext(privateRanges []*net.IPNet, allowedHosts map[string]struct{}) func(context.Context, string, string) (net.Conn, error) {
	allowedDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control: func(network, addr string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("could not parse resolved address %s", host)
			}
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
				ip.IsMulticast() || ip.IsUnspecified() || isPrivateIP(ip, privateRanges) {
				return fmt.Errorf("%s is a private or reserved IP", ip)
			}

			return nil
		},
	}

	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if isAllowedHost(addr, allowedHosts) {
			return allowedDialer.DialContext(ctx, network, addr)
		}

		return dialer.DialContext(ctx, network, addr)
	}
}

// isAllowedHost reports whether the hostname in addr ("host:port") was
// explicitly allowlisted via WithAllowedHosts.
func isAllowedHost(addr string, allowedHosts map[string]struct{}) bool {
	if len(allowedHosts) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	_, ok := allowedHosts[strings.ToLower(host)]

	return ok
}

func isPrivateIP(ip net.IP, privateRanges []*net.IPNet) bool {
	for _, network := range privateRanges {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// onioncapableTransport routes .onion addresses through TorClient when set,
// and all other requests through Clearnet (defaults to Client if nil).
type onioncapableTransport struct {
	// clearnet is the RoundTripper used for non-.onion requests.
	// If nil, the package-level Client is used.
	clearnet http.RoundTripper
}

func (t onioncapableTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Host, ".onion") && TorClient != nil {
		return TorClient.Do(r)
	}

	if t.clearnet != nil {
		return t.clearnet.RoundTrip(r)
	}

	return Client.Do(r)
}
