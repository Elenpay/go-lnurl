package lnurl

import (
	"context"
	"errors"
	"fmt"
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

// LNURLClient makes LNURL requests using the provided HTTP client.
// Use New for production (SSRF-safe) or NewInsecure for dev/test.
type LNURLClient struct {
	httpClient *http.Client
}

// New returns an LNURLClient with an SSRF-safe HTTP transport that blocks
// connections to private/reserved IP ranges via net.Dialer.Control and
// disables proxy forwarding to prevent proxy-based bypass.
func New() (*LNURLClient, error) {
	httpClient, err := newSafeHTTPClient()
	if err != nil {
		return nil, err
	}

	return &LNURLClient{httpClient: httpClient}, nil
}

// NewWithClient returns an LNURLClient using the provided http.Client.
// The caller is responsible for any transport-level security (e.g. SSRF protection).
func NewWithClient(httpClient *http.Client) *LNURLClient {
	return &LNURLClient{httpClient: httpClient}
}

// NewWithDefaultClient returns an LNURLClient using http.DefaultClient.
// No SSRF protection is applied — use only in dev/test environments.
func NewWithDefaultClient() *LNURLClient {
	return &LNURLClient{httpClient: http.DefaultClient}
}

// HTTPClient returns the underlying *http.Client.
func (c *LNURLClient) HTTPClient() *http.Client {
	return c.httpClient
}

func newSafeHTTPClient() (*http.Client, error) {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("go-lnurl: http.DefaultTransport is not *http.Transport; cannot clone for SSRF-safe client")
	}

	privateRanges, err := buildPrivateIPRanges()
	if err != nil {
		return nil, err
	}

	t := base.Clone()
	t.DialContext = safeDialContext(privateRanges)
	t.Proxy = nil

	return &http.Client{Transport: t}, nil
}

func buildPrivateIPRanges() ([]*net.IPNet, error) {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"100.64.0.0/10", // IANA Shared Address Space (RFC6598)
		"fc00::/7",      // IPv6 ULA
	}
	ranges := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("go-lnurl: invalid private CIDR %s: %w", cidr, err)
		}
		ranges = append(ranges, network)
	}

	return ranges, nil
}

// safeDialContext returns a DialContext function that uses net.Dialer.Control
// to validate resolved IPs before TCP connection. Control fires after DNS
// resolution but before the TCP handshake, preventing DNS-rebinding attacks.
func safeDialContext(privateRanges []*net.IPNet) func(context.Context, string, string) (net.Conn, error) {
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

	return dialer.DialContext
}

func isPrivateIP(ip net.IP, privateRanges []*net.IPNet) bool {
	for _, network := range privateRanges {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

type onioncapabletransport struct{}

func (_ onioncapabletransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Host, ".onion") && TorClient != nil {
		return TorClient.Do(r)
	}

	return Client.Do(r)
}
