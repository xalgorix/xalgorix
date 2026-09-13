// Package proxy provides HTTP, HTTPS and SOCKS5 proxy support for Xalgorix.
// It supports the following formats:
//   - ip:port
//   - ip:port:user:pass
//   - socks5://ip:port
//   - socks5://user:pass@ip:port
package proxy

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ProxyType represents the type of proxy.
type ProxyType string

const (
	ProxyTypeHTTP   ProxyType = "http"
	ProxyTypeHTTPS  ProxyType = "https"
	ProxyTypeSOCKS5 ProxyType = "socks5"
)

// Proxy holds the parsed proxy configuration.
type Proxy struct {
	Raw      string
	Type     ProxyType
	Host     string
	Port     string
	Username string
	Password string
}

// URL returns the proxy as a *url.URL suitable for http.Transport.
// FIX (ChatGPT P1): preserve the correct scheme for each proxy type
// so HTTPS proxies are not silently downgraded to http://.
func (p *Proxy) URL() (*url.URL, error) {
	if p == nil || p.Host == "" || p.Port == "" {
		return nil, fmt.Errorf("proxy: missing host or port")
	}
	var scheme string
	switch p.Type {
	case ProxyTypeSOCKS5:
		scheme = "socks5"
	case ProxyTypeHTTPS:
		scheme = "https"
	default:
		scheme = "http"
	}

	u := &url.URL{Scheme: scheme, Host: net.JoinHostPort(p.Host, p.Port)}
	if p.Username != "" {
		u.User = url.UserPassword(p.Username, p.Password)
	}
	return u, nil
}

// String returns a human-readable representation (password masked).
func (p *Proxy) String() string {
	if p.Username != "" {
		return fmt.Sprintf("%s://%s:****@%s:%s", p.Type, p.Username, p.Host, p.Port)
	}
	return fmt.Sprintf("%s://%s:%s", p.Type, p.Host, p.Port)
}

// Parse parses a proxy string into a Proxy struct.
// Supported formats:
//   - ip:port                     → HTTP proxy, no auth
//   - ip:port:user:pass           → HTTP proxy, with auth
//   - socks5://ip:port            → SOCKS5, no auth
//   - socks5://user:pass@ip:port  → SOCKS5, with auth
//   - http://ip:port              → HTTP proxy, no auth
//   - http://user:pass@ip:port    → HTTP proxy, with auth
//   - https://ip:port             → HTTPS proxy, no auth
func Parse(raw string) (*Proxy, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("proxy: empty string")
	}

	// Detect URI scheme
	if strings.Contains(raw, "://") {
		return parseURI(raw)
	}

	// Plain format: ip:port or ip:port:user:pass
	return parsePlain(raw)
}

func parseURI(raw string) (*Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("proxy: invalid URI %q: %w", raw, err)
	}

	p := &Proxy{Raw: raw}

	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h":
		p.Type = ProxyTypeSOCKS5
	case "https":
		p.Type = ProxyTypeHTTPS
	case "http":
		p.Type = ProxyTypeHTTP
	default:
		return nil, fmt.Errorf("proxy: unsupported URI scheme")
	}

	p.Host = u.Hostname()
	p.Port = u.Port()
	if p.Port == "" {
		if p.Type == ProxyTypeSOCKS5 {
			p.Port = "1080"
		} else {
			p.Port = "8080"
		}
	}

	if u.User != nil {
		p.Username = u.User.Username()
		p.Password, _ = u.User.Password()
	}

	if p.Host == "" {
		return nil, fmt.Errorf("proxy: missing host in %q", raw)
	}

	return p, nil
}

// parsePlain handles the "ip:port" and "ip:port:user:pass" formats.
// FIX (Gemini medium): use net.SplitHostPort to correctly handle IPv6
// addresses like [::1]:8080 which contain multiple colons.
func parsePlain(raw string) (*Proxy, error) {
	// First, try to split as "host:port" (handles IPv6 brackets)
	// If it succeeds we have a plain ip:port entry.
	if host, port, err := net.SplitHostPort(raw); err == nil {
		return &Proxy{
			Raw:  raw,
			Type: ProxyTypeHTTP,
			Host: host,
			Port: port,
		}, nil
	}

	// Fallback: ip:port:user:pass (four colon-separated fields, IPv4 only)
	parts := strings.Split(raw, ":")
	if len(parts) == 4 {
		return &Proxy{
			Raw:      raw,
			Type:     ProxyTypeHTTP,
			Host:     parts[0],
			Port:     parts[1],
			Username: parts[2],
			Password: parts[3],
		}, nil
	}

	return nil, fmt.Errorf("proxy: unrecognized format %q (want ip:port or ip:port:user:pass)", raw)
}

// NewTransport creates an *http.Transport configured to use the given proxy.
// FIX (Gemini medium + ChatGPT P2):
//   - When p is nil, return http.DefaultTransport (not a zero-value Transport)
//     so ProxyFromEnvironment and all tuned defaults are preserved.
//   - When p is set, clone DefaultTransport and only override Proxy,
//     so MaxIdleConns, DialContext timeouts, etc. remain optimal.
func NewTransport(p *Proxy) (*http.Transport, error) {
	if p == nil {
		// Return the default transport cast; callers that need a writable copy
		// should Clone() themselves, but for read-only use this is safe.
		return clonedDefaultTransport(), nil
	}
	proxyURL, err := p.URL()
	if err != nil {
		return nil, err
	}
	// Clone DefaultTransport to inherit all optimized settings, then
	// only override the Proxy field.
	tr := clonedDefaultTransport()
	tr.Proxy = http.ProxyURL(proxyURL)
	return tr, nil
}

// clonedDefaultTransport returns a writable clone of the stdlib default
// transport. http.DefaultTransport is documented to be a *http.Transport;
// the comma-ok guard falls back to a zero-value transport if a future
// runtime ever changes that, so the assertion can never panic.
func clonedDefaultTransport() *http.Transport {
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		return dt.Clone()
	}
	return &http.Transport{}
}

// NewClient returns an *http.Client configured with the given proxy and timeout.
func NewClient(p *Proxy, timeout time.Duration) (*http.Client, error) {
	tr, err := NewTransport(p)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}, nil
}

// NewDirectClient returns a direct HTTP client using Go's tuned default
// transport, optionally disabling TLS verification for explicit testing cases.
func NewDirectClient(tlsSkipVerify bool) *http.Client {
	tr := clonedDefaultTransport()
	if tlsSkipVerify {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{} //nolint:gosec // caller explicitly requested insecure TLS
		} else {
			tr.TLSClientConfig = tr.TLSClientConfig.Clone()
		}
		tr.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // controlled by XALGORIX_TLS_SKIP_VERIFY
	}
	return &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}
}

// ---------------------------------------------------------------------------
// Pool — proxy rotation
// ---------------------------------------------------------------------------

// Pool manages a list of proxies and provides round-robin / random rotation.
type Pool struct {
	mu      sync.Mutex
	proxies []*Proxy
	index   int
	rng     *rand.Rand
}

// NewPool creates a Pool from a slice of raw proxy strings.
// Invalid entries are skipped with a warning printed to stderr.
func NewPool(rawList []string) *Pool {
	p := &Pool{
		rng: rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	for _, raw := range rawList {
		prx, err := Parse(raw)
		if err != nil {
			// Never print raw proxy strings: they may contain credentials.
			fmt.Fprintln(os.Stderr, "[proxy] skipping invalid proxy entry")
			continue
		}
		p.proxies = append(p.proxies, prx)
	}
	return p
}

// LoadFile reads a proxy list from a file (one proxy per line, # comments ignored).
func LoadFile(path string) (*Pool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("proxy: cannot open file %q: %w", path, err)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("proxy: error reading file: %w", err)
	}
	return NewPool(lines), nil
}

// Len returns the number of valid proxies in the pool.
func (p *Pool) Len() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.proxies)
}

// Next returns the next proxy using round-robin rotation.
// FIX (Gemini HIGH): advance the index with modulo BEFORE storing it back
// so p.index never grows beyond len(proxies)-1 and integer overflow
// cannot produce a negative index causing a runtime panic.
func (p *Pool) Next() *Proxy {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.proxies) == 0 {
		return nil
	}
	prx := p.proxies[p.index]
	p.index = (p.index + 1) % len(p.proxies)
	return prx
}

// Random returns a random proxy from the pool.
// Returns nil if the pool is empty.
func (p *Pool) Random() *Proxy {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.proxies) == 0 {
		return nil
	}
	return p.proxies[p.rng.Intn(len(p.proxies))]
}

// All returns a copy of all proxies in the pool.
func (p *Pool) All() []*Proxy {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*Proxy, len(p.proxies))
	copy(out, p.proxies)
	return out
}
