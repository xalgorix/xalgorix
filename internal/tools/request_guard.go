package tools

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// RequestGuard reports why an HTTP tool must not send a request to rawURL,
// or nil when it may. The agent installs one per registry; the HTTP tools
// consult it for every redirect hop, because the agent's own guards only see
// the URL the tool was called with.
type RequestGuard func(rawURL string) error

// maxRedirects matches net/http's default redirect limit.
const maxRedirects = 10

// SetRequestGuard installs the guard the HTTP tools of this registry apply
// to redirect hops. A nil guard leaves redirects unchecked.
func (r *Registry) SetRequestGuard(g RequestGuard) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requestGuard = g
}

// RequestGuard returns the guard installed with SetRequestGuard, or nil.
func (r *Registry) RequestGuard() RequestGuard {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.requestGuard
}

// GuardRedirects makes client check every redirect hop with guard before
// following it. A refused hop is not followed: the client returns the
// redirect response itself, and the returned function reports the refusal so
// the tool can say why. The client must be private to one request, and must
// follow redirects (its CheckRedirect is replaced). A nil guard changes
// nothing.
func GuardRedirects(client *http.Client, guard RequestGuard) (refused func() string) {
	if guard == nil {
		return func() string { return "" }
	}
	var note string
	client.CheckRedirect = func(next *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		if err := guard(next.URL.String()); err != nil {
			note = fmt.Sprintf("⛔ REDIRECT NOT FOLLOWED — %s: %v. The redirect response is shown instead.",
				next.URL.Redacted(), err)
			return http.ErrUseLastResponse
		}
		return nil
	}
	return func() string { return note }
}

// DialGuard reports why an HTTP tool must not connect to address, the
// "ip:port" a destination host resolved to, or nil when it may. The agent's
// URL checks resolve a hostname once; the connection resolves it again. A
// DialGuard sees the address actually being connected to, so a name that
// answers differently the second time (DNS rebinding) is still refused.
type DialGuard func(address string) error

// SetDialGuard installs the guard the HTTP tools of this registry apply to
// every direct connection. A nil guard leaves connections unchecked.
func (r *Registry) SetDialGuard(g DialGuard) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dialGuard = g
}

// DialGuard returns the guard installed with SetDialGuard, or nil.
func (r *Registry) DialGuard() DialGuard {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.dialGuard
}

// dialTimeout and dialKeepAlive match http.DefaultTransport's dialer.
const (
	dialTimeout   = 30 * time.Second
	dialKeepAlive = 30 * time.Second
)

// dialResolver is the resolver guarded connections use; nil means
// net.DefaultResolver. Tests swap it with SetDialResolver.
var dialResolver atomic.Pointer[net.Resolver]

// SetDialResolver installs r as the resolver for connections made through
// GuardDials and returns the one it replaced, so a caller can restore it. A
// nil r means net.DefaultResolver. It lets tests make a name resolve one way
// for the scope checks and another way for the connection without replacing
// the process-wide default resolver.
func SetDialResolver(r *net.Resolver) *net.Resolver {
	return dialResolver.Swap(r)
}

// GuardDials makes tr check every direct connection with guard. The check
// runs after DNS resolution, on the exact address being connected to
// (net.Dialer.Control), so it holds for redirect hops and for every address
// a hostname resolves to. Connections to a proxy that tr.Proxy chose are not
// checked, since an operator's proxy often listens on loopback; the proxy
// resolves and connects to the destination itself, so a proxy route is only
// as safe as the proxy's own egress rules. tr must be private to the caller
// (its Proxy and DialContext are replaced). A transport with its own TLS
// dialer is refused, because its HTTPS connections would bypass the check. A
// nil guard changes nothing.
func GuardDials(tr *http.Transport, guard DialGuard) error {
	if tr == nil || guard == nil {
		return nil
	}
	if tr.DialTLSContext != nil || tr.DialTLS != nil { //nolint:staticcheck // DialTLS is deprecated but still honored by net/http
		return fmt.Errorf("transport has its own TLS dialer; its connections cannot be checked")
	}
	var proxies sync.Map // dial addresses of the proxies tr.Proxy chose
	if pick := tr.Proxy; pick != nil {
		tr.Proxy = func(req *http.Request) (*url.URL, error) {
			u, err := pick(req)
			if err == nil && u != nil {
				proxies.Store(proxyDialAddr(u), struct{}{})
			}
			return u, err
		}
	}
	direct := tr.DialContext
	if direct == nil {
		direct = (&net.Dialer{Timeout: dialTimeout, KeepAlive: dialKeepAlive}).DialContext
	}
	guarded := &net.Dialer{
		Timeout:   dialTimeout,
		KeepAlive: dialKeepAlive,
		Resolver:  dialResolver.Load(),
		Control: func(_, address string, _ syscall.RawConn) error {
			if err := guard(address); err != nil {
				return fmt.Errorf("connection to %s not allowed: %w", address, err)
			}
			return nil
		},
	}
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if _, ok := proxies.Load(addr); ok {
			return direct(ctx, network, addr)
		}
		return guarded.DialContext(ctx, network, addr)
	}
	return nil
}

// proxyDialAddr returns the address net/http dials for proxy u: its host and
// port, with the scheme's default port when u names none.
func proxyDialAddr(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		case "socks5", "socks5h":
			port = "1080"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}
