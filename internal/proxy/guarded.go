package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// GuardFunc reports why a connection to address must not be made, or nil when
// it may. address is "host:port"; host is a name or an IP address. The
// guarded proxy calls it with the destination as requested and, where it
// resolves the destination itself, again with every IP address that
// destination resolves to, so a guard that only knows how to classify
// addresses still sees each one.
type GuardFunc func(address string) error

// guardedDialTimeout and guardedKeepAlive match http.DefaultTransport's dialer.
const (
	guardedDialTimeout = 30 * time.Second
	guardedKeepAlive   = 30 * time.Second
)

// upstreamHandshakeTimeout bounds the exchange with an upstream proxy after
// the TCP connection to it is open: the CONNECT request and its reply, or the
// SOCKS5 handshake. A variable so tests can shorten it.
var upstreamHandshakeTimeout = 30 * time.Second

// refusedDestinationError is a destination the guard refused.
type refusedDestinationError struct {
	address string
	err     error
}

func (e *refusedDestinationError) Error() string {
	return fmt.Sprintf("connection to %s refused: %v", e.address, e.err)
}

func (e *refusedDestinationError) Unwrap() error { return e.err }

// GuardedLocal is a loopback-only HTTP proxy that checks every destination
// before it connects to it. It exists for clients that make connections the
// caller never sees: a browser follows redirects, loads subresources and
// opens WebSockets on its own, so checking the URL it is told to open says
// nothing about where it connects afterwards.
type GuardedLocal struct {
	url     string
	server  *http.Server
	handler *localHandler
}

// StartGuardedLocal starts a GuardedLocal on an ephemeral loopback port.
//
// Every plain-HTTP request and every CONNECT tunnel (HTTPS, WebSocket) is
// checked with guard before anything is sent; a refused destination gets a
// 403 and no connection is made.
//
// With a nil upstream the proxy connects to destinations itself, and guard
// also checks the address each connection dials after DNS resolution, so a
// name that resolves to a refused address at connection time (DNS rebinding)
// is still refused. opts.Proxy can send some destinations through a proxy
// instead, as an upstream.
//
// Through an upstream, what the upstream is sent depends on where it runs:
//
//   - An upstream on this machine (see upstreamOnThisMachine: an
//     intercepting proxy like Caido or Burp, a local forwarder) could
//     resolve a name to this machine, so it is only handed checked
//     addresses. The proxy resolves the destination itself and checks every
//     address it resolves to; a name that does not resolve here is refused.
//     CONNECT tunnels and SOCKS5 connections are requested for the checked
//     address, and plain-HTTP requests to an HTTP upstream carry it in the
//     request line. TLS SNI and the Host header keep the name.
//   - Any other upstream is sent the name, once the guard has accepted it
//     (the guard resolves names here when it can). Where that upstream
//     resolves the name, it reaches its own network, not this machine, and a
//     name only the upstream can resolve (a pivot into an internal network)
//     still works.
func StartGuardedLocal(upstream *Proxy, guard GuardFunc, opts GuardedOptions) (*GuardedLocal, error) {
	if guard == nil {
		return nil, errors.New("guarded local proxy needs a guard")
	}
	h := &localHandler{
		guard:   guard,
		exempt:  map[string]bool{},
		tunnels: &tunnelSet{conns: map[net.Conn]struct{}{}},
	}
	if upstream != nil {
		route, err := newUpstreamRoute(upstream)
		if err != nil {
			return nil, err
		}
		h.fixed = route
	} else {
		tr := clonedDefaultTransport()
		tr.Proxy = nil
		tr.DialContext = guardedDialer(guard).DialContext
		h.transport = tr
		h.proxyFor = opts.Proxy
		h.routes = map[string]*upstreamRoute{}
	}
	for _, address := range opts.Exempt {
		if address = strings.TrimSpace(address); address != "" {
			h.exempt[address] = true
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen on loopback: %w", err)
	}
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return &GuardedLocal{url: "http://" + ln.Addr().String(), server: srv, handler: h}, nil
}

// GuardedOptions adjusts a GuardedLocal.
type GuardedOptions struct {
	// Exempt lists host:port CONNECT destinations that are dialed directly
	// without the guard or an upstream, for a loopback service the client
	// must reach (a browser extension's channel back to this process).
	// Plain-HTTP requests to them are still guarded.
	Exempt []string
	// Proxy, when there is no upstream, picks a proxy for each destination
	// the way http.Transport.Proxy does: a nil URL connects directly. Pass
	// http.ProxyFromEnvironment to follow HTTP_PROXY, HTTPS_PROXY and
	// NO_PROXY the way http_request does. A proxy it picks is used as an
	// upstream (see StartGuardedLocal); destinations are still checked, the
	// connection to the proxy itself is not. CONNECT tunnels are looked up
	// as https URLs. Ignored when there is an upstream.
	Proxy func(*http.Request) (*url.URL, error)
}

// URL is the proxy's address, for example http://127.0.0.1:41234.
func (g *GuardedLocal) URL() string {
	if g == nil {
		return ""
	}
	return g.url
}

// Close stops the proxy and ends every open tunnel.
func (g *GuardedLocal) Close() error {
	if g == nil {
		return nil
	}
	err := g.server.Close()
	g.handler.tunnels.closeAll()
	g.handler.closeIdleConnections()
	return err
}

// upstreamRoute is an upstream proxy guarded connections are forwarded
// through.
type upstreamRoute struct {
	proxy *Proxy
	// onThisMachine marks an upstream that runs on this machine: it is only
	// handed checked addresses (see StartGuardedLocal). It is decided once,
	// when the route is created, and kept for the proxy's lifetime; the
	// proxy's own name is the operator's to resolve, not a scanned page's.
	onThisMachine bool
	// transport carries plain-HTTP requests through the upstream. It only
	// ever connects to the upstream itself.
	transport *http.Transport
}

func newUpstreamRoute(p *Proxy) (*upstreamRoute, error) {
	u, err := p.URL()
	if err != nil {
		return nil, fmt.Errorf("invalid upstream proxy: %w", err)
	}
	tr := clonedDefaultTransport()
	tr.Proxy = http.ProxyURL(u)
	return &upstreamRoute{proxy: p, onThisMachine: upstreamOnThisMachine(p), transport: tr}, nil
}

// upstreamLookupTimeout bounds the name lookup upstreamOnThisMachine makes.
const upstreamLookupTimeout = 10 * time.Second

// upstreamOnThisMachine reports whether proxy p listens on this machine: a
// loopback or unspecified address, a *.localhost name, one of this
// machine's interface addresses, or a name that resolves to any of those. A
// name that does not resolve here counts as this machine too, the strict
// answer. It deliberately does not ask the guard: the guard's policy may
// allow this machine's addresses as scan targets (a local-targets opt-in),
// or let a name through when its lookup fails, and neither says anything
// about where the proxy runs. A variable so tests can treat a loopback test
// proxy as a remote one.
var upstreamOnThisMachine = func(p *Proxy) bool {
	host := strings.TrimSuffix(strings.Trim(p.Host, "[]"), ".")
	if isLoopbackHost(host) {
		return true
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), upstreamLookupTimeout)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(addrs) == 0 {
			return true
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	return anyOnThisMachine(ips)
}

// anyOnThisMachine reports whether any of ips is a loopback or unspecified
// address or an address of one of this machine's interfaces. If the
// interfaces cannot be listed, every address counts as this machine.
func anyOnThisMachine(ips []net.IP) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return true
	}
	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsUnspecified() {
			return true
		}
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPNet:
				if v.IP.Equal(ip) {
					return true
				}
			case *net.IPAddr:
				if v.IP.Equal(ip) {
					return true
				}
			}
		}
	}
	return false
}

// isLoopbackHost reports whether host names this machine's loopback.
func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return host == "localhost" || strings.HasSuffix(host, ".localhost")
}

// proxyFromURL converts a proxy URL, as http.ProxyFromEnvironment returns
// it, to a Proxy. A missing port gets the default net/http uses for the
// scheme.
func proxyFromURL(u *url.URL) (*Proxy, error) {
	p := &Proxy{Host: u.Hostname(), Port: u.Port()}
	defaultPort := ""
	switch strings.ToLower(u.Scheme) {
	case "http":
		p.Type, defaultPort = ProxyTypeHTTP, "80"
	case "https":
		p.Type, defaultPort = ProxyTypeHTTPS, "443"
	case "socks5", "socks5h":
		p.Type, defaultPort = ProxyTypeSOCKS5, "1080"
	default:
		return nil, errors.New("unsupported proxy scheme")
	}
	if p.Host == "" {
		return nil, errors.New("proxy URL has no host")
	}
	if p.Port == "" {
		p.Port = defaultPort
	}
	if u.User != nil {
		p.Username = u.User.Username()
		p.Password, _ = u.User.Password()
	}
	return p, nil
}

// routeFor returns the upstream a guarded connection to target goes through,
// or nil to connect directly. scheme is the request's scheme, or "https" for
// a CONNECT tunnel.
func (h *localHandler) routeFor(scheme, target string) (*upstreamRoute, error) {
	if h.fixed != nil {
		return h.fixed, nil
	}
	if h.proxyFor == nil {
		return nil, nil
	}
	req := &http.Request{
		Method: http.MethodGet,
		URL:    &url.URL{Scheme: scheme, Host: target},
		Header: http.Header{},
		Host:   target,
	}
	u, err := h.proxyFor(req)
	if err != nil || u == nil {
		return nil, err
	}
	key := u.String()
	h.routesMu.Lock()
	route, ok := h.routes[key]
	h.routesMu.Unlock()
	if ok {
		return route, nil
	}
	// Build the route without the lock: deciding where the proxy runs may
	// mean a name lookup, which must not hold up other requests.
	p, err := proxyFromURL(u)
	if err != nil {
		return nil, err
	}
	if route, err = newUpstreamRoute(p); err != nil {
		return nil, err
	}
	h.routesMu.Lock()
	defer h.routesMu.Unlock()
	if existing, ok := h.routes[key]; ok {
		return existing, nil
	}
	if h.routesClosed {
		// The proxy is closing: serve this request without keeping the
		// route (and its connections) around.
		route.transport.DisableKeepAlives = true
		return route, nil
	}
	h.routes[key] = route
	return route, nil
}

// closeIdleConnections closes the idle connections of every transport the
// handler has used. Routes created after it are not kept.
func (h *localHandler) closeIdleConnections() {
	if h.transport != nil {
		h.transport.CloseIdleConnections()
	}
	if h.fixed != nil {
		h.fixed.transport.CloseIdleConnections()
	}
	h.routesMu.Lock()
	defer h.routesMu.Unlock()
	h.routesClosed = true
	for _, route := range h.routes {
		route.transport.CloseIdleConnections()
	}
}

// guardedDialer checks each address it is about to connect to, after DNS
// resolution, with guard.
func guardedDialer(guard GuardFunc) *net.Dialer {
	return &net.Dialer{
		Timeout:   guardedDialTimeout,
		KeepAlive: guardedKeepAlive,
		Control: func(_, address string, _ syscall.RawConn) error {
			if err := guard(address); err != nil {
				return &refusedDestinationError{address: address, err: err}
			}
			return nil
		},
	}
}

// dialConnect opens the tunnel for a CONNECT to target.
func (h *localHandler) dialConnect(ctx context.Context, target string) (net.Conn, io.Reader, error) {
	if h.guard == nil {
		return dialThroughUpstream(ctx, h.upstream, target)
	}
	if h.exempt[target] {
		// Only addresses the caller listed in exempt get here.
		conn, err := net.DialTimeout("tcp", target, guardedDialTimeout) //nolint:gosec // G704: target is one of the caller's fixed exempt addresses
		if err != nil {
			return nil, nil, err
		}
		return conn, conn, nil
	}
	if err := h.guard(target); err != nil {
		return nil, nil, &refusedDestinationError{address: target, err: err}
	}
	route, err := h.routeFor("https", target)
	if err != nil {
		return nil, nil, err
	}
	if route != nil {
		dest := target
		if route.onThisMachine {
			if dest, err = h.resolveChecked(ctx, target); err != nil {
				return nil, nil, err
			}
		}
		return dialThroughUpstream(ctx, route.proxy, dest)
	}
	conn, err := guardedDialer(h.guard).DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, nil, err
	}
	return conn, conn, nil
}

// errUnresolved refuses a destination whose name does not resolve here.
var errUnresolved = errors.New("the name does not resolve")

// resolveChecked resolves target's host, checks every address it resolves to
// with the guard, and returns one of them (IPv4 first) as host:port. A name
// that does not resolve, or that has any refused address, is refused.
func (h *localHandler) resolveChecked(ctx context.Context, target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return "", &refusedDestinationError{address: target, err: err}
	}
	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		ctx, cancel := context.WithTimeout(ctx, guardedDialTimeout)
		defer cancel()
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil || len(addrs) == 0 {
			return "", &refusedDestinationError{address: target, err: errUnresolved}
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	var pick net.IP
	for _, ip := range ips {
		address := net.JoinHostPort(ip.String(), port)
		if err := h.guard(address); err != nil {
			return "", &refusedDestinationError{address: address, err: err}
		}
		if pick == nil || (pick.To4() == nil && ip.To4() != nil) {
			pick = ip
		}
	}
	return net.JoinHostPort(pick.String(), port), nil
}

// requestHostPort is the host:port a proxied absolute-URL request goes to.
func requestHostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "80"
		if strings.EqualFold(u.Scheme, "https") || strings.EqualFold(u.Scheme, "wss") {
			port = "443"
		}
	}
	return net.JoinHostPort(u.Hostname(), port)
}

// notFromTarget ends every answer the guarded proxy makes up itself, so a
// reader (often a model reading the page) does not take it for the target's
// own response.
const notFromTarget = " This response comes from the browser's local egress proxy, not from the target."

// refuseDestination answers a request the guard refused and logs why for the
// operator. Nothing was sent to the destination. The page that made the
// request can read the body, so it says why in general terms only: not which
// rule matched or what a name resolved to.
func refuseDestination(w http.ResponseWriter, address string, err error) {
	log.Printf("[proxy] refused a guarded connection to %q: %v", address, err)
	msg := "Forbidden: the local-network guard refused this destination because it is the machine running the scan, its dashboard, or an address that reaches only that machine's own environment (such as its cloud metadata service). Nothing was sent to it."
	if errors.Is(err, errUnresolved) {
		msg = "Forbidden: the name does not resolve on the machine running the scan, so the local-network guard could not check it. Nothing was sent."
	}
	http.Error(w, msg+notFromTarget, http.StatusForbidden)
}

// guardedBadGateway answers a guarded request whose connection failed, naming
// the kind of failure (and nothing about addresses) and logging the details
// for the operator.
func guardedBadGateway(w http.ResponseWriter, address string, err error) {
	log.Printf("[proxy] guarded connection to %q failed: %v", address, err)
	http.Error(w, "Bad gateway: could not connect to the destination ("+connectFailure(err)+")."+notFromTarget, http.StatusBadGateway)
}

// upstreamStatusError is an upstream proxy's non-200 answer to CONNECT.
type upstreamStatusError struct{ code int }

func (e *upstreamStatusError) Error() string {
	return fmt.Sprintf("upstream CONNECT returned HTTP %d", e.code)
}

// connectFailure names the kind of a connection failure in a few words.
func connectFailure(err error) string {
	var dnsErr *net.DNSError
	var status *upstreamStatusError
	var netErr net.Error
	switch {
	case errors.As(err, &status):
		return "the upstream proxy refused the connection"
	case errors.As(err, &dnsErr):
		return "the name does not resolve"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &netErr) && netErr.Timeout():
		return "timed out"
	default:
		return "connection failed"
	}
}

// tunnelSet tracks the connections of open CONNECT tunnels so a closing
// proxy can end them. A nil set tracks nothing.
type tunnelSet struct {
	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed bool
}

// add registers conns, or closes them and reports false if the set is
// already closed.
func (t *tunnelSet) add(conns ...net.Conn) bool {
	if t == nil {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		for _, c := range conns {
			_ = c.Close()
		}
		return false
	}
	for _, c := range conns {
		t.conns[c] = struct{}{}
	}
	return true
}

func (t *tunnelSet) remove(conns ...net.Conn) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, c := range conns {
		delete(t.conns, c)
	}
}

func (t *tunnelSet) closeAll() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	for c := range t.conns {
		_ = c.Close()
	}
	t.conns = map[net.Conn]struct{}{}
}
