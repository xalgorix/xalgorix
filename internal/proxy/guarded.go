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
	"strings"
	"sync"
	"syscall"
	"time"
)

// GuardFunc reports why a connection to address must not be made, or nil when
// it may. address is "host:port"; host is a name or an IP address. The
// guarded proxy calls it with the destination as requested and again with
// every IP address that destination resolves to, so a guard that only knows
// how to classify addresses still sees each one.
type GuardFunc func(address string) error

// guardedDialTimeout and guardedKeepAlive match http.DefaultTransport's dialer.
const (
	guardedDialTimeout = 30 * time.Second
	guardedKeepAlive   = 30 * time.Second
)

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
	url       string
	server    *http.Server
	transport *http.Transport
	tunnels   *tunnelSet
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
// is still refused.
//
// With an upstream the proxy resolves the destination itself and checks
// every address it resolves to; a name that does not resolve here is
// refused, so a name only the upstream can resolve is not reachable. CONNECT
// tunnels (HTTPS, WebSocket) are then requested from the upstream for the
// checked address rather than the name, so the upstream cannot resolve the
// name to something else; TLS SNI and the Host header still carry the name.
// Plain-HTTP requests are pinned the same way through a SOCKS5 upstream; an
// HTTP upstream receives the name in the request line and resolves it again
// unless opts.PinPlainHTTP is set.
func StartGuardedLocal(upstream *Proxy, guard GuardFunc, opts GuardedOptions) (*GuardedLocal, error) {
	if guard == nil {
		return nil, errors.New("guarded local proxy needs a guard")
	}
	tr := clonedDefaultTransport()
	if upstream != nil {
		upstreamURL, err := upstream.URL()
		if err != nil {
			return nil, fmt.Errorf("invalid upstream proxy: %w", err)
		}
		tr.Proxy = http.ProxyURL(upstreamURL)
	} else {
		tr.Proxy = nil
		tr.DialContext = guardedDialer(guard).DialContext
	}
	h := &localHandler{
		upstream:     upstream,
		transport:    tr,
		guard:        guard,
		exempt:       map[string]bool{},
		tunnels:      &tunnelSet{conns: map[net.Conn]struct{}{}},
		pinPlainHTTP: opts.PinPlainHTTP && upstream != nil,
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
	return &GuardedLocal{url: "http://" + ln.Addr().String(), server: srv, transport: tr, tunnels: h.tunnels}, nil
}

// GuardedOptions adjusts a GuardedLocal.
type GuardedOptions struct {
	// Exempt lists host:port CONNECT destinations that are dialed directly
	// without the guard or the upstream, for a loopback service the client
	// must reach (a browser extension's channel back to this process).
	// Plain-HTTP requests to them are still guarded.
	Exempt []string
	// PinPlainHTTP sends plain-HTTP requests to an HTTP upstream with the
	// checked address in the request line, keeping the name in the Host
	// header, so the upstream cannot resolve the name to a different
	// address. Set it for an intercepting proxy on this machine (Caido,
	// Burp), whose own name lookups could otherwise be steered to this
	// machine. Leave it off for a proxy that follows RFC 7230 strictly: it
	// replaces the Host header with the request-line host.
	PinPlainHTTP bool
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
	g.tunnels.closeAll()
	g.transport.CloseIdleConnections()
	return err
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
		return h.dialThroughUpstream(target)
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
	if h.upstream != nil {
		pinned, err := h.resolveChecked(ctx, target)
		if err != nil {
			return nil, nil, err
		}
		return h.dialThroughUpstream(pinned)
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

// refuseDestination answers a request the guard refused and logs why for the
// operator. Nothing was sent to the destination. The body is deliberately
// generic: the page that made the request can read it, and should learn
// nothing about this machine from it.
func refuseDestination(w http.ResponseWriter, address string, err error) {
	log.Printf("[proxy] refused a guarded connection to %q: %v", address, err)
	http.Error(w, "Forbidden: destination blocked by network policy", http.StatusForbidden)
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
