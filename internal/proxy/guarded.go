package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// GuardFunc reports why a connection to address must not be made, or nil when
// it may. address is "host:port"; host is a name or an IP address. When the
// guarded proxy connects directly it calls the guard twice: once with the
// destination as requested and once with the IP address each connection
// actually dials, after DNS resolution.
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
}

// StartGuardedLocal starts a GuardedLocal on an ephemeral loopback port.
//
// Every plain-HTTP request and every CONNECT tunnel (HTTPS, WebSocket) is
// checked with guard before anything is sent; a refused destination gets a
// 403 and no connection is made. With a nil upstream the proxy connects to
// destinations itself and also checks the address each connection dials, so
// a name that resolves to a refused address at connection time (DNS
// rebinding) is still refused. With an upstream, requests are forwarded
// through it and only the first check applies: the upstream resolves and
// connects to the destination.
//
// exempt lists host:port CONNECT destinations that are dialed directly
// without the guard or the upstream, for a loopback service the client must
// reach (a browser extension's channel back to this process). Plain-HTTP
// requests to them are still guarded.
func StartGuardedLocal(upstream *Proxy, guard GuardFunc, exempt ...string) (*GuardedLocal, error) {
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
	h := &localHandler{upstream: upstream, transport: tr, guard: guard, exempt: map[string]bool{}}
	for _, address := range exempt {
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
	return &GuardedLocal{url: "http://" + ln.Addr().String(), server: srv, transport: tr}, nil
}

// URL is the proxy's address, for example http://127.0.0.1:41234.
func (g *GuardedLocal) URL() string {
	if g == nil {
		return ""
	}
	return g.url
}

// Close stops accepting connections. Open CONNECT tunnels end when their
// client closes them.
func (g *GuardedLocal) Close() error {
	if g == nil {
		return nil
	}
	err := g.server.Close()
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
func (h *localHandler) dialConnect(target string) (net.Conn, io.Reader, error) {
	if h.guard == nil {
		return h.dialThroughUpstream(target)
	}
	if h.exempt[target] {
		conn, err := net.DialTimeout("tcp", target, guardedDialTimeout)
		if err != nil {
			return nil, nil, err
		}
		return conn, conn, nil
	}
	if err := h.guard(target); err != nil {
		return nil, nil, &refusedDestinationError{address: target, err: err}
	}
	if h.upstream != nil {
		return h.dialThroughUpstream(target)
	}
	conn, err := guardedDialer(h.guard).Dial("tcp", target)
	if err != nil {
		return nil, nil, err
	}
	return conn, conn, nil
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

// refuseDestination answers a request the guard refused. Nothing was sent to
// the destination.
func refuseDestination(w http.ResponseWriter, address string, err error) {
	http.Error(w, fmt.Sprintf("Xalgorix refused this connection: %s (%v)", address, err), http.StatusForbidden)
}
