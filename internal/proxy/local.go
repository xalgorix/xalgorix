package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	xproxy "golang.org/x/net/proxy"
)

// LocalURL returns an unauthenticated, loopback-only HTTP proxy which forwards
// through the configured upstream. Chromium and common CLI tools cannot all
// consume authenticated upstream proxy URLs directly, so this bridge keeps
// credentials out of their command lines. It never connects directly to a
// requested destination when the upstream is unavailable.
func LocalURL() (string, error) {
	m := defaultManager.Load()
	if m == nil || !m.required || !m.enabled || m.pool == nil || m.pool.Len() != 1 {
		return "", fmt.Errorf("local proxy requires one initialized, required upstream")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return "", fmt.Errorf("local proxy manager is closed")
	}
	m.localOnce.Do(func() {
		upstream := m.pool.proxies[0]
		upstreamURL, err := upstream.URL()
		if err != nil {
			m.localErr = fmt.Errorf("invalid upstream proxy: %w", err)
			return
		}
		tr := clonedDefaultTransport()
		tr.Proxy = http.ProxyURL(upstreamURL)
		m.localTransport = tr
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			m.localErr = fmt.Errorf("listen on loopback: %w", err)
			return
		}
		m.localURL = "http://" + ln.Addr().String()
		m.localListener = ln
		srv := &http.Server{
			Handler:           &localHandler{upstream: upstream, transport: tr},
			ReadHeaderTimeout: 10 * time.Second,
		}
		m.localServer = srv
		go func() { _ = srv.Serve(ln) }()
	})
	return m.localURL, m.localErr
}

// hopByHopHeaders lists headers that must not be forwarded by a proxy (RFC 7230 Section 6.1).
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Trailers",
	"Transfer-Encoding",
	"Upgrade",
}

func removeHopByHopHeaders(h http.Header) {
	for _, val := range h["Connection"] {
		for _, token := range strings.Split(val, ",") {
			if token = strings.TrimSpace(token); token != "" {
				h.Del(token)
			}
		}
	}
	for _, hdr := range hopByHopHeaders {
		h.Del(hdr)
	}
}

type localHandler struct {
	// upstream is the proxy the unguarded required-proxy bridge (LocalURL)
	// forwards every request through; a guarded handler uses fixed or
	// routes instead.
	upstream *Proxy
	// transport sends plain-HTTP requests: through upstream for the bridge,
	// directly (with the guard's dial-time check) for a guarded handler.
	transport *http.Transport
	// guard, when non-nil, refuses destinations (see StartGuardedLocal).
	guard GuardFunc
	// fixed is the upstream a guarded handler forwards everything through,
	// or nil.
	fixed *upstreamRoute
	// proxyFor, for a guarded handler without fixed, picks a proxy per
	// destination (GuardedOptions.Proxy); routes caches one route per proxy
	// it picks.
	proxyFor     func(*http.Request) (*url.URL, error)
	routesMu     sync.Mutex
	routes       map[string]*upstreamRoute
	routesClosed bool
	// exempt lists the host:port CONNECT destinations a guarded handler
	// dials directly, without the guard or an upstream.
	exempt map[string]bool
	// tunnels, when non-nil, tracks open CONNECT tunnels so Close can end
	// them.
	tunnels *tunnelSet
}

func (h *localHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		h.serveConnect(w, r)
		return
	}
	if r.URL == nil || !r.URL.IsAbs() {
		http.Error(w, "absolute URL required", http.StatusBadRequest)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Header = r.Header.Clone()
	removeHopByHopHeaders(out.Header)
	transport := h.transport
	target := requestHostPort(r.URL)
	if h.guard != nil {
		if err := h.guard(target); err != nil {
			refuseDestination(w, target, err)
			return
		}
		route, err := h.routeFor(strings.ToLower(r.URL.Scheme), target)
		if err != nil {
			guardedBadGateway(w, target, err)
			return
		}
		if route != nil {
			transport = route.transport
		}
		if route != nil && route.onThisMachine {
			// Check every address the name resolves to (a name that does
			// not resolve is refused) and send the checked address. Through
			// a SOCKS5 upstream the connection goes to out.URL.Host while
			// the Host header keeps the name. An HTTP upstream would be sent
			// the name in the request line (net/http writes out.Host
			// there), so the checked address is put there instead. Any
			// other upstream is sent the request unchanged.
			pinned, err := h.resolveChecked(r.Context(), target)
			if err != nil {
				refuseDestination(w, target, err)
				return
			}
			out.URL.Host = pinned
			if route.proxy.Type != ProxyTypeSOCKS5 {
				path := r.URL.EscapedPath()
				if path == "" {
					path = "/"
				}
				// RequestURI() turns "//host/path" into scheme://host/path,
				// and net/http then writes it to the request line as is.
				out.URL.Opaque = "//" + pinned + path
			}
		}
	}
	resp, err := transport.RoundTrip(out)
	if err != nil {
		var refused *refusedDestinationError
		if errors.As(err, &refused) {
			refuseDestination(w, refused.address, refused.err)
			return
		}
		if h.guard != nil {
			guardedBadGateway(w, target, err)
			return
		}
		http.Error(w, "upstream proxy request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	removeHopByHopHeaders(resp.Header)
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	copyFlushing(w, resp.Body)
}

// copyFlushing copies a response body to w, flushing after every read so
// streamed responses (server-sent events, long polls) reach the client as
// they arrive.
func copyFlushing(w http.ResponseWriter, body io.Reader) {
	rc := http.NewResponseController(w)
	buf := make([]byte, 32*1024)
	for {
		n, err := body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			_ = rc.Flush()
		}
		if err != nil {
			return
		}
	}
}

func (h *localHandler) serveConnect(w http.ResponseWriter, r *http.Request) {
	if _, _, err := net.SplitHostPort(r.Host); err != nil {
		http.Error(w, "CONNECT host:port required", http.StatusBadRequest)
		return
	}
	upstreamConn, upstreamReader, err := h.dialConnect(r.Context(), r.Host)
	if err != nil {
		var refused *refusedDestinationError
		if errors.As(err, &refused) {
			refuseDestination(w, refused.address, refused.err)
			return
		}
		if h.guard != nil {
			guardedBadGateway(w, r.Host, err)
			return
		}
		http.Error(w, "upstream proxy CONNECT failed", http.StatusBadGateway)
		return
	}
	defer func() { _ = upstreamConn.Close() }()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "HTTP hijacking unavailable", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = clientConn.Close() }()
	if !h.tunnels.add(clientConn, upstreamConn) {
		return
	}
	defer h.tunnels.remove(clientConn, upstreamConn)
	if _, err := io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if h.tunnels == nil {
		// The required-proxy bridge serves CLI tools, some of which
		// half-close after sending and then read the reply.
		go func() {
			_, _ = io.Copy(upstreamConn, clientBuffer)
			if tcp, ok := upstreamConn.(*net.TCPConn); ok {
				_ = tcp.CloseWrite()
			}
		}()
		_, _ = io.Copy(clientConn, upstreamReader)
		return
	}
	// Guarded tunnels carry a browser's traffic to untrusted peers: when
	// either side finishes, close both (the deferred Closes), so a peer
	// that never closes its end cannot hold the tunnel open.
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstreamConn, clientBuffer)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, upstreamReader)
		done <- struct{}{}
	}()
	<-done
}

// dialThroughUpstream opens a connection to target through proxy p. The TCP
// connection to p gets 15 seconds and the exchange after it (the CONNECT
// request and reply, or the SOCKS5 handshake) is bounded by
// upstreamHandshakeTimeout, so a stalled upstream cannot hold the caller.
func dialThroughUpstream(ctx context.Context, p *Proxy, target string) (net.Conn, io.Reader, error) {
	proxyAddress := net.JoinHostPort(p.Host, p.Port)
	if p.Type == ProxyTypeSOCKS5 {
		var auth *xproxy.Auth
		if p.Username != "" {
			auth = &xproxy.Auth{User: p.Username, Password: p.Password}
		}
		dialer, err := xproxy.SOCKS5("tcp", proxyAddress, auth, &net.Dialer{Timeout: 15 * time.Second})
		if err != nil {
			return nil, nil, err
		}
		cd, ok := dialer.(xproxy.ContextDialer)
		if !ok {
			return nil, nil, errors.New("SOCKS5 dialer does not support deadlines")
		}
		// The SOCKS5 dialer applies the context's deadline to the
		// handshake and clears it once the connection is established, so
		// the TCP connect and the handshake together get
		// upstreamHandshakeTimeout.
		ctx, cancel := context.WithTimeout(ctx, upstreamHandshakeTimeout)
		defer cancel()
		conn, err := cd.DialContext(ctx, "tcp", target)
		if err != nil {
			return nil, nil, err
		}
		return conn, conn, nil
	}
	var conn net.Conn
	var err error
	if p.Type == ProxyTypeHTTPS {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", proxyAddress, &tls.Config{ServerName: p.Host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", proxyAddress)
	}
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(upstreamHandshakeTimeout))
	var request strings.Builder
	fmt.Fprintf(&request, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if p.Username != "" {
		credentials := base64.StdEncoding.EncodeToString([]byte(p.Username + ":" + p.Password))
		fmt.Fprintf(&request, "Proxy-Authorization: Basic %s\r\n", credentials)
	}
	request.WriteString("\r\n")
	if _, err := io.WriteString(conn, request.String()); err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, nil, &upstreamStatusError{code: resp.StatusCode}
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, reader, nil
}
