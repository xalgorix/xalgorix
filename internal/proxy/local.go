package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
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
	// upstream is the proxy every request is forwarded through. It is nil
	// only for a guarded handler that connects to destinations itself.
	upstream  *Proxy
	transport *http.Transport
	// guard, when non-nil, refuses destinations (see StartGuardedLocal).
	guard GuardFunc
	// exempt lists the host:port CONNECT destinations a guarded handler
	// dials directly, without the guard or the upstream.
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
	if h.guard != nil {
		target := requestHostPort(r.URL)
		if err := h.guard(target); err != nil {
			refuseDestination(w)
			return
		}
		if h.upstream != nil {
			// Check every address the name resolves to (a name that does
			// not resolve is refused), and connect to the checked address
			// where the route allows it: through a SOCKS5 upstream the
			// connection goes to out.URL.Host while the Host header keeps
			// the name. An HTTP upstream is sent the name in the request
			// line (net/http writes out.Host there), so for plain HTTP
			// through an HTTP proxy that proxy resolves the name again.
			pinned, err := h.resolveChecked(r.Context(), target)
			if err != nil {
				refuseDestination(w)
				return
			}
			out.URL.Host = pinned
		}
	}
	resp, err := h.transport.RoundTrip(out)
	if err != nil {
		var refused *refusedDestinationError
		if errors.As(err, &refused) {
			refuseDestination(w)
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
			refuseDestination(w)
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
	// When either side finishes, close both (the deferred Closes), so a
	// peer that never closes its end cannot hold the tunnel open.
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

func (h *localHandler) dialThroughUpstream(target string) (net.Conn, io.Reader, error) {
	p := h.upstream
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
		conn, err := dialer.Dial("tcp", target)
		return conn, conn, err
	}
	var conn net.Conn
	var err error
	if p.Type == ProxyTypeHTTPS {
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", proxyAddress, &tls.Config{ServerName: p.Host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = net.DialTimeout("tcp", proxyAddress, 15*time.Second)
	}
	if err != nil {
		return nil, nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
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
		return nil, nil, fmt.Errorf("upstream CONNECT returned HTTP %d", resp.StatusCode)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, reader, nil
}
