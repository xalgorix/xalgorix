package proxy

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Manager is the central proxy manager used by the rest of the application.
// It is initialized once via Init() and then accessed through the package-level
// helpers GetClient() / GetProxy().
//
// FIX (Gemini HIGH): the Manager now holds a single shared *http.Client per
// proxy slot instead of creating a new Transport on every call. This allows
// Go's http.Transport to reuse idle TCP connections (Keep-Alive) and avoids
// socket exhaustion under load.
type Manager struct {
	enabled        bool
	pool           *Pool
	rotation       string // "roundrobin" | "random"
	required       bool
	timeout        time.Duration
	client         *http.Client // shared client used when proxy routing is disabled
	mu             sync.Mutex   // guards the loopback listener and closed state
	closed         bool
	localOnce      sync.Once
	localURL       string
	localErr       error
	localListener  net.Listener
	localServer    *http.Server
	localTransport *http.Transport
}

var defaultManager atomic.Pointer[Manager]

// Init initializes the package-level Manager from explicit parameters.
// Call this once at startup (e.g. from main or server init).
//
//	useProxy   – enable proxy routing
//	proxyURL   – single proxy string (takes precedence over proxyFile)
//	proxyFile  – path to a file with one proxy per line
//	rotation   – "roundrobin" or "random"
//	timeout    – per-request timeout
func Init(useProxy bool, proxyURL, proxyFile, rotation string, timeout time.Duration) error {
	return InitWithPolicy(useProxy, false, proxyURL, proxyFile, rotation, timeout)
}

// InitWithPolicy enables the optional proxy-required mode. That mode accepts
// exactly one upstream proxy so a scan cannot switch egress IP mid-session.
// Proxy-required mode covers Xalgorix's built-in HTTP and browser paths;
// arbitrary subprocesses additionally need OS-level egress isolation.
func InitWithPolicy(useProxy, required bool, proxyURL, proxyFile, rotation string, timeout time.Duration) error {
	if required && (!useProxy || proxyURL == "") {
		return fmt.Errorf("proxy-required mode needs XALGORIX_USE_PROXY=true and XALGORIX_PROXY_URL")
	}
	m := &Manager{
		enabled:  useProxy,
		required: required,
		rotation: rotation,
		timeout:  timeout,
	}

	if useProxy {
		switch {
		case proxyURL != "":
			m.pool = NewPool([]string{proxyURL})
		case proxyFile != "":
			pool, err := LoadFile(proxyFile)
			if err != nil {
				return fmt.Errorf("proxy manager: %w", err)
			}
			m.pool = pool
		default:
			fmt.Fprintf(os.Stderr, "[proxy] USE_PROXY=true but no PROXY_URL or PROXY_FILE set — running without proxy\n")
			m.enabled = false
		}

		if m.pool != nil && m.pool.Len() == 0 {
			if required {
				return fmt.Errorf("proxy-required mode has no valid upstream proxy")
			}
			fmt.Fprintf(os.Stderr, "[proxy] proxy list is empty — running without proxy\n")
			m.enabled = false
		}
	}
	if required && (m.pool == nil || m.pool.Len() != 1) {
		return fmt.Errorf("proxy-required mode needs exactly one valid upstream proxy")
	}

	// Pre-build a shared no-proxy client (inherits DefaultTransport).
	// Used when proxy routing is disabled so behavior is truly zero-impact.
	noProxyTransport, _ := NewTransport(nil)
	m.client = &http.Client{
		Transport: noProxyTransport,
		Timeout:   m.timeoutOrDefault(),
	}

	if old := defaultManager.Swap(m); old != nil {
		_ = old.Close()
	}
	return nil
}

// Enabled reports whether proxy routing is active.
func Enabled() bool {
	m := defaultManager.Load()
	return m != nil && m.enabled
}

// Required reports whether the process was initialized in proxy-required mode.
func Required() bool {
	m := defaultManager.Load()
	return m != nil && m.required
}

// GetProxy returns the next proxy according to the configured rotation strategy.
// Returns nil when proxy routing is disabled or the pool is empty.
func GetProxy() *Proxy {
	m := defaultManager.Load()
	if m == nil || !m.enabled || m.pool == nil {
		return nil
	}
	if m.rotation == "random" {
		return m.pool.Random()
	}
	return m.pool.Next()
}

// GetClient returns an *http.Client ready to use for the next request.
//
// FIX (Gemini HIGH): instead of constructing a brand-new Transport on every
// call (which breaks TCP connection reuse), we now:
//   - Return the shared no-proxy client directly when proxying is disabled.
//   - Build one Transport per proxy entry (cached in the Proxy struct) when
//     proxying is enabled, so connections to the same proxy are reused.
func GetClient() (*http.Client, error) {
	m := defaultManager.Load()
	if m == nil {
		// Callers configured for proxy-required mode must also check their
		// configuration before using this legacy no-manager fallback.
		return http.DefaultClient, nil
	}
	m.mu.Lock()
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return nil, fmt.Errorf("proxy manager is closed")
	}
	if !m.enabled {
		// Return the pre-built shared client — zero extra allocation.
		return m.client, nil
	}
	var p *Proxy
	if m.pool != nil {
		if m.rotation == "random" {
			p = m.pool.Random()
		} else {
			p = m.pool.Next()
		}
	}
	if p == nil {
		if m.required {
			return nil, fmt.Errorf("proxy-required mode has no upstream proxy")
		}
		return m.client, nil
	}
	return NewClient(p, m.timeoutOrDefault())
}

// GetClientFor returns an *http.Client wired to the given proxy string.
// Useful when the caller wants to pin a specific proxy for a request sequence.
func GetClientFor(rawProxy string) (*http.Client, error) {
	p, err := Parse(rawProxy)
	if err != nil {
		return nil, err
	}
	return NewClient(p, defaultManager.Load().timeoutOrDefault())
}

func (m *Manager) timeoutOrDefault() time.Duration {
	if m == nil || m.timeout == 0 {
		return 30 * time.Second
	}
	return m.timeout
}

// Close shuts down the manager, releases any background loopback proxy server,
// and closes idle connections in cached transports.
func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	var firstErr error
	if m.localServer != nil {
		if err := m.localServer.Close(); err != nil {
			firstErr = err
		}
		m.localServer = nil
	}
	// Serve may not have started yet, in which case http.Server.Close has
	// not registered the listener and cannot close it for us.
	if m.localListener != nil {
		_ = m.localListener.Close()
		m.localListener = nil
	}
	m.localURL = ""
	// Never reset a sync.Once while LocalURL may still be using it. A closed
	// manager is terminal; InitWithPolicy constructs a fresh manager instead.
	if m.localTransport != nil {
		m.localTransport.CloseIdleConnections()
		m.localTransport = nil
	}
	if m.client != nil {
		m.client.CloseIdleConnections()
	}
	return firstErr
}

// Close shuts down the package-level default proxy manager and any background loopback proxy.
func Close() error {
	return defaultManager.Swap(nil).Close()
}

// Reset clears the package-level manager.
func Reset() {
	_ = Close()
}
