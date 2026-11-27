package browser

import (
	"fmt"

	egressproxy "github.com/xalgord/xalgorix/v4/internal/proxy"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// bindDialGuard records a registry's dial guard (the scan's local-network
// guard, the one http_request and send_request apply to every connection) on
// the scan's browser store, so the browser this scan launches routes every
// connection through it. The agent's argument checks only see the URL a
// browser_action call names; redirects, subresources, scripts and WebSockets
// the page itself opens never pass through them. The caller holds the store's
// action lock (withBrowserTransportRecovery), so CleanupContext cannot swap
// the store between binding and launch. A nil guard leaves the store
// unchanged.
func bindDialGuard(ctxID string, guard tools.DialGuard) {
	if guard == nil {
		return
	}
	s := getBrowserStoreByID(ctxID)
	s.mu.Lock()
	s.dialGuard = guard
	s.mu.Unlock()
}

// browserUpstreamProxy returns the proxy URL Chromium is to use for a
// browser_action proxy argument, or "" for a direct connection.
func browserUpstreamProxy(proxy string) string {
	switch proxy {
	case "", "none":
		return ""
	case "caido":
		return fmt.Sprintf("http://127.0.0.1:%d", detectCaidoPort())
	default:
		return proxy
	}
}

// startEgressGuard starts the loopback proxy a guarded browser sends all of
// its traffic through. Each destination is checked with guard before any
// connection is made; with no upstream the proxy also checks the address each
// connection dials after DNS resolution. bridgeAddr, when set, is the
// extension bridge's loopback address, which the embedded extension must
// still reach; the bridge itself admits only the extension (checkBridgeOrigin).
func startEgressGuard(upstream string, guard tools.DialGuard, bridgeAddr string) (*egressproxy.GuardedLocal, error) {
	var up *egressproxy.Proxy
	if upstream != "" {
		p, err := egressproxy.Parse(upstream)
		if err != nil {
			// Do not echo the value: a proxy URL may carry credentials.
			return nil, fmt.Errorf("invalid browser proxy setting")
		}
		up = p
	}
	var exempt []string
	if bridgeAddr != "" {
		exempt = append(exempt, bridgeAddr)
	}
	return egressproxy.StartGuardedLocal(up, egressproxy.GuardFunc(guard), exempt...)
}
