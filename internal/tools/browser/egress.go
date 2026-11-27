package browser

import (
	"fmt"
	"net/http"

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

// egressUpstream returns the proxy a guarded browser's traffic is forwarded
// through after the guard's checks, or nil when there is none. In
// proxy-required mode that is the operator's required upstream itself (the
// guard proxy speaks to it directly, so its credentials never reach
// Chromium's arguments). Whether the upstream runs on this machine, and so
// must be handed checked addresses rather than names, is decided by the
// guard proxy (see egressproxy.StartGuardedLocal).
func egressUpstream(proxy string, required bool) (*egressproxy.Proxy, error) {
	if required {
		p := egressproxy.GetProxy()
		if p == nil {
			return nil, fmt.Errorf("required browser proxy unavailable")
		}
		return p, nil
	}
	raw := browserUpstreamProxy(proxy)
	if raw == "" {
		return nil, nil
	}
	p, err := egressproxy.Parse(raw)
	if err != nil {
		// Do not echo the value: a proxy URL may carry credentials.
		return nil, fmt.Errorf("invalid browser proxy setting")
	}
	return p, nil
}

// startEgressGuard starts the loopback proxy a guarded browser sends all of
// its traffic through. Each destination is checked with guard before any
// connection is made; on a direct connection the proxy also checks the
// address it dials after DNS resolution. Without an upstream the proxy
// follows HTTP_PROXY, HTTPS_PROXY and NO_PROXY, as http_request does and as
// Chromium would without a --proxy-server, so a host whose only way out is an
// environment-configured proxy keeps a working browser. bridgeAddr, when
// set, is the extension bridge's loopback address, which the embedded
// extension must still reach; the bridge itself admits only the extension
// (checkBridgeOrigin).
func startEgressGuard(up *egressproxy.Proxy, guard tools.DialGuard, bridgeAddr string) (*egressproxy.GuardedLocal, error) {
	opts := egressproxy.GuardedOptions{}
	if up == nil {
		opts.Proxy = http.ProxyFromEnvironment
	}
	if bridgeAddr != "" {
		opts.Exempt = append(opts.Exempt, bridgeAddr)
	}
	return egressproxy.StartGuardedLocal(up, egressproxy.GuardFunc(guard), opts)
}
