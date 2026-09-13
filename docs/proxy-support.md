# Proxy Support

Xalgorix supports **HTTP**, **HTTPS**, and **SOCKS5** upstream proxies for its built-in HTTP tools. Proxy-required mode also routes its browser and gives proxy-aware terminal/Python programs a loopback HTTP proxy. An HTTP/SOCKS5 proxy is not a whole-machine VPN: arbitrary subprocesses, raw sockets, ICMP, and UDP may bypass proxy environment variables. Enforce an OS/container outbound policy if the operator needs a guarantee that no direct target connection can leave the host.

`scanner2.xalgorix.com` or any other dashboard DNS name is **inbound** configuration. Do not change its A/AAAA record to a purchased proxy IP; the proxy is only for outbound connections from the scanner.

## Quick Start

### Single proxy (environment variable)

```bash
# HTTP / HTTPS proxy — no auth
export XALGORIX_USE_PROXY=true
export XALGORIX_PROXY_URL="1.2.3.4:8080"

# HTTP / HTTPS proxy — with auth
export XALGORIX_USE_PROXY=true
export XALGORIX_PROXY_URL="1.2.3.4:8080:username:password"

# SOCKS5 proxy
export XALGORIX_USE_PROXY=true
export XALGORIX_PROXY_URL="socks5://10.0.0.1:1080"

# SOCKS5 with auth
export XALGORIX_USE_PROXY=true
export XALGORIX_PROXY_URL="socks5://user:pass@10.0.0.1:1080"
```

### Proxy-required mode for one static egress IP

```bash
export XALGORIX_USE_PROXY=true
export XALGORIX_PROXY_REQUIRED=true
export XALGORIX_PROXY_URL="http://USER:PASS@PROXY_HOST:PROXY_PORT"
```

Replace the placeholders with the proxy provider's actual host, port, and credentials. URL-encode reserved characters in the username/password and keep the environment file private. This mode requires exactly one `XALGORIX_PROXY_URL`; it does not rotate proxies within a scan. The browser and proxy-aware shell tools use an unauthenticated loopback bridge, so the upstream credentials are not placed in Chromium process arguments. The bridge never falls back to a direct target connection. Missing/invalid proxy configuration prevents startup; an unreachable upstream causes requests to fail.

Restart the scanner after changing proxy settings in the environment file or dashboard; active scans keep their existing process/network state. Validate the observed egress IP against an endpoint you control before starting an authorized scan. Keep the public `scanner2.xalgorix.com` DNS and inbound Cloudflare configuration unchanged.

This is **not** a complete no-leak mode for `terminal_execute` or `python_action`: their code may invoke tools that ignore `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` or use raw network protocols. Run the scanner under an independent egress policy that allows target-bound traffic only through the upstream proxy, or disable such tools for the proxy-required workload. Test the policy against a target you control before production use. Do not assume the existing proxy environment variables alone provide this boundary.

### Proxy list with rotation

```bash
export XALGORIX_USE_PROXY=true
export XALGORIX_PROXY_FILE="/path/to/proxies.txt"
export XALGORIX_PROXY_ROTATION="roundrobin"   # or "random"
```

See `proxies.txt.example` for the file format.

## Configuration Reference

| Environment Variable      | Default        | Description                                                  |
|---------------------------|----------------|--------------------------------------------------------------|
| `XALGORIX_USE_PROXY`      | `false`        | Set to `true` to enable proxy routing                        |
| `XALGORIX_PROXY_REQUIRED` | `false`        | Require one upstream proxy for built-in HTTP/browser paths; no direct fallback for those paths |
| `XALGORIX_PROXY_URL`      | _(empty)_      | Single proxy string; takes precedence over `PROXY_FILE`      |
| `XALGORIX_PROXY_FILE`     | _(empty)_      | Path to a file with one proxy per line                       |
| `XALGORIX_PROXY_ROTATION` | `roundrobin`   | Rotation strategy: `roundrobin` or `random`                  |

All variables can also be placed in `~/.xalgorix.env`.

## Proxy String Formats

| Format                           | Type   | Auth |
|----------------------------------|--------|------|
| `ip:port`                        | HTTP   | No   |
| `ip:port:user:pass`              | HTTP   | Yes  |
| `socks5://ip:port`               | SOCKS5 | No   |
| `socks5://user:pass@ip:port`     | SOCKS5 | Yes  |
| `http://ip:port`                 | HTTP   | No   |
| `http://user:pass@ip:port`       | HTTP   | Yes  |

## How It Works

1. At startup, `proxy.Init()` is called with the values from `config.Config`.
2. Every call to `proxy.GetClient()` returns an `*http.Client` pre-configured with the next proxy in the pool.
3. If the pool is empty or `USE_PROXY=false`, a plain client is returned in normal mode. Proxy-required mode rejects missing or invalid configuration.
4. The `Pool` is goroutine-safe; rotation state is protected by a mutex.

## Adding Proxy Support to New Code

```go
import "github.com/xalgord/xalgorix/v4/internal/proxy"

// Get a client for the next proxy in the rotation
client, err := proxy.GetClient()
if err != nil {
    return err
}
resp, err := client.Get(targetURL)
```

Or pin a specific proxy:

```go
client, err := proxy.GetClientFor("socks5://10.0.0.1:1080")
```
