---
name: websocket-api-security
description: WebSocket API security testing — upgrade authentication and Origin/CSWSH hijacking, per-message authorization bypass, frame injection, token lifecycle on reconnect, and unthrottled resource consumption on the WS path
intent: offensive
protocol: websocket
---

# WebSocket API Security

## Purpose
Test real-time WebSocket APIs for handshake authorization gaps (CSWSH), message-level authorization bypass, injection inside frames, and resource-consumption weaknesses specific to the WS path.

## Preconditions
- An identified WebSocket endpoint (ws:// or wss://)
- Client tooling: Python `websockets`/`websockify`, wscat, or a raw socket script
- The victim/attacker session contexts needed for differential tests

## Attack Surface Signals
- Upgrade requests (`Connection: Upgrade`, `Sec-WebSocket-Key`)
- wss:// URLs in JavaScript bundles (often with tokens in query strings)
- Socket.io / SockJS / GraphQL-over-WS endpoints
- Channels/rooms/topics in the message protocol

## Methodology

### Step 1: Handshake and Origin (CSWSH)
```bash
# Does the server validate Origin on upgrade? Cookie-auth sockets that skip
# validation are hijackable cross-site.
for origin in "https://target.com" "https://evil.com" "null" "https://target.com.evil.com"; do
  curl -sk -i -N "https://TARGET/socket" \
    -H "Connection: Upgrade" -H "Upgrade: websocket" \
    -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
    -H "Origin: $origin" | head -1
done
```
CSWSH confirmed when a connection bearing a foreign/absent Origin still receives the victim's real-time data (i.e., a cookie-authenticated session usable from attacker-controlled origins).

### Step 2: Per-Message Authorization
```python
# Auth often enforced ONLY at upgrade. Connect legitimately, then:
# - subscribe to channels/rooms belonging to another user
# - request objects by ID you do not own (BOLA over WS)
# - send admin-style messages (BFLA over WS)
import asyncio, websockets, json
async def attack():
    async with websockets.connect("wss://TARGET/socket", extra_headers={"Authorization":"Bearer LOW"}) as ws:
        await ws.send(json.dumps({"action":"subscribe","channel":"admin-alerts"}))
        print(await asyncio.wait_for(ws.recv(), 5))
asyncio.run(attack())
```
A finding requires another user's/channel's real data returned in frames — never just an ACK.

### Step 3: Token Lifecycle on the WS Path
- Upgrade with an expired/invalid token; does the server accept and only fail later?
- After token expiry mid-session: do live connections keep privileged subscriptions?
- Reconnect: does re-handshake re-validate, or inherit the old session's rights?

### Step 4: Injection Inside Frames
```text
JSON message fields are injection sinks that bypass HTTP WAFs and rate limits:
  - SQL/NoSQL into query-like fields
  - XSS into broadcast/echo/presence fields (stored then rendered)
  - command injection into server-side action fields
  - prototype pollution via __proto__ keys
Confirm with the same evidence contracts as HTTP (differential/OOB), not frame errors alone.
```

### Step 5: Resource Consumption on the WS Path
- Message flooding: sustained send rate without server-side backpressure/limits
- Oversized frames: single frames near/over buffer limits
- Connection exhaustion: open many parallel connections; quota enforced or not
- Subscription fan-out: subscribe to hundreds of channels; server memory/CPU impact
- Unvalidated binary frames / decompression bombs (permessage-deflate)
Measure: baseline behavior vs sustained load — a finding requires the server processing beyond its control, or verifiable degradation, not just "no rate limit header".

## Evidence Contract
- **CSWSH**: foreign-origin connection receives authenticated victim data
- **Authorization bypass**: frames return another user/channel's actual data
- **Injection**: payload effect proven in downstream context (stored render, query result, OOB callback)
- **Resource abuse**: baseline vs load differential with the server demonstrably losing control or capacity

**NOT evidence**: a successful upgrade alone, an ACK message, frame parse errors, no visible WS rate limit without load measurement

## Common Misses
- Only handshake tested; message-level authorization never probed
- Origin not tested with `null` and subdomain variants
- Expired-token reconnection never tested
- wss terminated at a proxy with different (weaker) checks than the app
- Socket.io fallback transports (XHR-polling) bypass WS-specific logic
- GraphQL subscriptions with weaker field authorization than HTTP queries

## False Positives / Non-Findings
- Foreign Origin rejected at 403 (validation working)
- Receiving only public broadcast data on a hijackable socket
- Parse errors for malformed JSON (validation working)
- Backpressure applied (server closes slow consumers — control working)

## Xalgorix Tool Strategy
- `terminal_execute` with Python websockets for scripted frame exchange
- `browser_action` for cross-origin PoCs against cookie-authenticated sessions
- `http_request` for the upgrade handshake itself
- api-bola/api-bfla/api-injection evidence contracts apply to their frame-based equivalents

## Stopping Rule
Every WS endpoint x every Origin variant x message-level authorization x token lifecycle stage, plus load tests where volume is authorized by the runtime policy.

## Handoff
Report endpoint, the bypass class (CSWSH, message authz, injection, resource), the exact frames sent, and the authenticated data or impact received. Chain frame-based BOLA/BFLA into the corresponding API skills for deeper REST-side follow-up.