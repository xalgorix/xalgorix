---
name: api-security-misconfiguration
description: Offensive testing for API security misconfigurations including verbose errors, debug endpoints, dangerous methods, CORS, and exposed management interfaces
intent: offensive
---

# API Security Misconfiguration (OWASP API8)

## Purpose
Test for API-level misconfigurations that expose attack surface, leak information, or enable unauthorized access.

## Preconditions
- A mapped API surface
- No requirement for authentication bypass (this tests the CONFIG, not the auth)

## Attack Surface Signals
- Verbose error messages in API responses
- Stack traces or framework debug pages
- HTTP 405 responses listing allowed methods
- CORS headers in responses
- OPTIONS/TRACE methods enabled
- Management/monitoring endpoints accessible

## Methodology

### Verbose Error Testing
```bash
# Send malformed requests — look for stack traces, SQL errors, internal paths
curl -sk "https://TARGET/api/nonexistent" | jq .
curl -sk -X POST "https://TARGET/api/users" -H "Content-Type: application/json" -d 'invalid'
curl -sk "https://TARGET/api/users?id=' OR 1=1--" | jq .
curl -sk -H "Content-Type: application/xml" -d '<root>' "https://TARGET/api/users" | head -20
```

Look for: framework names, versions, file paths, database errors, internal hostnames, stack traces.

### Debug/Admin Endpoint Discovery
```bash
for path in debug status health metrics actuator actuator/env actuator/heapdump \
  _debug __debug admin console management swagger api-docs v1/api-docs \
  graphql playground graphiql redoc api-docs/swagger.json .env config settings; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" "https://TARGET/$path")
  [ "$code" != "404" ] && [ "$code" != "000" ] && echo "[$code] /$path"
done
```

### Dangerous HTTP Methods
```bash
# Check which methods are allowed
curl -sk -X OPTIONS -i "https://TARGET/api/users" | grep -i allow

# Try dangerous methods on endpoints that should only accept GET/POST
for method in PUT DELETE PATCH TRACE TRACK; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X $method "https://TARGET/api/users")
  [ "$code" != "405" ] && [ "$code" != "404" ] && echo "[$method] $code"
done
```

### CORS Testing
```bash
# Check permissive origins
curl -sk -i "https://TARGET/api/users" \
  -H "Origin: https://evil.com" | grep -i "access-control"

# Check credentials with permissive CORS
curl -sk -i "https://TARGET/api/users" \
  -H "Origin: https://evil.com" | grep -iE "access-control-allow-(origin|credentials)"
```

**Evidence requirement**: Permissive CORS alone is a misconfiguration, but the finding's severity depends on what data the endpoint returns WITH credentials from another origin. Demonstrate impact.

### Content-Type Confusion
```bash
# Test alternate content types
curl -sk -H "Content-Type: text/xml" -d '<user><name>test</name></user>' "https://TARGET/api/users"
curl -sk -H "Content-Type: application/xml" -d '{"name":"test"}' "https://TARGET/api/users"
curl -sk -H "Content-Type: multipart/form-data" -F "name=test" "https://TARGET/api/users"
```

### Gateway vs Backend Inconsistencies
```bash
# Test if the gateway strips auth but the backend doesn't enforce it
# (or vice versa)
curl -sk "https://TARGET/api/v1/admin/users"          # through gateway
curl -sk "https://TARGET:8080/api/v1/admin/users"     # direct to backend (if port exposed)
```

### Default Credentials
```bash
# Common default credential patterns
for cred in "admin:admin" "admin:password" "api:api" "test:test" "user:user"; do
  user=$(echo $cred | cut -d: -f1)
  pass=$(echo $cred | cut -d: -f2)
  code=$(curl -sk -o /dev/null -w "%{http_code}" -u "$user:$pass" "https://TARGET/api/auth/login")
  [ "$code" = "200" ] && echo "[DEFAULT CRED] $cred works"
done
```

## Evidence Contract

- **Verbose errors**: Response contains stack trace, internal path, or framework version that materially aids exploitation
- **Debug endpoint**: Returns sensitive data (not just a 200)
- **CORS**: Permissive origin + credentials=true + the endpoint returns sensitive data
- **Dangerous methods**: DELETE/PUT/PATCH actually modifies state on an endpoint that shouldn't allow it
- **NOT evidence**: A 200 from a health check, OPTIONS listing methods (informational), a 405 (method properly blocked)

## Common Misses
- `.env` files exposed at the API root
- Kubernetes/consul/etcd endpoints accessible via the API domain
- HTTP TRACE enabled (reflects headers — XSS via headers)
- Inconsistent TLS enforcement (HTTP redirect to HTTPS, but API accepts HTTP)
- Backend services exposed on alternate ports

## False Positives / Non-Findings
- A health check endpoint returning 200 (intended)
- OPTIONS response listing methods (CORS preflight, intended)
- 405 Method Not Allowed (working as designed)
- Generic error message without internal details

## Xalgorix Tool Strategy
- `terminal_execute` with curl for precise endpoint probing
- `browser_action` for CORS verification in a browser context
- Python for batch endpoint enumeration

## Stopping Rule
Probe all discovered API paths with all methods, content types, and debug paths. Test CORS on data-bearing endpoints.

## Handoff
Report each confirmed misconfiguration with the endpoint, the misconfiguration type, and the concrete impact (data leaked, state changed, or attack surface expanded).
