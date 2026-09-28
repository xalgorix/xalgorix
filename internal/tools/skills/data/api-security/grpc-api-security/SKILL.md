---
name: grpc-api-security
description: gRPC API security testing covering reflection, service enumeration, method-level authorization, message tampering, and transcoded REST inconsistencies
intent: offensive
---

# gRPC API Security

## Purpose
Test gRPC services for reflection exposure, method-level authorization, message tampering, and gateway/REST transcoding inconsistencies.

## Preconditions
- A gRPC endpoint identified (typically port 50051, 443 with gRPC content-type, or via gateway)
- grpcurl available (or ability to install: go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest)

## Attack Surface Signals
- HTTP/2 with `Content-Type: application/grpc` or `application/grpc+proto`
- Port 50051, 50052, 6565 commonly used for gRPC
- `grpc-status` in response trailers
- gRPC-Web content-type: `application/grpc-web+proto`
- Gateway that proxies REST to gRPC (transcoding)

## Methodology

### Service Discovery via Reflection
```bash
# List services (if reflection is enabled)
grpcurl -plaintext TARGET:50051 list

# List methods for a service
grpcurl -plaintext TARGET:50051 list mypackage.MyService

# Get message descriptors
grpcurl -plaintext TARGET:50051 describe mypackage.MyService/GetUser
```

### Direct Method Invocation
```bash
# Call a method with parameters
grpcurl -plaintext -d '{"id": "123"}' TARGET:50051 mypackage.MyService/GetUser

# Try calling admin methods with a regular user token
grpcurl -plaintext -H "authorization: Bearer USER_TOKEN" \
  -d '{"id": "123"}' TARGET:50051 mypackage.AdminService/DeleteUser
```

### Method-Level Authorization Testing
```bash
# Test if per-method auth is enforced (not just per-service)
for method in GetUser ListUsers CreateUser DeleteUser UpdateUser; do
  result=$(grpcurl -plaintext -d '{}' TARGET:50051 "mypackage.UserService/$method" 2>&1)
  echo "[$method] $result" | head -1
done

# Test anonymous access
grpcurl -plaintext -d '{"id": "1"}' TARGET:50051 mypackage.UserService/GetUser
```

### Message Tampering
```bash
# Object ID manipulation (BOLA in gRPC)
grpcurl -plaintext -H "authorization: Bearer USER_A_TOKEN" \
  -d '{"user_id": "USER_B_ID"}' TARGET:50051 mypackage.UserService/GetUser

# Property tampering (BOPLA in gRPC)
grpcurl -plaintext -H "authorization: Bearer USER_TOKEN" \
  -d '{"user_id": "123", "role": "admin", "is_verified": true}' TARGET:50051 mypackage.UserService/UpdateUser
```

### Unknown / Extra Fields
```bash
# Some protobuf parsers accept unknown fields silently
# Try sending fields not in the schema (if the server deserializes into a dynamic message)
echo '{"id": "1", "unknown_field": "test", "debug": true}' | \
  grpcurl -plaintext -d @ TARGET:50051 mypackage.UserService/GetUser
```

### Gateway/REST Transcoding Inconsistencies
```bash
# If the gRPC service is exposed via a REST gateway (gRPC transcoding):
# Test that authorization is consistent between the REST and gRPC paths

# REST path (through gateway)
curl -sk "https://TARGET/api/users/123" -H "Authorization: Bearer USER_TOKEN"

# Direct gRPC path (if accessible)
grpcurl -plaintext -H "authorization: Bearer USER_TOKEN" \
  -d '{"id": "123"}' TARGET:50051 mypackage.UserService/GetUser

# A finding: REST path returns 403 but gRPC path returns data
```

### Oversized Messages / Resource Consumption
```bash
# Large payloads
python3 -c "print(json.dumps({'data': 'A' * 1000000}))" | \
  grpcurl -plaintext -d @ TARGET:50051 mypackage.UploadService/Process
```

### Metadata Header Testing
```bash
# Test custom metadata
grpcurl -plaintext \
  -H "x-user-role: admin" \
  -H "x-internal: true" \
  -d '{}' TARGET:50051 mypackage.AdminService/ListAll
```

## Evidence Contract

- **Reflection exposure**: Reflection reveals sensitive service/method names AND leads to a confirmed access-control bypass
- **BOLA in gRPC**: User A's token retrieves User B's data via a gRPC call
- **BFLA in gRPC**: Regular user executes an admin method
- **Message tampering**: A property change in the gRPC message is reflected in the server's behavior
- **Gateway inconsistency**: Different authorization outcomes for the same operation via REST vs gRPC
- **NOT evidence**: Reflection enabled alone, gRPC service exists, a 200-equivalent (OK status) from a public method

## Common Misses
- gRPC-Web endpoints accessible via the browser (different auth)
- Server streaming methods that don't check authorization per-message
- Client streaming methods that process all messages before auth
- Interceptor-level auth that doesn't apply to all methods
- Health check services exposing internal service information
- mTLS that can be bypassed via the REST gateway

## False Positives / Non-Findings
- Reflection enabled on a service with no sensitive methods
- A method returning UNAUTHENTICATED (auth is working)
- An empty response from a correctly permissioned endpoint

## Xalgorix Tool Strategy
- `terminal_execute` with grpcurl for direct gRPC interaction
- Python with grpcio for complex message construction
- curl for REST gateway comparison testing

## Stopping Rule
Exhaust every discovered service and method. Test read and write paths. Compare gRPC and REST gateway authorization.

## Handoff
Report each confirmed gRPC issue with the service, method, the authorization context, and the concrete unauthorized data or action.
