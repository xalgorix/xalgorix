---
name: serverless-cloud-security
description: Serverless offensive testing across AWS Lambda and Function URLs, Azure Functions with Managed Identity, and GCP Cloud Functions and Cloud Run — public invocation, weak authorization, event injection, unsafe deserialization, SSRF to metadata, secrets in environment variables and packages, overprivileged execution identities, and deployment artifact poisoning
intent: offensive
assessment_mode:
  - blackbox
  - credentialed
provider:
  - aws
  - azure
  - gcp
---

# Serverless Cloud Security

## Purpose
Offensive testing of serverless workloads: externally reachable functions (black-box) and credentialed function review (roles, environment, packages, event wiring). Consolidates the former serverless review/hardening guidance into attack-driven methodology.

## Entry Conditions
- Black-box: function URLs, API Gateway stages, or app endpoints invoking serverless backends (from `cloud-attack-surface-discovery`)
- Credentialed: cloud context from the provider pentest skill; function inventory visible

## Discovery Signals
- `*.lambda-url.*.on.aws`, API Gateway `execute-api` hosts, Azure Functions endpoints (`*.azurewebsites.net/api/*`), `*.cloudfunctions.net`, `*.run.app`
- API responses shaped like function output (missing static-asset semantics, `x-amz-*` invocation headers, `RequestId` fields)
- Event-driven features in the product (uploads → S3 triggers, form submissions → queues → functions)

## Attack Model

```text
public function identified (or event-wired function found)
→ invocation WITHOUT authorization (anonymous / wrong role / authorizer NONE)
→ input reaches code unvalidated
→ injection / SSRF-to-metadata / secret leak / privileged identity action
→ concrete protected impact
```

## Methodology

### Step 1: Public Invocation (black-box)
```bash
# AWS: Function URLs with AuthType NONE, resource policies with Principal "*", API Gateway with no authorizer
curl -sk -X POST "https://<fn-id>.lambda-url.<region>.on.aws/" -H "Content-Type: application/json" -d '{"input":"probe"}'
# Azure: function keys never required / host keys leaked in JS
curl -sk "https://<app>.azurewebsites.net/api/<function>?code=" 
# GCP: Cloud Run services with allow-unauthenticated, Functions invoker to allUsers
curl -sk -X POST "https://<svc>.run.app/" -H "Content-Type: application/json" -d '{}'
```
Two doors to exposure: the URL/auth config AND the resource policy — check both. Confirmed = the function actually executes (its real output/behavior observed), not merely that no auth header was required for a static 200.

### Step 2: Input Injection (all providers)
```text
Where a public function accepts input:
  - command injection: os.system, subprocess with shell=True, exec/eval, backticks
  - SQL/NoSQL: string-built queries from event fields
  - template injection: unsafely rendered templates with event data
  - unsafe deserialization: pickle.loads, yaml.load (not safe_load), Marshal, .NET BinaryFormatter, PHP unserialize
  - SSRF: functions fetching URLs from input → chain via cloud-metadata-workload-identity
Same evidence contracts as api-injection / command injection skills — never status-code-only.
```

### Step 3: Event Injection (event-wired functions)
Functions consuming S3/SQS/SNS/EventBridge/Azure Event Grid/PubSub events trust event structure:
- Poisoned payloads in message attributes/fields the function parses unsafely
- Event-source poisoning: if you can write to the bucket/queue feeding the function (write access from another finding), the function executes YOUR code path
- Credentialed review: grep the handler for untrusted fields from the event used in exec/query/eval contexts

### Step 4: Secrets and Environment
```bash
# Credentialed:
aws lambda get-function-configuration --function-name <fn>   # Environment.Variables
gcloud run services describe <svc> --format="value(spec.template.spec.containers[0].env)"
az functionapp config appsettings list --name <app> -g <rg>
# Black-box: error stacks and timing leaks; deployment packages (when code disclosure exists) carry
# committed .env/config.json that env-var scanning misses — scan the package, not just the config
```

### Step 5: Execution Identity
```text
Resolve the EFFECTIVE identity: execution role + inline policies + AWS managed policies (a "scoped"
managed policy plus one wildcard inline statement is the classic silent over-privilege).
Over-privileged identity + injection = full cloud primitive:
  AWS: role creds via a reverse shell / metadata within the runtime
  Azure: managed-identity tokens for any resource audience
  GCP: attached SA tokens
Prove: the privileged action performed from the function context.
```

### Step 6: Deployment Artifacts and Cross-Service Trust
- Writable deployment packages/layers/buckets (AWS: S3-backed deployment packages; GCP: function source buckets) = code poisoning → next invocation runs attacker code
- Cross-service trust: functions invoked by other services with unvalidated identity headers
- Deprecated runtime: a hardening/posture observation ONLY — report a finding only with a specific exploitable issue tied to the runtime

## Evidence Contract

```text
public function identified
→ unauthorized invocation ACTUALLY executes (real output observed)
→ concrete protected operation/data impact (injection executed, metadata reached, secret disclosed, privileged action)
→ report
```

**NOT evidence**: an unauthenticated static/200 response, `AuthType: NONE` in config without execution proof, an over-broad role alone (exposure risk), an EOL runtime by itself, a public endpoint whose function returns no protected behavior

## Common Misses
- Resource-based invoke policies alongside URL auth (one door checked, not both)
- Event fields never treated as untrusted input
- Deployment package contents never scanned for secrets
- Function URLs checked but API Gateway stages never enumerated
- Cloud Run `--allow-unauthenticated` missed because it is set at deploy time
- Layers (AWS) with embedded secrets or outdated vulnerable dependencies

## False Positives / Non-Findings
- Public health/status functions with no privileged behavior
- Functions requiring valid auth (authorizer working)
- Over-broad roles with no reachable execution primitive from the outside
- CORS misconfigurations without concrete cross-origin impact

## Xalgorix Tool Strategy
- `http_request`/curl for invocation testing; Python for payload generation
- `terminal_execute` with aws/az/gcloud for credentialed review
- Ledger: function inventory with auth model, verified invocation, identity reach

## Specialist Handoffs
- SSRF/metadata from functions → `cloud-metadata-workload-identity`
- Obtained execution-identity credentials → `cloud-credential-abuse`
- HTTP-layer injection → `api-injection`/web skills; escalation → provider privilege-escalation skills
- Secrets → `cloud-secrets-data-access`

## Stopping Rule
For each reachable function: prove invocation, test input handling once, chase one execution/identity path to concrete impact. Do not attempt every payload class against every function — depth-first on functions holding secrets, privileged identities, or writable event sources.