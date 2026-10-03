---
name: detecting-sql-injection-via-waf-logs
description: Analyze WAF (ModSecurity/AWS WAF/Cloudflare) logs to detect SQL injection attack campaigns. Parses ModSecurity
  audit logs and JSON WAF event logs to identify SQLi patterns (UNION SELECT, OR 1=1, SLEEP(), BENCHMARK()), tracks attack
  sources, correlates multi-stage injection attempts, and generates incident reports with OWASP classification.
domain: cybersecurity
subdomain: security-operations
tags:
- detecting
- sql
- injection
- via
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- DE.CM-01
- RS.MA-01
- GV.OV-01
- DE.AE-02
---
## Helper prerequisites

This bundled skill supplies methodology text; it does not install the local helper files invoked below. Before running a command using `agent.py` or a `scripts/` path, create that file from a complete implementation when one is supplied, or obtain and review the matching upstream helper. Check its `--help` and dependencies against the shown arguments. If no implementation is available, the invocation is a workflow illustration rather than a runnable command; use the documented underlying tools instead.



# Detecting SQL Injection via WAF Logs


## When to Use

- When investigating security incidents that require detecting sql injection via waf logs
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **WAF only logs what it inspects:** if SQLi arrives in a JSON body, a header, or a path segment the WAF doesn't parse, no rule (942100/942190/etc.) fires and your log analysis sees nothing. Confirm the WAF parses request bodies and the relevant content types before treating an empty result as "no attack."
- **Obfuscation evades the signatures you grep for:** inline comments (`UN/**/ION SEL/**/ECT`), case mixing, URL/double-URL encoding (`%2553ELECT`), whitespace alternates (`/**/`, `%0a`, `+`), and `CHAR()`/`CONCAT()` payloads slip literal-regex patterns. Normalize (decode twice, strip comments, collapse whitespace, lowercase) before matching, and lean on libinjection-based rules (942100) rather than only string patterns (942190).
- **Time-based blind SQLi has no row-count tell:** `SLEEP()`, `BENCHMARK()`, `pg_sleep()`, `WAITFOR DELAY` succeed with normal 200s and no data in the response — detect via response-latency deltas and repeated near-identical requests, not status codes.
- **Encoding/WAF mode:** Cloudflare/AWS WAF may log the decoded payload while ModSecurity logs raw — parse both forms. Count-only mode (no block) means 200s on malicious requests; don't infer failure from a 200.
- **Validate the rules fire:** replay an sqlmap run (classic, UNION, and `--technique=T` time-based) through the parser and confirm each OWASP class and the IP-clustering correlation populate. **FP tuning:** apps that legitimately pass SQL keywords (search, reporting) and security scanners cause noise — baseline trusted IPs/endpoints before raising incidents.

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install requests`
2. Collect WAF logs (ModSecurity audit log, AWS WAF JSON logs, or Cloudflare firewall events).
3. Run the agent to parse and analyze:
   - Detect SQLi payloads via 15+ regex patterns
   - Classify attacks by OWASP injection type (classic, blind, time-based, UNION-based)
   - Identify persistent attackers by IP clustering
   - Correlate multi-request injection campaigns
   - Calculate attack success probability based on response codes

```bash
python scripts/agent.py --log-file /var/log/modsec_audit.log --format modsecurity --output sqli_report.json
```

## Examples

### ModSecurity SQLi Detection
```
Rule 942100 triggered: SQL Injection Attack Detected via libinjection
URI: /api/users?id=1' UNION SELECT username,password FROM users--
Source IP: 203.0.113.42 (47 requests in 5 minutes)
Classification: UNION-based SQLi campaign
```
