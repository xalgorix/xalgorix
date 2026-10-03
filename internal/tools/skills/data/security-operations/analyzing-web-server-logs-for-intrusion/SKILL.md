---
name: analyzing-web-server-logs-for-intrusion
description: Parse Apache and Nginx access logs to detect SQL injection attempts, local file inclusion, directory traversal,
  web scanner fingerprints, and brute-force patterns. Uses regex-based pattern matching against OWASP attack signatures, GeoIP
  enrichment for source attribution, and statistical anomaly detection for request frequency and response size outliers.
domain: cybersecurity
subdomain: security-operations
tags:
- analyzing
- web
- server
- logs
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



# Analyzing Web Server Logs for Intrusion


## When to Use

- When investigating security incidents that require analyzing web server logs for intrusion
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Regex misses encoded SQLi:** `UNION SELECT` and `OR 1=1` are easy, but URL-encoding (`%55NION`), inline comments (`UNI/**/ON SE/**/LECT`), case mixing, and double-encoding bypass naive signatures. Normalize (URL-decode twice, strip comments, lowercase) before matching, and prefer libinjection-style tokenization over literal strings.
- **POST bodies and headers are invisible in access logs:** Apache/Nginx access logs record only the request line and query string — SQLi/XSS/LFI in POST bodies, cookies, or custom headers won't appear unless mod_security audit logging or body capture is enabled. State this coverage gap explicitly; an empty result over `access.log` is not proof of no attack.
- **Scanner UA spoofing:** sophisticated actors set a Chrome User-Agent, so `nikto|sqlmap|gobuster` UA matching only catches lazy scans. Add request-rate, 404-ratio, and path-fuzzing-burst heuristics independent of UA.
- **LFI/traversal evasion:** beyond `../etc/passwd`, test `..%2f`, `..%252f` (double-encode), `....//`, and absolute `/etc/passwd` with no traversal — match `root:.*:0:0:` in responses, not just the request.
- **Validate the rules fire:** replay a labeled attack log (sqlmap run, dirbuster sweep, a brute-force burst >50 POSTs/5min to `/login`) through the parser and confirm each rule and the GeoIP enrichment populate. **FP tuning:** WAF health checks, search-engine bots, and legitimate apps passing SQL keywords in search fields cause false hits — baseline trusted IPs/paths.

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install geoip2 user-agents`
2. Collect web server access logs in Combined Log Format (Apache) or Nginx default format.
3. Parse each log entry extracting: IP, timestamp, method, URI, status code, response size, user-agent, referer.
4. Apply detection rules:
   - SQL injection: `UNION SELECT`, `OR 1=1`, `' OR '`, hex encoding patterns
   - LFI/Path traversal: `../`, `/etc/passwd`, `/proc/self`, `php://filter`
   - XSS: `<script>`, `javascript:`, `onerror=`, `onload=`
   - Scanner signatures: nikto, sqlmap, dirbuster, gobuster, wfuzz user-agents
   - Brute force: >50 POST requests to login endpoints from same IP in 5 minutes
5. Enrich with GeoIP data and generate a prioritized findings report.

```bash
python scripts/agent.py --log-file /var/log/nginx/access.log --geoip-db GeoLite2-City.mmdb --output web_intrusion_report.json
```

## Examples

### Detect SQLi in URI
```
192.168.1.100 - - [15/Jan/2024:10:30:45 +0000] "GET /products?id=1' UNION SELECT username,password FROM users-- HTTP/1.1" 200 4532
```

### Scanner User-Agent Detection
```
Nikto/2.1.6, sqlmap/1.7, DirBuster-1.0-RC1, gobuster/3.1.0
```
