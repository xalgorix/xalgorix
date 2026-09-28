---
intent: defensive
name: implementing-runtime-application-self-protection
description: Deploy Runtime Application Self-Protection (RASP) agents to detect and block attacks from within application
  runtime, covering OpenRASP integration, attack pattern detection, and security policy configuration for Java and Python
  web applications.
domain: cybersecurity
subdomain: application-security
tags:
- rasp
- application-security
- openrasp
- runtime-protection
- sqli
- xss
- rce
- devsecops
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_ai_rmf:
- GOVERN-1.1
- MEASURE-2.7
- MANAGE-3.1
nist_csf:
- PR.PS-01
- PR.PS-04
- ID.RA-01
- PR.DS-10
---

# Implementing Runtime Application Self-Protection

## Overview

Runtime Application Self-Protection (RASP) instruments application code at runtime to detect and block attacks by examining actual execution context rather than relying solely on network traffic patterns. Unlike WAFs that inspect HTTP requests externally, RASP agents intercept dangerous operations (SQL queries, file operations, command execution, deserialization) at the function level inside the application. Function-level context sharply reduces false positives relative to network-layer WAFs, but it does not eliminate them: blind spots remain for logic-layer attacks, un-instrumented code paths, and exotic parsers. Treat any RASP accuracy claim (including from vendors) as unverified until tested against your own traffic. This skill covers deploying OpenRASP for Java applications, configuring detection policies for OWASP Top 10 attacks, tuning alerting thresholds, and integrating RASP telemetry with SIEM platforms.


## When to Use

- When deploying or configuring implementing runtime application self protection capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

RASP that is installed but left in monitor mode gives a false sense of protection — it logs attacks it never stops.

- **Stuck in monitor/detect-only:** OpenRASP policies left at `action: log` (or `inspect`) after the tuning phase never call `block`. Confirm each policy for SQLi, command injection, SSRF, path traversal, XXE, and deserialization is set to `block` in production.
- **Excluded or un-instrumented routes:** the JVM `-javaagent` attaches but a separately-deployed service, async worker, or native/JNI path is not hooked, leaving a coverage hole. Verify every entry point loads the agent (check startup logs for the RASP banner).
- **Over-broad allowlists:** tuning to kill false positives by whitelisting whole endpoints disables protection on exactly the routes that take user input.
- **Telemetry not reaching SIEM:** block events fire but the Splunk HEC / syslog forwarder is misconfigured, so nobody sees them.

**Verify with live payloads, not config review:** in staging, send a real SQLi (`' OR 1=1--`), an OS command-injection (`; id`), and a path-traversal (`../../etc/passwd`) against an instrumented endpoint and confirm the request is **blocked (HTTP 403/500)** with a matching stack-trace alert in the SIEM. A logged-but-served request means the agent is still monitor-only.

## Prerequisites

- Java 8+ application server (Tomcat, Spring Boot, or JBoss) or Python Flask/Django application
- OpenRASP agent package (rasp-java) — note: the upstream OpenRASP project is archived and no longer actively maintained; pin the agent version and treat rule updates as frozen. Commercial RASP/endpoint agents follow the same deployment pattern
- OpenRASP management console for centralized policy management
- SIEM integration endpoint (Splunk HEC, Elasticsearch, or syslog)
- Application staging environment for RASP testing before production

## Steps

### Step 1: Deploy RASP Agent

Install the RASP agent into the application server runtime using JVM agent attachment for Java or middleware hooks for Python.

### Step 2: Configure Detection Policies

Define detection rules for SQL injection, command injection, SSRF, path traversal, XXE, and deserialization attacks with block or monitor actions.

### Step 3: Tune and Baseline

Run the agent in monitor mode during normal operations to establish baseline behavior and tune policies to reduce false positives before switching to block mode.

### Step 4: Integrate with SIEM

Forward RASP alerts to the SIEM for correlation with WAF, IDS, and authentication events to build comprehensive attack timelines.

## Expected Output

JSON report containing RASP policy audit results, detected attack attempts with stack traces, blocked requests summary, and coverage assessment against OWASP Top 10.
