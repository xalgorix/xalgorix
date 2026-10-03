---
name: implementing-syslog-centralization-with-rsyslog
description: Configure rsyslog for centralized log collection with TLS encryption, custom templates, and log rotation. Generates
  server and client configuration files with GnuTLS stream drivers, x509 certificate authentication, per-host log segregation,
  and reliable queue settings for high-availability syslog infrastructure.
domain: cybersecurity
subdomain: security-operations
tags:
- implementing
- syslog
- centralization
- with
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



# Implementing Syslog Centralization with Rsyslog


## When to Use

- When deploying or configuring implementing syslog centralization with rsyslog capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

- **UDP (514) silently drops under load:** `@host` (single `@`) sends UDP with no delivery guarantee; messages are lost on congestion with zero error. Use TCP/TLS (`@@` / `omfwd protocol="tcp"`) plus disk-assisted queues so spikes spool instead of vanishing.
- **"TLS configured" but actually plaintext:** `imtcp`/`omfwd` without `StreamDriver="gtls"` + `StreamDriverMode="1"` falls back to cleartext on 6514. Confirm with `openssl s_client -connect server:6514` returning a cert, and `tcpdump -A port 6514` showing ciphertext rather than readable log lines.
- **Auth mode anon = any client accepted:** `StreamDriverAuthMode="anon"` trusts any cert. Use `x509/name` with a `permittedPeer` list so only known clients forward; verify a client with the wrong CN is rejected.
- **Queue not disk-assisted = restart loss:** without `queue.type="LinkedList"` + `queue.filename` + `queue.saveonshutdown="on"`, in-memory queues drop on rsyslog restart. Confirm a `.qi`/spool file exists under the queue path.
- **Confirm delivery end to end:** `logger -n server -P 6514 -T "rsyslog-test"` from a client, then verify the line lands in the per-host file (`/var/log/remote/<host>/...`). A reachable port is not the same as a stored log.

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install jinja2 paramiko`
2. Generate TLS certificates for rsyslog server and clients using OpenSSL.
3. Run the agent to generate rsyslog server and client configurations:
   - Server: TLS listener on port 6514, per-host directory output, JSON-format templates
   - Client: TLS forwarding with disk-assisted queues for reliability
4. Deploy configurations to servers via SSH (paramiko).
5. Validate TLS connectivity and log delivery.

```bash
python scripts/agent.py --server-ip 10.0.0.1 --clients 10.0.0.10,10.0.0.11 --ca-cert ca.pem --output syslog_report.json
```

## Examples

### Server Configuration (TLS)
```
module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1"
       StreamDriver.Authmode="x509/name")
input(type="imtcp" port="6514")
template(name="PerHostLog" type="string" string="/var/log/remote/%HOSTNAME%/%PROGRAMNAME%.log")
*.* ?PerHostLog
```

### Client Configuration (Reliable Forwarding)
```
action(type="omfwd" target="10.0.0.1" port="6514" protocol="tcp"
       StreamDriver="gtls" StreamDriverMode="1"
       StreamDriverAuthMode="x509/name"
       queue.type="LinkedList" queue.filename="fwdRule1"
       queue.maxdiskspace="1g" queue.saveonshutdown="on"
       action.resumeRetryCount="-1")
```
