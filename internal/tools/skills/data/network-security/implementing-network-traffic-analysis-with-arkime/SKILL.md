---
name: implementing-network-traffic-analysis-with-arkime
description: Deploy and query Arkime (formerly Moloch) for full packet capture network traffic analysis. Uses the Arkime API
  v3 to search sessions, download PCAPs, analyze connection patterns, detect beaconing behavior, and identify suspicious network
  flows. Monitors DNS queries, HTTP traffic, and TLS certificate anomalies across captured traffic.
domain: cybersecurity
subdomain: network-security
tags:
- implementing
- network
- traffic
- analysis
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.IR-01
- DE.CM-01
- ID.AM-03
- PR.DS-02
---
## Helper prerequisites

This bundled skill supplies methodology text; it does not install the local helper files invoked below. Before running a command using `agent.py` or a `scripts/` path, create that file from a complete implementation when one is supplied, or obtain and review the matching upstream helper. Check its `--help` and dependencies against the shown arguments. If no implementation is available, the invocation is a workflow illustration rather than a runnable command; use the documented underlying tools instead.



# Implementing Network Traffic Analysis with Arkime


## When to Use

- When deploying or configuring implementing network traffic analysis with arkime capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

- **Capture drops = blind spots, not clean traffic:** if `capture` can't keep up (NIC offload on, no PF_RING/AF_PACKET tuning) Arkime silently misses sessions. Check the stats page for non-zero `dropped`/`overload` before trusting that "no beaconing was found."
- **Snaplen truncation:** a low `snapLen`/`maxPacketsInQueue` stores headers but cuts payload, so HTTP/DNS/TLS field extraction is incomplete and content queries return empty. Verify full-payload capture on a known session.
- **Beaconing threshold tuned wrong:** flagging only `jitter < 5%` misses jittered C2, while too-loose intervals flag NTP/AV update polls. Validate against a known-good periodic host before alerting.
- **Time skew across sensors:** un-synced clocks scatter interval math and break session correlation — enforce NTP on every capture node.

**Verification:** confirm the API returns data (`GET /api/sessions?expression=...` → HTTP 200, non-zero `recordsTotal`), then validate a known flow end-to-end: search a test connection, download its PCAP, and confirm payload bytes are present. A true beaconing positive shows a tight inter-session interval *and* a consistent destination (e.g. 288 sessions ~300s apart to one IP:443); a regular interval alone to a CDN/keepalive is a false positive. Empty results plus capture drops means missing visibility, not a clean network.

## Prerequisites

- Familiarity with network security concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install requests`
2. Configure Arkime viewer URL and credentials.
3. Run the agent to query Arkime sessions and analyze traffic:
   - Search sessions by IP, port, protocol, or expression
   - Download PCAP data for forensic analysis
   - Detect C2 beaconing via connection interval analysis
   - Identify DNS tunneling through query length statistics
   - Flag connections to known-bad TLS certificate issuers

```bash
python scripts/agent.py --arkime-url https://arkime.local:8005 --user admin --password secret --output arkime_report.json
```

## Examples

### Beaconing Detection
```
Source: 10.1.2.50 -> 185.220.101.34:443
Sessions: 288 over 24 hours
Avg interval: 300s, Jitter: 4.2%
Verdict: HIGH confidence C2 beaconing (jitter < 5%)
```
