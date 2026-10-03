---
name: analyzing-network-flow-data-with-netflow
description: Parse NetFlow v9 and IPFIX records to detect volumetric anomalies, port scanning, data exfiltration, and C2 beaconing
  patterns. Uses the Python netflow library to decode flow records, builds traffic baselines, and applies statistical analysis
  to identify flows with abnormal byte counts, connection durations, and periodic timing patterns.
domain: cybersecurity
subdomain: network-security
tags:
- analyzing
- network
- flow
- data
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



# Analyzing Network Flow Data with Netflow


## When to Use

- When investigating security incidents that require analyzing network flow data with netflow
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Sampling loss blinds you:** sampled NetFlow (e.g., 1:1000 on the router) drops most low-volume flows — beaconing and slow exfil disappear. Check the IPFIX `samplingInterval`/`SAMPLING_INTERVAL` field; on sampled exporters, scale `IN_BYTES`/`IN_PKTS` and never trust raw flow counts for scan detection.
- **Flow records are metadata only:** NetFlow sees the 5-tuple, bytes, and timing — not payload. DNS C2 over DoH/DoT (port 443/853) and TLS-encrypted exfil look like ordinary HTTPS; pivot on destination reputation, JA3 from a sidecar sensor, and per-flow byte asymmetry, not content.
- **Low-and-slow beats fixed thresholds:** attackers pace beacons with jitter and keep flows under volumetric alarms. Compute inter-flow interval variance per (src,dst,dstport) over hours, not a single window; flag near-constant periods even at tiny byte counts.
- **Active/inactive timeouts split sessions:** one long transfer becomes many flow records (default 30s active / 15s inactive timeout), inflating flow counts and hiding total volume. Aggregate by 5-tuple before scoring exfil.
- **Validate the pipeline fires:** replay a known-bad pcap through `nfreplay`/softflowd to your collector (`python -m netflow.collector -p 9995`) and confirm the scan/beacon rule alerts on it; if no alert, the template (v9 template ID mismatch) or field mapping is broken.
- **FP tuning:** baseline backup windows, CDN/cloud sync, and SaaS keepalives per-host before alerting, or legitimate periodic traffic floods the beaconing detector.

## Prerequisites

- Familiarity with network security concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install netflow`
2. Collect NetFlow/IPFIX data from routers or use the built-in collector: `python -m netflow.collector -p 9995`
3. Parse captured flow data using `netflow.parse_packet()`.
4. Analyze flows for:
   - Port scanning: single source to many destinations on same port
   - Data exfiltration: high byte-count outbound flows to unusual destinations
   - C2 beaconing: periodic connections with consistent intervals
   - Volumetric anomalies: traffic spikes beyond baseline thresholds
5. Generate a prioritized findings report.

```bash
python scripts/agent.py --flow-file captured_flows.json --output netflow_report.json
```

## Examples

### Parse NetFlow v9 Packet
```python
import netflow
data, _ = netflow.parse_packet(raw_bytes, templates={})
for flow in data.flows:
    print(flow.IPV4_SRC_ADDR, flow.IPV4_DST_ADDR, flow.IN_BYTES)
```
