---
name: analyzing-threat-landscape-with-misp
description: Analyze the threat landscape using MISP (Malware Information Sharing Platform) by querying event statistics,
  attribute distributions, threat actor galaxy clusters, and tag trends over time. Uses PyMISP to pull event data, compute
  IOC type breakdowns, identify top threat actors and malware families, and generate threat landscape reports with temporal
  trends.
domain: cybersecurity
subdomain: threat-intelligence
tags:
- analyzing
- threat
- landscape
- with
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
d3fend_techniques:
- File Metadata Consistency Validation
- Application Protocol Command Analysis
- Identifier Analysis
- Content Format Conversion
- Message Analysis
nist_csf:
- ID.RA-01
- ID.RA-05
- DE.CM-01
- DE.AE-02
---
## Helper prerequisites

This bundled skill supplies methodology text; it does not install the local helper files invoked below. Before running a command using `agent.py` or a `scripts/` path, create that file from a complete implementation when one is supplied, or obtain and review the matching upstream helper. Check its `--help` and dependencies against the shown arguments. If no implementation is available, the invocation is a workflow illustration rather than a runnable command; use the documented underlying tools instead.



# Analyzing Threat Landscape with MISP


## When to Use

- When investigating security incidents that require analyzing threat landscape with misp
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Attribute-type coverage:** counting only `ip-dst`/`domain`/`sha256` undercounts the landscape -- MISP also stores `ip-src`, `hostname`, `url`, `md5`, `sha1`, `filename|sha256`, and `btc`. Enumerate the full `Attribute.type` set or your IOC-type breakdown is biased.
- **Galaxy/tag inconsistency:** actor attribution lives in `galaxy` clusters (`mitre-intrusion-set`, `threat-actor`) and free-text `Tag`s applied unevenly -- APT28 may appear as "Sofacy", "Fancy Bear", or a galaxy UUID. Normalize via galaxy synonyms before ranking top actors.
- **Sharing/visibility gaps:** API-key org permissions and event `distribution` levels mean `search()` returns only visible events; "top threat level" skews to what your org can see.
- **Stale events:** old events inflate counts unless you bound by `--days`/`timestamp`.

To validate: confirm event totals from PyMISP `search()` match the MISP web UI for the same date range and filters; verify pagination is not truncating results (default page limits). Re-run the technique ranking with galaxy-synonym normalization and confirm duplicate actors collapse. Sanity-check that `T1566`-style technique counts come from ATT&CK galaxy clusters, not ad-hoc tags, before reporting a "top technique."

## Prerequisites

- Familiarity with threat intelligence concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install pymisp`
2. Configure MISP URL and API key.
3. Run the agent to generate threat landscape analysis:
   - Pull event statistics by threat level and date range
   - Analyze attribute type distributions (IP, domain, hash, URL)
   - Identify top MITRE ATT&CK techniques from event tags
   - Track threat actor activity via galaxy clusters
   - Generate temporal trend analysis of IOC submissions

```bash
python scripts/agent.py --misp-url https://misp.local --api-key YOUR_KEY --days 90 --output landscape_report.json
```

## Examples

### Threat Landscape Summary
```
Period: Last 90 days
Events analyzed: 1,247
Top threat level: High (43%)
Top attribute type: ip-dst (31%), domain (22%), sha256 (18%)
Top MITRE technique: T1566 Phishing (89 events)
Top threat actor: APT28 (34 events)
```
