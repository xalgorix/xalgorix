---
intent: defensive
name: detecting-shadow-it-cloud-usage
description: Detect unauthorized SaaS and cloud service usage (shadow IT) by analyzing proxy logs, DNS query logs, and netflow
  data using Python pandas for traffic pattern analysis and domain classification.
domain: cybersecurity
subdomain: cloud-security
tags:
- shadow-IT
- SaaS-discovery
- proxy-logs
- DNS-analysis
- netflow
- cloud-security
- pandas
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Detecting Shadow IT Cloud Usage

## Overview

Shadow IT refers to unauthorized SaaS applications and cloud services used without IT approval. This skill analyzes proxy logs, DNS query logs, and firewall/netflow data to identify unauthorized cloud service usage, classify discovered domains against known SaaS categories, measure data transfer volumes, and flag high-risk services based on security posture and compliance requirements.


## When to Use

- When investigating security incidents that require detecting shadow it cloud usage
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

Shadow IT that hides from proxy/DNS/netflow analysis:
- **DNS-over-HTTPS (DoH) makes SaaS lookups invisible** to DNS query logs — a DoH-capable browser pointed at `1.1.1.1`/`dns.google` bypasses your visibility entirely. Flag connections to DoH resolvers themselves as a meta-signal.
- **CNAME chains and CDN fronting defeat naive domain classification.** `tldextract` on a resolved CNAME (e.g. `*.cloudfront.net`, `*.azureedge.net`) hides the real SaaS — classify on the proxy `Host`/SNI header, not the DNS answer.
- **Encrypted SNI / ECH** breaks SNI-based identification; fall back to JA3 fingerprint + destination IP ASN.
- **QUIC / UDP 443 bypasses the HTTP proxy**, so byte volumes from proxy logs undercount tunneled traffic — reconcile against netflow.
- **`pandas` groupby on raw FQDN splits apex vs subdomain** (`drive.google.com` vs `google.com`); normalize with `tldextract(...).registered_domain` before aggregating or counts/volumes fragment.

Validate: seed a known-unsanctioned domain into the sample logs and confirm it surfaces in the report ranked by risk; reconcile total proxy bytes against netflow to surface proxy-bypass gaps; load the approved-app catalog **before** scoring so sanctioned apps don't inflate false positives.

## Prerequisites

- Python 3.9+ with `pandas`, `tldextract`
- Proxy logs (Squid, Zscaler, or Palo Alto format) or DNS query logs
- SaaS application catalog/blocklist for classification
- Network firewall logs with FQDN resolution (optional)

## Steps

1. Parse proxy access logs and extract destination domains with traffic volumes
2. Parse DNS query logs to identify resolved cloud service domains
3. Aggregate traffic by domain using pandas — total bytes, request counts, unique users
4. Classify domains against known SaaS categories (storage, email, dev tools, AI)
5. Flag unauthorized services not on the approved application list
6. Calculate risk scores based on data volume, user count, and service category
7. Generate shadow IT discovery report with remediation recommendations

## Expected Output

- JSON report listing discovered cloud services with traffic volumes, user counts, risk scores, and approval status
- Top unauthorized services ranked by data exfiltration risk
