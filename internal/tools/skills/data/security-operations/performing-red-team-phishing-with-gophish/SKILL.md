---
name: performing-red-team-phishing-with-gophish
description: Automate GoPhish phishing simulation campaigns using the Python gophish library. Creates email templates with
  tracking pixels, configures SMTP sending profiles, builds target groups from CSV, launches campaigns, and analyzes results
  including open rates, click rates, and credential submission statistics for security awareness assessment.
domain: cybersecurity
subdomain: security-operations
tags:
- performing
- red
- team
- phishing
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



## When to Use

- When conducting security assessments that involve performing red team phishing with gophish
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Most Often Missed & How to Confirm

- **Mail never lands (the silent campaign killer):** a campaign that "launched" with 0 opens usually means delivery failed, not that users were vigilant. Before blaming awareness, confirm deliverability — SPF/DKIM/DMARC alignment on the sending domain, no Spamhaus/Barracuda listing, and that the gateway didn't quarantine. Send one seed email to a controlled inbox and inspect headers (`Authentication-Results: spf=pass dkim=pass`).
- **Sending Profile misconfig:** wrong SMTP host/port/auth, or a "From" that fails DMARC, gets silently junked. Use GoPhish's "Send Test Email" on the sending profile and confirm receipt before importing the target group.
- **Tracking pixel / landing page unreachable from the victim network:** opens and clicks only register if the phish server URL resolves and is reachable externally (valid TLS cert, not blocked by web proxy). Confirm by clicking the link yourself from off-network and watching the event appear in the campaign timeline.
- **Captured creds not recorded:** the landing page needs `Capture Submitted Data` (and `Capture Passwords`) enabled plus a valid redirect, or submissions show as clicks only. Submit a test credential and verify it appears under campaign results.
- **Don't conclude "low click rate = secure":** a 0% result with unverified delivery, DNS, and capture settings is an instrumentation failure, not a clean bill of health. Confirm the full open→click→submit chain works end to end with a seed target first.

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install gophish requests`
2. Deploy GoPhish server and obtain an API key from Settings.
3. Use the Python gophish library to automate campaign setup:
   - Create email templates with HTML body and tracking
   - Configure SMTP sending profiles
   - Import target groups from CSV
   - Create landing pages for credential capture
   - Launch and monitor campaigns
4. Analyze campaign results: opens, clicks, submitted data, reported.

```bash
# For authorized penetration testing and lab environments only
python scripts/agent.py --gophish-url https://localhost:3333 --api-key <key> --campaign-name "Q1 Awareness" --output phishing_report.json
```

## Examples

### Create Campaign via API
```python
from gophish import Gophish
from gophish.models import Campaign, Template, Group, SMTP, Page
api = Gophish("api_key", host="https://localhost:3333", verify=False)  # Self-signed cert on localhost lab
campaign = Campaign(name="Q1 Test", groups=[Group(name="Sales Team")],
    template=Template(name="IT Password Reset"), smtp=SMTP(name="Internal SMTP"),
    page=Page(name="Credential Page"))
api.campaigns.post(campaign)
```
