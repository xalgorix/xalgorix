---
intent: defensive
name: performing-cloud-forensics-with-aws-cloudtrail
description: Perform forensic investigation of AWS environments using CloudTrail logs to reconstruct attacker activity, identify
  compromised credentials, and analyze API call patterns.
domain: cybersecurity
subdomain: cloud-security
tags:
- cloud-security
- aws
- cloudtrail
- forensics
- incident-response
- dfir
- boto3
- s3
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Performing Cloud Forensics with AWS CloudTrail

## When to Use

- When investigating suspected AWS account compromise
- After detecting unauthorized API calls or credential exposure
- During incident response involving cloud infrastructure
- When analyzing S3 data exfiltration or IAM privilege escalation
- For post-incident forensic timeline reconstruction

## Detection Gaps & Validation

- **LookupEvents won't show data-plane activity:** `cloudtrail:LookupEvents` returns only management events for the last 90 days. S3 `GetObject`, `PutObject`, and Lambda `Invoke` are *data events*, absent unless data event logging was enabled before the incident - pivot to S3 server access logs / Athena to prove exfiltration.
- **Single-region or non-org trails leave blind spots:** an attacker operating in an unmonitored region produces no events in a region-scoped trail. Confirm the trail is multi-region and org-wide via `aws cloudtrail describe-trails` (`IsMultiRegionTrail`, `IsOrganizationTrail`).
- **Check for anti-forensics first:** hunt `StopLogging`, `UpdateTrail`, `DeleteTrail`, and `PutEventSelectors` events - an attacker may have blinded logging. Then run `aws cloudtrail validate-logs` against the digest files to detect deletion/tampering.
- **Attribute actions correctly:** track both `userIdentity.accessKeyId` and `sessionContext.sessionIssuer` - an `AssumeRole` issues temporary keys (`ASIA...`), so following only the original key loses the attacker after the pivot.
- **`AccessDenied` is signal, not noise:** denied calls are still logged and reveal recon and failed escalation; don't filter them out of the timeline.
- **How to confirm a finding:** corroborate the CloudTrail timeline against VPC Flow Logs (same source IP) and the resource's own logs, and remember every `eventTime` is UTC when sequencing events.
- **Don't conclude "no compromise" until** data events are accounted for (or shown to have been disabled), the trail covered all regions, and logging-tamper events plus digest validation have been checked.

## Prerequisites

- AWS account with CloudTrail enabled (management and data events)
- IAM permissions for cloudtrail:LookupEvents, s3:GetObject, athena:StartQueryExecution
- boto3 Python SDK installed
- CloudTrail logs delivered to S3 with optional Athena table configured
- AWS CLI configured with appropriate credentials

## Workflow

1. **Scope Investigation**: Identify timeframe, affected accounts, and compromised credentials.
2. **Query CloudTrail**: Use boto3 lookup_events or Athena to retrieve relevant API events.
3. **Filter by Indicators**: Search for suspicious user agents, source IPs, and event names.
4. **Reconstruct Timeline**: Build chronological sequence of attacker actions from API calls.
5. **Analyze Access Patterns**: Identify data access, IAM changes, and resource modifications.
6. **Identify Persistence**: Check for new IAM users, access keys, roles, or Lambda functions.
7. **Generate Report**: Produce forensic timeline with findings and remediation steps.

## Key Concepts

| Concept | Description |
|---------|-------------|
| LookupEvents | CloudTrail API to query management events (last 90 days) |
| Athena Queries | SQL queries against CloudTrail logs in S3 for historical analysis |
| User Agent Analysis | Identify tool signatures (AWS CLI, SDK, console, custom) |
| AccessKeyId | Track activity by specific IAM access key |
| EventName | AWS API action name (e.g., GetObject, CreateUser, AssumeRole) |
| sourceIPAddress | Origin IP of API call for geolocation analysis |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| boto3 CloudTrail client | Programmatic CloudTrail event lookup |
| AWS Athena | SQL-based analysis of CloudTrail S3 logs |
| AWS CLI | Command-line CloudTrail queries |
| jq | JSON processing for CloudTrail event parsing |
| CloudTrail Lake | Advanced event data store with SQL query support |

## Output Format

```
Forensic Report: AWS-IR-[DATE]-[SEQ]
Account: [AWS Account ID]
Timeframe: [Start] to [End]
Compromised Credentials: [Access Key IDs]
Suspicious Events: [Count]
Source IPs: [List of attacker IPs]
Actions Taken: [API calls by attacker]
Data Accessed: [S3 objects, secrets, etc.]
Persistence Mechanisms: [New users, keys, roles]
```
