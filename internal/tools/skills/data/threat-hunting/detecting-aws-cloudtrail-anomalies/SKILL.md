---
intent: defensive
name: detecting-aws-cloudtrail-anomalies
description: Detect unusual API call patterns in AWS CloudTrail logs using boto3, statistical baselining, and behavioral analysis
  to identify credential compromise, privilege escalation, and unauthorized resource access.
domain: cybersecurity
subdomain: cloud-security
tags:
- cloud-security
- aws
- cloudtrail
- anomaly-detection
- threat-detection
- boto3
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---
# Detecting AWS CloudTrail Anomalies

## Overview

AWS CloudTrail records API calls across AWS services. This skill covers querying CloudTrail events with boto3's `lookup_events` API, building statistical baselines of normal API activity, detecting anomalies such as unusual event sources, geographic anomalies, high-frequency API calls, and first-time API usage patterns that indicate compromised credentials or insider threats.


## When to Use

- When investigating security incidents that require detecting aws cloudtrail anomalies
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **`lookup_events` is management-events only, last 90 days:** S3/Lambda **data events** are not returned and read-only `List`/`Describe`/`Get` calls are excluded. Bulk `GetObject` exfil or enumeration will be invisible unless you read the trail's S3/CloudWatch Logs destination instead.
- **The log can be turned off or steered around:** attackers run `StopLogging`/`UpdateTrail`/`DeleteTrail`, disable the trail's KMS key, or simply operate in a region the trail doesn't cover. Alert on those control-plane events themselves and confirm the trail is multi-region.
- **Identity attribution traps:** assumed-role activity shows the **role** ARN, not the human — correlate `sourceIdentity`/session name; `sourceIPAddress` is often an AWS service hostname (`*.amazonaws.com`) for service-initiated calls, which naive geo/IP-anomaly logic mislabels.
- **Baseline & threshold evasion:** "first-time API" rules misfire after legitimate new deployments; high-error-rate recon can be paced under thresholds. Tune with per-principal baselines and exclude known automation ARNs.
- **Validate the detection:** check `aws cloudtrail get-trail-status` shows `IsLogging: true` and the trail is `IsMultiRegionTrail`; then perform a benign sensitive call (e.g., `iam:CreateUser` then delete) and confirm it surfaces in your pipeline within the expected window.

## Prerequisites

- Python 3.9+ with `boto3` library
- AWS credentials with CloudTrail read permissions (cloudtrail:LookupEvents)
- Understanding of AWS IAM and common API patterns
- CloudTrail enabled in target AWS account (management events at minimum)

## Steps

### Step 1: Query CloudTrail Events
Use boto3 CloudTrail client's lookup_events to retrieve recent API activity with pagination.

### Step 2: Build Activity Baseline
Aggregate events by user, source IP, event source, and event name to establish normal behavior patterns.

### Step 3: Detect Anomalies
Flag unusual patterns: new event sources per user, first-time API calls, geographic IP changes, high error rates, and sensitive API usage (IAM, KMS, S3 policy changes).

### Step 4: Generate Detection Report
Produce a JSON report with anomaly scores, top suspicious users, and recommended investigation actions.

## Expected Output

JSON report with event statistics, baseline deviations, anomalous users/IPs, sensitive API calls, and error rate analysis.
