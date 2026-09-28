---
intent: defensive
name: analyzing-office365-audit-logs-for-compromise
description: Parse Office 365 Unified Audit Logs via Microsoft Graph API to detect email forwarding rule creation, inbox delegation,
  suspicious OAuth app grants, and other indicators of account compromise.
domain: cybersecurity
subdomain: cloud-security
tags:
- Office365
- Microsoft-Graph
- audit-logs
- email-compromise
- inbox-rules
- OAuth
- BEC
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Analyzing Office 365 Audit Logs for Compromise

## Overview

Business Email Compromise (BEC) attacks often leave traces in Office 365 audit logs: suspicious inbox rule creation, email forwarding to external addresses, mailbox delegation changes, and unauthorized OAuth application consent grants. This skill uses the Microsoft Graph API to query the Unified Audit Log, enumerate inbox rules across mailboxes, detect forwarding configurations, and identify compromised account indicators.


## When to Use

- When investigating security incidents that require analyzing office365 audit logs for compromise
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **Forwarding hides in more than inbox rules:** check `New-InboxRule`/`Set-InboxRule`/`UpdateInboxRules` *and* mailbox-level `Set-Mailbox -ForwardingSmtpAddress`/`-ForwardingAddress`, plus transport rules (`New-TransportRule`). A clean inbox-rule list does not mean no forwarding.
- **Operations attackers use:** `Add-MailboxPermission`/`Add-RecipientPermission` (delegation), `Consent to application` / `Add app role assignment grant to user` (illicit OAuth consent), `Add delegated permission grant`, and `Set-MailboxAuditBypassAssociation` (silences mailbox auditing for an identity — a strong tamper signal).
- **MailItemsAccessed** (access-scoping for BEC blast radius) only logs with E5/Advanced Audit; on E3 you cannot prove which messages were read.
- **UAL realities:** ingestion latency (minutes to hours) means `ago(1h)` windows miss late events — pivot on the event's own timestamp; default retention is 90/180 days; verify auditing is even on with `Get-AdminAuditLogConfig`/`Get-Mailbox | fl AuditEnabled` before trusting an empty result.
- **Validate the query fires:** create a benign external-forwarding inbox rule on a test mailbox, then confirm it surfaces via `Search-UnifiedAuditLog -Operations New-InboxRule` / the Graph `auditLogs` query; tune FPs by allow-listing approved enterprise apps (AppId) and known delegation service accounts.

## Prerequisites

- Azure AD app registration with `AuditLog.Read.All`, `MailboxSettings.Read`, `Mail.Read` (application permissions)
- Python 3.9+ with `msal`, `requests`
- Client secret or certificate for authentication
- Global Reader or Security Reader role

## Steps

1. Authenticate to Microsoft Graph using MSAL client credentials flow
2. Query Unified Audit Log for suspicious operations (Set-Mailbox, New-InboxRule)
3. Enumerate inbox rules across mailboxes and flag forwarding rules
4. Detect mailbox delegation changes (Add-MailboxPermission)
5. Identify OAuth consent grants to suspicious applications
6. Check for suspicious sign-in patterns from audit logs
7. Generate compromise indicator report with timeline

## Expected Output

- JSON report listing forwarding rules, delegation changes, OAuth grants, and suspicious audit events with risk scores
- Timeline of compromise indicators with affected mailboxes
