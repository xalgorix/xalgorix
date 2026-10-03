---
name: implementing-log-integrity-with-blockchain
description: Build an append-only log integrity chain using SHA-256 hash chaining for tamper detection. Each log entry is
  hashed with the previous entry's hash to create a blockchain-like structure where modifying any entry invalidates all subsequent
  hashes. Implements log ingestion, chain verification, tamper detection with pinpoint identification, and periodic checkpoint
  anchoring to external timestamping services.
domain: cybersecurity
subdomain: security-operations
tags:
- implementing
- log
- integrity
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



# Implementing Log Integrity with Blockchain


## When to Use

- When deploying or configuring implementing log integrity with blockchain capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

- **Genesis not anchored:** if the first `prev_hash` is a hardcoded zero with no external witness, an attacker who rewrites the whole chain (including index 0) produces a valid-looking ledger. Anchor periodic checkpoint hashes to an external timestamping authority (RFC 3161 TSA / OpenTimestamps) so a full rewrite is detectable.
- **Hashing fields that omit ordering/index:** if `chain_hash` covers only `prev_hash + content` but not the index and timestamp, entries can be reordered or replayed without breaking the chain. Include the index and a monotonic timestamp in the hashed material.
- **Ledger stored writable next to the logs:** if `log_chain.json` has the same write perms on the same host as the source logs, tamper-then-rechain is trivial. Append-only storage (WORM / S3 Object Lock) or off-host replication is required for the integrity claim to hold.
- **Verification only checks the tail:** recompute and compare EVERY hash from index 0, not just the latest — a break at entry 42 must flag 42..N. Confirm by mutating one byte of a middle entry and re-running `--verify`; the report must pinpoint the first broken index.
- **Confirm anchoring round-trips:** after a checkpoint, independently re-verify the checkpoint hash against the external service's response, not just your local record of it.

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install requests`
2. Ingest log entries from syslog, JSON, or plain text files.
3. For each entry, compute SHA-256 hash of: previous_hash + timestamp + log_content.
4. Store the chain as a JSON ledger with entry index, timestamp, content hash, previous hash, and chain hash.
5. Verify chain integrity by recomputing all hashes and detecting breaks.
6. Optionally anchor checkpoint hashes to an external timestamping service.

```bash
python scripts/agent.py --log-file /var/log/syslog --chain-file log_chain.json --verify --output integrity_report.json
```

## Examples

### Chain Entry Structure
```json
{"index": 42, "timestamp": "2024-01-15T10:30:00Z", "content_hash": "a1b2c3...",
 "prev_hash": "d4e5f6...", "chain_hash": "SHA256(prev_hash + timestamp + content_hash)"}
```

### Tamper Detection
If entry 42 is modified, chain_hash[42] will not match SHA256(chain_hash[41] + ...), and all entries from 42 onward will be flagged as invalid.
