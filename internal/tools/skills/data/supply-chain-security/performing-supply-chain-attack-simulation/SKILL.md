---
intent: offensive
name: performing-supply-chain-attack-simulation
description: Simulate and detect software supply chain attacks including typosquatting detection via Levenshtein distance,
  dependency confusion testing against private registries, package hash verification with pip, and known vulnerability scanning
  with pip-audit.
domain: cybersecurity
subdomain: application-security
tags:
- supply-chain
- typosquatting
- dependency-confusion
- package-verification
- pip-audit
- PyPI
- software-composition-analysis
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.PS-01
- PR.PS-04
- ID.RA-01
- PR.DS-10
---

# Performing Supply Chain Attack Simulation

## Overview

Software supply chain attacks exploit trust in package registries through typosquatting (registering names similar to popular packages), dependency confusion (publishing higher-version public packages matching private names), and compromised package distribution. This skill detects these attack vectors by computing Levenshtein distance between package names and popular PyPI packages, verifying package integrity via SHA-256 hash comparison, scanning for known CVEs with pip-audit, and testing dependency resolution order for confusion vulnerabilities.


## When to Use

- When conducting security assessments that involve performing supply chain attack simulation
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Most Often Missed & How to Confirm

Simulations that only run `pip-audit` against installed packages miss the attacks that actually compromise pipelines.

- **Dependency confusion:** check whether each *internal* package name also exists on public PyPI/npm at a **higher** version. Resolvers that lack `--index-url` pinning or an explicit `priority`/scope will pull the public (attacker) version first.
- **Typosquats in lockfiles:** compute Levenshtein/edit distance of every dependency against the top-1000 list — distance 1-2 (`reqeusts`, `python-requsts`) is the high-signal band, plus separator swaps (`my-pkg` ↔ `my_pkg`).
- **CI token / secret theft:** a malicious package's `setup.py`/`postinstall` reads `os.environ` (`NPM_TOKEN`, `AWS_*`, `GITHUB_TOKEN`) at install time. Simulate by installing in a sandbox with `--no-build-isolation` off and watching for outbound egress + env reads.
- **Build-system compromise:** an unpinned or mutable build dependency swaps in a trojaned wheel. Verify by SHA-256 pinning (`--require-hashes`) and confirming a changed digest fails the install.

**Positive signal to confirm a hit:** for dependency confusion, the resolver actually installs the public higher-version package over the private one (observe the resolved index URL + version). For typosquats, a flagged name resolves to a *different author* with recent first-upload and near-zero downloads. **Do not conclude "not vulnerable"** until you have tested all four vectors against every direct *and* transitive dependency and across both registries — a clean `pip-audit` only covers known CVEs, not confusion or typosquatting.

## Prerequisites

- Python 3.9+ with `pip-audit`, `Levenshtein`, `requests`
- Access to PyPI JSON API (https://pypi.org/pypi/{package}/json)
- Network access for package metadata retrieval


> **Legal Notice:** This skill is for authorized security testing and educational purposes only. Unauthorized use against systems you do not own or have written permission to test is illegal and may violate computer fraud laws.

## Key Detection Areas

1. **Typosquatting** — compare package names against top PyPI packages using edit distance thresholds
2. **Dependency confusion** — check if internal package names exist on public PyPI with higher version numbers
3. **Hash verification** — download packages and verify SHA-256 digests match published hashes
4. **Vulnerability scanning** — audit installed packages against OSV and PyPA advisory databases
5. **Metadata anomalies** — flag packages with suspicious author emails, missing homepages, or very recent first upload dates

## Output

JSON report with risk scores per package, detected attack vectors, hash verification results, and CVE findings.
