---
name: implementing-secrets-scanning-in-ci-cd
description: Integrate gitleaks and trufflehog into CI/CD pipelines to detect leaked secrets before deployment
domain: cybersecurity
subdomain: devsecops
tags:
- secrets-scanning
- gitleaks
- trufflehog
- ci-cd
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.PS-01
- GV.SC-07
- ID.IM-04
- PR.PS-04
---


# Implementing Secrets Scanning in CI/CD

## Overview

This skill covers implementing automated secrets scanning in CI/CD pipelines using gitleaks and trufflehog. It enables security teams to detect API keys, tokens, passwords, and other credentials that have been accidentally committed to source code repositories, providing a CI gate that blocks deployments containing high-severity findings.

Gitleaks scans git repositories and directories for hardcoded secrets using regex patterns and entropy analysis. TruffleHog performs filesystem and git history scans with optional secret verification against live services. Together they provide comprehensive coverage for secrets detection.


## When to Use

- When deploying or configuring implementing secrets scanning in ci cd capabilities in your environment
- When establishing security controls aligned to compliance requirements
- When building or improving security architecture for this domain
- When conducting security assessments that require this implementation

## Common Misconfigurations & Verification

The most common failure is a scanner that runs but never fails the pipeline:

- **No `--exit-code`, or exit code swallowed.** `gitleaks detect/dir` without `--exit-code 1` (or wrapped in `|| true`, or a job with `continue-on-error: true`) reports findings while the stage stays green. The CI gate verdict must translate to a non-zero process exit.
- **Shallow clone / HEAD-only scan.** A default `fetch-depth: 1` checkout or scanning only the latest commit means secrets buried in history go undetected. Use `fetch-depth: 0` and scan full history (no narrowing `--log-opts`).
- **TruffleHog without verification or scoped too narrow.** `trufflehog filesystem` over a partial path, or ignoring `--only-verified` semantics, changes what counts as a finding — be explicit about scope and severity mapping.
- **Threshold set too high.** A gate that only fails on `critical` lets `high` secrets through; confirm the parse-and-filter step's threshold matches policy.
- **Over-broad `.gitleaksignore` / allowlist** silently suppresses real leaks.
- **Pre-commit hook in report-only mode** instead of `gitleaks protect --staged`, so secrets still reach the repo.

**Concrete verification:** Add a known fake credential (e.g. `AKIAIOSFODNN7EXAMPLE` plus a fake secret key, or a `ghp_` token) to a tracked file and run the pipeline. Confirm gitleaks/trufflehog report it, the CI gate verdict is `FAIL`, and the **process exits non-zero so the deployment is blocked** — then remove the test secret.

## Prerequisites

- Python 3.9 or later
- gitleaks v8.x installed and available on PATH
- trufflehog v3.x installed and available on PATH
- A git repository or directory to scan
- Access to CI/CD platform (GitHub Actions, GitLab CI, Jenkins)

## Steps

1. **Install scanning tools**: Install gitleaks via package manager or binary download. Install trufflehog via `brew install trufflehog` or download from GitHub releases.

2. **Configure gitleaks**: Create a `.gitleaks.toml` configuration file in the repository root to define custom rules, allowlists, and path exclusions. Use `--config` flag to point to custom configs.

3. **Run gitleaks directory scan**: Execute `gitleaks dir --source . --report-format json --report-path gitleaks-report.json` to scan the working directory and generate a JSON report.

4. **Run trufflehog filesystem scan**: Execute `trufflehog filesystem /path/to/repo --json > trufflehog-report.json` to scan files and output JSON findings to a report file.

5. **Parse and filter findings**: Use the agent script to parse both JSON reports, filter findings by severity (critical, high, medium, low), and determine whether the CI pipeline should pass or fail.

6. **Integrate into CI pipeline**: Add the scanning step to your GitHub Actions workflow, GitLab CI config, or Jenkins pipeline as a pre-deployment gate. Use `--exit-code` flag in gitleaks to control pipeline behavior.

7. **Configure pre-commit hooks**: Set up gitleaks as a pre-commit hook using `gitleaks protect --staged` to catch secrets before they are committed.

8. **Review and triage findings**: Examine the JSON output for false positives, add legitimate entries to `.gitleaksignore`, and rotate any confirmed leaked credentials immediately.

## Expected Output

The agent script produces a JSON report containing:
- Total findings count from each scanner
- Findings grouped by severity level
- Individual finding details including file path, line number, rule ID, and redacted secret
- A CI gate verdict (pass/fail) based on the configured severity threshold
- Execution metadata including scan duration and tool versions

```text
{
  "scan_summary": {
    "tool": "both",
    "total_findings": 3,
    "critical": 1,
    "high": 1,
    "medium": 1,
    "low": 0,
    "ci_gate": "FAIL",
    "fail_reason": "Found 1 critical and 1 high severity findings"
  },
  "findings": [...]
}
```
