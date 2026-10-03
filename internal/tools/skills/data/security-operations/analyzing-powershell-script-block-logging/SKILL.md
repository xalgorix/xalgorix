---
name: analyzing-powershell-script-block-logging
description: Parse Windows PowerShell Script Block Logs (Event ID 4104) from EVTX files to detect obfuscated commands, encoded
  payloads, and living-off-the-land techniques. Uses python-evtx to extract and reconstruct multi-block scripts, applies entropy
  analysis and pattern matching for Base64-encoded commands, Invoke-Expression abuse, download cradles, and AMSI bypass attempts.
domain: cybersecurity
subdomain: security-operations
tags:
- powershell
- script-block-logging
- event-id-4104
- obfuscation-detection
- windows-forensics
- endpoint-security
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



# Analyzing PowerShell Script Block Logging


## When to Use

- When investigating security incidents that require analyzing powershell script block logging
- When building detection rules or threat hunting queries for this domain
- When SOC analysts need structured procedures for this analysis type
- When validating security monitoring coverage for related attack techniques

## Detection Gaps & Validation

- **If 4104 is disabled, you have nothing:** Script Block Logging must be enabled via GPO (`Administrative Templates > Windows PowerShell > Turn on PowerShell Script Block Logging`) or registry `HKLM\...\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging=1`. Attackers running `powershell -version 2` downgrade to an engine with no 4104/AMSI at all. Hunt for 400/600 engine-start events showing v2 and for the absence of expected 4104 volume on a host.
- **AMSI bypass precedes the malicious block:** `amsiInitFailed`, `[Ref].Assembly.GetType('...AmsiUtils')`, and reflection/obfuscated variants neutralize scanning. Detect the *bypass string itself* in 4104, since the subsequent payload may log as benign or not at all.
- **Obfuscation defeats naive regex:** tick marks (`I`+`EX`), string `-join`/`-f` format ops, `[char]` arrays, gzip+base64, and `SecureString` hide `IEX`/`DownloadString`. Score on Shannon entropy and decoded content, not literal keywords. Reconstruct multi-part scripts by `ScriptBlockId` ordered by `MessageNumber` before scoring — a split payload evades per-event matching.
- **Watch 4103 too:** Module/pipeline logging (EID 4103) captures invocation detail 4104 misses; correlate both.
- **Validate the rule fires:** in a lab, run an `-EncodedCommand` download cradle and an AMSI bypass, then confirm your parser flags both EID 4104 entries and that base64 decodes as UTF-16LE. **FP tuning:** legitimate admin tooling, Chocolatey, SCCM, and installers emit large/encoded blocks — baseline by signing cert and parent process before alerting.

## Prerequisites

- Familiarity with security operations concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

1. Install dependencies: `pip install python-evtx lxml`
2. Collect PowerShell Operational logs: `Microsoft-Windows-PowerShell%4Operational.evtx`
3. Parse Event ID 4104 entries using python-evtx to extract ScriptBlockText, ScriptBlockId, and MessageNumber/MessageTotal for multi-part script reconstruction.
4. Apply detection heuristics:
   - Base64-encoded commands (`-EncodedCommand`, `FromBase64String`)
   - Download cradles (`DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `Net.WebClient`)
   - AMSI bypass patterns (`AmsiUtils`, `amsiInitFailed`)
   - Obfuscation indicators (high entropy, tick-mark insertion, string concatenation)
5. Generate a report with reconstructed scripts, risk scores, and MITRE ATT&CK mappings.

```bash
python scripts/agent.py --evtx-file /path/to/PowerShell-Operational.evtx --output ps_analysis.json
```

## Examples

### Detect Encoded Command Execution
```python
import base64
if "-encodedcommand" in script_text.lower():
    encoded = script_text.split()[-1]
    decoded = base64.b64decode(encoded).decode("utf-16-le")
```

### Reconstruct Multi-Block Script
Scripts split across multiple 4104 events share a `ScriptBlockId`. Concatenate blocks ordered by `MessageNumber` to recover the full script.
