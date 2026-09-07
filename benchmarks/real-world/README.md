# Real-world CVE benchmarks

This suite measures Xalgorix against locally deployed, version-pinned releases
of real open-source products. It complements the synthetic and XBOW suites; it
does not replace their broad per-class regression coverage.

The denominator is deliberately narrow and auditable. A target's manifest lists
specific vendor-documented vulnerabilities that are reachable in the supplied
configuration. A result such as `1/1` means Xalgorix proved the one CVE in that
targeted corpus. It does **not** claim the product has exactly one vulnerability.
Unmatched findings require manual triage and are not automatically labeled false
positives. A paired patched release is used to measure false-positive regressions.

## Grafana CVE-2021-43798

The first pair is Grafana OSS 8.2.6 and its patched 8.2.7 release. Grafana's
advisory documents unauthenticated path traversal/local-file disclosure through
an installed plugin route, affecting versions from 8.0.0-beta1 through 8.3.0;
8.2.7 is one of the patched releases.

Both official images are pinned by multi-platform manifest digest and remain on
an internal Docker network, which prevents the vulnerable applications from
reaching external systems. A capability-dropped, read-only HAProxy container
(also digest-pinned) bridges that network to ports bound only on loopback. The
manifest loader and CLI reject non-loopback target URLs, including command-line
overrides.

Start the pair:

```bash
docker compose -f benchmarks/real-world/grafana/compose.yaml up -d
```

Wait until both health endpoints answer:

```bash
curl --fail http://127.0.0.1:3300/api/health
curl --fail http://127.0.0.1:3301/api/health
```

Before spending model tokens, confirm that the pinned positive/control pair has
the expected behavior. Run these requests only against the loopback containers:

```bash
curl --path-as-is --fail \
  http://127.0.0.1:3300/public/plugins/alertlist/../../../../../../../../etc/passwd

curl --path-as-is --include \
  http://127.0.0.1:3301/public/plugins/alertlist/../../../../../../../../etc/passwd
```

The first response exposes the container's local passwd file. The fixed control
must refuse the same traversal request.

Run a blind full assessment of the vulnerable release. The expected CVE is used
only after the scan for deterministic scoring; it is not added to the agent's
instruction. Use at least three sequential runs when comparing scanner changes,
so an intermittent hit cannot masquerade as reliable recall:

```bash
go run ./cmd/xalgorix-bench \
  -manifest benchmarks/real-world/grafana/manifest.json \
  -target-id grafana-8.2.6-cve-2021-43798 \
  -runs 3 \
  -timeout 15m \
  -result-json tmp/grafana-8.2.6-result.json
```

Then run the patched control independently:

```bash
go run ./cmd/xalgorix-bench \
  -manifest benchmarks/real-world/grafana/manifest.json \
  -target-id grafana-8.2.7-fixed-control \
  -runs 3 \
  -timeout 15m \
  -result-json tmp/grafana-8.2.7-control.json
```

The command uses the production agent wiring and therefore requires a configured
Xalgorix LLM provider. A positive match must carry `verified` or
`exploit-proven` evidence and match the expected endpoint family. An exact CVE
identifier is authoritative even when the model omits optional CWE/class
metadata; otherwise the class and CWE must agree. An explicitly reported wrong
HTTP method is rejected, while an omitted optional method does not erase an
otherwise exact proof-bearing signature. Any matching report on the patched
release is a control regression.
Duplicate matches and unproven candidates are shown separately. Result files are
created with mode `0600` because proof may contain local file contents or tokens.
The aggregate reports mean and min/max targeted recall, each CVE's cross-run hit
rate, how many CVEs appeared in every run versus only some run, and how many
patched-control runs regressed. The command exits non-zero unless every expected
CVE is matched in every vulnerable-target run and every fixed-control run stays
clean; intermittent recall is a failed benchmark, not a passing average.

Clean up the exact benchmark stack when both runs finish:

```bash
docker compose -f benchmarks/real-world/grafana/compose.yaml down -v
```

Do not point these reproduction requests or active scans at third-party systems.
Add future targets only when their advisory, vulnerable version, fixed version,
container digest, reachable configuration, and positive/control behavior can all
be independently reproduced.
