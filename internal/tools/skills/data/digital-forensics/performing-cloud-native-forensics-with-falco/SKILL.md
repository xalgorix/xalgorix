---
intent: defensive
name: performing-cloud-native-forensics-with-falco
description: 'Uses Falco YAML rules for runtime threat detection in containers and Kubernetes, monitoring syscalls for shell
  spawns, file tampering, network anomalies, and privilege escalation. Manages Falco rules via the Falco gRPC API and parses
  Falco alert output. Use when building container runtime security or investigating k8s cluster compromises.

  '
domain: cybersecurity
subdomain: cloud-security
tags:
- performing
- cloud
- native
- forensics
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
nist_csf:
- PR.IR-01
- ID.AM-08
- GV.SC-06
- DE.CM-01
---

# Performing Cloud Native Forensics with Falco


## When to Use

- When conducting security assessments that involve performing cloud native forensics with falco
- When following incident response procedures for related security events
- When performing scheduled security testing or auditing activities
- When validating security controls through hands-on testing

## Detection Gaps & Validation

- **Rule exceptions are an evasion surface:** the `not proc.pname in (docker-entrypo, supervisord)` exclusion in the shell rule means an attacker who renames or reparents under those names evades it. Audit every `not ...` clause and anchor conditions on `proc.exepath`/`container.image` rather than `proc.pname`.
- **No driver = no events:** Falco needs a working kernel module or eBPF probe. If the driver fails to load, Falco runs but sees zero syscalls. Verify the driver loaded with `falco --version` and confirm events flow by triggering a known action.
- **Syscall drops silently lose alerts:** under load the ring buffer overflows. Monitor `falco_n_drops`/`n_evts` (Prometheus metrics or the periodic stats line) - nonzero drops mean missed detections, not a quiet host.
- **Detection is not prevention, and alerts must leave the node first:** an attacker can kill `falco` or wipe `/var/log/falco/alerts.json`. Ship alerts off-host immediately via the gRPC output / Falcosidekick so evidence survives node compromise.
- **K8s context needs the audit feed:** `container.*`/`k8s.*` fields and the k8s audit rules require the API audit log / metadata plugin wired in; without it, pod/namespace attribution is blank.
- **How to confirm coverage:** `kubectl exec -it <pod> -- sh` into a workload and confirm the "Shell Spawned in Container" alert appears in `alerts.json` with the right `container.name`/`image`; read a sensitive file and confirm the file-access rule fires.
- **Don't conclude the cluster is clean until** the driver is confirmed loaded, `falco_n_drops` is zero over the window, alerts are shown arriving at the off-node sink, and a synthetic shell/file-read actually triggers.

## Prerequisites

- Familiarity with cloud security concepts and tools
- Access to a test or lab environment for safe execution
- Python 3.8+ with required dependencies installed
- Appropriate authorization for any testing activities

## Instructions

Deploy and manage Falco rules for runtime security detection in containerized
environments. Parse Falco alerts for incident response.

```yaml
# Custom Falco rule for detecting shell in container
- rule: Shell Spawned in Container
  desc: Detect shell process started in a container
  condition: >
    spawned_process and container
    and proc.name in (bash, sh, zsh, dash, csh)
    and not proc.pname in (docker-entrypo, supervisord)
  output: >
    Shell spawned in container
    (user=%user.name command=%proc.cmdline container=%container.name
     image=%container.image.repository)
  priority: WARNING
  tags: [container, shell, mitre_execution]
```

Key detection rules:
1. Shell spawn in non-interactive containers
2. Sensitive file access (/etc/shadow, /etc/passwd)
3. Outbound connections from unexpected containers
4. Privilege escalation via setuid/setgid
5. Container escape via mount or ptrace

## Examples

```bash
# Run Falco with custom rules
falco -r /etc/falco/custom_rules.yaml -o json_output=true
# Parse JSON alerts
cat /var/log/falco/alerts.json | python3 -c "import json,sys; [print(json.loads(l)['output']) for l in sys.stdin]"
```
