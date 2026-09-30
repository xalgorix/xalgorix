# Xalgorix — AI autonomous penetration testing platform (Kali, batteries-included).
#
# The runtime is based on Kali Linux and pulls in Kali's pentest metapackages,
# so hundreds of offensive-security tools are preinstalled. On top of that every
# package manager the agent uses (apt, go, cargo, pipx/pip, npm) is available at
# runtime, so the LLM-driven terminal can still auto-install anything missing.
#
# It runs as ROOT on purpose: the engine only enables package auto-install for
# uid 0 (internal/config: AllowAutoInstall defaults to os.Getuid()==0), and
# apt/go/cargo installs need write access to system paths. The container is the
# isolation boundary — treat it as a disposable, network-isolated scanning
# sandbox and never expose the dashboard without auth.
#
# This is a large image (many GB — the full Kali toolset + wordlists + Go/Rust
# toolchains). That is intentional; size is traded for a complete toolbox.
#
# Build:  docker build -t xalgorix .
# Run:    docker run --rm -p 9137:9137 \
#           --privileged \
#           -e XALGORIX_LLM=openai/gpt-5.6 \
#           -e XALGORIX_API_KEY=your_provider_api_key \
#           -v xalgorix-data:/data \
#           ghcr.io/xalgord/xalgorix:latest
#
# --privileged gives the toolset the same host-like access it has when run
# natively as root. Docker's DEFAULT sandbox drops capabilities (NET_ADMIN, …)
# and applies a seccomp/AppArmor filter that breaks low-level tools (iptables,
# route/interface changes, ARP-spoof/MITM, tun/tap VPNs, ptrace debuggers,
# masscan interface tuning). An image CANNOT grant itself capabilities — they
# are set at run time — so pass --privileged (or the narrower
# --cap-add=NET_ADMIN --cap-add=NET_RAW --cap-add=SYS_PTRACE
# --security-opt seccomp=unconfined), or just use docker-compose.yml which
# sets privileged mode for you.
#
# Then open http://127.0.0.1:9137
#
# Published for linux/amd64 and linux/arm64. Release binaries also cover native
# Linux and macOS installs via the one-line installer.

# ── Stage 1: build the React web UI ──────────────────────────────────────────
FROM node:22-bookworm-slim AS webui
WORKDIR /src
# Copy the lockfile so npm ci installs the exact versions verified by the
# contributor (React 19 / TS 7 / Vite 8), instead of resolving fresh from
# the caret ranges on every rebuild. package-lock.json is now tracked in
# the repo (see .gitignore exception); the glob stays for any older build
# context that lacks it.
COPY webui/package.json webui/package-lock.json* ./webui/
# npm ci fails if package.json and the lockfile disagree — that is the
# point: a drift between the manifest and the lockfile must break the
# build rather than silently re-resolving to whatever is latest.
RUN cd webui && npm ci --no-audit --no-fund
COPY webui ./webui
COPY internal/web ./internal/web
RUN cd webui && npm run build

# ── Stage 2: build the Go binary + the latest Go security toolset ────────────
# Go 1.26+ is required: projectdiscovery/httpx v1.10.0 declares `go >= 1.26`, so
# a 1.25 builder makes `go install httpx@latest` fail (silently, via the `|| WARN`
# in the tool loop) and the image ships without the ProjectDiscovery scanner.
FROM golang:1.26-bookworm AS gobuild
# libpcap-dev is needed to compile naabu (CGO); git for module fetches.
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev git \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=webui /src/internal/web/static ./internal/web/static
ARG VERSION=docker
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/xalgorix ./cmd/xalgorix/

# Latest versions of the Go tools the engine knows how to auto-install
# (packageMap → goTools), into /go/bin. Best-effort per tool so one flaky
# module never fails the image; anything missing stays runtime-installable.
# NOTE: nuclei is deliberately NOT in this loop. It's the security-critical,
# fast-moving scanner, so it's installed + template-synced in a dedicated,
# cache-bustable layer in the runtime stage (see NUCLEI_VERSION/TOOLS_REFRESH
# below) to guarantee a fresh engine + latest templates on every refreshed build.
ENV GOBIN=/go/bin
RUN set -eux; \
    for pkg in \
      github.com/projectdiscovery/httpx/cmd/httpx@latest \
      github.com/projectdiscovery/dnsx/cmd/dnsx@latest \
      github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
      github.com/projectdiscovery/katana/cmd/katana@latest \
      github.com/jaeles-project/gospider@latest \
      github.com/lc/gau/v2/cmd/gau@latest \
      github.com/tomnomnom/waybackurls@latest \
      github.com/tomnomnom/assetfinder@latest \
      github.com/tomnomnom/qsreplace@latest \
      github.com/tomnomnom/gf@latest \
      github.com/tomnomnom/anew@latest \
      github.com/hakluke/hakrawler@latest \
      github.com/OJ/gobuster/v3@latest \
      github.com/ffuf/ffuf/v2@latest \
      github.com/hahwul/dalfox/v2@latest \
      github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest \
      github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest \
      github.com/projectdiscovery/notify/cmd/notify@latest \
      github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest \
      github.com/tomnomnom/unfurl@latest \
      github.com/tomnomnom/gron@latest \
      github.com/tomnomnom/httprobe@latest \
      github.com/haccer/subjack@latest \
      github.com/securego/gosec/v2/cmd/gosec@latest \
      github.com/zricethezav/gitleaks/v8@latest \
    ; do go install -v "$pkg" || echo "WARN: go install $pkg failed (installable at runtime)"; done; \
    CGO_ENABLED=1 go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest \
      || echo "WARN: naabu build failed (installable at runtime)"

# ── Stage 3: runtime — Kali Linux, full toolset, runs as root ────────────────
FROM kalilinux/kali-rolling

ARG TARGETARCH
ENV DEBIAN_FRONTEND=noninteractive

# Kali metapackages = the extensive toolset. Recommends are left ON so the
# metapackages pull their full tool set. Covers the web/app-pentest domains the
# agent uses plus general coverage, and adds the package managers required for
# runtime auto-install (go/cargo/pipx/npm) and Chromium for browser DAST.
#
# Kali rolling mirrors periodically serve size-mismatched (mid-sync) package
# indexes through CDN edges ("File has unexpected size … Mirror sync in
# progress?"), failing `apt-get update` with exit 100 even though the same
# index is consistent minutes later — release builds died on this race
# twice, 40 minutes apart. Retry the index fetch with backoff instead of
# failing the whole container build on a mirror sync.
RUN set -eux; \
    ok=0; \
    for i in 1 2 3 4 5; do \
      if apt-get -o Acquire::Retries=3 update; then ok=1; break; fi; \
      echo "apt index fetch failed (mirror sync?); retry $i/5 in 45s"; \
      rm -rf /var/lib/apt/lists/*; \
      sleep 45; \
    done; \
    [ "$ok" = "1" ]; \
    apt-get install -y \
      kali-linux-headless \
      kali-tools-information-gathering \
      kali-tools-web \
      kali-tools-vulnerability \
      kali-tools-fuzzing \
      kali-tools-passwords \
      kali-tools-exploitation \
      kali-tools-post-exploitation \
    && apt-get install -y --no-install-recommends \
      ca-certificates curl wget git jq unzip zip p7zip-full file tree bc xxd \
      seclists wordlists \
      python3 python3-pip python3-venv pipx \
      cargo \
      nodejs npm \
      build-essential pkg-config libpcap-dev libcap2-bin \
      chromium \
      findomain dirsearch \
    && rm -rf /var/lib/apt/lists/*

# Strip file capabilities from every bundled tool so a plain `docker run` works.
#
# Kali ships several tools (nmap most notably, at /usr/lib/nmap/nmap) with file
# capabilities set with the EFFECTIVE bit, e.g. cap_net_raw,cap_net_admin,
# cap_net_bind_service+eip. Under Docker's DEFAULT security profile the
# capability bounding set drops NET_ADMIN, and the kernel fails execve() with
# EPERM ("Operation not permitted") whenever a binary requests an effective
# capability that isn't in the bounding set — so `nmap` won't even start under a
# default `docker run`, with no cap-add/seccomp overrides.
#
# The engine runs as ROOT on purpose, and root already holds NET_RAW in Docker's
# default bounding set, so these file caps are redundant: removing them lets the
# binaries exec cleanly and fall back to root's own capabilities for raw-socket
# scans. This clears the entire class of "Operation not permitted" exec errors
# (nmap, masscan, arping, dumpcap, …) for containerized deployments.
RUN getcap -r / 2>/dev/null | awk '{print $1}' | while read -r f; do \
      setcap -r "$f" 2>/dev/null || true; \
    done || true

# Go toolchain at runtime so the agent can `go install` anything not baked in.
COPY --from=gobuild /usr/local/go /usr/local/go
# Prebuilt latest Go security tools → on PATH via /root/go/bin.
COPY --from=gobuild /go/bin/ /root/go/bin/
# The xalgorix binary itself.
COPY --from=gobuild /out/xalgorix /usr/local/bin/xalgorix

ENV PATH="/usr/local/go/bin:/root/go/bin:/root/.cargo/bin:/root/.local/bin:${PATH}" \
    GOBIN=/root/go/bin \
    HOME=/root

# feroxbuster (Rust) — Kali packages it, but grab the latest release binary too
# so it's current; cargo stays available at runtime as the engine's fallback.
RUN case "${TARGETARCH}" in \
      amd64) ferox_arch=x86_64 ;; \
      arm64) ferox_arch=aarch64 ;; \
      *) echo "Unsupported Docker target architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && curl -fsSLo /tmp/ferox.zip "https://github.com/epi052/feroxbuster/releases/latest/download/${ferox_arch}-linux-feroxbuster.zip" \
    && unzip -o /tmp/ferox.zip -d /usr/local/bin feroxbuster \
    && chmod +x /usr/local/bin/feroxbuster \
    && rm -f /tmp/ferox.zip \
    || echo "WARN: feroxbuster prefetch failed (present via Kali/cargo)"

# Python tools the engine auto-installs via pipx (best-effort at build). One per
# tool so a single flaky package never fails the image; the rest stay
# runtime-installable via the packageMap → pipx path.
RUN for p in scrapling semgrep bandit git-dumper arjun uro; do \
      pipx install "$p" || pip3 install --break-system-packages "$p" \
        || echo "WARN: pipx prefetch of $p failed (installable at runtime)"; \
    done

# paramspider — the real tool is GitHub-only (PyPI `paramspider` is an empty
# 1.3 kB stub with no CLI), so install straight from the repo.
RUN pipx install "git+https://github.com/devanshbatham/paramspider.git" \
    || echo "WARN: paramspider prefetch failed (installable at runtime)"

# Ruby (Rails SAST) — best-effort.
RUN gem install --no-document brakeman || echo "WARN: brakeman prefetch failed (installable at runtime)"

# trufflehog — no clean `go install` (its go.mod uses replace directives), so
# pull the official release binary into /usr/local/bin.
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
      | sh -s -- -b /usr/local/bin \
    || echo "WARN: trufflehog prefetch failed (installable at runtime)"

# GitHub CLI (gh) — not in the Kali apt index, so add GitHub's official repo.
RUN mkdir -p -m 755 /etc/apt/keyrings \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
         > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/* \
    || echo "WARN: gh prefetch failed (installable at runtime)"

# CMSmap — git-cloned CMS scanner; expose a `cmsmap` wrapper on PATH.
RUN git clone --depth 1 https://github.com/Dionach/CMSmap /opt/CMSmap \
    && (pip3 install --break-system-packages -r /opt/CMSmap/requirements.txt 2>/dev/null || true) \
    && printf '#!/bin/sh\nexec python3 /opt/CMSmap/cmsmap.py "$@"\n' > /usr/local/bin/cmsmap \
    && chmod +x /usr/local/bin/cmsmap \
    || echo "WARN: cmsmap prefetch failed (installable at runtime)"

# ── nuclei engine + templates: always-latest, dedicated cache-bustable layer ──
# nuclei is the security-critical, fast-moving scanner — a stale engine or stale
# vuln templates directly means missed findings. Installing it HERE (instead of
# the bulk go-tool loop in the builder) isolates it after every other expensive
# apt/tool/pipx layer, so a cache-bust re-pulls the latest engine AND templates
# cheaply, without re-running the layers above:
#
#   * default build ................ uses Docker's layer cache (fast, unchanged)
#   * --build-arg TOOLS_REFRESH=<changing value> .. forces a fresh engine +
#         templates. redeploy.sh and the release CI pass this on every build, so
#         shipped images always carry the latest nuclei + latest templates.
#   * --build-arg NUCLEI_VERSION=vX.Y.Z ........... pin the engine for repro builds.
#
# The runtime Go toolchain (copied above) builds it; the module/build caches are
# pruned afterwards so the layer stays lean. Best-effort: a network blip leaves
# nuclei runtime-installable, consistent with the rest of this image.
ARG NUCLEI_VERSION=latest
ARG TOOLS_REFRESH=
# echo references TOOLS_REFRESH so a changing value invalidates this layer's
# cache; go clean runs in the SAME RUN so the module/build caches are never
# committed to the image.
RUN echo "nuclei refresh token: ${TOOLS_REFRESH:-none}"; \
    { GOBIN=/root/go/bin go install -v "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}" \
      && /root/go/bin/nuclei -update-templates >/dev/null 2>&1 ; } \
      || echo "WARN: nuclei engine/template refresh failed (installable at runtime)"; \
    go clean -cache -modcache 2>/dev/null || true

# Make `httpx` resolve to ProjectDiscovery's scanner. Kali/pip ship a Python
# `httpx` CLI (the HTTP client) at /usr/bin/httpx that otherwise answers `httpx`
# and breaks the engine's recon (unknown flags like -silent/-title). /root/go/bin
# is already ahead of /usr/bin on PATH; also point the absolute path at the PD
# binary so nothing falls back to the Python client.
RUN if [ -x /root/go/bin/httpx ]; then ln -sf /root/go/bin/httpx /usr/bin/httpx; \
    else echo "WARN: ProjectDiscovery httpx not baked into /root/go/bin"; fi

# Same story for nuclei: Kali's kali-tools-vulnerability metapackage installs an
# (often older) nuclei at /usr/bin/nuclei. /root/go/bin is already ahead of
# /usr/bin on PATH, but pin the absolute path to the freshly-installed PD engine
# so login shells and any hard-coded /usr/bin/nuclei can't fall back to the apt
# build.
RUN if [ -x /root/go/bin/nuclei ]; then ln -sf /root/go/bin/nuclei /usr/bin/nuclei; \
    else echo "WARN: ProjectDiscovery nuclei not present in /root/go/bin"; fi

ENV XALGORIX_BIND=0.0.0.0 \
    XALGORIX_BROWSER_PATH=/usr/bin/chromium \
    XALGORIX_DATA_DIR=/data \
    XALGORIX_ALLOW_AUTO_INSTALL=1 \
    XALGORIX_NO_AUTO_UPDATE=1

# Entrypoint generates dashboard credentials when none are supplied (the image
# binds 0.0.0.0, which the engine won't do without auth) so a plain
# `docker run` starts cleanly and securely.
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

RUN mkdir -p /data
VOLUME ["/data"]
EXPOSE 9137

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["--web"]
