# Contributing to Xalgorix

Thanks for your interest in contributing. Xalgorix is a self-hosted,
autonomous AI pentesting engine: a single Go binary (`xalgorix`) that serves
an embedded React dashboard (`webui`) and runs scans locally. This document
covers the local development workflow.

By participating you agree to our [Code of Conduct](CODE_OF_CONDUCT.md).

## Where to start

New here? These labels are the best entry points:

- [`good first issue`](https://github.com/xalgorix/xalgorix/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
  — small, well-scoped tasks that don't require deep knowledge of the codebase.
- [`help wanted`](https://github.com/xalgorix/xalgorix/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
  — issues we'd love community help on.
- [`documentation`](https://github.com/xalgorix/xalgorix/issues?q=is%3Aissue+is%3Aopen+label%3Adocumentation)
  — documentation improvements, great for a first PR.

Comment on an issue to let us know you're picking it up so we don't double up.
Small fixes (typos, docs, obvious bugs) don't need an issue first — just open a PR.

## Contribution workflow

1. **Fork** the repo and create a topic branch off `main`
   (`git checkout -b fix/short-description`).
2. Make your change with tests. Keep the tree `gofmt`-clean and lint-clean.
3. Run the gates locally (see below) before pushing.
4. Open a PR against `main` using the PR template. CI runs `make lint`,
   `golangci-lint`, `go vet`, and the test suite on every PR — all must pass.
5. A maintainer reviews and merges. `main` is branch-protected; PRs are the
   only way in.

## Prerequisites

Install the following on your workstation:

- **Go 1.26+** — building and testing the `xalgorix` binary.
- **Node.js 20+** and **npm** — building the embedded `webui` dashboard bundle.
- **GNU Make** — the entry point for every common task.

Optional but recommended:

- `golangci-lint` (v2.x), `gosec`, `govulncheck` — used by `make lint` and the
  security tooling / CI gates.

## Building and testing

The Makefile wraps every common task:

```bash
make build          # builds webui, then the binary into ./build/xalgorix
make run            # build + run the web UI locally
make test           # runs the Go test suite
make test-race      # tests with the race detector
make lint           # gofmt + go vet
make webui          # builds the embedded webui bundle into internal/web/static
make webui-dev      # runs the webui dev server (Vite) against a local backend
```

The dashboard sources live in `webui/` (React + Vite + TypeScript) and are
compiled into `internal/web/static/`, which is embedded into the Go binary at
build time. After changing anything under `webui/`, run `make webui` (or
`make build`) so the embedded assets stay in sync.

Run all Go tooling with the module's pinned toolchain (`go.mod` sets it). Keep
the tree `gofmt`-clean and `golangci-lint`-clean — both are blocking gates in
CI (`.github/workflows/ci.yml`).

## Project layout

| Path                 | Purpose                                                        |
| -------------------- | -------------------------------------------------------------- |
| `cmd/xalgorix/`      | CLI entry point and service lifecycle (`--web`, `--start`, …). |
| `internal/web/`      | HTTP server, dashboard API, and embedded static assets.        |
| `internal/agent/`    | The autonomous scanning agent loop.                            |
| `internal/llm/`      | LLM provider catalog, router, and client.                      |
| `internal/tools/`    | Terminal execution sandbox and the bundled skill set.          |
| `webui/`             | React dashboard sources (compiled into `internal/web/static`). |

## Spec-driven workflow

Larger features are developed through specs under `.kiro/specs/`. Before
opening a PR that touches a spec area, read the relevant `requirements.md`,
`design.md`, and `tasks.md` and make sure your change either implements an
open task or proposes a clearly scoped addition.

## Releases

Releases are cut from `main` with `scripts/release.py`, a reproducible
pipeline that tags and publishes a version **only after its commit is on
`main`**. The version number lives in the `vX.Y.Z` tag and is baked into the
binary at build time — there is no version file to bump. Run the phases in
order:

```bash
python3 scripts/release.py prepare --version X.Y.Z   # verify the commit is the origin/main tip; stage a clean build tree
python3 scripts/release.py build   --version X.Y.Z   # cross-compile every platform; write manifest.json + SHA256SUMS
python3 scripts/release.py publish --version X.Y.Z --notes-file NOTES.md
```

`publish` creates the annotated `vX.Y.Z` tag on the released commit, publishes
the GitHub Release as a draft, verifies every uploaded asset against the
locally built bytes, then promotes it to published. Container images are built
and pushed by the Docker workflow, which triggers on the new tag. `main` is
branch-protected — never push to it directly.

## Reporting issues

Open a GitHub issue with reproduction steps, expected vs. actual behavior, and
any relevant logs. For security-sensitive reports, see [`SECURITY.md`](SECURITY.md).
