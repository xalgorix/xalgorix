#!/usr/bin/env python3
"""Build, publish, and verify a public Xalgorix release.

A safe, reproducible release pipeline. Unlike a branch-side "tag then release"
flow, this script NEVER creates a tag or a GitHub Release until the exact
commit being released is already merged to ``origin/main``. It builds every
platform binary from a clean detached checkout of that commit, publishes the
GitHub Release as a *draft*, verifies that every uploaded asset matches the
locally built bytes, and only then promotes the draft to published.

Usage (run the phases in order)::

    python3 scripts/release.py prepare --version X.Y.Z
    python3 scripts/release.py build   --version X.Y.Z
    python3 scripts/release.py publish --version X.Y.Z --notes-file NOTES.md
    python3 scripts/release.py verify  --version X.Y.Z --notes-file NOTES.md

The release commit must already be the tip of ``origin/main`` (or, with
``--revision``, a commit that is on ``origin/main``) — so **merge the release
PR first**, then run ``prepare``. ``main`` is protected; this script never
pushes to it, it only pushes the annotated ``vX.Y.Z`` tag once the commit is
confirmed live on ``main``.

Release assets (6): the four platform binaries, ``SHA256SUMS``, and
``manifest.json``. The one-line installer downloads the raw per-platform
binary; ``SHA256SUMS`` and ``manifest.json`` are supplementary integrity
metadata. Container images are published separately by
``.github/workflows/docker.yml``, which triggers on the pushed ``v*`` tag.

The webui bundle embedded in the binary is taken from the committed
``internal/web/static`` tree (contributors commit built assets alongside their
source changes), so this script does not rebuild it.

Optional ``--forbidden-file`` points at a newline-separated list of
case-insensitive regex patterns; if any matches the release notes, publishing
is refused. Use it to keep operational detail out of public release notes. The
file itself is never read into the repo.
"""
from __future__ import annotations

from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import subprocess

REPO_DEFAULT = "xalgorix/xalgorix"
ORIGIN_URL = "https://github.com/xalgorix/xalgorix.git"
PLATFORMS = [("linux", "amd64"), ("linux", "arm64"), ("darwin", "amd64"), ("darwin", "arm64")]
FILE_ARCH = {
    ("linux", "amd64"): "x86-64",
    ("linux", "arm64"): "ARM aarch64",
    ("darwin", "amd64"): "x86_64",
    ("darwin", "arm64"): "arm64",
}
ROOT = Path(__file__).resolve().parents[1]
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def run(args, *, cwd, env=None, timeout=1800):
    """Run a command, failing loudly with captured output on a non-zero exit."""
    result = subprocess.run(
        args, cwd=str(cwd), env=env, text=True, capture_output=True, timeout=timeout
    )
    if result.returncode:
        raise SystemExit(
            f"command failed ({result.returncode}): {' '.join(args)}\n"
            f"{result.stdout}\n{result.stderr}".rstrip()
        )
    return result.stdout.strip()


def ok(cwd, args):
    """Return True when a command exits 0, swallowing its output."""
    return subprocess.run(args, cwd=str(cwd), capture_output=True).returncode == 0


def emit(**fields):
    print(json.dumps(fields), flush=True)


class Release:
    def __init__(self, args):
        if not VERSION_RE.match(args.version):
            raise SystemExit(f"--version must be X.Y.Z, got {args.version!r}")
        self.version = args.version
        self.tag = f"v{args.version}"
        self.repo = args.repo
        self.workdir = (
            Path(args.workdir).resolve()
            if args.workdir
            else ROOT / "dist" / f"release-v{args.version}"
        )
        self.source = self.workdir / "src"
        self.assets = self.workdir / "assets"
        self.state_path = self.workdir / "release-state.json"
        self.notes = Path(args.notes_file).resolve() if getattr(args, "notes_file", None) else None
        self.forbidden_file = (
            Path(args.forbidden_file).resolve() if getattr(args, "forbidden_file", None) else None
        )
        self._revision = args.revision

    # ── state shared across phases ──────────────────────────────────────────
    def save_state(self, revision):
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(
            json.dumps({"version": self.version, "revision": revision, "repo": self.repo}, indent=2)
            + "\n"
        )

    def revision(self):
        if self._revision:
            return self._revision
        if self.state_path.exists():
            self._revision = json.loads(self.state_path.read_text())["revision"]
            return self._revision
        raise SystemExit("no recorded revision — run the 'prepare' phase first")

    # ── guards ──────────────────────────────────────────────────────────────
    def check_source(self, revision):
        assert run(["git", "rev-parse", "HEAD"], cwd=self.source) == revision, "source HEAD drifted"
        assert not run(["git", "status", "--porcelain"], cwd=self.source), "source tree is dirty"
        assert (
            run(["git", "remote", "get-url", "origin"], cwd=self.source) == ORIGIN_URL
        ), "source origin is not the public repo"
        on_main = run(["git", "ls-remote", "origin", "refs/heads/main"], cwd=self.source).split()[0]
        assert on_main == revision, (
            f"revision {revision} is not the current origin/main tip ({on_main}); "
            "merge the release PR and re-run prepare"
        )
        if self.notes is not None:
            self.check_notes(self.notes.read_text())

    def check_notes(self, text):
        if not self.forbidden_file:
            return
        patterns = [
            line.strip()
            for line in self.forbidden_file.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        for pat in patterns:
            if re.search(pat, text, re.I):
                raise SystemExit(f"release notes match forbidden pattern /{pat}/ — refusing")

    # ── phases ──────────────────────────────────────────────────────────────
    def prepare(self):
        run(["git", "fetch", "--quiet", "origin", "main"], cwd=ROOT)
        origin_tip = run(["git", "rev-parse", "origin/main"], cwd=ROOT)
        revision = self._revision or origin_tip
        if not SHA_RE.match(revision):
            revision = run(["git", "rev-parse", revision], cwd=ROOT)
        assert ok(ROOT, ["git", "merge-base", "--is-ancestor", revision, "origin/main"]), (
            f"revision {revision} is not on origin/main — merge the release PR first"
        )

        assert not self.source.exists(), f"{self.source} exists; remove it or pick a fresh --workdir"
        self.workdir.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", "--quiet", "--no-hardlinks", "--no-checkout", str(ROOT), str(self.source)], cwd=ROOT)
        run(["git", "remote", "set-url", "origin", ORIGIN_URL], cwd=self.source)
        run(["git", "fetch", "--quiet", "origin"], cwd=self.source)
        run(["git", "checkout", "--quiet", "--detach", revision], cwd=self.source)
        for field in ("user.name", "user.email"):
            value = run(["git", "config", "--get", field], cwd=ROOT)
            run(["git", "config", "--local", field, value], cwd=self.source)

        self.check_source(revision)
        self.save_state(revision)
        emit(prepared=True, source_revision=revision, workdir=str(self.workdir))

    def build(self):
        revision = self.revision()
        self.check_source(revision)
        assert not self.assets.exists(), f"{self.assets} exists; remove it to rebuild"
        self.assets.mkdir(mode=0o755, parents=True)

        manifest = []
        for system, arch in PLATFORMS:
            name = f"xalgorix-{system}-{arch}"
            path = self.assets / name
            env = dict(os.environ, CGO_ENABLED="0", GOOS=system, GOARCH=arch)
            run(
                ["go", "build", "-buildvcs=true", "-trimpath", "-ldflags",
                 f"-s -w -X main.version={self.version}", "-o", str(path), "./cmd/xalgorix"],
                cwd=self.source, env=env,
            )
            metadata = run(["go", "version", "-m", str(path)], cwd=self.source)
            for token in (f"vcs.revision={revision}", "vcs.modified=false", f"GOOS={system}", f"GOARCH={arch}"):
                assert token in metadata, f"{name}: missing build stamp {token!r}"
            description = run(["file", "-b", str(path)], cwd=self.source)
            assert FILE_ARCH[(system, arch)] in description, f"{name}: unexpected arch {description!r}"
            manifest.append({
                "name": name,
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "version": self.version,
                "source_revision": revision,
                "source_modified": False,
                "os": system,
                "architecture": arch,
            })
            emit(built=name, sha256=manifest[-1]["sha256"])

        (self.assets / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        (self.assets / "SHA256SUMS").write_text(
            "".join(f"{row['sha256']}  {row['name']}\n" for row in manifest)
        )
        native = self.assets / "xalgorix-linux-amd64"
        assert self.version in run([str(native), "--version"], cwd=self.source)
        assert not run(["git", "status", "--porcelain"], cwd=self.source)
        emit(build_verified=True, assets=len(manifest))

    def publish(self):
        if self.notes is None:
            raise SystemExit("publish requires --notes-file")
        revision = self.revision()
        self.check_source(revision)

        manifest = json.loads((self.assets / "manifest.json").read_text())
        assert len(manifest) == len(PLATFORMS), "manifest is incomplete — re-run build"
        for row in manifest:
            path = self.assets / row["name"]
            assert row["source_revision"] == revision and row["version"] == self.version
            assert row["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest(), f"{row['name']} changed since build"

        assert not run(
            ["git", "ls-remote", "origin", f"refs/tags/{self.tag}", f"refs/tags/{self.tag}^{{}}"],
            cwd=self.source,
        ), f"remote tag {self.tag} already exists"
        assert not ok(self.source, ["git", "rev-parse", "--verify", self.tag]), f"local tag {self.tag} exists"
        missing = subprocess.run(
            ["gh", "release", "view", self.tag, "--repo", self.repo, "--json", "tagName"],
            cwd=str(self.source), text=True, capture_output=True,
        )
        assert missing.returncode != 0 and "release not found" in missing.stderr.lower(), (
            f"a release for {self.tag} already exists"
        )

        run(["git", "tag", "-a", self.tag, revision, "-m", f"Release {self.tag}"], cwd=self.source)
        run(["git", "push", "origin", f"refs/tags/{self.tag}"], cwd=self.source)

        names = [row["name"] for row in manifest] + ["SHA256SUMS", "manifest.json"]
        run(
            ["gh", "release", "create", self.tag, "--repo", self.repo, "--draft", "--verify-tag",
             "--title", self.tag, "--notes-file", str(self.notes),
             *[str(self.assets / n) for n in names]],
            cwd=self.source,
        )
        self.verify(published=False)
        run(["gh", "release", "edit", self.tag, "--repo", self.repo, "--draft=false"], cwd=self.source)
        self.verify(published=True)

    def verify(self, *, published):
        revision = self.revision()
        release = json.loads(run(
            ["gh", "release", "view", self.tag, "--repo", self.repo, "--json",
             "tagName,isDraft,isPrerelease,publishedAt,url,body,assets"],
            cwd=self.source,
        ))
        assert release["tagName"] == self.tag and not release["isPrerelease"]
        assert release["isDraft"] == (not published), "unexpected draft state"
        if self.notes is not None:
            assert release["body"].strip() == self.notes.read_text().strip(), "published notes differ from --notes-file"
            self.check_notes(release["body"])

        local_names = {p.name for p in self.assets.iterdir()}
        remote = {asset["name"]: asset for asset in release["assets"]}
        assert set(remote) == local_names, f"asset set mismatch: {set(remote) ^ local_names}"
        for name, asset in remote.items():
            data = (self.assets / name).read_bytes()
            assert asset["state"] == "uploaded", f"{name} not fully uploaded"
            assert asset["size"] == len(data), f"{name} size mismatch"
            assert asset["digest"] == "sha256:" + hashlib.sha256(data).hexdigest(), f"{name} digest mismatch"

        assert run(["git", "cat-file", "-t", self.tag], cwd=self.source) == "tag", "tag is not annotated"
        assert run(["git", "rev-parse", f"{self.tag}^{{}}"], cwd=self.source) == revision, "tag points elsewhere"
        lines = run(
            ["git", "ls-remote", "origin", f"refs/tags/{self.tag}", f"refs/tags/{self.tag}^{{}}"],
            cwd=self.source,
        ).splitlines()
        refs = {ref: oid for oid, ref in (line.split("\t") for line in lines)}
        assert refs[f"refs/tags/{self.tag}"] == run(["git", "rev-parse", self.tag], cwd=self.source)
        assert refs[f"refs/tags/{self.tag}^{{}}"] == revision, "remote annotated tag points elsewhere"

        result = {
            "tag": self.tag,
            "source_revision": revision,
            "published": published,
            "published_at": release["publishedAt"],
            "url": release["url"],
            "verified_assets": len(remote),
        }
        (self.workdir / f"release-verification-{self.tag}.json").write_text(json.dumps(result, indent=2) + "\n")
        emit(**result)


def main():
    parser = argparse.ArgumentParser(description="Safe, reproducible Xalgorix release pipeline.")
    parser.add_argument("phase", choices=("prepare", "build", "publish", "verify"))
    parser.add_argument("--version", required=True, help="release version, e.g. 4.6.154")
    parser.add_argument("--revision", help="commit to release (default: current origin/main tip; must be on main)")
    parser.add_argument("--repo", default=REPO_DEFAULT, help=f"owner/name (default: {REPO_DEFAULT})")
    parser.add_argument("--workdir", help="build/output directory (default: dist/release-vX.Y.Z)")
    parser.add_argument("--notes-file", help="release notes markdown (required for publish)")
    parser.add_argument("--forbidden-file", help="newline-separated regexes rejected in release notes")
    args = parser.parse_args()

    release = Release(args)
    {
        "prepare": release.prepare,
        "build": release.build,
        "publish": release.publish,
        "verify": lambda: release.verify(published=True),
    }[args.phase]()


if __name__ == "__main__":
    main()
