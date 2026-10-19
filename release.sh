#!/usr/bin/env bash
#
# release.sh has been replaced by scripts/release.py.
#
# The previous release.sh created the vX.Y.Z tag and the GitHub Release on the
# release branch *before* the PR was merged to main — publishing artifacts for
# a commit that was not yet on main. scripts/release.py fixes that ordering: it
# tags and publishes only after the release commit is on origin/main, ships the
# GitHub Release as a draft, verifies every uploaded asset against the locally
# built bytes, and only then promotes it.
#
# See CONTRIBUTING.md -> "Releases".
#
set -euo pipefail

cat >&2 <<'MSG'
release.sh has been replaced by the safe, reproducible pipeline in
scripts/release.py.

Merge the release PR first, then run the phases in order:

  python3 scripts/release.py prepare --version X.Y.Z
  python3 scripts/release.py build   --version X.Y.Z
  python3 scripts/release.py publish --version X.Y.Z --notes-file NOTES.md

See CONTRIBUTING.md for details.
MSG
exit 1
