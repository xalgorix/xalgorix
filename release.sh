#!/usr/bin/env bash
set -euo pipefail

# ─── Xalgorix Release Script ───
# Usage:
#   ./release.sh                  # auto-bump patch (4.2.10 → 4.2.11)
#   ./release.sh 4.3.0            # explicit version
#   ./release.sh --minor          # bump minor (4.2.10 → 4.3.0)
#   ./release.sh --major          # bump major (4.2.10 → 5.0.0)
#
# The version bump is committed on a dedicated release/vX.Y.Z branch (never
# directly on main), so the PR merges cleanly without version-string conflicts.

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
MAIN_GO="$REPO_ROOT/cmd/xalgorix/main.go"
MAKEFILE="$REPO_ROOT/Makefile"
README="$REPO_ROOT/README.md"
BUILD_DIR="$REPO_ROOT/tmp/xalgorix-release"

# ─── Colors ───
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[•]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
die()   { echo -e "${RED}[✗]${NC} $*" >&2; exit 1; }

# ─── Pre-flight checks ───
command -v go >/dev/null  || die "go not found"
command -v gh >/dev/null  || die "gh CLI not found (install: https://cli.github.com)"
command -v git >/dev/null || die "git not found"
command -v npm >/dev/null || die "npm not found (needed to build the embedded web UI; install Node.js)"

# ─── Web UI writability pre-flight ───
# `npm install`/`npm run build` (Step 2.5) rewrite webui/package-lock.json and
# webui/node_modules. If a previous `sudo make build` left those owned by root,
# npm fails deep in the run with a cryptic EACCES trace. Catch it up front with
# a clear, actionable message instead.
check_webui_writable() {
    local lock="$REPO_ROOT/webui/package-lock.json"
    local nm="$REPO_ROOT/webui/node_modules"
    local bad=()
    [[ -e "$lock" && ! -w "$lock" ]] && bad+=("$lock")
    [[ -d "$nm"   && ! -w "$nm"   ]] && bad+=("$nm")
    if [[ ${#bad[@]} -gt 0 ]]; then
        warn "Web UI build files are not writable by $(whoami) (likely created by a past 'sudo make build'):"
        printf '    %s\n' "${bad[@]}"
        die "Reclaim ownership, then rerun:\n    sudo chown -R \"\$USER:\$USER\" webui/node_modules webui/package-lock.json"
    fi
}
check_webui_writable

cd "$REPO_ROOT"

# Capture the branch we started on so the auto-stash restore (below)
# and Step 10 can return here cleanly.
ORIGINAL_BRANCH="$(git branch --show-current)"

# ─── Auto-stash dirty working tree ───
# A dirty working tree used to hard-abort the release ("Working tree is
# dirty. Commit or stash changes first."). That blocked releases whenever
# unrelated/uncommitted work was present. Instead, stash everything
# (tracked + untracked) up front and restore it automatically when the
# script exits — on success OR failure — via the EXIT trap below. The
# release itself still happens from a clean tree on a dedicated
# release/vX.Y.Z branch, so the stashed changes never leak into the
# release commit.
#
# Opt out with: RELEASE_NO_AUTOSTASH=1 ./release.sh ...  (restores the old
# fail-fast behavior for anyone who prefers to stage changes by hand).
STASH_REF=""
restore_stash() {
    [[ -z "$STASH_REF" ]] && return 0
    # Only restore if the stash still exists (it was applied successfully
    # by a prior call, or the script never got far enough to pop it).
    if git stash list 2>/dev/null | grep -q "$STASH_REF"; then
        info "Restoring stashed working-tree changes ($STASH_REF)..."
        git checkout "$ORIGINAL_BRANCH" >/dev/null 2>&1 || true
        if git stash pop >/dev/null 2>&1; then
            ok "Working-tree changes restored"
        else
            warn "Could not auto-restore stashed changes — recover manually with: git stash pop ($STASH_REF)"
        fi
    fi
    STASH_REF=""
}

if [[ -n "$(git status --porcelain)" ]]; then
    if [[ "${RELEASE_NO_AUTOSTASH:-0}" == "1" ]]; then
        die "Working tree is dirty. Commit or stash changes first (RELEASE_NO_AUTOSTASH=1)."
    fi
    warn "Working tree is dirty — auto-stashing changes (restored on exit):"
    git status --short | sed 's/^/    /'
    STASH_REF="release-autostash-$(date +%s)"
    git stash push --include-untracked --message "$STASH_REF" >/dev/null \
        || die "Failed to stash dirty working tree. Commit or stash manually, then rerun."
    trap restore_stash EXIT
    ok "Stashed dirty changes as $STASH_REF (will be restored automatically)"
fi

# ─── Step 0: Sync main with origin to avoid divergence ───
if [[ "$ORIGINAL_BRANCH" != "main" ]]; then
    info "Switching to main..."
    git checkout main
fi
info "Syncing main with origin/main..."
git pull --ff-only origin main 2>/dev/null || {
    warn "Fast-forward pull failed — trying rebase..."
    git pull --rebase origin main || die "Cannot sync main with origin. Resolve manually."
}
ok "main is in sync with origin"

# ─── Determine current version ───
CURRENT=$(grep -oP 'var version = "\K[^"]+' "$MAIN_GO")
[[ -z "$CURRENT" ]] && die "Could not parse current version from $MAIN_GO"

IFS='.' read -r MAJOR MINOR PATCH <<< "$CURRENT"
info "Current version: ${CYAN}v$CURRENT${NC}"

# ─── Determine new version ───
if [[ $# -eq 0 ]]; then
    # Auto-bump patch
    NEW_VERSION="$MAJOR.$MINOR.$((PATCH + 1))"
elif [[ "$1" == "--minor" ]]; then
    NEW_VERSION="$MAJOR.$((MINOR + 1)).0"
elif [[ "$1" == "--major" ]]; then
    NEW_VERSION="$((MAJOR + 1)).0.0"
elif [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    NEW_VERSION="$1"
else
    die "Invalid argument: $1\nUsage: $0 [version|--minor|--major]"
fi

info "New version:     ${GREEN}v$NEW_VERSION${NC}"
echo ""

# ─── Confirm ───
read -rp "Proceed with release v$NEW_VERSION? [y/N] " confirm
[[ "$confirm" =~ ^[Yy]$ ]] || { warn "Aborted."; exit 0; }
echo ""

# ─── Step 1: Create release branch from main ───
RELEASE_BRANCH="release/v$NEW_VERSION"
if git rev-parse --verify --quiet "$RELEASE_BRANCH" >/dev/null; then
    warn "Branch $RELEASE_BRANCH already exists locally — refusing to overwrite. Delete it and rerun if intentional."
    die "release branch collision"
fi
info "Creating branch $RELEASE_BRANCH from main..."
git checkout -b "$RELEASE_BRANCH"
ok "On branch $RELEASE_BRANCH"

# ─── Step 2: Bump version in source (on release branch) ───
info "Bumping version in main.go..."
sed -i "s/var version = \"$CURRENT\"/var version = \"$NEW_VERSION\"/" "$MAIN_GO"
if [[ -f "$MAKEFILE" ]]; then
    sed -i "s/^VERSION=.*/VERSION=$NEW_VERSION/" "$MAKEFILE"
fi
if [[ -f "$README" ]]; then
    sed -i "s/assets\\/banner\\.png?v=$CURRENT/assets\\/banner.png?v=$NEW_VERSION/g" "$README"
fi
ok "Version bumped: $CURRENT → $NEW_VERSION"

# ─── Step 2.5: Build the embedded web UI ───
# The dashboard (internal/web/static/*) is bundled into the binary via
# //go:embed. Plain `go build` does NOT regenerate it from the React source
# in webui/, so a release built without this step would ship a STALE
# dashboard. Mirror the Makefile `webui` target (npm install + npm run build)
# here so the freshly built assets are embedded AND committed into the
# release commit (Step 6's `git add -A`).
info "Building web UI (React → internal/web/static)..."
if ! ( cd "$REPO_ROOT/webui" && npm install --no-audit --no-fund && npm run build ); then
    warn "Web UI build failed — reverting version bump and deleting release branch"
    git checkout -- "$MAIN_GO" "$MAKEFILE" "$README" internal/web/static
    git checkout main
    git branch -D "$RELEASE_BRANCH"
    die "Web UI build failed (version bump reverted, release branch deleted)"
fi
ok "Web UI built → internal/web/static"

# ─── Step 3: Build & verify ───
info "Building and verifying..."
if ! go build ./cmd/xalgorix/; then
    warn "Build failed — reverting version bump and deleting release branch"
    git checkout -- "$MAIN_GO" "$MAKEFILE" "$README" internal/web/static
    git checkout main
    git branch -D "$RELEASE_BRANCH"
    die "Build failed (version bump reverted, release branch deleted)"
fi
ok "Build successful"

# ─── Step 4: Build release binaries (multi-platform) ───
# Build native Linux and macOS binaries for Intel and ARM so the one-line
# installer can serve the right asset. Names must match the
# `${BINARY}-${OS}-${ARCH}` pattern install.sh downloads.
mkdir -p "$BUILD_DIR"
RELEASE_ASSETS=()
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do
    IFS=/ read -r target_os target_arch <<< "$target"
    info "Building $target_os/$target_arch release binary..."
    out="$BUILD_DIR/xalgorix-$target_os-$target_arch"
    CGO_ENABLED=0 GOOS="$target_os" GOARCH="$target_arch" go build \
        -ldflags "-s -w -X main.version=$NEW_VERSION" \
        -o "$out" \
        ./cmd/xalgorix/
    RELEASE_ASSETS+=("$out")
    ok "Binary built: $out"
done

# ─── Step 5: Generate changelog (commits since last tag) ───
info "Generating changelog..."
CHANGELOG=$(git log --oneline "v$CURRENT"..HEAD 2>/dev/null | sed 's/^/- /' || echo "- Release v$NEW_VERSION")
if [[ -z "$CHANGELOG" ]]; then
    CHANGELOG="- Release v$NEW_VERSION"
fi
echo "$CHANGELOG"
echo ""

# ─── Step 6: Commit & tag (on release branch) ───
info "Committing and tagging..."
git add -A
git commit -m "release: v$NEW_VERSION"
git tag "v$NEW_VERSION"
ok "Tagged v$NEW_VERSION"

# ─── Step 7: Push release branch & tag ───
info "Pushing $RELEASE_BRANCH and tag..."
git push -u origin "$RELEASE_BRANCH"
git push origin "v$NEW_VERSION"
ok "Pushed $RELEASE_BRANCH and tag v$NEW_VERSION"

# ─── Step 8: Open PR against main ───
info "Opening PR against main..."
PR_BODY="### Changes

$CHANGELOG"
PR_URL="$(gh pr create --base main --head "$RELEASE_BRANCH" \
    --title "release: v$NEW_VERSION" \
    --body "$PR_BODY" 2>/dev/null || true)"
if [[ -z "$PR_URL" ]]; then
    warn "PR creation failed or PR already exists; check GitHub manually."
else
    ok "PR opened: $PR_URL"
fi

# ─── Step 9: Create GitHub Release ───
info "Creating GitHub Release..."
gh release create "v$NEW_VERSION" \
    "${RELEASE_ASSETS[@]}" \
    --title "v$NEW_VERSION" \
    --notes "### Changes

$CHANGELOG"
ok "GitHub Release created"

# ─── Step 10: Switch back to main ───
info "Switching back to main..."
git checkout main
ok "Back on main (clean — version bump lives only on $RELEASE_BRANCH)"

# ─── Cleanup ───
rm -rf "$BUILD_DIR"

echo ""
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  ✅ Released v$NEW_VERSION successfully!${NC}"
echo -e "${GREEN}  https://github.com/xalgorix/xalgorix/releases/tag/v$NEW_VERSION${NC}"
echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
