package terminal

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const bundledWebWordlistRelativePath = "tmp/wordlists/xalgorix-web-common.txt"

// bundledWebWordlist is intentionally compact. It is a last-resort list for
// prebuilt-binary installs where ffuf is present but the host does not have a
// distro wordlist package. Full SecLists installations are always preferred.
//
//go:embed data/web-common.list
var bundledWebWordlist []byte

// SecLists is installed with different roots depending on the distro/package
// manager and whether it was cloned manually. Linux path matching is case
// sensitive, so both SecLists and seclists spellings are explicit here.
var portableSecListsRoots = []string{
	"/usr/share/seclists",
	"/usr/share/SecLists",
	"/usr/share/wordlists/seclists",
	"/usr/share/wordlists/SecLists",
	"/usr/local/share/seclists",
	"/usr/local/share/SecLists",
	"/opt/seclists",
	"/opt/SecLists",
}

var portableCommonWebWordlists = []string{
	"/usr/share/dirb/wordlists/common.txt",
	"/usr/share/wordlists/dirb/common.txt",
	"/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
	"/usr/share/seclists/Discovery/Web-Content/common.txt",
	"/usr/share/SecLists/Discovery/Web-Content/common.txt",
}

var (
	wordlistFlagRE      = regexp.MustCompile(`(?i)(^|[[:space:]])(-w|--wordlists?)([[:space:]]*=[[:space:]]*|[[:space:]]+)("[^"\r\n]+"|'[^'\r\n]+'|[^[:space:];|&]+)`)
	ffufKeywordSuffixRE = regexp.MustCompile(`:[A-Za-z][A-Za-z0-9_-]*$`)
)

type wordlistReplacement struct {
	requested string
	resolved  string
	bundled   bool
}

// normalizeCommandWordlists replaces a missing, literal system wordlist used
// by a content-discovery tool. It first looks for the identical path suffix in
// alternate SecLists roots (including the case-sensitive SecLists/seclists
// variants), then common distro wordlists, and finally materializes Xalgorix's
// embedded fallback under the scan-local tmp/ directory.
func normalizeCommandWordlists(command, workDir string) (string, string, error) {
	return normalizeCommandWordlistsWithLocations(
		command,
		workDir,
		portableSecListsRoots,
		portableCommonWebWordlists,
	)
}

func normalizeCommandWordlistsWithLocations(command, workDir string, secListsRoots, commonWordlists []string) (string, string, error) {
	var replacements []wordlistReplacement
	var rewriteErr error

	rewritten := rewriteShellSegments(command, func(segment string) string {
		if rewriteErr != nil || !hasContentDiscoveryCommand(segment) {
			return segment
		}

		return wordlistFlagRE.ReplaceAllStringFunc(segment, func(match string) string {
			if rewriteErr != nil {
				return match
			}
			parts := wordlistFlagRE.FindStringSubmatch(match)
			if len(parts) != 5 {
				return match
			}

			token := unquoteShellToken(parts[4])
			path, keywordSuffix := splitFFUFWordlistKeyword(segment, token)
			if !isLiteralSystemWordlistPath(path, secListsRoots, commonWordlists) || regularFileExists(path) {
				return match
			}

			resolved, bundled, err := resolvePortableWordlist(path, workDir, secListsRoots, commonWordlists)
			if err != nil {
				rewriteErr = fmt.Errorf("resolve missing wordlist %s: %w", path, err)
				return match
			}
			replacements = append(replacements, wordlistReplacement{
				requested: path,
				resolved:  resolved,
				bundled:   bundled,
			})
			return parts[1] + parts[2] + parts[3] + shellQuote(resolved+keywordSuffix)
		})
	})

	if rewriteErr != nil {
		return command, "", rewriteErr
	}
	return rewritten, formatWordlistNotice(replacements), nil
}

func hasContentDiscoveryCommand(segment string) bool {
	for _, tool := range []string{"ffuf", "gobuster", "feroxbuster", "dirsearch", "dirb", "wfuzz"} {
		if hasToolCommand(segment, tool) {
			return true
		}
	}
	return false
}

func unquoteShellToken(token string) string {
	if len(token) >= 2 {
		first, last := token[0], token[len(token)-1]
		if (first == '\'' && last == '\'') || (first == '"' && last == '"') {
			return token[1 : len(token)-1]
		}
	}
	return token
}

func splitFFUFWordlistKeyword(segment, token string) (string, string) {
	if !hasToolCommand(segment, "ffuf") {
		return token, ""
	}
	loc := ffufKeywordSuffixRE.FindStringIndex(token)
	if loc == nil {
		return token, ""
	}
	return token[:loc[0]], token[loc[0]:]
}

func isLiteralSystemWordlistPath(path string, secListsRoots, commonWordlists []string) bool {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, "$`*?[]{}()") {
		return false
	}
	clean := filepath.Clean(path)
	for _, root := range secListsRoots {
		if pathWithinRoot(clean, root) {
			return true
		}
	}
	for _, candidate := range commonWordlists {
		if clean == filepath.Clean(candidate) {
			return true
		}
	}
	return false
}

func resolvePortableWordlist(requested, workDir string, secListsRoots, commonWordlists []string) (string, bool, error) {
	for _, candidate := range equivalentWordlistPaths(requested, secListsRoots, commonWordlists) {
		if regularFileExists(candidate) {
			return candidate, false, nil
		}
	}

	fallback, err := materializeBundledWebWordlist(workDir)
	if err != nil {
		return "", false, err
	}
	return fallback, true, nil
}

func equivalentWordlistPaths(requested string, secListsRoots, commonWordlists []string) []string {
	requested = filepath.Clean(requested)
	candidates := make([]string, 0, len(secListsRoots)+len(commonWordlists))
	seen := map[string]struct{}{requested: {}}
	appendCandidate := func(path string) {
		path = filepath.Clean(path)
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		candidates = append(candidates, path)
	}

	for _, root := range secListsRoots {
		if !pathWithinRoot(requested, root) {
			continue
		}
		rel, err := filepath.Rel(filepath.Clean(root), requested)
		if err != nil || rel == "." {
			break
		}
		for _, alternateRoot := range secListsRoots {
			appendCandidate(filepath.Join(alternateRoot, rel))
		}
		break
	}

	if strings.EqualFold(filepath.Base(requested), "common.txt") {
		for _, candidate := range commonWordlists {
			appendCandidate(candidate)
		}
	}
	return candidates
}

func regularFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func pathWithinRoot(path, root string) bool {
	cleanPath, cleanRoot := filepath.Clean(path), filepath.Clean(root)
	rel, err := filepath.Rel(cleanRoot, cleanPath)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func materializeBundledWebWordlist(workDir string) (string, error) {
	if strings.TrimSpace(workDir) == "" {
		return "", fmt.Errorf("scan workspace is empty")
	}
	workDir = filepath.Clean(workDir)
	target := filepath.Join(workDir, filepath.FromSlash(bundledWebWordlistRelativePath))
	dir := filepath.Dir(target)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create scan-local wordlist directory: %w", err)
	}

	resolvedWorkDir, err := filepath.EvalSymlinks(workDir)
	if err != nil {
		return "", fmt.Errorf("resolve scan workspace: %w", err)
	}
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", fmt.Errorf("resolve scan-local wordlist directory: %w", err)
	}
	if !pathWithinRoot(resolvedDir, resolvedWorkDir) {
		return "", fmt.Errorf("scan-local wordlist directory escapes workspace")
	}

	if info, statErr := os.Lstat(target); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("refusing symlink at scan-local wordlist path")
		}
		if existing, readErr := os.ReadFile(target); readErr == nil && bytes.Equal(existing, bundledWebWordlist) {
			if chmodErr := os.Chmod(target, 0o600); chmodErr != nil {
				return "", fmt.Errorf("secure scan-local wordlist: %w", chmodErr)
			}
			return target, nil
		}
	} else if !os.IsNotExist(statErr) {
		return "", fmt.Errorf("inspect scan-local wordlist: %w", statErr)
	}

	tmp, err := os.CreateTemp(dir, ".xalgorix-web-common-*")
	if err != nil {
		return "", fmt.Errorf("create temporary wordlist: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("secure temporary wordlist: %w", err)
	}
	if _, err := tmp.Write(bundledWebWordlist); err != nil {
		_ = tmp.Close()
		return "", fmt.Errorf("write bundled wordlist: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("close bundled wordlist: %w", err)
	}
	if err := os.Rename(tmpName, target); err != nil {
		return "", fmt.Errorf("publish scan-local wordlist: %w", err)
	}
	return target, nil
}

func formatWordlistNotice(replacements []wordlistReplacement) string {
	if len(replacements) == 0 {
		return ""
	}
	var b strings.Builder
	seen := make(map[string]struct{}, len(replacements))
	for _, replacement := range replacements {
		key := replacement.requested + "\x00" + replacement.resolved
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		source := "installed alternate"
		if replacement.bundled {
			source = "bundled fallback"
		}
		fmt.Fprintf(&b, "[WORDLIST] %s is unavailable; using %s (%s).\n", replacement.requested, replacement.resolved, source)
	}
	return b.String()
}
