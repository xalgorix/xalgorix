package terminal

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

func TestPortableSecListsRootsIncludeBothCaseSpellings(t *testing.T) {
	want := map[string]bool{
		"/usr/share/seclists": false,
		"/usr/share/SecLists": false,
		"/opt/seclists":       false,
		"/opt/SecLists":       false,
	}
	for _, root := range portableSecListsRoots {
		if _, ok := want[root]; ok {
			want[root] = true
		}
	}
	for root, found := range want {
		if !found {
			t.Errorf("portableSecListsRoots missing %s", root)
		}
	}
}

func TestNormalizeCommandWordlistsSupportsSecListsCaseVariants(t *testing.T) {
	for _, tc := range []struct {
		name              string
		requestedSpelling string
		installedSpelling string
	}{
		{
			name:              "lowercase request finds capitalized install",
			requestedSpelling: "seclists",
			installedSpelling: "SecLists",
		},
		{
			name:              "capitalized request finds lowercase install",
			requestedSpelling: "SecLists",
			installedSpelling: "seclists",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			requestedRoot := filepath.Join(base, tc.requestedSpelling)
			installedRoot := filepath.Join(base, tc.installedSpelling)
			rel := filepath.Join("Discovery", "Web-Content", "common.txt")
			requested := filepath.Join(requestedRoot, rel)
			installed := filepath.Join(installedRoot, rel)
			if err := os.MkdirAll(filepath.Dir(installed), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(installed, []byte("admin\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			workDir := filepath.Join(base, "scan")
			if err := os.MkdirAll(workDir, 0o700); err != nil {
				t.Fatal(err)
			}

			command := fmt.Sprintf("ffuf -u https://example.test/FUZZ -w %q -mc 200", requested)
			got, notice, err := normalizeCommandWordlistsWithLocations(
				command,
				workDir,
				[]string{requestedRoot, installedRoot},
				nil,
			)
			if err != nil {
				t.Fatalf("normalizeCommandWordlistsWithLocations() error = %v", err)
			}
			if !strings.Contains(got, "-w "+shellQuote(installed)) {
				t.Fatalf("rewritten command did not use installed case variant\n got: %s\nwant path: %s", got, installed)
			}
			if !strings.Contains(notice, installed) || !strings.Contains(notice, "installed alternate") {
				t.Fatalf("notice = %q, want installed alternate %s", notice, installed)
			}
			if _, statErr := os.Stat(filepath.Join(workDir, filepath.FromSlash(bundledWebWordlistRelativePath))); !os.IsNotExist(statErr) {
				t.Fatalf("bundled fallback should not be created when case variant exists; stat err = %v", statErr)
			}
		})
	}
}

func TestNormalizeCommandWordlistsUsesCommonDistroAlternative(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "seclists")
	requested := filepath.Join(root, "Discovery", "Web-Content", "common.txt")
	dirbCommon := filepath.Join(base, "dirb", "common.txt")
	if err := os.MkdirAll(filepath.Dir(dirbCommon), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dirbCommon, []byte("admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	workDir := filepath.Join(base, "scan")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}

	command := fmt.Sprintf("gobuster dir -u https://example.test -w=%s", requested)
	got, notice, err := normalizeCommandWordlistsWithLocations(command, workDir, []string{root}, []string{dirbCommon})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "-w="+shellQuote(dirbCommon)) {
		t.Fatalf("got %q, want common distro wordlist %s", got, dirbCommon)
	}
	if !strings.Contains(notice, "installed alternate") {
		t.Fatalf("notice = %q, want installed alternate", notice)
	}
}

func TestNormalizeCommandWordlistsMaterializesBundledFallback(t *testing.T) {
	base := t.TempDir()
	lowerRoot := filepath.Join(base, "seclists")
	upperRoot := filepath.Join(base, "SecLists")
	requested := filepath.Join(lowerRoot, "Discovery", "Web-Content", "raft-medium-directories.txt")
	workDir := filepath.Join(base, "scan")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}

	command := fmt.Sprintf("ffuf -w %s:PATH -u https://example.test/PATH", requested)
	got, notice, err := normalizeCommandWordlistsWithLocations(command, workDir, []string{lowerRoot, upperRoot}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fallback := filepath.Join(workDir, filepath.FromSlash(bundledWebWordlistRelativePath))
	if !strings.Contains(got, "-w "+shellQuote(fallback+":PATH")) {
		t.Fatalf("got %q, want bundled fallback %s with ffuf keyword", got, fallback)
	}
	if !strings.Contains(notice, requested) || !strings.Contains(notice, "bundled fallback") {
		t.Fatalf("notice = %q, want requested path and bundled fallback", notice)
	}
	content, err := os.ReadFile(fallback)
	if err != nil {
		t.Fatalf("read fallback: %v", err)
	}
	for _, entry := range []string{"admin\n", ".git/HEAD\n", "openapi.json\n"} {
		if !strings.Contains(string(content), entry) {
			t.Errorf("bundled fallback missing %q", strings.TrimSpace(entry))
		}
	}
	info, err := os.Stat(fallback)
	if err != nil {
		t.Fatal(err)
	}
	if gotMode := info.Mode().Perm(); gotMode != 0o600 {
		t.Fatalf("fallback mode = %#o, want 0600", gotMode)
	}

	gotAgain, noticeAgain, err := normalizeCommandWordlistsWithLocations(command, workDir, []string{lowerRoot, upperRoot}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if gotAgain != got || noticeAgain != notice {
		t.Fatalf("normalization is not idempotent\nfirst:  %q / %q\nsecond: %q / %q", got, notice, gotAgain, noticeAgain)
	}
}

func TestNormalizeCommandWordlistsPreservesUsableAndDynamicPaths(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "SecLists")
	existing := filepath.Join(root, "Discovery", "Web-Content", "common.txt")
	if err := os.MkdirAll(filepath.Dir(existing), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(existing, []byte("admin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	workDir := filepath.Join(base, "scan")
	if err := os.MkdirAll(workDir, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, command := range []string{
		fmt.Sprintf("ffuf -u https://example.test/FUZZ -w %s", existing),
		`ffuf -u https://example.test/FUZZ -w "$WL"`,
		`ffuf -u https://example.test/FUZZ -w tmp/generated.txt`,
		fmt.Sprintf("curl -sS -w %s https://example.test", filepath.Join(root, "missing.txt")),
	} {
		got, notice, err := normalizeCommandWordlistsWithLocations(command, workDir, []string{root}, nil)
		if err != nil {
			t.Fatalf("command %q: %v", command, err)
		}
		if got != command || notice != "" {
			t.Fatalf("command should be preserved\n got: %q / %q\nwant: %q / empty notice", got, notice, command)
		}
	}
}

func TestMaterializeBundledWebWordlistRejectsWorkspaceEscape(t *testing.T) {
	workDir := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workDir, "tmp"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(workDir, "tmp", "wordlists")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := materializeBundledWebWordlist(workDir); err == nil || !strings.Contains(err.Error(), "escapes workspace") {
		t.Fatalf("materializeBundledWebWordlist() error = %v, want workspace escape rejection", err)
	}
}

func TestRunShellInternalUsesBundledWordlistForMissingSecListsPath(t *testing.T) {
	goPath := t.TempDir()
	binDir := filepath.Join(goPath, "bin")
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fakeFFUF := `#!/bin/sh
set -eu
wordlist=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-w" ]; then
    shift
    wordlist="$1"
  fi
  shift
done
test -f "$wordlist"
grep -qx admin "$wordlist"
printf 'WORDLIST=%s\n' "$wordlist"
`
	if err := os.WriteFile(filepath.Join(binDir, "ffuf"), []byte(fakeFFUF), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOPATH", goPath)

	workDir := t.TempDir()
	sc := scanctx.New("portable-wordlist-integration", workDir)
	scanctx.Activate(sc)
	defer func() {
		CleanupContext(sc.ID)
		scanctx.Deactivate(sc.ID)
	}()

	missing := "/opt/SecLists/Discovery/Web-Content/xalgorix-issue-630-missing.txt"
	output, exitCode := runShellInternal(sc.ID, "ffuf -u https://example.test/FUZZ -w "+missing)
	if exitCode != 0 {
		t.Fatalf("runShellInternal() exit = %d, output:\n%s", exitCode, output)
	}
	if !strings.Contains(output, "[WORDLIST]") || !strings.Contains(output, "bundled fallback") {
		t.Fatalf("output does not disclose portable fallback:\n%s", output)
	}
	wantPath := filepath.Join(workDir, filepath.FromSlash(bundledWebWordlistRelativePath))
	if !strings.Contains(output, "WORDLIST="+wantPath) {
		t.Fatalf("fake ffuf did not receive scan-local fallback %s:\n%s", wantPath, output)
	}
	rel, err := filepath.Rel(workDir, wantPath)
	if err != nil || filepath.ToSlash(rel) != bundledWebWordlistRelativePath {
		t.Fatalf("fallback is not under the scan-local tmp directory: path=%s rel=%s err=%v", wantPath, rel, err)
	}
}
