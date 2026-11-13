package fileedit

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/sandbox"
	"github.com/xalgord/xalgorix/v4/internal/tools"
)

const searchSecret = "sk-test-SECRET-4242"

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSearchExclusionsOnlyNamesEntriesUnderRoot(t *testing.T) {
	root := t.TempDir()
	deny := []string{
		filepath.Join(root, "llm_keys.json"),
		filepath.Join(root, "auth-profiles.json"),
		filepath.Join(root, "llm_keys.json"), // duplicate (resolved-symlink form)
		filepath.Join(root, "secret[1].txt"),
		"/home/operator/.ssh",
	}
	got := searchExclusions(deny, root)
	want := []string{"llm_keys.json*", "auth-profiles.json*", `secret\[1\].txt*`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("searchExclusions = %v, want %v", got, want)
	}
	if got := searchExclusions(deny, filepath.Join(root, "scan-1")); len(got) != 0 {
		t.Fatalf("searchExclusions for a scan subdir = %v, want none", got)
	}
}

// TestSearchCommandArgsSkipCredentialStores runs the real search binaries
// over a Data_Dir-shaped tree: credential store contents (and their .tmp
// siblings) must not be printed, also when the caller's include glob matches
// them, while ordinary scan output, hidden files and ignored files still are.
func TestSearchCommandArgsSkipCredentialStores(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"llm_keys.json":                   `{"provider":{"api_key":"` + searchSecret + `"}}`,
		"llm_keys.json.tmp":               `{"provider":{"api_key":"` + searchSecret + `"}}`,
		"old/llm_keys.json/llm_keys.json": `{"k":"` + searchSecret + `"}`, // legacy nested layout
		"auth-profiles.json":              `{"token":"` + searchSecret + `"}`,
		"auth-profiles.json.tmp.0a1b":     `{"token":"` + searchSecret + `"}`,
		"secret[1].txt":                   searchSecret,
		"scan-1/findings.json":            `{"evidence":"` + searchSecret + `"}`,
		"scan-1/repo/.env":                "KEY=" + searchSecret,
		"scan-1/repo/.gitignore":          "ignored.yml\n",
		"scan-1/repo/ignored.yml":         "k: " + searchSecret,
	})
	deny := []string{
		filepath.Join(root, "llm_keys.json"),
		filepath.Join(root, "auth-profiles.json"),
		filepath.Join(root, "secret[1].txt"),
	}
	exclude := searchExclusions(deny, root)

	for _, include := range []string{"", "*.json*"} {
		rgArgs, grepArgs := searchCommandArgs("SECRET-4242", root, include, exclude)
		runs := map[string][]string{"grep": grepArgs}
		if _, err := exec.LookPath("rg"); err == nil {
			runs["rg"] = rgArgs
		}
		for bin, args := range runs {
			out, err := tools.RunCommand(bin, args...)
			if err != nil {
				t.Fatalf("%s %v: %v", bin, args, err)
			}
			if !strings.Contains(out, filepath.Join("scan-1", "findings.json")) {
				t.Errorf("%s include=%q: scan output missing from results:\n%s", bin, include, out)
			}
			if include == "" {
				for _, want := range []string{".env", "ignored.yml"} {
					if !strings.Contains(out, want) {
						t.Errorf("%s: %s missing from results (hidden/ignored files must be searched):\n%s", bin, want, out)
					}
				}
			}
			for _, leaked := range []string{"llm_keys.json", "auth-profiles.json", "secret[1].txt"} {
				if strings.Contains(out, leaked) {
					t.Errorf("%s include=%q: deny-listed %s searched:\n%s", bin, include, leaked, out)
				}
			}
		}
	}
}

// TestSearchFilesWithPolicySymlinkedRoot: a directory symlink inside the scan
// workspace (for example from a cloned or extracted target artifact) that
// points at Data_Dir must not let the search print the credential store.
func TestSearchFilesWithPolicySymlinkedRoot(t *testing.T) {
	dataDir := t.TempDir()
	scanDir := filepath.Join(dataDir, "scan-1")
	writeTree(t, dataDir, map[string]string{
		"llm_keys.json":      `{"provider":{"api_key":"` + searchSecret + `"}}`,
		"scan-1/notes.txt":   "found " + searchSecret,
		"scan-1/repo/app.js": "const x = 1",
	})
	vendor := filepath.Join(scanDir, "repo", "vendor")
	if err := os.Symlink(dataDir, vendor); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	policy := sandbox.NewWithReadDeny([]string{dataDir}, []string{filepath.Join(dataDir, "llm_keys.json")})

	for _, root := range []string{vendor, scanDir} {
		res, err := searchFilesWithPolicy(policy, nil, "SECRET-4242", root, "")
		if err != nil {
			t.Fatalf("search %s: %v", root, err)
		}
		if strings.Contains(res.Output, "llm_keys.json") || strings.Contains(res.Output, `"api_key"`) {
			t.Errorf("search rooted at %s printed the key store:\n%s", root, res.Output)
		}
		if !strings.Contains(res.Output, "notes.txt") {
			t.Errorf("search rooted at %s lost ordinary results:\n%s%s", root, res.Output, res.Error)
		}
	}

	// A root that resolves to the store itself is refused outright.
	link := filepath.Join(scanDir, "keys")
	if err := os.Symlink(filepath.Join(dataDir, "llm_keys.json"), link); err != nil {
		t.Fatal(err)
	}
	if res, _ := searchFilesWithPolicy(policy, nil, "SECRET", link, ""); res.Error == "" {
		t.Errorf("search rooted at a symlink to the key store was not refused: %q", res.Output)
	}
}

// TestSearchFilesWithPolicyRefusesProc: process environment files carry the
// scanner's env-file values, so a search rooted (directly or via a symlink)
// under /proc is refused.
func TestSearchFilesWithPolicyRefusesProc(t *testing.T) {
	if _, err := os.Stat("/proc/self/environ"); err != nil {
		t.Skip("no procfs")
	}
	scanDir := t.TempDir()
	link := filepath.Join(scanDir, "loot")
	if err := os.Symlink("/proc/self", link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	policy := sandbox.NewWithReadDeny([]string{scanDir}, nil)
	for _, root := range []string{link, "/proc/self", "/proc"} {
		if res, _ := searchFilesWithPolicy(policy, nil, "PATH", root, ""); res.Error == "" {
			t.Errorf("search rooted at %s was not refused: %.200q", root, res.Output)
		}
	}
}

// TestSearchCommandArgsDashPattern: a pattern beginning with "-" is a
// pattern, not a flag.
func TestSearchCommandArgsDashPattern(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{"a.txt": "x --flaglike y"})
	rgArgs, grepArgs := searchCommandArgs("--flaglike", root, "", nil)
	runs := map[string][]string{"grep": grepArgs}
	if _, err := exec.LookPath("rg"); err == nil {
		runs["rg"] = rgArgs
	}
	for bin, args := range runs {
		out, err := tools.RunCommand(bin, args...)
		if err != nil || !strings.Contains(out, "a.txt") {
			t.Fatalf("%s %v = %q, %v; want a match in a.txt", bin, args, out, err)
		}
	}
}
