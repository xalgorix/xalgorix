package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func denyCovers(list []string, path string) bool {
	path = filepath.Clean(path)
	for _, entry := range list {
		entry = filepath.Clean(entry)
		if path == entry || strings.HasPrefix(path, entry+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// TestReadDenyListCoversScannerCredentialStores pins the agent file-tool
// deny-list to the scanner's own credential files: the dotenv files load()
// reads, the provider key store, the auth profile store and the CLI
// credential files the OAuth drivers import.
func TestReadDenyListCoversScannerCredentialStores(t *testing.T) {
	t.Setenv("SUDO_USER", "operator")
	t.Setenv("CODEX_HOME", "/srv/codex-home")
	t.Setenv("XALGORIX_CODEX_AUTH_FILE", "/srv/codex/auth-override.json")

	home := t.TempDir()
	dataDir := filepath.Join(t.TempDir(), "data")
	list := resolveReadDenyList(home, dataDir, "")

	for _, want := range []string{
		filepath.Join(home, ".xalgorix.env"),
		"/etc/xalgorix.env",
		"/root/.xalgorix.env",
		"/home/operator/.xalgorix.env",
		filepath.Join(dataDir, "llm_keys.json"),
		filepath.Join(dataDir, "llm_keys.json", "llm_keys.json"), // legacy nested layout
		filepath.Join(dataDir, "auth-profiles.json"),
		filepath.Join(home, ".claude", ".credentials.json"),
		filepath.Join(home, ".config", "anthropic", "credentials.json"),
		filepath.Join(home, ".codex", "auth.json"),
		"/srv/codex-home/auth.json",
		"/srv/codex/auth-override.json",
		filepath.Join(home, ".ssh", "id_rsa"), // existing default still present
	} {
		if !denyCovers(list, want) {
			t.Errorf("deny-list does not cover %s", want)
		}
	}

	// Scan output and other Data_Dir content must stay readable.
	for _, allowed := range []string{
		dataDir,
		filepath.Join(dataDir, "2026-11-13", "scan-1", "findings.json"),
		filepath.Join(dataDir, "auth-profiles.json.lock"),
		filepath.Join(home, ".xalgorix", "skills", "x.md"),
		"/usr/share/wordlists/rockyou.txt",
	} {
		if denyCovers(list, allowed) {
			t.Errorf("deny-list unexpectedly covers %s", allowed)
		}
	}
}

func TestReadDenyListKeepsOperatorEntries(t *testing.T) {
	list := resolveReadDenyList(t.TempDir(), "", "/opt/secrets: /srv/other ")
	for _, want := range []string{"/opt/secrets", "/srv/other", "/etc/xalgorix.env"} {
		if !denyCovers(list, want) {
			t.Errorf("deny-list does not cover %s", want)
		}
	}
}

// TestWritePrivateFileAtomicallyStagesUnderDeniedName: the env file's
// staging file must be named "<env file>.tmp-*" so the sandbox's ".tmp"
// sibling rule keeps agent file tools off it while it exists.
func TestWritePrivateFileAtomicallyStagesUnderDeniedName(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, ".xalgorix.env")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Skip(err)
	}
	err := writePrivateFileAtomically(target, []byte("A=1\n"))
	_ = os.Chmod(dir, 0o700)
	if err == nil {
		t.Skip("directory is writable for this user (root?); cannot observe the temp name")
	}
	if !strings.Contains(err.Error(), "create temporary env file") {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(err.Error(), ".xalgorix.env.tmp-") {
		t.Errorf("staging file name %q does not use the <env file>.tmp-* pattern", err.Error())
	}
	if err := writePrivateFileAtomically(target, []byte("A=1\n")); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 || entries[0].Name() != ".xalgorix.env" {
		t.Errorf("leftover staging files: %v", entries)
	}
}
