package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// credentialPolicy mirrors Default(): Data_Dir and /tmp are write roots and
// the credential stores at the Data_Dir root are deny-listed.
func credentialPolicy(t *testing.T) (p *Policy, dataDir, keys, profiles string) {
	t.Helper()
	dataDir = t.TempDir()
	keys = filepath.Join(dataDir, "llm_keys.json")
	profiles = filepath.Join(dataDir, "auth-profiles.json")
	for _, f := range []string{keys, profiles} {
		if err := os.WriteFile(f, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p = NewWithReadDeny([]string{dataDir, "/tmp"}, []string{keys, profiles})
	return p, dataDir, keys, profiles
}

// TestCheckResolve_DenyListWinsOverAllowList: the credential stores sit
// inside the write Allow_List (Data_Dir); a write to them must still be
// refused, for create/replace/insert alike.
func TestCheckResolve_DenyListWinsOverAllowList(t *testing.T) {
	p, dataDir, keys, profiles := credentialPolicy(t)

	for _, target := range []string{keys, profiles, filepath.Join(keys, "llm_keys.json")} {
		for _, tool := range []string{"fileedit.create", "fileedit.replace", "fileedit.insert"} {
			if _, err := p.CheckResolve(nil, tool, target); !errors.Is(err, ErrPathReject) {
				t.Errorf("%s %s: err = %v, want ErrPathReject", tool, target, err)
			}
		}
	}

	// Relative spelling from a scan rooted at Data_Dir, and the ScanDir
	// exception, must not reopen the store.
	sc := scanctx.New("cred-store-scan", dataDir)
	if _, err := p.CheckResolve(sc, "fileedit.create", "llm_keys.json"); !errors.Is(err, ErrPathReject) {
		t.Errorf("relative write to the key store from a Data_Dir-rooted scan: err = %v, want ErrPathReject", err)
	}
	if _, err := p.CheckResolve(sc, "fileedit.create", "../"+filepath.Base(dataDir)+"/auth-profiles.json"); !errors.Is(err, ErrPathReject) {
		t.Errorf("dot-dot write to the profile store: err = %v, want ErrPathReject", err)
	}

	// Ordinary scan output under Data_Dir stays writable.
	if _, err := p.CheckResolve(sc, "fileedit.create", filepath.Join(dataDir, "scan-1", "notes.txt")); err != nil {
		t.Errorf("scan output write rejected: %v", err)
	}
}

// TestCheckResolve_SymlinkIntoCredentialStoreRejected: a symlink planted in
// a writable root that points at the key store resolves to the store and is
// refused.
func TestCheckResolve_SymlinkIntoCredentialStoreRejected(t *testing.T) {
	p, dataDir, keys, _ := credentialPolicy(t)
	link := filepath.Join(dataDir, "innocent.json")
	if err := os.Symlink(keys, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := p.CheckResolve(nil, "fileedit.replace", link); !errors.Is(err, ErrPathReject) {
		t.Errorf("write through symlink to key store: err = %v, want ErrPathReject", err)
	}
	if _, err := p.CheckRead(nil, "fileedit.view", link); !errors.Is(err, ErrPathReject) {
		t.Errorf("read through symlink to key store: err = %v, want ErrPathReject", err)
	}
}

// TestCheckRead_DenyEntryBehindSymlinkedDataDir: when Data_Dir itself is a
// symlink, tool paths resolve to the real directory, so the deny entry has
// to be compared in its resolved form too.
func TestCheckRead_DenyEntryBehindSymlinkedDataDir(t *testing.T) {
	real := t.TempDir()
	linkDir := filepath.Join(t.TempDir(), "data")
	if err := os.Symlink(real, linkDir); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := os.WriteFile(filepath.Join(real, "llm_keys.json"), []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	p := NewWithReadDeny([]string{linkDir}, []string{filepath.Join(linkDir, "llm_keys.json")})

	for _, path := range []string{filepath.Join(linkDir, "llm_keys.json"), filepath.Join(real, "llm_keys.json")} {
		if _, err := p.CheckRead(nil, "fileedit.view", path); !errors.Is(err, ErrPathReject) {
			t.Errorf("read %s: err = %v, want ErrPathReject", path, err)
		}
	}
}

// TestCheckRead_ProcEnvironDenied: the scanner's process environment holds
// the values loaded from its env files (EnvironmentFile=, --env-file).
func TestCheckRead_ProcEnvironDenied(t *testing.T) {
	p := New(t.TempDir())
	for _, path := range []string{"/proc/self/environ", "/proc/1/environ", "/proc/self/task/1/environ", "/proc/thread-self/environ"} {
		if _, err := p.CheckRead(nil, "fileedit.view", path); !errors.Is(err, ErrPathReject) {
			t.Errorf("read %s: err = %v, want ErrPathReject", path, err)
		}
	}
	if _, err := p.CheckRead(nil, "fileedit.view", "/proc/self/status"); err != nil {
		t.Errorf("read /proc/self/status rejected: %v", err)
	}
}

// TestCheckRead_TempSiblingsDenied: the stores stage atomic rewrites in
// "<store>.tmp" / "<store>.tmp.<random>" siblings holding the same secrets.
func TestCheckRead_TempSiblingsDenied(t *testing.T) {
	p, dataDir, keys, profiles := credentialPolicy(t)
	for _, path := range []string{keys + ".tmp", profiles + ".tmp.3f9a0c"} {
		if _, err := p.CheckRead(nil, "fileedit.view", path); !errors.Is(err, ErrPathReject) {
			t.Errorf("read %s: err = %v, want ErrPathReject", path, err)
		}
		if _, err := p.CheckResolve(nil, "fileedit.create", path); !errors.Is(err, ErrPathReject) {
			t.Errorf("write %s: err = %v, want ErrPathReject", path, err)
		}
	}
	for _, path := range []string{profiles + ".lock", filepath.Join(dataDir, "llm_keys.json.md")} {
		if _, err := p.CheckRead(nil, "fileedit.view", path); err != nil {
			t.Errorf("read %s rejected: %v", path, err)
		}
	}
}

// TestCheckResolve_DanglingSymlinkWritesRejected: a link shipped inside the
// scan workspace (cloned repo, extracted archive) whose target does not exist
// yet must canonicalize to where a write would actually land.
func TestCheckResolve_DanglingSymlinkWritesRejected(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".xalgorix", "data")
	scanDir := filepath.Join(dataDir, "scan-1")
	if err := os.MkdirAll(scanDir, 0o700); err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(home, ".xalgorix.env") // not created
	p := NewWithReadDeny(
		[]string{dataDir, filepath.Join(home, ".xalgorix")},
		[]string{envFile, filepath.Join(dataDir, "llm_keys.json"), filepath.Join(home, ".ssh")},
	)
	sc := scanctx.New("dangling-link-scan", scanDir)
	link := func(name, target string) string {
		t.Helper()
		p := filepath.Join(scanDir, name)
		if err := os.Symlink(target, p); err != nil {
			t.Skipf("symlink unsupported: %v", err)
		}
		return p
	}

	cases := map[string]string{
		// A: dangling link straight at the (absent) env file.
		"dangling-abs": link("notes.txt", envFile),
		// Relative dangling target.
		"dangling-rel": link("notes2.txt", "../../../.xalgorix.env"),
		// B: symlinked dir to Data_Dir, store and nested layout absent.
		"multi-missing": filepath.Join(link("vendor", dataDir), "llm_keys.json", "llm_keys.json"),
		// C: symlinked dir to home, ~/.ssh absent.
		"home-ssh": filepath.Join(link("h", home), ".ssh", "authorized_keys"),
		// Dangling link out of every write root.
		"outside": link("cron", "/etc/cron.d/xalgorix-test-never"),
	}
	for name, path := range cases {
		if _, err := p.CheckResolve(sc, "fileedit.create", path); err == nil {
			t.Errorf("%s: write to %s allowed, want rejection", name, path)
		}
	}

	// Ordinary new files in the scan dir, and through a link to a real
	// scan subdirectory, stay writable.
	if err := os.MkdirAll(filepath.Join(scanDir, "out"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(scanDir, "new", "a.txt"), filepath.Join(link("o", filepath.Join(scanDir, "out")), "b.txt")} {
		if _, err := p.CheckResolve(sc, "fileedit.create", path); err != nil {
			t.Errorf("write to %s rejected: %v", path, err)
		}
	}
}

func TestCanonicalize_SymlinkLoopFailsClosed(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.Symlink(b, a); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatal(err)
	}
	p := New(dir)
	if _, err := p.CheckResolve(nil, "fileedit.create", filepath.Join(a, "x")); err == nil {
		t.Fatal("write through a symlink loop was allowed")
	}
}

// TestResolve_DotDotAfterMissingComponentFailsClosed: a link target such as
// "missing/../evil/k" must not be folded textually onto a sibling symlink
// the walk never followed (the kernel fails it with ENOENT).
func TestResolve_DotDotAfterMissingComponentFailsClosed(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_rsa"), []byte("PRIVATE"), 0o600); err != nil {
		t.Fatal(err)
	}
	scanDir := t.TempDir()
	if err := os.Symlink(sshDir, filepath.Join(scanDir, "evil")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	p := NewWithReadDeny([]string{scanDir}, []string{sshDir})
	sc := scanctx.New("dotdot-missing-scan", scanDir)
	for name, target := range map[string]string{
		"rel-write": "missing/../evil/authorized_keys",
		"rel-read":  "missing/../evil/id_rsa",
		"abs-read":  scanDir + "/nope/../evil/id_rsa", // not Join: keep the ".."
	} {
		link := filepath.Join(scanDir, name)
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := p.CheckResolve(sc, "fileedit.create", link); err == nil {
			t.Errorf("%s: write through %s -> %s allowed", name, link, target)
		}
		if _, err := p.CheckRead(sc, "fileedit.view", link); err == nil {
			t.Errorf("%s: read through %s -> %s allowed", name, link, target)
		}
	}
}

// TestNew_SymlinkedRootStillWritable: a symlinked Data_Dir keeps working as
// a write root for new and existing files.
func TestNew_SymlinkedRootStillWritable(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "data")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := os.WriteFile(filepath.Join(real, "existing.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := New(link)
	for _, path := range []string{
		filepath.Join(link, "existing.txt"),
		filepath.Join(link, "new.txt"),
		filepath.Join(link, "scan-1", "deep", "new.txt"),
	} {
		if _, err := p.CheckResolve(nil, "fileedit.create", path); err != nil {
			t.Errorf("write %s under a symlinked root rejected: %v", path, err)
		}
	}
}
