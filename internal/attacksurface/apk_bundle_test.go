package attacksurface

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// buildZip writes a ZIP whose entries are the given name→content pairs. Stored
// (uncompressed) entries keep UncompressedSize64 populated, which the parser
// uses to size its read buffer.
func buildZip(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range entries {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store})
		if err != nil {
			t.Fatalf("CreateHeader(%q): %v", name, err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("Write(%q): %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes()
}

// Endpoints in React Native / Flutter apps live in native libraries rather than
// classes.dex, so lib/**.so must be scanned.
func TestParseAPKScansNativeLibraries(t *testing.T) {
	apk := buildZip(t, map[string][]byte{
		"lib/arm64-v8a/libflutter.so": []byte(`dart snapshot "https://api.native-example.com/v1/login"`),
		"res/drawable/icon.png":       []byte("\x89PNG not scanned"),
	})

	// The nil result is handled in the else branch so every deref below sits
	// inside a branch where res is provably non-nil (staticcheck SA5011).
	if res := parseAPK(apk); res != nil {
		if len(res.BaseURLs) == 0 && len(res.Endpoints) == 0 {
			t.Fatalf("native library was not scanned: %+v", res)
		}
	} else {
		t.Fatal("parseAPK returned nil for a valid APK")
	}
}

// .apks/.xapk bundles are ZIPs of APKs; the parser must descend into them.
func TestParseAPKDescendsIntoSplitBundle(t *testing.T) {
	base := buildZip(t, map[string][]byte{
		"classes.dex": []byte(`const url = "https://api.bundle-example.com/v2/users"`),
	})
	bundle := buildZip(t, map[string][]byte{
		"splits/base-master.apk": base,
		"toc.pb":                 []byte("table of contents"),
	})

	if res := parseAPK(bundle); res != nil {
		if len(res.BaseURLs) == 0 && len(res.Endpoints) == 0 {
			t.Fatalf("split bundle yielded nothing — nested APK not parsed: %+v", res)
		}
	} else {
		t.Fatal("parseAPK returned nil for a split bundle")
	}
}

// Recursion must terminate: a bundle nested deeper than maxAPKNesting is
// ignored rather than followed indefinitely.
func TestParseAPKBoundsNesting(t *testing.T) {
	inner := buildZip(t, map[string][]byte{
		"classes.dex": []byte(`"https://api.too-deep-example.com/v1/secret"`),
	})
	mid := buildZip(t, map[string][]byte{"splits/inner.apk": inner})
	outer := buildZip(t, map[string][]byte{"splits/mid.apk": mid})

	// Should not panic or hang; the deepest layer is simply not reached.
	if res := parseAPK(outer); res == nil {
		t.Fatal("parseAPK returned nil for a deeply nested bundle")
	}
}

// An artifact yielding only hosts (no concrete paths) is still usable context
// and must not be rejected — this was the hard 400 on APK upload.
func TestLoadFromPathAcceptsBaseURLsOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.apk")
	apk := buildZip(t, map[string][]byte{
		"classes.dex": []byte(`retrofit.baseUrl("https://api.hosts-only-example.com")`),
	})
	if err := os.WriteFile(path, apk, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	res, err := LoadFromPath(path)
	if err != nil {
		t.Fatalf("LoadFromPath rejected an APK that yielded hosts: %v", err)
	}
	if res == nil || (len(res.BaseURLs) == 0 && len(res.Endpoints) == 0) {
		t.Fatalf("expected recovered context, got %+v", res)
	}
}

// A ZIP-based Android artifact is routed through the streaming path, so the
// .apks extension must load from disk without being read wholesale.
func TestLoadFromPathStreamsSplitBundle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.apks")
	base := buildZip(t, map[string][]byte{
		"classes.dex": []byte(`"https://api.streamed-example.com/v1/items"`),
	})
	if err := os.WriteFile(path, buildZip(t, map[string][]byte{"splits/base.apk": base}), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	res, err := LoadFromPath(path)
	if err != nil {
		t.Fatalf("LoadFromPath(.apks) failed: %v", err)
	}
	if len(res.BaseURLs) == 0 && len(res.Endpoints) == 0 {
		t.Fatalf(".apks yielded nothing: %+v", res)
	}
}

func TestIsAndroidArchive(t *testing.T) {
	for _, p := range []string{"a.apk", "a.APK", "b.apks", "c.xapk", "d.aab"} {
		if !isAndroidArchive(p) {
			t.Errorf("isAndroidArchive(%q) = false, want true", p)
		}
	}
	for _, p := range []string{"spec.json", "cap.har", "s.yaml", "notes.txt"} {
		if isAndroidArchive(p) {
			t.Errorf("isAndroidArchive(%q) = true, want false", p)
		}
	}
}
