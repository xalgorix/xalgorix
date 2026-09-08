package web

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadReportLogoUploadBoundary(t *testing.T) {
	s := &Server{dataDir: t.TempDir(), currentScanDir: t.TempDir()}
	logosDir := filepath.Join(s.dataDir, "logos")
	if err := os.Mkdir(logosDir, 0700); err != nil {
		t.Fatal(err)
	}
	logo := filepath.Join(logosDir, "brand.png")
	writeTestPNG(t, logo)
	want, err := os.ReadFile(logo)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"brand.png", "/uploads/logos/brand.png", logo} {
		t.Run(ref, func(t *testing.T) {
			data, format := s.loadReportLogo(ref)
			if !bytes.Equal(data, want) || format != "png" {
				t.Fatalf("expected the uploaded PNG, got %d bytes of %q", len(data), format)
			}
		})
	}

	other := filepath.Join(s.currentScanDir, "other.png")
	writeTestPNG(t, other)
	for _, ref := range []string{
		"", ".", "..", "other.png", other,
		"../brand.png", "/uploads/logos/../brand.png",
		"nested/brand.png", `nested\brand.png`,
		"brand.svg", "missing.png", "https://example.com/brand.png",
	} {
		t.Run("reject "+ref, func(t *testing.T) {
			data, format := s.loadReportLogo(ref)
			if len(data) != 0 || format != "" {
				t.Fatal("non-upload reference was accepted")
			}
		})
	}
}

func TestLoadReportLogoRejectsExternalSymlink(t *testing.T) {
	s := &Server{dataDir: t.TempDir()}
	logosDir := filepath.Join(s.dataDir, "logos")
	if err := os.Mkdir(logosDir, 0700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other.png")
	writeTestPNG(t, other)
	if err := os.Symlink(other, filepath.Join(logosDir, "linked.png")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if data, _ := s.loadReportLogo("linked.png"); len(data) != 0 {
		t.Fatal("a symlink outside the uploads directory was accepted")
	}
}

func TestLoadReportLogoRejectsInvalidFiles(t *testing.T) {
	s := &Server{dataDir: t.TempDir()}
	logosDir := filepath.Join(s.dataDir, "logos")
	if err := os.Mkdir(logosDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(logosDir, "invalid.png"), []byte("not an image"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(logosDir, "directory.png"), 0700); err != nil {
		t.Fatal(err)
	}
	large, err := os.Create(filepath.Join(logosDir, "large.png"))
	if err != nil {
		t.Fatal(err)
	}
	if err := large.Truncate(maxReportLogoBytes + 1); err != nil {
		large.Close()
		t.Fatal(err)
	}
	large.Close()
	for _, name := range []string{"invalid.png", "directory.png", "large.png"} {
		if data, _ := s.loadReportLogo(name); len(data) != 0 {
			t.Errorf("invalid logo %q was accepted", name)
		}
	}
}

func TestLegacyReportEmbedsUploadedLogo(t *testing.T) {
	s := &Server{dataDir: t.TempDir(), currentScanDir: t.TempDir()}
	logosDir := filepath.Join(s.dataDir, "logos")
	if err := os.Mkdir(logosDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeTestPNG(t, filepath.Join(logosDir, "brand.png"))
	path, err := s.generateReport(&ScanRecord{
		ID: "legacy-logo", Target: "example.com", Status: "finished",
		CompanyName: "Example", LogoPath: "/uploads/logos/brand.png",
	})
	if err != nil {
		t.Fatal(err)
	}
	pdf, err := os.ReadFile(path)
	if err != nil || !bytes.Contains(pdf, []byte("/Subtype /Image")) {
		t.Fatalf("legacy renderer did not embed the uploaded logo: %v", err)
	}
}
