package reporting

import (
	"bytes"
	"image"
	"image/jpeg"
	"image/png"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateWithLogoData(t *testing.T) {
	for _, format := range []string{"png", "jpeg"} {
		t.Run(format, func(t *testing.T) {
			var data bytes.Buffer
			logo := image.NewRGBA(image.Rect(0, 0, 2, 2))
			var err error
			if format == "png" {
				err = png.Encode(&data, logo)
			} else {
				err = jpeg.Encode(&data, logo, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			path, err := Generate(&Scan{
				ID: "logo-test", Target: "example.com", Status: "finished", CompanyName: "Example",
			}, Options{
				LogoData: data.Bytes(), LogoType: format,
				// The in-memory snapshot must take precedence; no file is here.
				LogoPath: filepath.Join(dir, "missing.png"), ScanDir: dir,
			})
			if err != nil {
				t.Fatal(err)
			}
			pdf, err := os.ReadFile(path)
			if err != nil || !bytes.HasPrefix(pdf, []byte("%PDF-")) {
				t.Fatalf("expected a PDF from the logo snapshot: %v", err)
			}
			if !bytes.Contains(pdf, []byte("/Subtype /Image")) {
				t.Fatal("PDF does not contain the uploaded image")
			}
		})
	}
}
