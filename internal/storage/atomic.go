// Package storage holds shared on-disk write primitives consumed by
// internal/providers and internal/auth so the temp+rename contract is
// implemented exactly once.
package storage

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// WriteAtomic writes data to "<dst>.tmp.<rand>" in the same directory
// as dst, fsyncs it, chmods it to 0o600, then renames over dst.
//
// On any failure prior to the rename the temp file is removed so the
// caller never observes a stray "<dst>.tmp.*" sibling on disk. After a
// successful rename the destination has mode 0o600.
//
// WriteAtomic does NOT create the parent directory. Callers that need
// to ensure the destination directory exists should call
// EnsureSecureDir on filepath.Dir(dst) first.
//
// Validates: Requirements 1.1, 1.4, 4.1, 4.4.
func WriteAtomic(dst string, data []byte) error {
	dir := filepath.Dir(dst)
	base := filepath.Base(dst)

	// Generate a random suffix so concurrent writers in the same
	// directory cannot collide on the temp filename.
	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return fmt.Errorf("storage: random suffix: %w", err)
	}
	tmp := filepath.Join(dir, fmt.Sprintf("%s.tmp.%s", base, hex.EncodeToString(suffix[:])))

	// O_EXCL guarantees we never reuse a previous abandoned temp file.
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("storage: create temp %q: %w", tmp, err)
	}

	cleanup := func() { _ = os.Remove(tmp) }

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("storage: write temp %q: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		cleanup()
		return fmt.Errorf("storage: fsync temp %q: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		cleanup()
		return fmt.Errorf("storage: close temp %q: %w", tmp, err)
	}
	// Chmod after Close so any umask effects on OpenFile are normalized.
	if err := os.Chmod(tmp, 0o600); err != nil {
		cleanup()
		return fmt.Errorf("storage: chmod temp %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		cleanup()
		return fmt.Errorf("storage: rename temp %q -> %q: %w", tmp, dst, err)
	}
	// Persist the directory entry as well as the file contents on systems
	// that support directory fsync, so a power loss cannot undo the rename.
	if runtime.GOOS != "windows" {
		d, err := os.Open(dir)
		if err != nil {
			return fmt.Errorf("storage: open directory: %w", err)
		}
		err = d.Sync()
		_ = d.Close()
		if err != nil {
			return fmt.Errorf("storage: fsync directory: %w", err)
		}
	}
	return nil
}

// EnsureSecureDir creates the directory at path (and any missing
// parents) with mode 0o700 if it does not already exist. When the
// directory already exists EnsureSecureDir leaves its mode untouched —
// callers that need to tighten permissions on a pre-existing directory
// must do so explicitly.
//
// Validates: Requirements 1.1, 4.1.
func EnsureSecureDir(path string) error {
	if path == "" {
		return fmt.Errorf("storage: ensure dir: empty path")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("storage: ensure dir %q: %w", path, err)
	}
	return nil
}
