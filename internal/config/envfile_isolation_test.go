package config

import "testing"

// isolateEnvFiles keeps load() from reading the developer's own env files
// (~/.xalgorix.env, the sudo user's copy), which would override the values a
// test sets.
func isolateEnvFiles(t *testing.T) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SUDO_USER", "")
}
