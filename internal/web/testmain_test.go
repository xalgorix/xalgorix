package web

import (
	"crypto/sha256"
	"fmt"
	"os"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// realEnvFile is the env file of the account running the tests, and
// realEnvFileBefore its state before any test ran.
var realEnvFile, realEnvFileBefore string

// TestMain points HOME at a temp dir before any test runs. Settings handlers
// persist through applyEnvironmentUpdates into config.EnvFilePath(), which is
// $HOME/.xalgorix.env, so without this any test that saves a setting rewrites
// the real file. On 2026-11-12 the suite ran as root on a production scanner
// and TestKeyPool_InputValidation replaced /root/.xalgorix.env's API keys.
// Tests that set their own HOME with t.Setenv still work: it is restored to
// the temp HOME afterwards.
//
// Package init runs before this with the real HOME: internal/tools/proxy's
// init calls config.Get(), so the config singleton has already read the real
// env files and holds the real data dir. Only paths resolved from HOME after
// this point, such as EnvFilePath(), use the temp dir.
func TestMain(m *testing.M) {
	os.Exit(runWithTempHome(m))
}

func runWithTempHome(m *testing.M) int {
	realEnvFile = config.EnvFilePath()
	realEnvFileBefore = envFileState(realEnvFile)

	home, err := os.MkdirTemp("", "xalgorix-web-test-home-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create temp HOME: %v\n", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(home) }()
	// config.load also reads /home/$SUDO_USER/.xalgorix.env.
	for key, value := range map[string]string{"HOME": home, "SUDO_USER": ""} {
		if err := os.Setenv(key, value); err != nil {
			fmt.Fprintf(os.Stderr, "set %s: %v\n", key, err)
			return 1
		}
	}

	code := m.Run()
	if envFileState(realEnvFile) != realEnvFileBefore {
		fmt.Fprintf(os.Stderr, "FAIL: the tests changed %s, the env file of the account running them; settings must be written under the temp HOME\n", realEnvFile)
		return 1
	}
	return code
}

// envFileState fingerprints whether a file exists, its mode and its content.
func envFileState(path string) string {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return "absent"
	}
	if err != nil {
		return "stat error: " + err.Error()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("%v unreadable: %v", info.Mode(), err)
	}
	return fmt.Sprintf("%v %x", info.Mode(), sha256.Sum256(data))
}
