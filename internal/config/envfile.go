package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var envFileKeyPattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

// accountEnvFiles are, in a test binary, the env files of the account running
// it. They are resolved when the package loads, before a test can point HOME
// at a temp dir, so UpdateEnvFile can refuse them.
var accountEnvFiles = func() []string {
	if !testing.Testing() {
		return nil
	}
	paths := []string{"/etc/xalgorix.env", "/root/.xalgorix.env"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths, filepath.Join(home, ".xalgorix.env"))
	}
	if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
		paths = append(paths, filepath.Join("/home", sudoUser, ".xalgorix.env"))
	}
	return paths
}()

// refuseAccountEnvFile stops a test binary from writing the env file of the
// account running it. On 2026-11-12 the test suite ran as root on a production
// scanner, replaced /root/.xalgorix.env's API keys with test keys, and every
// LLM call failed after the next restart.
func refuseAccountEnvFile(path string, protected []string) error {
	target := resolveEnvFilePath(path)
	targetInfo, targetErr := os.Stat(path)
	for _, p := range protected {
		same := resolveEnvFilePath(p) == target
		if !same && targetErr == nil {
			if info, err := os.Stat(p); err == nil {
				same = os.SameFile(info, targetInfo)
			}
		}
		if same {
			return fmt.Errorf("refusing to write %s from a test binary: it is the env file of the account running the tests (point HOME at a temp dir)", path)
		}
	}
	return nil
}

// resolveEnvFilePath resolves symlinks in the path's directory and makes it
// absolute, so a relative path or one through a symlinked dir still matches.
// Symlinks are resolved before ".." is applied, as the kernel does. The file
// itself may not exist yet.
func resolveEnvFilePath(path string) string {
	dir, file := filepath.Split(path)
	if dir == "" {
		dir = "."
	}
	if resolved, err := filepath.EvalSymlinks(dir); err == nil {
		dir = resolved
	}
	if abs, err := filepath.Abs(dir); err == nil {
		dir = abs
	}
	return filepath.Join(dir, file)
}

// EnvFilePath returns the per-user configuration file used by both the CLI
// setup wizard and the dashboard settings page.
func EnvFilePath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "/root"
	}
	return filepath.Join(home, ".xalgorix.env")
}

// ReadEnvFile parses a dotenv-style file without changing the process
// environment. Missing files are treated as empty configuration.
func ReadEnvFile(path string) (map[string]string, error) {
	values := map[string]string{}
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return values, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read env file: %w", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		key, value, ok := parseEnvLine(scanner.Text())
		if ok {
			values[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read env file: %w", err)
	}
	return values, nil
}

// UpdateEnvFile preserves unrelated settings and comments while applying the
// supplied values. An empty value removes that key. The replacement is atomic
// and the resulting file is always private to the current user. In a test
// binary it refuses the env files of the account running the tests.
func UpdateEnvFile(path string, updates map[string]string) error {
	if testing.Testing() {
		if err := refuseAccountEnvFile(path, accountEnvFiles); err != nil {
			return err
		}
	}
	for key, value := range updates {
		if !envFileKeyPattern.MatchString(key) {
			return fmt.Errorf("invalid environment variable name %q", key)
		}
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("%s cannot contain newlines", key)
		}
	}

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read env file: %w", err)
	}
	var lines []string
	if len(existing) > 0 {
		lines = strings.Split(strings.TrimRight(string(existing), "\n"), "\n")
	}

	seen := make(map[string]bool, len(updates))
	newLines := make([]string, 0, len(lines)+len(updates)+1)
	for _, line := range lines {
		key, _, ok := parseEnvLine(line)
		if !ok {
			newLines = append(newLines, line)
			continue
		}
		value, shouldUpdate := updates[key]
		if !shouldUpdate {
			newLines = append(newLines, line)
			continue
		}
		seen[key] = true
		if value != "" {
			newLines = append(newLines, formatEnvLine(key, value))
		}
	}

	missing := make([]string, 0, len(updates))
	for key, value := range updates {
		if !seen[key] && value != "" {
			missing = append(missing, key)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 && len(newLines) > 0 && strings.TrimSpace(newLines[len(newLines)-1]) != "" {
		newLines = append(newLines, "")
	}
	for _, key := range missing {
		newLines = append(newLines, formatEnvLine(key, updates[key]))
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create env dir: %w", err)
	}
	out := strings.TrimRight(strings.Join(newLines, "\n"), "\n")
	if out != "" {
		out += "\n"
	}
	return writePrivateFileAtomically(path, []byte(out))
}

func parseEnvLine(line string) (string, string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return "", "", false
	}
	trimmed = strings.TrimPrefix(trimmed, "export ")
	parts := strings.SplitN(trimmed, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key := strings.TrimSpace(parts[0])
	if !envFileKeyPattern.MatchString(key) {
		return "", "", false
	}
	value := strings.TrimSpace(parts[1])
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}
	}
	return key, value, true
}

func formatEnvLine(key, value string) string {
	return key + "=" + value
}

func writePrivateFileAtomically(path string, data []byte) error {
	// The ".tmp" suffix on the env file's own name keeps the staging file
	// under the agent file-tool deny-list entry for that env file.
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary env file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("secure temporary env file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write env file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync env file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close env file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("replace env file: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("chmod env file: %w", err)
	}
	return nil
}
