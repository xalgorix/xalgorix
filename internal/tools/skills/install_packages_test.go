package skills

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// verifiedInstallPackagesFile lists every package name that the bundled
// skills (and the repository's tools.md) tell the agent or an operator to
// install from a public registry. Skills are followed by an agent that runs
// commands on the scanning host, so a name there that the intended project
// does not publish is an install of whatever someone else uploads under it.
const verifiedInstallPackagesFile = "testdata/verified_install_packages.list"

// installCommandRe finds package-manager install commands. Group 1 is the
// package manager, group 2 the argument text up to the end of the shell
// command, Markdown code span or table cell.
var installCommandRe = regexp.MustCompile("(?m)(?:^|[\\s`(\"'])(?:sudo\\s+)?" +
	"(pip3?|python3?(?:\\.[0-9]+)?\\s+-m\\s+pip|pipx|uv\\s+pip|uv\\s+tool|npm|yarn(?:\\s+global)?|pnpm|bun|gem|cargo)" +
	"\\s+(?:install|i|add)\\b([^\\n`|;&)#]*)")

var (
	pypiNameRe  = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	pypiSepRe   = regexp.MustCompile(`[-_.]+`)
	npmNameRe   = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$`)
	gemNameRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	crateNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)
)

// installFlagsWithValue are the options whose next argument is not a package.
var installFlagsWithValue = map[string]map[string]bool{
	"pypi": setOf("-r", "--requirement", "-c", "--constraint", "-e", "--editable",
		"-i", "--index-url", "--extra-index-url", "-f", "--find-links", "-t", "--target",
		"--prefix", "--root", "--src", "--python", "--platform", "--python-version",
		"--implementation", "--abi", "--upgrade-strategy", "--trusted-host", "--proxy",
		"--timeout", "--retries", "--cache-dir", "--log", "-C", "--config-settings",
		"--pip-args", "--suffix", "--progress-bar", "--only-binary", "--no-binary"),
	"npm": setOf("--registry", "--prefix", "--tag", "-w", "--workspace", "--cache",
		"--omit", "--include", "--install-strategy"),
	"rubygems": setOf("-v", "--version", "-i", "--install-dir", "-n", "--bindir",
		"--source", "--platform"),
	"crates": setOf("--version", "--vers", "--git", "--path", "--branch", "--tag", "--rev",
		"--root", "--index", "--registry", "--features", "-F", "--bin", "--example",
		"--target", "--target-dir", "--profile", "-j", "--jobs", "--config"),
}

func setOf(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, item := range items {
		m[item] = true
	}
	return m
}

// installProseWords end an install command's argument list when Markdown
// prose follows the command on the same line ("pip install foo or use apt").
var installProseWords = setOf("or", "and", "then", "if", "to", "for", "from", "via", "using", "with")

type installRef struct {
	ecosystem string
	name      string
	line      int
}

func installEcosystem(manager string) string {
	switch strings.Fields(manager)[0] {
	case "npm", "yarn", "pnpm", "bun":
		return "npm"
	case "gem":
		return "rubygems"
	case "cargo":
		return "crates"
	default: // pip, pip3, python -m pip, pipx, uv pip, uv tool
		return "pypi"
	}
}

// installPackageName returns the registry name a single install argument
// refers to, or "" when it is not a registry name (a path, URL, VCS spec,
// placeholder or shell variable).
func installPackageName(ecosystem, tok string) string {
	if tok == "" || strings.ContainsAny(tok[:1], "./~$<{[%\\") || strings.Contains(tok, "://") {
		return ""
	}
	switch ecosystem {
	case "pypi":
		if i := strings.IndexAny(tok, "[<>=!~;@(,"); i >= 0 {
			tok = tok[:i]
		}
		if !pypiNameRe.MatchString(tok) {
			return ""
		}
		return pypiSepRe.ReplaceAllString(strings.ToLower(tok), "-")
	case "npm":
		var name string
		if strings.HasPrefix(tok, "@") {
			scope, rest, ok := strings.Cut(tok, "/")
			if !ok {
				return ""
			}
			rest, _, _ = strings.Cut(rest, "@")
			name = scope + "/" + rest
		} else {
			if strings.Contains(tok, "/") || strings.Contains(tok, ":") {
				return "" // GitHub shorthand, git or file spec
			}
			name, _, _ = strings.Cut(tok, "@")
		}
		if !npmNameRe.MatchString(name) {
			return ""
		}
		return name
	case "rubygems":
		name, _, _ := strings.Cut(tok, ":")
		if !gemNameRe.MatchString(name) {
			return ""
		}
		return name
	case "crates":
		if !crateNameRe.MatchString(tok) {
			return ""
		}
		return strings.ReplaceAll(strings.ToLower(tok), "_", "-")
	}
	return ""
}

// findInstallRefs returns every registry package named by an install command
// in text, with its 1-based line number.
func findInstallRefs(text string) []installRef {
	// Join backslash-continued shell lines without moving byte offsets.
	joined := strings.ReplaceAll(text, "\\\n", "  ")
	var refs []installRef
	for pos := 0; pos < len(joined); {
		m := installCommandRe.FindStringSubmatchIndex(joined[pos:])
		if m == nil {
			break
		}
		for i := range m {
			if m[i] >= 0 {
				m[i] += pos
			}
		}
		ecosystem := installEcosystem(joined[m[2]:m[3]])
		line := 1 + strings.Count(text[:m[2]], "\n")
		next := m[5]
		toks := fieldOffsets(joined[m[4]:m[5]])
		for i := 0; i < len(toks); i++ {
			tok := strings.Trim(toks[i].text, `"'`)
			if installProseWords[strings.ToLower(tok)] {
				// Prose follows the command. Resume the scan there so a
				// second command later on the same line is still checked.
				next = m[4] + toks[i].at
				break
			}
			if strings.HasPrefix(tok, "-") {
				if !strings.Contains(tok, "=") && installFlagsWithValue[ecosystem][tok] {
					i++
				}
				continue
			}
			if name := installPackageName(ecosystem, tok); name != "" {
				refs = append(refs, installRef{ecosystem: ecosystem, name: name, line: line})
			}
		}
		pos = next
	}
	return refs
}

type fieldOffset struct {
	text string
	at   int
}

// fieldOffsets splits s on ASCII whitespace like strings.Fields and records
// where each field starts.
func fieldOffsets(s string) []fieldOffset {
	var out []fieldOffset
	start := -1
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n' || s[i] == '\v' || s[i] == '\f' {
			if start >= 0 {
				out = append(out, fieldOffset{text: s[start:i], at: start})
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	return out
}

func TestFindInstallRefsParsesCommandForms(t *testing.T) {
	cases := []struct {
		text string
		want []string
	}{
		{"pip install -r requirements.txt foo==1.2 'bar[x]>=2'", []string{"pypi foo", "pypi bar"}},
		{"python3 -m pip install --index-url https://example.test/simple Foo_Bar", []string{"pypi foo-bar"}},
		{"- jwt_tool (`pip install jwt_tool` or `git clone https://github.com/x/y.git`)", []string{"pypi jwt-tool"}},
		{"(pip install XLMMacroDeobfuscator)", []string{"pypi xlmmacrodeobfuscator"}},
		{"sudo pip3 install --break-system-packages a \\\n    b  # comment c", []string{"pypi a", "pypi b"}},
		{"pipx install git+https://github.com/a/b.git", nil},
		{"pip install <internal-package-name>   # placeholder", nil},
		{"pip install -e . && pip install ./dist/pkg.whl", nil},
		{"npm i -g @scope/pkg@1.0 left-pad expressjs/express", []string{"npm @scope/pkg", "npm left-pad"}},
		{"npm install            # or npm ci", nil},
		{"yarn global add wscat", []string{"npm wscat"}},
		{"gem install --no-document -v 1.0 evil-winrm", []string{"rubygems evil-winrm"}},
		{"cargo install x8 --features foo", []string{"crates x8"}},
		{"| tool | `cargo install feroxbuster --locked` |", []string{"crates feroxbuster"}},
		{"npm init && pip installer && gem list", nil},
		{"(`pip install foo` or use the distro package)", []string{"pypi foo"}},
		{"pip install foo or apt-get install bar", []string{"pypi foo"}},
		{"pip install foo or pip install bar", []string{"pypi foo", "pypi bar"}},
		{"pip install foo and then gem install baz", []string{"pypi foo", "rubygems baz"}},
		{"pip install --progress-bar off foo", []string{"pypi foo"}},
		{"npm install --omit dev left-pad", []string{"npm left-pad"}},
	}
	for _, tc := range cases {
		var got []string
		for _, ref := range findInstallRefs(tc.text) {
			got = append(got, ref.ecosystem+" "+ref.name)
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("findInstallRefs(%q) = %q, want %q", tc.text, got, tc.want)
		}
	}
	refs := findInstallRefs("a\nb \\\nc\npip install x\n")
	if len(refs) != 1 || refs[0].line != 4 {
		t.Fatalf("line numbers: got %+v, want one ref on line 4", refs)
	}
}

type installSource struct {
	name string
	text string
}

func installCommandSources(t *testing.T) []installSource {
	t.Helper()
	var sources []installSource
	err := fs.WalkDir(embeddedSkillsDataFS, ".", func(file string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := fs.ReadFile(embeddedSkillsDataFS, file)
		if err != nil {
			return err
		}
		sources = append(sources, installSource{name: "data/" + file, text: string(data)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) < 800 {
		t.Fatalf("walked only %d skill files; the embedded catalog did not load", len(sources))
	}
	toolsDoc := filepath.Join("..", "..", "..", "tools.md")
	data, err := os.ReadFile(toolsDoc)
	if err != nil {
		t.Fatal(err)
	}
	return append(sources, installSource{name: "tools.md", text: string(data)})
}

func loadVerifiedInstallPackages(t *testing.T) map[string]bool {
	t.Helper()
	f, err := os.Open(verifiedInstallPackagesFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	verified := make(map[string]bool)
	scanner := bufio.NewScanner(f)
	for n := 1; scanner.Scan(); n++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || installFlagsWithValue[fields[0]] == nil {
			t.Fatalf("%s:%d: want \"<pypi|npm|rubygems|crates> <name>\", got %q", verifiedInstallPackagesFile, n, line)
		}
		if installPackageName(fields[0], fields[1]) != fields[1] {
			t.Fatalf("%s:%d: %q is not a normalized %s name", verifiedInstallPackagesFile, n, fields[1], fields[0])
		}
		verified[fields[0]+" "+fields[1]] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return verified
}

// TestInstallCommandsNameVerifiedPackages pins every registry package that a
// skill or tools.md tells the reader to install to a reviewed list, so a skill
// cannot send the agent to a name that is unregistered, held with no
// releases, or owned by an unrelated project.
func TestInstallCommandsNameVerifiedPackages(t *testing.T) {
	verified := loadVerifiedInstallPackages(t)
	used := make(map[string]bool)
	for _, src := range installCommandSources(t) {
		for _, ref := range findInstallRefs(src.text) {
			key := ref.ecosystem + " " + ref.name
			used[key] = true
			if !verified[key] {
				t.Errorf("%s:%d tells the reader to install %s package %q, which is not in %s. "+
					"Confirm on the registry that this name is published, with releases, by the project the text means "+
					"(not an unregistered name, an empty placeholder or an unrelated project), or use the tool's upstream "+
					"install method instead; then add the entry.",
					src.name, ref.line, ref.ecosystem, ref.name, verifiedInstallPackagesFile)
			}
		}
	}
	for key := range verified {
		if !used[key] {
			t.Errorf("%s lists %q but no skill or tools.md installs it any more; remove the entry", verifiedInstallPackagesFile, key)
		}
	}
}
