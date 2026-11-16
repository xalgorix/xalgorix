package terminal

import (
	"strings"
	"testing"
)

// The opt-in auto-installer hands these specs to `pipx install` / `pip3
// install` as root on the scanning host. A bare spec is resolved on PyPI, so it
// must be a name the tool's own project publishes there; anything else has to
// come from the project's repository.
func TestPipxInstallSpecsUseVerifiedSources(t *testing.T) {
	// Checked on PyPI: published, with releases, by the tool's own project.
	verifiedOnPyPI := map[string]bool{
		"arjun": true, "bandit": true, "git-dumper": true,
		"scrapling": true, "semgrep": true, "uro": true,
	}
	if got, want := pipxInstallSpecs["paramspider"], "git+https://github.com/devanshbatham/paramspider.git"; got != want {
		t.Fatalf("paramspider install spec = %q, want %q (the project ships from its repository)", got, want)
	}
	for cmd, spec := range pipxInstallSpecs {
		if strings.HasPrefix(spec, "git+https://github.com/") {
			continue
		}
		if !verifiedOnPyPI[spec] {
			t.Errorf("auto-install of %q resolves %q on PyPI, which is not a verified name for that project; "+
				"check it on PyPI and add it to verifiedOnPyPI, or install from the upstream repository", cmd, spec)
		}
	}
}
