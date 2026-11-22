package skills

import (
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/tools"
	"github.com/xalgord/xalgorix/v4/internal/tools/codesearch"
)

const whiteboxSkill = "implementing-semgrep-for-custom-sast-rules" // devsecops

type skillTools struct {
	search, list, read func(map[string]string) (tools.Result, error)
}

// skillToolsForScan builds the three skill tools the way Register does, bound
// to a fresh scan context.
func skillToolsForScan(t *testing.T) (skillTools, string) {
	t.Helper()
	sub, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprintf("whitebox-gate-%s-%d", t.Name(), time.Now().UnixNano())
	reg := tools.NewRegistry()
	reg.SetScanContextID(id)
	state := newAgentSkillState()
	t.Cleanup(func() { codesearch.SetSourceRoot(id, "") })
	return skillTools{
		search: makeSearchSkillsFor(sub, reg),
		list:   makeListSkillsWithState(sub, reg, state),
		read:   makeReadSkillWithState(sub, reg, state),
	}, id
}

// TestWhiteboxSkillsHiddenWithoutSource verifies that a black-box scan never
// sees source-review skills: search leaves them out, list leaves out their
// categories, and read refuses them with the reason. Web skills are unaffected.
func TestWhiteboxSkillsHiddenWithoutSource(t *testing.T) {
	st, _ := skillToolsForScan(t)

	res, _ := st.search(map[string]string{"query": "semgrep custom sast rules"})
	if strings.Contains(res.Output, whiteboxSkill) {
		t.Fatalf("search offered a source-review skill to a black-box scan:\n%s", res.Output)
	}
	res, _ = st.search(map[string]string{"query": "sast", "category": "devsecops"})
	if !strings.Contains(res.Output, "source code attached") {
		t.Fatalf("search in a source-review category did not explain why it is empty: %q", res.Output)
	}

	res, _ = st.list(map[string]string{})
	for _, cat := range []string{"DEVSECOPS", "SUPPLY-CHAIN-SECURITY"} {
		if strings.Contains(res.Output, "### "+cat+" ") {
			t.Fatalf("list showed %s to a black-box scan", cat)
		}
	}
	if !strings.Contains(res.Output, "### WEB-APPLICATION-SECURITY ") {
		t.Fatal("list lost the web categories")
	}
	res, _ = st.list(map[string]string{"category": "supply-chain-security"})
	if !strings.Contains(res.Output, "source code attached") {
		t.Fatalf("listing a source-review category did not explain why: %q", res.Output)
	}

	res, _ = st.read(map[string]string{"name": whiteboxSkill})
	if res.Output != "" || !strings.Contains(res.Error, "source code attached") {
		t.Fatalf("read returned a source-review skill to a black-box scan: output %d bytes, error %q", len(res.Output), res.Error)
	}
	res, _ = st.read(map[string]string{"name": "exploiting-server-side-request-forgery"})
	if !strings.HasPrefix(res.Output, "---\nname: exploiting-server-side-request-forgery") {
		t.Fatalf("a web skill no longer loads: %q", res.Error)
	}
}

// TestWhiteboxSkillsAvailableWithSource verifies that the same tools offer the
// source-review skills once the scan has source code attached.
func TestWhiteboxSkillsAvailableWithSource(t *testing.T) {
	st, id := skillToolsForScan(t)
	codesearch.SetSourceRoot(id, t.TempDir())

	res, _ := st.search(map[string]string{"query": "semgrep custom sast rules"})
	if !strings.Contains(res.Output, whiteboxSkill) {
		t.Fatalf("search did not offer the source-review skill to a scan with source:\n%s", res.Output)
	}
	res, _ = st.list(map[string]string{})
	if !strings.Contains(res.Output, "### DEVSECOPS ") || !strings.Contains(res.Output, "### SUPPLY-CHAIN-SECURITY ") {
		t.Fatal("list did not show the source-review categories to a scan with source")
	}
	res, _ = st.read(map[string]string{"name": whiteboxSkill})
	if !strings.HasPrefix(res.Output, "---\nname: "+whiteboxSkill) {
		t.Fatalf("read refused the source-review skill to a scan with source: %q", res.Error)
	}
}
