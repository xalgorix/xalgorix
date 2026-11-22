package skills

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

func createMockSkillsFS() fstest.MapFS {
	return fstest.MapFS{
		"web-application-security/testing-for-xss-vulnerabilities/SKILL.md": &fstest.MapFile{
			Data: []byte("---\nname: testing-for-xss-vulnerabilities\ndescription: Complete XSS testing methodology\n---\n# XSS Methodology\nDetailed payloads and verification steps."),
		},
		"web-application-security/exploiting-server-side-request-forgery/SKILL.md": &fstest.MapFile{
			Data: []byte("---\nname: exploiting-server-side-request-forgery\ndescription: Complete SSRF testing methodology\n---\n# SSRF Methodology\nDetailed SSRF payloads."),
		},
		"network-security/pentesting-ssh/SKILL.md": &fstest.MapFile{
			Data: []byte("---\nname: pentesting-ssh\ndescription: SSH pentesting methodology\n---\n# SSH Methodology\nAudit configurations and weak ciphers."),
		},
	}
}

func TestReadSkillDuplicateSuppression(t *testing.T) {
	mockFS := createMockSkillsFS()

	t.Run("FirstReadReturnsFullContent", func(t *testing.T) {
		reg := tools.NewRegistry()
		state := newAgentSkillState()
		readFn := makeReadSkillWithState(mockFS, reg, state)

		res, err := readFn(map[string]string{"name": "testing-for-xss-vulnerabilities"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(res.Output, "Detailed payloads and verification steps") {
			t.Fatalf("expected full content, got: %s", res.Output)
		}
	})

	t.Run("ImmediateDuplicateSuppressedWhenInActiveContext", func(t *testing.T) {
		reg := tools.NewRegistry()
		state := newAgentSkillState()
		readFn := makeReadSkillWithState(mockFS, reg, state)

		// First read
		res1, err := readFn(map[string]string{"name": "testing-for-xss-vulnerabilities"})
		if err != nil {
			t.Fatalf("unexpected error on first read: %v", err)
		}
		if !strings.Contains(res1.Output, "Detailed payloads") {
			t.Fatalf("expected full content on first read")
		}

		// Simulate that the content is in the agent's active LLM context
		reg.SetContentChecker(func(snippet string) bool {
			return strings.Contains(res1.Output, snippet) || strings.Contains(snippet, "Detailed payloads")
		})

		// Immediate duplicate read
		res2, err := readFn(map[string]string{"name": "testing-for-xss-vulnerabilities"})
		if err != nil {
			t.Fatalf("unexpected error on second read: %v", err)
		}
		if !strings.Contains(res2.Output, "Skill already loaded in the current active context") {
			t.Fatalf("expected duplicate suppression message, got: %s", res2.Output)
		}
		if strings.Contains(res2.Output, "Detailed payloads and verification steps") {
			t.Fatalf("duplicate suppression should not repeat full methodology content")
		}
	})

	t.Run("AliasesResolveToSameCanonicalIdentity", func(t *testing.T) {
		reg := tools.NewRegistry()
		state := newAgentSkillState()
		readFn := makeReadSkillWithState(mockFS, reg, state)

		// First read using shorthand alias "xss"
		res1, err := readFn(map[string]string{"name": "xss"})
		if err != nil {
			t.Fatalf("unexpected error on xss read: %v", err)
		}
		if !strings.Contains(res1.Output, "Detailed payloads") {
			t.Fatalf("expected full content on xss read")
		}

		// Mock active context containing the skill output
		reg.SetContentChecker(func(snippet string) bool {
			return strings.Contains(res1.Output, snippet) || strings.Contains(snippet, "Detailed payloads")
		})

		// Second read using another alias "cross-site-scripting"
		res2, err := readFn(map[string]string{"name": "cross-site-scripting"})
		if err != nil {
			t.Fatalf("unexpected error on cross-site-scripting read: %v", err)
		}
		if !strings.Contains(res2.Output, "Skill already loaded in the current active context: testing-for-xss-vulnerabilities") {
			t.Fatalf("expected canonical alias suppression, got: %s", res2.Output)
		}
	})

	t.Run("DifferentSkillsUnaffected", func(t *testing.T) {
		reg := tools.NewRegistry()
		state := newAgentSkillState()
		readFn := makeReadSkillWithState(mockFS, reg, state)

		res1, err := readFn(map[string]string{"name": "xss"})
		if err != nil || !strings.Contains(res1.Output, "Detailed payloads") {
			t.Fatalf("failed loading xss")
		}

		reg.SetContentChecker(func(snippet string) bool {
			return strings.Contains(res1.Output, snippet)
		})

		// Reading a different skill "ssrf" must return complete content
		res2, err := readFn(map[string]string{"name": "ssrf"})
		if err != nil {
			t.Fatalf("unexpected error reading ssrf: %v", err)
		}
		if !strings.Contains(res2.Output, "Detailed SSRF payloads") {
			t.Fatalf("expected full content for ssrf, got: %s", res2.Output)
		}
	})

	t.Run("DifferentAgentsUnaffected", func(t *testing.T) {
		regA := tools.NewRegistry()
		stateA := newAgentSkillState()
		readFnA := makeReadSkillWithState(mockFS, regA, stateA)

		regB := tools.NewRegistry()
		stateB := newAgentSkillState()
		readFnB := makeReadSkillWithState(mockFS, regB, stateB)

		// Agent A loads xss
		resA, _ := readFnA(map[string]string{"name": "xss"})
		if !strings.Contains(resA.Output, "Detailed payloads") {
			t.Fatalf("agent A initial read failed")
		}
		regA.SetContentChecker(func(snippet string) bool { return true })

		// Agent A duplicate is suppressed
		resA2, _ := readFnA(map[string]string{"name": "xss"})
		if !strings.Contains(resA2.Output, "already loaded") {
			t.Fatalf("agent A duplicate should be suppressed")
		}

		// Agent B loading xss for the first time MUST receive full content
		resB, err := readFnB(map[string]string{"name": "xss"})
		if err != nil {
			t.Fatalf("agent B read error: %v", err)
		}
		if !strings.Contains(resB.Output, "Detailed payloads and verification steps") {
			t.Fatalf("agent B must receive complete methodology, got: %s", resB.Output)
		}
	})

	t.Run("PrunedFromContextReturnsFullContentAgain", func(t *testing.T) {
		reg := tools.NewRegistry()
		state := newAgentSkillState()
		readFn := makeReadSkillWithState(mockFS, reg, state)

		res1, _ := readFn(map[string]string{"name": "xss"})
		if !strings.Contains(res1.Output, "Detailed payloads") {
			t.Fatalf("expected full content on first read")
		}

		// Active context holds content
		activeContext := res1.Output
		reg.SetContentChecker(func(snippet string) bool {
			return strings.Contains(activeContext, snippet)
		})

		// Immediate duplicate is suppressed
		res2, _ := readFn(map[string]string{"name": "xss"})
		if !strings.Contains(res2.Output, "already loaded") {
			t.Fatalf("expected suppression while in context")
		}

		// Now simulate context compaction pruning out the original skill
		activeContext = "[CONTEXT PRUNED: older messages compacted]"

		// Next read MUST return the complete skill again
		res3, err := readFn(map[string]string{"name": "xss"})
		if err != nil {
			t.Fatalf("unexpected error after pruning: %v", err)
		}
		if !strings.Contains(res3.Output, "Detailed payloads and verification steps") {
			t.Fatalf("expected full content after context pruning, got: %s", res3.Output)
		}
	})

	t.Run("ChangedSkillContentReturnsNewCompleteContent", func(t *testing.T) {
		dynamicFS := fstest.MapFS{
			"web-application-security/testing-for-xss-vulnerabilities/SKILL.md": &fstest.MapFile{
				Data: []byte("Version 1 of XSS skill"),
			},
		}

		reg := tools.NewRegistry()
		state := newAgentSkillState()
		readFn := makeReadSkillWithState(dynamicFS, reg, state)

		res1, _ := readFn(map[string]string{"name": "testing-for-xss-vulnerabilities"})
		if !strings.Contains(res1.Output, "Version 1") {
			t.Fatalf("expected Version 1")
		}

		reg.SetContentChecker(func(snippet string) bool { return true })

		// Update file content in filesystem
		dynamicFS["web-application-security/testing-for-xss-vulnerabilities/SKILL.md"] = &fstest.MapFile{
			Data: []byte("Version 2 of XSS skill with novel DOM clobbering bypasses"),
		}

		res2, err := readFn(map[string]string{"name": "testing-for-xss-vulnerabilities"})
		if err != nil {
			t.Fatalf("unexpected error reading updated skill: %v", err)
		}
		if !strings.Contains(res2.Output, "Version 2 of XSS skill with novel DOM clobbering bypasses") {
			t.Fatalf("expected changed version content, got: %s", res2.Output)
		}
	})
}

func TestListSkillsDuplicateSuppression(t *testing.T) {
	mockFS := createMockSkillsFS()

	t.Run("FirstCallReturnsFullListing", func(t *testing.T) {
		reg := tools.NewRegistry()
		state := newAgentSkillState()
		listFn := makeListSkillsWithState(mockFS, reg, state)

		res, err := listFn(map[string]string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(res.Output, "Available Skills") || !strings.Contains(res.Output, "testing-for-xss-vulnerabilities") {
			t.Fatalf("expected full skill catalog, got: %s", res.Output)
		}
	})

	t.Run("DuplicateSuppressedWhenInActiveContext", func(t *testing.T) {
		reg := tools.NewRegistry()
		state := newAgentSkillState()
		listFn := makeListSkillsWithState(mockFS, reg, state)

		res1, _ := listFn(map[string]string{})
		reg.SetContentChecker(func(snippet string) bool {
			return strings.Contains(res1.Output, snippet)
		})

		res2, err := listFn(map[string]string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(res2.Output, "Skills list already loaded in the current active context") {
			t.Fatalf("expected list duplicate suppression, got: %s", res2.Output)
		}
		if strings.Contains(res2.Output, "testing-for-xss-vulnerabilities") {
			t.Fatalf("duplicate list should not repeat catalog entries")
		}
	})

	t.Run("DifferentCategoryFilterTreatedAsDifferentRequest", func(t *testing.T) {
		reg := tools.NewRegistry()
		state := newAgentSkillState()
		listFn := makeListSkillsWithState(mockFS, reg, state)

		// First call with category filter
		res1, _ := listFn(map[string]string{"category": "web-application-security"})
		reg.SetContentChecker(func(snippet string) bool {
			return strings.Contains(res1.Output, snippet)
		})

		// Second call for a different category filter MUST return full catalog for that category
		res2, err := listFn(map[string]string{"category": "network-security"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(res2.Output, "pentesting-ssh") {
			t.Fatalf("expected network-security skills, got: %s", res2.Output)
		}
	})

	t.Run("PrunedContextReturnsCompleteListAgain", func(t *testing.T) {
		reg := tools.NewRegistry()
		state := newAgentSkillState()
		listFn := makeListSkillsWithState(mockFS, reg, state)

		res1, _ := listFn(map[string]string{})
		if !strings.Contains(res1.Output, "Available Skills") {
			t.Fatalf("expected full catalog on initial list")
		}
		inContext := true
		reg.SetContentChecker(func(snippet string) bool {
			return inContext
		})

		res2, _ := listFn(map[string]string{})
		if !strings.Contains(res2.Output, "already loaded") {
			t.Fatalf("expected suppression")
		}

		// Prune
		inContext = false

		res3, err := listFn(map[string]string{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(res3.Output, "Available Skills") || !strings.Contains(res3.Output, "testing-for-xss-vulnerabilities") {
			t.Fatalf("expected complete catalog after pruning, got: %s", res3.Output)
		}
	})
}
