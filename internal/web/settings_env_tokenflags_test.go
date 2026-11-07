package web

import (
	"testing"
)

// TestTokenSaverEnvSettingsExposed guards that the two token-optimization
// flags and their tunables are configurable from the dashboard Environment
// tab (they were flag-gated in v4.6.90 but missing from the allowlist, so the
// WebUI 400'd on save and the settings were invisible).
func TestTokenSaverEnvSettingsExposed(t *testing.T) {
	defs := envDefinitionByKey()
	for _, key := range []string{
		"XALGORIX_BOUNDED_CONTEXT",
		"XALGORIX_TOOL_ARCHIVE_ACTIVE_WINDOW",
		"XALGORIX_TOOL_ARCHIVE_MIN_BYTES",
		"XALGORIX_ROLE_SCOPED_TOOLS",
	} {
		def, ok := defs[key]
		if !ok {
			t.Fatalf("%s missing from env setting definitions; the WebUI would 400 when saving it", key)
		}
		if def.Category != "LLM" {
			t.Errorf("%s category = %q, want LLM (grouped with context settings)", key, def.Category)
		}
		if def.Sensitive {
			t.Errorf("%s should not be Sensitive", key)
		}
	}
}

// TestTokenSaverSettingsHotApply verifies saving the flags through the
// environment endpoint applies them to the live runtime config so NEW scans
// pick them up without a server restart.
func TestTokenSaverSettingsHotApply(t *testing.T) {
	s := newTestServer(t, nil)
	if s.cfg.BoundedContext || s.cfg.RoleScopedTools {
		t.Fatalf("a zero config must start with the flags off, got bounded=%v scoped=%v", s.cfg.BoundedContext, s.cfg.RoleScopedTools)
	}

	restart, err := s.applyEnvironmentUpdates(map[string]string{
		"XALGORIX_BOUNDED_CONTEXT":            "true",
		"XALGORIX_ROLE_SCOPED_TOOLS":          "true",
		"XALGORIX_TOOL_ARCHIVE_MIN_BYTES":     "2000",
		"XALGORIX_TOOL_ARCHIVE_ACTIVE_WINDOW": "12",
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if restart {
		t.Fatal("token-saver flags hot-apply to new scans; they must not require a restart")
	}
	if !s.cfg.BoundedContext || !s.cfg.RoleScopedTools {
		t.Fatalf("flags not applied to runtime config: bounded=%v scoped=%v", s.cfg.BoundedContext, s.cfg.RoleScopedTools)
	}
	if s.cfg.ToolArchiveMinBytes != 2000 || s.cfg.ToolArchiveActiveWindow != 12 {
		t.Fatalf("tunables not applied: min=%d window=%d", s.cfg.ToolArchiveMinBytes, s.cfg.ToolArchiveActiveWindow)
	}

	// Live-value reads reflect the runtime config (drives the UI display).
	if got := s.envSettingValue("XALGORIX_BOUNDED_CONTEXT"); got != "true" {
		t.Fatalf("live value = %q, want true", got)
	}
}
