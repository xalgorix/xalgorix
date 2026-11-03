package web

import "testing"

// The principled-finish tunables are editable from the dashboard Environment
// tab and hot-apply to new scans.
func TestConvergeFinishSettingsExposedAndHotApplied(t *testing.T) {
	defs := envDefinitionByKey()
	for key, want := range map[string]string{
		"XALGORIX_CONVERGE_FINISH_IDLE":        "500",
		"XALGORIX_CONVERGE_FINISH_LEAD_WINDOW": "100",
	} {
		def, ok := defs[key]
		if !ok {
			t.Fatalf("%s missing from env setting definitions; the WebUI would 400 when saving it", key)
		}
		if def.DefaultValue != want || def.Category != "Runtime" || def.InputType != "number" || def.RequiresRestart {
			t.Errorf("%s definition = %+v, want default %s, Runtime, number, no restart", key, def, want)
		}
	}

	s := newTestServer(t, nil)
	restart, err := s.applyEnvironmentUpdates(map[string]string{
		"XALGORIX_CONVERGE_FINISH_IDLE":        "800",
		"XALGORIX_CONVERGE_FINISH_LEAD_WINDOW": "40",
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if restart {
		t.Error("converge-finish tunables must not require a restart")
	}
	if s.cfg.ConvergeFinishIdle != 800 || s.cfg.ConvergeFinishLeadWindow != 40 {
		t.Fatalf("not applied: idle=%d window=%d", s.cfg.ConvergeFinishIdle, s.cfg.ConvergeFinishLeadWindow)
	}
	if got := s.envSettingValue("XALGORIX_CONVERGE_FINISH_IDLE"); got != "800" {
		t.Errorf("live idle value = %q, want 800", got)
	}

	// Values are clamped to safe ranges; a negative window disables it.
	for key, tc := range map[string]struct{ in, want string }{
		"XALGORIX_CONVERGE_FINISH_IDLE":        {"5", "50"},
		"XALGORIX_CONVERGE_FINISH_LEAD_WINDOW": {"-9", "-1"},
	} {
		got, err := normalizeEnvSettingValue(defs[key], tc.in)
		if err != nil || got != tc.want {
			t.Errorf("normalize %s(%q) = %q, %v; want %q", key, tc.in, got, err, tc.want)
		}
	}
	if got, _ := normalizeEnvSettingValue(defs["XALGORIX_CONVERGE_FINISH_IDLE"], "99999"); got != "5000" {
		t.Errorf("idle upper clamp = %q, want 5000", got)
	}
}
