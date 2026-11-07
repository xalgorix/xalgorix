package web

import "testing"

// The dashboard shows and applies epoch coverage as on by default.
func TestEpochCoverageSettingDefaultsOn(t *testing.T) {
	def, ok := envDefinitionByKey()["XALGORIX_EPOCH_COVERAGE"]
	if !ok || def.DefaultValue != "true" {
		t.Fatalf("XALGORIX_EPOCH_COVERAGE definition = %+v, want default true", def)
	}
	s := newTestServer(t, nil)
	s.cfg.EpochCoverage = false
	s.applyEnvironmentToRuntimeConfig(map[string]string{"XALGORIX_EPOCH_COVERAGE": ""})
	if !s.cfg.EpochCoverage {
		t.Fatal("an empty XALGORIX_EPOCH_COVERAGE did not fall back to the default (true)")
	}
}
