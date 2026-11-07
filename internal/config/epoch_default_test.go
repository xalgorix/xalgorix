package config

import "testing"

// Epoch-based coverage convergence is on unless explicitly disabled.
func TestEpochCoverageDefaultsOn(t *testing.T) {
	isolateEnvFiles(t)
	t.Setenv("XALGORIX_EPOCH_COVERAGE", "")
	if !load().EpochCoverage {
		t.Fatal("EpochCoverage default = false, want true")
	}
	t.Setenv("XALGORIX_EPOCH_COVERAGE", "false")
	if load().EpochCoverage {
		t.Fatal("XALGORIX_EPOCH_COVERAGE=false did not disable epoch coverage")
	}
}
