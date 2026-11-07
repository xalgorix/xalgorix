package config

import "testing"

// The principled finish is on unless explicitly disabled.
func TestConvergeFinishDefaultsOn(t *testing.T) {
	isolateEnvFiles(t)
	t.Setenv("XALGORIX_CONVERGE_FINISH", "")
	if !load().ConvergeFinish {
		t.Fatal("ConvergeFinish default = false, want true")
	}
	t.Setenv("XALGORIX_CONVERGE_FINISH", "false")
	if load().ConvergeFinish {
		t.Fatal("XALGORIX_CONVERGE_FINISH=false did not disable the principled finish")
	}
}
