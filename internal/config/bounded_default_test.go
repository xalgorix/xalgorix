package config

import "testing"

// Bounded working context is on unless explicitly disabled.
func TestBoundedContextDefaultsOn(t *testing.T) {
	isolateEnvFiles(t)
	t.Setenv("XALGORIX_BOUNDED_CONTEXT", "")
	if !load().BoundedContext {
		t.Fatal("BoundedContext default = false, want true")
	}
	t.Setenv("XALGORIX_BOUNDED_CONTEXT", "false")
	if load().BoundedContext {
		t.Fatal("XALGORIX_BOUNDED_CONTEXT=false did not disable bounded context")
	}
}
