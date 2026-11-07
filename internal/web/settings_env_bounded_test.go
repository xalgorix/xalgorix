package web

import "testing"

// The dashboard shows and applies bounded working context as on by default.
func TestBoundedContextSettingDefaultsOn(t *testing.T) {
	def, ok := envDefinitionByKey()["XALGORIX_BOUNDED_CONTEXT"]
	if !ok || def.DefaultValue != "true" {
		t.Fatalf("XALGORIX_BOUNDED_CONTEXT definition = %+v, want default true", def)
	}
	s := newTestServer(t, nil)
	s.applyEnvironmentToRuntimeConfig(map[string]string{"XALGORIX_BOUNDED_CONTEXT": ""})
	if !s.cfg.BoundedContext {
		t.Fatal("an empty XALGORIX_BOUNDED_CONTEXT did not fall back to the default (true)")
	}
}
