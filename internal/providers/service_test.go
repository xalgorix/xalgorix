// Package providers — unit tests for the v4.4.22 compiled-in
// catalog. The tests cover the Builtin() + Service surface only;
// the v4.4.21 mutation property tests were dropped along with the
// runtime-editable catalog.
package providers

import (
	"context"
	"sort"
	"strings"
	"testing"
)

// TestBuiltin_AlphabeticalAndUnique asserts the compiled-in slice
// is sorted alphabetically by ID, contains no duplicate IDs, and
// places "custom" last (so the LLM tab dropdown ordering matches
// the data ordering). Catches accidental merge conflicts that
// duplicate or reorder entries.
func TestBuiltin_AlphabeticalAndUnique(t *testing.T) {
	entries := Builtin()
	if len(entries) == 0 {
		t.Fatal("Builtin() returned empty slice")
	}

	// Pick out the trailing "custom" entry; assert it is the
	// last element so the LLM tab dropdown reads naturally.
	if entries[len(entries)-1].ID != "custom" {
		t.Errorf("last entry = %q, want \"custom\"", entries[len(entries)-1].ID)
	}

	// Excluding "custom", every other entry is alphabetical.
	rest := entries[:len(entries)-1]
	ids := make([]string, len(rest))
	for i, e := range rest {
		ids[i] = e.ID
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("non-custom entries are not alphabetically sorted: %v", ids)
	}

	// Uniqueness across the whole slice (custom included).
	seen := make(map[string]int, len(entries))
	for i, e := range entries {
		if prev, dup := seen[e.ID]; dup {
			t.Errorf("duplicate id %q at index %d (first seen at %d)", e.ID, i, prev)
		}
		seen[e.ID] = i
	}
}

// TestBuiltin_RequiredFields asserts every entry has at minimum an
// ID, DisplayName, and HeaderStyle set, and that HeaderStyle is one
// of the three values the LLM client knows how to dispatch on.
// Empty BaseURL is allowed (operator must fill via Custom Provider
// override or env var); empty AuthMethods is treated as "api_key"
// by the UI.
func TestBuiltin_RequiredFields(t *testing.T) {
	allowed := map[string]struct{}{
		"openai":           {},
		"openai_responses": {},
		"anthropic":        {},
		"gemini":           {},
	}
	for _, e := range Builtin() {
		if strings.TrimSpace(e.ID) == "" {
			t.Errorf("entry has empty ID: %+v", e)
			continue
		}
		if strings.TrimSpace(e.DisplayName) == "" {
			t.Errorf("entry %q has empty DisplayName", e.ID)
		}
		if _, ok := allowed[e.HeaderStyle]; !ok {
			t.Errorf("entry %q has invalid HeaderStyle %q (want openai|openai_responses|anthropic|gemini)", e.ID, e.HeaderStyle)
		}
	}
}

// TestService_RoundTripsBuiltin asserts NewService.List returns the
// same set of entries Builtin() produces and Get correctly resolves
// every ID.
func TestService_RoundTripsBuiltin(t *testing.T) {
	svc := NewService()
	if svc.IsEmpty() {
		t.Fatal("NewService.IsEmpty() = true; want false")
	}
	listed, err := svc.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != len(Builtin()) {
		t.Errorf("List len = %d, want %d", len(listed), len(Builtin()))
	}
	for _, e := range Builtin() {
		got, ok, err := svc.Get(context.Background(), e.ID)
		if err != nil {
			t.Errorf("Get %q: err = %v", e.ID, err)
			continue
		}
		if !ok {
			t.Errorf("Get %q: ok = false; want true", e.ID)
			continue
		}
		if got.ID != e.ID || got.DisplayName != e.DisplayName {
			t.Errorf("Get %q mismatch: got %+v want %+v", e.ID, got, e)
		}
	}
}

func TestBuiltin_NovitaConfiguration(t *testing.T) {
	entry, ok := LookupBuiltin("novita")
	if !ok {
		t.Fatal("Novita provider is missing from the built-in catalog")
	}
	if entry.BaseURL != "https://api.novita.ai/openai/v1" {
		t.Errorf("Novita BaseURL = %q, want https://api.novita.ai/openai/v1", entry.BaseURL)
	}
	if entry.HeaderStyle != "openai" {
		t.Errorf("Novita HeaderStyle = %q, want openai", entry.HeaderStyle)
	}
	if len(entry.AuthMethods) != 1 || entry.AuthMethods[0] != "api_key" {
		t.Errorf("Novita AuthMethods = %v, want [api_key]", entry.AuthMethods)
	}
}

func TestBuiltin_RuncrateConfiguration(t *testing.T) {
	entry, ok := LookupBuiltin("runcrate")
	if !ok {
		t.Fatal("Runcrate provider is missing from the built-in catalog")
	}
	if entry.BaseURL != "https://api.runcrate.ai/v1" {
		t.Errorf("Runcrate BaseURL = %q, want https://api.runcrate.ai/v1", entry.BaseURL)
	}
	if entry.HeaderStyle != "openai" {
		t.Errorf("Runcrate HeaderStyle = %q, want openai", entry.HeaderStyle)
	}
	if len(entry.AuthMethods) != 1 || entry.AuthMethods[0] != "api_key" {
		t.Errorf("Runcrate AuthMethods = %v, want [api_key]", entry.AuthMethods)
	}
}

func TestBuiltin_ZAIConfigurations(t *testing.T) {
	tests := []struct {
		id      string
		baseURL string
	}{
		{"zai", "https://api.z.ai/api/paas/v4"},
		{"zai-coding-plan", "https://api.z.ai/api/coding/paas/v4"},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			entry, ok := LookupBuiltin(tt.id)
			if !ok {
				t.Fatalf("%s provider is missing from the built-in catalog", tt.id)
			}
			if entry.BaseURL != tt.baseURL {
				t.Errorf("BaseURL = %q, want %q", entry.BaseURL, tt.baseURL)
			}
			if entry.HeaderStyle != "openai" {
				t.Errorf("HeaderStyle = %q, want openai", entry.HeaderStyle)
			}
			if len(entry.AuthMethods) != 1 || entry.AuthMethods[0] != "api_key" {
				t.Errorf("AuthMethods = %v, want [api_key]", entry.AuthMethods)
			}
		})
	}
}

// TestService_GetUnknown asserts an unknown id returns
// (zero, false, nil) without an error so callers can branch
// cleanly.
func TestService_GetUnknown(t *testing.T) {
	svc := NewService()
	_, ok, err := svc.Get(context.Background(), "no-such-provider-id")
	if err != nil {
		t.Fatalf("Get unknown err = %v, want nil", err)
	}
	if ok {
		t.Error("Get unknown ok = true; want false")
	}
}

// TestClientIDForEntry_EnvOverride asserts the
// XALGORIX_<UPPER_ID>_OAUTH_CLIENT_ID escape hatch wins over the
// compiled-in ClientID, and that the absence of the env var
// returns the compiled-in default unchanged.
func TestClientIDForEntry_EnvOverride(t *testing.T) {
	e := Entry{ID: "google", ClientID: ""}

	t.Run("default empty when env unset", func(t *testing.T) {
		t.Setenv("XALGORIX_GOOGLE_OAUTH_CLIENT_ID", "")
		if got := ClientIDForEntry(e); got != "" {
			t.Errorf("ClientIDForEntry default = %q, want empty", got)
		}
	})

	t.Run("env override wins", func(t *testing.T) {
		t.Setenv("XALGORIX_GOOGLE_OAUTH_CLIENT_ID", "operator-supplied-client-id")
		if got := ClientIDForEntry(e); got != "operator-supplied-client-id" {
			t.Errorf("ClientIDForEntry override = %q, want operator-supplied-client-id", got)
		}
	})

	t.Run("compiled-in default when env unset and ClientID present", func(t *testing.T) {
		t.Setenv("XALGORIX_COPILOT_OAUTH_CLIENT_ID", "")
		entry := Entry{ID: "copilot", ClientID: "Iv1.b507a08c87ecfe98"}
		if got := ClientIDForEntry(entry); got != "Iv1.b507a08c87ecfe98" {
			t.Errorf("ClientIDForEntry copilot default = %q, want Iv1.b507a08c87ecfe98", got)
		}
	})
}
