package llm

import "testing"

// A MiniMax tool call wrapped with — or abutting — its internal control-token
// delimiter (<]minimax[>) must still parse to the real call. Before the
// normalizeFormat strip, the delimiter broke the XML parse, so the turn was
// misread as "no tool call" and then flagged provider_control_token_leak,
// driving the malformed-recovery ladder (hard context reset at 5) on output
// that actually contained a healthy call.
func TestParseToolCalls_StripsProviderControlToken(t *testing.T) {
	cases := []string{
		"<]minimax[>\n<function=terminal_execute>\n<parameter=command>id</parameter>\n</function>",
		"planning]<]minimax[>[\n<function=terminal_execute>\n<parameter=command>id</parameter>\n</function>",
		"<function=terminal_execute>\n<parameter=command>id</parameter>\n</function>\n<] MiniMax [>",
	}
	for i, in := range cases {
		calls := ParseToolCalls(in)
		if len(calls) != 1 {
			t.Fatalf("case %d: expected 1 call, got %d (%+v)", i, len(calls), calls)
		}
		if calls[0].Name != "terminal_execute" {
			t.Fatalf("case %d: name = %q", i, calls[0].Name)
		}
		if calls[0].Args["command"] != "id" {
			t.Fatalf("case %d: command = %q, want id", i, calls[0].Args["command"])
		}
	}

	// A bare control-token leak with no call must still yield zero calls, so the
	// caller's MalformedToolOutputReason path still recognizes a genuine
	// no-action turn — the strip must not fabricate a call.
	if calls := ParseToolCalls("<]minimax[> just some prose, no call here"); len(calls) != 0 {
		t.Fatalf("bare leak: expected 0 calls, got %d", len(calls))
	}
}
