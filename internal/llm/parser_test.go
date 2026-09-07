package llm

import (
	"strings"
	"testing"
)

func TestParseAllFormats(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		wantFn string
		wantP  map[string]string
	}{
		{
			"standard equals",
			"<function=terminal_execute>\n<parameter=command>curl -I https://example.com</parameter>\n</function>",
			"terminal_execute",
			map[string]string{"command": "curl -I https://example.com"},
		},
		{
			"space variant",
			"<function=terminal_execute>\n<parameter command>curl -I https://example.com</parameter>\n</function>",
			"terminal_execute",
			map[string]string{"command": "curl -I https://example.com"},
		},
		{
			"name attr variant",
			"<function=python_action>\n<parameter name=\"code\">print(1)</parameter>\n</function>",
			"python_action",
			map[string]string{"code": "print(1)"},
		},
		{
			"finish space",
			"<function=finish>\n<parameter summary>assessment done</parameter>\n</function>",
			"finish",
			map[string]string{"summary": "assessment done"},
		},
		{
			"multi-line value",
			"<function=finish>\n<parameter=summary>line1\nline2\nline3</parameter>\n</function>",
			"finish",
			map[string]string{"summary": "line1\nline2\nline3"},
		},
		{
			"list_files space",
			"<function=list_files>\n<parameter path>/var/www</parameter>\n</function>",
			"list_files",
			map[string]string{"path": "/var/www"},
		},
		{
			"send_request multi space",
			"<function=send_request>\n<parameter method>GET</parameter>\n<parameter url>https://example.com</parameter>\n</function>",
			"send_request",
			map[string]string{"method": "GET", "url": "https://example.com"},
		},
		{
			"multi-line space value",
			"<function=finish>\n<parameter summary>line one\nline two\nline three</parameter>\n</function>",
			"finish",
			map[string]string{"summary": "line one\nline two\nline three"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := ParseToolCalls(tt.input)
			if len(calls) == 0 {
				t.Fatalf("no tool calls parsed")
			}
			if calls[0].Name != tt.wantFn {
				t.Errorf("fn = %q, want %q", calls[0].Name, tt.wantFn)
			}
			for k, v := range tt.wantP {
				got, ok := calls[0].Args[k]
				if !ok {
					t.Errorf("missing param %q (args=%v)", k, calls[0].Args)
				} else if got != v {
					t.Errorf("param[%s] = %q, want %q", k, got, v)
				}
			}
		})
	}
}

func TestParseToolCallsRepairsNamedParameterClosingTags(t *testing.T) {
	in := `<function=report_vulnerability>
<parameter=title>Error-Based SQL Injection in X-Auth-Token Header</title>
<parameter=target>https://pentest-ground.com:9000</target>
<parameter=severity>high</severity>
<parameter=description>Database errors prove injectable input.</description>
</function>`

	calls := ParseToolCalls(in)
	if len(calls) != 1 {
		t.Fatalf("got %d calls, want 1", len(calls))
	}
	args := calls[0].Args
	if got := args["title"]; got != "Error-Based SQL Injection in X-Auth-Token Header" {
		t.Fatalf("title absorbed adjacent XML fields: %q", got)
	}
	if got := args["target"]; got != "https://pentest-ground.com:9000" {
		t.Fatalf("target = %q", got)
	}
	if got := args["severity"]; got != "high" {
		t.Fatalf("severity = %q", got)
	}
	if got := args["description"]; got != "Database errors prove injectable input." {
		t.Fatalf("description = %q", got)
	}
}

// TestFixIncomplete_SingleUnclosed exercises the original (pre-fix) case:
// one open <function=...> tag with no </function>. The repaired string
// must parse cleanly.
func TestFixIncomplete_SingleUnclosed(t *testing.T) {
	in := "<function=terminal_execute>\n<parameter=command>id</parameter>"
	fixed := fixIncomplete(in)
	if !strings.Contains(fixed, "</function>") {
		t.Fatalf("fixIncomplete did not append closing tag: %q", fixed)
	}
	calls := ParseToolCalls(fixed)
	if len(calls) != 1 || calls[0].Name != "terminal_execute" {
		t.Fatalf("expected 1 terminal_execute call, got %+v", calls)
	}
	if calls[0].Args["command"] != "id" {
		t.Errorf("command = %q, want id", calls[0].Args["command"])
	}
}

// TestFixIncomplete_MultiBlockTrailingUnclosed is the regression case the
// review flagged: two open tags but only one close — the trailing one is
// the truncated one. The fix should still produce a parseable string.
func TestFixIncomplete_MultiBlockTrailingUnclosed(t *testing.T) {
	in := "<function=list_files>\n<parameter=path>/etc</parameter>\n</function>\n" +
		"<function=terminal_execute>\n<parameter=command>id</parameter>"
	fixed := fixIncomplete(in)
	calls := ParseToolCalls(fixed)
	if len(calls) != 2 {
		t.Fatalf("expected 2 tool calls after repair, got %d (fixed=%q)", len(calls), fixed)
	}
	if calls[0].Name != "list_files" || calls[1].Name != "terminal_execute" {
		t.Errorf("call order wrong: %v", calls)
	}
}

// TestFixIncomplete_AlreadyBalanced must be a no-op when every open has a
// matching close — otherwise we'd double-close and break the parser.
func TestFixIncomplete_AlreadyBalanced(t *testing.T) {
	in := "<function=list_files>\n<parameter=path>/etc</parameter>\n</function>"
	if got := fixIncomplete(in); got != in {
		t.Errorf("expected no-op for balanced input, got %q", got)
	}
}

// TestFixIncomplete_NoOpenTag must also be a no-op so plain prose isn't
// mangled into a fake tool call.
func TestFixIncomplete_NoOpenTag(t *testing.T) {
	in := "I will now run a command."
	if got := fixIncomplete(in); got != in {
		t.Errorf("expected no-op for non-tool prose, got %q", got)
	}
}

// TestFixIncomplete_PartialEndTag handles the case where the model started
// emitting "</" but was cut off mid-tag. The fix completes it as
// "</function>".
func TestFixIncomplete_PartialEndTag(t *testing.T) {
	in := "<function=finish>\n<parameter=summary>done</parameter>\n</"
	fixed := fixIncomplete(in)
	if !strings.HasSuffix(fixed, "</function>") {
		t.Errorf("expected fixed string to end with </function>, got %q", fixed)
	}
	calls := ParseToolCalls(fixed)
	if len(calls) != 1 || calls[0].Name != "finish" {
		t.Fatalf("expected 1 finish call, got %+v", calls)
	}
}

// TestFixIncomplete_TrailingBareOpenDropped is the regression for the
// MiniMax-M3 case: a valid call followed by a trailing, param-less
// "<function=terminal_execute>" open tag (the model truncated before emitting
// params). Previously fixIncomplete closed it into a phantom empty call that
// failed "missing required parameter 'command'" and tripped the repeated-call
// guard. The bare open must now be dropped, leaving only the real call.
func TestFixIncomplete_TrailingBareOpenDropped(t *testing.T) {
	in := "<function=terminal_execute>\n<parameter=command>id</parameter>\n</function>\n" +
		"<function=terminal_execute>"
	calls := ParseToolCalls(in)
	if len(calls) != 1 {
		t.Fatalf("expected exactly 1 call (phantom empty dropped), got %d: %+v", len(calls), calls)
	}
	if calls[0].Name != "terminal_execute" || calls[0].Args["command"] != "id" {
		t.Fatalf("expected the real terminal_execute(command=id), got %+v", calls[0])
	}
}

// TestFixIncomplete_TrailingBareOpenWithCloseOnly guards the "empty but fully
// closed" open the model sometimes emits standalone. A single bare open with
// no body and no close is truncation noise — it must not become a call.
func TestFixIncomplete_LoneBareOpenDropped(t *testing.T) {
	if calls := ParseToolCalls("<function=terminal_execute>"); len(calls) != 0 {
		t.Fatalf("expected 0 calls from a lone bare open tag, got %+v", calls)
	}
}

// ParseOrphanedCalls must recover <parameter> blocks that have a trailing
// </function> but NO <function=NAME> open tag — the malformation that force-
// stopped the codeant.ai scan. The caller resolves the tool name via the
// registry schema.
func TestParseOrphanedCallsDroppedOpenTag(t *testing.T) {
	// Exact pattern from codeant.ai: open tag truncated to "_plan>", then
	// well-formed params + close.
	got := ParseOrphanedCalls("_plan>\n<parameter=task_id>dirbust</parameter>\n<parameter=status>completed</parameter>\n<parameter=notes>Done</parameter>\n</function>")
	if len(got) != 1 {
		t.Fatalf("expected 1 orphaned call, got %d", len(got))
	}
	if got[0].Args["task_id"] != "dirbust" || got[0].Args["status"] != "completed" || got[0].Args["notes"] != "Done" {
		t.Errorf("orphaned args = %v, want task_id/status/notes", got[0].Args)
	}
	if len(got[0].ParamNames) != 3 {
		t.Errorf("ParamNames = %v, want 3", got[0].ParamNames)
	}
}

// The http_request-style malformation: entire open tag + the "<" of the first
// <parameter gone, leaving "parameter=method>...</parameter>...</function>".
func TestParseOrphanedCallsMissingOpenAndParamBracket(t *testing.T) {
	got := ParseOrphanedCalls("parameter=method>POST</parameter>\n<parameter=url>https://api.x/api/analysis</parameter>\n<parameter=headers>{\"Content-Type\":\"application/json\"}</parameter>\n<parameter=body>{\"repo\":\"foo/bar\"}</parameter>\n</function>")
	if len(got) != 1 {
		t.Fatalf("expected 1 orphaned call, got %d", len(got))
	}
	// The first param lost its leading "<" so paramEqRegex won't match it;
	// the remaining well-formed params must still be recovered so the caller
	// can match the tool by url/headers/body.
	if got[0].Args["url"] == "" {
		t.Errorf("url param not recovered: %v", got[0].Args)
	}
	if got[0].Args["headers"] == "" {
		t.Errorf("headers param not recovered: %v", got[0].Args)
	}
}

// Regression (v4.5.50 → v4.5.79): the model dropped only "<function=" but kept
// the tool NAME, e.g. `terminal_execute>\n<parameter=command>curl…`. Its param
// set is just {command}, which ties across terminal_execute/browser_action/
// pageagent, so MatchByParams rejects it and the call became "no tool call" →
// reasoning loop. ParseOrphanedCalls must surface the emitted name as NameHint
// so the agent can resolve it directly (validated against the registry).
func TestParseOrphanedCallsCapturesNameHint(t *testing.T) {
	got := ParseOrphanedCalls("terminal_execute>\n<parameter=command>curl -v https://portal.flare.network/ 2>&1 | head -40</parameter>\n</function>")
	if len(got) != 1 {
		t.Fatalf("expected 1 orphaned call, got %d", len(got))
	}
	if got[0].NameHint != "terminal_execute" {
		t.Errorf("NameHint = %q, want terminal_execute", got[0].NameHint)
	}
	if got[0].Args["command"] == "" {
		t.Errorf("command param not recovered: %v", got[0].Args)
	}
}

// A pure orphaned block with NO preceding bare name must yield an empty
// NameHint (so the caller falls back to MatchByParams rather than trusting a
// spurious hint).
func TestParseOrphanedCallsNoNameHintWhenAbsent(t *testing.T) {
	got := ParseOrphanedCalls("<parameter=command>id</parameter>\n</function>")
	if len(got) != 1 {
		t.Fatalf("expected 1 orphaned call, got %d", len(got))
	}
	if got[0].NameHint != "" {
		t.Errorf("NameHint = %q, want empty", got[0].NameHint)
	}
}

// Well-formed calls must NOT be double-counted as orphans.
func TestParseOrphanedCallsSkipsWellFormed(t *testing.T) {
	content := "<function=terminal_execute>\n<parameter=command>id</parameter>\n</function>"
	got := ParseOrphanedCalls(content)
	if len(got) != 0 {
		t.Errorf("well-formed call should not produce orphans, got %d", len(got))
	}
}

// Multiple orphaned calls in one response each map to a separate OrphanedCall.
func TestParseOrphanedCallsMultiple(t *testing.T) {
	content := "<parameter=command>curl a</parameter>\n</function>\n<parameter=command>curl b</parameter>\n</function>"
	got := ParseOrphanedCalls(content)
	if len(got) != 2 {
		t.Fatalf("expected 2 orphaned calls, got %d", len(got))
	}
}
