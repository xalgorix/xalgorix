package llm

import "testing"

// Regression for the production incident where the model emitted tool calls
// with a corrupted opening tag (missing the leading "<" or the whole
// "<function"). The strict parser skipped them, they counted as "no tool call"
// responses, and 15 in a row force-stopped the scan. These are the exact
// shapes observed in the bidatabox.com scan log.
func TestParseToolCalls_RepairsMalformedOpenTag(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		wantName string
		wantKey  string
		wantVal  string
	}{
		{
			name:     "missing leading angle bracket",
			input:    `function=terminal_execute><parameter=command>curl -sk https://x</parameter></function>`,
			wantName: "terminal_execute",
			wantKey:  "command",
			wantVal:  "curl -sk https://x",
		},
		{
			name:     "missing whole <function, bare equals",
			input:    `=terminal_execute><parameter=command>echo "test"</parameter></function>`,
			wantName: "terminal_execute",
			wantKey:  "command",
			wantVal:  `echo "test"`,
		},
		{
			name:     "bare equals send_request",
			input:    `=send_request><parameter=method>GET</parameter><parameter=url>https://bidatabox.com/Login.aspx</parameter></function>`,
			wantName: "send_request",
			wantKey:  "method",
			wantVal:  "GET",
		},
		{
			name:     "malformed with leading prose",
			input:    "Let me run this:\nfunction=http_request><parameter=url>https://x</parameter></function>",
			wantName: "http_request",
			wantKey:  "url",
			wantVal:  "https://x",
		},
		{
			name:     "stray quote before angle bracket (missing leading <)",
			input:    "function=terminal_execute\">\n<parameter=command>id</parameter>\n</function>",
			wantName: "terminal_execute",
			wantKey:  "command",
			wantVal:  "id",
		},
		{
			name:     "stray quote before angle bracket, bare equals",
			input:    "=terminal_execute\">\n<parameter=command>whoami</parameter></function>",
			wantName: "terminal_execute",
			wantKey:  "command",
			wantVal:  "whoami",
		},
		{
			name:     "quoted name",
			input:    "<function=\"send_request\"><parameter=method>GET</parameter></function>",
			wantName: "send_request",
			wantKey:  "method",
			wantVal:  "GET",
		},
		{
			// The codeant.ai incident: the model dropped the ENTIRE "<function="
			// prefix, leaving the bare tool name + a stray quote, then a
			// well-formed <parameter> body + </function>. Before the
			// repairBareNameQuotedRe repair was added, this shape was NOT
			// recovered, fell through to orphaned-param matching, tied
			// terminal_execute/browser_action/str_replace_editor/pageagent (all
			// share a single required "command" param), and the wrong tool
			// (browser_action) won non-deterministically — failing every call
			// with "unknown browser action: python3..." and force-stopping the
			// scan at 15 no-tool responses.
			name:     "whole function= prefix dropped, bare name + stray quote (codeant.ai)",
			input:    "terminal_execute\">\n<parameter=command>python3 << 'EOF'\nimport re\nEOF</parameter>\n</function>",
			wantName: "terminal_execute",
			wantKey:  "command",
			wantVal:  "python3 << 'EOF'\nimport re\nEOF",
		},
		{
			name:     "correct tag still parses (idempotent)",
			input:    "<function=finish>\n<parameter=summary>done</parameter>\n</function>",
			wantName: "finish",
			wantKey:  "summary",
			wantVal:  "done",
		},
		{
			name:     "nested parameter tag emitted by MiniMax",
			input:    "<function=terminal_execute>\n<parameter<parameter>command</parameter>\n<parameter>echo repaired</parameter>\n</function>",
			wantName: "terminal_execute",
			wantKey:  "command",
			wantVal:  "echo repaired",
		},
		{
			name:     "bare malformed parameter name",
			input:    "<function=finish>\n<parameter<summary</parameter>\n<parameter>done</parameter>\n</function>",
			wantName: "finish",
			wantKey:  "summary",
			wantVal:  "done",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := ParseToolCalls(tc.input)
			if len(calls) != 1 {
				t.Fatalf("got %d tool calls, want 1 (input=%q)", len(calls), tc.input)
			}
			if calls[0].Name != tc.wantName {
				t.Errorf("name = %q, want %q", calls[0].Name, tc.wantName)
			}
			if got := calls[0].Args[tc.wantKey]; got != tc.wantVal {
				t.Errorf("args[%q] = %q, want %q", tc.wantKey, got, tc.wantVal)
			}
		})
	}
}

// Ordinary prose containing "=word>" but NOT a tool-call body must never be
// mistaken for a tool call.
func TestParseToolCalls_DoesNotMisparseProse(t *testing.T) {
	inputs := []string{
		"The comparison a=b> shows the config value.",
		"Set timeout=30> in the file and restart.",
		"No tools here, just explaining the plan for the next step.",
	}
	for _, in := range inputs {
		if calls := ParseToolCalls(in); len(calls) != 0 {
			t.Errorf("ParseToolCalls(%q) = %d calls, want 0", in, len(calls))
		}
	}
}

// The repaired malformed call must also be stripped from displayed text so the
// UI doesn't show raw "function=terminal_execute>..." noise as a message.
func TestCleanContent_StripsRepairedMalformedCall(t *testing.T) {
	in := "Running fingerprint:\nfunction=terminal_execute><parameter=command>id</parameter></function>"
	got := CleanContent(in)
	if got != "Running fingerprint:" {
		t.Errorf("CleanContent = %q, want %q", got, "Running fingerprint:")
	}
}

func TestMalformedToolOutputReason(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "MiniMax internal control token leak",
			in:   "echo]<]minimax[>[\\nReading /reservation/user1",
			want: "provider_control_token_leak",
		},
		{
			name: "bare tool-call marker",
			in:   "agent\\n<tool_call>",
			want: "unparsed_tool_call",
		},
		{
			name: "unrecoverable XML residue",
			in:   "<function>terminal_execute</function>",
			want: "malformed_tool_xml",
		},
		{
			name: "ordinary prose",
			in:   "I should make a tool call next.",
			want: "",
		},
		{
			name: "valid parsed call is classified only by caller",
			in:   "normal text with no protocol tags",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MalformedToolOutputReason(tt.in); got != tt.want {
				t.Fatalf("MalformedToolOutputReason() = %q, want %q", got, tt.want)
			}
		})
	}
}
