package llm

import "testing"

// Some models can emit their native DSML tool-call markup as plain
// text. Every turn was previously classified as "no tool call" and the scan was
// force-stopped after the no-tool limit; each shape must now parse to real calls.
func TestParseToolCalls_DSMLMarkup(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []ToolCall
	}{
		{
			name: "fullwidth bars, single call",
			input: "<｜DSML｜function_calls>\n" +
				"<｜DSML｜invoke name=\"terminal_execute\">\n" +
				"<｜DSML｜parameter name=\"command\" string=\"true\">echo hi</｜DSML｜parameter>\n" +
				"</｜DSML｜invoke>\n" +
				"</｜DSML｜function_calls>",
			want: []ToolCall{{Name: "terminal_execute", Args: map[string]string{"command": "echo hi"}}},
		},
		{
			name: "ascii bars with spacing, multiple params and calls",
			input: "Checking the endpoint.\n<| DSML |function_calls>\n" +
				"<| DSML |invoke name=\"http_request\">\n" +
				"<| DSML |parameter name=\"url\" string=\"true\">https://example.com/api?a=1&b=2</| DSML |parameter>\n" +
				"<| DSML |parameter name=\"method\" string=\"true\">GET</| DSML |parameter>\n" +
				"</| DSML |invoke>\n" +
				"<| DSML |invoke name=\"add_note\">\n" +
				"<| DSML |parameter name=\"key\" string=\"false\">3</| DSML |parameter>\n" +
				"</| DSML |invoke>\n" +
				"</| DSML |function_calls>",
			want: []ToolCall{
				{Name: "http_request", Args: map[string]string{"url": "https://example.com/api?a=1&b=2", "method": "GET"}},
				{Name: "add_note", Args: map[string]string{"key": "3"}},
			},
		},
		{
			name: "multi-line value with shell redirect",
			input: "<｜DSML｜invoke name=\"terminal_execute\">\n" +
				"<｜DSML｜parameter name=\"command\" string=\"true\">curl -sk https://example.com/ > out.html\nwc -c out.html</｜DSML｜parameter>\n" +
				"</｜DSML｜invoke>",
			want: []ToolCall{{Name: "terminal_execute", Args: map[string]string{"command": "curl -sk https://example.com/ > out.html\nwc -c out.html"}}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := ParseToolCalls(tc.input)
			if len(calls) != len(tc.want) {
				t.Fatalf("expected %d calls, got %d (%+v)", len(tc.want), len(calls), calls)
			}
			for i, want := range tc.want {
				if calls[i].Name != want.Name {
					t.Fatalf("call %d name = %q, want %q", i, calls[i].Name, want.Name)
				}
				for k, v := range want.Args {
					if got := calls[i].Args[k]; got != v {
						t.Fatalf("call %d arg %q = %q, want %q", i, k, got, v)
					}
				}
				if len(calls[i].Args) != len(want.Args) {
					t.Fatalf("call %d args = %+v, want %+v", i, calls[i].Args, want.Args)
				}
			}
		})
	}
}

// Prose that merely mentions DSML is not a call, and a plain invoke call is
// unaffected by the DSML normalization.
func TestParseToolCalls_DSML_NoFalsePositive(t *testing.T) {
	if calls := ParseToolCalls("The model's DSML format uses a ｜DSML｜ marker; nothing to run."); len(calls) != 0 {
		t.Fatalf("prose: expected 0 calls, got %d (%+v)", len(calls), calls)
	}
	calls := ParseToolCalls("<invoke name=\"terminal_execute\">\n<parameter name=\"command\">id</parameter>\n</invoke>")
	if len(calls) != 1 || calls[0].Name != "terminal_execute" || calls[0].Args["command"] != "id" {
		t.Fatalf("plain invoke altered: %+v", calls)
	}
}
