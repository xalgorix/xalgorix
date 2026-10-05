package tools

import (
	"strings"
	"sync"
	"testing"
)

// TestExecute_DoesNotMutateCallerArgs verifies the defensive-copy fix:
// callers (e.g. the agent's tool-call logger) hand a map to Execute and
// must see it unchanged, even when _raw fallback substitution happens.
func TestExecute_DoesNotMutateCallerArgs(t *testing.T) {
	r := NewRegistry()
	r.Register(&Tool{
		Name: "echo",
		Parameters: []Parameter{
			{Name: "msg", Required: true},
		},
		Execute: func(args map[string]string) (Result, error) {
			return Result{Output: args["msg"]}, nil
		},
	})

	original := map[string]string{"_raw": "hello"}
	// Snapshot the original keys so we can compare after the call.
	snapshot := map[string]string{}
	for k, v := range original {
		snapshot[k] = v
	}

	res, err := r.Execute("echo", original)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.Output != "hello" {
		t.Errorf("output=%q, want hello (raw fallback should fill required param)", res.Output)
	}

	// Caller's map must still contain only "_raw" — the registry must not
	// have inserted "msg" or removed "_raw".
	if len(original) != len(snapshot) {
		t.Errorf("caller args mutated (len %d → %d): %v", len(snapshot), len(original), original)
	}
	for k, v := range snapshot {
		if got, ok := original[k]; !ok || got != v {
			t.Errorf("caller args[%q] = %q, want %q", k, got, v)
		}
	}
	if _, leaked := original["msg"]; leaked {
		t.Error("registry leaked 'msg' substitution back into caller's map")
	}
}

// TestExecute_RawFallbackToRequiredParam covers the happy path: a tool with
// a single required parameter and an args map containing only _raw should
// be invoked with that param filled.
func TestExecute_RawFallbackToRequiredParam(t *testing.T) {
	r := NewRegistry()
	r.Register(&Tool{
		Name: "run",
		Parameters: []Parameter{
			{Name: "command", Required: true},
		},
		Execute: func(args map[string]string) (Result, error) {
			if _, hasRaw := args["_raw"]; hasRaw {
				t.Error("inner Execute saw _raw; it should have been deleted")
			}
			return Result{Output: args["command"]}, nil
		},
	})

	res, err := r.Execute("run", map[string]string{"_raw": "id"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.Output != "id" {
		t.Errorf("output=%q, want id", res.Output)
	}
}

// TestExecute_MissingRequiredParam exercises the validation path.
func TestExecute_MissingRequiredParam(t *testing.T) {
	r := NewRegistry()
	r.Register(&Tool{
		Name: "needs_arg",
		Parameters: []Parameter{
			{Name: "target", Required: true},
		},
		Execute: func(_ map[string]string) (Result, error) {
			t.Error("Execute should not have been called")
			return Result{}, nil
		},
	})

	_, err := r.Execute("needs_arg", map[string]string{})
	if err == nil {
		t.Fatal("expected error when required param missing")
	}
	if !strings.Contains(err.Error(), "missing required parameter 'target'") {
		t.Errorf("err = %v, want containing 'missing required parameter target'", err)
	}
}

// TestExecute_BatchesMissingRequiredParams verifies that when SEVERAL required
// params are missing, a single error lists ALL of them (so the agent fixes
// them in one resubmit instead of thrashing one field per iteration — the
// report_vulnerability loop).
func TestExecute_BatchesMissingRequiredParams(t *testing.T) {
	r := NewRegistry()
	r.Register(&Tool{
		Name: "report",
		Parameters: []Parameter{
			{Name: "title", Required: true},
			{Name: "severity", Required: true},
			{Name: "description", Required: true},
			{Name: "impact", Required: false},
		},
		Execute: func(_ map[string]string) (Result, error) {
			t.Error("Execute should not run while required params are missing")
			return Result{}, nil
		},
	})

	// Provide only title → severity + description still missing.
	_, err := r.Execute("report", map[string]string{"title": "SQLi"})
	if err == nil {
		t.Fatal("expected error when required params missing")
	}
	msg := err.Error()
	for _, want := range []string{"severity", "description"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error should list missing %q; got: %s", want, msg)
		}
	}
	if strings.Contains(msg, "title") {
		t.Errorf("error should not list the provided 'title'; got: %s", msg)
	}
}

// TestSchemaXML_EscapesUnsafeChars is the regression for the XML-injection
// risk flagged in the review: a skill or tool with "<", ">", "&", or quote
// characters in its name/description must produce well-formed XML.
func TestSchemaXML_EscapesUnsafeChars(t *testing.T) {
	r := NewRegistry()
	r.Register(&Tool{
		Name:        "evil&tool",
		Description: `desc with <tag> and "quotes" & ampersand`,
		Parameters: []Parameter{
			{
				Name:        "param<bad>",
				Description: "value contains </parameter> close tag attempt",
				Required:    true,
			},
		},
	})

	out := r.SchemaXML()

	// Raw unsafe chars must be gone from the rendered description text.
	if strings.Contains(out, "<tag>") {
		t.Errorf("schema contains literal <tag>: %s", out)
	}
	if strings.Contains(out, "& ampersand") {
		t.Errorf("schema contains unescaped &: %s", out)
	}
	// And the entities we expect must be present.
	if !strings.Contains(out, "&amp;") {
		t.Errorf("schema missing &amp; entity: %s", out)
	}
	if !strings.Contains(out, "&lt;tag&gt;") {
		t.Errorf("schema missing &lt;tag&gt; escaped form: %s", out)
	}
}

// TestSchemaXML_ConcurrentReads sanity-checks that SchemaXML is safe to call
// from multiple goroutines (it acquires r.mu read-locks). Without -race we
// rely on the goroutines completing without panic.
func TestSchemaXML_ConcurrentReads(t *testing.T) {
	r := NewRegistry()
	for i := 0; i < 5; i++ {
		r.Register(&Tool{
			Name:        "tool",
			Description: "desc",
		})
	}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = r.SchemaXML()
		}()
	}
	wg.Wait()
}

// MatchByParams resolves a tool whose required params are all present — the
// recovery path for tool calls whose <function=NAME> open tag was dropped,
// leaving only <parameter> blocks. Must be conservative: ambiguous/partial
// sets resolve to nothing.
func TestMatchByParamsUpdatePlan(t *testing.T) {
	r := NewRegistry()
	r.Register(&Tool{Name: "update_plan", Parameters: []Parameter{
		{Name: "task_id", Required: true}, {Name: "status", Required: true}, {Name: "notes", Required: false},
	}})
	r.Register(&Tool{Name: "terminal_execute", Parameters: []Parameter{
		{Name: "command", Required: true},
	}})

	// update_plan's required params present → resolves to update_plan.
	name, ok := r.MatchByParams([]string{"task_id", "status", "notes"})
	if !ok || name != "update_plan" {
		t.Errorf("MatchByParams(task_id,status,notes) = %q,%v, want update_plan,true", name, ok)
	}
	// Missing a required param (status) → no match (don't execute wrong tool).
	name, ok = r.MatchByParams([]string{"task_id", "notes"})
	if ok {
		t.Errorf("MatchByParams with missing required param should not resolve, got %q", name)
	}
	// terminal_execute's single required param → resolves.
	name, ok = r.MatchByParams([]string{"command"})
	if !ok || name != "terminal_execute" {
		t.Errorf("MatchByParams(command) = %q,%v, want terminal_execute,true", name, ok)
	}
	// Empty / unknown params → no match.
	name, ok = r.MatchByParams([]string{"nonsense"})
	if ok {
		t.Errorf("MatchByParams(nonsense) should not resolve, got %q", name)
	}
	name, ok = r.MatchByParams(nil)
	if ok {
		t.Errorf("MatchByParams(nil) should not resolve, got %q", name)
	}
}

// MatchByParams must NOT resolve a tie. This is the codeant.ai root cause:
// terminal_execute, browser_action, str_replace_editor and pageagent all share
// a single required "command" parameter, so a dropped-open-tag call that
// recovers only {"command"} cannot uniquely identify the tool. The previous
// implementation picked an arbitrary winner via randomized map iteration
// (browser_action), executed the wrong tool, and force-stopped the scan.
// A tie is ambiguity — it must resolve to nothing rather than a guess.
func TestMatchByParamsRejectsTie(t *testing.T) {
	r := NewRegistry()
	for _, def := range []struct {
		name   string
		params []Parameter
	}{
		{"terminal_execute", []Parameter{{Name: "command", Required: true}}},
		{"browser_action", []Parameter{
			{Name: "command", Required: true},
			{Name: "url", Required: false},
		}},
		{"str_replace_editor", []Parameter{
			{Name: "command", Required: true},
			{Name: "path", Required: true},
		}},
		{"pageagent", []Parameter{
			{Name: "command", Required: true},
			{Name: "id", Required: false},
		}},
	} {
		r.Register(&Tool{Name: def.name, Parameters: def.params})
	}

	// "command" alone ties all four tools at score 1 → ambiguous → no match.
	if name, ok := r.MatchByParams([]string{"command"}); ok {
		t.Errorf("MatchByParams(command) with 4 command-param tools = %q,true, want no match (tie)", name)
	}

	// Adding a browser-only optional param breaks the tie → browser_action wins.
	if name, ok := r.MatchByParams([]string{"command", "url"}); !ok || name != "browser_action" {
		t.Errorf("MatchByParams(command,url) = %q,%v, want browser_action,true", name, ok)
	}

	// Adding pageagent-only "id" → pageagent wins (score 2 vs the others' 1).
	if name, ok := r.MatchByParams([]string{"command", "id"}); !ok || name != "pageagent" {
		t.Errorf("MatchByParams(command,id) = %q,%v, want pageagent,true", name, ok)
	}
}

// RequiresParams reports whether a tool declares any REQUIRED parameter. The
// agent loop uses it to drop empty-Args calls (well-formed <function=NAME>
// </function> bodies that the parser matched but that yielded zero params —
// produced when a model splits a multi-param call's fields across separate
// calls). Such a call can never satisfy required params, so it's dropped
// rather than wasting an iteration on a guaranteed registry error. Critically,
// a tool whose params are ALL optional (e.g. code_search) legitimately accepts
// an empty body and must report RequiresParams=false so its calls are kept.
func TestRequiresParams(t *testing.T) {
	r := NewRegistry()
	r.Register(&Tool{Name: "update_plan", Parameters: []Parameter{
		{Name: "task_id", Required: true}, {Name: "status", Required: true}, {Name: "notes", Required: false},
	}})
	r.Register(&Tool{Name: "code_search", Parameters: []Parameter{
		{Name: "query", Required: false}, {Name: "sinks", Required: false}, {Name: "glob", Required: false},
	}})
	r.Register(&Tool{Name: "terminal_execute", Parameters: []Parameter{
		{Name: "command", Required: true},
	}})

	// Tools with ≥1 required param → true (empty body is never a valid call).
	if !r.RequiresParams("update_plan") {
		t.Error("update_plan requires task_id+status → RequiresParams must be true")
	}
	if !r.RequiresParams("terminal_execute") {
		t.Error("terminal_execute requires command → RequiresParams must be true")
	}

	// Tool with ALL-optional params → false (empty body is legitimate).
	if r.RequiresParams("code_search") {
		t.Error("code_search has no required params → RequiresParams must be false (empty body is valid)")
	}

	// Unknown tool → false (don't block calls to tools we don't know about).
	if r.RequiresParams("does_not_exist") {
		t.Error("unknown tool → RequiresParams must be false")
	}
}
