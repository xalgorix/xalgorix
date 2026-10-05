// Package tools provides the tool registry and execution framework.
package tools

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// CircuitBreaker tracks tool failures and can temporarily block failing tools
type CircuitBreaker struct {
	mu           sync.RWMutex
	failures     map[string]int
	lastFailure  map[string]time.Time
	failLimit    int
	recoveryTime time.Duration
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(failLimit int, recoverySeconds int) *CircuitBreaker {
	return &CircuitBreaker{
		failures:     make(map[string]int),
		lastFailure:  make(map[string]time.Time),
		failLimit:    failLimit,
		recoveryTime: time.Duration(recoverySeconds) * time.Second,
	}
}

// RecordFailure records a failure for a tool
func (cb *CircuitBreaker) RecordFailure(toolName string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures[toolName]++
	cb.lastFailure[toolName] = time.Now()
}

// RecordSuccess records a success for a tool (resets failures)
func (cb *CircuitBreaker) RecordSuccess(toolName string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures[toolName] = 0
}

// IsOpen checks if the circuit is open (blocked) for a tool
func (cb *CircuitBreaker) IsOpen(toolName string) bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	failCount, exists := cb.failures[toolName]
	if !exists || failCount < cb.failLimit {
		return false
	}

	// Check if recovery time has passed
	if lastFail, ok := cb.lastFailure[toolName]; ok {
		if time.Since(lastFail) > cb.recoveryTime {
			return false // Allow retry after recovery time
		}
	}

	return true
}

// GetRecoveryTime returns seconds until circuit closes (for UI)
func (cb *CircuitBreaker) GetRecoveryTime(toolName string) int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if lastFail, ok := cb.lastFailure[toolName]; ok {
		remaining := cb.recoveryTime - time.Since(lastFail)
		if remaining > 0 {
			return int(remaining.Seconds())
		}
	}
	return 0
}

// Reset clears all circuit breaker state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = make(map[string]int)
	cb.lastFailure = make(map[string]time.Time)
}

// Tool represents a registered tool that the agent can call.
type Tool struct {
	Name        string
	Description string
	Parameters  []Parameter
	Execute     func(args map[string]string) (Result, error)
}

// Parameter describes a tool parameter.
type Parameter struct {
	Name        string
	Description string
	Required    bool
}

// Result is the output of a tool execution.
type Result struct {
	Output   string         `json:"output"`
	Error    string         `json:"error,omitempty"`
	Success  bool           `json:"success"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Registry holds all registered tools.
type Registry struct {
	mu             sync.RWMutex
	tools          map[string]*Tool
	circuitBreaker *CircuitBreaker
	scanContextID  string // ID of the ScanContext this registry belongs to
	contentChecker func(snippet string) bool
	// schemaHidden withholds tool DOCUMENTATION from SchemaXML for role
	// scoping. Hidden tools stay registered and executable.
	schemaHidden map[string]bool
}

// NewRegistry creates a new tool registry.
func NewRegistry() *Registry {
	return &Registry{
		tools:          make(map[string]*Tool),
		circuitBreaker: NewCircuitBreaker(5, 60), // 5 failures, 60s recovery
	}
}

// SetContentChecker associates a function that checks whether a content snippet
// is present in the active conversation context.
func (r *Registry) SetContentChecker(fn func(snippet string) bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.contentChecker = fn
}

// HasActiveContent reports whether the given content snippet is present in the
// active conversation context. If no checker is registered, it returns false.
func (r *Registry) HasActiveContent(snippet string) bool {
	r.mu.RLock()
	fn := r.contentChecker
	r.mu.RUnlock()
	if fn == nil {
		return false
	}
	return fn(snippet)
}

// SetScanContextID associates this registry with a ScanContext.
// Tools can then use scanctx.Get(id) to access session-scoped state.
func (r *Registry) SetScanContextID(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanContextID = id
}

// GetScanContextID returns the associated ScanContext ID.
func (r *Registry) GetScanContextID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.scanContextID
}

// Register adds a tool to the registry.
func (r *Registry) Register(t *Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tools[t.Name] = t
}

// Get returns a tool by name.
func (r *Registry) Get(name string) (*Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tools[name]
	return t, ok
}

// RequiresParams reports whether the named tool declares any REQUIRED
// parameter. Used by the agent loop to decide whether an empty-Args tool call
// (a well-formed <function=NAME></function> body the parser matched but that
// yielded zero <parameter> children — observed when models drift and split a
// multi-param call's fields across separate calls) is a real invocation or a
// malformed fragment. For a tool with required params, an empty body can never
// be a valid call, so the caller drops it (letting orphan-recovery or the
// no-tool compaction path handle it) instead of wasting an iteration on a
// guaranteed "missing required parameter" registry error. A tool whose params
// are all optional (e.g. code_search) legitimately accepts an empty body, so
// this returns false and the call proceeds.
func (r *Registry) RequiresParams(name string) bool {
	t, ok := r.Get(name)
	if !ok {
		return false
	}
	for _, p := range t.Parameters {
		if p.Required {
			return true
		}
	}
	return false
}

// List returns all registered tool names.
func (r *Registry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.tools))
	for name := range r.tools {
		names = append(names, name)
	}
	return names
}

// MatchByParams returns the registered tool whose parameter names best match
// the supplied set, used to recover tool calls whose <function=NAME> open tag
// was dropped by the model (leaving orphaned <parameter=X> blocks + a trailing
// </function>). The match is schema-guided: a tool scores +1 for each of the
// given param names it declares, and the tool with the highest score wins,
// provided every REQUIRED parameter of that tool is present in the given set.
// Returns ("", false) when no tool's required params are all satisfied.
//
// This is deliberately conservative: it only ever resolves to a tool when the
// orphaned parameters are a complete-enough superset of that tool's required
// schema AND uniquely identify a single tool, so a genuinely ambiguous or
// partial fragment is left unresolved (caller treats it as no-tool) rather
// than executing the wrong tool. A tie between two or more tools at the best
// score is treated as ambiguous and resolves to nothing — executing a
// randomly-chosen winner (e.g. browser_action vs terminal_execute when both
// share a single required "command" param) has caused whole-scan force-stops
// in production (codeant.ai), because the wrong tool then fails on every call.
func (r *Registry) MatchByParams(paramNames []string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if len(paramNames) == 0 {
		return "", false
	}
	got := make(map[string]bool, len(paramNames))
	for _, p := range paramNames {
		got[strings.ToLower(strings.TrimSpace(p))] = true
	}
	bestName := ""
	bestScore := 0
	tie := false
	for _, t := range r.tools {
		score := 0
		allRequired := true
		for _, p := range t.Parameters {
			pn := strings.ToLower(strings.TrimSpace(p.Name))
			if got[pn] {
				score++
			} else if p.Required {
				allRequired = false
			}
		}
		// Only candidate tools whose required params are all present, and
		// that actually matched at least one param. Prefer the tighter match
		// (higher score / fewer unmatched given params) to disambiguate tools
		// that share a parameter name. If two eligible tools score equally,
		// mark it a tie — the parameter set does not uniquely identify the
		// tool, so resolving to either one would be a guess.
		if !allRequired || score == 0 {
			continue
		}
		switch {
		case score > bestScore:
			bestScore = score
			bestName = t.Name
			tie = false
		case score == bestScore:
			tie = true
		}
	}
	if bestName == "" || bestScore == 0 || tie {
		return "", false
	}
	return bestName, true
}

// Execute runs a tool by name with the given arguments.
// Note: the caller's args map is never mutated — Execute works on a copy.
func (r *Registry) Execute(name string, args map[string]string) (Result, error) {
	// Check circuit breaker
	if r.circuitBreaker.IsOpen(name) {
		recoveryTime := r.circuitBreaker.GetRecoveryTime(name)
		return Result{
			Error:   fmt.Sprintf("Circuit breaker OPEN for '%s' — too many failures. Try again in %d seconds.", name, recoveryTime),
			Success: false,
		}, nil
	}

	tool, ok := r.Get(name)
	if !ok {
		return Result{}, fmt.Errorf("unknown tool: %s", name)
	}

	// Defensive copy — agents/loggers may retain a reference to the original
	// args map and we don't want to surface or hide _raw / required-param
	// substitutions back to them.
	localArgs := make(map[string]string, len(args)+1)
	for k, v := range args {
		localArgs[k] = v
	}

	// Map _raw fallback to first required parameter if needed
	if raw, hasRaw := localArgs["_raw"]; hasRaw {
		for _, p := range tool.Parameters {
			if p.Required {
				if _, exists := localArgs[p.Name]; !exists {
					localArgs[p.Name] = raw
				}
			}
		}
		delete(localArgs, "_raw")
	}

	// Validate required parameters. Collect ALL missing ones and report them in
	// a single error, rather than failing on the first — otherwise a tool with
	// several required params (e.g. report_vulnerability) makes the agent
	// resubmit once per missing field, burning iterations on a thrash loop.
	var missing []string
	for _, p := range tool.Parameters {
		if p.Required {
			if v, exists := localArgs[p.Name]; !exists || strings.TrimSpace(v) == "" {
				missing = append(missing, p.Name)
			}
		}
	}
	if len(missing) > 0 {
		if name == "report_vulnerability" {
			return Result{}, fmt.Errorf(
				"missing required parameter for tool '%s': %s — 'title' is the only hard-required field; include it (with severity + description + exploitation_proof for a complete report) inside a single <function=report_vulnerability>...</function> block. severity/description are salvaged if omitted, but proof is still enforced by the reporting policy for actionable severities",
				name, strings.Join(missing, ", "),
			)
		}
		if len(missing) == 1 {
			return Result{}, fmt.Errorf("missing required parameter '%s' for tool '%s' — you MUST include <parameter=%s>value</parameter> inside <function=%s>...</function>", missing[0], name, missing[0], name)
		}
		return Result{}, fmt.Errorf(
			"missing required parameters for tool '%s': %s — provide ALL of them in a single call (one <parameter=NAME>…</parameter> per field)",
			name, strings.Join(missing, ", "),
		)
	}

	result, err := tool.Execute(localArgs)
	if err != nil {
		// Record failure in circuit breaker
		r.circuitBreaker.RecordFailure(name)
		return Result{
			Output:  "",
			Error:   err.Error(),
			Success: false,
		}, nil
	}

	// Record success - reset failure count
	r.circuitBreaker.RecordSuccess(name)
	result.Success = true
	return result, nil
}

// GetCircuitBreaker returns the circuit breaker for external access
func (r *Registry) GetCircuitBreaker() *CircuitBreaker {
	return r.circuitBreaker
}

// SchemaXML generates XML schema for all tools (for the system prompt).
// Tool/parameter names and descriptions are XML-escaped so user-supplied
// content (e.g. skill names loaded from disk) cannot break the prompt.
func (r *Registry) SchemaXML() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := "<tools>\n"
	// Sorted tool order: map iteration is randomized per call, which made the
	// schema section of the system prompt a different byte layout on every
	// build (hurting provider prefix-cache stability and reproducibility).
	// Content is unchanged — only the order becomes canonical.
	sortedTools := make([]*Tool, 0, len(r.tools))
	for _, t := range r.tools {
		sortedTools = append(sortedTools, t)
	}
	sort.Slice(sortedTools, func(i, j int) bool { return sortedTools[i].Name < sortedTools[j].Name })
	var hidden []string
	for _, t := range sortedTools {
		if r.schemaHidden[t.Name] {
			hidden = append(hidden, t.Name)
			continue
		}
		out += fmt.Sprintf("  <tool name=\"%s\">\n", attrEscape(t.Name))
		out += fmt.Sprintf("    <description>%s</description>\n", textEscape(t.Description))
		if len(t.Parameters) > 0 {
			out += "    <parameters>\n"
			for _, p := range t.Parameters {
				req := ""
				if p.Required {
					req = " required=\"true\""
				}
				out += fmt.Sprintf("      <parameter name=\"%s\"%s>%s</parameter>\n",
					attrEscape(p.Name), req, textEscape(p.Description))
			}
			out += "    </parameters>\n"
		}
		out += "  </tool>\n"
	}
	// Role-scoped schema: tools hidden from the prompt stay REGISTERED and
	// callable — only their documentation is withheld. The one-line index
	// keeps the model aware they exist (no phantom gaps), so the reachable
	// tool set is unchanged; the coordinator retains full documentation.
	if len(hidden) > 0 {
		out += fmt.Sprintf("  <hidden_tools>%s</hidden_tools>\n", strings.Join(hidden, ", "))
		out += "  <note>hidden_tools exist and remain callable but are outside your delegated lane; your coordinator retains them. If your assigned lane genuinely requires one, say so in your lane results instead of improvising.</note>\n"
	}
	out += "</tools>\n"
	return out
}

// SetSchemaHidden withholds the given tool names from SchemaXML output while
// keeping them fully registered and executable. nil/empty clears the scope.
func (r *Registry) SetSchemaHidden(names []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(names) == 0 {
		r.schemaHidden = nil
		return
	}
	r.schemaHidden = make(map[string]bool, len(names))
	for _, n := range names {
		r.schemaHidden[n] = true
	}
}

// SchemaHiddenNames returns the tools currently withheld from the schema.
func (r *Registry) SchemaHiddenNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.schemaHidden))
	for n := range r.schemaHidden {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// textEscape escapes characters that are unsafe in XML text nodes.
func textEscape(s string) string {
	var buf bytes.Buffer
	if err := xml.EscapeText(&buf, []byte(s)); err != nil {
		// EscapeText only fails on the io.Writer; we use bytes.Buffer.
		return s
	}
	return buf.String()
}

// attrEscape escapes characters that are unsafe in XML attribute values.
func attrEscape(s string) string {
	// xml.EscapeText handles attribute-safe escaping for &, <, >, " and '.
	return textEscape(s)
}
