// Package llm provides LLM client and tool call parsing.
package llm

import (
	"html"
	"regexp"
	"strings"
	"unicode"
)

// ToolCall represents a parsed tool invocation from LLM output.
type ToolCall struct {
	Name string            `json:"name"`
	Args map[string]string `json:"args"`
}

var (
	// Function matching — dotall for multi-line bodies
	fnRegex = regexp.MustCompile(`(?s)<function=([^>]+)>\n?(.*?)</function>`)

	// All parameter formats we need to handle — ALL dotall for multi-line values:
	// 1. Standard: <parameter=name>value</parameter>
	paramEqRegex = regexp.MustCompile(`(?s)<parameter=([^>]+)>(.*?)</parameter>`)
	// 2. Space variant: <parameter name>value</parameter>  (MiniMax)
	paramSpRegex = regexp.MustCompile(`(?s)<parameter\s+([^=>]+)>(.*?)</parameter>`)
	// 3. name= attr: <parameter name="X">value</parameter>
	paramAttrRegex = regexp.MustCompile(`(?s)<parameter\s+name=["']([^"']+)["']>(.*?)</parameter>`)

	// Alternate top-level format: <invoke name="X">...</invoke>
	invokeOpen   = regexp.MustCompile(`<invoke\s+name=["']([^"']+)["']>`)
	funcCallsTag = regexp.MustCompile(`</?function_calls>`)

	// Recover malformed tool-call OPEN tags. Some models intermittently mangle
	// the opening tag while still emitting a well-formed body and "</function>".
	// Observed variants (all counted as "no tool call" by the strict fnRegex):
	//     function=terminal_execute><parameter=command>id</parameter></function>   (no leading "<")
	//     =send_request><parameter=method>GET</parameter></function>               (no "<function")
	//     function=terminal_execute"><parameter=command>id</parameter></function>  (stray quote before ">")
	//     <function="terminal_execute"><parameter=...>                             (quoted name)
	// 15 such responses in a row force-stop the whole scan (observed in
	// production against bitbank.cc). This repair rebuilds the canonical
	// "<function=name>" form, tolerating an optional leading "<"/"<function",
	// optional surrounding quotes, and stray quotes/whitespace before the ">".
	// The leading "(^|[^\w/<])" boundary prevents the name from also matching
	// inside a CLOSING tag ("</parameter>" has no "=", but the name "parameter"
	// plus its ">" must never be mistaken for an open tag); it is captured so it
	// can be re-emitted in the replacement. Requiring a "<parameter" or
	// "</function>" immediately after the name makes this a specific,
	// low-false-positive signal (ordinary prose never has "=word><parameter"),
	// and correct "<function=name>" tags rewrite to the identical form, so it is
	// idempotent.
	repairFnOpenRe = regexp.MustCompile(`(?s)(^|[^\w/<])<?(?:function\s*)?=\s*["']?([A-Za-z_][A-Za-z0-9_-]*)["'\s]*>(\s*(?:<parameter|</function>))`)

	// Second repair for the codeant.ai shape: the model dropped the ENTIRE
	// "<function=" prefix, leaving only the bare tool name + a STRAY QUOTE before
	// the ">", then a well-formed body. E.g.
	//     terminal_execute"><parameter=command>python3...</parameter></function>
	// This is distinct from a truncation like "_plan>" (suffix of "<update_plan>")
	// because the stray quote (a leftover from "<function=\"name\">" or
	// "function=name\">") is a near-zero-false-positive signal that ordinary
	// prose never produces. Truncations carry NO quote, so they correctly stay
	// on the orphaned-call path where MatchByParams resolves them via their
	// parameter set (e.g. {task_id,status,notes} → update_plan).
	repairBareNameQuotedRe = regexp.MustCompile(`(?s)(^|[^\w/<])([A-Za-z_][A-Za-z0-9_-]*)["']\s*>(\s*(?:<parameter|</function>))`)

	// Normalize quotes around = in tags: <function = "name"> → <function=name>
	stripQuotesRe = regexp.MustCompile(`<(function|parameter)\s*=\s*["']?([^>"']+?)["']?\s*>`)

	// MiniMax occasionally emits a parameter name as a nested/garbled open
	// tag, for example `<parameter<parameter>command</parameter>` or
	// `<parameter<poc_description</parameter>`. These fragments otherwise make
	// the whole assistant turn look like prose, causing the no-tool recovery
	// loop. The repair is deliberately limited to identifier-shaped names.
	malformedNestedParamRe = regexp.MustCompile(`(?s)<parameter<parameter>\s*([A-Za-z_][A-Za-z0-9_-]*)\s*</parameter>`)
	malformedBareParamRe   = regexp.MustCompile(`(?s)<parameter<([A-Za-z_][A-Za-z0-9_-]*)\s*</parameter>`)
	malformedBodyParamRe   = regexp.MustCompile(`(?s)(<parameter=[A-Za-z_][A-Za-z0-9_-]*>)\s*<parameter>`)
	// Some providers close a parameter with its field name instead of the XML
	// wrapper name, for example <parameter=title>...</title>. Without repair,
	// paramEqRegex keeps consuming through the next </parameter>, merging fields
	// such as target/severity into the title. The names are compared in code
	// because Go's regexp engine intentionally does not support backreferences.
	malformedNamedParamCloseRe = regexp.MustCompile(`(?s)<parameter=([A-Za-z_][A-Za-z0-9_-]*)>(.*?)</([A-Za-z_][A-Za-z0-9_-]*)>`)

	// CleanContent regexes — compiled once
	toolPattern    = regexp.MustCompile(`(?s)<function=[^>]+>.*?</function>`)
	incompleteFunc = regexp.MustCompile(`(?s)<function=[^>]+>.*$`)
	interAgentRe   = regexp.MustCompile(`(?is)<inter_agent_message>.*?</inter_agent_message>`)
	agentReportRe  = regexp.MustCompile(`(?is)<agent_completion_report>.*?</agent_completion_report>`)
	multiBlankRe   = regexp.MustCompile(`\n\s*\n`)

	// Strategy 2 lenient param matching (fallback)
	lenientParamRe = regexp.MustCompile(`(?s)<parameter[^>]*?(\w+)\s*>(.*?)</parameter>`)
	// Split identifier on punctuation/whitespace
	identSplitRe = regexp.MustCompile(`[.\s,;:!?]+`)

	// nameHintRe captures a bare tool name emitted right before an orphaned
	// parameter run, i.e. the model dropped the "<function=" prefix but kept the
	// name: `terminal_execute>\n<parameter=command>…`. We match the trailing
	// `identifier>` at the end of the text preceding the first <parameter block.
	// The captured name is only a HINT — the caller validates it against the
	// registered tools before using it — so a false capture (e.g. the tail of a
	// closing tag) is harmless. This rescues the common case that MatchByParams
	// cannot: a call carrying only {command}, which ties across terminal_execute
	// / browser_action / pageagent and is therefore rejected as ambiguous.
	nameHintRe = regexp.MustCompile(`(?s)([A-Za-z_][A-Za-z0-9_-]*)\s*>\s*$`)
)

// ParseToolCalls extracts tool calls from LLM XML output.
func ParseToolCalls(content string) []ToolCall {
	content = normalizeFormat(content)
	content = fixIncomplete(content)

	var calls []ToolCall

	for _, match := range fnRegex.FindAllStringSubmatch(content, -1) {
		fnName := sanitizeParamName(strings.TrimSpace(match[1]))
		if fnName == "" {
			continue
		}

		body := match[2]
		args := extractParams(body)

		calls = append(calls, ToolCall{Name: fnName, Args: args})
	}

	return calls
}

// extractParams tries all known parameter formats to extract key-value pairs.
// Falls back to progressively more lenient parsing strategies.
func extractParams(body string) map[string]string {
	args := make(map[string]string)

	// Strategy 1: Try exact formats in priority order
	regexes := []*regexp.Regexp{paramEqRegex, paramAttrRegex, paramSpRegex}

	for _, re := range regexes {
		matches := re.FindAllStringSubmatch(body, -1)
		if len(matches) > 0 {
			for _, pm := range matches {
				pName := sanitizeParamName(pm[1])
				if pName == "" {
					continue
				}
				args[pName] = html.UnescapeString(strings.TrimSpace(pm[2]))
			}
			if len(args) > 0 {
				return args
			}
		}
	}

	// Strategy 2: Ultra-lenient — match anything that looks like <parameter...>...</parameter>
	// Catches: <parameter = command>, <parameter  command >, etc.
	for _, pm := range lenientParamRe.FindAllStringSubmatch(body, -1) {
		pName := sanitizeParamName(pm[1])
		if pName != "" {
			args[pName] = html.UnescapeString(strings.TrimSpace(pm[2]))
		}
	}
	if len(args) > 0 {
		return args
	}

	// Strategy 3: No parameter tags at all — treat raw body as single value.
	// Use the first word-like chunk after "=" or the trimmed body.
	trimmed := strings.TrimSpace(body)
	if trimmed != "" && !strings.Contains(trimmed, "<") {
		// Single unnamed param — callers (registry) can map it to the first required param
		args["_raw"] = trimmed
	}

	return args
}

// sanitizeParamName extracts a valid identifier from a potentially garbled name.
func sanitizeParamName(raw string) string {
	raw = strings.TrimSpace(raw)
	if isIdentifier(raw) {
		return raw
	}

	parts := identSplitRe.Split(raw, -1)
	for i := len(parts) - 1; i >= 0; i-- {
		p := strings.TrimSpace(parts[i])
		if isIdentifier(p) {
			return p
		}
	}
	return ""
}

func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if i == 0 && !unicode.IsLetter(r) && r != '_' {
			return false
		}
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	return true
}

// normalizeFormat converts alternative XML formats to the expected one.
func normalizeFormat(content string) string {
	// Handle <invoke name="X"> ... </invoke> format
	if strings.Contains(content, "<invoke") || strings.Contains(content, "<function_calls") {
		content = funcCallsTag.ReplaceAllString(content, "")
		content = invokeOpen.ReplaceAllString(content, "<function=$1>")
		content = strings.ReplaceAll(content, "</invoke>", "</function>")
	}

	// Repair malformed function-open tags (missing leading "<" / "<function").
	// ${1} is the leading boundary char (re-emitted so we don't eat punctuation).
	content = repairFnOpenRe.ReplaceAllString(content, "${1}<function=${2}>${3}")
	// Repair bare-name+quote drops (codeant.ai shape). Same ${1} boundary trick.
	content = repairBareNameQuotedRe.ReplaceAllString(content, "${1}<function=${2}>${3}")
	content = malformedNestedParamRe.ReplaceAllString(content, "<parameter=${1}>")
	content = malformedBareParamRe.ReplaceAllString(content, "<parameter=${1}>")
	content = malformedBodyParamRe.ReplaceAllString(content, "${1}")

	// Normalize quotes/spaces around = signs: <function = "name"> → <function=name>
	content = stripQuotesRe.ReplaceAllStringFunc(content, func(s string) string {
		m := stripQuotesRe.FindStringSubmatch(s)
		if len(m) < 3 {
			return s
		}
		val := strings.TrimSpace(m[2])
		return "<" + m[1] + "=" + val + ">"
	})
	content = malformedNamedParamCloseRe.ReplaceAllStringFunc(content, func(s string) string {
		m := malformedNamedParamCloseRe.FindStringSubmatch(s)
		if len(m) != 4 || !strings.EqualFold(m[1], m[3]) {
			return s
		}
		return "<parameter=" + m[1] + ">" + m[2] + "</parameter>"
	})

	return content
}

// fixIncomplete adds a missing closing tag to the last unclosed tool-call
// block in content. Earlier blocks are matched normally by the regex; only
// the trailing one (the most common LLM truncation) is repaired here.
func fixIncomplete(content string) string {
	countOpen := strings.Count(content, "<function=") + strings.Count(content, "<invoke ")
	countClose := strings.Count(content, "</function>") + strings.Count(content, "</invoke>")

	if countOpen <= countClose {
		return content
	}

	// At least one open tag has no matching close.
	content = strings.TrimRight(content, " \t\n\r")

	// Truncated CLOSING tag ("...</") — the body already exists, just finish
	// the close so the well-formed pair parses.
	if strings.HasSuffix(content, "</") {
		return content + "function>"
	}

	// A trailing OPEN tag is unclosed. Decide whether to RECOVER it (it carries
	// a partial body worth parsing) or DROP it (it is a bare, param-less open).
	// Completing a param-less open would fabricate an empty, argument-less call
	// (e.g. `<function=terminal_execute></function>`) that fails with
	// "missing required parameter" and, when the model repeats the truncation,
	// trips the repeated-call guard and burns iterations. We inspect the tail
	// from the last "<function=" open: if it has no matching close AND no
	// <parameter, it is truncation noise — strip it. Otherwise close it so the
	// partial params are recovered.
	if lastOpen := strings.LastIndex(content, "<function="); lastOpen >= 0 {
		tail := content[lastOpen:]
		if !strings.Contains(tail, "</function>") && !strings.Contains(tail, "<parameter") {
			return strings.TrimRight(content[:lastOpen], " \t\n\r")
		}
	}

	// Append a single closing tag — even if multiple tags are unclosed, the
	// regex is non-greedy and will pick up the well-formed pairs first.
	return content + "\n</function>"
}

// FormatToolCall formats a tool call back into XML for display.
func FormatToolCall(name string, args map[string]string) string {
	var b strings.Builder
	b.WriteString("<function=")
	b.WriteString(name)
	b.WriteString(">\n")
	for k, v := range args {
		b.WriteString("<parameter=")
		b.WriteString(k)
		b.WriteString(">")
		b.WriteString(v)
		b.WriteString("</parameter>\n")
	}
	b.WriteString("</function>")
	return b.String()
}

// OrphanedCall is a block of <parameter=...> values closed by </function> but
// with no preceding <function=NAME> open tag — the model dropped the open tag.
// Recoverable when the caller matches the param set against the tool schema.
type OrphanedCall struct {
	Args       map[string]string
	ParamNames []string // ordered, dedup'd param names present
	// NameHint is the bare tool name the model emitted immediately before the
	// parameter run when it dropped only the "<function=" prefix (e.g.
	// "terminal_execute" from `terminal_execute>\n<parameter=command>…`). Empty
	// when no such token precedes the params. The caller MUST validate it
	// against the registered tools before trusting it.
	NameHint string
}

// ParseOrphanedCalls extracts <parameter=X>...</parameter> blocks that are
// bounded by a </function> close tag but have NO <function=NAME> open tag
// before them. These are the calls the strict fnRegex misses because the model
// truncated/dropped the opening tag (observed: `_plan>\n<parameter=task_id>…`
// and `parameter=method>POST</parameter>…</function>`).
//
// It works by:
//  1. Removing all WELL-FORMED <function=…>…</function> blocks (already parsed
//     by ParseToolCalls) so only malformed fragments remain.
//  2. Finding </function> close tags and walking back to collect the contiguous
//     run of <parameter=…>…</parameter> blocks immediately preceding each close.
//
// Returns one OrphanedCall per close tag that has ≥1 parameter. The caller
// resolves the tool name via registry.MatchByParams; if it can't, the call is
// dropped (safer than executing an ambiguous guess).
func ParseOrphanedCalls(content string) []OrphanedCall {
	content = normalizeFormat(content)
	// Strip well-formed calls so their params aren't mistaken for orphans.
	stripped := fnRegex.ReplaceAllString(content, "")
	// Also drop any lone incomplete <function=…> opens that survived (no body).
	stripped = incompleteFunc.ReplaceAllString(stripped, "")

	var out []OrphanedCall
	// Split on </function>; each segment that ends at a close tag may carry
	// orphaned <parameter> blocks in its tail.
	for _, frag := range strings.Split(stripped, "</function>") {
		// Collect the trailing run of <parameter=…>…</parameter> in this fragment.
		params := paramEqRegex.FindAllStringSubmatch(frag, -1)
		if len(params) == 0 {
			continue
		}
		// Capture the bare tool name emitted right before the first parameter
		// block, if any (the model dropped only "<function="): e.g.
		// `terminal_execute>\n<parameter=command>…`. Validated by the caller.
		nameHint := ""
		if firstParam := strings.Index(frag, "<parameter"); firstParam > 0 {
			if m := nameHintRe.FindStringSubmatch(frag[:firstParam]); m != nil {
				nameHint = sanitizeParamName(m[1])
			}
		}
		args := make(map[string]string, len(params))
		var names []string
		seen := make(map[string]bool)
		for _, pm := range params {
			name := sanitizeParamName(strings.TrimSpace(pm[1]))
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			names = append(names, name)
			args[name] = html.UnescapeString(strings.TrimSpace(pm[2]))
		}
		if len(args) > 0 {
			out = append(out, OrphanedCall{Args: args, ParamNames: names, NameHint: nameHint})
		}
	}
	return out
}

var (
	// Residue left after CleanContent when the model MALFORMED a tool call:
	// orphaned `<parameter=…>…</parameter>` blocks (open tag dropped), stray
	// `<function…>`/`</function>` tags, and a lone `name>` line (the bare tool
	// name from a dropped-open-tag call). CleanContent only strips well-formed
	// `<function=…>…</function>` pairs, so these survive into the prose.
	orphanParamResidueRe = regexp.MustCompile(`(?s)<parameter\b[^>]*>.*?</parameter>`)
	strayFuncTagRe       = regexp.MustCompile(`</?function[^>]*>`)
	danglingNameLineRe   = regexp.MustCompile(`(?m)^\s*[A-Za-z_][A-Za-z0-9_-]*>\s*$`)
)

// StripToolResidue removes tool-call XML — well-formed OR malformed — from
// prose so a rebuilt (canonical) assistant turn carries no leftover markup.
// Used when persisting a turn whose tool calls were parsed/recovered, so the
// model never sees its own malformed tool-call fragments and mimic them.
func StripToolResidue(content string) string {
	content = toolPattern.ReplaceAllString(content, "")
	content = orphanParamResidueRe.ReplaceAllString(content, "")
	content = strayFuncTagRe.ReplaceAllString(content, "")
	content = danglingNameLineRe.ReplaceAllString(content, "")
	content = multiBlankRe.ReplaceAllString(content, "\n\n")
	return strings.TrimSpace(content)
}

// CleanContent removes tool call XML from content for display.
func CleanContent(content string) string {
	content = normalizeFormat(content)
	content = fixIncomplete(content)

	cleaned := toolPattern.ReplaceAllString(content, "")
	cleaned = incompleteFunc.ReplaceAllString(cleaned, "")
	cleaned = interAgentRe.ReplaceAllString(cleaned, "")
	cleaned = agentReportRe.ReplaceAllString(cleaned, "")
	cleaned = multiBlankRe.ReplaceAllString(cleaned, "\n\n")

	return strings.TrimSpace(cleaned)
}
