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

	// ID identifies the call when it arrived through the native (OpenAI-style)
	// channel: the role:"tool" result that follows must reference it. Empty for
	// calls parsed out of the XML dialect.
	ID string `json:"id,omitempty"`

	// RawArguments preserves the exact `arguments` JSON the server returned, so
	// the assistant turn can be replayed byte-for-byte in the history.
	RawArguments string `json:"-"`

	// ArgumentError records a malformed `arguments` payload. The call is kept
	// rather than dropped, so the agent can return a corrective tool result
	// instead of losing the turn.
	ArgumentError string `json:"-"`
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

	// Alternate top-level format: <invoke name="X">...</invoke>, plus the
	// quote-dropped and half-quoted variants some providers emit while the body
	// stays well-formed and closes with </function>:
	//     <invoke name=terminal_execute>      (no quotes)
	//     <invoke name="claim_next_hypothesis> (opening quote, no closing)
	// The strict both-quotes form matched none of these, so they parsed as
	// "no tool call" and drove the malformed-recovery ladder. Optional quotes on
	// each side, with an identifier-only name, normalize all of them to
	// <function=X> (and keep ordinary prose from matching).
	invokeOpen = regexp.MustCompile(`<invoke\s+name=["']?([A-Za-z_][A-Za-z0-9_-]*)["']?\s*>`)
	// invokeEqOpenRe recovers the equals-style invoke open tag "<invoke=NAME>"
	// (some models emit the Claude <invoke …> vocabulary but with "=" instead of
	// name="…"), e.g. <invoke=read_ledger>. invokeOpen above only handles the
	// name="…" form, so the "=" form was left unparseable and the whole call —
	// a real probe or ledger op — was discarded as malformed_tool_xml.
	invokeEqOpenRe = regexp.MustCompile(`<invoke\s*=\s*["']?([A-Za-z_][A-Za-z0-9_-]*)["']?\s*>`)
	// slashFnOpenRe recovers a function OPEN tag mangled with a LEADING SLASH,
	// e.g. </function=terminal_execute> where <function=terminal_execute> belongs
	// (observed: a real command probe discarded this way). The "=NAME" after
	// "</function" is what distinguishes it from the legitimate close tag
	// "</function>" (which has no "="), so this never rewrites a real close.
	slashFnOpenRe = regexp.MustCompile(`</function\s*=\s*["']?([A-Za-z_][A-Za-z0-9_-]*)["']?\s*>`)
	funcCallsTag  = regexp.MustCompile(`</?function_calls>`)

	// Some models (observed through a model-routing aggregator) emit their
	// native "DSML" tool-call markup as plain text:
	//     <｜DSML｜function_calls>
	//     <｜DSML｜invoke name="terminal_execute">
	//     <｜DSML｜parameter name="command" string="true">id</｜DSML｜parameter>
	//     </｜DSML｜invoke>
	//     </｜DSML｜function_calls>
	// The body is the invoke/parameter vocabulary we already parse, only with a
	// "｜DSML｜" namespace marker (fullwidth or ASCII bars) inside every tag and
	// a string="true|false" type hint on parameters. Unrecognized, every turn
	// counted as "no tool call" until the scan was force-stopped. Stripping the
	// marker and the type hint reduces it to the supported <invoke> form.
	dsmlTagRe        = regexp.MustCompile(`<(/?)\s*[|｜]\s*DSML\s*[|｜]\s*`)
	dsmlStringAttrRe = regexp.MustCompile(`(<parameter\s+name=["'][^"']+["'])\s+string=["'](?:true|false)["']\s*>`)

	// Space-attribute function form: <function name="X">...</function>. The
	// body is well-formed but fnRegex requires "<function=", so these turns
	// were previously classified as unparsable "unparsed_tool_call" output
	// and pushed scans into the malformed-recovery ladder. Normalizing the
	// open tag executes the call normally instead.
	funcNameAttrRe = regexp.MustCompile(`(?s)<function\s+name=["']([^"']+)["']\s*>`)
	// Tool-call variant family: <tool_call name="X">...`, often
	// batched inside a bare <tool_calls> wrapper. Same story: a real,
	// well-formed body in the wrong vocabulary. Named opens rewrite to
	// <function=X>; the singular close rewrites to </function>; the bare
	// plural wrapper (a batch delimiter, not a call) is stripped LAST so a
	// singular close is never mistaken for its own wrapper. A bare unnamed
	// `tool call marker carries no recoverable name and deliberately stays
	// on the malformed path.
	toolCallOpenRe = regexp.MustCompile(`(?s)<tool_calls?\s+name=["']([^"']+)["']\s*>`)
	toolCallsTagRe = regexp.MustCompile(`(?is)</?tool_calls>`)

	// Some providers intermittently substitute ">" for "=" in the function-open
	// tag, emitting `<function>NAME>` instead of `<function=NAME>` while the
	// parameter body stays well-formed. Observed shapes:
	//     <function>scan_source_sinks>\n<parameter=max_per_class>20</parameter>\n</function>
	//     <function>check_agent>\n<parameter=agent_id>sub_1_…</parameter>\n</function>
	// Every other open-tag repair requires an "=", so these fell through to
	// "no tool call" and were classified malformed_tool_xml, adding a recovery
	// round-trip per occurrence. Requiring an identifier then ">" then a
	// "<parameter" or "</function>" makes this a specific, idempotent signal
	// (ordinary prose never has "<function>word><parameter"); a correct
	// "<function=name>" has "=" after "<function" and never matches. Only the
	// function open is repaired — a parameter value legitimately contains ">"
	// (e.g. a shell redirect), so the same ">"-for-"=" rewrite is unsafe there.
	funcGtOpenRe = regexp.MustCompile(`(?s)<function>\s*([A-Za-z_][A-Za-z0-9_-]*)\s*>(\s*(?:<parameter|</function>))`)

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
	// misTaggedFnOpenRe catches the model writing <parameter=NAME> where
	// <function=NAME> belongs. some models confuse the two (both use the
	// <tag=value> syntax), emitting the function OPEN as a parameter tag, e.g.
	//     <parameter=update_hypothesis>
	//     <parameter=hypothesis_id>H-97</parameter>
	//     <parameter=status>rejected</parameter>
	// The whole call is then unparseable (no <function=…>) and classified
	// malformed_tool_xml, which discards the turn and re-sends the ENTIRE context
	// to retry — a dominant source of wasted tokens in production. Signature: a
	// parameter-open IMMEDIATELY followed by another parameter-open (only
	// whitespace between), which a legitimate parameter — always carrying a value
	// and </parameter> — can never produce. Applied (in normalizeFormat) only when
	// the turn has no well-formed <function=…>…</function> block, so a parameter
	// value that itself contains markup is never rewritten.
	misTaggedFnOpenRe = regexp.MustCompile(`<parameter=([A-Za-z_][A-Za-z0-9_-]*)>(\s*<parameter[=\s])`)
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

	// Provider/tool-protocol residue that cannot be executed by the XML tool
	// parser. MiniMax has been observed leaking its internal channel delimiter
	// (`<]minimax[>`) and sometimes emitting a bare `<tool_call>` marker with no
	// function name or arguments. Treating those turns as ordinary prose caused
	// the agent to make dozens of identical paid requests before falsely
	// reporting a clean completion. These expressions are intentionally narrow:
	// ordinary prose mentioning "tool call" is not classified as malformed.
	providerControlTokenRe = regexp.MustCompile(`(?i)<\]\s*minimax\s*\[>`)
	// Redaction counterpart of providerControlTokenRe for DISPLAY and HISTORY
	// surfaces: strips any provider's internal channel delimiters (identifier
	// wrapped in `<]`…`[>`, with optionally abutting flanking brackets) from
	// model-emitted prose. The classification regex above stays deliberately
	// narrow; this one is generic so emitted text can never carry a provider's
	// internal control tokens into UIs, reports, or persisted history.
	providerControlStripRe = regexp.MustCompile(`(?i)\]?<\]\s*[A-Za-z0-9_.-]+\s*\[>\[?`)
	bareToolCallTagRe      = regexp.MustCompile(`(?is)</?tool_calls?\b[^>]*>`)
	toolXMLResidueRe       = regexp.MustCompile(`(?is)</?function(?:\s*=|\b)|<parameter(?:\s*=|\s+)|</parameter>`)
)

// MalformedToolOutputReason returns a stable machine-readable reason when a
// model response visibly attempted to use a tool protocol but did not contain
// a parseable call. Callers should invoke this only after ParseToolCalls and
// ParseOrphanedCalls have both failed, so recoverable malformed XML is still
// executed normally. An empty result means the response is ordinary prose.
func MalformedToolOutputReason(content string) string {
	if providerControlTokenRe.MatchString(content) {
		return "provider_control_token_leak"
	}
	if bareToolCallTagRe.MatchString(content) {
		return "unparsed_tool_call"
	}
	if toolXMLResidueRe.MatchString(content) {
		return "malformed_tool_xml"
	}
	return ""
}

// StripProviderControlTokens redacts internal provider control delimiters
// (see providerControlStripRe) from model-emitted text. Applied to every event
// surface and to display/history copies of model prose so provider protocol
// residue never reaches clients or gets persisted. Cheap Contains gate first:
// most event text never contains the artifact and skips the regex entirely.
func StripProviderControlTokens(content string) string {
	if !strings.Contains(content, "<]") {
		return content
	}
	return providerControlStripRe.ReplaceAllString(content, "")
}

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
	// Strip provider internal channel delimiters (e.g. MiniMax's `<]minimax[>`)
	// before any tool-call parsing. They are protocol noise, never part of a
	// call; left in place they break the XML parse, so a call wrapped in or
	// abutting a control token is misread as "no tool call" and then classified
	// as provider_control_token_leak — driving the malformed-recovery ladder
	// (hard context reset at 5) even though the model did emit a real call.
	if strings.Contains(content, "<]") {
		content = providerControlStripRe.ReplaceAllString(content, "")
	}

	// Reduce DSML-namespaced tags to the plain invoke/parameter vocabulary.
	if strings.Contains(content, "DSML") {
		content = dsmlTagRe.ReplaceAllString(content, "<${1}")
		content = dsmlStringAttrRe.ReplaceAllString(content, "${1}>")
	}

	// Handle <invoke name="X"> ... </invoke> format
	if strings.Contains(content, "<invoke") || strings.Contains(content, "<function_calls") {
		content = funcCallsTag.ReplaceAllString(content, "")
		content = invokeOpen.ReplaceAllString(content, "<function=$1>")
		content = invokeEqOpenRe.ReplaceAllString(content, "<function=$1>")
		content = strings.ReplaceAll(content, "</invoke>", "</function>")
	}

	// Space-attribute and tool_call vocabularies, before the generic repairs
	// (which all require "=" and would not fire on these shapes).
	content = funcNameAttrRe.ReplaceAllString(content, "<function=${1}>")
	content = toolCallOpenRe.ReplaceAllString(content, "<function=${1}>")
	// Repair the ">"-for-"=" function-open substitution (<function>NAME> →
	// <function=NAME>) before the generic repairs, which all require an "=".
	content = funcGtOpenRe.ReplaceAllString(content, "<function=${1}>${2}")
	// Recover a function OPEN mangled with a leading slash: </function=NAME> →
	// <function=NAME>. Safe because the legitimate close "</function>" carries no
	// "=NAME", so only the mis-tagged open is rewritten.
	content = slashFnOpenRe.ReplaceAllString(content, "<function=${1}>")
	content = strings.ReplaceAll(content, "</tool_call>", "</function>")
	content = toolCallsTagRe.ReplaceAllString(content, "")

	// Repair malformed function-open tags (missing leading "<" / "<function").
	// ${1} is the leading boundary char (re-emitted so we don't eat punctuation).
	content = repairFnOpenRe.ReplaceAllString(content, "${1}<function=${2}>${3}")
	// Repair bare-name+quote drops (codeant.ai shape). Same ${1} boundary trick.
	content = repairBareNameQuotedRe.ReplaceAllString(content, "${1}<function=${2}>${3}")
	content = malformedNestedParamRe.ReplaceAllString(content, "<parameter=${1}>")
	content = malformedBareParamRe.ReplaceAllString(content, "<parameter=${1}>")
	content = malformedBodyParamRe.ReplaceAllString(content, "${1}")

	// Recover a function OPEN mis-tagged as a parameter (<parameter=NAME> for
	// <function=NAME>). Guarded to turns with no well-formed call so legitimate
	// parameter values are never rewritten; fixIncomplete then supplies the
	// missing </function>, and the call parses normally instead of being
	// discarded + retried with a full context resend.
	if !fnRegex.MatchString(content) {
		content = misTaggedFnOpenRe.ReplaceAllString(content, "<function=${1}>${2}")
	}

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
	content = StripProviderControlTokens(content)
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
	cleaned = StripProviderControlTokens(cleaned)
	cleaned = multiBlankRe.ReplaceAllString(cleaned, "\n\n")

	return strings.TrimSpace(cleaned)
}
