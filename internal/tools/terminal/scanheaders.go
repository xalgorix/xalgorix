package terminal

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/config"
)

// scanHeaderTool describes how one HTTP command-line tool takes a custom
// request header, so an operator-configured scan/attribution header can be
// passed straight through to it.
type scanHeaderTool struct {
	name string
	// flag is a fmt template for one header; %s receives the shell-quoted
	// "Name: value".
	flag string
	// dedicated maps a lower-cased header name to the tool's own options for
	// setting that header (curl -A for User-Agent, for example). A header the
	// agent set through one of them counts as already present, so an operator
	// default never overrides a value the agent chose on purpose, such as a
	// User-Agent payload.
	dedicated map[string][]string
}

// scanHeaderTools are the HTTP tools whose invocations get the scan headers.
// httpx, nuclei and curl take a repeatable -H "Name: value". wget must use
// --header=: its -H is --span-hosts, so a -H would switch on recursive
// cross-host fetching and turn the header text into an extra URL.
var scanHeaderTools = []scanHeaderTool{
	{name: "httpx", flag: "-H %s"},
	{name: "nuclei", flag: "-H %s"},
	{name: "curl", flag: "-H %s", dedicated: map[string][]string{
		"user-agent": {"-A", "--user-agent"},
		"referer":    {"-e", "--referer"},
	}},
	{name: "wget", flag: "--header=%s", dedicated: map[string][]string{
		"user-agent": {"-U", "--user-agent"},
		"referer":    {"--referer"},
	}},
}

// InjectScanHeadersIntoCommand appends the operator-configured scan headers
// (XALGORIX_SCAN_HEADERS / -H) to every httpx, nuclei, curl and wget
// invocation in command, each in that tool's own header syntax, so terminal
// traffic carries the same identifying header as the agent's own requests. It
// is pipe-aware (each piped stage is handled independently) and idempotent: a
// header already present on a stage is never duplicated. Returns command
// unchanged when no scan headers are configured or no matching tool is invoked.
func InjectScanHeadersIntoCommand(command string) string {
	return injectScanHeaders(command, config.Get().ScanHeaders)
}

// injectScanHeaders is the pure core of InjectScanHeadersIntoCommand, taking
// the header list explicitly so it can be tested without global config.
func injectScanHeaders(command string, headers []string) string {
	if len(headers) == 0 {
		return command
	}
	return rewriteShellSegments(command, func(segment string) string {
		return injectScanHeadersIntoSegment(segment, headers)
	})
}

// injectScanHeadersIntoSegment appends header flags for a single piped stage
// when that stage invokes one of scanHeaderTools. A stage that invokes no such
// tool is returned unchanged.
func injectScanHeadersIntoSegment(segment string, headers []string) string {
	var tool *scanHeaderTool
	for i := range scanHeaderTools {
		if hasToolCommand(segment, scanHeaderTools[i].name) {
			tool = &scanHeaderTools[i]
			break
		}
	}
	if tool == nil {
		return segment
	}
	for _, h := range headers {
		if segmentHasHeader(segment, h) || segmentSetsHeaderViaOption(argsAfterTool(segment, tool.name), h, tool.dedicated) {
			continue
		}
		segment = appendCommandArg(segment, fmt.Sprintf(tool.flag, shellQuote(h)))
	}
	return segment
}

// segmentHasHeader reports whether segment already passes a -H / -header /
// --header flag for the same header name (case-insensitive), so an
// operator-configured header the agent happened to add itself is not
// duplicated.
func segmentHasHeader(segment, header string) bool {
	name := scanHeaderName(header)
	if name == "" {
		return false
	}
	re := regexp.MustCompile(`(?i)(?:^|\s)-{1,2}(?:h|header)[=\s]+['"]?` + regexp.QuoteMeta(name) + `\s*:`)
	return re.MatchString(segment)
}

// argsAfterTool returns the part of segment after the first word naming tool
// (bare or as a path), so options of a wrapper in front of it, like the -e of
// "stdbuf -eL curl ...", are not read as the tool's own. It returns segment
// unchanged when the tool word is not found.
func argsAfterTool(segment, tool string) string {
	re := regexp.MustCompile(`(?i)(?:^|[\s/(])` + regexp.QuoteMeta(tool) + `(?:\s|$)`)
	if loc := re.FindStringIndex(segment); loc != nil {
		return segment[loc[1]:]
	}
	return segment
}

// segmentSetsHeaderViaOption reports whether args set header through one of
// the tool's dedicated options (curl -A "x", wget --user-agent=x, ...). Short
// options may carry their value attached (-Ax), long ones take it after a
// space or "=".
func segmentSetsHeaderViaOption(args, header string, dedicated map[string][]string) bool {
	opts := dedicated[strings.ToLower(scanHeaderName(header))]
	for _, opt := range opts {
		pattern := `(?:^|\s)` + regexp.QuoteMeta(opt)
		if strings.HasPrefix(opt, "--") {
			pattern += `(?:[=\s]|$)`
		}
		if regexp.MustCompile(pattern).MatchString(args) {
			return true
		}
	}
	return false
}

// scanHeaderName returns the trimmed name part of a "Name: value" header, or
// "" when header has no name.
func scanHeaderName(header string) string {
	idx := strings.IndexByte(header, ':')
	if idx <= 0 {
		return ""
	}
	return strings.TrimSpace(header[:idx])
}
