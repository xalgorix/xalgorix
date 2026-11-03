package terminal

import (
	"fmt"
	"regexp"
	"strings"
)

// toolFlagAlias maps an option a tool does NOT accept to the one it does.
type toolFlagAlias struct {
	re   *regexp.Regexp
	from string
	to   string // "" drops the option and its value
}

func newToolFlagAlias(from, to string) toolFlagAlias {
	// Case-sensitive on purpose: arjun's -t (threads) and -T (timeout) differ.
	return toolFlagAlias{
		re:   regexp.MustCompile(`(^|\s)` + regexp.QuoteMeta(from) + `(?:=|\s+)`),
		from: from,
		to:   to,
	}
}

// arjunFlagAliases are long options models commonly invent for arjun. arjun's
// argparse rejects the WHOLE command on any unknown option ("unrecognized
// arguments"), so one guessed flag silently discards the parameter-discovery
// run and its output file. Its real options are -t THREADS, -c CHUNKS,
// -d DELAY, -T TIMEOUT, -m METHOD, -w WORDLIST, -o JSON_FILE, -u URL, -q.
var arjunFlagAliases = []toolFlagAlias{
	newToolFlagAlias("--threads", "-t"),
	newToolFlagAlias("-threads", "-t"),
	newToolFlagAlias("--thread", "-t"),
	newToolFlagAlias("--chunks", "-c"),
	newToolFlagAlias("--chunk", "-c"),
	newToolFlagAlias("--chunk-size", "-c"),
	newToolFlagAlias("--delay", "-d"),
	newToolFlagAlias("--stable-sleep", "-d"),
	newToolFlagAlias("--timeout", "-T"),
	newToolFlagAlias("--method", "-m"),
	newToolFlagAlias("--wordlist", "-w"),
	newToolFlagAlias("--output", "-o"),
	newToolFlagAlias("--json", "-o"),
	newToolFlagAlias("-oJ", "-o"),
	newToolFlagAlias("-oj", "-o"),
	newToolFlagAlias("--url", "-u"),
}

var arjunQuietAliasRE = regexp.MustCompile(`(^|\s)--quiet($|\s)`)

// NormalizeToolFlags rewrites options that a known tool rejects into the
// option it actually accepts, so a guessed flag does not throw away the whole
// run. Only commands that INVOKE the tool are touched. It returns the
// rewritten command and a short notice for the model ("" when unchanged).
func NormalizeToolFlags(command string) (string, string) {
	var fixed []string
	rewritten := rewriteShellSegments(command, func(segment string) string {
		if !hasToolCommand(segment, "arjun") {
			return segment
		}
		for _, alias := range arjunFlagAliases {
			if alias.re.FindStringIndex(segment) == nil {
				continue
			}
			segment = alias.re.ReplaceAllString(segment, "${1}"+alias.to+" ")
			fixed = append(fixed, alias.from+"→"+alias.to)
		}
		if arjunQuietAliasRE.FindStringIndex(segment) != nil {
			segment = arjunQuietAliasRE.ReplaceAllString(segment, "${1}-q${2}")
			fixed = append(fixed, "--quiet→-q")
		}
		return segment
	})
	if len(fixed) == 0 {
		return command, ""
	}
	return rewritten, fmt.Sprintf("[TOOL FLAGS] arjun does not accept %s; rewrote to its real options (%s). arjun options: -u URL -m METHOD -t THREADS -c CHUNKS -d DELAY -T TIMEOUT -w WORDLIST -o JSON_FILE -q --stable --rate-limit N.\n",
		strings.Join(aliasSources(fixed), ", "), strings.Join(fixed, ", "))
}

func aliasSources(fixed []string) []string {
	out := make([]string, 0, len(fixed))
	for _, f := range fixed {
		if i := strings.Index(f, "→"); i > 0 {
			out = append(out, f[:i])
		}
	}
	return out
}
