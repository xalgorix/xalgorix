package terminal

import (
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

// rewriteShellSegments applies rewrite to every simple command of a shell
// command line and reassembles it byte-for-byte otherwise. A simple command
// ends at an unquoted list or pipeline operator: ; | || |& && & (background)
// or a newline. Quoted text, backslash escapes, comments, redirections such as
// 2>&1 / &> / >|, and here-document bodies are never split, and here-document
// bodies are copied through verbatim (they are data, not commands).
//
// Newlines and background & must be separators: model-written commands are
// often multi-line scripts, and treating a whole script as one segment let a
// flag meant for a tool on line 3 be appended to the end of line 9.
func rewriteShellSegments(command string, rewrite func(string) string) string {
	var b strings.Builder
	b.Grow(len(command))
	start := 0
	var quote rune
	escaped := false
	var heredocs []heredocSpec
	// arith counts open (( ... )) / $(( ... )) arithmetic, where << is a
	// left shift rather than a here-document operator.
	arith := 0
	i := 0
	for i < len(command) {
		r, size := utf8.DecodeRuneInString(command[i:])
		if escaped {
			escaped = false
			i += size
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped = true
			i += size
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			i += size
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			i += size
			continue
		}
		if r == '#' && startsShellWord(command, i) {
			// A comment runs to the end of the line; an apostrophe inside it
			// must not open a quote that swallows the rest of the script.
			if nl := strings.IndexByte(command[i:], '\n'); nl >= 0 {
				i += nl
			} else {
				i = len(command)
			}
			continue
		}
		if r == '(' && strings.HasPrefix(command[i:], "((") {
			arith++
			i += 2
			continue
		}
		if r == ')' && arith > 0 && strings.HasPrefix(command[i:], "))") {
			arith--
			i += 2
			continue
		}
		if r == '<' && arith == 0 && strings.HasPrefix(command[i:], "<<") && !strings.HasPrefix(command[i:], "<<<") {
			if spec, consumed, ok := parseHeredocOperator(command[i:]); ok {
				heredocs = append(heredocs, spec)
				i += consumed
				continue
			}
		}
		delimiterLen := shellDelimiterLen(command, i)
		if delimiterLen == 0 {
			i += size
			continue
		}
		b.WriteString(rewrite(command[start:i]))
		b.WriteString(command[i : i+delimiterLen])
		i += delimiterLen
		if command[i-1] == '\n' && len(heredocs) > 0 {
			bodyEnd := skipHeredocBodies(command, i, heredocs)
			b.WriteString(command[i:bodyEnd])
			i = bodyEnd
			heredocs = nil
		}
		start = i
	}
	b.WriteString(rewrite(command[start:]))
	return b.String()
}

// shellSegments returns the simple commands of a command line (see
// rewriteShellSegments for the splitting rules).
func shellSegments(command string) []string {
	var segments []string
	rewriteShellSegments(command, func(segment string) string {
		segments = append(segments, segment)
		return segment
	})
	return segments
}

// shellDelimiterLen reports the byte length of the list/pipeline operator that
// starts at command[i], or 0 when command[i] does not start one.
func shellDelimiterLen(command string, i int) int {
	next := byte(0)
	if i+1 < len(command) {
		next = command[i+1]
	}
	prev := byte(0)
	if i > 0 {
		prev = command[i-1]
	}
	switch command[i] {
	case '\n', ';':
		return 1
	case '|':
		if prev == '>' {
			return 0 // >| (clobber redirection)
		}
		if next == '|' || next == '&' {
			return 2
		}
		return 1
	case '&':
		if next == '&' {
			return 2
		}
		if next == '>' || prev == '>' || prev == '<' {
			return 0 // &> file, 2>&1, >&2, <&3 are redirections
		}
		return 1 // background
	}
	return 0
}

// startsShellWord reports whether the byte at i begins a shell word (start of
// input or preceded by whitespace or an operator), which is where # begins a
// comment rather than being part of a word such as a URL fragment.
func startsShellWord(command string, i int) bool {
	if i == 0 {
		return true
	}
	switch command[i-1] {
	case ' ', '\t', '\n', ';', '|', '&', '(':
		return true
	}
	return false
}

type heredocSpec struct {
	word      string
	stripTabs bool
}

// parseHeredocOperator parses "<<[-] WORD" at the start of s and returns the
// terminator spec and the number of bytes consumed (operator plus word,
// including any quotes around the word).
func parseHeredocOperator(s string) (heredocSpec, int, bool) {
	i := 2
	spec := heredocSpec{}
	if i < len(s) && s[i] == '-' {
		spec.stripTabs = true
		i++
	}
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i >= len(s) {
		return heredocSpec{}, 0, false
	}
	var word strings.Builder
	switch s[i] {
	case '\'', '"':
		q := s[i]
		end := strings.IndexByte(s[i+1:], q)
		if end < 0 {
			return heredocSpec{}, 0, false
		}
		word.WriteString(s[i+1 : i+1+end])
		i += end + 2
	default:
		for i < len(s) {
			c := s[i]
			if c == ' ' || c == '\t' || c == '\n' || c == ';' || c == '|' || c == '&' || c == '<' || c == '>' || c == '(' || c == ')' {
				break
			}
			if c == '\\' || c == '\'' || c == '"' {
				i++ // quoting characters inside the word only disable expansion
				continue
			}
			word.WriteByte(c)
			i++
		}
	}
	if word.Len() == 0 {
		return heredocSpec{}, 0, false
	}
	spec.word = word.String()
	return spec, i, true
}

// skipHeredocBodies returns the offset just past the terminator line of each
// pending here-document, in order. An unterminated body runs to the end.
func skipHeredocBodies(command string, pos int, specs []heredocSpec) int {
	for _, spec := range specs {
		for {
			if pos >= len(command) {
				return len(command)
			}
			lineEnd := strings.IndexByte(command[pos:], '\n')
			var line string
			next := len(command)
			if lineEnd >= 0 {
				line = command[pos : pos+lineEnd]
				next = pos + lineEnd + 1
			} else {
				line = command[pos:]
			}
			line = strings.TrimSuffix(line, "\r")
			if spec.stripTabs {
				line = strings.TrimLeft(line, "\t")
			}
			pos = next
			if line == spec.word {
				break
			}
		}
	}
	return pos
}

// hasToolCommand reports whether a simple command (or any simple command of a
// command line) INVOKES tool — i.e. the tool is the command word, after
// optional wrappers such as sudo, env/VAR=value, timeout, nohup, nice, stdbuf,
// xargs or a shell keyword like do/then. A tool merely MENTIONED as an argument
// (which arjun, echo "ffuf done", for t in ffuf nmap, grep nuclei) is not an
// invocation: rewriting those appended scanner flags to unrelated commands.
func hasToolCommand(segment, tool string) bool {
	for _, simple := range shellSegments(segment) {
		for _, name := range invokedCommandChain(simple) {
			if strings.EqualFold(name, tool) {
				return true
			}
		}
	}
	return false
}

// commandInvokesTool is hasToolCommand that also looks inside command and
// process substitutions ($(...), `...`, <(...)). It is for classification
// (timeouts), never for flag rewriting: a flag appended to the end of the
// enclosing command would land outside the substitution.
func commandInvokesTool(command, tool string) bool {
	if hasToolCommand(command, tool) {
		return true
	}
	for _, opener := range []string{"$(", "<(", ">(", "`"} {
		rest := command
		for {
			idx := strings.Index(rest, opener)
			if idx < 0 {
				break
			}
			rest = rest[idx+len(opener):]
			for _, name := range invokedCommandChain(rest) {
				if strings.EqualFold(name, tool) {
					return true
				}
			}
		}
	}
	return false
}

var (
	shellAssignmentRE  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=`)
	shellRedirectionRE = regexp.MustCompile(`^[0-9]*(<<?|>>?|&>>?|>&|<&|>\|)`)
)

// invokedCommandChain returns the lower-cased base names of the commands a
// simple command executes: any wrapper commands (sudo, timeout, xargs, nice,
// env, ...) followed by the wrapped command, skipping assignments, shell
// keywords and leading redirections. "timeout 300 arjun -u x" yields
// [timeout arjun]; "which arjun" yields [which].
func invokedCommandChain(simple string) []string {
	var chain []string
	fields := strings.Fields(simple)
	for i := 0; i < len(fields); i++ {
		tok := strings.TrimLeft(fields[i], "({!")
		if tok == "" {
			continue
		}
		if shellAssignmentRE.MatchString(tok) {
			continue
		}
		if shellRedirectionRE.MatchString(tok) {
			if op := shellRedirectionRE.FindString(tok); op == tok {
				i++ // operator and target are separate words: "2> /dev/null"
			}
			continue
		}
		lower := strings.ToLower(tok)
		switch lower {
		case "do", "then", "else", "elif", "if", "while", "until", "time", "exec", "nohup", "builtin":
			continue
		case "sudo":
			chain = append(chain, lower)
			i = skipWrapperOptions(fields, i, map[string]bool{"-u": true, "-g": true, "-C": true, "-D": true, "-p": true, "-U": true})
			continue
		case "env":
			chain = append(chain, lower)
			i = skipWrapperOptions(fields, i, map[string]bool{"-u": true, "-C": true, "-S": true})
			continue
		case "nice", "ionice":
			chain = append(chain, lower)
			i = skipWrapperOptions(fields, i, map[string]bool{"-n": true, "-c": true, "-p": true})
			continue
		case "stdbuf":
			chain = append(chain, lower)
			i = skipWrapperOptions(fields, i, nil)
			continue
		case "xargs":
			chain = append(chain, lower)
			i = skipWrapperOptions(fields, i, map[string]bool{"-I": true, "-P": true, "-n": true, "-L": true, "-d": true, "-s": true, "-a": true, "-E": true, "-e": true})
			continue
		case "timeout":
			chain = append(chain, lower)
			i = skipWrapperOptions(fields, i, map[string]bool{"-k": true, "-s": true})
			if i+1 < len(fields) {
				i++ // the duration
			}
			continue
		case "command":
			if i+1 < len(fields) && strings.HasPrefix(fields[i+1], "-") {
				return append(chain, "command") // command -v/-V is a lookup, not an invocation
			}
			continue
		}
		tok = strings.Trim(tok, `"'`)
		tok = strings.TrimRight(tok, ")`;&|")
		if tok == "" {
			return chain
		}
		return append(chain, strings.ToLower(path.Base(tok)))
	}
	return chain
}

// skipWrapperOptions advances past a wrapper's dash options (and the separate
// value of any option in withValue) and returns the index of the last option
// consumed, so the caller's loop continues at the wrapped command.
func skipWrapperOptions(fields []string, i int, withValue map[string]bool) int {
	for i+1 < len(fields) && strings.HasPrefix(fields[i+1], "-") {
		i++
		if fields[i] == "--" {
			break
		}
		if withValue[fields[i]] && i+1 < len(fields) {
			i++
		}
	}
	return i
}

// trailingCommentIndex returns the byte offset of an unquoted trailing
// "# comment" in a simple command, or -1. Arguments appended to a command must
// go before its comment, otherwise the shell ignores them.
func trailingCommentIndex(segment string) int {
	var quote rune
	escaped := false
	for i, r := range segment {
		if escaped {
			escaped = false
			continue
		}
		if r == '\\' && quote != '\'' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
			continue
		}
		if r == '#' && startsShellWord(segment, i) {
			return i
		}
	}
	return -1
}
