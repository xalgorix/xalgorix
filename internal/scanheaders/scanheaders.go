// Package scanheaders manages operator-supplied custom HTTP headers that
// identify authorized Xalgorix scan traffic (for example "X-Bug-Bounty: user").
//
// The headers mark every target-facing request as an authorized run, so the
// traffic is attributable in the target's access logs and can be allow-listed
// by its WAF/SOC. They are applied to the agent's HTTP client and passed
// through, in each tool's own header syntax, to the httpx, nuclei, curl and
// wget commands the agent runs. The engine NEVER attaches them to its own
// destinations — LLM/provider APIs, AgentMail, Discord/Telegram, or the
// dashboard. A curl or wget command carries them to whatever host it requests.
package scanheaders

import (
	"bufio"
	"net/http"
	"os"
	"strings"
)

// Parse turns an operator-supplied raw string into a normalized,
// de-duplicated, order-preserving list of "Name: value" headers. Entries are
// separated by newlines and/or ';'. Each entry must be a valid
// "Header-Name: value" pair; malformed entries (missing ':' or an invalid
// header name) are skipped. A value containing ';' is not supported in this
// packed form — supply such a header one-per-line via a file or as a separate
// CLI -H flag.
func Parse(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var out []string
	seen := map[string]struct{}{}
	for _, line := range strings.Split(raw, "\n") {
		for _, part := range strings.Split(line, ";") {
			add(&out, seen, part)
		}
	}
	return out
}

// ParseFile reads headers from a file, one "Name: value" per line. Blank lines
// and '#'-comment lines are ignored. Returns (nil, err) if the file cannot be
// read; callers may treat a missing file as a non-fatal configuration error.
func ParseFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	seen := map[string]struct{}{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		add(&out, seen, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Merge concatenates header lists, de-duplicating by canonical header name
// (case-insensitive) while preserving first-seen order. Earlier lists win, so
// callers can layer sources by precedence (for example env first, then CLI).
func Merge(lists ...[]string) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, list := range lists {
		for _, h := range list {
			add(&out, seen, h)
		}
	}
	return out
}

// Apply sets each configured header on h, but never overwrites a header the
// caller already set — a deliberate request header must win over the global
// attribution header. Empty input is a no-op.
func Apply(h http.Header, headers []string) {
	for _, entry := range headers {
		name, value, ok := split(entry)
		if !ok {
			continue
		}
		if h.Get(name) != "" {
			continue
		}
		h.Set(name, value)
	}
}

// add validates entry and appends its canonical "Name: value" form to out,
// skipping malformed entries and duplicates (by case-insensitive name).
func add(out *[]string, seen map[string]struct{}, entry string) {
	name, value, ok := split(entry)
	if !ok {
		return
	}
	key := strings.ToLower(name)
	if _, dup := seen[key]; dup {
		return
	}
	seen[key] = struct{}{}
	*out = append(*out, name+": "+value)
}

// split parses "Name: value" into its parts, validating the header name. Only
// the first ':' separates name from value, so values may contain ':'.
func split(entry string) (name, value string, ok bool) {
	entry = strings.TrimSpace(entry)
	idx := strings.IndexByte(entry, ':')
	if idx <= 0 {
		return "", "", false
	}
	name = strings.TrimSpace(entry[:idx])
	value = strings.TrimSpace(entry[idx+1:])
	if name == "" || value == "" || !isHeaderName(name) {
		return "", "", false
	}
	return name, value, true
}

// isHeaderName reports whether tok is a valid RFC 7230 header field-name (token
// characters only), so a value or a stray word is never mistaken for a header
// name.
func isHeaderName(tok string) bool {
	if tok == "" {
		return false
	}
	for _, r := range tok {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", r):
		default:
			return false
		}
	}
	return true
}
