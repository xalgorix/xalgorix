// Package skills provides the read_skill and list_skills tools for on-demand knowledge loading.
package skills

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

//go:embed data/*/*/*
var embeddedSkills embed.FS

// fs.Sub returns a distinct wrapper for each call. The skill-index cache uses
// fs.FS as its key, so creating a wrapper during every skill lookup retains a
// complete catalog index for each scan iteration. Reuse one wrapper for the
// immutable embedded catalog across all agents and tool registrations.
var embeddedSkillsDataFS = func() fs.FS {
	subFS, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		return embeddedSkills
	}
	return subFS
}()

type loadedSkillRecord struct {
	canonicalName string
	contentHash   string // SHA-256 hex
	fullContent   string
}

type loadedListRecord struct {
	contentHash string // SHA-256 hex
	fullContent string
}

type agentSkillState struct {
	mu           sync.Mutex
	loadedSkills map[string]loadedSkillRecord // key: canonicalName
	loadedLists  map[string]loadedListRecord  // key: filterCat
}

func newAgentSkillState() *agentSkillState {
	return &agentSkillState{
		loadedSkills: make(map[string]loadedSkillRecord),
		loadedLists:  make(map[string]loadedListRecord),
	}
}

// Register adds skill tools to the registry.
func Register(r *tools.Registry, _ string) {
	state := newAgentSkillState()
	r.Register(&tools.Tool{
		Name:        "read_skill",
		Description: "Load a structured security-testing skill to get deep methodology, tooling commands, and verification steps. Use this BEFORE testing a specific vulnerability class or technology (e.g., read_skill name=exploiting-server-side-request-forgery). The skill catalog follows the agentskills.io standard and covers web applications, APIs, identity (OAuth, SAML, JWT), reconnaissance, cloud exposure, exposed network services, AI features, and more. Don't know the exact name? Use search_skills query='<concept>' to find the right skill, or list_skills to browse categories.",
		Parameters: []tools.Parameter{
			{Name: "name", Description: "Kebab-case skill name without extension (e.g., exploiting-oauth-misconfiguration, testing-jwt-token-security). Use list_skills to discover names.", Required: true},
			{Name: "category", Description: "Optional category to disambiguate (e.g., web-application-security, api-security, reconnaissance). If omitted, all categories are searched.", Required: false},
		},
		Execute: makeReadSkillWithState(embeddedSkillsDataFS, r, state),
	})

	r.Register(&tools.Tool{
		Name:        "list_skills",
		Description: "List all available skills organized by category. Call this to see what deep knowledge is available before deciding which skills to load for your current engagement.",
		Parameters: []tools.Parameter{
			{Name: "category", Description: "Optional category filter (e.g., web-application-security, api-security, reconnaissance). Omit to list all.", Required: false},
		},
		Execute: makeListSkillsWithState(embeddedSkillsDataFS, r, state),
	})

	r.Register(&tools.Tool{
		Name:        "search_skills",
		Description: "Search the skill catalog by keywords/concept and get the most relevant skills ranked, each with its category, name, and description. Use this when you don't know a skill's exact name — e.g. search_skills query='oauth token theft' or query='payment price tampering'. Then load the best match with read_skill. Far faster than scanning list_skills category by category.",
		Parameters: []tools.Parameter{
			{Name: "query", Description: "Keywords or a short phrase describing what you want (e.g. 'graphql batching', 'reset password poisoning', 'jwt algorithm confusion').", Required: true},
			{Name: "category", Description: "Optional category filter (e.g., web-application-security, cloud-security).", Required: false},
			{Name: "max", Description: "Max results to return (default 10, hard cap 25).", Required: false},
		},
		Execute: makeSearchSkills(embeddedSkillsDataFS),
	})
}

// skillMeta is one indexed skill: its category, canonical name, a
// human-readable description, and a lowercased haystack (name + description +
// tags + category) used for keyword scoring.
type skillMeta struct {
	category    string
	name        string
	description string
	intent      string
	haystack    string
}

var (
	skillIndexMu    sync.Mutex
	skillIndexCache = map[fs.FS][]skillMeta{}
)

// buildSkillIndex walks the skill tree of the given filesystem and parses
// each SKILL.md's YAML frontmatter (name/description/tags/intent) into a
// searchable record. Indexes are cached per fs.FS for the process lifetime;
// the embedded FS in production and the on-disk FS in tests are each
// immutable within a process, so a per-filesystem cache is safe and keeps
// test fixtures isolated from the embedded index.
func buildSkillIndex(fsys fs.FS) []skillMeta {
	skillIndexMu.Lock()
	defer skillIndexMu.Unlock()
	if idx, ok := skillIndexCache[fsys]; ok {
		return idx
	}
	idx := buildSkillIndexFor(fsys)
	skillIndexCache[fsys] = idx
	return idx
}

// buildSkillIndexFor performs the actual tree walk for buildSkillIndex.
func buildSkillIndexFor(fsys fs.FS) []skillMeta {
	var idx []skillMeta
	cats := listCategories(fsys)
	for _, cat := range cats {
		entries, err := fs.ReadDir(fsys, cat)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			data, err := fs.ReadFile(fsys, cat+"/"+name+"/SKILL.md")
			if err != nil {
				continue
			}
			desc, fm := parseSkillFrontmatter(string(data))
			hay := strings.ToLower(name + " " + cat + " " + fm)
			idx = append(idx, skillMeta{
				category:    cat,
				name:        name,
				description: desc,
				intent:      parseSkillIntent(fm),
				haystack:    hay,
			})
		}
	}
	return idx
}

// parseSkillFrontmatter extracts the description value and the raw frontmatter
// block (name/description/tags/…) from a SKILL.md. The description may be a
// YAML folded scalar spanning several indented lines; those are joined. Returns
// (description, frontmatterText). Degrades gracefully when there is no
// frontmatter.
func parseSkillFrontmatter(content string) (string, string) {
	lines := strings.Split(content, "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) != "---" {
		return "", ""
	}
	var fm []string
	var descParts []string
	inDesc := false
	for _, raw := range lines[1:] {
		if strings.TrimSpace(raw) == "---" {
			break
		}
		fm = append(fm, raw)
		if inDesc {
			// Continuation of a folded description: indented, not a new key.
			if strings.HasPrefix(raw, " ") || strings.HasPrefix(raw, "\t") {
				descParts = append(descParts, strings.TrimSpace(raw))
				continue
			}
			inDesc = false
		}
		if strings.HasPrefix(raw, "description:") {
			v := strings.TrimSpace(strings.TrimPrefix(raw, "description:"))
			if v != "" {
				descParts = append(descParts, v)
			}
			inDesc = true
		}
	}
	desc := strings.Join(descParts, " ")
	if len(desc) > 300 {
		desc = desc[:297] + "..."
	}
	return desc, strings.Join(fm, "\n")
}

// parseSkillIntent extracts the optional `intent:` frontmatter tag
// (offensive/defensive) used for intent-aware search ranking. Returns an
// empty string when the skill carries no intent metadata.
func parseSkillIntent(frontmatter string) string {
	for _, line := range strings.Split(frontmatter, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "intent:") {
			continue
		}
		v := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(line, "intent:")))
		v = strings.Trim(v, `"'`)
		if v == "offensive" || v == "defensive" {
			return v
		}
		return ""
	}
	return ""
}

// defensiveQuerySignals are terms that indicate the caller explicitly wants
// implementation/hardening guidance rather than attack methodology.
var defensiveQuerySignals = []string{
	"implement", "implementation", "harden", "hardening", "mitigate",
	"mitigation", "prevent", "prevention", "defend", "defensive",
	"secure coding", "best practice", "best practices", "configure",
	"configuration guide", "deploy", "rollout", "detection rule",
	"monitoring", "posture management", "how to build",
	"anomaly detection", "threat detection",
}

// queryWantsDefensive reports whether the search query explicitly asks for
// defensive/implementation content.
func queryWantsDefensive(query string) bool {
	for _, s := range defensiveQuerySignals {
		if strings.Contains(query, s) {
			return true
		}
	}
	return false
}

func makeSearchSkills(fsys fs.FS) func(args map[string]string) (tools.Result, error) {
	return func(args map[string]string) (tools.Result, error) {
		query := strings.ToLower(strings.TrimSpace(args["query"]))
		if query == "" {
			return tools.Result{Output: "❌ Provide a 'query' (keywords or a short phrase), e.g. query='oauth token theft'."}, nil
		}
		filterCat := strings.TrimSpace(args["category"])
		max := 10
		if s := strings.TrimSpace(args["max"]); s != "" {
			if n, err := parseIntSafe(s); err == nil && n > 0 {
				max = n
			}
		}
		if max > 25 {
			max = 25
		}

		// Tokenize on whitespace and commas; drop very short noise tokens.
		tokens := strings.FieldsFunc(query, func(r rune) bool {
			return r == ' ' || r == ',' || r == '\t' || r == '\n' || r == '/'
		})
		terms := make([]string, 0, len(tokens))
		for _, t := range tokens {
			if len(t) >= 2 {
				terms = append(terms, t)
			}
		}
		if len(terms) == 0 {
			terms = []string{query}
		}

		type scored struct {
			m     skillMeta
			score int
		}
		var results []scored
		for _, m := range buildSkillIndex(fsys) {
			if filterCat != "" && m.category != filterCat {
				continue
			}
			score := 0
			for _, term := range terms {
				// Name matches are the strongest signal, then frontmatter
				// (tags/description), then the whole exact phrase.
				if strings.Contains(strings.ToLower(m.name), term) {
					score += 3
				}
				if strings.Contains(m.haystack, term) {
					score += 1
				}
			}
			if strings.Contains(m.haystack, query) {
				// Exact full-phrase bonus: the whole query appearing verbatim in
				// the skill is stronger evidence than generic single-token name
				// matches (e.g. "s3 public access" ranks storage testing above
				// any skill whose *name* merely contains "access").
				score += 3
			}
			if score > 0 {
				// Intent-aware ranking: autonomous pentest agents search
				// for attack/testing methodology, so offensive skills rank
				// above implementation/hardening guidance unless the query
				// explicitly asks for defensive content. The intent bonus
				// only reorders lexical matches — it never makes a
				// non-matching skill appear.
				switch {
				case queryWantsDefensive(query) && m.intent == "defensive":
					score += 6
				case queryWantsDefensive(query) && m.intent == "offensive":
					// no boost: still listed, below defensive matches
				case m.intent == "offensive":
					score += 4
				case m.intent == "defensive":
					score -= 3
				}
				results = append(results, scored{m: m, score: score})
			}
		}
		if len(results) == 0 {
			return tools.Result{Output: fmt.Sprintf("No skills matched %q. Try broader keywords, or list_skills to browse categories.", query)}, nil
		}
		sort.SliceStable(results, func(i, j int) bool {
			if results[i].score != results[j].score {
				return results[i].score > results[j].score
			}
			return results[i].m.name < results[j].m.name
		})
		if len(results) > max {
			results = results[:max]
		}
		var b strings.Builder
		fmt.Fprintf(&b, "Top %d skill match(es) for %q — load one with read_skill name=<name>:\n\n", len(results), query)
		for _, r := range results {
			fmt.Fprintf(&b, "• %s  [%s]\n", r.m.name, r.m.category)
			if r.m.description != "" {
				fmt.Fprintf(&b, "  %s\n", r.m.description)
			}
		}
		return tools.Result{Output: strings.TrimRight(b.String(), "\n")}, nil
	}
}

// parseIntSafe parses a base-10 int, returning an error on any non-numeric
// input. Small local helper so search_skills' `max` parsing has no deps.
func parseIntSafe(s string) (int, error) {
	n := 0
	_, err := fmt.Sscanf(s, "%d", &n)
	return n, err
}

// listCategories returns the set of category directories that exist on the
// embedded skill filesystem. This replaces the previous hardcoded list so
// adding a new category folder is a zero-code change.
func listCategories(fsys fs.FS) []string {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil
	}
	cats := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if name == "" || name == "." || strings.HasPrefix(name, ".") {
			continue
		}
		cats = append(cats, name)
	}
	sort.Strings(cats)
	return cats
}

// skillAliases maps common shorthand names to their canonical full skill
// directory names. This lets the LLM agent use natural terms like "xss",
// "sqli", or "ssrf" without knowing the verbose directory name.
var skillAliases = map[string]string{
	// ── Web application vulnerabilities ──────────────────────────────
	"sql-injection":                    "exploiting-sql-injection-vulnerabilities",
	"sqli":                             "exploiting-sql-injection-vulnerabilities",
	"sql-injection-sqlmap":             "exploiting-sql-injection-with-sqlmap",
	"sqlmap":                           "exploiting-sql-injection-with-sqlmap",
	"nosql-injection":                  "exploiting-nosql-injection-vulnerabilities",
	"nosqli":                           "exploiting-nosql-injection-vulnerabilities",
	"xss":                              "testing-for-xss-vulnerabilities",
	"cross-site-scripting":             "testing-for-xss-vulnerabilities",
	"dom-xss":                          "testing-for-xss-vulnerabilities",
	"xss-burp":                         "testing-for-xss-vulnerabilities-with-burpsuite",
	"ssrf":                             "exploiting-server-side-request-forgery",
	"blind-ssrf":                       "performing-blind-ssrf-exploitation",
	"csrf":                             "performing-csrf-attack-simulation",
	"cross-site-request-forgery":       "performing-csrf-attack-simulation",
	"xxe":                              "testing-for-xxe-injection-vulnerabilities",
	"xml-external-entity":              "testing-for-xxe-injection-vulnerabilities",
	"idor":                             "exploiting-idor-vulnerabilities",
	"insecure-direct-object-reference": "exploiting-idor-vulnerabilities",
	"ssti":                             "exploiting-template-injection-vulnerabilities",
	"template-injection":               "exploiting-template-injection-vulnerabilities",
	"server-side-template-injection":   "exploiting-template-injection-vulnerabilities",
	"cors":                             "testing-cors-misconfiguration",
	"cors-misconfiguration":            "testing-cors-misconfiguration",
	"cors-exploitation":                "testing-cors-misconfiguration",
	"open-redirect":                    "testing-for-open-redirect-vulnerabilities",
	"clickjacking":                     "performing-clickjacking-attack-test",
	"deserialization":                  "exploiting-insecure-deserialization",
	"insecure-deserialization":         "exploiting-insecure-deserialization",

	// ── Additional web skills (reachability aliases) ─────────────────
	"prototype-pollution":     "exploiting-prototype-pollution-in-javascript",
	"type-juggling":           "exploiting-type-juggling-vulnerabilities",
	"websocket":               "exploiting-websocket-vulnerabilities",
	"websocket-hijacking":     "exploiting-websocket-vulnerabilities",
	"request-smuggling":       "exploiting-http-request-smuggling",
	"http-request-smuggling":  "exploiting-http-request-smuggling",
	"broken-access-control":   "authorization-testing",
	"bac":                     "authorization-testing",
	"business-logic":          "business-logic-testing",
	"host-header-injection":   "testing-for-host-header-injection",
	"host-header-attacks":     "testing-for-host-header-injection",
	"hpp":                     "performing-http-parameter-pollution-attack",
	"parameter-pollution":     "performing-http-parameter-pollution-attack",
	"graphql":                 "performing-graphql-security-assessment",
	"graphql-advanced":        "performing-graphql-security-assessment",
	"web-cache-poisoning":     "performing-web-cache-poisoning-attack",
	"cache-poisoning":         "performing-web-cache-poisoning-attack",
	"web-cache-deception":     "performing-web-cache-deception-attack",
	"csp-bypass":              "performing-content-security-policy-bypass",
	"waf-bypass":              "performing-web-application-firewall-bypass",
	"second-order-sqli":       "performing-second-order-sql-injection",
	"sensitive-data-exposure": "testing-for-sensitive-data-exposure",
	"information-disclosure":  "testing-for-sensitive-data-exposure",
	"xml-injection":           "testing-for-xml-injection-vulnerabilities",
	"email-header-injection":  "testing-for-email-header-injection",
	"broken-link-hijacking":   "exploiting-broken-link-hijacking",

	// ── Auth / session / account flows (checklist-derived skills) ────
	"session":              "authentication-session-testing",
	"session-management":   "authentication-session-testing",
	"session-fixation":     "authentication-session-testing",
	"cookie-security":      "exploiting-cookie-based-vulnerabilities",
	"2fa":                  "bypassing-two-factor-and-otp",
	"mfa":                  "bypassing-two-factor-and-otp",
	"otp":                  "bypassing-two-factor-and-otp",
	"2fa-bypass":           "bypassing-two-factor-and-otp",
	"mfa-bypass":           "bypassing-two-factor-and-otp",
	"otp-bypass":           "bypassing-two-factor-and-otp",
	"2fa-mfa-bypass":       "bypassing-two-factor-and-otp",
	"password-reset":       "testing-password-reset-flaws",
	"forgot-password":      "testing-password-reset-flaws",
	"reset-password":       "testing-password-reset-flaws",
	"account-recovery":     "testing-password-reset-flaws",
	"registration":         "testing-registration-and-account-flaws",
	"signup":               "testing-registration-and-account-flaws",
	"account-takeover":     "performing-account-takeover-attacks",
	"ato":                  "performing-account-takeover-attacks",
	"pre-account-takeover": "performing-account-takeover-attacks",

	// ── Injection / misc / business logic (checklist-derived) ────────
	"csv-injection":             "exploiting-csv-formula-injection",
	"formula-injection":         "exploiting-csv-formula-injection",
	"excel-injection":           "exploiting-csv-formula-injection",
	"dde":                       "exploiting-csv-formula-injection",
	"rfd":                       "performing-reflected-file-download",
	"reflected-file-download":   "performing-reflected-file-download",
	"captcha":                   "bypassing-captcha-protections",
	"captcha-bypass":            "bypassing-captcha-protections",
	"recaptcha":                 "bypassing-captcha-protections",
	"saml":                      "exploiting-saml-authentication-flaws",
	"saml-bypass":               "exploiting-saml-authentication-flaws",
	"saml-attacks":              "exploiting-saml-authentication-flaws",
	"xsw":                       "exploiting-saml-authentication-flaws",
	"signature-wrapping":        "exploiting-saml-authentication-flaws",
	"ecommerce":                 "testing-ecommerce-and-payment-logic",
	"payment":                   "testing-ecommerce-and-payment-logic",
	"payment-logic":             "testing-ecommerce-and-payment-logic",
	"price-tampering":           "testing-ecommerce-and-payment-logic",
	"voucher":                   "testing-ecommerce-and-payment-logic",
	"checkout":                  "testing-ecommerce-and-payment-logic",
	"shopping-cart":             "testing-ecommerce-and-payment-logic",
	"race-condition":            "race-condition-testing",
	"race-conditions":           "race-condition-testing",
	"application-modeling":      "application-attack-surface-modeling",
	"attack-surface-modeling":   "application-attack-surface-modeling",
	"auth-session":              "authentication-session-testing",
	"account-lifecycle":         "authentication-session-testing",
	"authorization":             "authorization-testing",
	"tenant-isolation":          "authorization-testing",
	"ownership-transition":      "authorization-testing",
	"workflow-testing":          "workflow-state-machine-testing",
	"state-machine":             "workflow-state-machine-testing",
	"step-bypass":               "workflow-state-machine-testing",
	"type-confusion":            "input-boundary-testing",
	"parameter-tampering":       "input-boundary-testing",
	"mass-assignment-testing":   "input-boundary-testing",
	"double-spend":              "race-condition-testing",
	"toctou":                    "race-condition-testing",
	"file-pipeline":             "file-processing-pipeline-testing",
	"archive-extraction":        "file-processing-pipeline-testing",
	"zip-slip":                  "file-processing-pipeline-testing",
	"control-differential":      "security-control-differential-testing",
	"layer-differential":        "security-control-differential-testing",
	"application-data-exposure": "application-data-exposure-testing",
	"over-fetching":             "application-data-exposure-testing",
	"whitebox":                  "source-assisted-analysis",
	"source-assisted":           "source-assisted-analysis",
	"source-review":             "source-assisted-analysis",
	"source-to-sink":            "source-assisted-analysis",
	"mass-assignment":           "exploiting-mass-assignment-in-rest-apis",
	"api-injection":             "api-injection",

	// ── Path traversal / LFI / RFI ───────────────────────────────────
	// The directory-traversal skill is the canonical LFI/path-traversal
	// reference. Without these aliases the agent's natural lookups
	// (read_skill name=lfi / path-traversal) silently failed, which is a
	// frequent cause of missed file-read findings (e.g. //etc/passwd).
	"lfi":                    "performing-directory-traversal-testing",
	"local-file-inclusion":   "performing-directory-traversal-testing",
	"rfi":                    "performing-directory-traversal-testing",
	"remote-file-inclusion":  "performing-directory-traversal-testing",
	"path-traversal":         "performing-directory-traversal-testing",
	"path-traversal-lfi-rfi": "performing-directory-traversal-testing",
	"directory-traversal":    "performing-directory-traversal-testing",
	"file-read":              "performing-directory-traversal-testing",
	"arbitrary-file-read":    "performing-directory-traversal-testing",
	"etc-passwd":             "performing-directory-traversal-testing",

	// ── OS command injection / RCE ───────────────────────────────────
	// "command-injection" previously resolved to a Modbus/ICS detection
	// skill, which is wrong for web testing. Point the web-facing terms at
	// the dedicated web command-injection skill; keep the ICS one reachable
	// under an explicit modbus alias.
	"command-injection":     "exploiting-os-command-injection",
	"os-command-injection":  "exploiting-os-command-injection",
	"rce":                   "exploiting-os-command-injection",
	"remote-code-execution": "exploiting-os-command-injection",
	"shell-injection":       "exploiting-os-command-injection",

	// ── Authentication & authorization ───────────────────────────────
	"jwt":                "jwt-security-testing",
	"jwt-attack":         "jwt-security-testing",
	"authentication-jwt": "jwt-security-testing",
	"jwt-signing":        "implementing-jwt-signing-and-verification",
	"oauth":              "exploiting-oauth-misconfiguration",
	"oauth-misconfig":    "exploiting-oauth-misconfiguration",
	"oauth2-attacks":     "exploiting-oauth-misconfiguration",
	"forced-browsing":    "bypassing-authentication-with-forced-browsing",
	"passwordless":       "implementing-passwordless-authentication-with-fido2",
	"fido2":              "implementing-passwordless-authentication-with-fido2",

	// ── Reconnaissance ───────────────────────────────────────────────
	"recon":           "conducting-external-reconnaissance-with-osint",
	"reconnaissance":  "conducting-external-reconnaissance-with-osint",
	"osint":           "performing-open-source-intelligence-gathering",
	"subdomain":       "performing-subdomain-enumeration-with-subfinder",
	"subdomain-enum":  "performing-subdomain-enumeration-with-subfinder",
	"subfinder":       "performing-subdomain-enumeration-with-subfinder",
	"nmap":            "scanning-network-with-nmap-advanced",
	"network-scan":    "scanning-network-with-nmap-advanced",
	"api-enumeration": "api-bola",
	"shadow-api":      "api-discovery",

	// ── API security ─────────────────────────────────────────────────
	"api-security":             "conducting-api-security-testing",
	"api-gateway":              "api-security-misconfiguration",
	"api-rate-limiting":        "api-resource-consumption",
	"api-schema":               "api-security-misconfiguration",
	"api-keys":                 "api-authentication-session",
	"api-abuse":                "api-business-flow-abuse",
	"api-posture":              "api-security-misconfiguration",
	"data-exposure":            "api-bopla",
	"aws-pentest":              "aws-cloud-pentesting",
	"aws-enum":                 "aws-cloud-pentesting",
	"azure-pentest":            "azure-entra-cloud-pentesting",
	"entra":                    "azure-entra-cloud-pentesting",
	"entra-id":                 "azure-entra-cloud-pentesting",
	"gcp-pentest":              "gcp-cloud-pentesting",
	"imds":                     "cloud-metadata-workload-identity",
	"imds-v2":                  "cloud-metadata-workload-identity",
	"cloud-metadata":           "cloud-metadata-workload-identity",
	"metadata-endpoint":        "cloud-metadata-workload-identity",
	"managed-identity":         "cloud-metadata-workload-identity",
	"workload-identity":        "cloud-metadata-workload-identity",
	"cloud-credentials":        "cloud-credential-abuse",
	"iam-privilege-escalation": "aws-iam-privilege-escalation",
	"passrole":                 "aws-iam-privilege-escalation",
	"gcp-escalation":           "gcp-iam-privilege-escalation",
	"actas":                    "gcp-iam-privilege-escalation",
	"azure-escalation":         "azure-privilege-escalation",
	"s3":                       "cloud-storage-exposure-testing",
	"s3-buckets":               "cloud-storage-exposure-testing",
	"gcs":                      "cloud-storage-exposure-testing",
	"blob-storage":             "cloud-storage-exposure-testing",
	"key-vault":                "cloud-secrets-data-access",
	"cross-account":            "cloud-cross-account-tenant-trust",
	"cloud-fingerprint":        "cloud-attack-surface-discovery",
	"bola":                     "api-bola",
	"bfla":                     "api-bfla",
	"bopla":                    "api-bopla",
	"json-rpc":                 "rpc-api-security",
	"jsonrpc":                  "rpc-api-security",
	"business-flow":            "api-business-flow-abuse",
	"unsafe-consumption":       "api-unsafe-third-party-consumption",
	"api-webhooks":             "api-unsafe-third-party-consumption",

	// ── Active Directory ─────────────────────────────────────────────
	"ad-pentest":       "performing-active-directory-penetration-test",
	"active-directory": "performing-active-directory-penetration-test",
	"bloodhound":       "exploiting-active-directory-with-bloodhound",
	"ad-acl":           "analyzing-active-directory-acl-abuse",
	"kerberoasting":    "performing-active-directory-penetration-test",
	"ad-cert":          "exploiting-active-directory-certificate-services-esc1",

	// ── Lateral movement & privilege escalation ──────────────────────

	// ── Phishing ─────────────────────────────────────────────────────
	"spearphishing":       "conducting-spearphishing-simulation-campaign",
	"phishing-simulation": "executing-phishing-simulation-campaign",

	// ── Cloud & Kubernetes ───────────────────────────────────────────
	"azure-ad":  "auditing-azure-active-directory-configuration",
	"azure-pim": "implementing-azure-ad-privileged-identity-management",

	// ── Memory / binary exploitation ─────────────────────────────────

	// ── Detection & monitoring ───────────────────────────────────────

	// ── Mobile ───────────────────────────────────────────────────────

	// ── File upload testing ──────────────────────────────────────────
	"file-upload":           "exploiting-file-upload-vulnerabilities",
	"upload":                "exploiting-file-upload-vulnerabilities",
	"upload-bypass":         "exploiting-file-upload-vulnerabilities",
	"webshell-upload":       "exploiting-file-upload-vulnerabilities",
	"insecure-file-uploads": "exploiting-file-upload-vulnerabilities",

	// ── CMS-specific testing ────────────────────────────────────────
	"cms":         "performing-cms-specific-security-testing",
	"cms-testing": "performing-cms-specific-security-testing",
	"wordpress":   "performing-cms-specific-security-testing",
	"wpscan":      "performing-cms-specific-security-testing",
	"drupal":      "performing-cms-specific-security-testing",
	"joomla":      "performing-cms-specific-security-testing",

	// ── Subdomain takeover ──────────────────────────────────────────
	"subdomain-takeover": "exploiting-subdomain-takeover-vulnerabilities",
	"takeover":           "exploiting-subdomain-takeover-vulnerabilities",
	"dangling-cname":     "exploiting-subdomain-takeover-vulnerabilities",

	// ── Zero-day & novel vulnerability discovery ────────────────────
	"zero-day":         "performing-zero-day-vulnerability-discovery",
	"0day":             "performing-zero-day-vulnerability-discovery",
	"novel-vuln":       "performing-zero-day-vulnerability-discovery",
	"attack-chaining":  "performing-zero-day-vulnerability-discovery",
	"logic-flaw":       "performing-zero-day-vulnerability-discovery",
	"zero-day-hunting": "performing-zero-day-vulnerability-discovery",

	// ── Exploit verification ────────────────────────────────────────
	"exploit-verification": "performing-exploit-verification",
	"verify-exploit":       "performing-exploit-verification",
	"false-positive":       "performing-exploit-verification",
	"proof-of-concept":     "performing-exploit-verification",
	"poc":                  "performing-exploit-verification",

	// ── Email security testing ──────────────────────────────────────
	"email-security": "performing-email-security-testing",
	"email-testing":  "performing-email-security-testing",
	"smtp-relay":     "performing-email-security-testing",
	"email-spoofing": "performing-email-security-testing",
	"spf-bypass":     "performing-email-security-testing",

	// ── Misc ─────────────────────────────────────────────────────────

	// ── New web vuln-class skills (HackTricks-derived) ───────────────
	"crlf":                           "testing-for-crlf-injection",
	"crlf-injection":                 "testing-for-crlf-injection",
	"http-header-injection":          "testing-for-crlf-injection",
	"response-splitting":             "testing-for-crlf-injection",
	"ldap-injection":                 "exploiting-ldap-injection",
	"ldapi":                          "exploiting-ldap-injection",
	"xpath-injection":                "exploiting-xpath-injection",
	"xpath":                          "exploiting-xpath-injection",
	"xslt-injection":                 "exploiting-xslt-server-side-injection",
	"xslt":                           "exploiting-xslt-server-side-injection",
	"client-side-path-traversal":     "exploiting-client-side-path-traversal",
	"cspt":                           "exploiting-client-side-path-traversal",
	"osrf":                           "exploiting-client-side-path-traversal",
	"csti":                           "exploiting-client-side-template-injection",
	"client-side-template-injection": "exploiting-client-side-template-injection",
	"ssi-injection":                  "exploiting-server-side-includes-esi-injection",
	"ssi":                            "exploiting-server-side-includes-esi-injection",
	"esi-injection":                  "exploiting-server-side-includes-esi-injection",
	"esi":                            "exploiting-server-side-includes-esi-injection",
	"orm-injection":                  "exploiting-orm-injection",
	"orm-leak":                       "exploiting-orm-injection",
	"dependency-confusion":           "exploiting-dependency-confusion",
	"dep-confusion":                  "exploiting-dependency-confusion",
	"postmessage":                    "exploiting-postmessage-vulnerabilities",
	"post-message":                   "exploiting-postmessage-vulnerabilities",
	"redos":                          "testing-for-regex-dos-redos",
	"regex-dos":                      "testing-for-regex-dos-redos",
	"cookie-hacking":                 "exploiting-cookie-based-vulnerabilities",
	"hop-by-hop":                     "abusing-hop-by-hop-headers",
	"hop-by-hop-headers":             "abusing-hop-by-hop-headers",
	"xs-search":                      "performing-xs-search-attacks",
	"xs-leaks":                       "performing-xs-search-attacks",
	"xsleaks":                        "performing-xs-search-attacks",
	"xssi":                           "exploiting-cross-site-script-inclusion-xssi",
	"reverse-tabnabbing":             "exploiting-reverse-tab-nabbing",
	"tabnabbing":                     "exploiting-reverse-tab-nabbing",
	"dangling-markup":                "exploiting-dangling-markup-injection",
	"scriptless-injection":           "exploiting-dangling-markup-injection",

	// ── Network-services-pentesting (per-service skills) ─────────────
	"ftp":             "pentesting-ftp",
	"ssh":             "pentesting-ssh",
	"telnet":          "pentesting-telnet",
	"smtp":            "pentesting-smtp",
	"imap":            "pentesting-imap",
	"pop3":            "pentesting-pop3",
	"pop":             "pentesting-pop3",
	"rsync":           "pentesting-rsync",
	"nfs":             "pentesting-nfs",
	"tftp":            "pentesting-tftp",
	"mysql":           "pentesting-mysql",
	"mssql":           "pentesting-mssql",
	"sql-server":      "pentesting-mssql",
	"postgresql":      "pentesting-postgresql",
	"postgres":        "pentesting-postgresql",
	"oracle":          "pentesting-oracle",
	"oracle-tns":      "pentesting-oracle",
	"redis":           "pentesting-redis",
	"mongodb":         "pentesting-mongodb",
	"mongo":           "pentesting-mongodb",
	"elasticsearch":   "pentesting-elasticsearch",
	"couchdb":         "pentesting-couchdb",
	"memcached":       "pentesting-memcached",
	"memcache":        "pentesting-memcached",
	"smb":             "pentesting-smb",
	"cifs":            "pentesting-smb",
	"netbios":         "pentesting-netbios",
	"msrpc":           "pentesting-msrpc",
	"rpc":             "pentesting-msrpc",
	"kerberos":        "pentesting-kerberos",
	"ldap-service":    "pentesting-ldap",
	"rdp":             "pentesting-rdp",
	"vnc":             "pentesting-vnc",
	"winrm":           "pentesting-winrm",
	"x11":             "pentesting-x11",
	"snmp":            "pentesting-snmp",
	"ntp":             "pentesting-ntp",
	"dns":             "pentesting-dns",
	"ipmi":            "pentesting-ipmi",
	"bmc":             "pentesting-ipmi",
	"docker-api":      "pentesting-docker",
	"docker-daemon":   "pentesting-docker",
	"docker-registry": "pentesting-docker-registry",
	"ajp":             "pentesting-ajp",
	"ghostcat":        "pentesting-ajp",
	"rabbitmq":        "pentesting-rabbitmq",
	"amqp":            "pentesting-rabbitmq",
	"voip":            "pentesting-voip",
	"sip":             "pentesting-voip",

	// ── Binary exploitation (HackTricks-derived) ─────────────────────

	// ── macOS security ───────────────────────────────────────────────

	// ── Linux hardening / post-exploitation ──────────────────────────
	"restricted-shell": "bypassing-restricted-shells",
	"rbash":            "bypassing-restricted-shells",
	"shell-escape":     "bypassing-restricted-shells",
	"freeipa":          "pentesting-freeipa",
	"pivoting":         "performing-network-pivoting-and-tunneling",
	"tunneling":        "performing-network-pivoting-and-tunneling",
	"port-forwarding":  "performing-network-pivoting-and-tunneling",

	// ── AI / LLM offensive security ──────────────────────────────────
	"model-rce":             "exploiting-ai-model-file-rce",
	"pickle-rce":            "exploiting-ai-model-file-rce",
	"model-deserialization": "exploiting-ai-model-file-rce",
	"prompt-injection":      "testing-llm-prompt-injection-and-jailbreaks",
	"jailbreak":             "testing-llm-prompt-injection-and-jailbreaks",
	"llm-injection":         "testing-llm-prompt-injection-and-jailbreaks",
	"web-llm-attacks":       "testing-llm-prompt-injection-and-jailbreaks",
	"mcp":                   "testing-mcp-server-security",
	"mcp-security":          "testing-mcp-server-security",
	"tool-poisoning":        "testing-mcp-server-security",

	// ── Auto-generated reachability aliases: one shorthand per skill
	// (verb-stripped slug). Generated by research/gen_aliases.py;
	// collision-checked against existing aliases and skill dir names.
	"sbom-for-supply-chain-vulnerabilities":       "analyzing-sbom-for-supply-chain-vulnerabilities",
	"api-recon":                                   "api-discovery",
	"aws-s3-bucket-permissions":                   "cloud-storage-exposure-testing",
	"gcp-iam-permissions":                         "gcp-cloud-pentesting",
	"terraform-infrastructure-for-security":       "auditing-terraform-infrastructure-for-security",
	"c2-infrastructure-with-sliver-framework":     "building-c2-infrastructure-with-sliver-framework",
	"devsecops-pipeline-with-gitlab-ci":           "building-devsecops-pipeline-with-gitlab-ci",
	"identity-federation-with-saml-azure-ad":      "building-identity-federation-with-saml-azure-ad",
	"identity-governance-lifecycle-process":       "building-identity-governance-lifecycle-process",
	"patch-tuesday-response-process":              "building-patch-tuesday-response-process",
	"red-team-c2-infrastructure-with-havoc":       "building-red-team-c2-infrastructure-with-havoc",
	"role-mining-for-rbac-optimization":           "building-role-mining-for-rbac-optimization",
	"vulnerability-aging-and-sla-tracking":        "building-vulnerability-aging-and-sla-tracking",
	"vulnerability-dashboard-with-defectdojo":     "building-vulnerability-dashboard-with-defectdojo",
	"vulnerability-exception-tracking-system":     "building-vulnerability-exception-tracking-system",
	"cloud-penetration-testing":                   "cloud-attack-surface-discovery",
	"domain-persistence-with-dcsync":              "conducting-domain-persistence-with-dcsync",
	"full-scope-red-team-engagement":              "conducting-full-scope-red-team-engagement",
	"internal-network-penetration-test":           "conducting-internal-network-penetration-test",
	"internal-reconnaissance-with-bloodhound-ce":  "conducting-internal-reconnaissance-with-bloodhound-ce",
	"mobile-app-penetration-test":                 "conducting-mobile-app-penetration-test",
	"network-penetration-test":                    "conducting-network-penetration-test",
	"pass-the-ticket-attack":                      "conducting-pass-the-ticket-attack",
	"social-engineering-penetration-test":         "conducting-social-engineering-penetration-test",
	"social-engineering-pretext-call":             "conducting-social-engineering-pretext-call",
	"wireless-network-penetration-test":           "conducting-wireless-network-penetration-test",
	"active-directory-tiered-model":               "configuring-active-directory-tiered-model",
	"certificate-authority-with-openssl":          "configuring-certificate-authority-with-openssl",
	"hsm-for-key-storage":                         "configuring-hsm-for-key-storage",
	"ldap-security-hardening":                     "configuring-ldap-security-hardening",
	"multi-factor-authentication-with-duo":        "configuring-multi-factor-authentication-with-duo",
	"oauth2-authorization-flow":                   "configuring-oauth2-authorization-flow",
	"tls-1-3-for-secure-communications":           "configuring-tls-1-3-for-secure-communications",
	"ai-model-prompt-injection-attacks":           "detecting-ai-model-prompt-injection-attacks",
	"anomalous-authentication-patterns":           "detecting-anomalous-authentication-patterns",
	"aws-credential-exposure-with-trufflehog":     "detecting-aws-credential-exposure-with-trufflehog",
	"broken-object-property-level-authorization":  "api-bopla",
	"typosquatting-packages-in-npm-pypi":          "detecting-typosquatting-packages-in-npm-pypi",
	"eadas":                                       "executing-active-directory-attack-simulation",
	"ertep":                                       "executing-red-team-engagement-planning",
	"erte":                                        "executing-red-team-exercise",
	"broken-function-level-authorization":         "api-bfla",
	"constrained-delegation-abuse":                "exploiting-constrained-delegation-abuse",
	"kerberoasting-with-impacket":                 "exploiting-kerberoasting-with-impacket",
	"ms17-010-eternalblue-vulnerability":          "exploiting-ms17-010-eternalblue-vulnerability",
	"nopac-cve-2021-42278-42287":                  "exploiting-nopac-cve-2021-42278-42287",
	"server-side-request-forgery":                 "exploiting-server-side-request-forgery",
	"vulnerabilities-with-metasploit-framework":   "exploiting-vulnerabilities-with-metasploit-framework",
	"zerologon-vulnerability-cve-2020-1472":       "exploiting-zerologon-vulnerability-cve-2020-1472",
	"aes-encryption-for-data-at-rest":             "implementing-aes-encryption-for-data-at-rest",
	"api-security-testing-with-42crunch":          "api-fuzzing-restler",
	"api-threat-protection-with-apigee":           "api-security-misconfiguration",
	"aqua-security-for-container-scanning":        "implementing-aqua-security-for-container-scanning",
	"attack-path-analysis-with-xm-cyber":          "implementing-attack-path-analysis-with-xm-cyber",
	"attack-surface-management":                   "implementing-attack-surface-management",
	"aws-iam-permission-boundaries":               "implementing-aws-iam-permission-boundaries",
	"aws-nitro-enclave-security":                  "implementing-aws-nitro-enclave-security",
	"cloud-vulnerability-posture-management":      "implementing-cloud-vulnerability-posture-management",
	"code-signing-for-artifacts":                  "implementing-code-signing-for-artifacts",
	"conditional-access-policies-azure-ad":        "implementing-conditional-access-policies-azure-ad",
	"continuous-security-validation-with-bas":     "implementing-continuous-security-validation-with-bas",
	"delinea-secret-server-for-pam":               "implementing-delinea-secret-server-for-pam",
	"devsecops-security-scanning":                 "implementing-devsecops-security-scanning",
	"digital-signatures-with-ed25519":             "implementing-digital-signatures-with-ed25519",
	"end-to-end-encryption-for-messaging":         "implementing-end-to-end-encryption-for-messaging",
	"envelope-encryption-with-aws-kms":            "implementing-envelope-encryption-with-aws-kms",
	"epss-score-for-vulnerability-prioritization": "implementing-epss-score-for-vulnerability-prioritization",
	"fuzz-testing-in-cicd-with-aflplusplus":       "implementing-fuzz-testing-in-cicd-with-aflplusplus",
	"github-advanced-security-for-code-scanning":  "implementing-github-advanced-security-for-code-scanning",
	"google-workspace-admin-security":             "implementing-google-workspace-admin-security",
	"google-workspace-sso-configuration":          "implementing-google-workspace-sso-configuration",
	"hardware-security-key-authentication":        "implementing-hardware-security-key-authentication",
	"hashicorp-vault-dynamic-secrets":             "implementing-hashicorp-vault-dynamic-secrets",
	"identity-governance-with-sailpoint":          "implementing-identity-governance-with-sailpoint",
	"infrastructure-as-code-security-scanning":    "implementing-infrastructure-as-code-security-scanning",
	"just-in-time-access-provisioning":            "implementing-just-in-time-access-provisioning",
	"llm-guardrails-for-security":                 "implementing-llm-guardrails-for-security",
	"pam-for-database-access":                     "implementing-pam-for-database-access",
	"passwordless-auth-with-microsoft-entra":      "implementing-passwordless-auth-with-microsoft-entra",
	"patch-management-workflow":                   "implementing-patch-management-workflow",
	"policy-as-code-with-open-policy-agent":       "implementing-policy-as-code-with-open-policy-agent",
	"privileged-access-management-with-cyberark":  "implementing-privileged-access-management-with-cyberark",
	"privileged-access-workstation":               "implementing-privileged-access-workstation",
	"privileged-session-monitoring":               "implementing-privileged-session-monitoring",
	"rapid7-insightvm-for-scanning":               "implementing-rapid7-insightvm-for-scanning",
	"rsa-key-pair-management":                     "implementing-rsa-key-pair-management",
	"runtime-application-self-protection":         "implementing-runtime-application-self-protection",
	"saml-sso-with-okta":                          "implementing-saml-sso-with-okta",
	"scim-provisioning-with-okta":                 "implementing-scim-provisioning-with-okta",
	"secret-scanning-with-gitleaks":               "implementing-secret-scanning-with-gitleaks",
	"secrets-management-with-vault":               "implementing-secrets-management-with-vault",
	"secrets-scanning-in-ci-cd":                   "implementing-secrets-scanning-in-ci-cd",
	"semgrep-for-custom-sast-rules":               "implementing-semgrep-for-custom-sast-rules",
	"sigstore-for-software-signing":               "implementing-sigstore-for-software-signing",
	"vulnerability-management-with-greenbone":     "implementing-vulnerability-management-with-greenbone",
	"vulnerability-remediation-sla":               "implementing-vulnerability-remediation-sla",
	"vulnerability-sla-breach-alerting":           "implementing-vulnerability-sla-breach-alerting",
	"web-application-logging-with-modsecurity":    "implementing-web-application-logging-with-modsecurity",
	"zero-knowledge-proof-for-authentication":     "implementing-zero-knowledge-proof-for-authentication",
	"zero-standing-privilege-with-cyberark":       "implementing-zero-standing-privilege-with-cyberark",
	"dast-with-owasp-zap-in-pipeline":             "integrating-dast-with-owasp-zap-in-pipeline",
	"sast-into-github-actions-pipeline":           "integrating-sast-into-github-actions-pipeline",
	"js-analysis":                                 "javascript-analysis",
	"cloud-identity-with-okta":                    "managing-cloud-identity-with-okta",
	"access-recertification-with-saviynt":         "performing-access-recertification-with-saviynt",
	"access-review-and-certification":             "performing-access-review-and-certification",
	"active-directory-bloodhound-analysis":        "performing-active-directory-bloodhound-analysis",
	"active-directory-forest-trust-attack":        "performing-active-directory-forest-trust-attack",
	"active-directory-vulnerability-assessment":   "performing-active-directory-vulnerability-assessment",
	"agentless-vulnerability-scanning":            "performing-agentless-vulnerability-scanning",
	"ai-assisted-vulnerability-discovery":         "performing-ai-assisted-vulnerability-discovery",
	"api-fuzzing-with-restler":                    "api-fuzzing-restler",
	"api-inventory-and-discovery":                 "api-discovery",
	"api-rate-limiting-bypass":                    "api-resource-consumption",
	"api-security-testing-with-postman":           "conducting-api-security-testing",
	"asset-criticality-scoring-for-vulns":         "performing-asset-criticality-scoring-for-vulns",
	"authenticated-scan-with-openvas":             "performing-authenticated-scan-with-openvas",
	"authenticated-vulnerability-scan":            "performing-authenticated-vulnerability-scan",
	"aws-account-enumeration-with-scout-suite":    "aws-cloud-pentesting",
	"aws-privilege-escalation-assessment":         "aws-iam-privilege-escalation",
	"binary-exploitation-analysis":                "performing-binary-exploitation-analysis",
	"cloud-asset-inventory-with-cartography":      "cloud-attack-surface-discovery",
	"cloud-penetration-testing-with-pacu":         "aws-cloud-pentesting",
	"container-image-hardening":                   "performing-container-image-hardening",
	"credential-access-with-lazagne":              "performing-credential-access-with-lazagne",
	"cryptographic-audit-of-application":          "performing-cryptographic-audit-of-application",
	"cve-prioritization-with-kev-catalog":         "performing-cve-prioritization-with-kev-catalog",
	"entitlement-review-with-sailpoint-iiq":       "performing-entitlement-review-with-sailpoint-iiq",
	"external-network-penetration-test":           "performing-external-network-penetration-test",
	"gcp-penetration-testing-with-gcpbucketbrute": "cloud-storage-exposure-testing",
	"gcp-security-assessment-with-forseti":        "gcp-cloud-pentesting",
	"graphql-depth-limit-attack":                  "graphql-api-security",
	"graphql-introspection-attack":                "graphql-api-security",
	"hardware-security-module-integration":        "performing-hardware-security-module-integration",
	"hash-cracking-with-hashcat":                  "performing-hash-cracking-with-hashcat",
	"initial-access-with-evilginx3":               "performing-initial-access-with-evilginx3",
	"internal-network-pentesting":                 "performing-internal-network-pentesting",
	"iot-security-assessment":                     "performing-iot-security-assessment",
	"jwt-none-algorithm-attack":                   "jwt-security-testing",
	"kerberoasting-attack":                        "performing-kerberoasting-attack",
	"lateral-movement-with-wmiexec":               "performing-lateral-movement-with-wmiexec",
	"network-tunneling-and-pivoting":              "performing-network-tunneling-and-pivoting",
	"oauth-scope-minimization-review":             "performing-oauth-scope-minimization-review",
	"physical-intrusion-assessment":               "performing-physical-intrusion-assessment",
	"post-quantum-cryptography-migration":         "performing-post-quantum-cryptography-migration",
	"privilege-escalation-assessment":             "performing-privilege-escalation-assessment",
	"privilege-escalation-on-linux":               "performing-privilege-escalation-on-linux",
	"privileged-account-access-review":            "performing-privileged-account-access-review",
	"privileged-account-discovery":                "performing-privileged-account-discovery",
	"red-team-with-covenant":                      "performing-red-team-with-covenant",
	"sca-dependency-scanning-with-snyk":           "performing-sca-dependency-scanning-with-snyk",
	"security-headers-audit":                      "performing-security-headers-audit",
	"serverless-function-security-review":         "serverless-cloud-security",
	"service-account-audit":                       "performing-service-account-audit",
	"service-account-credential-rotation":         "performing-service-account-credential-rotation",
	"soap-web-service-security-testing":           "soap-api-security",
	"ssl-certificate-lifecycle-management":        "performing-ssl-certificate-lifecycle-management",
	"supply-chain-attack-simulation":              "performing-supply-chain-attack-simulation",
	"thick-client-application-penetration-test":   "performing-thick-client-application-penetration-test",
	"threat-modeling-with-owasp-threat-dragon":    "performing-threat-modeling-with-owasp-threat-dragon",
	"vulnerability-scanning-with-nessus":          "performing-vulnerability-scanning-with-nessus",
	"web-application-penetration-test":            "performing-web-application-penetration-test",
	"web-application-scanning-with-nikto":         "performing-web-application-scanning-with-nikto",
	"web-application-vulnerability-triage":        "performing-web-application-vulnerability-triage",
	"wnpt":                                        "performing-wireless-network-penetration-test",
	"prioritizing-vulnerabilities":                "prioritizing-vulnerabilities-with-cvss-scoring",
	"containers-with-trivy-in-cicd":               "scanning-containers-with-trivy-in-cicd",
	"infrastructure-with-nessus":                  "scanning-infrastructure-with-nessus",
	"aws-iam-permissions":                         "securing-aws-iam-permissions",
	"aws-lambda-execution-roles":                  "serverless-cloud-security",
	"container-registry-images":                   "securing-container-registry-images",
	"github-actions-workflows":                    "securing-github-actions-workflows",
	"serverless-functions":                        "serverless-cloud-security",
	"subs":                                        "subdomain-enumeration",
	"api-authentication-weaknesses":               "api-authentication-session",
	"api-for-broken-object-level-authorization":   "api-bola",
	"api-for-mass-assignment-vulnerability":       "api-bopla",
	"api-security-with-owasp-top-10":              "testing-api-security-with-owasp-top-10",
	"for-json-web-token-vulnerabilities":          "testing-for-json-web-token-vulnerabilities",
	"jwt-token-security":                          "testing-jwt-token-security",
	"oauth2-implementation-flaws":                 "oauth-oidc-security",
	"websocket-api-security":                      "websocket-api-security",
	"vulnerabilities-with-ssvc-framework":         "triaging-vulnerabilities-with-ssvc-framework",
}

// resolveAlias returns the canonical skill name for a shorthand alias.
// If no alias matches, the original name is returned unchanged.
// Underscores are normalized to dashes before lookup so that old-style
// names (e.g. "nosql_injection") resolve via the dash-keyed alias map.
func resolveAlias(name string) string {
	key := strings.ToLower(name)
	key = strings.ReplaceAll(key, "_", "-")
	if canonical, ok := skillAliases[key]; ok {
		return canonical
	}
	return name
}

func makeReadSkill(fsys fs.FS) func(args map[string]string) (tools.Result, error) {
	return makeReadSkillWithState(fsys, nil, nil)
}

func makeReadSkillWithState(fsys fs.FS, r *tools.Registry, state *agentSkillState) func(args map[string]string) (tools.Result, error) {
	return func(args map[string]string) (tools.Result, error) {
		name := strings.TrimSpace(args["name"])
		category := strings.TrimSpace(args["category"])

		// Sanitize category (only allow alphanum and dash)
		category = sanitizeSlug(category)

		if name == "" {
			return tools.Result{Error: "skill name is required"}, nil
		}

		// Strip a trailing /SKILL.md, .md, or any extension the user supplied,
		// then sanitize. This accepts both old-style ("sql_injection") and
		// kebab-case names as exposed by list_skills.
		name = strings.TrimSuffix(name, "/SKILL.md")
		name = strings.TrimSuffix(name, ".md")
		name = sanitizeSlug(name)
		if name == "" {
			return tools.Result{Error: "skill name is empty after sanitization"}, nil
		}

		// Resolve canonical skill identity via alias map.
		canonicalName := resolveAlias(name)

		var (
			rawContent    string
			foundCategory string
			found         bool
		)

		// Lookup is literal-first, alias-fallback: if a real skill matches the
		// name as given we use it; only when no literal match exists do we
		// resolve an alias and retry. This keeps short aliases (lfi, sqli,
		// graphql, rce, …) working without shadowing any skill whose directory
		// name happens to equal an alias key.
		if out, where, ok := lookupSkill(fsys, category, name); ok {
			rawContent = out
			foundCategory = where
			found = true
			if alias := resolveAlias(name); alias != name {
				canonicalName = alias
			} else {
				canonicalName = name
			}
		} else if alias := resolveAlias(name); alias != name {
			if out, where, ok := lookupSkill(fsys, category, alias); ok {
				rawContent = out
				foundCategory = where
				found = true
				canonicalName = alias
			}
		}

		if !found {
			// Best-effort hint when the user has a near-match name.
			hint := fuzzyHint(fsys, name)
			errMsg := fmt.Sprintf("skill not found: %s — use list_skills to see available skills", name)
			if hint != "" {
				errMsg += "\nDid you mean: " + hint
			}
			return tools.Result{Error: errMsg}, nil
		}

		fullOutput := noteIfCrossCategory(category, foundCategory, rawContent)

		// If state or registry is nil, return full content (graceful fallback).
		if state == nil || r == nil {
			return tools.Result{Output: fullOutput}, nil
		}

		contentHash := fmt.Sprintf("%x", sha256.Sum256([]byte(fullOutput)))

		state.mu.Lock()
		existing, exists := state.loadedSkills[canonicalName]
		if exists && existing.contentHash == contentHash && r.HasActiveContent(existing.fullContent) {
			state.mu.Unlock()
			suppressedMsg := fmt.Sprintf("Skill already loaded in the current active context: %s. The complete methodology remains available earlier in this conversation.", canonicalName)
			// Tag the result so runtime accounting can distinguish a
			// suppressed duplicate from a genuinely new canonical load.
			return tools.Result{Output: suppressedMsg, Metadata: map[string]any{
				"skill_name":      canonicalName,
				"skill_duplicate": true,
			}}, nil
		}

		// First load, content changed, or pruned from active context.
		state.loadedSkills[canonicalName] = loadedSkillRecord{
			canonicalName: canonicalName,
			contentHash:   contentHash,
			fullContent:   fullOutput,
		}
		state.mu.Unlock()

		// Tag the canonical name so runtime skill accounting counts successful
		// canonical loads (never failed lookups or duplicates) — the
		// first-class signal for skill-usage telemetry and recommendations.
		return tools.Result{Output: fullOutput, Metadata: map[string]any{
			"skill_name": canonicalName,
		}}, nil
	}
}

// ResolveSkillName resolves a concept query or shorthand alias to one
// canonical skill name, using the alias map first and the lexical search
// index second. It is the small deterministic skill-resolution layer the
// runtime (planner/specialist lanes) consults to attach methodology to
// planned work — no embeddings, no external service. The second return is
// false when nothing scores strongly enough to be a confident resolution.
func ResolveSkillName(query string) (string, bool) {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return "", false
	}
	// Alias-first: exact shorthand hits are the strongest possible resolution.
	if slug := sanitizeSlug(q); slug != "" {
		if alias := resolveAlias(slug); alias != slug && alias != "" {
			return alias, true
		}
	}
	return bestSkillMatch(embeddedSkillsDataFS, q)
}

// bestSkillMatch runs the same lexical + intent scoring as search_skills and
// returns the single best canonical name when its score clears the resolution
// threshold.
func bestSkillMatch(fsys fs.FS, query string) (string, bool) {
	tokens := strings.FieldsFunc(query, func(r rune) bool {
		return r == ' ' || r == ',' || r == '\t' || r == '\n' || r == '/'
	})
	terms := make([]string, 0, len(tokens))
	for _, t := range tokens {
		if len(t) >= 2 {
			terms = append(terms, t)
		}
	}
	if len(terms) == 0 {
		terms = []string{query}
	}
	best, bestScore := "", 0
	for _, m := range buildSkillIndex(fsys) {
		score := 0
		for _, term := range terms {
			if strings.Contains(strings.ToLower(m.name), term) {
				score += 3
			}
			if strings.Contains(m.haystack, term) {
				score += 1
			}
		}
		if strings.Contains(m.haystack, query) {
			score += 3
		}
		if score > 0 {
			switch {
			case queryWantsDefensive(query) && m.intent == "defensive":
				score += 6
			case m.intent == "offensive":
				score += 4
			}
		}
		if score > bestScore || (score == bestScore && best != "" && m.name < best) {
			best, bestScore = m.name, score
		}
	}
	// Threshold 4: a name-token match from an offensive skill (3+4), or a
	// name + frontmatter match (4), resolves; single weak haystack hits (1)
	// or defensive hits on offensive queries do not.
	if bestScore < 4 || best == "" {
		return "", false
	}
	return best, true
}

// lookupSkill resolves <name>/SKILL.md, preferring the supplied category and
// falling back to a scan of every category. Returns the file contents, the
// category it was found under, and whether it was found.
func lookupSkill(fsys fs.FS, category, name string) (string, string, bool) {
	if category != "" {
		if data, err := fs.ReadFile(fsys, category+"/"+name+"/SKILL.md"); err == nil {
			return string(data), category, true
		}
	}
	if found, where := searchAllCategories(fsys, name); found != "" {
		return found, where, true
	}
	return "", "", false
}

// noteIfCrossCategory prepends an informational note when a skill requested
// under one category was actually found in another.
func noteIfCrossCategory(requested, found, out string) string {
	if requested != "" && found != requested {
		return fmt.Sprintf("Note: skill not found in category '%s'; loaded from '%s'.\n\n%s",
			requested, found, out)
	}
	return out
}

// sanitizeSlug keeps only alphanumerics, dash, and underscore. This both
// prevents path traversal and normalizes user input.
func sanitizeSlug(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-' || r == '_':
			return r
		}
		return -1
	}, s)
}

// searchAllCategories looks up `<category>/<name>/SKILL.md` across every
// category directory currently embedded. Returns the file contents and the
// category it was found under.
func searchAllCategories(fsys fs.FS, name string) (string, string) {
	for _, cat := range listCategories(fsys) {
		path := cat + "/" + name + "/SKILL.md"
		if data, err := fs.ReadFile(fsys, path); err == nil {
			return string(data), cat
		}
	}
	return "", ""
}

// fuzzyHint returns up to 3 skill names whose lowercase form contains the
// query as a substring. Used to nudge the LLM toward a valid name when a
// lookup fails. Empty string when no candidates match.
func fuzzyHint(fsys fs.FS, query string) string {
	q := strings.ToLower(query)
	if q == "" {
		return ""
	}
	var matches []string
	for _, cat := range listCategories(fsys) {
		entries, err := fs.ReadDir(fsys, cat)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			n := e.Name()
			if strings.Contains(strings.ToLower(n), q) {
				matches = append(matches, n)
				if len(matches) >= 3 {
					return strings.Join(matches, ", ")
				}
			}
		}
	}
	return strings.Join(matches, ", ")
}

func makeListSkills(fsys fs.FS) func(args map[string]string) (tools.Result, error) {
	return makeListSkillsWithState(fsys, nil, nil)
}

func makeListSkillsWithState(fsys fs.FS, r *tools.Registry, state *agentSkillState) func(args map[string]string) (tools.Result, error) {
	return func(args map[string]string) (tools.Result, error) {
		filterCat := strings.TrimSpace(args["category"])
		filterCat = sanitizeSlug(filterCat)

		var categories []string
		if filterCat != "" {
			categories = []string{filterCat}
		} else {
			categories = listCategories(fsys)
		}

		var b strings.Builder
		b.WriteString("Available Skills\n\n")

		totalSkills := 0
		for _, cat := range categories {
			entries, err := fs.ReadDir(fsys, cat)
			if err != nil {
				continue
			}

			var skills []string
			for _, e := range entries {
				// Only list directories (skill packages)
				if !e.IsDir() || e.Name() == ".gitkeep" {
					continue
				}
				skills = append(skills, e.Name())
			}

			if len(skills) == 0 {
				continue
			}

			sort.Strings(skills)
			totalSkills += len(skills)

			b.WriteString(fmt.Sprintf("### %s (%d skills)\n", strings.ToUpper(cat), len(skills)))
			for _, s := range skills {
				b.WriteString(fmt.Sprintf("  - %s\n", s))
			}
			b.WriteString("\n")
		}

		b.WriteString(fmt.Sprintf("Total: %d skills available\n", totalSkills))
		b.WriteString("\nUsage: read_skill(name=\"skill_name\")  -- category is optional\n")

		fullOutput := b.String()

		if state == nil || r == nil {
			return tools.Result{Output: fullOutput}, nil
		}

		contentHash := fmt.Sprintf("%x", sha256.Sum256([]byte(fullOutput)))

		state.mu.Lock()
		existing, exists := state.loadedLists[filterCat]
		if exists && existing.contentHash == contentHash && r.HasActiveContent(existing.fullContent) {
			state.mu.Unlock()
			catDesc := "all categories"
			if filterCat != "" {
				catDesc = fmt.Sprintf("category %q", filterCat)
			}
			suppressedMsg := fmt.Sprintf("Skills list already loaded in the current active context for %s. The complete catalog remains available earlier in this conversation.", catDesc)
			return tools.Result{Output: suppressedMsg}, nil
		}

		state.loadedLists[filterCat] = loadedListRecord{
			contentHash: contentHash,
			fullContent: fullOutput,
		}
		state.mu.Unlock()

		return tools.Result{Output: fullOutput}, nil
	}
}
