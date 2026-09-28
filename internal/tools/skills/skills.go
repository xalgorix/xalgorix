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
	subFS, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		// Should not happen unless embed is empty
		subFS = embeddedSkills
	}
	state := newAgentSkillState()
	r.Register(&tools.Tool{
		Name:        "read_skill",
		Description: "Load a structured cybersecurity skill to get deep testing/defense methodology, tooling commands, and verification steps. Use this BEFORE attempting work in a specific domain (e.g., read_skill name=analyzing-active-directory-acl-abuse). The skill catalog is sourced from the agentskills.io standard and covers offensive testing, threat hunting, DFIR, cloud, mobile, OT/ICS, AI security, and more. Don't know the exact name? Use search_skills query='<concept>' to find the right skill, or list_skills to browse categories.",
		Parameters: []tools.Parameter{
			{Name: "name", Description: "Kebab-case skill name without extension (e.g., performing-memory-forensics-with-volatility3, analyzing-active-directory-acl-abuse). Use list_skills to discover names.", Required: true},
			{Name: "category", Description: "Optional category to disambiguate (e.g., web-application-security, threat-hunting, reconnaissance). If omitted, all categories are searched.", Required: false},
		},
		Execute: makeReadSkillWithState(subFS, r, state),
	})

	r.Register(&tools.Tool{
		Name:        "list_skills",
		Description: "List all available skills organized by category. Call this to see what deep knowledge is available before deciding which skills to load for your current engagement.",
		Parameters: []tools.Parameter{
			{Name: "category", Description: "Optional category filter (e.g., web-application-security, malware-analysis, reconnaissance). Omit to list all.", Required: false},
		},
		Execute: makeListSkillsWithState(subFS, r, state),
	})

	r.Register(&tools.Tool{
		Name:        "search_skills",
		Description: "Search the skill catalog by keywords/concept and get the most relevant skills ranked, each with its category, name, and description. Use this when you don't know a skill's exact name — e.g. search_skills query='oauth token theft' or query='payment price tampering'. Then load the best match with read_skill. Far faster than scanning list_skills across 800+ skills.",
		Parameters: []tools.Parameter{
			{Name: "query", Description: "Keywords or a short phrase describing what you want (e.g. 'graphql batching', 'reset password poisoning', 'kubernetes pod escape').", Required: true},
			{Name: "category", Description: "Optional category filter (e.g., web-application-security, cloud-security).", Required: false},
			{Name: "max", Description: "Max results to return (default 10, hard cap 25).", Required: false},
		},
		Execute: makeSearchSkills(subFS),
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
	"ssrf":                             "performing-ssrf-vulnerability-exploitation",
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
	"command-injection":        "exploiting-os-command-injection",
	"os-command-injection":     "exploiting-os-command-injection",
	"rce":                      "exploiting-os-command-injection",
	"remote-code-execution":    "exploiting-os-command-injection",
	"shell-injection":          "exploiting-os-command-injection",
	"modbus-command-injection": "detecting-modbus-command-injection-attacks",

	// ── Authentication & authorization ───────────────────────────────
	"jwt":                "jwt-security-testing",
	"jwt-attack":         "jwt-security-testing",
	"authentication-jwt": "jwt-security-testing",
	"jwt-signing":        "implementing-jwt-signing-and-verification",
	"oauth":              "exploiting-oauth-misconfiguration",
	"oauth-misconfig":    "exploiting-oauth-misconfiguration",
	"oauth2-attacks":     "exploiting-oauth-misconfiguration",
	"oauth-token-theft":  "detecting-oauth-token-theft",
	"forced-browsing":    "bypassing-authentication-with-forced-browsing",
	"brute-force":        "detecting-rdp-brute-force-attacks",
	"passwordless":       "implementing-passwordless-authentication-with-fido2",
	"fido2":              "implementing-passwordless-authentication-with-fido2",

	// ── Reconnaissance ───────────────────────────────────────────────
	"recon":             "conducting-external-reconnaissance-with-osint",
	"reconnaissance":    "conducting-external-reconnaissance-with-osint",
	"osint":             "performing-open-source-intelligence-gathering",
	"subdomain":         "performing-subdomain-enumeration-with-subfinder",
	"subdomain-enum":    "performing-subdomain-enumeration-with-subfinder",
	"subfinder":         "performing-subdomain-enumeration-with-subfinder",
	"nmap":              "scanning-network-with-nmap-advanced",
	"network-scan":      "scanning-network-with-nmap-advanced",
	"api-enumeration":   "api-bola",
	"shadow-api":        "api-discovery",
	"cert-transparency": "analyzing-certificate-transparency-for-phishing",

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
	"dcsync":           "detecting-dcsync-attack-in-active-directory",
	"ad-cert":          "exploiting-active-directory-certificate-services-esc1",

	// ── Lateral movement & privilege escalation ──────────────────────
	"lateral-movement":     "detecting-lateral-movement-in-network",
	"privilege-escalation": "detecting-privilege-escalation-attempts",
	"privesc":              "detecting-privilege-escalation-attempts",
	"aws-privesc":          "detecting-aws-iam-privilege-escalation",
	"azure-lateral":        "detecting-azure-lateral-movement",
	"dcom":                 "hunting-for-dcom-lateral-movement",
	"wmi":                  "hunting-for-lateral-movement-via-wmi",

	// ── Phishing ─────────────────────────────────────────────────────
	"phishing":            "conducting-phishing-incident-response",
	"spearphishing":       "conducting-spearphishing-simulation-campaign",
	"phishing-simulation": "executing-phishing-simulation-campaign",
	"qr-phishing":         "detecting-qr-code-phishing-with-email-security",
	"email-headers":       "analyzing-email-headers-for-phishing-investigation",

	// ── Cloud & Kubernetes ───────────────────────────────────────────
	"k8s-privesc":    "detecting-privilege-escalation-in-kubernetes-pods",
	"opa-gatekeeper": "implementing-opa-gatekeeper-for-policy-enforcement",
	"azure-ad":       "auditing-azure-active-directory-configuration",
	"azure-pim":      "implementing-azure-ad-privileged-identity-management",

	// ── Memory / binary exploitation ─────────────────────────────────
	"heap-spray": "analyzing-heap-spray-exploitation",

	// ── Detection & monitoring ───────────────────────────────────────
	"sql-injection-waf": "detecting-sql-injection-via-waf-logs",
	"lateral-splunk":    "detecting-lateral-movement-with-splunk",
	"lateral-zeek":      "detecting-lateral-movement-with-zeek",

	// ── Mobile ───────────────────────────────────────────────────────
	"burpsuite-mobile": "intercepting-mobile-traffic-with-burpsuite",
	"burp":             "intercepting-mobile-traffic-with-burpsuite",

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
	"darkweb": "monitoring-darkweb-sources",
	"dmarc":   "performing-dmarc-policy-enforcement-rollout",

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
	"stack-overflow":       "exploiting-stack-buffer-overflows",
	"buffer-overflow":      "exploiting-stack-buffer-overflows",
	"bof":                  "exploiting-stack-buffer-overflows",
	"format-string":        "exploiting-format-string-vulnerabilities",
	"fmtstr":               "exploiting-format-string-vulnerabilities",
	"rop":                  "performing-return-oriented-programming",
	"ret2libc":             "performing-return-oriented-programming",
	"mitigation-bypass":    "bypassing-binary-exploitation-mitigations",
	"aslr-bypass":          "bypassing-binary-exploitation-mitigations",
	"nx-bypass":            "bypassing-binary-exploitation-mitigations",
	"canary-bypass":        "bypassing-binary-exploitation-mitigations",
	"heap-exploitation":    "exploiting-glibc-heap-vulnerabilities",
	"glibc-heap":           "exploiting-glibc-heap-vulnerabilities",
	"tcache":               "exploiting-glibc-heap-vulnerabilities",
	"integer-overflow":     "exploiting-integer-overflow-vulnerabilities",
	"kernel-exploitation":  "exploiting-linux-kernel-vulnerabilities",
	"linux-kernel-exploit": "exploiting-linux-kernel-vulnerabilities",
	"windows-exploitation": "performing-windows-binary-exploitation",
	"seh-overflow":         "performing-windows-binary-exploitation",
	"arbitrary-write":      "exploiting-arbitrary-write-to-execution",
	"write-what-where":     "exploiting-arbitrary-write-to-execution",
	"got-overwrite":        "exploiting-arbitrary-write-to-execution",

	// ── macOS security ───────────────────────────────────────────────
	"macos-privesc":     "performing-macos-privilege-escalation",
	"macos-red-team":    "performing-macos-red-teaming",
	"gatekeeper":        "bypassing-macos-gatekeeper-tcc-and-sip",
	"tcc":               "bypassing-macos-gatekeeper-tcc-and-sip",
	"macos-sip":         "bypassing-macos-gatekeeper-tcc-and-sip",
	"macos-persistence": "analyzing-macos-persistence-and-autostart",
	"dyld-hijacking":    "exploiting-macos-dyld-hijacking-and-process-injection",
	"dylib-hijacking":   "exploiting-macos-dyld-hijacking-and-process-injection",

	// ── Linux hardening / post-exploitation ──────────────────────────
	"restricted-shell":        "bypassing-restricted-shells",
	"rbash":                   "bypassing-restricted-shells",
	"shell-escape":            "bypassing-restricted-shells",
	"linux-capabilities":      "exploiting-linux-capabilities",
	"capabilities":            "exploiting-linux-capabilities",
	"sudo-privesc":            "exploiting-sudo-suid-and-cron-misconfigurations",
	"suid":                    "exploiting-sudo-suid-and-cron-misconfigurations",
	"gtfobins":                "exploiting-sudo-suid-and-cron-misconfigurations",
	"linux-privesc":           "exploiting-sudo-suid-and-cron-misconfigurations",
	"linux-post-exploitation": "performing-linux-post-exploitation",
	"freeipa":                 "pentesting-freeipa",
	"dbus":                    "exploiting-dbus-and-socket-command-injection",
	"socket-injection":        "exploiting-dbus-and-socket-command-injection",
	"pivoting":                "performing-network-pivoting-and-tunneling",
	"tunneling":               "performing-network-pivoting-and-tunneling",
	"port-forwarding":         "performing-network-pivoting-and-tunneling",
	"container-escape":        "exploiting-container-escapes",
	"docker-escape":           "exploiting-container-escapes",
	"container-breakout":      "exploiting-container-escapes",

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
	"disk-image-with-dd-and-dcfldd":                       "acquiring-disk-image-with-dd-and-dcfldd",
	"android-malware-with-apktool":                        "analyzing-android-malware-with-apktool",
	"api-gateway-access-logs":                             "analyzing-api-gateway-access-logs",
	"apt-group-with-mitre-navigator":                      "analyzing-apt-group-with-mitre-navigator",
	"azure-activity-logs-for-threats":                     "analyzing-azure-activity-logs-for-threats",
	"bootkit-and-rootkit-samples":                         "analyzing-bootkit-and-rootkit-samples",
	"browser-forensics-with-hindsight":                    "analyzing-browser-forensics-with-hindsight",
	"campaign-attribution-evidence":                       "analyzing-campaign-attribution-evidence",
	"cloud-storage-access-patterns":                       "analyzing-cloud-storage-access-patterns",
	"cobalt-strike-beacon-configuration":                  "analyzing-cobalt-strike-beacon-configuration",
	"cobaltstrike-malleable-c2-profiles":                  "analyzing-cobaltstrike-malleable-c2-profiles",
	"command-and-control-communication":                   "analyzing-command-and-control-communication",
	"cyber-kill-chain":                                    "analyzing-cyber-kill-chain",
	"disk-image-with-autopsy":                             "analyzing-disk-image-with-autopsy",
	"dns-logs-for-exfiltration":                           "analyzing-dns-logs-for-exfiltration",
	"docker-container-forensics":                          "analyzing-docker-container-forensics",
	"ethereum-smart-contract-vulnerabilities":             "analyzing-ethereum-smart-contract-vulnerabilities",
	"golang-malware-with-ghidra":                          "analyzing-golang-malware-with-ghidra",
	"ioc":                                                 "analyzing-indicators-of-compromise",
	"ios-app-security-with-objection":                     "analyzing-ios-app-security-with-objection",
	"kubernetes-audit-logs":                               "analyzing-kubernetes-audit-logs",
	"linux-audit-logs-for-intrusion":                      "analyzing-linux-audit-logs-for-intrusion",
	"linux-elf-malware":                                   "analyzing-linux-elf-malware",
	"linux-kernel-rootkits":                               "analyzing-linux-kernel-rootkits",
	"linux-system-artifacts":                              "analyzing-linux-system-artifacts",
	"lnk-file-and-jump-list-artifacts":                    "analyzing-lnk-file-and-jump-list-artifacts",
	"macro-malware-in-office-documents":                   "analyzing-macro-malware-in-office-documents",
	"malicious-pdf-with-peepdf":                           "analyzing-malicious-pdf-with-peepdf",
	"malicious-url-with-urlscan":                          "analyzing-malicious-url-with-urlscan",
	"malware-behavior-with-cuckoo-sandbox":                "analyzing-malware-behavior-with-cuckoo-sandbox",
	"malware-family-relationships-with-malpedia":          "analyzing-malware-family-relationships-with-malpedia",
	"malware-persistence-with-autoruns":                   "analyzing-malware-persistence-with-autoruns",
	"malware-sandbox-evasion-techniques":                  "analyzing-malware-sandbox-evasion-techniques",
	"memory-dumps-with-volatility":                        "analyzing-memory-dumps-with-volatility",
	"memory-forensics-with-lime-and-volatility":           "analyzing-memory-forensics-with-lime-and-volatility",
	"mft-for-deleted-file-recovery":                       "analyzing-mft-for-deleted-file-recovery",
	"network-covert-channels-in-malware":                  "analyzing-network-covert-channels-in-malware",
	"network-flow-data-with-netflow":                      "analyzing-network-flow-data-with-netflow",
	"network-packets-with-scapy":                          "analyzing-network-packets-with-scapy",
	"network-traffic-for-incidents":                       "analyzing-network-traffic-for-incidents",
	"network-traffic-of-malware":                          "analyzing-network-traffic-of-malware",
	"network-traffic-with-wireshark":                      "analyzing-network-traffic-with-wireshark",
	"office365-audit-logs-for-compromise":                 "analyzing-office365-audit-logs-for-compromise",
	"outlook-pst-for-email-forensics":                     "analyzing-outlook-pst-for-email-forensics",
	"packed-malware-with-upx-unpacker":                    "analyzing-packed-malware-with-upx-unpacker",
	"pdf-malware-with-pdfid":                              "analyzing-pdf-malware-with-pdfid",
	"persistence-mechanisms-in-linux":                     "analyzing-persistence-mechanisms-in-linux",
	"powershell-empire-artifacts":                         "analyzing-powershell-empire-artifacts",
	"powershell-script-block-logging":                     "analyzing-powershell-script-block-logging",
	"prefetch-files-for-execution-history":                "analyzing-prefetch-files-for-execution-history",
	"ransomware-encryption-mechanisms":                    "analyzing-ransomware-encryption-mechanisms",
	"ransomware-leak-site-intelligence":                   "analyzing-ransomware-leak-site-intelligence",
	"ransomware-network-indicators":                       "analyzing-ransomware-network-indicators",
	"ransomware-payment-wallets":                          "analyzing-ransomware-payment-wallets",
	"sbom-for-supply-chain-vulnerabilities":               "analyzing-sbom-for-supply-chain-vulnerabilities",
	"security-logs-with-splunk":                           "analyzing-security-logs-with-splunk",
	"slack-space-and-file-system-artifacts":               "analyzing-slack-space-and-file-system-artifacts",
	"supply-chain-malware-artifacts":                      "analyzing-supply-chain-malware-artifacts",
	"threat-actor-ttps-with-mitre-attack":                 "analyzing-threat-actor-ttps-with-mitre-attack",
	"threat-actor-ttps-with-mitre-navigator":              "analyzing-threat-actor-ttps-with-mitre-navigator",
	"threat-intelligence-feeds":                           "analyzing-threat-intelligence-feeds",
	"threat-landscape-with-misp":                          "analyzing-threat-landscape-with-misp",
	"tls-certificate-transparency-logs":                   "analyzing-tls-certificate-transparency-logs",
	"typosquatting-domains-with-dnstwist":                 "analyzing-typosquatting-domains-with-dnstwist",
	"uefi-bootkit-persistence":                            "analyzing-uefi-bootkit-persistence",
	"usb-device-connection-history":                       "analyzing-usb-device-connection-history",
	"web-server-logs-for-intrusion":                       "analyzing-web-server-logs-for-intrusion",
	"windows-amcache-artifacts":                           "analyzing-windows-amcache-artifacts",
	"windows-event-logs-in-splunk":                        "analyzing-windows-event-logs-in-splunk",
	"windows-lnk-files-for-artifacts":                     "analyzing-windows-lnk-files-for-artifacts",
	"windows-prefetch-with-python":                        "analyzing-windows-prefetch-with-python",
	"windows-registry-for-artifacts":                      "analyzing-windows-registry-for-artifacts",
	"windows-shellbag-artifacts":                          "analyzing-windows-shellbag-artifacts",
	"api-recon":                                           "api-discovery",
	"aws-s3-bucket-permissions":                           "cloud-storage-exposure-testing",
	"cloud-with-cis-benchmarks":                           "auditing-cloud-with-cis-benchmarks",
	"gcp-iam-permissions":                                 "gcp-cloud-pentesting",
	"kubernetes-cluster-rbac":                             "auditing-kubernetes-cluster-rbac",
	"terraform-infrastructure-for-security":               "auditing-terraform-infrastructure-for-security",
	"tctl":                                                "auditing-tls-certificate-transparency-logs",
	"ioc-enrichment":                                      "automating-ioc-enrichment",
	"adversary-infrastructure-tracking-system":            "building-adversary-infrastructure-tracking-system",
	"attack-pattern-library-from-cti-reports":             "building-attack-pattern-library-from-cti-reports",
	"automated-malware-submission-pipeline":               "building-automated-malware-submission-pipeline",
	"c2-infrastructure-with-sliver-framework":             "building-c2-infrastructure-with-sliver-framework",
	"cloud-siem-with-sentinel":                            "building-cloud-siem-with-sentinel",
	"detection-rule-with-splunk-spl":                      "building-detection-rule-with-splunk-spl",
	"detection-rules-with-sigma":                          "building-detection-rules-with-sigma",
	"devsecops-pipeline-with-gitlab-ci":                   "building-devsecops-pipeline-with-gitlab-ci",
	"identity-federation-with-saml-azure-ad":              "building-identity-federation-with-saml-azure-ad",
	"identity-governance-lifecycle-process":               "building-identity-governance-lifecycle-process",
	"incident-response-dashboard":                         "building-incident-response-dashboard",
	"incident-response-playbook":                          "building-incident-response-playbook",
	"incident-timeline-with-timesketch":                   "building-incident-timeline-with-timesketch",
	"ioc-defanging-and-sharing-pipeline":                  "building-ioc-defanging-and-sharing-pipeline",
	"ioc-enrichment-pipeline-with-opencti":                "building-ioc-enrichment-pipeline-with-opencti",
	"malware-incident-communication-template":             "building-malware-incident-communication-template",
	"patch-tuesday-response-process":                      "building-patch-tuesday-response-process",
	"phishing-reporting-button-workflow":                  "building-phishing-reporting-button-workflow",
	"ransomware-playbook-with-cisa-framework":             "building-ransomware-playbook-with-cisa-framework",
	"red-team-c2-infrastructure-with-havoc":               "building-red-team-c2-infrastructure-with-havoc",
	"role-mining-for-rbac-optimization":                   "building-role-mining-for-rbac-optimization",
	"soc-escalation-matrix":                               "building-soc-escalation-matrix",
	"soc-metrics-and-kpi-tracking":                        "building-soc-metrics-and-kpi-tracking",
	"soc-playbook-for-ransomware":                         "building-soc-playbook-for-ransomware",
	"threat-actor-profile-from-osint":                     "building-threat-actor-profile-from-osint",
	"threat-feed-aggregation-with-misp":                   "building-threat-feed-aggregation-with-misp",
	"threat-hunt-hypothesis-framework":                    "building-threat-hunt-hypothesis-framework",
	"threat-intelligence-enrichment-in-splunk":            "building-threat-intelligence-enrichment-in-splunk",
	"threat-intelligence-feed-integration":                "building-threat-intelligence-feed-integration",
	"threat-intelligence-platform":                        "building-threat-intelligence-platform",
	"vulnerability-aging-and-sla-tracking":                "building-vulnerability-aging-and-sla-tracking",
	"vulnerability-dashboard-with-defectdojo":             "building-vulnerability-dashboard-with-defectdojo",
	"vulnerability-exception-tracking-system":             "building-vulnerability-exception-tracking-system",
	"vulnerability-scanning-workflow":                     "building-vulnerability-scanning-workflow",
	"indicators-of-compromise":                            "collecting-indicators-of-compromise",
	"open-source-intelligence":                            "collecting-open-source-intelligence",
	"threat-intelligence-with-misp":                       "collecting-threat-intelligence-with-misp",
	"volatile-evidence-from-compromised-host":             "collecting-volatile-evidence-from-compromised-host",
	"cloud-incident-response":                             "conducting-cloud-incident-response",
	"cloud-penetration-testing":                           "cloud-attack-surface-discovery",
	"domain-persistence-with-dcsync":                      "conducting-domain-persistence-with-dcsync",
	"full-scope-red-team-engagement":                      "conducting-full-scope-red-team-engagement",
	"internal-network-penetration-test":                   "conducting-internal-network-penetration-test",
	"internal-reconnaissance-with-bloodhound-ce":          "conducting-internal-reconnaissance-with-bloodhound-ce",
	"malware-incident-response":                           "conducting-malware-incident-response",
	"man-in-the-middle-attack-simulation":                 "conducting-man-in-the-middle-attack-simulation",
	"memory-forensics-with-volatility":                    "conducting-memory-forensics-with-volatility",
	"mobile-app-penetration-test":                         "conducting-mobile-app-penetration-test",
	"network-penetration-test":                            "conducting-network-penetration-test",
	"pass-the-ticket-attack":                              "conducting-pass-the-ticket-attack",
	"post-incident-lessons-learned":                       "conducting-post-incident-lessons-learned",
	"social-engineering-penetration-test":                 "conducting-social-engineering-penetration-test",
	"social-engineering-pretext-call":                     "conducting-social-engineering-pretext-call",
	"wireless-network-penetration-test":                   "conducting-wireless-network-penetration-test",
	"active-directory-tiered-model":                       "configuring-active-directory-tiered-model",
	"aws-verified-access-for-ztna":                        "configuring-aws-verified-access-for-ztna",
	"certificate-authority-with-openssl":                  "configuring-certificate-authority-with-openssl",
	"host-based-intrusion-detection":                      "configuring-host-based-intrusion-detection",
	"hsm-for-key-storage":                                 "configuring-hsm-for-key-storage",
	"identity-aware-proxy-with-google-iap":                "configuring-identity-aware-proxy-with-google-iap",
	"ldap-security-hardening":                             "configuring-ldap-security-hardening",
	"microsegmentation-for-zero-trust":                    "configuring-microsegmentation-for-zero-trust",
	"multi-factor-authentication-with-duo":                "configuring-multi-factor-authentication-with-duo",
	"network-segmentation-with-vlans":                     "configuring-network-segmentation-with-vlans",
	"oauth2-authorization-flow":                           "configuring-oauth2-authorization-flow",
	"pfsense-firewall-rules":                              "configuring-pfsense-firewall-rules",
	"snort-ids-for-intrusion-detection":                   "configuring-snort-ids-for-intrusion-detection",
	"suricata-for-network-monitoring":                     "configuring-suricata-for-network-monitoring",
	"tls-1-3-for-secure-communications":                   "configuring-tls-1-3-for-secure-communications",
	"windows-defender-advanced-settings":                  "configuring-windows-defender-advanced-settings",
	"windows-event-logging-for-detection":                 "configuring-windows-event-logging-for-detection",
	"zscaler-private-access-for-ztna":                     "configuring-zscaler-private-access-for-ztna",
	"active-breach":                                       "containing-active-breach",
	"security-events-in-qradar":                           "correlating-security-events-in-qradar",
	"threat-campaigns":                                    "correlating-threat-campaigns",
	"javascript-malware":                                  "deobfuscating-javascript-malware",
	"powershell-obfuscated-malware":                       "deobfuscating-powershell-obfuscated-malware",
	"active-directory-honeytokens":                        "deploying-active-directory-honeytokens",
	"cloudflare-access-for-zero-trust":                    "deploying-cloudflare-access-for-zero-trust",
	"decoy-files-for-ransomware-detection":                "deploying-decoy-files-for-ransomware-detection",
	"edr-agent-with-crowdstrike":                          "deploying-edr-agent-with-crowdstrike",
	"osquery-for-endpoint-monitoring":                     "deploying-osquery-for-endpoint-monitoring",
	"palo-alto-prisma-access-zero-trust":                  "deploying-palo-alto-prisma-access-zero-trust",
	"ransomware-canary-files":                             "deploying-ransomware-canary-files",
	"software-defined-perimeter":                          "deploying-software-defined-perimeter",
	"tailscale-for-zero-trust-vpn":                        "deploying-tailscale-for-zero-trust-vpn",
	"ai-model-prompt-injection-attacks":                   "detecting-ai-model-prompt-injection-attacks",
	"anomalies-in-industrial-control-systems":             "detecting-anomalies-in-industrial-control-systems",
	"anomalous-authentication-patterns":                   "detecting-anomalous-authentication-patterns",
	"arp-poisoning-in-network-traffic":                    "detecting-arp-poisoning-in-network-traffic",
	"attacks-on-historian-servers":                        "detecting-attacks-on-historian-servers",
	"attacks-on-scada-systems":                            "detecting-attacks-on-scada-systems",
	"aws-cloudtrail-anomalies":                            "detecting-aws-cloudtrail-anomalies",
	"aws-credential-exposure-with-trufflehog":             "detecting-aws-credential-exposure-with-trufflehog",
	"aws-guardduty-findings-automation":                   "detecting-aws-guardduty-findings-automation",
	"azure-service-principal-abuse":                       "detecting-azure-service-principal-abuse",
	"azure-storage-account-misconfigurations":             "detecting-misconfigured-azure-storage",
	"beaconing-patterns-with-zeek":                        "detecting-beaconing-patterns-with-zeek",
	"bluetooth-low-energy-attacks":                        "detecting-bluetooth-low-energy-attacks",
	"broken-object-property-level-authorization":          "api-bopla",
	"business-email-compromise":                           "detecting-business-email-compromise",
	"business-email-compromise-with-ai":                   "detecting-business-email-compromise-with-ai",
	"cloud-threats-with-guardduty":                        "detecting-cloud-threats-with-guardduty",
	"command-and-control-over-dns":                        "detecting-command-and-control-over-dns",
	"compromised-cloud-credentials":                       "detecting-compromised-cloud-credentials",
	"container-drift-at-runtime":                          "detecting-container-drift-at-runtime",
	"container-escape-attempts":                           "detecting-container-escape-attempts",
	"container-escape-with-falco-rules":                   "detecting-container-escape-with-falco-rules",
	"credential-dumping-techniques":                       "detecting-credential-dumping-techniques",
	"cryptomining-in-cloud":                               "detecting-cryptomining-in-cloud",
	"deepfake-audio-in-vishing-attacks":                   "detecting-deepfake-audio-in-vishing-attacks",
	"dll-sideloading-attacks":                             "detecting-dll-sideloading-attacks",
	"dnp3-protocol-anomalies":                             "detecting-dnp3-protocol-anomalies",
	"dns-exfiltration-with-dns-query-analysis":            "detecting-dns-exfiltration-with-dns-query-analysis",
	"email-account-compromise":                            "detecting-email-account-compromise",
	"email-forwarding-rules-attack":                       "detecting-email-forwarding-rules-attack",
	"evasion-techniques-in-endpoint-logs":                 "detecting-evasion-techniques-in-endpoint-logs",
	"exfiltration-over-dns-with-zeek":                     "detecting-exfiltration-over-dns-with-zeek",
	"fileless-attacks-on-endpoints":                       "detecting-fileless-attacks-on-endpoints",
	"fileless-malware-techniques":                         "detecting-fileless-malware-techniques",
	"golden-ticket-attacks-in-kerberos-logs":              "detecting-golden-ticket-attacks-in-kerberos-logs",
	"golden-ticket-forgery":                               "detecting-golden-ticket-forgery",
	"insider-data-exfiltration-via-dlp":                   "detecting-insider-data-exfiltration-via-dlp",
	"insider-threat-behaviors":                            "detecting-insider-threat-behaviors",
	"insider-threat-with-ueba":                            "detecting-insider-threat-with-ueba",
	"kerberoasting-attacks":                               "detecting-kerberoasting-attacks",
	"living-off-the-land-attacks":                         "detecting-living-off-the-land-attacks",
	"living-off-the-land-with-lolbas":                     "detecting-living-off-the-land-with-lolbas",
	"malicious-scheduled-tasks-with-sysmon":               "detecting-malicious-scheduled-tasks-with-sysmon",
	"mimikatz-execution-patterns":                         "detecting-mimikatz-execution-patterns",
	"misconfigured-azure-storage":                         "detecting-misconfigured-azure-storage",
	"mobile-malware-behavior":                             "detecting-mobile-malware-behavior",
	"modbus-protocol-anomalies":                           "detecting-modbus-protocol-anomalies",
	"network-anomalies-with-zeek":                         "detecting-network-anomalies-with-zeek",
	"network-scanning-with-ids-signatures":                "detecting-network-scanning-with-ids-signatures",
	"ntlm-relay-with-event-correlation":                   "detecting-ntlm-relay-with-event-correlation",
	"pass-the-hash-attacks":                               "detecting-pass-the-hash-attacks",
	"pass-the-ticket-attacks":                             "detecting-pass-the-ticket-attacks",
	"port-scanning-with-fail2ban":                         "detecting-port-scanning-with-fail2ban",
	"process-hollowing-technique":                         "detecting-process-hollowing-technique",
	"process-injection-techniques":                        "detecting-process-injection-techniques",
	"ransomware-encryption-behavior":                      "detecting-ransomware-encryption-behavior",
	"ransomware-precursors-in-network":                    "detecting-ransomware-precursors-in-network",
	"rootkit-activity":                                    "detecting-rootkit-activity",
	"s3-data-exfiltration-attempts":                       "detecting-s3-data-exfiltration-attempts",
	"serverless-function-injection":                       "detecting-serverless-function-injection",
	"service-account-abuse":                               "detecting-service-account-abuse",
	"shadow-it-cloud-usage":                               "detecting-shadow-it-cloud-usage",
	"spearphishing-with-email-gateway":                    "detecting-spearphishing-with-email-gateway",
	"stuxnet-style-attacks":                               "detecting-stuxnet-style-attacks",
	"supply-chain-attacks-in-ci-cd":                       "detecting-supply-chain-attacks-in-ci-cd",
	"suspicious-oauth-application-consent":                "detecting-suspicious-oauth-application-consent",
	"suspicious-powershell-execution":                     "detecting-suspicious-powershell-execution",
	"t1003-credential-dumping-with-edr":                   "detecting-t1003-credential-dumping-with-edr",
	"t1055-process-injection-with-sysmon":                 "detecting-t1055-process-injection-with-sysmon",
	"t1548-abuse-elevation-control-mechanism":             "detecting-t1548-abuse-elevation-control-mechanism",
	"typosquatting-packages-in-npm-pypi":                  "detecting-typosquatting-packages-in-npm-pypi",
	"wmi-persistence":                                     "detecting-wmi-persistence",
	"malware-from-infected-systems":                       "eradicating-malware-from-infected-systems",
	"threat-intelligence-platforms":                       "evaluating-threat-intelligence-platforms",
	"eadas":                                               "executing-active-directory-attack-simulation",
	"ertep":                                               "executing-red-team-engagement-planning",
	"erte":                                                "executing-red-team-exercise",
	"bgp-hijacking-vulnerabilities":                       "exploiting-bgp-hijacking-vulnerabilities",
	"broken-function-level-authorization":                 "api-bfla",
	"constrained-delegation-abuse":                        "exploiting-constrained-delegation-abuse",
	"deeplink-vulnerabilities":                            "exploiting-deeplink-vulnerabilities",
	"insecure-data-storage-in-mobile":                     "exploiting-insecure-data-storage-in-mobile",
	"ipv6-vulnerabilities":                                "exploiting-ipv6-vulnerabilities",
	"kerberoasting-with-impacket":                         "exploiting-kerberoasting-with-impacket",
	"ms17-010-eternalblue-vulnerability":                  "exploiting-ms17-010-eternalblue-vulnerability",
	"nopac-cve-2021-42278-42287":                          "exploiting-nopac-cve-2021-42278-42287",
	"server-side-request-forgery":                         "exploiting-server-side-request-forgery",
	"smb-vulnerabilities-with-metasploit":                 "exploiting-smb-vulnerabilities-with-metasploit",
	"vulnerabilities-with-metasploit-framework":           "exploiting-vulnerabilities-with-metasploit-framework",
	"zerologon-vulnerability-cve-2020-1472":               "exploiting-zerologon-vulnerability-cve-2020-1472",
	"browser-history-artifacts":                           "extracting-browser-history-artifacts",
	"config-from-agent-tesla-rat":                         "extracting-config-from-agent-tesla-rat",
	"credentials-from-memory-dump":                        "extracting-credentials-from-memory-dump",
	"iocs-from-malware-samples":                           "extracting-iocs-from-malware-samples",
	"memory-artifacts-with-rekall":                        "extracting-memory-artifacts-with-rekall",
	"windows-event-logs-artifacts":                        "extracting-windows-event-logs-artifacts",
	"threat-intelligence-reports":                         "generating-threat-intelligence-reports",
	"docker-containers-for-production":                    "hardening-docker-containers-for-production",
	"docker-daemon-configuration":                         "hardening-docker-daemon-configuration",
	"linux-endpoint-with-cis-benchmark":                   "hardening-linux-endpoint-with-cis-benchmark",
	"windows-endpoint-with-cis-benchmark":                 "hardening-windows-endpoint-with-cis-benchmark",
	"advanced-persistent-threats":                         "hunting-advanced-persistent-threats",
	"credential-stuffing-attacks":                         "hunting-credential-stuffing-attacks",
	"for-anomalous-powershell-execution":                  "hunting-for-anomalous-powershell-execution",
	"for-beaconing-with-frequency-analysis":               "hunting-for-beaconing-with-frequency-analysis",
	"for-cobalt-strike-beacons":                           "hunting-for-cobalt-strike-beacons",
	"for-command-and-control-beaconing":                   "hunting-for-command-and-control-beaconing",
	"for-data-exfiltration-indicators":                    "hunting-for-data-exfiltration-indicators",
	"for-data-staging-before-exfiltration":                "hunting-for-data-staging-before-exfiltration",
	"for-dcsync-attacks":                                  "hunting-for-dcsync-attacks",
	"for-defense-evasion-via-timestomping":                "hunting-for-defense-evasion-via-timestomping",
	"for-dns-based-persistence":                           "hunting-for-dns-based-persistence",
	"for-dns-tunneling-with-zeek":                         "hunting-for-dns-tunneling-with-zeek",
	"for-domain-fronting-c2-traffic":                      "hunting-for-domain-fronting-c2-traffic",
	"for-living-off-the-cloud-techniques":                 "hunting-for-living-off-the-cloud-techniques",
	"for-living-off-the-land-binaries":                    "hunting-for-living-off-the-land-binaries",
	"for-lolbins-execution-in-endpoint-logs":              "hunting-for-lolbins-execution-in-endpoint-logs",
	"for-ntlm-relay-attacks":                              "hunting-for-ntlm-relay-attacks",
	"for-persistence-mechanisms-in-windows":               "hunting-for-persistence-mechanisms-in-windows",
	"for-persistence-via-wmi-subscriptions":               "hunting-for-persistence-via-wmi-subscriptions",
	"for-process-injection-techniques":                    "hunting-for-process-injection-techniques",
	"for-registry-persistence-mechanisms":                 "hunting-for-registry-persistence-mechanisms",
	"for-registry-run-key-persistence":                    "hunting-for-registry-run-key-persistence",
	"for-scheduled-task-persistence":                      "hunting-for-scheduled-task-persistence",
	"for-shadow-copy-deletion":                            "hunting-for-shadow-copy-deletion",
	"for-spearphishing-indicators":                        "hunting-for-spearphishing-indicators",
	"for-startup-folder-persistence":                      "hunting-for-startup-folder-persistence",
	"for-supply-chain-compromise":                         "hunting-for-supply-chain-compromise",
	"for-suspicious-scheduled-tasks":                      "hunting-for-suspicious-scheduled-tasks",
	"for-t1098-account-manipulation":                      "hunting-for-t1098-account-manipulation",
	"for-unusual-network-connections":                     "hunting-for-unusual-network-connections",
	"for-unusual-service-installations":                   "hunting-for-unusual-service-installations",
	"for-webshell-activity":                               "hunting-for-webshell-activity",
	"aes-encryption-for-data-at-rest":                     "implementing-aes-encryption-for-data-at-rest",
	"alert-fatigue-reduction":                             "implementing-alert-fatigue-reduction",
	"anti-phishing-training-program":                      "implementing-anti-phishing-training-program",
	"anti-ransomware-group-policy":                        "implementing-anti-ransomware-group-policy",
	"api-security-testing-with-42crunch":                  "api-fuzzing-restler",
	"api-threat-protection-with-apigee":                   "api-security-misconfiguration",
	"application-whitelisting-with-applocker":             "implementing-application-whitelisting-with-applocker",
	"aqua-security-for-container-scanning":                "implementing-aqua-security-for-container-scanning",
	"attack-path-analysis-with-xm-cyber":                  "implementing-attack-path-analysis-with-xm-cyber",
	"attack-surface-management":                           "implementing-attack-surface-management",
	"aws-config-rules-for-compliance":                     "implementing-aws-config-rules-for-compliance",
	"aws-iam-permission-boundaries":                       "implementing-aws-iam-permission-boundaries",
	"aws-macie-for-data-classification":                   "implementing-aws-macie-for-data-classification",
	"aws-nitro-enclave-security":                          "implementing-aws-nitro-enclave-security",
	"aws-security-hub":                                    "implementing-aws-security-hub",
	"aws-security-hub-compliance":                         "implementing-aws-security-hub-compliance",
	"azure-defender-for-cloud":                            "implementing-azure-defender-for-cloud",
	"beyondcorp-zero-trust-access-model":                  "implementing-beyondcorp-zero-trust-access-model",
	"bgp-security-with-rpki":                              "implementing-bgp-security-with-rpki",
	"browser-isolation-for-zero-trust":                    "implementing-browser-isolation-for-zero-trust",
	"canary-tokens-for-network-intrusion":                 "implementing-canary-tokens-for-network-intrusion",
	"cisa-zero-trust-maturity-model":                      "implementing-cisa-zero-trust-maturity-model",
	"cloud-dlp-for-data-protection":                       "implementing-cloud-dlp-for-data-protection",
	"cloud-security-posture-management":                   "implementing-cloud-security-posture-management",
	"cloud-trail-log-analysis":                            "implementing-cloud-trail-log-analysis",
	"cloud-vulnerability-posture-management":              "implementing-cloud-vulnerability-posture-management",
	"cloud-waf-rules":                                     "implementing-cloud-waf-rules",
	"cloud-workload-protection":                           "implementing-cloud-workload-protection",
	"code-signing-for-artifacts":                          "implementing-code-signing-for-artifacts",
	"conditional-access-policies-azure-ad":                "implementing-conditional-access-policies-azure-ad",
	"conduit-security-for-ot-remote-access":               "implementing-conduit-security-for-ot-remote-access",
	"container-image-minimal-base-with-distroless":        "implementing-container-image-minimal-base-with-distroless",
	"container-network-policies-with-calico":              "implementing-container-network-policies-with-calico",
	"continuous-security-validation-with-bas":             "implementing-continuous-security-validation-with-bas",
	"data-loss-prevention-with-microsoft-purview":         "implementing-data-loss-prevention-with-microsoft-purview",
	"ddos-mitigation-with-cloudflare":                     "implementing-ddos-mitigation-with-cloudflare",
	"deception-based-detection-with-canarytoken":          "implementing-deception-based-detection-with-canarytoken",
	"delinea-secret-server-for-pam":                       "implementing-delinea-secret-server-for-pam",
	"device-posture-assessment-in-zero-trust":             "implementing-device-posture-assessment-in-zero-trust",
	"devsecops-security-scanning":                         "implementing-devsecops-security-scanning",
	"diamond-model-analysis":                              "implementing-diamond-model-analysis",
	"digital-signatures-with-ed25519":                     "implementing-digital-signatures-with-ed25519",
	"disk-encryption-with-bitlocker":                      "implementing-disk-encryption-with-bitlocker",
	"dmarc-dkim-spf-email-security":                       "implementing-dmarc-dkim-spf-email-security",
	"dragos-platform-for-ot-monitoring":                   "implementing-dragos-platform-for-ot-monitoring",
	"ebpf-security-monitoring":                            "implementing-ebpf-security-monitoring",
	"email-sandboxing-with-proofpoint":                    "implementing-email-sandboxing-with-proofpoint",
	"end-to-end-encryption-for-messaging":                 "implementing-end-to-end-encryption-for-messaging",
	"endpoint-detection-with-wazuh":                       "implementing-endpoint-detection-with-wazuh",
	"endpoint-dlp-controls":                               "implementing-endpoint-dlp-controls",
	"envelope-encryption-with-aws-kms":                    "implementing-envelope-encryption-with-aws-kms",
	"epss-score-for-vulnerability-prioritization":         "implementing-epss-score-for-vulnerability-prioritization",
	"file-integrity-monitoring-with-aide":                 "implementing-file-integrity-monitoring-with-aide",
	"fuzz-testing-in-cicd-with-aflplusplus":               "implementing-fuzz-testing-in-cicd-with-aflplusplus",
	"gcp-binary-authorization":                            "implementing-gcp-binary-authorization",
	"gcp-organization-policy-constraints":                 "implementing-gcp-organization-policy-constraints",
	"gcp-vpc-firewall-rules":                              "implementing-gcp-vpc-firewall-rules",
	"gdpr-data-protection-controls":                       "implementing-gdpr-data-protection-controls",
	"gdpr-data-subject-access-request":                    "implementing-gdpr-data-subject-access-request",
	"github-advanced-security-for-code-scanning":          "implementing-github-advanced-security-for-code-scanning",
	"google-workspace-admin-security":                     "implementing-google-workspace-admin-security",
	"google-workspace-phishing-protection":                "implementing-google-workspace-phishing-protection",
	"google-workspace-sso-configuration":                  "implementing-google-workspace-sso-configuration",
	"hardware-security-key-authentication":                "implementing-hardware-security-key-authentication",
	"hashicorp-vault-dynamic-secrets":                     "implementing-hashicorp-vault-dynamic-secrets",
	"honeypot-for-ransomware-detection":                   "implementing-honeypot-for-ransomware-detection",
	"honeytokens-for-breach-detection":                    "implementing-honeytokens-for-breach-detection",
	"ics-firewall-with-tofino":                            "implementing-ics-firewall-with-tofino",
	"identity-governance-with-sailpoint":                  "implementing-identity-governance-with-sailpoint",
	"identity-verification-for-zero-trust":                "implementing-identity-verification-for-zero-trust",
	"iec-62443-security-zones":                            "implementing-iec-62443-security-zones",
	"image-provenance-verification-with-cosign":           "implementing-image-provenance-verification-with-cosign",
	"immutable-backup-with-restic":                        "implementing-immutable-backup-with-restic",
	"infrastructure-as-code-security-scanning":            "implementing-infrastructure-as-code-security-scanning",
	"iso-27001-information-security-management":           "implementing-iso-27001-information-security-management",
	"just-in-time-access-provisioning":                    "implementing-just-in-time-access-provisioning",
	"kubernetes-network-policy-with-calico":               "implementing-kubernetes-network-policy-with-calico",
	"kubernetes-pod-security-standards":                   "implementing-kubernetes-pod-security-standards",
	"llm-guardrails-for-security":                         "implementing-llm-guardrails-for-security",
	"log-forwarding-with-fluentd":                         "implementing-log-forwarding-with-fluentd",
	"log-integrity-with-blockchain":                       "implementing-log-integrity-with-blockchain",
	"memory-protection-with-dep-aslr":                     "implementing-memory-protection-with-dep-aslr",
	"microsegmentation-with-guardicore":                   "implementing-microsegmentation-with-guardicore",
	"mimecast-targeted-attack-protection":                 "implementing-mimecast-targeted-attack-protection",
	"mitre-attack-coverage-mapping":                       "implementing-mitre-attack-coverage-mapping",
	"mobile-application-management":                       "implementing-mobile-application-management",
	"mtls-for-zero-trust-services":                        "implementing-mtls-for-zero-trust-services",
	"nerc-cip-compliance-controls":                        "implementing-nerc-cip-compliance-controls",
	"network-access-control":                              "implementing-network-access-control",
	"network-access-control-with-cisco-ise":               "implementing-network-access-control-with-cisco-ise",
	"network-deception-with-honeypots":                    "implementing-network-deception-with-honeypots",
	"network-intrusion-prevention-with-suricata":          "implementing-network-intrusion-prevention-with-suricata",
	"network-policies-for-kubernetes":                     "implementing-network-policies-for-kubernetes",
	"network-segmentation-for-ot":                         "implementing-network-segmentation-for-ot",
	"network-segmentation-with-firewall-zones":            "implementing-network-segmentation-with-firewall-zones",
	"network-traffic-analysis-with-arkime":                "implementing-network-traffic-analysis-with-arkime",
	"network-traffic-baselining":                          "implementing-network-traffic-baselining",
	"next-generation-firewall-with-palo-alto":             "implementing-next-generation-firewall-with-palo-alto",
	"ot-incident-response-playbook":                       "implementing-ot-incident-response-playbook",
	"ot-network-traffic-analysis-with-nozomi":             "implementing-ot-network-traffic-analysis-with-nozomi",
	"pam-for-database-access":                             "implementing-pam-for-database-access",
	"passwordless-auth-with-microsoft-entra":              "implementing-passwordless-auth-with-microsoft-entra",
	"patch-management-for-ot-systems":                     "implementing-patch-management-for-ot-systems",
	"patch-management-workflow":                           "implementing-patch-management-workflow",
	"pci-dss-compliance-controls":                         "implementing-pci-dss-compliance-controls",
	"pod-security-admission-controller":                   "implementing-pod-security-admission-controller",
	"policy-as-code-with-open-policy-agent":               "implementing-policy-as-code-with-open-policy-agent",
	"privileged-access-management-with-cyberark":          "implementing-privileged-access-management-with-cyberark",
	"privileged-access-workstation":                       "implementing-privileged-access-workstation",
	"privileged-session-monitoring":                       "implementing-privileged-session-monitoring",
	"proofpoint-email-security-gateway":                   "implementing-proofpoint-email-security-gateway",
	"purdue-model-network-segmentation":                   "implementing-purdue-model-network-segmentation",
	"ransomware-backup-strategy":                          "implementing-ransomware-backup-strategy",
	"ransomware-kill-switch-detection":                    "implementing-ransomware-kill-switch-detection",
	"rapid7-insightvm-for-scanning":                       "implementing-rapid7-insightvm-for-scanning",
	"rbac-hardening-for-kubernetes":                       "implementing-rbac-hardening-for-kubernetes",
	"rsa-key-pair-management":                             "implementing-rsa-key-pair-management",
	"runtime-application-self-protection":                 "implementing-runtime-application-self-protection",
	"runtime-security-with-tetragon":                      "implementing-runtime-security-with-tetragon",
	"saml-sso-with-okta":                                  "implementing-saml-sso-with-okta",
	"scim-provisioning-with-okta":                         "implementing-scim-provisioning-with-okta",
	"secret-scanning-with-gitleaks":                       "implementing-secret-scanning-with-gitleaks",
	"secrets-management-with-vault":                       "implementing-secrets-management-with-vault",
	"secrets-scanning-in-ci-cd":                           "implementing-secrets-scanning-in-ci-cd",
	"security-chaos-engineering":                          "implementing-security-chaos-engineering",
	"security-information-sharing-with-stix2":             "implementing-security-information-sharing-with-stix2",
	"security-monitoring-with-datadog":                    "implementing-security-monitoring-with-datadog",
	"semgrep-for-custom-sast-rules":                       "implementing-semgrep-for-custom-sast-rules",
	"siem-correlation-rules-for-apt":                      "implementing-siem-correlation-rules-for-apt",
	"siem-use-case-tuning":                                "implementing-siem-use-case-tuning",
	"siem-use-cases-for-detection":                        "implementing-siem-use-cases-for-detection",
	"sigstore-for-software-signing":                       "implementing-sigstore-for-software-signing",
	"soar-automation-with-phantom":                        "implementing-soar-automation-with-phantom",
	"soar-playbook-for-phishing":                          "implementing-soar-playbook-for-phishing",
	"soar-playbook-with-palo-alto-xsoar":                  "implementing-soar-playbook-with-palo-alto-xsoar",
	"stix-taxii-feed-integration":                         "implementing-stix-taxii-feed-integration",
	"supply-chain-security-with-in-toto":                  "implementing-supply-chain-security-with-in-toto",
	"syslog-centralization-with-rsyslog":                  "implementing-syslog-centralization-with-rsyslog",
	"taxii-server-with-opentaxii":                         "implementing-taxii-server-with-opentaxii",
	"threat-intelligence-lifecycle-management":            "implementing-threat-intelligence-lifecycle-management",
	"threat-modeling-with-mitre-attack":                   "implementing-threat-modeling-with-mitre-attack",
	"ticketing-system-for-incidents":                      "implementing-ticketing-system-for-incidents",
	"usb-device-control-policy":                           "implementing-usb-device-control-policy",
	"velociraptor-for-ir-collection":                      "implementing-velociraptor-for-ir-collection",
	"vulnerability-management-with-greenbone":             "implementing-vulnerability-management-with-greenbone",
	"vulnerability-remediation-sla":                       "implementing-vulnerability-remediation-sla",
	"vulnerability-sla-breach-alerting":                   "implementing-vulnerability-sla-breach-alerting",
	"web-application-logging-with-modsecurity":            "implementing-web-application-logging-with-modsecurity",
	"zero-knowledge-proof-for-authentication":             "implementing-zero-knowledge-proof-for-authentication",
	"zero-standing-privilege-with-cyberark":               "implementing-zero-standing-privilege-with-cyberark",
	"zero-trust-dns-with-nextdns":                         "implementing-zero-trust-dns-with-nextdns",
	"zero-trust-for-saas-applications":                    "implementing-zero-trust-for-saas-applications",
	"zero-trust-in-cloud":                                 "implementing-zero-trust-in-cloud",
	"zero-trust-network-access":                           "implementing-zero-trust-network-access",
	"zero-trust-network-access-with-zscaler":              "implementing-zero-trust-network-access-with-zscaler",
	"zero-trust-with-beyondcorp":                          "implementing-zero-trust-with-beyondcorp",
	"zero-trust-with-hashicorp-boundary":                  "implementing-zero-trust-with-hashicorp-boundary",
	"dast-with-owasp-zap-in-pipeline":                     "integrating-dast-with-owasp-zap-in-pipeline",
	"sast-into-github-actions-pipeline":                   "integrating-sast-into-github-actions-pipeline",
	"insider-threat-indicators":                           "investigating-insider-threat-indicators",
	"phishing-email-incident":                             "investigating-phishing-email-incident",
	"ransomware-attack-artifacts":                         "investigating-ransomware-attack-artifacts",
	"js-analysis":                                         "javascript-analysis",
	"cloud-identity-with-okta":                            "managing-cloud-identity-with-okta",
	"intelligence-lifecycle":                              "managing-intelligence-lifecycle",
	"mmat":                                                "mapping-mitre-attack-techniques",
	"scada-modbus-traffic-anomalies":                      "monitoring-scada-modbus-traffic-anomalies",
	"access-recertification-with-saviynt":                 "performing-access-recertification-with-saviynt",
	"access-review-and-certification":                     "performing-access-review-and-certification",
	"active-directory-bloodhound-analysis":                "performing-active-directory-bloodhound-analysis",
	"active-directory-compromise-investigation":           "performing-active-directory-compromise-investigation",
	"active-directory-forest-trust-attack":                "performing-active-directory-forest-trust-attack",
	"active-directory-vulnerability-assessment":           "performing-active-directory-vulnerability-assessment",
	"adversary-in-the-middle-phishing-detection":          "performing-adversary-in-the-middle-phishing-detection",
	"agentless-vulnerability-scanning":                    "performing-agentless-vulnerability-scanning",
	"ai-assisted-vulnerability-discovery":                 "performing-ai-assisted-vulnerability-discovery",
	"ai-driven-osint-correlation":                         "performing-ai-driven-osint-correlation",
	"alert-triage-with-elastic-siem":                      "performing-alert-triage-with-elastic-siem",
	"android-app-static-analysis-with-mobsf":              "performing-android-app-static-analysis-with-mobsf",
	"api-fuzzing-with-restler":                            "api-fuzzing-restler",
	"api-inventory-and-discovery":                         "api-discovery",
	"api-rate-limiting-bypass":                            "api-resource-consumption",
	"api-security-testing-with-postman":                   "conducting-api-security-testing",
	"arp-spoofing-attack-simulation":                      "performing-arp-spoofing-attack-simulation",
	"asset-criticality-scoring-for-vulns":                 "performing-asset-criticality-scoring-for-vulns",
	"authenticated-scan-with-openvas":                     "performing-authenticated-scan-with-openvas",
	"authenticated-vulnerability-scan":                    "performing-authenticated-vulnerability-scan",
	"automated-malware-analysis-with-cape":                "performing-automated-malware-analysis-with-cape",
	"aws-account-enumeration-with-scout-suite":            "aws-cloud-pentesting",
	"aws-privilege-escalation-assessment":                 "aws-iam-privilege-escalation",
	"bandwidth-throttling-attack-simulation":              "performing-bandwidth-throttling-attack-simulation",
	"binary-exploitation-analysis":                        "performing-binary-exploitation-analysis",
	"bluetooth-security-assessment":                       "performing-bluetooth-security-assessment",
	"brand-monitoring-for-impersonation":                  "performing-brand-monitoring-for-impersonation",
	"cloud-asset-inventory-with-cartography":              "cloud-attack-surface-discovery",
	"cloud-forensics-investigation":                       "performing-cloud-forensics-investigation",
	"cloud-forensics-with-aws-cloudtrail":                 "performing-cloud-forensics-with-aws-cloudtrail",
	"cloud-incident-containment-procedures":               "performing-cloud-incident-containment-procedures",
	"cloud-log-forensics-with-athena":                     "performing-cloud-log-forensics-with-athena",
	"cloud-native-forensics-with-falco":                   "performing-cloud-native-forensics-with-falco",
	"cloud-native-threat-hunting-with-aws-detective":      "performing-cloud-native-threat-hunting-with-aws-detective",
	"cloud-penetration-testing-with-pacu":                 "aws-cloud-pentesting",
	"cloud-storage-forensic-acquisition":                  "performing-cloud-storage-forensic-acquisition",
	"container-escape-detection":                          "performing-container-escape-detection",
	"container-image-hardening":                           "performing-container-image-hardening",
	"container-security-scanning-with-trivy":              "performing-container-security-scanning-with-trivy",
	"credential-access-with-lazagne":                      "performing-credential-access-with-lazagne",
	"cryptographic-audit-of-application":                  "performing-cryptographic-audit-of-application",
	"cve-prioritization-with-kev-catalog":                 "performing-cve-prioritization-with-kev-catalog",
	"dark-web-monitoring-for-threats":                     "performing-dark-web-monitoring-for-threats",
	"deception-technology-deployment":                     "performing-deception-technology-deployment",
	"disk-forensics-investigation":                        "performing-disk-forensics-investigation",
	"dns-enumeration-and-zone-transfer":                   "performing-dns-enumeration-and-zone-transfer",
	"dns-tunneling-detection":                             "performing-dns-tunneling-detection",
	"docker-bench-security-assessment":                    "performing-docker-bench-security-assessment",
	"dynamic-analysis-of-android-app":                     "performing-dynamic-analysis-of-android-app",
	"dynamic-analysis-with-any-run":                       "performing-dynamic-analysis-with-any-run",
	"endpoint-forensics-investigation":                    "performing-endpoint-forensics-investigation",
	"endpoint-vulnerability-remediation":                  "performing-endpoint-vulnerability-remediation",
	"entitlement-review-with-sailpoint-iiq":               "performing-entitlement-review-with-sailpoint-iiq",
	"external-network-penetration-test":                   "performing-external-network-penetration-test",
	"false-positive-reduction-in-siem":                    "performing-false-positive-reduction-in-siem",
	"file-carving-with-foremost":                          "performing-file-carving-with-foremost",
	"firmware-extraction-with-binwalk":                    "performing-firmware-extraction-with-binwalk",
	"firmware-malware-analysis":                           "performing-firmware-malware-analysis",
	"fuzzing-with-aflplusplus":                            "performing-fuzzing-with-aflplusplus",
	"gcp-penetration-testing-with-gcpbucketbrute":         "cloud-storage-exposure-testing",
	"gcp-security-assessment-with-forseti":                "gcp-cloud-pentesting",
	"graphql-depth-limit-attack":                          "graphql-api-security",
	"graphql-introspection-attack":                        "graphql-api-security",
	"hardware-security-module-integration":                "performing-hardware-security-module-integration",
	"hash-cracking-with-hashcat":                          "performing-hash-cracking-with-hashcat",
	"ics-asset-discovery-with-claroty":                    "performing-ics-asset-discovery-with-claroty",
	"indicator-lifecycle-management":                      "performing-indicator-lifecycle-management",
	"initial-access-with-evilginx3":                       "performing-initial-access-with-evilginx3",
	"insider-threat-investigation":                        "performing-insider-threat-investigation",
	"internal-network-pentesting":                         "performing-internal-network-pentesting",
	"ioc-enrichment-automation":                           "performing-ioc-enrichment-automation",
	"ios-app-security-assessment":                         "performing-ios-app-security-assessment",
	"iot-security-assessment":                             "performing-iot-security-assessment",
	"ip-reputation-analysis-with-shodan":                  "performing-ip-reputation-analysis-with-shodan",
	"jwt-none-algorithm-attack":                           "jwt-security-testing",
	"kerberoasting-attack":                                "performing-kerberoasting-attack",
	"kubernetes-cis-benchmark-with-kube-bench":            "performing-kubernetes-cis-benchmark-with-kube-bench",
	"kubernetes-etcd-security-assessment":                 "performing-kubernetes-etcd-security-assessment",
	"kubernetes-penetration-testing":                      "performing-kubernetes-penetration-testing",
	"lateral-movement-detection":                          "performing-lateral-movement-detection",
	"lateral-movement-with-wmiexec":                       "performing-lateral-movement-with-wmiexec",
	"linux-log-forensics-investigation":                   "performing-linux-log-forensics-investigation",
	"log-analysis-for-forensic-investigation":             "performing-log-analysis-for-forensic-investigation",
	"log-source-onboarding-in-siem":                       "performing-log-source-onboarding-in-siem",
	"malware-hash-enrichment-with-virustotal":             "performing-malware-hash-enrichment-with-virustotal",
	"malware-ioc-extraction":                              "performing-malware-ioc-extraction",
	"malware-persistence-investigation":                   "performing-malware-persistence-investigation",
	"malware-triage-with-yara":                            "performing-malware-triage-with-yara",
	"memory-forensics-with-volatility3":                   "performing-memory-forensics-with-volatility3",
	"memory-forensics-with-volatility3-plugins":           "performing-memory-forensics-with-volatility3-plugins",
	"mobile-app-certificate-pinning-bypass":               "performing-mobile-app-certificate-pinning-bypass",
	"mobile-device-forensics-with-cellebrite":             "performing-mobile-device-forensics-with-cellebrite",
	"network-forensics-with-wireshark":                    "performing-network-forensics-with-wireshark",
	"network-packet-capture-analysis":                     "performing-network-packet-capture-analysis",
	"network-traffic-analysis-with-tshark":                "performing-network-traffic-analysis-with-tshark",
	"network-traffic-analysis-with-zeek":                  "performing-network-traffic-analysis-with-zeek",
	"network-tunneling-and-pivoting":                      "performing-network-tunneling-and-pivoting",
	"nist-csf-maturity-assessment":                        "performing-nist-csf-maturity-assessment",
	"oauth-scope-minimization-review":                     "performing-oauth-scope-minimization-review",
	"oil-gas-cybersecurity-assessment":                    "performing-oil-gas-cybersecurity-assessment",
	"osint-with-spiderfoot":                               "performing-osint-with-spiderfoot",
	"ot-network-security-assessment":                      "performing-ot-network-security-assessment",
	"ot-vulnerability-assessment-with-claroty":            "performing-ot-vulnerability-assessment-with-claroty",
	"ot-vulnerability-scanning-safely":                    "performing-ot-vulnerability-scanning-safely",
	"packet-injection-attack":                             "performing-packet-injection-attack",
	"paste-site-monitoring-for-credentials":               "performing-paste-site-monitoring-for-credentials",
	"phishing-simulation-with-gophish":                    "performing-phishing-simulation-with-gophish",
	"physical-intrusion-assessment":                       "performing-physical-intrusion-assessment",
	"plc-firmware-security-analysis":                      "performing-plc-firmware-security-analysis",
	"post-quantum-cryptography-migration":                 "performing-post-quantum-cryptography-migration",
	"power-grid-cybersecurity-assessment":                 "performing-power-grid-cybersecurity-assessment",
	"privacy-impact-assessment":                           "performing-privacy-impact-assessment",
	"privilege-escalation-assessment":                     "performing-privilege-escalation-assessment",
	"privilege-escalation-on-linux":                       "performing-privilege-escalation-on-linux",
	"privileged-account-access-review":                    "performing-privileged-account-access-review",
	"privileged-account-discovery":                        "performing-privileged-account-discovery",
	"purple-team-atomic-testing":                          "performing-purple-team-atomic-testing",
	"purple-team-exercise":                                "performing-purple-team-exercise",
	"ransomware-response":                                 "performing-ransomware-response",
	"ransomware-tabletop-exercise":                        "performing-ransomware-tabletop-exercise",
	"red-team-phishing-with-gophish":                      "performing-red-team-phishing-with-gophish",
	"red-team-with-covenant":                              "performing-red-team-with-covenant",
	"s7comm-protocol-security-analysis":                   "performing-s7comm-protocol-security-analysis",
	"sca-dependency-scanning-with-snyk":                   "performing-sca-dependency-scanning-with-snyk",
	"scada-hmi-security-assessment":                       "performing-scada-hmi-security-assessment",
	"security-headers-audit":                              "performing-security-headers-audit",
	"serverless-function-security-review":                 "serverless-cloud-security",
	"service-account-audit":                               "performing-service-account-audit",
	"service-account-credential-rotation":                 "performing-service-account-credential-rotation",
	"soap-web-service-security-testing":                   "soap-api-security",
	"soc-tabletop-exercise":                               "performing-soc-tabletop-exercise",
	"soc2-type2-audit-preparation":                        "performing-soc2-type2-audit-preparation",
	"sqlite-database-forensics":                           "performing-sqlite-database-forensics",
	"ssl-certificate-lifecycle-management":                "performing-ssl-certificate-lifecycle-management",
	"ssl-stripping-attack":                                "performing-ssl-stripping-attack",
	"ssl-tls-inspection-configuration":                    "performing-ssl-tls-inspection-configuration",
	"ssl-tls-security-assessment":                         "performing-ssl-tls-security-assessment",
	"static-malware-analysis-with-pe-studio":              "performing-static-malware-analysis-with-pe-studio",
	"steganography-detection":                             "performing-steganography-detection",
	"supply-chain-attack-simulation":                      "performing-supply-chain-attack-simulation",
	"thick-client-application-penetration-test":           "performing-thick-client-application-penetration-test",
	"threat-emulation-with-atomic-red-team":               "performing-threat-emulation-with-atomic-red-team",
	"threat-hunting-with-elastic-siem":                    "performing-threat-hunting-with-elastic-siem",
	"threat-hunting-with-yara-rules":                      "performing-threat-hunting-with-yara-rules",
	"threat-intelligence-sharing-with-misp":               "performing-threat-intelligence-sharing-with-misp",
	"threat-landscape-assessment-for-sector":              "performing-threat-landscape-assessment-for-sector",
	"threat-modeling-with-owasp-threat-dragon":            "performing-threat-modeling-with-owasp-threat-dragon",
	"timeline-reconstruction-with-plaso":                  "performing-timeline-reconstruction-with-plaso",
	"user-behavior-analytics":                             "performing-user-behavior-analytics",
	"vlan-hopping-attack":                                 "performing-vlan-hopping-attack",
	"vulnerability-scanning-with-nessus":                  "performing-vulnerability-scanning-with-nessus",
	"web-application-penetration-test":                    "performing-web-application-penetration-test",
	"web-application-scanning-with-nikto":                 "performing-web-application-scanning-with-nikto",
	"web-application-vulnerability-triage":                "performing-web-application-vulnerability-triage",
	"wifi-password-cracking-with-aircrack":                "performing-wifi-password-cracking-with-aircrack",
	"windows-artifact-analysis-with-eric-zimmerman-tools": "performing-windows-artifact-analysis-with-eric-zimmerman-tools",
	"wnpt": "performing-wireless-network-penetration-test",
	"wireless-security-assessment-with-kismet":  "performing-wireless-security-assessment-with-kismet",
	"yara-rule-development-for-detection":       "performing-yara-rule-development-for-detection",
	"prioritizing-vulnerabilities":              "prioritizing-vulnerabilities-with-cvss-scoring",
	"stix-taxii-feeds":                          "processing-stix-taxii-feeds",
	"threat-actor-groups":                       "profiling-threat-actor-groups",
	"deleted-files-with-photorec":               "recovering-deleted-files-with-photorec",
	"from-ransomware-attack":                    "recovering-from-ransomware-attack",
	"s3-bucket-misconfiguration":                "remediating-s3-bucket-misconfiguration",
	"android-malware-with-jadx":                 "reverse-engineering-android-malware-with-jadx",
	"dotnet-malware-with-dnspy":                 "reverse-engineering-dotnet-malware-with-dnspy",
	"ios-app-with-frida":                        "reverse-engineering-ios-app-with-frida",
	"malware-with-ghidra":                       "reverse-engineering-malware-with-ghidra",
	"ransomware-encryption-routine":             "reverse-engineering-ransomware-encryption-routine",
	"rust-malware":                              "reverse-engineering-rust-malware",
	"container-images-with-grype":               "scanning-container-images-with-grype",
	"containers-with-trivy-in-cicd":             "scanning-containers-with-trivy-in-cicd",
	"docker-images-with-trivy":                  "scanning-docker-images-with-trivy",
	"infrastructure-with-nessus":                "scanning-infrastructure-with-nessus",
	"kubernetes-manifests-with-kubesec":         "scanning-kubernetes-manifests-with-kubesec",
	"api-gateway-with-aws-waf":                  "securing-api-gateway-with-aws-waf",
	"aws-iam-permissions":                       "securing-aws-iam-permissions",
	"aws-lambda-execution-roles":                "serverless-cloud-security",
	"azure-with-microsoft-defender":             "securing-azure-with-microsoft-defender",
	"container-registry-images":                 "securing-container-registry-images",
	"container-registry-with-harbor":            "securing-container-registry-with-harbor",
	"github-actions-workflows":                  "securing-github-actions-workflows",
	"helm-chart-deployments":                    "securing-helm-chart-deployments",
	"historian-server-in-ot-environment":        "securing-historian-server-in-ot-environment",
	"kubernetes-on-cloud":                       "securing-kubernetes-on-cloud",
	"remote-access-to-ot-environment":           "securing-remote-access-to-ot-environment",
	"serverless-functions":                      "serverless-cloud-security",
	"subs":                                      "subdomain-enumeration",
	"android-intents-for-vulnerabilities":       "testing-android-intents-for-vulnerabilities",
	"api-authentication-weaknesses":             "api-authentication-session",
	"api-for-broken-object-level-authorization": "api-bola",
	"api-for-mass-assignment-vulnerability":     "api-bopla",
	"api-security-with-owasp-top-10":            "testing-api-security-with-owasp-top-10",
	"for-json-web-token-vulnerabilities":        "testing-for-json-web-token-vulnerabilities",
	"jwt-token-security":                        "testing-jwt-token-security",
	"mobile-api-authentication":                 "testing-mobile-api-authentication",
	"oauth2-implementation-flaws":               "oauth-oidc-security",
	"ransomware-recovery-procedures":            "testing-ransomware-recovery-procedures",
	"websocket-api-security":                    "websocket-api-security",
	"threat-actor-infrastructure":               "tracking-threat-actor-infrastructure",
	"security-alerts-in-splunk":                 "triaging-security-alerts-in-splunk",
	"security-incident":                         "triaging-security-incident",
	"security-incident-with-ir-playbook":        "triaging-security-incident-with-ir-playbook",
	"vulnerabilities-with-ssvc-framework":       "triaging-vulnerabilities-with-ssvc-framework",
	"backup-integrity-for-recovery":             "validating-backup-integrity-for-recovery",
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
	subFS, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		subFS = embeddedSkills
	}
	return bestSkillMatch(subFS, q)
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
