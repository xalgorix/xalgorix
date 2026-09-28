package skills

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/tools"
)

// setupTestSkills creates a temporary skills directory with test files.
func setupTestSkills(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	// Create category directories
	categories := []string{"vulnerabilities", "protocols", "frameworks"}
	for _, cat := range categories {
		os.MkdirAll(filepath.Join(dir, cat), 0755)
	}

	// Create test skill files in new directory/SKILL.md format
	files := map[string]string{
		"vulnerabilities/sql_injection/SKILL.md": "# SQL Injection\nTest payloads...",
		"vulnerabilities/xss/SKILL.md":           "# XSS\nReflected payloads...",
		"protocols/graphql/SKILL.md":             "# GraphQL\nIntrospection...",
		"frameworks/django/SKILL.md":             "# Django\nDebug mode...",
	}
	for path, content := range files {
		os.MkdirAll(filepath.Join(dir, filepath.Dir(path)), 0755)
		os.WriteFile(filepath.Join(dir, path), []byte(content), 0644)
	}

	return dir
}

func TestReadSkill_Basic(t *testing.T) {
	dir := setupTestSkills(t)
	reg := tools.NewRegistry()
	Register(reg, "")

	fn := makeReadSkill(os.DirFS(dir))

	// Read existing skill
	result, err := fn(map[string]string{"name": "sql_injection"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "SQL Injection") {
		t.Errorf("expected SQL Injection content, got: %s", result.Output)
	}
}

func TestReadSkill_WithExtension(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeReadSkill(os.DirFS(dir))

	// Should work with .md extension too
	result, err := fn(map[string]string{"name": "sql_injection.md"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "SQL Injection") {
		t.Errorf("expected SQL Injection content, got: %s", result.Output)
	}
}

func TestReadSkill_DifferentCategory(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeReadSkill(os.DirFS(dir))

	result, err := fn(map[string]string{"name": "graphql", "category": "protocols"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "GraphQL") {
		t.Errorf("expected GraphQL content, got: %s", result.Output)
	}
}

func TestReadSkill_NotFound(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeReadSkill(os.DirFS(dir))

	result, _ := fn(map[string]string{"name": "nonexistent_skill"})
	if result.Error == "" {
		t.Error("expected error for nonexistent skill")
	}
	if !strings.Contains(result.Error, "skill not found") {
		t.Errorf("expected 'skill not found' error, got: %s", result.Error)
	}
}

func TestReadSkill_EmptyName(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeReadSkill(os.DirFS(dir))

	result, _ := fn(map[string]string{"name": ""})
	if result.Error == "" {
		t.Error("expected error for empty name")
	}
}

func TestReadSkill_PathTraversal(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeReadSkill(os.DirFS(dir))

	// Attempt path traversal
	traversalInputs := []string{
		"../../etc/passwd",
		"../../../etc/shadow",
		"../secrets",
		"..%2F..%2Fetc%2Fpasswd",
	}
	for _, input := range traversalInputs {
		result, _ := fn(map[string]string{"name": input})
		if result.Output != "" && strings.Contains(result.Output, "root:") {
			t.Errorf("path traversal succeeded with input: %s", input)
		}
	}
}

func TestReadSkill_CrossCategorySearch(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeReadSkill(os.DirFS(dir))

	// Request skill from protocols category without specifying category
	// (defaults to vulnerabilities, then searches all categories)
	result, _ := fn(map[string]string{"name": "graphql"})
	if !strings.Contains(result.Output, "GraphQL") {
		t.Errorf("cross-category search should find graphql in protocols, got: %s", result.Output)
	}
}

func TestListSkills_All(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeListSkills(os.DirFS(dir))

	result, err := fn(map[string]string{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should list all skills across categories
	if !strings.Contains(result.Output, "sql_injection") {
		t.Error("expected sql_injection in output")
	}
	if !strings.Contains(result.Output, "graphql") {
		t.Error("expected graphql in output")
	}
	if !strings.Contains(result.Output, "django") {
		t.Error("expected django in output")
	}
	if !strings.Contains(result.Output, "Total: 4 skills") {
		t.Errorf("expected total of 4 skills, got: %s", result.Output)
	}
}

func TestListSkills_FilterCategory(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeListSkills(os.DirFS(dir))

	result, err := fn(map[string]string{"category": "protocols"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !strings.Contains(result.Output, "graphql") {
		t.Error("expected graphql in protocols output")
	}
	if strings.Contains(result.Output, "sql_injection") {
		t.Error("should NOT contain sql_injection when filtering protocols")
	}
}

func TestListSkills_EmptyCategory(t *testing.T) {
	dir := setupTestSkills(t)
	fn := makeListSkills(os.DirFS(dir))

	result, _ := fn(map[string]string{"category": "nonexistent"})
	if !strings.Contains(result.Output, "Total: 0 skills") {
		t.Errorf("expected 0 skills for nonexistent category, got: %s", result.Output)
	}
}

func TestResolveAlias(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"xss", "testing-for-xss-vulnerabilities"},
		{"XSS", "testing-for-xss-vulnerabilities"},
		{"sqli", "exploiting-sql-injection-vulnerabilities"},
		{"sql-injection", "exploiting-sql-injection-vulnerabilities"},
		{"ssrf", "performing-ssrf-vulnerability-exploitation"},
		{"csrf", "performing-csrf-attack-simulation"},
		{"xxe", "testing-for-xxe-injection-vulnerabilities"},
		{"idor", "exploiting-idor-vulnerabilities"},
		{"ssti", "exploiting-template-injection-vulnerabilities"},
		{"cors", "testing-cors-misconfiguration"},
		{"jwt", "jwt-security-testing"},
		{"oauth", "exploiting-oauth-misconfiguration"},
		{"nmap", "scanning-network-with-nmap-advanced"},
		{"recon", "conducting-external-reconnaissance-with-osint"},
		{"privesc", "detecting-privilege-escalation-attempts"},
		{"bloodhound", "exploiting-active-directory-with-bloodhound"},
		// Non-alias passthrough
		{"some-random-name", "some-random-name"},
		{"", ""},
	}
	for _, tc := range tests {
		got := resolveAlias(tc.input)
		if got != tc.want {
			t.Errorf("resolveAlias(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestResolveAlias_SystemPromptHints verifies that every alias referenced
// in agent.go's system prompt (the read_skill(name="...") hints) resolves
// to a real skill. These were previously broken (16 dead references).
func TestResolveAlias_SystemPromptHints(t *testing.T) {
	hints := []struct {
		input string
		want  string
	}{
		{"2fa-mfa-bypass", "bypassing-two-factor-and-otp"},
		{"authentication-jwt", "jwt-security-testing"},
		{"cache-poisoning", "performing-web-cache-poisoning-attack"},
		{"cors-exploitation", "testing-cors-misconfiguration"},
		{"dom-xss", "testing-for-xss-vulnerabilities"},
		{"graphql-advanced", "performing-graphql-security-assessment"},
		{"host-header-attacks", "testing-for-host-header-injection"},
		{"information-disclosure", "testing-for-sensitive-data-exposure"},
		{"insecure-file-uploads", "exploiting-file-upload-vulnerabilities"},
		{"oauth2-attacks", "exploiting-oauth-misconfiguration"},
		{"path-traversal-lfi-rfi", "performing-directory-traversal-testing"},
		{"race-conditions", "exploiting-race-condition-vulnerabilities"},
		{"web-llm-attacks", "testing-llm-prompt-injection-and-jailbreaks"},
		{"websocket-hijacking", "exploiting-websocket-vulnerabilities"},
		{"zero-day-hunting", "performing-zero-day-vulnerability-discovery"},
	}
	for _, tc := range hints {
		got := resolveAlias(tc.input)
		if got != tc.want {
			t.Errorf("resolveAlias(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestResolveAlias_UnderscoreNormalization verifies that underscore-style
// names (used in old system prompt examples) resolve via the dash-keyed
// alias map after normalization.
func TestResolveAlias_UnderscoreNormalization(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"nosql_injection", "exploiting-nosql-injection-vulnerabilities"},
		{"prototype_pollution", "exploiting-prototype-pollution-in-javascript"},
		{"http_request_smuggling", "exploiting-http-request-smuggling"},
		{"mass_assignment", "exploiting-mass-assignment-in-rest-apis"},
		{"sql_injection", "exploiting-sql-injection-vulnerabilities"},
		// Mixed case + underscores
		{"SQL_Injection", "exploiting-sql-injection-vulnerabilities"},
		{"NOSQL_INJECTION", "exploiting-nosql-injection-vulnerabilities"},
	}
	for _, tc := range tests {
		got := resolveAlias(tc.input)
		if got != tc.want {
			t.Errorf("resolveAlias(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestReadSkill_Alias(t *testing.T) {
	// Set up a test FS that has the full canonical name the alias resolves to.
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "vulnerabilities", "exploiting-sql-injection-vulnerabilities"), 0755)
	os.WriteFile(
		filepath.Join(dir, "vulnerabilities", "exploiting-sql-injection-vulnerabilities", "SKILL.md"),
		[]byte("# SQL Injection\nFull methodology..."),
		0644,
	)

	fn := makeReadSkill(os.DirFS(dir))

	// Use shorthand alias
	result, err := fn(map[string]string{"name": "sql-injection"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "SQL Injection") {
		t.Errorf("alias 'sql-injection' should resolve to full skill, got: %s", result.Output)
	}

	// Also test 'sqli' alias
	result, err = fn(map[string]string{"name": "sqli"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "SQL Injection") {
		t.Errorf("alias 'sqli' should resolve to full skill, got: %s", result.Output)
	}

	// Test underscore-style name resolves via normalization
	result, err = fn(map[string]string{"name": "sql_injection"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(result.Output, "SQL Injection") {
		t.Errorf("underscore alias 'sql_injection' should resolve to full skill, got: %s", result.Output)
	}
}

func TestSearchSkills_FindsByConcept(t *testing.T) {
	subFS, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}
	search := makeSearchSkills(subFS)

	cases := []struct {
		query     string
		wantSkill string
	}{
		{"payment price tampering", "testing-ecommerce-and-payment-logic"},
		{"reset password poisoning", "testing-password-reset-flaws"},
		{"two factor otp bypass", "bypassing-two-factor-and-otp"},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			res, err := search(map[string]string{"query": c.query})
			if err != nil {
				t.Fatalf("search error: %v", err)
			}
			if !strings.Contains(res.Output, c.wantSkill) {
				t.Fatalf("query %q: expected %q in results, got:\n%s", c.query, c.wantSkill, res.Output)
			}
		})
	}
}

func TestSearchSkills_EmptyQuery(t *testing.T) {
	subFS, _ := fs.Sub(embeddedSkills, "data")
	res, err := makeSearchSkills(subFS)(map[string]string{"query": "   "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(res.Output, "Provide a 'query'") {
		t.Fatalf("expected guidance for empty query, got: %s", res.Output)
	}
}

func TestSearchSkills_NoMatch(t *testing.T) {
	subFS, _ := fs.Sub(embeddedSkills, "data")
	res, _ := makeSearchSkills(subFS)(map[string]string{"query": "zzqqxx-nonexistent-topic"})
	if !strings.Contains(res.Output, "No skills matched") {
		t.Fatalf("expected no-match message, got: %s", res.Output)
	}
}

// setupIntentTestSkills creates a fixture skills tree containing an
// offensive and a defensive skill that both match "rate limiting" keywords,
// for intent-aware ranking tests.
func setupIntentTestSkills(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"api-security/api-rate-limit-bypass-testing/SKILL.md": `---
name: api-rate-limit-bypass-testing
description: Rate limiting bypass and throttling evasion testing
intent: offensive
---

# Rate Limit Bypass Testing
Bypass rate controls via header spray and counter drift.
`,
		"api-security/implementing-rate-limit-throttling/SKILL.md": `---
name: implementing-rate-limit-throttling
description: Rate limiting and throttling implementation and configuration guidance
intent: defensive
---

# Implementing Rate Limiting
Configure throttling controls and quotas.
`,
	}
	for path, content := range files {
		os.MkdirAll(filepath.Join(dir, filepath.Dir(path)), 0755)
		os.WriteFile(filepath.Join(dir, path), []byte(content), 0644)
	}
	return dir
}

// TestSearchSkills_OffensiveRanksAboveDefensive verifies that for a generic
// attack-context query, an offensive skill outranks a lexically-equivalent
// defensive implementation skill.
func TestSearchSkills_OffensiveRanksAboveDefensive(t *testing.T) {
	dir := setupIntentTestSkills(t)
	search := makeSearchSkills(os.DirFS(dir))

	res, err := search(map[string]string{"query": "rate limiting"})
	if err != nil {
		t.Fatalf("search error: %v", err)
	}
	offPos := strings.Index(res.Output, "api-rate-limit-bypass-testing")
	defPos := strings.Index(res.Output, "implementing-rate-limit-throttling")
	if offPos < 0 || defPos < 0 {
		t.Fatalf("expected both skills in results, got:\n%s", res.Output)
	}
	if offPos > defPos {
		t.Errorf("offensive skill should rank above defensive skill for attack-context query, got:\n%s", res.Output)
	}
}

// TestSearchSkills_DefensiveSearchableWhenRequested verifies defensive
// skills remain reachable and outrank offensive ones when the query
// explicitly asks for implementation guidance.
func TestSearchSkills_DefensiveSearchableWhenRequested(t *testing.T) {
	dir := setupIntentTestSkills(t)
	search := makeSearchSkills(os.DirFS(dir))

	res, err := search(map[string]string{"query": "implement rate limiting"})
	if err != nil {
		t.Fatalf("search error: %v", err)
	}
	defPos := strings.Index(res.Output, "implementing-rate-limit-throttling")
	offPos := strings.Index(res.Output, "api-rate-limit-bypass-testing")
	if defPos < 0 {
		t.Fatalf("defensive skill should be searchable when explicitly requested, got:\n%s", res.Output)
	}
	if offPos >= 0 && defPos > offPos {
		t.Errorf("defensive skill should rank first for an explicit defensive query, got:\n%s", res.Output)
	}
}

// TestParseSkillIntent verifies the intent frontmatter parser.
func TestParseSkillIntent(t *testing.T) {
	tests := []struct {
		fm   string
		want string
	}{
		{"intent: offensive\nname: x", "offensive"},
		{"intent: defensive\nname: x", "defensive"},
		{`intent: "offensive"`, "offensive"},
		{"intent: Offensive", "offensive"},
		{"intent: garbage", ""},
		{"name: x\ndescription: y", ""},
		{"", ""},
	}
	for _, tc := range tests {
		got := parseSkillIntent(tc.fm)
		if got != tc.want {
			t.Errorf("parseSkillIntent(%q) = %q, want %q", tc.fm, got, tc.want)
		}
	}
}

// TestSearchSkills_APISkillDiscovery verifies the consolidated API security
// skills are discoverable by natural queries, covering OWASP API6
// (business-flow abuse), API10 (unsafe third-party consumption), gRPC, and
// JSON-RPC.
func TestSearchSkills_APISkillDiscovery(t *testing.T) {
	subFS, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}
	search := makeSearchSkills(subFS)

	cases := []struct {
		query     string
		wantSkill string
	}{
		// API6: sensitive business-flow abuse
		{"coupon referral abuse automation", "api-business-flow-abuse"},
		{"otp sms sending throttling abuse", "api-business-flow-abuse"},
		// API10: unsafe third-party API consumption
		{"webhook signature validation bypass", "api-unsafe-third-party-consumption"},
		{"third-party api response trust poisoning", "api-unsafe-third-party-consumption"},
		// gRPC
		{"grpc reflection service method enumeration", "grpc-api-security"},
		// JSON-RPC
		{"json-rpc batch method authorization", "rpc-api-security"},
		// Consolidated specialists
		{"jwt none algorithm forgery", "jwt-security-testing"},
		{"broken object property level authorization mass assignment", "api-bopla"},
		{"object level authorization idor api", "api-bola"},
		{"function level authorization admin bypass", "api-bfla"},
		{"graphql introspection batching depth", "graphql-api-security"},
		{"api rate limit bypass resource consumption", "api-resource-consumption"},
		{"oauth redirect uri pkce bypass", "oauth-oidc-security"},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			res, err := search(map[string]string{"query": c.query})
			if err != nil {
				t.Fatalf("search error: %v", err)
			}
			if !strings.Contains(res.Output, c.wantSkill) {
				t.Fatalf("query %q: expected %q in results, got:\n%s", c.query, c.wantSkill, res.Output)
			}
		})
	}
}

// TestAPISkillEvidenceContracts verifies that the consolidated API skills
// teach the verified-only evidence model: status codes, field names, and
// schema availability alone must never be treated as proof.
func TestAPISkillEvidenceContracts(t *testing.T) {
	require := map[string]struct {
		path   string
		must   []string
		forbid []string
	}{
		"jwt-security-testing": {
			path:   "api-security/jwt-security-testing/SKILL.md",
			must:   []string{"does NOT prove", "NOT evidence"},
			forbid: []string{"accepted = response.status_code == 200", "[VULNERABLE]"},
		},
		"graphql-api-security": {
			path:   "api-security/graphql-api-security/SKILL.md",
			must:   []string{"NOT a standalone vulnerability", "Introspection is attack-surface intelligence"},
			forbid: []string{"depth > 10", "= HIGH"},
		},
		"api-bfla": {
			path:   "api-security/api-bfla/SKILL.md",
			must:   []string{"404 (route doesn't exist)", "NOT evidence"},
			forbid: []string{"not in (401, 403) {"},
		},
		"api-bopla": {
			path:   "api-security/api-bopla/SKILL.md",
			must:   []string{"Field NAMES alone are not evidence", "NOT evidence"},
			forbid: []string{},
		},
	}
	for name, spec := range require {
		t.Run(name, func(t *testing.T) {
			data, err := embeddedSkills.ReadFile("data/" + spec.path)
			if err != nil {
				t.Fatalf("read embedded skill: %v", err)
			}
			content := string(data)
			for _, m := range spec.must {
				if !strings.Contains(content, m) {
					t.Errorf("%s: expected evidence-contract text %q in skill content", name, m)
				}
			}
			for _, f := range spec.forbid {
				if strings.Contains(content, f) {
					t.Errorf("%s: skill content still contains false-positive logic %q", name, f)
				}
			}
		})
	}
}
