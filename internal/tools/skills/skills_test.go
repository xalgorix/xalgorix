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
		{"race-conditions", "race-condition-testing"},
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

// TestSearchSkills_CloudOffensiveDiscovery verifies each consolidated offensive
// cloud skill is discoverable by natural agent queries.
func TestSearchSkills_CloudOffensiveDiscovery(t *testing.T) {
	subFS, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}
	search := makeSearchSkills(subFS)

	cases := []struct {
		query     string
		wantSkill string
	}{
		{"cloud fingerprint target domain aws azure gcp", "cloud-attack-surface-discovery"},
		{"s3 bucket public access anonymous listing", "cloud-storage-exposure-testing"},
		{"imds metadata endpoint credentials ssrf", "cloud-metadata-workload-identity"},
		{"found aws access key what now", "cloud-credential-abuse"},
		{"aws pentest account enumeration iam", "aws-cloud-pentesting"},
		{"azure entra tenant service principal graph", "azure-entra-cloud-pentesting"},
		{"gcp project service account iam inheritance", "gcp-cloud-pentesting"},
		{"aws privilege escalation createpolicyversion", "aws-iam-privilege-escalation"},
		{"gcp service account impersonation actas", "gcp-iam-privilege-escalation"},
		{"azure application service principal credential escalation", "azure-privilege-escalation"},
		{"lambda function url public invoke serverless", "serverless-cloud-security"},
		{"cross account role trust assume role", "cloud-cross-account-tenant-trust"},
		{"secrets manager key vault retrieve", "cloud-secrets-data-access"},
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

// TestSearchSkills_CloudOffensiveRanksAboveDefensive verifies that for
// attack-context cloud queries, offensive methodology outranks defensive
// implementation and detection skills (which were moved out of cloud-security).
func TestSearchSkills_CloudOffensiveRanksAboveDefensive(t *testing.T) {
	subFS, _ := fs.Sub(embeddedSkills, "data")
	search := makeSearchSkills(subFS)

	res, err := search(map[string]string{"query": "aws cloud security privilege escalation"})
	if err != nil {
		t.Fatalf("search error: %v", err)
	}
	offPos := strings.Index(res.Output, "aws-iam-privilege-escalation")
	if offPos < 0 {
		t.Fatalf("expected offensive skill in results, got:\n%s", res.Output)
	}
	for _, def := range []string{"securing-aws-iam-permissions", "implementing-aws-security-hub", "detecting-aws-iam-privilege-escalation"} {
		defPos := strings.Index(res.Output, def)
		if defPos >= 0 && defPos < offPos {
			t.Errorf("defensive skill %q ranks above offensive skill for attack-context query, got:\n%s", def, res.Output)
		}
	}
}

// TestSearchSkills_CloudDefensiveSearchableWhenRequested verifies defensive
// cloud skills (moved to their proper categories) remain reachable for
// explicitly defensive queries and rank above offensive skills there.
func TestSearchSkills_CloudDefensiveSearchableWhenRequested(t *testing.T) {
	subFS, _ := fs.Sub(embeddedSkills, "data")
	search := makeSearchSkills(subFS)

	res, err := search(map[string]string{"query": "implement cloud security posture management"})
	if err != nil {
		t.Fatalf("search error: %v", err)
	}
	defPos := strings.Index(res.Output, "implementing-cloud-security-posture-management")
	if defPos < 0 {
		t.Fatalf("defensive cloud skill should remain searchable when explicitly requested, got:\n%s", res.Output)
	}
	offPos := strings.Index(res.Output, "aws-cloud-pentesting")
	if offPos >= 0 && offPos < defPos {
		t.Errorf("offensive skill should not outrank explicit defensive request, got:\n%s", res.Output)
	}
}

// TestSearchSkills_CloudDetectionSkillsFindable verifies detection-oriented
// cloud skills still surface for detection-context queries in their new
// category (threat-hunting).
func TestSearchSkills_CloudDetectionSkillsFindable(t *testing.T) {
	subFS, _ := fs.Sub(embeddedSkills, "data")
	search := makeSearchSkills(subFS)

	res, err := search(map[string]string{"query": "detect aws cloudtrail anomalies"})
	if err != nil {
		t.Fatalf("search error: %v", err)
	}
	if !strings.Contains(res.Output, "detecting-aws-cloudtrail-anomalies") {
		t.Fatalf("expected moved detection skill to remain findable, got:\n%s", res.Output)
	}
}

// TestSearchSkills_ForsetiNotPromoted verifies the retired (upstream-archived)
// Forseti methodology no longer exists as a first-class skill and that its
// historical alias resolves to the modern GCP assessment methodology.
func TestSearchSkills_ForsetiNotPromoted(t *testing.T) {
	subFS, _ := fs.Sub(embeddedSkills, "data")
	search := makeSearchSkills(subFS)

	res, _ := search(map[string]string{"query": "gcp security assessment forseti"})
	if strings.Contains(res.Output, "performing-gcp-security-assessment-with-forseti") {
		t.Fatalf("retired Forseti skill should no longer be promoted, got:\n%s", res.Output)
	}

	if got := resolveAlias("gcp-security-assessment-with-forseti"); got != "gcp-cloud-pentesting" {
		t.Errorf("forseti alias should resolve to modern GCP methodology, got %q", got)
	}
}

// TestResolveAlias_CloudOffensive verifies the new cloud alias surface.
func TestResolveAlias_CloudOffensive(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"s3", "cloud-storage-exposure-testing"},
		{"gcs", "cloud-storage-exposure-testing"},
		{"imds", "cloud-metadata-workload-identity"},
		{"managed-identity", "cloud-metadata-workload-identity"},
		{"aws-pentest", "aws-cloud-pentesting"},
		{"azure-pentest", "azure-entra-cloud-pentesting"},
		{"gcp-pentest", "gcp-cloud-pentesting"},
		{"actas", "gcp-iam-privilege-escalation"},
		{"passrole", "aws-iam-privilege-escalation"},
		{"key-vault", "cloud-secrets-data-access"},
		{"cloud-penetration-testing-with-pacu", "aws-cloud-pentesting"},
		{"aws-privilege-escalation-assessment", "aws-iam-privilege-escalation"},
		{"gcp-penetration-testing-with-gcpbucketbrute", "cloud-storage-exposure-testing"},
		{"aws-lambda-execution-roles", "serverless-cloud-security"},
		{"serverless-functions", "serverless-cloud-security"},
	}
	for _, tc := range tests {
		got := resolveAlias(tc.input)
		if got != tc.want {
			t.Errorf("resolveAlias(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestFrontmatterProviderMetadata verifies the frontmatter parser tolerates
// richer metadata (provider lists, assessment_mode) without breaking skill
// indexing or search.
func TestFrontmatterProviderMetadata(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "cloud-security", "test-cloud-skill"), 0755)
	os.WriteFile(filepath.Join(dir, "cloud-security", "test-cloud-skill", "SKILL.md"), []byte(`---
name: test-cloud-skill
description: Metadata tolerance test skill
intent: offensive
assessment_mode:
  - blackbox
  - credentialed
provider:
  - aws
  - gcp
---

# Test
Body.
`), 0644)

	search := makeSearchSkills(os.DirFS(dir))
	res, err := search(map[string]string{"query": "blackbox aws cloud"})
	if err != nil {
		t.Fatalf("search error: %v", err)
	}
	if !strings.Contains(res.Output, "test-cloud-skill") {
		t.Fatalf("expected skill with provider list metadata to be indexed and findable, got:\n%s", res.Output)
	}
}

// TestSearchSkills_ApplicationSecurityDiscovery verifies each new
// application-security skill is discoverable by the concepts it covers.
func TestSearchSkills_ApplicationSecurityDiscovery(t *testing.T) {
	subFS, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}
	search := makeSearchSkills(subFS)

	cases := []struct {
		query     string
		wantSkill string
	}{
		{"application attack surface model roles workflows states", "application-attack-surface-modeling"},
		{"session fixation logout invalidation replay", "authentication-session-testing"},
		{"mfa bypass password reset account recovery", "authentication-session-testing"},
		{"horizontal vertical tenant authorization boundary", "authorization-testing"},
		{"ownership transition revoked share access", "authorization-testing"},
		{"coupon quantity price business rules tampering", "business-logic-testing"},
		{"referral credit limits invariant violation", "business-logic-testing"},
		{"workflow step skipping state machine replay", "workflow-state-machine-testing"},
		{"cross-account token reuse stale state", "workflow-state-machine-testing"},
		{"type confusion mass assignment parameter domain", "input-boundary-testing"},
		{"duplicate parameters encoding differential parser", "input-boundary-testing"},
		{"double spend concurrent coupon race", "race-condition-testing"},
		{"toctou check then act limit overrun", "race-condition-testing"},
		{"file upload archive extraction transformation pipeline", "file-processing-pipeline-testing"},
		{"polyglot content type mismatch serve stage", "file-processing-pipeline-testing"},
		{"waf gateway path normalization differential", "security-control-differential-testing"},
		{"method override proxy layer interpretation", "security-control-differential-testing"},
		{"response over fetching export serializer exposure", "application-data-exposure-testing"},
		{"error response stack trace data leak", "application-data-exposure-testing"},
		{"source code sink trace reachability whitebox", "source-assisted-analysis"},
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

// TestSearchSkills_ApplicationSecurityRanking verifies black-box application
// skills outrank defensive implementation skills for pentest queries, and
// that the relocated DevSecOps/RASP/fuzzing skills no longer pollute
// application-security search results.
func TestSearchSkills_ApplicationSecurityRanking(t *testing.T) {
	subFS, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}
	search := makeSearchSkills(subFS)

	cases := []struct {
		query    string
		wantTop  string
		wantGone string
	}{
		{"application authentication testing session", "authentication-session-testing", "implementing-runtime-application-self-protection"},
		{"business logic workflow testing", "business-logic-testing", "implementing-devsecops-security-scanning"},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			res, err := search(map[string]string{"query": c.query})
			if err != nil {
				t.Fatalf("search error: %v", err)
			}
			lines := strings.Split(res.Output, "\n")
			// First result line starts with "• ".
			var first string
			for _, l := range lines {
				if strings.HasPrefix(l, "• ") {
					first = strings.TrimSpace(strings.TrimPrefix(l, "• "))
					break
				}
			}
			if first == "" || !strings.HasPrefix(first, c.wantTop) {
				t.Fatalf("query %q: expected first result %q, got:\n%s", c.query, c.wantTop, res.Output)
			}
			if strings.Contains(res.Output, c.wantGone) {
				t.Fatalf("query %q: relocated skill %q should not rank in pentest results, got:\n%s", c.query, c.wantGone, res.Output)
			}
		})
	}
}

// TestSearchSkills_MovedSkillsInNewCategories verifies the four relocated
// skills remain searchable within their new homes.
func TestSearchSkills_MovedSkillsInNewCategories(t *testing.T) {
	subFS, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}
	search := makeSearchSkills(subFS)

	cases := []struct {
		query    string
		category string
		want     string
	}{
		{"devsecops pipeline sast dast security gate", "devsecops", "implementing-devsecops-security-scanning"},
		{"rasp runtime protection block mode", "devsecops", "implementing-runtime-application-self-protection"},
		{"coverage guided binary fuzzing crash triage afl", "binary-exploitation", "performing-fuzzing-with-aflplusplus"},
		{"dependency confusion typosquat simulation pip-audit", "supply-chain-security", "performing-supply-chain-attack-simulation"},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			res, err := search(map[string]string{"query": c.query, "category": c.category})
			if err != nil {
				t.Fatalf("search error: %v", err)
			}
			if !strings.Contains(res.Output, c.want) {
				t.Fatalf("query %q in %q: expected %q, got:\n%s", c.query, c.category, c.want, res.Output)
			}
		})
	}
}

// TestApplicationSecurityCategoryContents verifies the category now consists
// of the black-box application reasoning skills only - no DevSecOps, RASP,
// fuzzing, or supply-chain implementation skills remain.
func TestApplicationSecurityCategoryContents(t *testing.T) {
	subFS, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}
	list := makeListSkills(subFS)
	res, err := list(map[string]string{"category": "application-security"})
	if err != nil {
		t.Fatalf("list error: %v", err)
	}
	for _, banned := range []string{
		"implementing-devsecops-security-scanning",
		"implementing-runtime-application-self-protection",
		"performing-fuzzing-with-aflplusplus",
		"performing-supply-chain-attack-simulation",
	} {
		if strings.Contains(res.Output, banned) {
			t.Fatalf("misplaced skill still in application-security: %s", banned)
		}
	}
	for _, want := range []string{
		"application-attack-surface-modeling",
		"authentication-session-testing",
		"authorization-testing",
		"business-logic-testing",
		"workflow-state-machine-testing",
		"input-boundary-testing",
		"race-condition-testing",
		"file-processing-pipeline-testing",
		"security-control-differential-testing",
		"application-data-exposure-testing",
		"source-assisted-analysis",
	} {
		if !strings.Contains(res.Output, want) {
			t.Fatalf("expected application-security skill %q in category listing, got:\n%s", want, res.Output)
		}
	}
}

// TestResolveAlias_ApplicationSecurity verifies remapped and new aliases
// resolve to the rebuilt skills.
func TestResolveAlias_ApplicationSecurity(t *testing.T) {
	cases := []struct{ in, want string }{
		{"broken-access-control", "authorization-testing"},
		{"bac", "authorization-testing"},
		{"business-logic", "business-logic-testing"},
		{"session", "authentication-session-testing"},
		{"session-management", "authentication-session-testing"},
		{"session-fixation", "authentication-session-testing"},
		{"race-condition", "race-condition-testing"},
		{"race-conditions", "race-condition-testing"},
		{"authorization", "authorization-testing"},
		{"tenant-isolation", "authorization-testing"},
		{"state-machine", "workflow-state-machine-testing"},
		{"type-confusion", "input-boundary-testing"},
		{"double-spend", "race-condition-testing"},
		{"toctou", "race-condition-testing"},
		{"zip-slip", "file-processing-pipeline-testing"},
		{"control-differential", "security-control-differential-testing"},
		{"over-fetching", "application-data-exposure-testing"},
		{"whitebox", "source-assisted-analysis"},
		{"source-assisted", "source-assisted-analysis"},
		{"fuzzing-with-aflplusplus", "performing-fuzzing-with-aflplusplus"},
		{"runtime-application-self-protection", "implementing-runtime-application-self-protection"},
		{"devsecops-security-scanning", "implementing-devsecops-security-scanning"},
		{"supply-chain-attack-simulation", "performing-supply-chain-attack-simulation"},
	}
	for _, tc := range cases {
		if got := resolveAlias(tc.in); got != tc.want {
			t.Errorf("resolveAlias(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestApplicationSecuritySkillMetadata verifies every rebuilt skill carries
// offensive intent metadata and that the source-assisted skill is tagged
// whitebox while remaining blackbox-first in positioning.
func TestApplicationSecuritySkillMetadata(t *testing.T) {
	dir := "data/application-security"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	offensive := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name(), "SKILL.md"))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		content := string(raw)
		if !strings.Contains(content, "intent: offensive") {
			t.Errorf("%s: missing 'intent: offensive' frontmatter", e.Name())
		} else {
			offensive++
		}
	}
	if offensive != 11 {
		t.Errorf("expected 11 offensive application-security skills, got %d", offensive)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "source-assisted-analysis", "SKILL.md"))
	if err != nil {
		t.Fatalf("read source-assisted-analysis: %v", err)
	}
	src := string(raw)
	for _, want := range []string{"whitebox: true", "blackbox: false", "phase: source-analysis"} {
		if !strings.Contains(src, want) {
			t.Errorf("source-assisted-analysis: missing frontmatter %q", want)
		}
	}
	if !strings.Contains(src, "BLACK BOX") {
		t.Errorf("source-assisted-analysis: missing black-box-first positioning")
	}
}

// TestSearchSkills_CloudRetrievalPrecision verifies the representative
// cloud retrieval behaviors: offensive provider queries rank the matching
// offensive skill first, and detection/implementation queries still find
// the defensive skills in their new homes.
func TestSearchSkills_CloudRetrievalPrecision(t *testing.T) {
	subFS, err := fs.Sub(embeddedSkills, "data")
	if err != nil {
		t.Fatalf("fs.Sub: %v", err)
	}
	search := makeSearchSkills(subFS)
	first := func(q string) string {
		res, err := search(map[string]string{"query": q})
		if err != nil {
			t.Fatalf("search %q: %v", q, err)
		}
		for _, l := range strings.Split(res.Output, "\n") {
			if strings.HasPrefix(l, "• ") {
				return strings.TrimSpace(strings.TrimPrefix(l, "• "))
			}
		}
		return ""
	}
	cases := []struct{ query, wantFirst string }{
		{"aws privilege escalation", "aws-iam-privilege-escalation"},
		{"azure managed identity attack", "azure-"},
		{"gcp service account impersonation", "gcp-iam-privilege-escalation"},
		{"s3 public access", "cloud-storage-exposure-testing"},
	}
	for _, c := range cases {
		t.Run(c.query, func(t *testing.T) {
			if got := first(c.query); !strings.HasPrefix(got, c.wantFirst) {
				t.Fatalf("query %q: first result %q, want prefix %q", c.query, got, c.wantFirst)
			}
		})
	}
	for _, c := range []struct{ query, want string }{
		{"cloudtrail anomaly detection", "detecting-aws-cloudtrail-anomalies"},
		{"AWS Security Hub setup", "implementing-aws-security-hub"},
	} {
		t.Run(c.query, func(t *testing.T) {
			res, err := search(map[string]string{"query": c.query})
			if err != nil {
				t.Fatalf("search %q: %v", c.query, err)
			}
			if !strings.Contains(res.Output, c.want) {
				t.Fatalf("query %q: expected %q in results, got:\n%s", c.query, c.want, res.Output)
			}
		})
	}
}
