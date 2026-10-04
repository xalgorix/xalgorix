// Package agent — vuln_classes.go is the single canonical registry of
// vulnerability classes. The same class knowledge was previously hardcoded
// independently in the planner (requiredCoverageClasses/classPhase), the
// specialist profiles, the coverage-normalization switch, the finish-gate
// nudges and the ledger seeds — letting them drift (a specialist owning
// business-logic while no plan task or hypothesis ever carried that class).
// Every subsystem now normalizes through this registry: canonical ID, aliases,
// methodology phase, specialist owner, and the deterministic skill query that
// resolves the class to its testing methodology.
//
// The Phase field is the ONLY class→phase mapping in the codebase. The
// planner's historical classPhase() switch (which defaulted every unknown
// class to Phase 6) is gone; classPhase() now resolves through this registry
// and returns 0 for unknown classes so nothing can silently masclassify as
// injection.
package agent

import (
	"sort"
	"strings"
	"sync"

	"github.com/xalgord/xalgorix/v4/internal/tools/skills"
)

// VulnClassDefinition is the canonical description of one vulnerability class.
type VulnClassDefinition struct {
	// ID is the canonical class identifier — the coverage-matrix key and the
	// plan task class. Aliases normalize onto it.
	ID string
	// Aliases are alternate spellings used across prompts, tools, ledgers and
	// specialist task text (bola, broken-access-control, …).
	Aliases []string
	// Phase is the canonical methodology phase (1-22, internal/methodology)
	// the class's testing work maps to. Cross-cutting classes carry ONE
	// canonical phase for bookkeeping even when their testing methodology
	// spans phases (e.g. command injection stays in the generic injection
	// lane while deserialization-gadget RCE maps to Phase 11).
	Phase int
	// Specialist is the owning specialist lane ("" = root/coordinator-owned).
	Specialist string
	// SkillQuery resolves the class's testing methodology via
	// skills.ResolveSkillName — the deterministic skill-resolution layer.
	SkillQuery string
	// Description is a one-line human/model-facing summary.
	Description string
	// WholeTarget marks classes whose methodology is inherently target-scoped
	// rather than per-endpoint: their plan task completes on scan-level
	// class evidence (VulnClassesTested) instead of the endpoint × class
	// coverage matrix (CORS policy, mail posture, CMS fingerprint, …).
	WholeTarget bool
	// Exploratory marks whole-target classes whose evidence is the
	// exploration itself (novel-discovery, content-spoofing): the engine
	// cannot mechanically verify the lane, so a concrete update_plan note
	// may complete their task.
	Exploratory bool
}

// vulnClassRegistry is the ordered canonical registry. IDs match the historical
// coverage-matrix keys exactly so existing persisted state keeps resolving.
//
// Canonical phase placements (cross-cutting classes choose ONE lane):
//   - cmdi (OS command injection) stays in the generic injection lane (6);
//     deserialization-gadget / JNDI / code-execution RCE maps to Phase 11.
//   - mass-assignment is placed in Phase 8 (access-control family: writable
//     property abuse is property-level authorization).
//   - parameter_mining maps to Phase 2 (manual discovery), NOT Phase 4 —
//     Phase 4 is real CORS & cookie analysis.
//   - csrf maps to Phase 5 (ambient-cookie authority abuse travels with the
//     authentication & session lane).
var vulnClassRegistry = []VulnClassDefinition{
	// Injection family
	{ID: "sqli", Aliases: []string{"sql-injection", "sql_injection", "blind-sqli", "sql"}, Phase: 6, Specialist: "injection-serverside", SkillQuery: "sql injection", Description: "SQL injection across input sinks"},
	{ID: "nosqli", Aliases: []string{"nosql-injection", "mongodb-injection", "no-sql-injection"}, Phase: 6, Specialist: "injection-serverside", SkillQuery: "nosql injection", Description: "NoSQL/MongoDB operator injection in JSON inputs"},
	{ID: "ssti", Aliases: []string{"server-side-template-injection", "template-injection"}, Phase: 6, Specialist: "injection-serverside", SkillQuery: "ssti", Description: "Server-side template injection"},
	{ID: "cmdi", Aliases: []string{"command-injection", "os-command-injection", "shell-injection", "expression-injection", "jdbc-injection"}, Phase: 6, Specialist: "injection-serverside", SkillQuery: "command injection", Description: "OS command / expression injection"},
	{ID: "path_traversal", Aliases: []string{"lfi", "local-file-inclusion", "path-traversal", "directory-traversal", "rfi", "remote-file-inclusion", "file-read"}, Phase: 6, Specialist: "injection-serverside", SkillQuery: "path traversal lfi", Description: "Path/directory traversal and local file inclusion"},
	{ID: "crlf", Aliases: []string{"crlf-injection", "http-response-splitting"}, Phase: 6, Specialist: "injection-serverside", SkillQuery: "crlf injection", Description: "CRLF / HTTP response splitting"},
	{ID: "redos", Aliases: []string{"regex-dos", "regex-denial-of-service", "catastrophic-backtracking"}, Phase: 6, Specialist: "", SkillQuery: "", Description: "Bounded regular-expression denial-of-service testing after other lanes", WholeTarget: true},
	{ID: "xxe", Aliases: []string{"xml-external-entity"}, Phase: 7, Specialist: "injection-serverside", SkillQuery: "xxe", Description: "XML external entity injection on XML-parsing surfaces"},
	{ID: "ssrf", Aliases: []string{"server-side-request-forgery"}, Phase: 7, Specialist: "injection-serverside", SkillQuery: "ssrf", Description: "Server-side request forgery"},
	{ID: "file-upload", Aliases: []string{"file-upload-bypass", "upload-bypass", "file-processing"}, Phase: 10, Specialist: "injection-serverside", SkillQuery: "file upload", Description: "File upload validation bypass and pipeline abuse"},
	{ID: "websocket", Aliases: []string{"websockets", "socket"}, Phase: 17, Specialist: "injection-serverside", SkillQuery: "websocket", Description: "WebSocket origin/authorization/message abuse"},
	// Deserialization & RCE family (Phase 11)
	{ID: "deserialization", Aliases: []string{"insecure-deserialization", "deserialization-attack"}, Phase: 11, Specialist: "injection-serverside", SkillQuery: "deserialization", Description: "Insecure deserialization of serialized payloads"},
	{ID: "rce", Aliases: []string{"remote-code-execution", "code-execution", "code-injection", "jndi-injection"}, Phase: 11, Specialist: "injection-serverside", SkillQuery: "rce", Description: "Remote code execution primitives (incl. JNDI/gadget chains)"},
	// Client family
	{ID: "xss", Aliases: []string{"cross-site-scripting", "cross_site_scripting", "reflected-xss", "stored-xss"}, Phase: 6, Specialist: "client-source", SkillQuery: "xss", Description: "Reflected/stored cross-site scripting"},
	{ID: "dom-xss", Aliases: []string{"dom_xss", "domxss", "client-side-xss"}, Phase: 6, Specialist: "client-source", SkillQuery: "dom xss", Description: "DOM-based cross-site scripting"},
	{ID: "csrf", Aliases: []string{"cross-site-request-forgery"}, Phase: 5, Specialist: "client-source", SkillQuery: "csrf", Description: "Cross-site request forgery on ambient-cookie state changes"},
	{ID: "open-redirect", Aliases: []string{"openredirect", "redirect"}, Phase: 14, Specialist: "client-source", SkillQuery: "open redirect", Description: "Unvalidated redirect/forward"},
	{ID: "cors", Aliases: []string{"cors-misconfiguration"}, Phase: 4, Specialist: "client-source", SkillQuery: "cors", Description: "CORS misconfiguration analysis", WholeTarget: true},
	{ID: "cookie-security", Aliases: []string{"cookie-flags", "cookie-attributes", "session-cookie-security"}, Phase: 4, Specialist: "client-source", SkillQuery: "cookie-security", Description: "Cookie attribute and session-cookie behavior analysis", WholeTarget: true},
	{ID: "secret-exposure", Aliases: []string{"secrets-exposure", "secret-leak", "leaked-secrets", "api-key-exposure"}, Phase: 2, Specialist: "client-source", SkillQuery: "secret exposure", Description: "Exposed secrets in client bundles/responses"},
	{ID: "api-auth", Aliases: []string{"api-authentication", "broken-api-authentication"}, Phase: 5, Specialist: "client-source", SkillQuery: "api authentication", Description: "API authentication weaknesses"},
	// Authorization family (bola/bfla normalize to the idor matrix class)
	{ID: "idor", Aliases: []string{"bola", "broken-object-level-authorization", "broken-access-control", "bfla", "broken-function-level-authorization", "access-control", "authorization"}, Phase: 8, Specialist: "authz-logic", SkillQuery: "authorization idor", Description: "Broken object/function-level authorization"},
	{ID: "privilege-escalation", Aliases: []string{"privesc", "privilege-escalation-vertical"}, Phase: 8, Specialist: "authz-logic", SkillQuery: "privilege escalation", Description: "Vertical privilege escalation"},
	{ID: "auth-bypass", Aliases: []string{"authentication-bypass", "forced-browsing"}, Phase: 5, Specialist: "authz-logic", SkillQuery: "authentication bypass", Description: "Authentication bypass"},
	// Business/workflow family (does NOT require multiple identities)
	{ID: "business-logic", Aliases: []string{"business-logic-vulnerability", "workflow-bypass", "business-rule-abuse"}, Phase: 12, Specialist: "business-logic", SkillQuery: "business logic", Description: "Business-rule and workflow abuse"},
	{ID: "race-conditions", Aliases: []string{"race-condition", "toctou", "double-spend"}, Phase: 12, Specialist: "business-logic", SkillQuery: "race conditions", Description: "Race conditions on state-changing workflows"},
	{ID: "mass-assignment", Aliases: []string{"bopla", "mass-assignment-bopla"}, Phase: 8, Specialist: "business-logic", SkillQuery: "mass assignment", Description: "Mass assignment / writable property abuse (canonical placement: access-control family)"},
	// Authentication / session (root-owned lane)
	{ID: "auth", Aliases: []string{"authentication", "session", "auth-session", "session-management"}, Phase: 5, Specialist: "", SkillQuery: "authentication session", Description: "Authentication and session control testing"},
	// GraphQL and API/protocol surfaces
	{ID: "graphql", Aliases: []string{"graphql-api", "graphql-authorization"}, Phase: 9, Specialist: "injection-serverside", SkillQuery: "graphql", Description: "GraphQL introspection/batching/complexity and resolver abuse"},
	// Reconnaissance-owned classes
	{ID: "parameter_mining", Aliases: []string{"parameter-mining", "param_mining", "parameter-discovery"}, Phase: 2, Specialist: "recon-discovery", SkillQuery: "parameter mining", Description: "Hidden parameter/input discovery (manual discovery lane, NOT a CORS/cookie substitute)"},
	{ID: "dirbusting", Aliases: []string{"content-discovery", "directory-brute-force", "dirbust"}, Phase: 3, Specialist: "recon-discovery", SkillQuery: "", Description: "Content/directory discovery"},
	{ID: "file_disclosure", Aliases: []string{"file-disclosure", "source-disclosure"}, Phase: 2, Specialist: "recon-discovery", SkillQuery: "file disclosure", Description: "Exposed files, backups, source maps"},
	{ID: "subdomain-takeover", Aliases: []string{"subdomain-takeover-check"}, Phase: 13, Specialist: "recon-discovery", SkillQuery: "subdomain takeover", Description: "Dangling CNAME subdomain takeover", WholeTarget: true},
	{ID: "email-security", Aliases: []string{"spf-dkim-dmarc", "mail-security"}, Phase: 15, Specialist: "recon-discovery", SkillQuery: "email-security", Description: "Mail infrastructure and email workflow security where in scope", WholeTarget: true},
	{ID: "cloud-config", Aliases: []string{"cloud-configuration", "cloud-misconfiguration", "cloud-metadata", "container-k8s", "ci-cd-exposure"}, Phase: 16, Specialist: "recon-discovery", SkillQuery: "cloud-metadata", Description: "Cloud posture/metadata/container exposure", WholeTarget: true},
	{ID: "cloud-storage", Aliases: []string{"s3-bucket", "blob-storage", "storage-exposure", "cloud-identity"}, Phase: 16, Specialist: "recon-discovery", SkillQuery: "cloud storage", Description: "Cloud storage/identity exposure", WholeTarget: true},
	{ID: "information-exposure", Aliases: []string{"info-exposure", "information-disclosure", "sensitive-data-exposure"}, Phase: 2, Specialist: "recon-discovery", SkillQuery: "information exposure", Description: "Information exposure in static surfaces"},
	{ID: "prototype-pollution", Aliases: []string{"prototype_pollution", "prototype-pollution-client"}, Phase: 6, Specialist: "injection-serverside", SkillQuery: "prototype pollution", Description: "JavaScript prototype pollution"},
	{ID: "cms-security", Aliases: []string{"cms", "wordpress", "drupal", "joomla", "magento", "cms-fingerprinting"}, Phase: 18, Specialist: "recon-discovery", SkillQuery: "cms", Description: "CMS/plugin ecosystem testing when a CMS is fingerprinted", WholeTarget: true},
	{ID: "broken-link-hijacking", Aliases: []string{"blh", "broken-link", "dangling-reference"}, Phase: 19, Specialist: "client-source", SkillQuery: "broken link hijacking", Description: "Trusted references to dead/unclaimed external resources", WholeTarget: true, Exploratory: true},
	{ID: "content-spoofing", Aliases: []string{"content-injection"}, Phase: 19, Specialist: "client-source", SkillQuery: "content spoofing", Description: "User-controlled trusted-content rendering", WholeTarget: true, Exploratory: true},
	{ID: "novel-testing", Aliases: []string{"novel-discovery", "novel-application-testing", "zero-day-discovery"}, Phase: 21, Specialist: "", SkillQuery: "novel vulnerability discovery", Description: "Bounded application-specific anomaly exploration after ordinary lanes settle", WholeTarget: true, Exploratory: true},
}

// vulnClassIndex maps every canonical ID and alias (lowercased) to its
// registry entry.
var vulnClassIndex = func() map[string]VulnClassDefinition {
	idx := make(map[string]VulnClassDefinition, len(vulnClassRegistry)*2)
	for _, def := range vulnClassRegistry {
		idx[def.ID] = def
		for _, a := range def.Aliases {
			idx[strings.ToLower(strings.TrimSpace(a))] = def
		}
	}
	return idx
}()

// LookupVulnClass resolves a class name or alias to its canonical definition.
func LookupVulnClass(name string) (VulnClassDefinition, bool) {
	def, ok := vulnClassIndex[strings.ToLower(strings.TrimSpace(name))]
	return def, ok
}

// CanonicalVulnClassID returns the canonical class ID for a name/alias, or ""
// when unknown.
func CanonicalVulnClassID(name string) string {
	if def, ok := LookupVulnClass(name); ok {
		return def.ID
	}
	return ""
}

// VulnClassesForSpecialist returns the canonical class IDs owned by a
// specialist lane, in registry order.
func VulnClassesForSpecialist(role string) []string {
	role = strings.ToLower(strings.TrimSpace(role))
	var out []string
	for _, def := range vulnClassRegistry {
		if strings.EqualFold(def.Specialist, role) {
			out = append(out, def.ID)
		}
	}
	return out
}

// VulnClassSpecialist returns the owning specialist lane for a class (""
// = root-owned or unknown).
func VulnClassSpecialist(classID string) string {
	if def, ok := LookupVulnClass(classID); ok {
		return def.Specialist
	}
	return ""
}

// VulnClassWholeTarget reports whether the class's methodology is
// target-scoped (completes on scan-level evidence, not the endpoint × class
// matrix).
func VulnClassWholeTarget(classID string) bool {
	if def, ok := LookupVulnClass(classID); ok {
		return def.WholeTarget
	}
	return false
}

// VulnClassExploratory reports whether a whole-target class accepts a
// concrete update_plan note as completion evidence (the engine cannot
// mechanically verify an exploration lane).
func VulnClassExploratory(classID string) bool {
	if def, ok := LookupVulnClass(classID); ok {
		return def.Exploratory
	}
	return false
}

// vulnClassSkillCache memoizes class → skill resolution (the resolver walks
// the embedded index once per query; the cache keeps per-iteration planner
// calls free).
var vulnClassSkillCache = struct {
	sync.Mutex
	m map[string]string
}{m: make(map[string]string)}

// VulnClassSkill resolves a canonical class to its testing-methodology skill
// via the deterministic resolver. Returns ("", false) when the catalog has no
// strong match.
func VulnClassSkill(classID string) (string, bool) {
	def, ok := LookupVulnClass(classID)
	if !ok || def.SkillQuery == "" {
		return "", false
	}
	vulnClassSkillCache.Lock()
	name, cached := vulnClassSkillCache.m[def.ID]
	vulnClassSkillCache.Unlock()
	if cached {
		return name, name != ""
	}
	name, resolved := skills.ResolveSkillName(def.SkillQuery)
	vulnClassSkillCache.Lock()
	vulnClassSkillCache.m[def.ID] = name
	vulnClassSkillCache.Unlock()
	return name, resolved
}

// SortedVulnClassIDs returns all canonical IDs sorted (for deterministic
// telemetry output).
func SortedVulnClassIDs() []string {
	ids := make([]string, 0, len(vulnClassRegistry))
	for _, def := range vulnClassRegistry {
		ids = append(ids, def.ID)
	}
	sort.Strings(ids)
	return ids
}
