// Package methodology is the single canonical definition of the Xalgorix
// 22-phase testing methodology. It lives in its own dependency-free package
// so the agent planner, the reporting layer, and the web server all consume
// ONE registry — previously three unshared copies of the phase names
// (reporting.MethodologyPhaseNames, internal/web report.go, and the webui
// PHASES list) drifted independently, and the vulnerability-class registry
// carried yet another phase mapping.
//
// The phase NUMBER is taxonomy, not chronology: the engine schedules work
// from observed surface applicability, and a later phase may execute before
// an earlier one. The guarantee this package underwrites is that every
// selected/applicable phase receives a real, engine-visible obligation or an
// explicit disposition before a scan may claim complete coverage.
package methodology

// PhaseDefinition is one canonical methodology phase.
type PhaseDefinition struct {
	// ID is the stable phase number (1-22). IDs are the cross-system
	// contract: plan tasks, phase restrictions, scan records, reports and
	// the UI all key on them.
	ID int
	// Name is the canonical display name.
	Name string
	// Description is a one-line summary of what the phase covers.
	Description string
}

// Phases is the ordered canonical registry. IDs must stay stable for
// backward compatibility with persisted scan records; names may be refined
// only via registry review (the webui list is generated from this table).
var Phases = []PhaseDefinition{
	{ID: 1, Name: "Deep Reconnaissance & Attack Surface Mapping", Description: "Comprehensive surface discovery: DNS, services, crawling, JS/API analysis, fingerprinting, endpoint inventory"},
	{ID: 2, Name: "Manual Vulnerability Discovery", Description: "Manual anomaly and exposure discovery: hidden parameters, exposed secrets/files, response differentials, unusual behavior"},
	{ID: 3, Name: "Directory & File Discovery", Description: "Content discovery: wordlist passes, hidden paths, backups, source/config files"},
	{ID: 4, Name: "CORS & Cookie Analysis", Description: "Cross-origin policy and cookie attribute analysis: Secure/HttpOnly/SameSite, scope, cross-origin credential behavior"},
	{ID: 5, Name: "Authentication & Session Testing", Description: "Authentication and session controls: login bypass, JWT/session tokens, password reset, MFA/OTP, CSRF"},
	{ID: 6, Name: "Injection Testing", Description: "Input injection: SQLi, NoSQLi, XSS, SSTI, command injection, CRLF, path traversal, prototype pollution"},
	{ID: 7, Name: "SSRF / Server-Side Request & XML External Entity Testing", Description: "Server-side request forgery and XML external entity testing, including blind/OAST verification"},
	{ID: 8, Name: "IDOR & Broken Access Control", Description: "Broken object/function-level authorization, privilege escalation, cross-tenant access, mass assignment"},
	{ID: 9, Name: "API & GraphQL Testing", Description: "Structured API surface testing: GraphQL introspection/batching, protocol and application-interface abuse"},
	{ID: 10, Name: "File Upload Testing", Description: "Upload pipeline testing: multipart surfaces, upload/parse/convert/preview/retrieve abuse"},
	{ID: 11, Name: "Deserialization & RCE", Description: "Insecure deserialization and remote code execution primitives"},
	{ID: 12, Name: "Race Conditions & Business Logic", Description: "Workflow/state-machine abuse, concurrency races, replay, business-rule and value manipulation"},
	{ID: 13, Name: "Subdomain Takeover", Description: "Dangling CNAME/NS delegation and third-party hosting takeover on domain-scoped targets"},
	{ID: 14, Name: "Open Redirect Testing", Description: "Unvalidated redirect/forward parameters (url, next, return, callback, destination)"},
	{ID: 15, Name: "Email Security Testing", Description: "Mail infrastructure and email workflow abuse where in scope: service exposure, workflow/token abuse, spoofing posture"},
	{ID: 16, Name: "Cloud & Infrastructure", Description: "Cloud service exposure: storage, identity, metadata, container/k8s and CI/CD surfaces identified on the target"},
	{ID: 17, Name: "WebSocket Testing", Description: "WebSocket surface: origin/auth validation, message authorization, state abuse, input injection"},
	{ID: 18, Name: "CMS-Specific Testing", Description: "CMS/plugin ecosystem testing when a CMS is fingerprinted (WordPress, Drupal, Joomla, Magento, Ghost, ...)"},
	{ID: 19, Name: "Broken Link Hijacking & Content Spoofing", Description: "Trusted references to dead/unclaimed external resources and user-controlled trusted-content rendering"},
	{ID: 20, Name: "Exploit Verification", Description: "Cross-cutting verification state: every actionable candidate holds a verified/rejected/blocked disposition"},
	{ID: 21, Name: "Novel Vulnerability Discovery", Description: "Bounded application-specific anomaly exploration after ordinary applicable lanes settle"},
	{ID: 22, Name: "Final Report", Description: "Terminal reporting state: findings, methodology disposition and honest completion"},
}

// PhaseCount is the fixed number of canonical phases.
const PhaseCount = 22

// PhaseName returns the canonical display name for a phase ID, or "" when
// the ID is outside 1-22.
func PhaseName(id int) string {
	if id < 1 || id > PhaseCount {
		return ""
	}
	return Phases[id-1].Name
}

// ValidPhase reports whether id is a canonical phase.
func ValidPhase(id int) bool {
	return id >= 1 && id <= PhaseCount
}

// PhaseIDs returns all canonical phase IDs in order.
func PhaseIDs() []int {
	ids := make([]int, 0, PhaseCount)
	for _, p := range Phases {
		ids = append(ids, p.ID)
	}
	return ids
}

// Allows reports whether phase is within a phase selection. An EMPTY
// selection means the full methodology is allowed — never "no phases".
func Allows(selection []int, phase int) bool {
	if !ValidPhase(phase) {
		return false
	}
	if len(selection) == 0 {
		return true
	}
	for _, p := range selection {
		if p == phase {
			return true
		}
	}
	return false
}

// IsReconReportOnlySelection reports whether a non-empty selection consists
// exclusively of reconnaissance (1) and final reporting (22) — the
// recon-only contract.
func IsReconReportOnlySelection(selection []int) bool {
	if len(selection) == 0 {
		return false
	}
	for _, phase := range selection {
		if phase != 1 && phase != 22 {
			return false
		}
	}
	return true
}
