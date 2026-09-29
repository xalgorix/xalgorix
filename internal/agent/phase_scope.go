// Package agent — phase_scope.go implements the phase-selection layer of the
// methodology orchestration:
//
//	applicable class → canonical phase → AllowedPhases → schedule or suppress
//
// The operator's phase selection is enforced at PLAN GENERATION time (the
// primary authority): baseline classes, applicability extras, auth/IDOR lanes,
// and target-level obligations are only created for selected phases. A
// restricted selection still receives bounded TECHNICAL PREREQUISITES
// (marked Task.Prerequisite) so executing the selected phases is possible —
// Phase 10 needs upload routes, Phase 17 needs WebSocket URLs — without
// running excluded methodology or pretending Phase 1/3 were selected.
//
// Backstops (first-class tools, ledger seeding, skill suggestions) consult the
// same helpers, so no subsystem can resurrect an excluded lane.
package agent

import (
	"fmt"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/methodology"
)

// phaseScope is the resolved phase filter for one plan build or subsystem
// decision.
type phaseScope struct {
	allowed    []int // the operator's selection; empty = full methodology
	restricted bool  // len(allowed) > 0
}

// phaseScopeFor resolves the scope for a phase selection.
func phaseScopeFor(selection []int) phaseScope {
	return phaseScope{allowed: selection, restricted: len(selection) > 0}
}

// allows reports whether the scope contains a phase (empty = all).
func (s phaseScope) allows(phase int) bool {
	return methodology.Allows(s.allowed, phase)
}

// classAllowed reports whether the class's canonical phase is selected.
// Unknown classes are conservatively excluded under a restriction.
func (s phaseScope) classAllowed(class string) bool {
	if !s.restricted {
		return true
	}
	def, ok := LookupVulnClass(class)
	if !ok {
		return false
	}
	return s.allows(def.Phase)
}

// selectionNeedsRouteDiscovery reports whether any selected phase needs
// bounded route/content discovery as a technical prerequisite. A selected
// Phase 1 owes the comprehensive-recon contract, which itself includes
// content discovery; the testing phases need routes; pure domain-level
// phases (13 takeover, 15 mail, 16 cloud) carry their own discovery and do
// not owe a web wordlist pass; 20/22 are cross-cutting/terminal.
func selectionNeedsRouteDiscovery(selection []int) bool {
	for _, phase := range selection {
		switch phase {
		case 13, 15, 16, 20, 22:
			continue
		}
		if phase >= 1 && phase <= 21 {
			return true
		}
	}
	return false
}

// prerequisiteProfileNotes renders the bounded technical-prerequisite
// contract for a restricted phase selection: the minimum discovery needed to
// EXECUTE the selected phases, never full Phase 1/3 methodology and never
// excluded-phase work.
func prerequisiteProfileNotes(selection []int) string {
	var lines []string
	lines = append(lines,
		fmt.Sprintf("TECHNICAL PREREQUISITE — NOT Phase 1 methodology. Perform ONLY the bounded discovery the selected phases (%s) need:", selectedPhaseList(selection)),
		"- reachability: HTTP-probe the live hosts (status, redirects, titles); basic technology fingerprint only where it steers the selected work")
	seen := map[string]bool{}
	add := func(note string) {
		if note == "" || seen[note] {
			return
		}
		seen[note] = true
		lines = append(lines, note)
	}
	for _, phase := range selection {
		switch phase {
		case 2:
			add("- exposure surface: client bundles/JS and response differentials for anomaly and exposure discovery")
		case 5, 8:
			add("- auth/session surface mapping: login/registration/token/role flows (credentials themselves are NOT a prerequisite to enumerate the surface)")
		case 9:
			add("- API/GraphQL route discovery: crawl, first-party JS, OpenAPI/GraphQL documents — locate the structured API surface")
		case 10:
			add("- upload route discovery: locate upload/import/attach/avatar functionality (bounded crawl + keyword pass: upload, import, attach, file)")
		case 12:
			add("- application modeling: discover workflows, state-changing endpoints, business values (prices/quotas/roles) and multi-step flows")
		case 14:
			add("- redirect parameter inventory: url/next/return/continue/callback/destination parameters on routes that redirect")
		case 17:
			add("- WebSocket URL discovery: first-party JS bundles and Upgrade headers for ws://wss:// endpoints")
		case 18:
			add("- CMS fingerprint: identify the CMS/version only if a CMS is suspected")
		case 19:
			add("- external-reference inventory: href/src references to third-party hosts in trusted in-scope pages")
		case 21:
			add("- feature/parameter inventory: map inputs and state transitions for the bounded anomaly pass")
		}
	}
	add("- skip historical URLs, full parameter mining, service/port enumeration, and mail checks unless a selected phase needs them")
	add("- do NOT run methodology of excluded phases (no injection probing, no business-logic lanes, etc.); record an explicit disposition for lanes the surface proves absent")
	return strings.Join(lines, "\n")
}

// selectedPhaseList renders "9 (API & GraphQL Testing), 10 (File Upload…)".
func selectedPhaseList(selection []int) string {
	parts := make([]string, 0, len(selection))
	for _, phase := range selection {
		if name := methodology.PhaseName(phase); name != "" {
			parts = append(parts, fmt.Sprintf("%d %s", phase, name))
		}
	}
	return strings.Join(parts, ", ")
}

// ── Target-level obligation signals ───────────────────────────────────────────
//
// Whole-target classes activate from scan-level surface evidence (black-box
// observable only): observed traffic, fingerprints, discovered hosts, scope
// shape. Source assistance may add evidence but nothing here requires it.

// webSurfaceObserved reports whether any live web surface is known.
func webSurfaceObserved(state *ScanState) bool {
	return state != nil && (len(state.DiscoveredEndpoints) > 0 || len(state.SeededSurface) > 0)
}

// cookieSurfaceObserved reports whether cookie evidence exists (cookie-auth
// flow observed). Cookie attribute analysis without any cookie surface is
// not applicable, and missing cookie attributes are configuration facts —
// never automatically vulnerabilities.
func cookieSurfaceObserved(state *ScanState) bool {
	return state != nil && state.CookieAuthObserved
}

// mailSurfaceApplicable reports whether scope/evidence supports mail
// infrastructure testing: a bare-domain/wildcard scope (MX-observable) or a
// discovered mail host. Public DNS records alone are never findings.
func mailSurfaceApplicable(state *ScanState) bool {
	if state == nil {
		return false
	}
	if subdomainScopeApplicable(state) {
		return true
	}
	for host := range state.DiscoveredHosts {
		if hostLooksLikeMail(host) {
			return true
		}
	}
	for _, ep := range state.DiscoveredEndpoints {
		if host := hostOfEndpoint(ep); host != "" && hostLooksLikeMail(host) {
			return true
		}
	}
	return false
}

func hostLooksLikeMail(host string) bool {
	lh := strings.ToLower(host)
	return strings.HasPrefix(lh, "mail.") ||
		strings.HasPrefix(lh, "smtp.") ||
		strings.HasPrefix(lh, "imap.") ||
		strings.HasPrefix(lh, "autodiscover.") ||
		strings.HasPrefix(lh, "mx.") ||
		strings.HasSuffix(lh, ".mail")
}

// cloudTechKeys are DetectedTechs keys that indicate cloud/infrastructure
// surface. A plain CDN (cloudflare) is deliberately NOT cloud-infra
// evidence — applicability first.
var cloudTechKeys = []string{"aws", "azure", "gcp", "kubernetes", "firebase", "cloudfront"}

// cloudStorageSignals match discovered endpoint/host strings for
// object-storage services.
var cloudStorageSignals = []string{
	"s3.amazonaws.com", ".s3.amazonaws.com", "storage.googleapis.com", ".blob.core.windows.net",
	"firebaseio.com", "cloudfront.net", ".appspot.com", "digitaloceanspaces.com",
}

// cloudConfigEvidence reports whether cloud/infrastructure posture evidence
// exists: a cloud tech fingerprint, a cloud-service hostname in the surface,
// or metadata-service probing already observed. Scheduling every cloud class
// because a CDN is present is explicitly NOT the behavior.
func cloudConfigEvidence(state *ScanState) bool {
	if state == nil {
		return false
	}
	for _, key := range cloudTechKeys {
		if state.DetectedTechs[key] {
			return true
		}
	}
	return cloudHostEvidence(state, cloudStorageSignals)
}

// cloudStorageEvidence reports whether object-storage/identity surface is
// referenced by the discovered endpoints or hosts.
func cloudStorageEvidence(state *ScanState) bool {
	if state == nil {
		return false
	}
	for _, key := range cloudTechKeys {
		if state.DetectedTechs[key] {
			return true
		}
	}
	return cloudHostEvidence(state, cloudStorageSignals)
}

func cloudHostEvidence(state *ScanState, signals []string) bool {
	candidates := make([]string, 0, len(state.DiscoveredEndpoints)+len(state.DiscoveredHosts))
	candidates = append(candidates, state.DiscoveredEndpoints...)
	for host := range state.DiscoveredHosts {
		candidates = append(candidates, host)
	}
	for _, candidate := range candidates {
		lc := strings.ToLower(candidate)
		for _, signal := range signals {
			if strings.Contains(lc, signal) {
				return true
			}
		}
	}
	return false
}

// cmsTechKeys are DetectedTechs keys indicating a CMS/plugin ecosystem.
var cmsTechKeys = []string{"wordpress", "drupal", "joomla", "magento", "ghost"}

// cmsEvidence reports whether a CMS was fingerprinted (detected techs or
// CMS-specific paths in the discovered surface). CMS methodology is never run
// against arbitrary PHP sites.
func cmsEvidence(state *ScanState) bool {
	if state == nil {
		return false
	}
	for _, key := range cmsTechKeys {
		if state.DetectedTechs[key] {
			return true
		}
	}
	for _, ep := range state.DiscoveredEndpoints {
		lc := strings.ToLower(ep)
		if strings.Contains(lc, "wp-content") || strings.Contains(lc, "wp-json") ||
			strings.Contains(lc, "/sites/all/") || strings.Contains(lc, "drupal") ||
			strings.Contains(lc, "joomla") || strings.Contains(lc, "magento") {
			return true
		}
	}
	return false
}

// externalReferenceEvidence reports whether trusted in-scope pages referenced
// external resources (the broken-link-hijacking / content-spoofing surface
// signal recorded by hookExternalReferenceTracker).
func externalReferenceEvidence(state *ScanState) bool {
	return state != nil && len(state.ExternalReferences) > 0
}

// richDynamicSurface reports whether the observed surface is rich enough to
// owe a bounded novel-discovery pass: state-changing or parameterized
// endpoints beyond a small static site. Small/static targets disposition
// Phase 21 not_applicable instead of an infinite creativity gate.
func richDynamicSurface(state *ScanState) bool {
	if state == nil || len(state.DiscoveredEndpoints) == 0 {
		return false
	}
	dynamic := 0
	for _, ep := range state.DiscoveredEndpoints {
		se := buildSurfaceEndpoint(state, ep)
		if se.stateChanging() || se.HasFeature("parameterized") || se.HasFeature("workflow") {
			dynamic++
		}
	}
	return dynamic >= 3
}

// targetObligationClasses returns the whole-target classes whose surface
// evidence exists, filtered by the phase scope. Order is deterministic.
func targetObligationClasses(state *ScanState, scope phaseScope) []string {
	if state == nil {
		return nil
	}
	type signal struct {
		class string
		ok    bool
	}
	signals := []signal{
		{"cors", webSurfaceObserved(state)},
		{"cookie-security", cookieSurfaceObserved(state)},
		{"subdomain-takeover", subdomainScopeApplicable(state)},
		{"email-security", mailSurfaceApplicable(state)},
		{"cloud-config", cloudConfigEvidence(state)},
		{"cloud-storage", cloudStorageEvidence(state)},
		{"cms-security", cmsEvidence(state)},
		{"broken-link-hijacking", externalReferenceEvidence(state)},
		{"content-spoofing", state.FormsObserved || webSurfaceObserved(state) && surfaceHasParameterizedEndpoints(state)},
		{"novel-testing", richDynamicSurface(state)},
	}
	var out []string
	for _, s := range signals {
		if !s.ok || !scope.classAllowed(s.class) {
			continue
		}
		out = append(out, s.class)
	}
	sort.Strings(out)
	return out
}

func surfaceHasParameterizedEndpoints(state *ScanState) bool {
	for _, ep := range state.DiscoveredEndpoints {
		if se := buildSurfaceEndpoint(state, ep); se.HasFeature("parameterized") {
			return true
		}
	}
	return false
}

// appendTargetObligations adds one whole-target task per target-level class
// whose evidence exists and whose phase is selected. These tasks complete on
// scan-level class evidence (or a typed disposition); phases without surface
// simply never appear.
func appendTargetObligations(state *ScanState, p *Plan, scope phaseScope) {
	for _, class := range targetObligationClasses(state, scope) {
		t := wholeTargetTask(class)
		if t == nil {
			continue
		}
		if p.Get(t.ID) != nil {
			t.ID += "-obligation"
		}
		p.add(t)
	}
}

// wholeTargetTask builds the engine-owned task for a target-scoped class.
func wholeTargetTask(class string) *Task {
	def, ok := LookupVulnClass(class)
	if !ok {
		return nil
	}
	t := &Task{
		ID:          "test-" + class,
		Title:       targetObligationTitle(class),
		Phase:       def.Phase,
		VulnClass:   class,
		Status:      TaskPending,
		DependsOn:   []string{"recon"},
		Origin:      "auto",
		WholeTarget: true,
		Notes:       targetObligationNotes(class),
	}
	if skill, ok := VulnClassSkill(class); ok && skill != "" {
		t.Notes += " Load the methodology first: read_skill(name=\"" + skill + "\")."
	}
	return t
}

func targetObligationTitle(class string) string {
	switch class {
	case "cors":
		return "CORS policy analysis (Phase 4) — origin reflection, credentials, cross-origin behavior"
	case "cookie-security":
		return "Cookie & session analysis (Phase 4) — Secure/HttpOnly/SameSite, scope, session behavior"
	case "subdomain-takeover":
		return "Subdomain takeover checks (Phase 13) — CNAME/dangling-record verification for the domain scope"
	case "email-security":
		return "Mail security testing (Phase 15) — in-scope mail service exposure and workflow abuse"
	case "cloud-config":
		return "Cloud & infrastructure posture (Phase 16) — identified cloud service exposure"
	case "cloud-storage":
		return "Cloud storage/identity exposure (Phase 16) — referenced object-storage and identity surfaces"
	case "cms-security":
		return "CMS-specific testing (Phase 18) — version/plugin/theme triage for the fingerprinted CMS"
	case "broken-link-hijacking":
		return "Broken link hijacking (Phase 19) — verify trusted references to external resources"
	case "content-spoofing":
		return "Content spoofing (Phase 19) — user-controlled content in trusted rendering contexts"
	case "novel-testing":
		return "Bounded novel vulnerability discovery (Phase 21) — application-specific anomaly pass"
	}
	return "Test " + class
}

// targetObligationNotes carries the methodology contract for each
// target-level lane: what to test, what is NOT a finding, and the stopping
// rule.
func targetObligationNotes(class string) string {
	switch class {
	case "cors":
		return "Probe cross-origin behavior on the app surface: reflected/allowed Origin values, Access-Control-Allow-Credentials, wildcard+credentials combinations, and preflight handling. Established exploitability rules apply: an open CORS policy without credentialed impact is a finding only with a concrete cross-origin data/credential effect — do not report misconfiguration alone."
	case "cookie-security":
		return "Analyze every Set-Cookie surface: Secure/HttpOnly/SameSite attributes, Scope (Domain/Path), session cookie rotation, and cross-origin credential behavior. Missing attributes are configuration observations — report them as vulnerabilities only with demonstrated impact; this lane is testing methodology, not a finding generator."
	case "subdomain-takeover":
		return "Enumerate subdomains for the domain scope, resolve CNAME/NS records for each, and check dangling or third-party-hosted targets against known takeover signatures (unclaimed S3/Heroku/GitHub Pages/Ghost/Zendesk...). Only in-scope discovered hosts may be verified; a takeover claim requires a concrete registration proof, not just a CNAME. A dangling-looking record behind an active provider NXDOMAIN is a hypothesis, not a finding."
	case "email-security":
		return "Only where mail infrastructure is in scope: enumerate MX/mail hosts for the scope domain, test mail service exposure and email workflow/token abuse (verification-link behavior, spoofing posture WITH demonstrated impact). Public DNS records (MX/TXT/SPF/DKIM/DMARC existence) are configuration observations, not vulnerabilities; standard mail ports being open are not findings."
	case "cloud-config":
		return "Test the cloud/infrastructure surface actually identified on the target: metadata endpoints behind SSRF-class primitives, exposed cloud service config, container/CI hints. Do NOT probe third-party infrastructure outside scope. A cloud hostname reference alone is applicability, never proof."
	case "cloud-storage":
		return "Verify referenced object-storage/identity surfaces: bucket listing, permissive ACLs, exposed credentials in referenced assets. Applicability comes from observed references only; do not blind-probe storage accounts that are not part of the target."
	case "cms-security":
		return "A CMS was fingerprinted: confirm version, enumerate plugins/themes, triage known-vulnerable extensions against the live instance, and test CMS-specific auth/config/admin/debug surfaces. Do not run CMS methodology against sites without a CMS fingerprint."
	case "broken-link-hijacking":
		return "For trusted in-scope pages referencing external resources: check whether referenced hosts/resources are dead or unclaimable, and verify the in-scope trust/reference weakness without probing unrelated third-party infrastructure beyond a single reachability check. A hijack claim requires the dangling reference plus a demonstrated claim/registration path."
	case "content-spoofing":
		return "Test user-controlled content rendered in trusted contexts: profile fields, message bodies, embedded/link previews, error pages. A finding requires demonstrated spoofed-content rendering a victim would trust — reflection alone is not proof."
	case "novel-testing":
		return "Bounded application-specific anomaly pass AFTER the ordinary applicable lanes settle: boundary/type confusion, unexpected sequencing, cross-feature chaining, parser and method/content-type differentials, cache/proxy inconsistencies, state-machine edge cases, creative parameter combinations. Do NOT duplicate completed Phase 12 work. Stopping rule: one focused pass over the highest-value flows — stop when a full pass yields no new anomaly; record the outcome either way (finding, or a concrete not_applicable/blocked disposition with what was covered)."
	}
	return ""
}
