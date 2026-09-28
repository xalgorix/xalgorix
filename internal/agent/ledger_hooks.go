// Package agent — ledger_hooks.go makes the durable hypothesis/evidence ledger
// (internal/scanctx.LedgerStore) actually DRIVE the scan, rather than just being
// a store the model may or may not touch. It provides:
//
//   - hookLedgerSeed: once a plan exists, seed the shared ledger with one
//     hypothesis per planned vuln class so the graph is populated deterministically
//     (not solely dependent on the LLM calling record_hypothesis).
//   - buildDelegationNudge + specialist profiles: the coordinator's one-time
//     delegation prompt now assigns work from the ledger to well-defined
//     specialists, each with an explicit evidence contract and stopping rule.
//   - hookLedgerFinishGate: a precision gate that refuses to finish while a
//     hypothesis is marked proven but has no linked finding — enforcing
//     verify-by-execution and precision-over-volume.
//
// Hooks receive only *ScanState, so the ledger is resolved through the shared
// ScanContext via ScanContextID (nil-safe: unit tests without an active context
// simply no-op).
package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

var (
	advisoryCVEPattern      = regexp.MustCompile(`(?i)\bCVE-[0-9]{4}-[0-9]{4,7}\b`)
	advisoryFileNamePattern = regexp.MustCompile(`[^A-Za-z0-9-]`)
	advisoryRoutePattern    = regexp.MustCompile(`(?i)(/api/[a-z0-9._~!$&'()*+,;=:@%/-]+)`)
	advisoryRCEPattern      = regexp.MustCompile(`\brce\b`)
	versionedProductPattern = regexp.MustCompile(`(?i)\b([a-z][a-z0-9._-]{2,30})(?:\s+(?:oss|community|enterprise|server|cms))?\s+v?([0-9]+\.[0-9]+(?:\.[0-9]+){0,2}(?:[-+][a-z0-9._-]+)?)\b`)
)

type advisoryRouteCandidate struct {
	route string
	index int
	score int
}

// ledgerForState resolves the durable ledger for a scan state, or nil when the
// state has no owning context or the context is not active (e.g. unit tests).
func ledgerForState(state *ScanState) *scanctx.LedgerStore {
	if state == nil || state.ScanContextID == "" {
		return nil
	}
	if sc := scanctx.Get(state.ScanContextID); sc != nil {
		return sc.Ledger
	}
	return nil
}

// ── Deterministic specialist profiles ───────────────────────────────────────
//
// These formalize the three non-overlapping roles the coordinator delegates to.
// Encoding them as data (rather than free prose) makes the decomposition
// deterministic and testable, and lets each specialist carry an explicit
// evidence contract + stopping rule — the mechanism that turns "run more agents"
// into precise, verify-by-execution work. The class coverage deliberately targets
// the classes autonomous scanners are weakest at (blind injection via OOB, XSS
// via browser confirmation, multi-role authorization).
type specialistProfile struct {
	Role             string
	Focus            string
	VulnClasses      []string
	EvidenceContract string
	StoppingRule     string
}

var defaultSpecialistProfiles = []specialistProfile{
	{
		// Discovery lane: launches EARLY (as soon as the plan + ledger exist),
		// in parallel with the root's remaining baseline recon — not with the
		// testing wave. Deep enumeration beyond the root's bounded baseline is
		// the highest-leverage coverage lever: undiscovered surface is silently
		// untested surface (missed debug consoles, backup files, source maps).
		Role:  "recon-discovery",
		Focus: "Deep surface enumeration: crawling, content/file discovery, fingerprinting depth, hidden paths, parameter mining",
		VulnClasses: []string{
			"dirbusting", "parameter_mining", "file_disclosure", "subdomain-takeover",
			"email-security", "cms-fingerprinting", "cloud-config",
		},
		EvidenceContract: "surface DISCOVERY only — never exploit; report suspected exposures (open .git, readable backups, leaked config) as hypotheses for the testing lanes. Go BEYOND the root's already-inventoried baseline routes: extension-based content fuzzing (.bak/.old/.orig/.save, backup archives, .git/.env/config source files, debug consoles), recursive crawling of forms/links/JS-declared routes, source-map hunting, parameter mining (arjun/x8), CMS/plugin fingerprinting, mail-domain SPF/DKIM/DMARC checks, CNAME/takeover checks for discovered subdomains. LIVE-VERIFY every candidate route (a real HTTP response class, not a wordlist hit alone) and fold ALL new routes into a note titled 'Discovery Manifest' with the heading 'Discovered Endpoints:' followed by one path per line, so the coordinator's plan and the testing lanes absorb them. Do not re-run the root's baseline wordlist or re-fingerprint what the inventory already records",
		StoppingRule:     "bounded: stop when a full discovery pass over every technique adds no new live route to the Discovery Manifest, or the lane budget is exhausted; never re-enumerate already-inventoried routes",
	},
	{
		Role:             "authz-logic",
		Focus:            "Authorization and access control across identity boundaries",
		VulnClasses:      []string{"idor", "bola", "bfla", "privilege-escalation", "auth-bypass"},
		EvidenceContract: "only enter this lane when live reconnaissance provides the required account/session roles or an operator-supplied credential path; use a baseline request as the legitimate role AND the same request as another/lower-privileged role, showing a concrete cross-role difference (cross-user/cross-tenant data or a state-changing action) — the authz_matrix tool produces this differential automatically across role A / role B / anonymous. For EVERY user-scoped state-changing endpoint, test ownership AND uniqueness enforcement with two distinct identities (act as user A on user B\u2019s object or repeat user A\u2019s submission as user B — cross-user bookings/reservations/records must fail). For authentication flows, test token identity (two different users logging in must NOT receive identical or interchangeable tokens) and expiry enforcement (an expired token must be rejected), plus a bounded failed-login burst to check authentication rate limiting (stop early once the counter proves unlimited attempts; do not lock out real accounts). Do not substitute default-password spraying, account creation on a disabled signup flow, or offline hash cracking for missing role prerequisites",
		StoppingRule:     "do not stop after the first finding; exhaust every assigned object/action and role boundary, report each distinct proven failure, reject each safe hypothesis with its baseline, and finish only when no assigned queued/testing hypothesis remains",
	},
	{
		// Business/workflow lane: deliberately SEPARATE from authz-logic so a
		// single-identity (or anonymous) target keeps workflow abuse testing.
		// Business-logic, race-condition and mass-assignment probes do not
		// need a second account: double-submit, coupon abuse, price
		// manipulation, replay, state-machine bypass and concurrent-request
		// races are all provable with one identity against the workflow's
		// own invariants.
		Role:             "business-logic",
		Focus:            "Business logic, workflow abuse, and race conditions",
		VulnClasses:      []string{"business-logic", "race-conditions", "mass-assignment"},
		EvidenceContract: "for every state-changing workflow endpoint (checkout, coupon, booking, order, transfer, vote, refund, subscription), test the business invariants: replay/double-submit the same action and prove a duplicate effect; manipulate price/quantity/discount/limit values in both directions (negative quantity, zero cost, over-limit) and prove the server accepts or misprices; abuse the state machine (skip steps, revisit completed steps, submit out of order); for race-prone actions fire 5-20 concurrent identical requests (single identity is sufficient) and prove an invariant break such as a multi-use coupon, overdrawn balance, or duplicate booking. For writable-object endpoints (PUT/PATCH with JSON), test mass assignment of privileged properties (role, is_admin, price, owner_id) with one identity. A proven differential (baseline request vs. manipulated request) is required for each claim; a refused manipulation is a rejected hypothesis with its control",
		StoppingRule:     "do not stop after the first finding; exhaust every assigned workflow endpoint and invariant, report each distinct proven failure, reject each safe hypothesis with its baseline, and finish only when no assigned queued/testing hypothesis remains",
	},
	{
		Role:             "injection-serverside",
		Focus:            "Injection and server-side behavior",
		VulnClasses:      []string{"rce", "remote-code-execution", "code-injection", "expression-injection", "jndi-injection", "jdbc-injection", "sqli", "blind-sqli", "nosqli", "ssti", "cmdi", "ssrf", "xxe", "lfi", "path_traversal", "deserialization", "file-upload", "websocket"},
		EvidenceContract: "own remote/code-execution hypotheses as well as injection primitives, including version-matched public-advisory leads on a reachable route. For an exact product/version or CVE lead, use web_search/exploit_search and cve_search once, recover the authoritative request byte-for-byte, and replay that exact request before adapting it; preserve nested JSON, escaped Unicode/newlines, quoting, and Content-Type instead of reconstructing a multi-line payload ad hoc. Require a concrete exploitation outcome — extracted data, command/template output, a target-attributable out-of-band (interactsh/OAST) callback emitted by the claimed primitive, or verify_timing's repeated control/probe differential for an unambiguous safe delay primitive — not a version banner, reflected payload, scanner-origin callback, single slow response, or timing hunch. For RCE/CMDi, a RUNSCRIPT/URL/XML/webhook/database fetch proves only that fetch primitive; the callback must be emitted by an injected OS/runtime/template execution expression. For blind JVM/native-runtime exploits prefer a server-native safe primitive such as Thread.sleep over assuming curl/wget exists. Once one exact root cause is proven, report its strongest safe impact and move to the next distinct class/endpoint; do not repeatedly read more files or crack recovered hashes merely to inflate the same finding",
		StoppingRule:     "do not stop after the first finding; exhaust every assigned endpoint × class hypothesis, report each distinct proven issue, reject each safe hypothesis with its control, and finish only when no assigned queued/testing hypothesis remains",
	},
	{
		Role:             "client-source",
		Focus:            "Client/API surface, including discovered dynamic URL routes, and source-to-sink data flow when source is available",
		VulnClasses:      []string{"xss", "dom-xss", "csrf", "open-redirect", "cors", "secret-exposure", "api-auth", "content-spoofing", "broken-link-hijacking"},
		EvidenceContract: "use the first-class discover_client_routes on the live root/login page before manually downloading or grepping bundles, then inventory its dynamic path segments; it automatically browser-checks a bounded set of the highest-priority public prefixes when AngularJS signals are returned, and any AUTOMATED PATH-XSS CONFIRMED result must be reported immediately. Use browser_action command=verify_path_template_xss only for additional candidates. For other XSS/DOM contexts use command=verify_xss. Require browser-confirmed script execution, not reflection; for source review require an attacker-input→sensitive-sink path plus a live request that exercises it",
		StoppingRule:     "do not stop after the first finding; exhaust every assigned client/API/source hypothesis, report each distinct proven issue, reject each defended path with evidence, and finish only when no assigned queued/testing hypothesis remains",
	},
}

// renderSpecialistProfiles formats the profiles as a numbered contract list.
func renderSpecialistProfiles() string {
	var b strings.Builder
	for i, p := range defaultSpecialistProfiles {
		fmt.Fprintf(&b, "%d. %s (role \"%s\") — classes: %s.\n   Required proof: %s.\n   Stop rule: %s.\n",
			i+1, p.Focus, p.Role, strings.Join(p.VulnClasses, ", "), p.EvidenceContract, p.StoppingRule)
	}
	return b.String()
}

// buildDelegationNudge builds the coordinator's one-time multi-agent
// decomposition prompt. It assigns work from the shared ledger to the
// deterministic specialist profiles, each with an evidence contract, and points
// the coordinator at concrete schedulable hypotheses when the ledger is already
// populated.
func buildDelegationNudge(state *ScanState) string {
	var b strings.Builder
	b.WriteString(`🧭 MULTI-AGENT DECOMPOSITION: Recon is mature enough to split the assessment. Act as coordinator now: launch only the 1–3 NON-OVERLAPPING specialists whose prerequisites exist on the observed surface, each owning a bounded set of hypotheses from the shared ledger. Do not launch an authorization specialist when no usable accounts/sessions or signup path exists.

Specialist roles (use these exact roles and hold each to its evidence contract):
`)
	b.WriteString(renderSpecialistProfiles())
	b.WriteString(`
Drive the work from the shared hypothesis ledger so specialists never overlap:
- Call read_ledger(filter=schedulable) to see the open hypotheses.
- Give each specialist a DISJOINT lane with an explicit class list and endpoint/hypothesis set. It must repeatedly call claim_next_hypothesis(vuln_class=<one assigned class>) for every class in its lane until each class has no schedulable candidate left. One claim or one finding is never lane completion. (Use update_hypothesis(assigned_to=...) only for manual overrides.)
- Require each specialist to close EVERY claimed hypothesis: record evidence with add_hypothesis_evidence, set a final status of proven or rejected, report every distinct proven vulnerability immediately, link it with kind=finding_ref, then continue to the next claim. A proven vulnerability is a result, not a stopping signal.
- Before a specialist calls finish, it must read the ledger once more and confirm it owns no hypothesis still in queued/testing state. Its stopping condition is exhausted assigned work, never "one bug found."
- Keep coordinating while they run: incorporate every result with wait_agent/check_agent, independently verify candidates, and do not finish with an uncollected delegation or a proven-but-unreported hypothesis.
Do not delegate three generic scans or duplicate your own work.`)

	// Surface concrete schedulable hypotheses if the ledger is already seeded,
	// so the coordinator has something specific to assign.
	if l := ledgerForState(state); l != nil {
		if sched := l.Schedulable(8); len(sched) > 0 {
			b.WriteString("\n\nCurrently schedulable hypotheses:\n")
			for _, h := range sched {
				loc := strings.TrimSpace(h.VulnClass + " " + h.Endpoint)
				if h.Parameter != "" {
					loc += " [" + h.Parameter + "]"
				}
				fmt.Fprintf(&b, "  • %s: %s (confidence %.2f)\n", h.ID, loc, h.Confidence)
			}
		}
	}

	// Preserve the original recon context line (detected stack + surface).
	contextParts := []string{}
	if len(state.DetectedTechs) > 0 {
		techs := make([]string, 0, len(state.DetectedTechs))
		for tech := range state.DetectedTechs {
			techs = append(techs, tech)
		}
		sort.Strings(techs)
		contextParts = append(contextParts, "detected stack: "+strings.Join(techs, ", "))
	}
	if len(state.DiscoveredEndpoints) > 0 {
		end := minInt(4, len(state.DiscoveredEndpoints))
		contextParts = append(contextParts, "representative surface: "+strings.Join(state.DiscoveredEndpoints[:end], ", "))
	}
	if len(contextParts) > 0 {
		b.WriteString("\nCurrent context: " + strings.Join(contextParts, "; ") + ".")
	}
	return b.String()
}

// ── hookLedgerSeed ───────────────────────────────────────────────────────────
// Once a plan exists, seed the shared ledger with one hypothesis per planned
// vuln class so the graph is populated deterministically. This is a side effect
// only (no nudge) and runs once per agent; the ledger dedups, so the coordinator
// and any specialist that also seeds cannot create duplicates.
func hookLedgerSeed(state *ScanState, args map[string]string) HookResult {
	if state == nil || state.ReconOnlyMode || state.LedgerSeeded || state.Plan == nil {
		return HookResult{}
	}
	if l := ledgerForState(state); l != nil {
		seedLedgerFromPlan(state, l)
		state.LedgerSeeded = true
	}
	return HookResult{}
}

// seedLedgerFromPlan creates a class-level hypothesis for every planned task
// that targets a vuln class (structural tasks like recon/dirbust/verify/report
// carry no VulnClass and are skipped). Returns the number of new hypotheses.
func seedLedgerFromPlan(state *ScanState, l *scanctx.LedgerStore) int {
	if state == nil || state.Plan == nil || l == nil {
		return 0
	}
	seeded := 0
	for _, t := range state.Plan.Tasks {
		if strings.TrimSpace(t.VulnClass) == "" {
			continue
		}
		before := l.Len()
		l.Upsert(scanctx.Hypothesis{
			Title:      t.Title,
			VulnClass:  t.VulnClass,
			Endpoint:   t.Endpoint,
			Status:     scanctx.HypothesisQueued,
			Confidence: 0.4,
			Origin:     "auto-plan",
			NextAction: "Probe " + t.VulnClass + " across the discovered surface; record specific endpoints/params as their own hypotheses.",
		})
		if l.Len() > before {
			seeded++
		}
		// Surface × class seeding: every APPLICABLE (class, endpoint) pair
		// becomes a concrete, claimable hypothesis — bounded per class. This
		// is what guarantees a specialist calling
		// claim_next_hypothesis(vuln_class="business-logic") finds real work
		// instead of "No queued hypotheses" while the application has
		// untested checkout/coupon workflows. Idempotent via ledger dedup on
		// (vuln_class, endpoint, parameter, role).
		eps := ApplicableEndpointsForClass(state, t.VulnClass)
		for i, ep := range eps {
			if i >= maxSurfaceClassSeed {
				break
			}
			before := l.Len()
			l.Upsert(scanctx.Hypothesis{
				Title:      "Test " + t.VulnClass + " on " + ep,
				VulnClass:  t.VulnClass,
				Endpoint:   ep,
				Status:     scanctx.HypothesisQueued,
				Confidence: 0.5,
				Origin:     "auto-plan-surface",
				NextAction: "Probe " + ep + " for " + t.VulnClass + " with a benign control first, then the class-specific technique; record the differential as evidence.",
			})
			if l.Len() > before {
				seeded++
			}
		}
	}
	return seeded
}

// maxSurfaceClassSeed bounds endpoint-level hypotheses seeded per class so a
// large surface cannot flood the ledger; the class-level hypothesis plus the
// plan task notes still describe the remainder.
const maxSurfaceClassSeed = 6

// hookAdvisoryLeadCommitment turns an exact advisory lookup into durable work
// instead of disposable prose. The lookup remains a lead, never proof: this
// hook only seeds/strengthens the matching hypothesis and forces a route-level
// control/probe decision before the model wanders into broad recon. It is
// intentionally product-agnostic and fires only when the tool output contains
// an exact CVE plus a recognizable vulnerability mechanism.
func hookAdvisoryLeadCommitment(state *ScanState, args map[string]string) HookResult {
	if state == nil || !state.ProfessionalAssessment || state.ReconOnlyMode {
		return HookResult{}
	}
	toolName := strings.ToLower(strings.TrimSpace(args["tool_name"]))
	var leadParts []string
	switch toolName {
	case "cve_search", "exploit_search", "web_search":
		// Search output is expected to contain untrusted snippets, but only an
		// exact CVE plus a recognized mechanism can commit a hypothesis.
		leadParts = []string{args["query"], args["cve_id"], args["output"]}
	case "terminal_execute":
		// Inspect only the model-authored command, never the target-controlled
		// output. If the model already names a CVE while composing a probe, make
		// it recover the authoritative classification/request before improvising.
		leadParts = []string{args["command"]}
	case "add_note":
		// Notes are model-authored durable conclusions, so an exact CVE recorded
		// here is an intentional lead rather than untrusted page content.
		leadParts = []string{args["key"], args["value"]}
	case "record_hypothesis":
		leadParts = []string{args["title"], args["description"], args["next_action"], args["endpoint"], args["vuln_class"]}
	default:
		return HookResult{}
	}
	blob := strings.TrimSpace(strings.Join(leadParts, "\n"))
	cve := strings.ToUpper(advisoryCVEPattern.FindString(blob))
	if cve == "" && toolName == "add_note" {
		product, version := versionedProductLead(blob)
		if product == "" {
			return HookResult{}
		}
		key := strings.ToLower("version|" + product + "|" + version)
		if state.AdvisoryLeadsNudged == nil {
			state.AdvisoryLeadsNudged = make(map[string]bool)
		}
		if state.AdvisoryLeadsNudged[key] {
			return HookResult{}
		}
		state.AdvisoryLeadsNudged[key] = true
		return HookResult{Nudge: fmt.Sprintf("🔎 VERSIONED PRODUCT CHECKPOINT — your durable fingerprint identifies %s %s. Before delegation or generic breadth, perform ONE bounded web_search for `%s %s security vulnerabilities CVE`, then call cve_search for each credible exact CVE that matches this version. Convert only a mechanism-and-route match into a live hypothesis; a version match alone is never proof.", product, version, product, version)}
	}
	class := advisoryVulnClass(blob)
	if cve == "" {
		return HookResult{}
	}
	if class == "" {
		// exploit_search is intentionally lightweight and often returns only its
		// query plus an Exploit-DB link. Do not silently discard an exact CVE in
		// that sparse result: force the authoritative NVD classification before
		// the model fans out into generic reconnaissance. This still creates no
		// hypothesis because a CVE identifier alone is not an exploit mechanism.
		key := strings.ToLower("enrich|" + cve)
		if state.AdvisoryLeadsNudged == nil {
			state.AdvisoryLeadsNudged = make(map[string]bool)
		}
		if state.AdvisoryLeadsNudged[key] {
			return HookResult{}
		}
		state.AdvisoryLeadsNudged[key] = true
		return HookResult{Nudge: fmt.Sprintf("🔎 ADVISORY LEAD NEEDS CLASSIFICATION — %s is exact, but this result does not identify a vulnerability mechanism. Call cve_search with cve_id=%s NOW. Then perform one focused web_search for the same CVE's authoritative request method, route, body shape, and safe proof primitive before broad reconnaissance. Do not treat the identifier or version match as proof.", cve, cve)}
	}

	routes := rankedAdvisoryRoutes(blob, 3)
	key := strings.ToLower(cve + "|" + class + "|" + strings.Join(routes, ","))
	if state.AdvisoryLeadsNudged == nil {
		state.AdvisoryLeadsNudged = make(map[string]bool)
	}
	if state.AdvisoryLeadsNudged[key] {
		return HookResult{}
	}
	state.AdvisoryLeadsNudged[key] = true

	if l := ledgerForState(state); l != nil {
		seedRoutes := routes
		if len(seedRoutes) == 0 {
			seedRoutes = []string{""}
		}
		for _, route := range seedRoutes {
			next := "Recover the authoritative request method/body shape, establish a benign control, and test the exact reachable route safely. The advisory/version is not proof."
			if route != "" {
				next = "Test " + route + " directly by first replaying the advisory's exact request byte-for-byte, preserving nested JSON, escaped Unicode/newlines, quoting, and Content-Type; only then adapt a safe control/probe. Do not infer that this route is disabled merely because an adjacent setup, login, metadata, or UI workflow is disabled."
			}
			if class == "rce" || class == "sqli" || class == "ssti" {
				next += " If the effect is blind and a safe runtime delay primitive exists, call verify_timing; otherwise require target-attributable OAST emitted by the claimed primitive or in-band output. For RCE, an outbound RUNSCRIPT/URL fetch is not code execution proof."
			}
			l.Upsert(scanctx.Hypothesis{
				Title:      cve + " " + strings.ToUpper(class) + " advisory lead",
				VulnClass:  class,
				Endpoint:   route,
				Status:     scanctx.HypothesisQueued,
				Confidence: 0.75,
				Origin:     "advisory-lookup",
				NextAction: next,
			})
		}
	}

	route := "the exact advisory route"
	if len(routes) > 0 {
		route = strings.Join(routes, ", ")
	} else {
		route += " (no route was present in this result, so recover it with one focused web_search first)"
	}
	artifactNudge := ""
	if blob := extractLargestRequestBlock(args["output"]); blob != "" {
		if path, ok := persistAdvisoryRequest(state, cve, blob); ok {
			artifactNudge = fmt.Sprintf(" The authoritative request body was extracted VERBATIM from this result to %s — do NOT retype or reconstruct it (reconstruction is what breaks nested JSON and \\uXXXX escapes). Replay it exactly once from the file with terminal curl --data @%q, adjusting ONLY the Host and the harmless proof primitive (callback marker or server-native delay), and preserving the original Content-Type.", path, path)
		}
	}
	return HookResult{Nudge: fmt.Sprintf("🎯 ADVISORY LEAD COMMITTED — %s maps to the %s lane. Treat the advisory only as a request-shape lead, but resolve %s NOW before broad recon. First replay the authoritative request byte-for-byte, preserving nested JSON, escaped Unicode/newlines, quoting, and Content-Type; only then adapt a benign control and safe exploit probe. Test that route independently: a completed/disabled adjacent setup, login, or UI flow does not prove the vulnerable validation/API route is disabled. For a blind primitive, use verify_oob with the exact callback-bearing payload or verify_timing with a server-native harmless delay. For RCE, a RUNSCRIPT/URL/XML/webhook/database fetch proves only the fetch primitive; the callback must come from OS/runtime/template execution. Never rely on one slow response or assume curl/wget exists in the target.%s", cve, class, route, artifactNudge)}
}

// ── Advisory request artifact ───────────────────────────────────────────────
//
// Measured failure mode (r10/r11 Metabase evidence): the model recovers the
// authoritative public request via web/exploit search, then RECONSTRUCTS it
// from memory in a python heredoc and silently breaks the nested JSON or the
// \uXXXX escape sequences, so the exploit never executes and the run dies at
// the deadline doing terminal gymnastics. The generic fix: extract the
// request-shaped fragment from the advisory output VERBATIM, persist it into
// the scan workspace, and tell the model to replay it from the file.

// extractLargestRequestBlock returns the largest request-shaped fragment of
// advisory tool output: fenced code blocks first, then brace-balanced JSON
// bodies. Bytes are preserved exactly — this function must never normalize,
// re-quote, or re-encode anything (that is the whole point).
func extractLargestRequestBlock(output string) string {
	best := ""
	for _, block := range fencedCodeBlocks(output) {
		if len(block) > len(best) && requestShaped(block) {
			best = block
		}
	}
	for _, blob := range braceBalancedBlobs(output) {
		if len(blob) > len(best) && requestShaped(blob) {
			best = blob
		}
	}
	return strings.TrimSpace(best)
}

// requestShaped keeps extraction conservative so prose is never mistaken for
// a request body: something must look structured (JSON/assignment/command)
// AND name a path-like route.
func requestShaped(s string) bool {
	if len(s) < 80 {
		return false
	}
	if !strings.Contains(s, "/") {
		return false
	}
	structured := strings.Contains(s, "{") || strings.Contains(s, "=") ||
		strings.Contains(s, "curl") || strings.Contains(s, "POST ") || strings.Contains(s, "GET ")
	return structured
}

// fencedCodeBlocks returns the inner content of ``` and ~~~ fenced blocks.
func fencedCodeBlocks(output string) []string {
	var blocks []string
	for _, fence := range []string{"```", "~~~"} {
		rest := output
		for {
			start := strings.Index(rest, fence)
			if start < 0 {
				break
			}
			after := rest[start+len(fence):]
			end := strings.Index(after, fence)
			if end < 0 {
				break
			}
			inner := after[:end]
			// Allow an optional language tag line (```json, ```bash).
			if nl := strings.IndexByte(inner, '\n'); nl >= 0 && !strings.ContainsAny(inner[:nl], " {=") {
				inner = inner[nl+1:]
			}
			blocks = append(blocks, inner)
			rest = after[end+len(fence):]
		}
	}
	return blocks
}

// braceBalancedBlobs returns maximal brace-balanced substrings, tracking
// string literals and backslash escapes so JSON bodies with nested quotes and
// \uXXXX sequences extract whole.
func braceBalancedBlobs(output string) []string {
	var blobs []string
	for i := 0; i < len(output); i++ {
		if output[i] != '{' {
			continue
		}
		depth := 0
		inStr := false
		for j := i; j < len(output); j++ {
			c := output[j]
			switch {
			case inStr && c == '\\':
				j++ // skip the escaped character
			case inStr && c == '"':
				inStr = false
			case !inStr && c == '"':
				inStr = true
			case !inStr && c == '{':
				depth++
			case !inStr && c == '}':
				depth--
				if depth == 0 {
					blobs = append(blobs, output[i:j+1])
					i = j
					j = len(output)
				}
			}
		}
	}
	return blobs
}

// persistAdvisoryRequest writes the verbatim advisory request to
// <ScanDir>/advisory-replay/<cve>.request.txt (trusted scan sandbox root) and
// returns the absolute path for the replay nudge.
func persistAdvisoryRequest(state *ScanState, cve, blob string) (string, bool) {
	if state == nil || state.ScanContextID == "" {
		return "", false
	}
	sc := scanctx.Get(state.ScanContextID)
	if sc == nil || sc.ScanDir == "" {
		return "", false
	}
	safe := advisoryFileNamePattern.ReplaceAllString(strings.ToUpper(cve), "")
	if safe == "" {
		return "", false
	}
	dir := filepath.Join(sc.ScanDir, "advisory-replay")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", false
	}
	path := filepath.Join(dir, safe+".request.txt")
	if err := os.WriteFile(path, []byte(blob), 0o600); err != nil {
		return "", false
	}
	return path, true
}

func versionedProductLead(blob string) (string, string) {
	for _, match := range versionedProductPattern.FindAllStringSubmatch(blob, -1) {
		if len(match) != 3 {
			continue
		}
		product := strings.TrimSpace(match[1])
		version := strings.TrimSpace(match[2])
		switch strings.ToLower(product) {
		case "http", "https", "html", "build", "release", "version", "cve", "cvss":
			continue
		}
		return product, version
	}
	return "", ""
}

// rankedAdvisoryRoutes returns a small, stable list of likely exploit sinks.
// Search snippets frequently mention both a metadata/token-source endpoint and
// the state-changing sink. Selecting the first textual /api/ path caused the
// scanner to commit to the former, so rank action routes and local exploit
// language while demoting health/version/property endpoints. Product names and
// CVE-specific routes deliberately do not appear here.
func rankedAdvisoryRoutes(blob string, limit int) []string {
	if limit <= 0 {
		return nil
	}
	matches := advisoryRoutePattern.FindAllStringSubmatchIndex(blob, -1)
	byRoute := make(map[string]advisoryRouteCandidate)
	for _, match := range matches {
		if len(match) < 4 {
			continue
		}
		route := strings.TrimRight(blob[match[2]:match[3]], `.,:;)]}'"`)
		if route == "" {
			continue
		}
		candidate := advisoryRouteCandidate{route: route, index: match[2]}
		lowerRoute := strings.ToLower(route)
		for _, keyword := range []string{"validate", "execute", "trigger", "render", "compile", "import", "upload", "preview", "test", "query", "fetch", "callback", "webhook"} {
			if strings.Contains(lowerRoute, keyword) {
				candidate.score += 6
			}
		}
		for _, keyword := range []string{"health", "version", "status", "properties", "metadata", "login"} {
			if strings.Contains(lowerRoute, keyword) {
				candidate.score -= 5
			}
		}
		start := maxInt(0, match[2]-240)
		end := minInt(len(blob), match[3]+240)
		window := strings.ToLower(blob[start:end])
		for _, signal := range []string{"post ", "payload", "exploit", "trigger", "vulnerable", "code execution", "command execution", "request body"} {
			if strings.Contains(window, signal) {
				candidate.score += 2
			}
		}
		if previous, ok := byRoute[strings.ToLower(route)]; !ok || candidate.score > previous.score {
			byRoute[strings.ToLower(route)] = candidate
		}
	}
	candidates := make([]advisoryRouteCandidate, 0, len(byRoute))
	for _, candidate := range byRoute {
		candidates = append(candidates, candidate)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].index < candidates[j].index
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	routes := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		routes = append(routes, candidate.route)
	}
	return routes
}

func advisoryVulnClass(blob string) string {
	lower := strings.ToLower(blob)
	switch {
	case strings.Contains(lower, "remote code execution"), strings.Contains(lower, "arbitrary code execution"),
		strings.Contains(lower, "code injection"), strings.Contains(lower, "command injection"),
		strings.Contains(lower, "cwe-94"), strings.Contains(lower, "cwe-78"),
		advisoryRCEPattern.MatchString(lower):
		return "rce"
	case strings.Contains(lower, "sql injection"), strings.Contains(lower, "sqli"), strings.Contains(lower, "cwe-89"):
		return "sqli"
	case strings.Contains(lower, "server-side template injection"), strings.Contains(lower, "ssti"), strings.Contains(lower, "cwe-1336"):
		return "ssti"
	case strings.Contains(lower, "server-side request forgery"), strings.Contains(lower, "ssrf"), strings.Contains(lower, "cwe-918"):
		return "ssrf"
	case strings.Contains(lower, "xml external entity"), strings.Contains(lower, "xxe"), strings.Contains(lower, "cwe-611"):
		return "xxe"
	case strings.Contains(lower, "path traversal"), strings.Contains(lower, "directory traversal"), strings.Contains(lower, "cwe-22"):
		return "lfi"
	}
	return ""
}

// ── hookLedgerFinishGate ─────────────────────────────────────────────────────
// Precision gate: refuse to finish while a hypothesis is marked proven but has
// no linked finding. A proven hypothesis must become a reported, evidence-backed
// finding (or be downgraded if it was not actually exploitable). Registered
// AFTER hookFinishGatekeeper, so when both block the coverage reason surfaces
// first; self-bounded by FinishAttempts so it can never deadlock the scan.
func hookLedgerFinishGate(state *ScanState, args map[string]string) HookResult {
	if state == nil || state.DiscoveryMode || state.ReconOnlyMode {
		return HookResult{}
	}
	// hookFinishGatekeeper has already incremented FinishAttempts for this
	// attempt. Give the model a few chances to report, then get out of the way.
	if state.FinishAttempts > 3 {
		return HookResult{}
	}
	l := ledgerForState(state)
	if l == nil {
		return HookResult{}
	}
	owner := ""
	if state.DelegatedAgent {
		owner = state.DelegatedAgentID
	}
	unreported := provenUnreportedHypothesesForOwner(l, owner)
	inProgress := testingHypothesesForOwner(l, owner)
	// Lane completion (Part 15): a specialist's lane is exhausted only when
	// its ASSIGNED work is settled too. Pre-assigned hypotheses still queued
	// mean the lane was never worked, not that it is empty.
	unclaimed := assignedUnclaimedHypothesesForOwner(l, owner)
	if len(unreported) == 0 && len(inProgress) == 0 && len(unclaimed) == 0 {
		return HookResult{}
	}
	var reasons []string
	if len(unreported) > 0 {
		reasons = append(reasons, "proven but unreported: "+strings.Join(unreported, ", "))
	}
	if len(inProgress) > 0 {
		reasons = append(reasons, "claimed but not closed: "+strings.Join(inProgress, ", "))
	}
	if len(unclaimed) > 0 {
		reasons = append(reasons, "lane-assigned but never claimed: "+strings.Join(unclaimed, ", "))
	}
	return HookResult{
		Block: true,
		BlockReason: "⚠️ LEDGER WORK INCOMPLETE — " + strings.Join(reasons, "; ") +
			". File and link every proven finding; close every testing hypothesis as proven or rejected with evidence; claim and settle every lane-assigned hypothesis (or hand it back with update_hypothesis). Then continue through the remaining assigned lane rather than stopping after the first bug.",
	}
}

// assignedUnclaimedHypothesesForOwner returns queued hypotheses soft-assigned
// to an agent's lane that it never claimed. An empty owner (root coordinator)
// matches nothing: the root is responsible for the whole ledger, not a lane.
func assignedUnclaimedHypothesesForOwner(l *scanctx.LedgerStore, owner string) []string {
	owner = strings.TrimSpace(owner)
	if l == nil || owner == "" {
		return nil
	}
	var out []string
	for _, h := range l.All() {
		if h.Status == scanctx.HypothesisQueued && strings.TrimSpace(h.AssignedTo) == owner {
			out = append(out, h.ID)
		}
	}
	sort.Strings(out)
	return out
}

// testingHypothesesForOwner returns claimed hypotheses that an agent has not
// closed. A completed delegation must never strand work in the shared ledger
// and let the coordinator mistake collection of its prose result for lane
// completion.
func testingHypothesesForOwner(l *scanctx.LedgerStore, owner string) []string {
	if l == nil {
		return nil
	}
	var out []string
	for _, h := range l.All() {
		if h.Status == scanctx.HypothesisTesting && hypothesisBelongsToOwner(h, owner) {
			out = append(out, h.ID)
		}
	}
	sort.Strings(out)
	return out
}

// provenUnreportedHypotheses returns the IDs of hypotheses marked proven that
// carry no finding reference (no finding_ref evidence and no evidence FindingID).
func provenUnreportedHypotheses(l *scanctx.LedgerStore) []string {
	return provenUnreportedHypothesesForOwner(l, "")
}

func provenUnreportedHypothesesForOwner(l *scanctx.LedgerStore, owner string) []string {
	if l == nil {
		return nil
	}
	var out []string
	for _, h := range l.All() {
		if h.Status != scanctx.HypothesisProven || !hypothesisBelongsToOwner(h, owner) {
			continue
		}
		linked := false
		for _, ev := range h.Evidence {
			if ev.Kind == scanctx.EvidenceFindingRef || strings.TrimSpace(ev.FindingID) != "" {
				linked = true
				break
			}
		}
		if !linked {
			out = append(out, h.ID)
		}
	}
	sort.Strings(out)
	return out
}

// hypothesisBelongsToOwner filters shared-ledger finish work for a delegated
// specialist. AssignedTo is authoritative for claimed coordinator work; Origin
// covers hypotheses the specialist discovered itself before assignment.
// An empty owner means the root coordinator and intentionally matches all work.
func hypothesisBelongsToOwner(h scanctx.Hypothesis, owner string) bool {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return true
	}
	return strings.TrimSpace(h.AssignedTo) == owner || strings.TrimSpace(h.Origin) == owner
}
