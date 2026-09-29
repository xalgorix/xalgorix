package agent

import (
	"strings"
	"testing"

	"github.com/xalgord/xalgorix/v4/internal/scanctx"
)

// ── Applicability (Part 21 cases 9-15) ───────────────────────────────────────

func surfaceState(eps []string, methods map[string]string, cts map[string]string) *ScanState {
	s := NewScanState()
	s.ReconDone = true
	s.DiscoveredEndpoints = eps
	for k, v := range methods {
		recordEndpointMethod(s, k, v)
	}
	for k, v := range cts {
		recordEndpointContentType(s, k, v)
	}
	return s
}

// Case 9: /robots.txt must not be forced through XXE/SQLi/SSTI/CSRF.
func TestApplicability_StaticAssetsSkipInjectionClasses(t *testing.T) {
	state := surfaceState([]string{"example.com/robots.txt", "example.com/sitemap.xml"}, nil, nil)
	for _, ep := range state.DiscoveredEndpoints {
		got := ApplicableClassesForEndpoint(state, ep)
		for _, banned := range []string{"xxe", "sqli", "ssti", "csrf", "cmdi", "ssrf"} {
			for _, c := range got {
				if c == banned {
					t.Fatalf("%s must not owe %s testing, got %v", ep, banned, got)
				}
			}
		}
	}
	// The coverage-gap nudge must not demand injection work on robots.txt.
	gaps := CoverageGaps(state, state.DiscoveredEndpoints)
	for _, g := range gaps {
		if g.Endpoint == "example.com/robots.txt" && g.VulnClass != "" {
			t.Fatalf("robots.txt must produce no class gap, got %+v", g)
		}
	}
}

// Case 10: JSON state-changing API routes activate authorization/property/
// business obligations.
func TestApplicability_StateChangingJSONAPI(t *testing.T) {
	state := surfaceState(
		[]string{"example.com/api/users/1"},
		map[string]string{"example.com/api/users/1": "PATCH"},
		map[string]string{"example.com/api/users/1": "application/json"},
	)
	got := ApplicableClassesForEndpoint(state, "example.com/api/users/1")
	want := map[string]bool{"idor": false, "mass-assignment": false, "business-logic": false, "race-conditions": false, "csrf": false, "sqli": false}
	for _, c := range got {
		if _, ok := want[c]; ok {
			want[c] = true
		}
	}
	for c, present := range want {
		if !present {
			t.Fatalf("PATCH /api/users/1 (JSON) must activate %s, got %v", c, got)
		}
	}
}

// Case 11: XML input activates XXE.
func TestApplicability_XMLActivatesXXE(t *testing.T) {
	state := surfaceState(
		[]string{"example.com/api/import"},
		map[string]string{"example.com/api/import": "POST"},
		map[string]string{"example.com/api/import": "application/xml"},
	)
	got := ApplicableClassesForEndpoint(state, "example.com/api/import")
	if !hasStr(got, "xxe") {
		t.Fatalf("XML endpoint must activate xxe, got %v", got)
	}
}

// Case 12: file upload activates file-upload testing.
func TestApplicability_UploadEndpoint(t *testing.T) {
	state := surfaceState([]string{"example.com/upload"}, map[string]string{"example.com/upload": "POST"}, nil)
	got := ApplicableClassesForEndpoint(state, "example.com/upload")
	if !hasStr(got, "file-upload") {
		t.Fatalf("upload endpoint must activate file-upload, got %v", got)
	}
}

// Case 13: GraphQL activates GraphQL-specific testing.
func TestApplicability_GraphQLSurface(t *testing.T) {
	state := surfaceState([]string{"example.com/graphql"}, nil, nil)
	got := ApplicableClassesForEndpoint(state, "example.com/graphql")
	if !hasStr(got, "graphql") || !hasStr(got, "idor") || !hasStr(got, "business-logic") {
		t.Fatalf("GraphQL surface must activate graphql/idor/business-logic, got %v", got)
	}
}

// Case 14: WebSocket activates WebSocket-specific testing.
func TestApplicability_WebSocketSurface(t *testing.T) {
	state := surfaceState([]string{"example.com/ws/chat"}, nil, nil)
	got := ApplicableClassesForEndpoint(state, "example.com/ws/chat")
	if !hasStr(got, "websocket") {
		t.Fatalf("WebSocket surface must activate websocket testing, got %v", got)
	}
}

// Case 15: checkout/coupon/reservation workflows activate business-logic and
// race-condition candidates.
func TestApplicability_WorkflowEndpoints(t *testing.T) {
	for _, ep := range []string{"example.com/api/checkout", "example.com/api/coupon/redeem", "example.com/api/reservations"} {
		methods := map[string]string{ep: "POST"}
		if strings.Contains(ep, "reservations") {
			methods[ep] = "GET"
			// object-scoped GET still owes idor but business-logic needs
			// state change or workflow path: path keyword suffices.
		}
		state := surfaceState([]string{ep}, methods, nil)
		got := ApplicableClassesForEndpoint(state, ep)
		if !hasStr(got, "business-logic") || !hasStr(got, "race-conditions") {
			t.Fatalf("%s must activate business-logic + race-conditions, got %v", ep, got)
		}
	}
}

func hasStr(list []string, want string) bool {
	for _, x := range list {
		if x == want {
			return true
		}
	}
	return false
}

// Case 9b: an applicability-excluded pair cannot hold a coverage task open —
// and cannot be completed by an unrelated test either.
func TestTaskCoverage_RespectsApplicability(t *testing.T) {
	state := surfaceState([]string{"example.com/robots.txt", "example.com/search"}, nil, nil)
	// sqli tested on /search only; robots.txt owes no sqli → task completes.
	state.EndpointClassCoverage = map[string]map[string]bool{
		"example.com/search": {"sqli": true},
		"/search":            {"sqli": true},
	}
	task := newCoverageTask("sqli", state.DiscoveredEndpoints)
	if !taskCoverageComplete(state, task) {
		t.Fatal("sqli task must complete once every applicable endpoint is covered")
	}
}

// ── Plan + ledger seeding (Part 21 cases 16-18) ──────────────────────────────

// Case 16+17: business-logic must have claimable hypotheses once a workflow
// endpoint is on the surface — not "No queued hypotheses" because AutoPlan's
// legacy class floor never carried the class.
func TestLedgerSeeding_BusinessLogicHypotheses(t *testing.T) {
	ctx, state := newTestCtxState(t)
	state.DiscoveredEndpoints = []string{"example.com/api/checkout", "example.com/api/coupon/redeem"}
	recordEndpointMethod(state, "example.com/api/checkout", "POST")
	recordEndpointMethod(state, "example.com/api/coupon/redeem", "POST")
	state.Plan = AutoPlanFromState(state)

	if state.Plan.Get("test-business-logic") == nil {
		t.Fatal("AutoPlanFromState must schedule a business-logic task for a checkout workflow")
	}
	if state.Plan.Get("test-race-conditions") == nil {
		t.Fatal("AutoPlanFromState must schedule a race-condition task for a state-changing workflow")
	}

	seeded := seedLedgerFromPlan(state, ctx.Ledger)
	if seeded == 0 {
		t.Fatal("expected hypotheses to be seeded from the plan")
	}
	var bizLogic, race []scanctx.Hypothesis
	for _, h := range ctx.Ledger.All() {
		if h.Status != scanctx.HypothesisQueued {
			continue
		}
		if vulnClassMatches(h.VulnClass, "business-logic") {
			bizLogic = append(bizLogic, h)
		}
		if vulnClassMatches(h.VulnClass, "race-conditions") {
			race = append(race, h)
		}
	}
	if len(bizLogic) == 0 {
		t.Fatal("claim_next_hypothesis(vuln_class=\"business-logic\") would find nothing — seeding must create concrete business-logic hypotheses")
	}
	if len(race) == 0 {
		t.Fatal("race-condition hypotheses must be seeded for state-changing workflows")
	}
	for _, h := range race {
		if !strings.Contains(h.Endpoint, "checkout") && !strings.Contains(h.Endpoint, "coupon") {
			t.Fatalf("race hypothesis must target the workflow endpoint, got %s %s", h.VulnClass, h.Endpoint)
		}
	}
}

// Case 18 confirmed above via race hypotheses; case 9b above covers gap
// suppression for static assets.

// ── Specialist lanes (Part 21 cases 19-20) ───────────────────────────────────

// Case 19: the authorization lane is identity-gated ONLY for its multi-role
// classes; case 20: the business/workflow lane still runs with one identity.
func TestSpecialistSplit_BusinessLaneSurvivesSingleIdentity(t *testing.T) {
	a := &Agent{cfg: nil, state: NewScanState()}
	profiles := a.eligibleSpecialistProfiles()
	var hasAuthz, hasBusiness, hasInjection bool
	for _, p := range profiles {
		switch p.Role {
		case "authz-logic":
			hasAuthz = true
		case "business-logic":
			hasBusiness = true
		case "injection-serverside":
			hasInjection = true
		}
	}
	if hasAuthz {
		t.Fatal("authz-logic must not run without identities (len(authzIdentities) <= 1)")
	}
	if !hasBusiness {
		t.Fatal("business-logic lane must survive a single-identity target")
	}
	if !hasInjection {
		t.Fatal("injection lane must be present")
	}
	// authzIdentities with two identities would re-include authz-logic; the
	// business lane is never identity-gated.
	if VulnClassesForSpecialist("business-logic") == nil {
		t.Fatal("registry must own business-logic classes")
	}
	if got := VulnClassSpecialist("race-conditions"); got != "business-logic" {
		t.Fatalf("race-conditions must belong to the business-logic lane, got %q", got)
	}
}

// The authz profile must no longer carry business classes; the split keeps
// lanes bounded and non-overlapping.
func TestSpecialistProfiles_NonOverlapping(t *testing.T) {
	byClass := map[string]string{}
	for _, p := range defaultSpecialistProfiles {
		for _, c := range p.VulnClasses {
			canonical := CanonicalVulnClassID(c)
			if canonical == "" {
				continue
			}
			if prev, dup := byClass[canonical]; dup && prev != p.Role {
				t.Fatalf("class %q owned by both %q and %q", canonical, prev, p.Role)
			}
			byClass[canonical] = p.Role
		}
	}
	if byClass["business-logic"] != "business-logic" {
		t.Fatalf("business-logic ownership wrong: %v", byClass["business-logic"])
	}
	if byClass["idor"] != "authz-logic" {
		t.Fatalf("idor ownership wrong: %v", byClass["idor"])
	}
}

// VulnClassSkill: class → methodology resolution works for the registry.
func TestVulnClassSkill_Resolution(t *testing.T) {
	for _, class := range []string{"business-logic", "race-conditions", "xxe", "graphql"} {
		if _, ok := VulnClassSkill(class); !ok {
			t.Errorf("VulnClassSkill(%q) must resolve a methodology skill", class)
		}
	}
	if _, ok := VulnClassSkill("dirbusting"); ok {
		t.Error("dirbusting has no methodology skill query and must not resolve")
	}
}

// Part 21 case 25: empty AllowedPhases (full methodology) must not disable
// deep-mode requirements.
func TestScanDepth_EmptyPhasesMeansDeep(t *testing.T) {
	a := &Agent{state: NewScanState()}
	// Legacy inference: len(AllowedPhases)==0 -> NOT deep (the bug).
	a.allowedPhases = nil
	a.state.AllowedPhases = nil
	a.state.ScanDepth = "deep" // derived at Run() start
	if !a.isDeepMode() {
		t.Fatal("empty AllowedPhases means the full methodology: deep requirements must apply")
	}
	a.state.ScanDepth = "standard"
	if a.isDeepMode() {
		t.Fatal("explicit standard depth must not be deep")
	}
}
