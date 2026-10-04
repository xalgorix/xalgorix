package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAcceptedDispositionSurvivesUnrelatedSurfaceRefresh(t *testing.T) {
	for _, mixed := range []bool{false, true} {
		name := "engine"
		if mixed {
			name = "mixed"
		}
		t.Run(name, func(t *testing.T) {
			state := NewScanState()
			RecordSurfaceObservation(state, SurfaceObservation{Endpoint: "/tokens", Method: "POST", ContentType: "application/json", Promote: true})
			state.Plan = AutoPlanFromState(state)
			if mixed {
				state.Plan.add(&Task{ID: "custom", Title: "Custom review", Origin: "llm", Status: TaskActive})
			}
			state.PlanBuilt = true
			state.PlanSurfaceRevision = surfaceRevision(state)
			a := &Agent{state: state}
			result, err := a.updatePlanTool(map[string]string{
				"task_id": "test-csrf", "status": "not_applicable",
				"notes": "The token endpoint uses an explicit authorization header; no ambient cookie credentials were observed.",
			})
			if err != nil || result.Error != "" {
				t.Fatalf("disposition rejected: %v %s", err, result.Error)
			}
			before := state.Plan.Get("test-csrf")
			if before.DispositionSurface == "" {
				t.Fatal("accepted disposition must bind its relevant surface")
			}
			RecordSurfaceObservation(state, SurfaceObservation{Endpoint: "/health", Method: "GET", Promote: true})
			refreshPlanForSurface(state)
			after := state.Plan.Get("test-csrf")
			if after.Status != TaskSkipped || after.Disposition != DispositionNotApplicable || after.DispositionSurface != before.DispositionSurface {
				t.Fatalf("unrelated GET discovery reopened accepted work: %+v", after)
			}
			if taskCoverageComplete(state, after) {
				t.Fatal("a disposition must not invent executed class coverage")
			}
		})
	}
}

func TestAcceptedDispositionReopensForNewApplicableInput(t *testing.T) {
	for _, change := range []string{"route", "method", "parameter", "content-type", "auth", "cookie", "technology"} {
		t.Run(change, func(t *testing.T) {
			state := NewScanState()
			RecordSurfaceObservation(state, SurfaceObservation{Endpoint: "/tokens", Method: "POST", ContentType: "application/json", Promote: true})
			state.Plan = AutoPlanFromState(state)
			state.PlanBuilt = true
			state.PlanSurfaceRevision = surfaceRevision(state)
			a := &Agent{state: state}
			result, _ := a.updatePlanTool(map[string]string{"task_id": "test-csrf", "status": "not_applicable",
				"notes": "No ambient cookie credentials were observed; authentication uses an explicit request header."})
			if result.Error != "" {
				t.Fatal(result.Error)
			}
			task := state.Plan.Get("test-csrf")
			switch change {
			case "route":
				RecordSurfaceObservation(state, SurfaceObservation{Endpoint: "/checkout", Method: "POST", Promote: true})
			case "method":
				RecordSurfaceObservation(state, SurfaceObservation{Endpoint: "/tokens", Method: "PATCH", Promote: true})
			case "parameter":
				RecordSurfaceObservation(state, SurfaceObservation{Endpoint: "/tokens", Parameters: []SurfaceParameter{{Name: "session", Location: "body"}}})
			case "content-type":
				RecordSurfaceObservation(state, SurfaceObservation{Endpoint: "/tokens", ContentType: "application/x-www-form-urlencoded"})
			case "auth":
				state.AuthContextAvailable = true
			case "cookie":
				state.CookieAuthObserved = true
			case "technology":
				state.DetectedTechs["nodejs"] = true
			}
			if skipDispositionStillValid(state, task) {
				t.Fatal("new applicable input must invalidate the old judgment")
			}
			refreshPlanForSurface(state)
			task = state.Plan.Get("test-csrf")
			if task.Status != TaskPending || task.Disposition != "" || task.DispositionSurface != "" {
				t.Fatalf("new surface did not reopen task: %+v", task)
			}
		})
	}
}

func TestDispositionSurfacePersistsWithoutCountingAsCoverage(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"/api/search"}
	task := &Task{ID: "test-sqli", VulnClass: "sqli", Origin: "auto", Status: TaskSkipped, Disposition: DispositionNotApplicable}
	task.DispositionSurface = dispositionSurfaceSignature(state, task)
	encoded, err := json.Marshal(task)
	if err != nil {
		t.Fatal(err)
	}
	var restored Task
	if err := json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if !skipDispositionStillValid(state, &restored) || restored.DispositionSurface != task.DispositionSurface {
		t.Fatal("persisted disposition lost its surface binding")
	}
	if endpointTestedForClass(state, "/api/search", "sqli") {
		t.Fatal("restoring a disposition must not mark the endpoint tested")
	}
	state.DiscoveredEndpoints = append(state.DiscoveredEndpoints, "/api/users")
	if skipDispositionStillValid(state, &restored) {
		t.Fatal("restored disposition must reopen for new applicable endpoints")
	}
}

func TestCompletionRejectionNamesOnlyMissingApplicableEndpoints(t *testing.T) {
	state := NewScanState()
	for _, path := range []string{"/first", "/second"} {
		RecordSurfaceObservation(state, SurfaceObservation{Endpoint: path, Method: "POST", ContentType: "application/json", Promote: true})
	}
	RecordSurfaceObservation(state, SurfaceObservation{Endpoint: "/robots.txt", Method: "GET", Promote: true})
	state.Plan = AutoPlanFromState(state)
	markEndpointClassCoverage(state, "/first", "sqli")
	result, _ := (&Agent{state: state}).updatePlanTool(map[string]string{"task_id": "test-sqli", "status": "completed"})
	if !strings.Contains(result.Error, "Untested applicable endpoints (1): /second") ||
		strings.Contains(result.Error, "/first") || strings.Contains(result.Error, "/robots.txt") {
		t.Fatalf("completion rejection must identify actionable gaps: %s", result.Error)
	}
	if state.Plan.Get("test-sqli").Status != TaskPending {
		t.Fatal("gap guidance must not weaken the coverage gate")
	}
}

func TestPlannerNotesExcludeFindingAndCommandTranscripts(t *testing.T) {
	text := endpointInventoryNotes(map[string]string{
		"Endpoint Inventory":     "/api/users\n/user/{user}\n/widget\n",
		"Discovery Manifest":     "/console\n",
		"Final Findings Summary": "Read /etc/passwd; tool installed at /usr/bin/nmap; see https://manual.example.test/docs",
		"target_overview":        "Tool command: /root/go/bin/subfinder",
	})
	paths := extractPaths(text)
	for _, path := range []string{"/api/users", "/user/{user}", "/widget", "/console"} {
		if !contains(paths, path) {
			t.Fatalf("inventory route %q lost: %v", path, paths)
		}
	}
	if len(paths) != 4 {
		t.Fatalf("non-inventory notes created obligations: %v", paths)
	}
}

func TestAPIRouteExtractionRejectsMarkupAndCommandNoise(t *testing.T) {
	state := NewScanState()
	maybeRecordAPIRoutes(state, `paths:
  /api/users:
  /user/{user}:
<html><body>application/json</body></html>
9000/tcp open http
100 requests/sec
/usr/bin/nmap
/root/go/bin/subfinder
source: /usr/src/app/server.py
file: /etc/passwd
schema: "#/components/schemas/User"
`)
	if len(state.DiscoveredEndpoints) != 2 || !endpointInInventory(state, "/api/users") || !endpointInInventory(state, "/user/{user}") {
		t.Fatalf("markup, protocol and local files must not become target routes: %v", state.DiscoveredEndpoints)
	}
}

func TestParameterizedCoverageKeepsClassAndHostBoundaries(t *testing.T) {
	state := NewScanState()
	markEndpointClassCoverage(state, "example.test/user/22", "sqli")
	for _, endpoint := range []string{"/user/{user}", "example.test/user/{user}", "https://example.test/user/{user}", "/user/:user"} {
		if !endpointTestedForClass(state, endpoint, "sqli") {
			t.Errorf("concrete request should cover %s", endpoint)
		}
	}
	for _, endpoint := range []string{"other.test/user/{user}", "/users/{user}", "/user/{user}/profile", "/user/23"} {
		if endpointTestedForClass(state, endpoint, "sqli") {
			t.Errorf("unrelated identity must not gain coverage: %s", endpoint)
		}
	}
	if endpointTestedForClass(state, "/user/{user}", "xss") {
		t.Fatal("a different class must not gain coverage")
	}
	if got := endpointCoverageAliases("/user/{user}"); len(got) != 1 || got[0] != "/user/{user}" {
		t.Fatalf("route template must survive alias normalization: %v", got)
	}
}
