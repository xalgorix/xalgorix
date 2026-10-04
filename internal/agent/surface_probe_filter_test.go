package agent

import "testing"

func TestProbeRequestsDoNotCreateRouteObligations(t *testing.T) {
	state := NewScanState()
	state.ScanTargets = []string{"https://app.example.test:9000"}
	for _, candidate := range []string{
		"app.example.test:9000/FUZZ",
		"app.example.test:9000/../../../etc/passwd",
		"app.example.test:9000/uptime/test;id",
		"app.example.test:9000/user/1' UNION SELECT 1 --",
		"/usr/local/lib/python3.8/site-packages/pkg/__init__.py",
		"oast.pro/request",
	} {
		RecordSurfaceObservation(state, SurfaceObservation{Endpoint: candidate, Method: "GET", Source: "request", Promote: true})
		if len(state.DiscoveredEndpoints) != 0 {
			t.Fatalf("probe artifact %q became a route: %v", candidate, state.DiscoveredEndpoints)
		}
	}
	RecordSurfaceObservation(state, SurfaceObservation{Endpoint: "app.example.test:9000/user/{user}", Method: "GET", Source: "api", Promote: true})
	RecordSurfaceObservation(state, SurfaceObservation{Endpoint: "app.example.test:9000/user/22", Method: "GET", Source: "request", Promote: true})
	if len(state.DiscoveredEndpoints) != 1 || state.DiscoveredEndpoints[0] != "app.example.test:9000/user/{user}" {
		t.Fatalf("concrete path parameter became a second route: %v", state.DiscoveredEndpoints)
	}
	state.DiscoveredEndpoints = nil
	RecordSurfaceObservation(state, SurfaceObservation{Endpoint: "app.example.test:9000/user/22", Method: "GET", Source: "request", Promote: true})
	RecordSurfaceObservation(state, SurfaceObservation{Endpoint: "app.example.test:9000/user/{user}", Method: "GET", Source: "api", Promote: true})
	if len(state.DiscoveredEndpoints) != 1 || state.DiscoveredEndpoints[0] != "app.example.test:9000/user/{user}" {
		t.Fatalf("later route template did not replace a concrete parameter value: %v", state.DiscoveredEndpoints)
	}
}

func TestRouteMergePrunesProbeArtifactsAndConcreteTemplateValues(t *testing.T) {
	state := NewScanState()
	state.DiscoveredEndpoints = []string{"app.example.test:9000/FUZZ", "app.example.test:9000/user/22", "oast.pro/request"}
	got := mergeDiscoveredEndpoints(state, []string{"/user/{user}", "/tokens", "/usr/local/lib/pkg/module.py"})
	if len(got) != 2 || got[0] != "/tokens" || got[1] != "/user/{user}" {
		t.Fatalf("merge kept a probe or duplicated a template route: %v", got)
	}
}

func TestAPIRouteExtractionIgnoresLocalTraceback(t *testing.T) {
	state := NewScanState()
	maybeRecordAPIRoutes(state, "GET /tokens\nTraceback: /usr/local/lib/python3.8/site-packages/pkg/__init__.py")
	if len(state.DiscoveredEndpoints) != 1 || state.DiscoveredEndpoints[0] != "/tokens" {
		t.Fatalf("API output promoted a local traceback path: %v", state.DiscoveredEndpoints)
	}
}

func TestTemplateKeepsConcreteRequestEvidence(t *testing.T) {
	state := NewScanState()
	RecordSurfaceObservation(state, SurfaceObservation{
		Endpoint: "app.example.test:9000/user/22", Method: "POST",
		ContentType: "application/json", Parameters: []SurfaceParameter{{Name: "role", Location: "body"}},
		Source: "request", Promote: true,
	})
	RecordSurfaceObservation(state, SurfaceObservation{Endpoint: "app.example.test:9000/user/{user}", Source: "api", Promote: true})
	if len(state.DiscoveredEndpoints) != 1 {
		t.Fatalf("concrete value remained an inventory obligation: %v", state.DiscoveredEndpoints)
	}
	got := buildSurfaceEndpoint(state, state.DiscoveredEndpoints[0])
	if !got.hasMethod("POST") || len(got.Parameters) != 1 || got.Parameters[0].Name != "role" ||
		len(got.ContentTypes) != 1 || got.ContentTypes[0] != "application/json" {
		t.Fatalf("template lost concrete request evidence: %+v", got)
	}
}

func TestDistinctRouteTemplatesDoNotRemoveEachOther(t *testing.T) {
	state := NewScanState()
	for _, route := range []string{"/user/{id}", "/user/{name}", "/user/22"} {
		RecordSurfaceObservation(state, SurfaceObservation{Endpoint: route, Source: "api", Promote: true})
	}
	got := state.DiscoveredEndpoints
	if len(got) != 2 || got[0] != "/user/{id}" || got[1] != "/user/{name}" {
		t.Fatalf("template pruning removed a template or retained a concrete value: %v", got)
	}
}

func TestProbeFilterKeepsLegitimateFuzzingRoute(t *testing.T) {
	if isProbeArtifactEndpoint("/fuzzing") {
		t.Fatal("normal route containing fuzz was classified as a wordlist placeholder")
	}
}

func TestScopedRequestsEnrichRelativeRouteWithoutCrossHostLeak(t *testing.T) {
	state := NewScanState()
	RecordSurfaceObservation(state, SurfaceObservation{Endpoint: "one.example.test/help", Method: "GET", Source: "request"})
	RecordSurfaceObservation(state, SurfaceObservation{Endpoint: "two.example.test/help", Method: "POST", Source: "request"})
	relative := buildSurfaceEndpoint(state, "/help")
	if !relative.hasMethod("GET") || !relative.hasMethod("POST") {
		t.Fatalf("relative inventory route lost observed methods: %+v", relative)
	}
	scoped := buildSurfaceEndpoint(state, "one.example.test/help")
	if !scoped.hasMethod("GET") || scoped.hasMethod("POST") {
		t.Fatalf("scoped route inherited another host's method: %+v", scoped)
	}
}

func TestAPISchemaDocumentsAreDiscoveryOnly(t *testing.T) {
	state := NewScanState()
	for _, endpoint := range []string{"/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger.yaml"} {
		classes := ApplicableClassesForEndpoint(state, endpoint)
		if len(classes) != 1 || classes[0] != "information-exposure" {
			t.Fatalf("schema document %q acquired input-test obligations: %v", endpoint, classes)
		}
	}
}
