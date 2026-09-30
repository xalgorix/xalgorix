package attacksurface

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func findEndpoint(res *Result, method, pathContains string) *Endpoint {
	for i := range res.Endpoints {
		e := &res.Endpoints[i]
		if strings.EqualFold(e.Method, method) && strings.Contains(e.Path, pathContains) {
			return e
		}
	}
	return nil
}

func TestParseOpenAPIJSON_V3(t *testing.T) {
	spec := `{
	  "openapi": "3.0.0",
	  "servers": [{"url": "https://api.example.com/v1"}],
	  "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
	  "paths": {
	    "/users/{id}": {
	      "get": {"parameters": [{"name":"id","in":"path"},{"name":"expand","in":"query"}]}
	    },
	    "/login": {"post": {}}
	  }
	}`
	// Deref-bearing assertions live inside the non-nil branch so the nil
	// check is structurally visible to the analyzer (staticcheck SA5011).
	if res := ParseBytes([]byte(spec), "openapi.json"); res != nil {
		res.finalize()
		if e := findEndpoint(res, "GET", "/users/{id}"); e == nil {
			t.Fatal("missing GET /users/{id}")
		} else {
			if !contains(e.Params, "id") || !contains(e.Params, "expand") {
				t.Fatalf("params = %v, want id+expand", e.Params)
			}
			if !strings.HasPrefix(e.Path, "https://api.example.com/v1") {
				t.Fatalf("base URL not applied: %s", e.Path)
			}
		}
		if findEndpoint(res, "POST", "/login") == nil {
			t.Fatal("missing POST /login")
		}
		if len(res.Notes) == 0 {
			t.Fatal("expected a security-scheme note")
		}
	} else {
		t.Fatal("expected a result")
	}
}

func TestParseSwaggerJSON_V2(t *testing.T) {
	spec := `{
	  "swagger": "2.0",
	  "host": "api.example.com",
	  "basePath": "/v2",
	  "paths": {"/pets": {"get": {}, "post": {}}}
	}`
	res := ParseBytes([]byte(spec), "swagger.json")
	if res == nil {
		t.Fatal("expected result")
	}
	res.finalize()
	if e := findEndpoint(res, "GET", "/pets"); e == nil || !strings.Contains(e.Path, "api.example.com/v2/pets") {
		t.Fatalf("swagger 2.0 host+basePath not applied: %+v", res.Endpoints)
	}
}

func TestParseOpenAPIYAML(t *testing.T) {
	spec := "openapi: 3.0.1\n" +
		"paths:\n" +
		"  /search:\n" +
		"    get:\n" +
		"      parameters:\n" +
		"        - name: q\n" +
		"          in: query\n"
	res := ParseBytes([]byte(spec), "openapi.yaml")
	if res == nil {
		t.Fatal("expected result from YAML")
	}
	res.finalize()
	if e := findEndpoint(res, "GET", "/search"); e == nil || !contains(e.Params, "q") {
		t.Fatalf("YAML parse failed: %+v", res.Endpoints)
	}
}

func TestParseHAR_ExtractsEndpointsAndAuth(t *testing.T) {
	har := `{
	  "log": {"entries": [
	    {"request": {
	      "method": "GET",
	      "url": "https://app.example.com/api/orders?status=open",
	      "headers": [
	        {"name":"Authorization","value":"Bearer eyJreal.token.here"},
	        {"name":"Cookie","value":"session=abc123"},
	        {"name":"Accept","value":"application/json"}
	      ],
	      "queryString": [{"name":"status"}]
	    }},
	    {"request": {
	      "method": "POST",
	      "url": "https://app.example.com/api/orders",
	      "headers": [],
	      "postData": {"text": "{\"item\":1}", "params": []}
	    }}
	  ]}
	}`
	if res := ParseBytes([]byte(har), "capture.har"); res != nil {
		res.finalize()
		if findEndpoint(res, "GET", "/api/orders") == nil {
			t.Fatal("missing GET /api/orders")
		}
		if res.AuthHeaders["Authorization"] != "Bearer eyJreal.token.here" {
			t.Fatalf("Authorization not harvested: %v", res.AuthHeaders)
		}
		if res.AuthHeaders["Cookie"] != "session=abc123" {
			t.Fatalf("Cookie not harvested: %v", res.AuthHeaders)
		}
		if _, ok := res.AuthHeaders["Accept"]; ok {
			t.Fatal("Accept must NOT be treated as auth")
		}
		// URL query must be stripped from the stored path.
		if e := findEndpoint(res, "GET", "/api/orders"); e != nil && strings.Contains(e.Path, "?") {
			t.Fatalf("query not stripped: %s", e.Path)
		}
	} else {
		t.Fatal("expected HAR result")
	}
}

func TestParsePostman(t *testing.T) {
	coll := `{
	  "info": {"name": "My API"},
	  "item": [
	    {"name": "folder", "item": [
	      {"name": "get user", "request": {
	        "method": "GET",
	        "url": {"raw": "https://api.example.com/users/1"},
	        "header": [{"key":"X-Api-Key","value":"k-secret-123"}]
	      }}
	    ]},
	    {"name": "login", "request": {
	      "method": "POST",
	      "url": "https://api.example.com/login",
	      "header": [],
	      "body": {"raw": "{\"u\":\"a\"}"}
	    }}
	  ]
	}`
	if res := ParseBytes([]byte(coll), "collection.json"); res != nil {
		res.finalize()
		if findEndpoint(res, "GET", "/users/1") == nil {
			t.Fatal("missing nested GET /users/1")
		}
		if findEndpoint(res, "POST", "/login") == nil {
			t.Fatal("missing POST /login (string url form)")
		}
		if res.AuthHeaders["X-Api-Key"] != "k-secret-123" {
			t.Fatalf("X-Api-Key not harvested: %v", res.AuthHeaders)
		}
	} else {
		t.Fatal("expected postman result")
	}
}

func TestFinalizeDedupAndBriefing(t *testing.T) {
	res := &Result{AuthHeaders: map[string]string{"Authorization": "Bearer x"}}
	res.Endpoints = []Endpoint{
		{Method: "GET", Path: "/a", Params: []string{"x"}, Source: "openapi"},
		{Method: "GET", Path: "/a", Params: []string{"y"}, Source: "har"}, // dup, merge params
		{Method: "POST", Path: "/b", Source: "openapi"},
	}
	res.finalize()
	if len(res.Endpoints) != 2 {
		t.Fatalf("expected 2 deduped endpoints, got %d", len(res.Endpoints))
	}
	if e := findEndpoint(res, "GET", "/a"); e == nil || !contains(e.Params, "x") || !contains(e.Params, "y") {
		t.Fatalf("params not merged on dedup: %+v", res.Endpoints)
	}
	b := res.Briefing()
	for _, want := range []string{"ATTACK SURFACE", "GET /a", "POST /b", "IDOR", "Authorization"} {
		if !strings.Contains(b, want) {
			t.Errorf("briefing missing %q:\n%s", want, b)
		}
	}
}

func TestParseBurp(t *testing.T) {
	// A minimal Burp export with one base64-encoded request carrying auth.
	rawReq := "GET /api/account?ref=1 HTTP/1.1\r\nHost: t.example\r\nAuthorization: Bearer burp.tok.123\r\nCookie: sid=xyz\r\nAccept: */*\r\n\r\n"
	b64 := base64.StdEncoding.EncodeToString([]byte(rawReq))
	xmlDoc := `<?xml version="1.0"?>
<items burpVersion="2023.10">
  <item>
    <url><![CDATA[https://t.example/api/account?ref=1]]></url>
    <method><![CDATA[GET]]></method>
    <path><![CDATA[/api/account?ref=1]]></path>
    <request base64="true"><![CDATA[` + b64 + `]]></request>
  </item>
</items>`
	if res := ParseBytes([]byte(xmlDoc), "burp.xml"); res != nil {
		res.finalize()
		if e := findEndpoint(res, "GET", "/api/account"); e == nil {
			t.Fatalf("missing GET /api/account: %+v", res.Endpoints)
		} else if !contains(e.Params, "ref") {
			t.Fatalf("query param not extracted: %v", e.Params)
		}
		if res.AuthHeaders["Authorization"] != "Bearer burp.tok.123" {
			t.Fatalf("Authorization not harvested from raw request: %v", res.AuthHeaders)
		}
		if res.AuthHeaders["Cookie"] != "sid=xyz" {
			t.Fatalf("Cookie not harvested: %v", res.AuthHeaders)
		}
		if _, ok := res.AuthHeaders["Accept"]; ok {
			t.Fatal("Accept must not be auth")
		}
	} else {
		t.Fatal("expected Burp result")
	}
}

func TestParseAPK(t *testing.T) {
	// Build a minimal APK (ZIP) with a fake classes.dex containing backend
	// URLs/paths plus framework noise that must be filtered out.
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	dex, _ := zw.Create("classes.dex")
	dex.Write([]byte("dex\n035\x00" +
		"https://api.realbackend.io/v1/users " +
		"\"https://api.realbackend.io/v1/orders?status=open\" " +
		"'/api/internal/secret' " +
		"http://schemas.android.com/apk/res/android " + // noise
		"https://fonts.googleapis.com/css " + // noise
		"end"))
	mf, _ := zw.Create("AndroidManifest.xml")
	mf.Write([]byte("https://auth.realbackend.io/oauth/token"))
	zw.Close()

	res := ParseBytes(buf.Bytes(), "app.apk")
	if res == nil {
		t.Fatal("expected APK result")
	}
	res.finalize()
	if findEndpoint(res, "", "api.realbackend.io/v1/users") == nil {
		t.Fatalf("missing real backend URL: %+v", res.Endpoints)
	}
	if findEndpoint(res, "", "/api/internal/secret") == nil {
		t.Fatalf("missing internal API path: %+v", res.Endpoints)
	}
	if findEndpoint(res, "", "auth.realbackend.io/oauth/token") == nil {
		t.Fatal("missing manifest URL")
	}
	// Framework/CDN noise must be filtered.
	for _, e := range res.Endpoints {
		if strings.Contains(e.Path, "schemas.android.com") || strings.Contains(e.Path, "fonts.googleapis.com") {
			t.Fatalf("noise host leaked into surface: %s", e.Path)
		}
	}
	// Query must be stripped.
	if e := findEndpoint(res, "", "/v1/orders"); e != nil && strings.Contains(e.Path, "?") {
		t.Fatalf("query not stripped: %s", e.Path)
	}
}

func TestParseBytes_UnknownReturnsNil(t *testing.T) {
	if ParseBytes([]byte("just some text"), "notes.txt") != nil {
		t.Fatal("unknown content should return nil")
	}
	if ParseBytes([]byte(""), "empty") != nil {
		t.Fatal("empty content should return nil")
	}
}

func TestLoadFromPath_Directory(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"openapi":"3.0.0","paths":{"/x":{"get":{}}}}`), 0o644)
	os.WriteFile(filepath.Join(dir, "b.har"), []byte(`{"log":{"entries":[{"request":{"method":"GET","url":"https://h/y","headers":[]}}]}}`), 0o644)
	res, err := LoadFromPath(dir)
	if err != nil {
		t.Fatalf("LoadFromPath dir: %v", err)
	}
	if findEndpoint(res, "GET", "/x") == nil || findEndpoint(res, "GET", "/y") == nil {
		t.Fatalf("merged endpoints missing: %+v", res.Endpoints)
	}
	if len(res.Formats) < 2 {
		t.Fatalf("expected both formats, got %v", res.Formats)
	}
}

func TestLoadFromPath_MissingErrors(t *testing.T) {
	if _, err := LoadFromPath("/no/such/file.json"); err == nil {
		t.Fatal("expected error for missing path")
	}
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestPostmanResolvesEnvironmentVariables covers the multi-file Postman upload:
// a collection whose URLs/headers/auth use {{placeholders}} plus a sibling
// environment file that supplies them. LoadFromPath must merge them so the
// seeded surface has real hosts and captured auth.
func TestPostmanResolvesEnvironmentVariables(t *testing.T) {
	dir := t.TempDir()
	env := `{
	  "name": "Prod",
	  "_postman_variable_scope": "environment",
	  "values": [
	    {"key": "base_url", "value": "https://api.example.com", "enabled": true},
	    {"key": "access_token", "value": "tok-abc-123", "enabled": true},
	    {"key": "api_key", "value": "key-xyz-789", "enabled": true},
	    {"key": "off", "value": "SHOULD_NOT_RESOLVE", "enabled": false}
	  ]
	}`
	coll := `{
	  "info": {"name": "My API"},
	  "auth": {"type": "bearer", "bearer": [{"key": "token", "value": "{{access_token}}"}]},
	  "variable": [{"key": "ver", "value": "v2"}],
	  "item": [
	    {"name": "get user", "request": {
	      "method": "GET",
	      "url": {"raw": "{{base_url}}/{{ver}}/users/1"},
	      "header": [{"key": "X-Api-Key", "value": "{{api_key}}"}]
	    }},
	    {"name": "secret", "request": {
	      "method": "GET",
	      "url": "{{base_url}}/{{off}}"
	    }}
	  ]
	}`
	if err := os.WriteFile(filepath.Join(dir, "collection.json"), []byte(coll), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "prod.postman_environment.json"), []byte(env), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := LoadFromPath(dir)
	if err != nil {
		t.Fatalf("LoadFromPath: %v", err)
	}
	// Environment {{base_url}} and collection-level {{ver}} both resolved.
	if findEndpoint(res, "GET", "https://api.example.com/v2/users/1") == nil {
		t.Fatalf("env/collection variables not resolved into URL: %+v", res.Endpoints)
	}
	// A collection-level bearer token sourced from the environment becomes an
	// Authorization header.
	if got := res.AuthHeaders["Authorization"]; got != "Bearer tok-abc-123" {
		t.Fatalf("bearer token not resolved from env: %q (%v)", got, res.AuthHeaders)
	}
	// An API-key header value resolved from the environment.
	if got := res.AuthHeaders["X-Api-Key"]; got != "key-xyz-789" {
		t.Fatalf("api key not resolved from env: %q (%v)", got, res.AuthHeaders)
	}
	// A disabled environment value must NOT resolve — the placeholder stays.
	if findEndpoint(res, "GET", "{{off}}") == nil {
		t.Fatalf("disabled env var should not resolve: %+v", res.Endpoints)
	}
}

// TestPostmanCollectionVariablesResolveWithoutEnv confirms a collection's own
// variable[] defaults resolve even for a single-file upload (no environment).
func TestPostmanCollectionVariablesResolveWithoutEnv(t *testing.T) {
	coll := `{
	  "info": {"name": "API"},
	  "variable": [{"key": "host", "value": "https://svc.local"}],
	  "item": [
	    {"name": "ping", "request": {"method": "GET", "url": "{{host}}/ping"}}
	  ]
	}`
	res := ParseBytes([]byte(coll), "collection.json")
	if res == nil {
		t.Fatal("expected postman result")
	}
	if findEndpoint(res, "GET", "https://svc.local/ping") == nil {
		t.Fatalf("collection variable not resolved: %+v", res.Endpoints)
	}
}

// TestPostmanEnvironmentDetectionAndAuthRendering verifies a standalone
// environment file is not mistaken for an endpoint source, that its variables
// are still harvested, and that basic auth renders a resolved header.
func TestPostmanEnvironmentDetectionAndAuthRendering(t *testing.T) {
	env := `{"name":"E","values":[{"key":"u","value":"admin"},{"key":"p","value":"s3cr3t"}]}`
	if ParseBytes([]byte(env), "env.json") != nil {
		t.Fatal("environment file must not parse as an endpoint source")
	}
	vars := parsePostmanEnv([]byte(env))
	if vars["u"] != "admin" || vars["p"] != "s3cr3t" {
		t.Fatalf("env vars not extracted: %v", vars)
	}
	name, val := postmanAuthHeader(&postmanAuth{
		Type:  "basic",
		Basic: []postmanAuthKV{{Key: "username", Value: "{{u}}"}, {Key: "password", Value: "{{p}}"}},
	}, vars)
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("admin:s3cr3t"))
	if name != "Authorization" || val != want {
		t.Fatalf("basic auth not rendered: %q %q (want %q)", name, val, want)
	}
}
