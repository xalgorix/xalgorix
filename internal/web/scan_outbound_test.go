package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/config"
	"github.com/xalgord/xalgorix/v4/internal/llm"
	"github.com/xalgord/xalgorix/v4/internal/providers"
	"github.com/xalgord/xalgorix/v4/internal/scopeguard"
)

// stubWebhookDNS pins scopeguard's resolver so these tests never depend on
// real DNS: discord.com and example.com resolve to public addresses,
// rebind.example resolves to loopback and meta.example to the link-local
// metadata address.
func stubWebhookDNS(t *testing.T) {
	t.Helper()
	prev := scopeguard.SetLookupHost(func(host string) ([]string, error) {
		switch host {
		case "discord.com":
			return []string{"162.159.135.232"}, nil
		case "example.com", "collector.example", "llm.internal.example", "gateway.example":
			return []string{"93.184.215.14"}, nil
		case "rebind.example":
			return []string{"127.0.0.1"}, nil
		case "meta.example":
			return []string{"169.254.169.254"}, nil
		}
		return nil, errors.New("no such host")
	})
	t.Cleanup(func() { scopeguard.SetLookupHost(prev) })
}

func newWebhookTestServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	stubWebhookDNS(t)
	s := newTestServer(t, cfg)
	s.port = 9137
	return s
}

func TestValidateScanWebhookRejectsSelfAndMetadataDestinations(t *testing.T) {
	s := newWebhookTestServer(t, nil)

	rejected := []string{
		"http://127.0.0.1:8888/SSRF-PROOF-F1", // the reported PoC
		"http://localhost:8888/x",
		"http://[::1]:8888/x",
		"http://rebind.example:8888/x", // hostname resolving to loopback
		"http://meta.example/latest/meta-data/",
		"http://127.0.0.1:9137/api/stop",
		"http://0.0.0.0:8888/x",
		"http://169.254.169.254/latest/meta-data/",
		"http://[fd00:ec2::254]/latest/meta-data/",
		"http://100.100.100.200/latest/meta-data/",
		"http://168.63.129.16/machine",
		"http://224.0.0.1/x",
		"http://[fe80::1%25eth0]/x",                 // IPv6 zone
		"http://169.254.169.254./latest/meta-data/", // trailing dot
		"http://[fd20:ce::254]/computeMetadata/v1/", // IPv6 metadata
		"http://[::127.0.0.1]/x",                    // IPv4-compatible IPv6
		"http://0/x",                                // numeric forms some resolvers read as IPv4
		"http://2130706433/x",
		"http://0x7f.1/x",
		"http://127.1/x",
		"ftp://discord.com/api/webhooks/1/x",
		"discord.com/api/webhooks/1/x",
		"not a url",
	}
	for _, raw := range rejected {
		if err := s.validateScanWebhook(raw); err == nil {
			t.Errorf("validateScanWebhook(%q) = nil, want rejection", raw)
		}
	}

	allowed := []string{
		"",
		"   ",
		"https://discord.com/api/webhooks/123/abc",
		"http://10.0.0.5:8080/hook", // LAN relay: private ranges stay allowed, as for targets
		"https://192.168.1.20/hook",
	}
	for _, raw := range allowed {
		if err := s.validateScanWebhook(raw); err != nil {
			t.Errorf("validateScanWebhook(%q) = %v, want nil", raw, err)
		}
	}
}

func TestValidateScanWebhookFollowsAllowLocalTargets(t *testing.T) {
	s := newWebhookTestServer(t, &config.Config{AllowLocalTargets: true})

	if err := s.validateScanWebhook("http://127.0.0.1:8888/relay"); err != nil {
		t.Fatalf("loopback relay with AllowLocalTargets: %v", err)
	}
	for _, raw := range []string{
		"http://127.0.0.1:9137/api/stop", // the dashboard listener is never allowed
		"http://169.254.169.254/latest/meta-data/",
	} {
		if err := s.validateScanWebhook(raw); err == nil {
			t.Errorf("validateScanWebhook(%q) = nil with AllowLocalTargets, want rejection", raw)
		}
	}
}

func TestValidateScanWebhookTrustsOperatorGlobalWebhook(t *testing.T) {
	s := newWebhookTestServer(t, nil)
	s.discordWebhook = "http://127.0.0.1:8888/operator-relay"
	if err := s.validateScanWebhook(" http://127.0.0.1:8888/operator-relay "); err != nil {
		t.Fatalf("operator-configured global webhook rejected: %v", err)
	}
}

func countingServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestNotificationClientRefusesLoopbackAtDialTime(t *testing.T) {
	s := newWebhookTestServer(t, nil)
	srv, hits := countingServer(t)

	// "localhost" only becomes 127.0.0.1 at connect time, so this exercises
	// the dial guard rather than the textual request-time check.
	target := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	resp, err := s.notificationClient(target).Post(target, "application/json", strings.NewReader(`{}`))
	if err == nil {
		resp.Body.Close()
		t.Fatal("per-scan webhook to loopback was delivered, want dial-time refusal")
	}
	if !strings.Contains(err.Error(), errWebhookDestination.Error()) {
		t.Fatalf("unexpected error: %v", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("listener received %d request(s), want 0", n)
	}
}

func TestNotificationClientDeliversToOperatorGlobalWebhook(t *testing.T) {
	s := newWebhookTestServer(t, nil)
	srv, hits := countingServer(t)
	s.discordWebhook = srv.URL

	resp, err := s.notificationClient(srv.URL).Post(srv.URL, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("operator global webhook delivery failed: %v", err)
	}
	resp.Body.Close()
	if n := hits.Load(); n != 1 {
		t.Fatalf("listener received %d request(s), want 1", n)
	}
}

func TestNotificationClientDoesNotFollowRedirects(t *testing.T) {
	// AllowLocalTargets lets the test reach its own httptest listeners; the
	// redirect must still not be followed.
	s := newWebhookTestServer(t, &config.Config{AllowLocalTargets: true})
	final, finalHits := countingServer(t)
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/internal", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redirector.Close)

	resp, err := s.notificationClient(redirector.URL).Post(redirector.URL, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want the unfollowed 307", resp.StatusCode)
	}
	if n := finalHits.Load(); n != 0 {
		t.Fatalf("redirect target received %d request(s), want 0", n)
	}
}

func TestSendSimpleEmbedToSkipsLoopbackPerScanWebhook(t *testing.T) {
	s := newWebhookTestServer(t, nil)
	perScan, perScanHits := countingServer(t)
	operator, operatorHits := countingServer(t)
	s.discordWebhook = operator.URL

	// A per-scan webhook persisted before validation existed (queue state,
	// saved scans) must still be refused by the sender itself. The operator
	// send started right after it is the positive control: once it has
	// landed, the earlier per-scan send has had the same chance to.
	s.sendSimpleEmbedTo(perScan.URL, 0x00ff88, "Scan Started", "test")
	s.sendSimpleEmbedTo(operator.URL, 0x00ff88, "Scan Started", "test")
	deadline := time.Now().Add(5 * time.Second)
	for operatorHits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if operatorHits.Load() != 1 {
		t.Fatalf("positive control: operator webhook received %d request(s), want 1", operatorHits.Load())
	}
	time.Sleep(200 * time.Millisecond)
	if n := perScanHits.Load(); n != 0 {
		t.Fatalf("loopback per-scan webhook received %d request(s), want 0", n)
	}
}

func TestHandleScanRejectsLoopbackDiscordWebhook(t *testing.T) {
	s := newWebhookTestServer(t, nil)
	bestEffortDataDir(t, s)

	body := `{"targets":["https://example.com"],"discord_webhook":"http://127.0.0.1:8888/SSRF-PROOF-F1"}`
	rr := httptest.NewRecorder()
	s.handleScan(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "discord_webhook") {
		t.Fatalf("error does not name the field: %s", rr.Body.String())
	}
}

func TestHandleSchedulesRejectsLoopbackDiscordWebhook(t *testing.T) {
	s := newWebhookTestServer(t, nil)

	body := `{"targets":["https://example.com"],"discord_webhook":"http://localhost:8888/x"}`
	rr := httptest.NewRecorder()
	s.handleSchedules(rr, httptest.NewRequest(http.MethodPost, "/api/schedules", strings.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	s.schedulesMu.Lock()
	n := len(s.schedules)
	s.schedulesMu.Unlock()
	if n != 0 {
		t.Fatalf("schedule stored despite rejected webhook (%d schedules)", n)
	}
}

func TestCheckScanAPIBaseOverride(t *testing.T) {
	stubWebhookDNS(t)
	stored := &config.Config{
		LLM:     "custom/test-model",
		APIBase: "https://llm.internal.example/v1",
		APIKey:  "stored-key",
	}
	gateway := &config.Config{
		LLM:     "custom/test-model",
		APIBase: "https://gateway.example/v1/tenant-a/llm",
		APIKey:  "stored-key",
	}
	cases := []struct {
		name    string
		cfg     *config.Config
		req     ScanRequest
		wantErr bool
	}{
		{"no override", stored, ScanRequest{}, false},
		{"foreign host without key", stored, ScanRequest{APIBase: "https://collector.example/v1"}, true},
		{"loopback host without key", stored, ScanRequest{APIBase: "http://127.0.0.1:11434/v1"}, true},
		{"scheme-less override without key", stored, ScanRequest{APIBase: "collector.example/v1"}, true},
		{"foreign host with caller key", stored, ScanRequest{APIBase: "https://collector.example/v1", APIKey: "caller-key"}, false},
		{"same endpoint, deeper path", stored, ScanRequest{APIBase: "https://llm.internal.example/v1/chat/completions"}, false},
		{"same endpoint, normalized", stored, ScanRequest{APIBase: "HTTPS://LLM.internal.example:443/v1/"}, false},
		{"same origin, sibling path", stored, ScanRequest{APIBase: "https://llm.internal.example/v2/chat"}, true},
		{"same origin, dot segments escape", stored, ScanRequest{APIBase: "https://llm.internal.example/v1/../other"}, true},
		{"gateway, same tenant", gateway, ScanRequest{APIBase: "https://gateway.example/v1/tenant-a/llm/chat/completions"}, false},
		{"gateway, other tenant", gateway, ScanRequest{APIBase: "https://gateway.example/v1/tenant-b/llm"}, true},
		{"gateway, query added", gateway, ScanRequest{APIBase: "https://gateway.example/v1/tenant-a/llm?account=b"}, true},
		{"gateway, path-parameter dot segments", gateway, ScanRequest{APIBase: "https://gateway.example/v1/tenant-a/llm/..;/..;/tenant-b/llm"}, true},
		{"gateway, encoded backslash dot segments", gateway, ScanRequest{APIBase: "https://gateway.example/v1/tenant-a/llm/..%5c..%5c..%5ctenant-b/llm"}, true},
		{"gateway, backslash dot segments", gateway, ScanRequest{APIBase: `https://gateway.example/v1/tenant-a/llm/..\..\..\tenant-b/llm`}, true},
		{"gateway, double-encoded dot segments", gateway, ScanRequest{APIBase: "https://gateway.example/v1/tenant-a/llm/%252e%252e/%252e%252e/tenant-b/llm"}, true},
		{"key pool only", &config.Config{LLM: "custom/test-model", APIKeys: []string{"pooled"}}, ScanRequest{APIBase: "https://collector.example/v1"}, true},
		{"no stored credential", &config.Config{LLM: "custom/test-model", APIBase: "http://127.0.0.1:11434/v1"}, ScanRequest{APIBase: "http://10.0.0.7:11434/v1"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{cfg: c.cfg}
			err := s.checkScanAPIBaseOverride(t.Context(), c.req)
			if c.wantErr && !errors.Is(err, errAPIBaseNeedsKey) {
				t.Fatalf("err = %v, want errAPIBaseNeedsKey", err)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("err = %v, want nil", err)
			}
		})
	}
}

// TestCheckScanAPIBaseOverrideComparesSelectedProfileEndpoint covers a
// provider_profile whose credential lives on a different host than the
// global api_base: an override onto the global base must not carry the
// profile's credential there.
func TestCheckScanAPIBaseOverrideComparesSelectedProfileEndpoint(t *testing.T) {
	stubWebhookDNS(t)
	cat := providers.NewService()
	prof, err := auth.NewStore(filepath.Join(t.TempDir(), "auth-profiles.json"), cat)
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	if err := prof.Put(t.Context(), auth.Profile{Provider: "google", ProfileID: "default", Type: auth.APIKey, APIKey: "profile-key"}); err != nil {
		t.Fatalf("prof.Put: %v", err)
	}
	s := &Server{catalog: cat, profiles: prof, cfg: &config.Config{
		LLM:     "custom/test-model",
		APIBase: "https://gateway.example/v1",
		APIKey:  "stored-key",
	}}
	err = s.checkScanAPIBaseOverride(t.Context(), ScanRequest{ProviderProfile: "google:default", APIBase: "https://gateway.example/v1"})
	if !errors.Is(err, errAPIBaseNeedsKey) {
		t.Fatalf("err = %v, want errAPIBaseNeedsKey", err)
	}
}

// profileOnlyConfig is the usual Settings setup: the provider credential lives
// only in an auth profile, with no configured key and no key pool.
func profileOnlyConfig() *config.Config {
	return &config.Config{LLM: "custom/test-model", LLMProfile: "google:default"}
}

// attachProfileStores gives s a catalog and an empty auth-profile store and
// returns a func that saves the "google:default" API-key profile.
func attachProfileStores(t *testing.T, s *Server) (saveProfile func()) {
	t.Helper()
	cat := providers.NewService()
	prof, err := auth.NewStore(filepath.Join(t.TempDir(), "auth-profiles.json"), cat)
	if err != nil {
		t.Fatalf("auth.NewStore: %v", err)
	}
	s.catalog, s.profiles = cat, prof
	return func() {
		t.Helper()
		if err := prof.Put(t.Context(), auth.Profile{Provider: "google", ProfileID: "default", Type: auth.APIKey, APIKey: "profile-key"}); err != nil {
			t.Fatalf("prof.Put: %v", err)
		}
	}
}

// TestAPIBaseCheckIgnoresRequestCancellation: a caller that cancels its
// request (for example by half-closing the connection right after the body)
// must not make the profile lookup fail and the override pass as "no stored
// credential".
func TestAPIBaseCheckIgnoresRequestCancellation(t *testing.T) {
	stubWebhookDNS(t)
	s := &Server{cfg: profileOnlyConfig()}
	attachProfileStores(t, s)()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := s.checkScanRequestDestinations(ctx, ScanRequest{APIBase: "https://collector.example/v1"})
	if !errors.Is(err, errAPIBaseNeedsKey) {
		t.Fatalf("err = %v, want errAPIBaseNeedsKey", err)
	}
}

func TestHandleScanRejectsAPIBaseOverrideOnCanceledRequest(t *testing.T) {
	s := newWebhookTestServer(t, profileOnlyConfig())
	attachProfileStores(t, s)()
	bestEffortDataDir(t, s)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	body := `{"targets":["https://example.com"],"api_base":"https://collector.example/v1"}`
	rr := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(body)).WithContext(ctx)
	s.handleScan(rr, r)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "profile-key") {
		t.Fatal("error body leaks the stored key")
	}
}

// TestScanLLMClientKeepsStoredCredentialOnItsEndpoint checks the rule where
// it matters: the client a scan runs with. Whatever the admission check
// decided, it must never send a stored credential to a foreign api_base, and
// it must not fall back to the default client, which would send the per-scan
// config's key there.
func TestScanLLMClientKeepsStoredCredentialOnItsEndpoint(t *testing.T) {
	stubWebhookDNS(t)
	foreign := ScanRequest{APIBase: "https://collector.example/v1"}
	cases := []struct {
		name    string
		cfg     *config.Config
		profile bool
	}{
		{"configured key", &config.Config{LLM: "custom/test-model", APIBase: "https://llm.internal.example/v1", APIKey: "stored-key"}, false},
		{"key pool only", &config.Config{LLM: "custom/test-model", APIKeys: []string{"pooled-secret"}}, false},
		{"auth profile", profileOnlyConfig(), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := &Server{cfg: c.cfg}
			if c.profile {
				attachProfileStores(t, s)()
			}
			scanCfg := *s.cfg
			applyScanLLMOverrides(&scanCfg, foreign)
			client := s.scanLLMClientForRequest(foreign, &scanCfg)
			if client == nil {
				t.Fatal("fell back to the default client, which sends the stored key to the request's api_base")
			}
			for i := 0; i < 4; i++ {
				ep, err := client.ResolveEndpoint(t.Context())
				var cfgErr *llm.ConfigError
				if !errors.As(err, &cfgErr) {
					t.Fatalf("request %d: err = %v, want *llm.ConfigError (url %s, key set %v)", i, err, ep.URL, ep.APIKey != "")
				}
				if ep.APIKey != "" || ep.AccessToken != "" {
					t.Fatalf("request %d: refused endpoint carries a credential", i)
				}
			}
		})
	}

	t.Run("override on the stored endpoint keeps working", func(t *testing.T) {
		s := &Server{cfg: &config.Config{LLM: "custom/test-model", APIBase: "https://llm.internal.example/v1", APIKey: "stored-key"}}
		req := ScanRequest{APIBase: "https://llm.internal.example/v1/chat/completions"}
		scanCfg := *s.cfg
		applyScanLLMOverrides(&scanCfg, req)
		client := s.scanLLMClientForRequest(req, &scanCfg)
		if client == nil {
			t.Fatal("no client for an in-scope override")
		}
		ep, err := client.ResolveEndpoint(t.Context())
		if err != nil || ep.URL != "https://llm.internal.example/v1/chat/completions" {
			t.Fatalf("in-scope override refused: url %q err %v", ep.URL, err)
		}
	})

	t.Run("profile credential on its own endpoint keeps working", func(t *testing.T) {
		s := &Server{cfg: profileOnlyConfig()}
		attachProfileStores(t, s)()
		storedURL := s.storedEndpointURL(t.Context(), ScanRequest{}, s.cfg)
		if storedURL == "" {
			t.Fatal("profile resolved to no endpoint")
		}
		req := ScanRequest{APIBase: storedURL}
		scanCfg := *s.cfg
		applyScanLLMOverrides(&scanCfg, req)
		client := s.scanLLMClientForRequest(req, &scanCfg)
		if client == nil {
			t.Fatal("no client for an in-scope override")
		}
		ep, err := client.ResolveEndpoint(t.Context())
		if err != nil || ep.APIKey != "profile-key" {
			t.Fatalf("in-scope override lost the profile credential: url %q key set %v err %v", ep.URL, ep.APIKey != "", err)
		}
	})
}

// TestAPIBaseRuleAppliesWhenProfileSavedAfterAdmission: the scan was admitted
// while no credential was stored, so its override was allowed, and the
// operator saved a profile before the scan built its client (it waited in the
// queue, or it is a later target of a multi-target scan). The new credential
// must not go to the request's api_base.
func TestAPIBaseRuleAppliesWhenProfileSavedAfterAdmission(t *testing.T) {
	stubWebhookDNS(t)
	s := &Server{cfg: profileOnlyConfig()}
	saveProfile := attachProfileStores(t, s)
	req := ScanRequest{APIBase: "https://collector.example/v1"}
	if err := s.checkScanRequestDestinations(t.Context(), req); err != nil {
		t.Fatalf("admission with no stored credential: %v", err)
	}
	scanCfg := *s.cfg
	applyScanLLMOverrides(&scanCfg, req)

	saveProfile()
	client := s.scanLLMClientForRequest(req, &scanCfg)
	if client == nil {
		t.Fatal("fell back to the default client")
	}
	ep, err := client.ResolveEndpoint(t.Context())
	if err == nil || ep.APIKey != "" {
		t.Fatalf("profile saved after admission reached the request's api_base: url %q key set %v err %v", ep.URL, ep.APIKey != "", err)
	}
}

// TestCallerKeyReplacesStoredKeyPool: with a caller-supplied api_key and a
// foreign api_base, no request may ever carry a stored or pooled key.
func TestCallerKeyReplacesStoredKeyPool(t *testing.T) {
	stubWebhookDNS(t)
	s := &Server{cfg: &config.Config{
		LLM:     "custom/test-model",
		APIBase: "https://llm.internal.example/v1",
		APIKey:  "stored-key",
		APIKeys: []string{"stored-key", "pooled-secret-1", "pooled-secret-2"},
	}}
	req := ScanRequest{APIBase: "https://collector.example/v1", APIKey: "caller-key"}
	if err := s.checkScanRequestDestinations(t.Context(), req); err != nil {
		t.Fatalf("caller-keyed override refused: %v", err)
	}
	scanCfg := *s.cfg
	applyScanLLMOverrides(&scanCfg, req)
	if len(s.cfg.APIKeys) != 3 {
		t.Fatalf("operator config mutated: %v", s.cfg.APIKeys)
	}

	clients := []*llm.Client{llm.NewClient(&scanCfg)}
	if c, err := s.buildScanLLMClient(t.Context(), req, &scanCfg); err == nil && c != nil {
		clients = append(clients, c)
	}
	for ci, c := range clients {
		for i := 0; i < 8; i++ {
			ep, err := c.ResolveEndpoint(t.Context())
			if err != nil {
				t.Fatalf("client %d resolve %d: %v", ci, i, err)
			}
			if ep.APIKey != "caller-key" || ep.AccessToken != "" {
				t.Fatalf("client %d request %d carries a stored credential (key=%q token set=%v) to %s", ci, i, ep.APIKey, ep.AccessToken != "", ep.URL)
			}
		}
	}
}

func TestHandleScanRejectsAPIBaseOverrideWithoutKey(t *testing.T) {
	s := newWebhookTestServer(t, &config.Config{
		LLM:     "custom/test-model",
		APIBase: "https://llm.internal.example/v1",
		APIKey:  "stored-key",
	})
	bestEffortDataDir(t, s)

	body := `{"targets":["https://example.com"],"api_base":"https://collector.example/v1"}`
	rr := httptest.NewRecorder()
	s.handleScan(rr, httptest.NewRequest(http.MethodPost, "/api/scan", strings.NewReader(body)))
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "api_base") {
		t.Fatalf("error does not name the field: %s", rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "stored-key") {
		t.Fatal("error body leaks the stored key")
	}
}

// TestWebSocketScanAppliesDestinationChecks: the WebSocket scan message is a
// second way to start a scan and must refuse the same requests as /api/scan.
func TestWebSocketScanAppliesDestinationChecks(t *testing.T) {
	s := newWebhookTestServer(t, &config.Config{
		LLM:     "custom/test-model",
		APIBase: "https://llm.internal.example/v1",
		APIKey:  "stored-key",
	})
	bestEffortDataDir(t, s)
	srv := httptest.NewServer(http.HandlerFunc(s.handleWebSocket))
	t.Cleanup(srv.Close)

	for _, msg := range []string{
		`{"targets":["https://example.com"],"api_base":"https://collector.example/v1"}`,
		`{"targets":["https://example.com"],"discord_webhook":"http://127.0.0.1:8888/x"}`,
	} {
		conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
			t.Fatalf("write: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		refused := false
		for !refused {
			_, data, err := conn.ReadMessage()
			if err != nil {
				t.Fatalf("no refusal for %s: %v", msg, err)
			}
			var evt WSEvent
			if json.Unmarshal(data, &evt) == nil && evt.Type == "error" && strings.Contains(evt.Content, "Scan request refused") {
				refused = true
				if strings.Contains(evt.Content, "stored-key") {
					t.Fatal("refusal leaks the stored key")
				}
			}
		}
		conn.Close()
	}
	s.instancesMu.RLock()
	n := len(s.instances)
	s.instancesMu.RUnlock()
	if n != 0 {
		t.Fatalf("%d scan instance(s) started from refused WebSocket requests", n)
	}
}
