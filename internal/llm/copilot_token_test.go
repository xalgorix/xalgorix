package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestCopilotIntegrationID(t *testing.T) {
	cases := map[string]string{
		"github_pat_11ABC":  copilotIntegrationCLI,    // fine-grained PAT
		"gho_oauthtoken123": copilotIntegrationEditor, // OAuth user token
		"ghu_appusertoken":  copilotIntegrationEditor, // GitHub App user token
		"":                  copilotIntegrationEditor, // default
	}
	for tok, want := range cases {
		if got := copilotIntegrationID(tok); got != want {
			t.Errorf("copilotIntegrationID(%q) = %q, want %q", tok, got, want)
		}
	}
}

func TestExchangeCopilotTokenSuccess(t *testing.T) {
	var gotAuth, gotIntegration string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotIntegration = r.Header.Get("Copilot-Integration-Id")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "tid=abc;exp=123",
			"expires_at": time.Now().Add(20 * time.Minute).Unix(),
			"endpoints":  map[string]string{"api": "https://api.githubcopilot.com"},
		})
	}))
	defer srv.Close()

	orig := copilotTokenExchangeURL
	copilotTokenExchangeURL = srv.URL
	defer func() { copilotTokenExchangeURL = orig }()

	tok, err := exchangeCopilotToken(context.Background(), "github_pat_xyz")
	if err != nil {
		t.Fatalf("exchangeCopilotToken: %v", err)
	}
	if tok.bearer != "tid=abc;exp=123" {
		t.Errorf("bearer = %q", tok.bearer)
	}
	if tok.apiBase != "https://api.githubcopilot.com" {
		t.Errorf("apiBase = %q", tok.apiBase)
	}
	if gotAuth != "token github_pat_xyz" {
		t.Errorf("exchange Authorization = %q, want token scheme", gotAuth)
	}
	if gotIntegration != copilotIntegrationCLI {
		t.Errorf("exchange integration id = %q, want %q (PAT)", gotIntegration, copilotIntegrationCLI)
	}
}

func TestExchangeCopilotTokenClassicPATError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"bad token"}`))
	}))
	defer srv.Close()

	orig := copilotTokenExchangeURL
	copilotTokenExchangeURL = srv.URL
	defer func() { copilotTokenExchangeURL = orig }()

	_, err := exchangeCopilotToken(context.Background(), "ghp_classicpattoken")
	if err == nil {
		t.Fatal("expected error for classic ghp_ PAT")
	}
	if !contains(err.Error(), "classic ghp_") {
		t.Errorf("error should call out classic ghp_ PATs, got: %v", err)
	}
}

func TestCopilotTokenCacheReusesUntilSkew(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "tok-fresh",
			"expires_at": time.Now().Add(20 * time.Minute).Unix(),
		})
	}))
	defer srv.Close()

	orig := copilotTokenExchangeURL
	copilotTokenExchangeURL = srv.URL
	defer func() { copilotTokenExchangeURL = orig }()

	cache := newCopilotTokenCache()
	for i := 0; i < 3; i++ {
		if got, _ := cache.resolveBearer(context.Background(), "gho_tok"); got != "tok-fresh" {
			t.Fatalf("resolveBearer = %q, want exchanged token", got)
		}
	}
	if calls != 1 {
		t.Errorf("exchange called %d times, want 1 (cached)", calls)
	}
}

func TestCopilotResolveBearerDirectFallback(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusNotFound) // Copilot Free: no exchange endpoint
		_, _ = w.Write([]byte(`{"message":"Not Found"}`))
	}))
	defer srv.Close()

	orig := copilotTokenExchangeURL
	copilotTokenExchangeURL = srv.URL
	defer func() { copilotTokenExchangeURL = orig }()

	cache := newCopilotTokenCache()
	const pat = "github_pat_free"
	for i := 0; i < 3; i++ {
		if got, base := cache.resolveBearer(context.Background(), pat); got != pat || base != "" {
			t.Fatalf("resolveBearer = (%q,%q), want raw token + empty base (direct path)", got, base)
		}
	}
	if calls != 1 {
		t.Errorf("exchange attempted %d times, want 1 (direct decision negative-cached)", calls)
	}
}

func TestCopilotVendorOverrideDynamicHost(t *testing.T) {
	// Exchange advertises a tenant-specific (data-residency) host.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "ent-bearer",
			"expires_at": time.Now().Add(20 * time.Minute).Unix(),
			"endpoints":  map[string]string{"api": "https://api.tenant.ghe.com"},
		})
	}))
	defer srv.Close()

	origURL := copilotTokenExchangeURL
	copilotTokenExchangeURL = srv.URL
	defer func() { copilotTokenExchangeURL = origURL }()

	origCache := defaultCopilotTokens
	defaultCopilotTokens = newCopilotTokenCache()
	defer func() { defaultCopilotTokens = origCache }()

	override := copilotVendorOverride("gho_enttoken")
	req, _ := http.NewRequest(http.MethodPost, "https://api.githubcopilot.com/chat/completions", nil)
	override(req)

	if req.URL.Host != "api.tenant.ghe.com" {
		t.Errorf("host = %q, want api.tenant.ghe.com (dynamic repoint)", req.URL.Host)
	}
	if req.URL.Path != "/chat/completions" {
		t.Errorf("path = %q, want /chat/completions preserved", req.URL.Path)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer ent-bearer" {
		t.Errorf("Authorization = %q, want exchanged bearer", got)
	}
	if got := req.Header.Get("Copilot-Integration-Id"); got != copilotIntegrationEditor {
		t.Errorf("integration-id = %q, want %q (OAuth token)", got, copilotIntegrationEditor)
	}
}

func TestCopilotTokenCacheExpired(t *testing.T) {
	cache := newCopilotTokenCache()
	cache.put("gho_tok", cachedCopilotToken{
		bearer:    "stale",
		expiresAt: time.Now().Add(copilotTokenSkew / 2), // inside the skew window => treated as expired
	})
	if _, ok := cache.get("gho_tok", time.Now()); ok {
		t.Error("token within skew window should be treated as expired")
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
