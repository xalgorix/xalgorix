package llm

// Live, opt-in smoke test for the GitHub Copilot integration.
//
// It is SKIPPED unless COPILOT_GITHUB_TOKEN is set, so normal
// `go test ./...` and CI are unaffected. When a token is present it
// drives the real production path end to end:
//
//	PAT/OAuth token
//	  -> exchangeCopilotToken              (copilot_token.go)
//	  -> BuildCatalogEndpoint("copilot")   (resolver.go)
//	  -> applyAuthHeaders + VendorOverride  (client.go / copilot_token.go)
//	  -> POST api.githubcopilot.com/chat/completions
//
// Run it yourself so the token stays out of the chat/transcript:
//
//	COPILOT_GITHUB_TOKEN='<your fine-grained PAT>' \
//	  go test ./internal/llm/ -run TestCopilotLive -v -count=1
//
// Optional overrides: COPILOT_MODEL (default gpt-4o),
// COPILOT_TARGET (default http://testfire.net/).
//
// The token is never logged — only a masked preview.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xalgord/xalgorix/v4/internal/auth"
	"github.com/xalgord/xalgorix/v4/internal/providers"
)

func maskSecret(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 10 {
		return "****"
	}
	return s[:4] + "…" + s[len(s)-4:]
}

func TestCopilotLive(t *testing.T) {
	pat := strings.TrimSpace(os.Getenv("COPILOT_GITHUB_TOKEN"))
	if pat == "" {
		t.Skip("set COPILOT_GITHUB_TOKEN to run the live Copilot smoke test")
	}
	model := os.Getenv("COPILOT_MODEL")
	if model == "" {
		model = "gpt-4o"
	}
	target := os.Getenv("COPILOT_TARGET")
	if target == "" {
		target = "http://testfire.net/"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// ---- Stage 1 (diagnostic probe): which path does this account
	// take? Non-fatal — stage 2 drives the real production path. ----
	t.Logf("stage 1 (probe): credential %s, integration-id = %s", maskSecret(pat), copilotIntegrationID(pat))
	if tok, perr := exchangeCopilotToken(ctx, pat); perr != nil {
		t.Logf("stage 1: exchange unavailable -> direct-Bearer path: %v", perr)
	} else {
		t.Logf("stage 1: exchange OK -> bearer %s, advertised api host %s, expires %s",
			maskSecret(tok.bearer), tok.apiBase, tok.expiresAt.Format(time.RFC3339))
	}

	// ---- Stage 2: the real production path (resolver + VendorOverride:
	// exchange-or-direct, bearer, editor headers, and the dynamic
	// Enterprise/data-residency host repoint). ----
	entry, ok := providers.LookupBuiltin("copilot")
	if !ok {
		t.Fatal("copilot provider missing from builtin catalog")
	}
	prof := auth.Profile{Type: auth.APIKey, APIKey: pat}
	ep, err := BuildCatalogEndpoint(entry, prof, model, "")
	if err != nil {
		t.Fatalf("stage 2 FAILED — BuildCatalogEndpoint: %v", err)
	}
	t.Logf("stage 2: resolved URL = %s, model = %s", ep.URL, ep.Model)

	prompt := fmt.Sprintf(
		"You are a penetration-testing assistant. The target %s is IBM's "+
			"intentionally-vulnerable Altoro Mutual demo app, authorized for testing. "+
			"In 3 short bullets, name the first recon steps you'd take. Be concise.",
		target)

	reqBody, _ := json.Marshal(map[string]any{
		"model": ep.Model,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
		"max_tokens": 200,
		"stream":     false,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("stage 2 FAILED — build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Production header path: standard auth switch + the Copilot
	// VendorOverride. This is exactly what the running app does.
	applyAuthHeaders(req, ep)
	t.Logf("stage 2: final request host = %s", req.URL.Host)

	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("stage 2 FAILED — chat request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stage 2 FAILED — chat completion HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed struct {
		Model   string `json:"model"`
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("stage 2 FAILED — decode response: %v (body: %s)", err, strings.TrimSpace(string(body)))
	}
	if len(parsed.Choices) == 0 || strings.TrimSpace(parsed.Choices[0].Message.Content) == "" {
		t.Fatalf("stage 2 FAILED — empty completion (body: %s)", strings.TrimSpace(string(body)))
	}

	t.Logf("stage 2 OK — model %q replied:\n%s", parsed.Model, parsed.Choices[0].Message.Content)
	t.Log("✅ Copilot inference works end-to-end through xalgorix's native path.")
}
