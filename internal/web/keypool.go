package web

// keypool.go: a scoped LLM key-pool API for machine-to-machine clients.
//
// The settings surface (/api/settings/*) is operator-only BY DESIGN: it
// exposes every environment variable, so machine API tokens are blocked from
// it (see auth_session.go's machineTokenRouteDenylist). But an automation
// control plane (the SaaS admin panel) legitimately needs to manage exactly
// one knob: the LLM API key pool that outbound requests rotate across to
// spread provider rate limits.
//
// /api/pool exposes that single setting with a purpose-built, masked read
// model. Machine tokens are allowed here (it is not on the denylist and it
// returns no secret material), while /api/settings/* stays operator-only -
// an automation client can rotate keys without ever being able to read any
// other environment value.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// maxKeyPoolSize bounds the pool the same way an operator would be bounded
// by practicality; the env-file value must stay a single parseable line.
const (
	maxKeyPoolSize   = 64
	maxKeyPoolKeyLen = 1024
)

type keyPoolResponse struct {
	Keys   int      `json:"keys"`
	Masked []string `json:"masked"`
	// RestartNeeded mirrors applyEnvironmentUpdates' verdict. The pool and
	// the primary key apply to new scans immediately, so this is normally
	// false; it is surfaced for completeness.
	RestartNeeded bool `json:"restart_needed,omitempty"`
}

// currentKeyPool renders the live pool (runtime config) with every key
// masked. The response deliberately contains no secret material.
func (s *Server) currentKeyPool() keyPoolResponse {
	s.settingsMu.Lock()
	defer s.settingsMu.Unlock()
	pool := append([]string(nil), s.cfg.APIKeys...)
	masked := maskedKeyPoolList(pool)
	if masked == nil {
		masked = []string{}
	}
	return keyPoolResponse{Keys: len(pool), Masked: masked}
}

// cleanKeyPoolInput trims, drops empties, dedupes preserving order, and
// enforces the same single-line constraints the env writer applies: commas
// separate pool entries in the stored value, so a key containing one would
// corrupt the pool.
func cleanKeyPoolInput(keys []string) ([]string, error) {
	seen := make(map[string]bool, len(keys))
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if strings.ContainsAny(k, "\r\n,") {
			return nil, fmt.Errorf("API keys cannot contain commas or newlines")
		}
		if len(k) > maxKeyPoolKeyLen {
			return nil, fmt.Errorf("API key exceeds the maximum length of %d", maxKeyPoolKeyLen)
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, k)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one API key is required")
	}
	if len(out) > maxKeyPoolSize {
		return nil, fmt.Errorf("too many keys (max %d)", maxKeyPoolSize)
	}
	return out, nil
}

// handleKeyPool serves GET /api/pool (masked pool view) and POST /api/pool
// (replace the pool; the first key also becomes the primary LLM API key,
// mirroring the operator dashboard's semantics). Both the dashboard session
// and machine API tokens authorize it.
func (s *Server) handleKeyPool(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSONStatus(w, http.StatusOK, s.currentKeyPool())
		return
	case http.MethodPost:
		var body struct {
			Keys []string `json:"keys"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{
				"error": "invalid JSON body",
			})
			return
		}
		clean, err := cleanKeyPoolInput(body.Keys)
		if err != nil {
			writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		restart, err := s.applyEnvironmentUpdates(map[string]string{
			"XALGORIX_API_KEYS": strings.Join(clean, ","),
			"XALGORIX_API_KEY":  clean[0],
		})
		if err != nil {
			writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		resp := s.currentKeyPool()
		resp.RestartNeeded = restart
		writeJSONStatus(w, http.StatusOK, resp)
		return
	default:
		writeJSONStatus(w, http.StatusMethodNotAllowed, map[string]string{
			"error": "method not allowed",
		})
	}
}
